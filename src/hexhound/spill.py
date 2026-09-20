"""有界、按运行隔离的工具输出溢写存储（spill store）。

对标机制来源：Strix 把超长工具输出写到 `/workspace/.tool-output/<id>.txt` 并告诉
agent 用 `exec_command` 读回来（`strix/tools/output_store.py`，见
`docs/research-notes/strix-pentagi-refresh-2026.md` §C1）。它的短板是**没有
offset/limit 读取器**——只能靠 `sed -n` 之类的通用命令，也就等于把"读哪一段"
交回给一个通用 shell。

HexHound 的取舍：保留"正文仍有界 + 原始输出不丢"这个核心，但把读回路径做成
**专用工具**（`spill_read`），因此：

- 不需要给模型一个 shell 就能读回完整输出；
- 读取天然带 offset/limit/search，不用模型自己拼命令；
- **无法用于读任意路径**（只有句柄，没有路径参数）；
- **无法跨运行读取**（句柄只在本 run 的存储里有效）。

设计约束（逐条对应需求）：

1. 返回给模型的正文上限 `GOVERNOR_SMALL_LIMIT`（16 KiB），超出的进溢写；
2. 句柄是 **opaque 的**（`SO-` + 32 位十六进制随机串），不含路径、不含序号，
   无法从别的句柄猜出来；
3. 按 offset/limit 分页读取；
4. 支持字面量搜索（非正则，避免 ReDoS，也符合"照着日志找一行"的真实用法）;
5. 单条 / 单次运行 / 总量三级配额，超配额时**明确降级**并如实说明；
6. 元数据记录 original_size / stored_bytes / truncated / sha256；
7. 工具失败、超时与部分输出同样落盘——它们恰恰是最需要回看的输出。
"""
from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any

#: 句柄前缀（可读、便于在报告里一眼认出是溢写句柄）。
HANDLE_PREFIX = "SO-"

#: 单条溢写内容的字节上限（超过只留头尾，并记录 truncated 与原始大小）。
MAX_ENTRY_BYTES = 256 * 1024

#: 单次运行的全部溢写内容字节上限。
MAX_RUN_BYTES = 32 * 1024 * 1024

#: 溢写存储的总量上限（配额，防止长期运行把磁盘吃满）。
MAX_TOTAL_BYTES = 512 * 1024 * 1024

#: 单次读取返回给模型的字符上限（分页大小上限）。
MAX_READ_CHARS = 16 * 1024

#: 搜索返回的最大命中数。
MAX_SEARCH_HITS = 50


def new_handle() -> str:
    """生成不可猜测的 opaque 句柄。

    用 `secrets.token_hex(16)`（128 位熵）而不是自增序号或哈希：
    序号可以枚举（`SO-1`、`SO-2`…），哈希会泄露原文的结构。
    句柄里**不含路径**，因此它不能被改造成任意文件读取的入口。
    """
    return HANDLE_PREFIX + secrets.token_hex(16)


def is_handle(value: str) -> bool:
    """判断一个字符串是否形如溢写句柄（用于识别模型给的参数）。"""
    text = str(value or "").strip()
    if not text.startswith(HANDLE_PREFIX):
        return False
    rest = text[len(HANDLE_PREFIX):]
    return len(rest) == 32 and all(ch in "0123456789abcdef" for ch in rest)


@dataclass
class SpillEntry:
    """一条溢写记录的元数据（正文另存，元数据进报告与审计）。"""

    handle: str
    label: str
    original_bytes: int
    stored_bytes: int
    truncated: bool
    sha256: str
    total_chars: int
    stored_chars: int
    lines: int
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """写进证据/报告的元数据视图。**不含正文**（正文按需分页读）。"""
        return {
            "handle": self.handle,
            "label": self.label,
            "original_size": self.original_bytes,
            "stored_size": self.stored_bytes,
            "truncated": self.truncated,
            "sha256": self.sha256,
            "total_chars": self.total_chars,
            "stored_chars": self.stored_chars,
            "lines": self.lines,
            "reasons": list(self.reasons),
        }


@dataclass
class ReadResult:
    """一次分页读取的结果。"""

    ok: bool
    handle: str = ""
    text: str = ""
    start: int = 0
    end: int = 0
    total_chars: int = 0
    has_more: bool = False
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "handle": self.handle,
            "start": self.start,
            "end": self.end,
            "total_chars": self.total_chars,
            "has_more": self.has_more,
            "error": self.error,
            "metadata": self.metadata,
            "text": self.text,
        }


class SpillStore:
    """一次运行的溢写存储（线程安全，有界）。

    **默认在内存里**（`persist=False`）：一次运行的输出通常是几百 KB 到几 MB，
    内存完全够用，而且不必处理磁盘权限、清理、并发写文件这些麻烦事；
    同时天然满足"禁止跨 run 读取"——没有文件系统路径可指。
    调试或需要离线翻查时才开 `persist=True`，落到运行产物目录的 `spill/` 下，
    文件名仍然是 opaque 句柄（不是原路径），并且读取仍然只走句柄查表。
    """

    def __init__(
        self,
        *,
        label: str = "",
        persist: bool = False,
        directory: Any = None,
        max_entry_bytes: int = MAX_ENTRY_BYTES,
        max_run_bytes: int = MAX_RUN_BYTES,
        total_budget_bytes: int = MAX_TOTAL_BYTES,
    ) -> None:
        self.label = label
        self.persist = bool(persist) and directory is not None
        self.directory = directory
        self.max_entry_bytes = int(max_entry_bytes)
        self.max_run_bytes = int(max_run_bytes)
        self.total_budget_bytes = int(total_budget_bytes)
        self._entries: dict[str, SpillEntry] = {}
        self._bodies: dict[str, str] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()
        self._used_bytes = 0
        self._rejected = 0
        self._last_rejection = ""
        if self.persist:
            try:
                self.directory.mkdir(parents=True, exist_ok=True)
            except OSError:
                # 落盘不可用就退回内存——溢写是**能力增强**，不该让工具调用失败。
                self.persist = False

    # ---------- 写入 ----------

    def store(self, content: str, *, label: str = "", reasons: list[str] | None = None) -> SpillEntry:
        """保存一段输出，返回元数据（含句柄）。

        `content` 是**清理后**的文本（清洗在 governor 里已经做过，见 sanitize.py）——
        溢写存的是"可读版本"，因为它的用途就是给人和模型读回。
        原始字节数仍按 UTF-8 编码后的长度如实记录，便于核对是否被截断。
        """
        text = str(content or "")
        encoded = text.encode("utf-8")
        original_bytes = len(encoded)
        truncated = False
        stored = text
        if original_bytes > self.max_entry_bytes:
            # 单条超限：保留头尾（结论常在尾部），并记下截断事实。
            head = self.max_entry_bytes * 2 // 3
            tail = self.max_entry_bytes - head
            head_text = encoded[:head].decode("utf-8", errors="replace")
            tail_text = encoded[-tail:].decode("utf-8", errors="replace")
            stored = (
                f"{head_text}\n…[本条输出超过单条上限 {self.max_entry_bytes} 字节，"
                f"中间 {original_bytes - self.max_entry_bytes} 字节未保存]…\n{tail_text}"
            )
            truncated = True
        stored_bytes = len(stored.encode("utf-8"))

        handle = new_handle()
        entry = SpillEntry(
            handle=handle,
            label=str(label or "")[:120],
            original_bytes=original_bytes,
            stored_bytes=stored_bytes,
            truncated=truncated,
            sha256=hashlib.sha256(encoded).hexdigest(),
            total_chars=len(text),
            stored_chars=len(stored),
            lines=stored.count("\n") + 1,
            reasons=list(reasons or []),
        )

        with self._lock:
            budget_left = self.max_run_bytes - self._used_bytes
            if stored_bytes > budget_left:
                # 运行级配额用完：**不假装存下了**。返回带 handle 的元数据但
                # stored_size=0，并在 reasons 里写明原因，调用方据此如实提示。
                self._rejected += 1
                self._last_rejection = (
                    f"本次运行溢写配额已用尽（{self._used_bytes}/{self.max_run_bytes} 字节），"
                    "该输出未保存。"
                )
                entry.reasons.append("run_quota_exceeded")
                entry.stored_bytes = 0
                entry.stored_chars = 0
                entry.truncated = True
                return entry
            self._entries[handle] = entry
            self._bodies[handle] = stored
            self._order.append(handle)
            self._used_bytes += stored_bytes

        if self.persist:
            self._write_to_disk(handle, stored)
        return entry

    def _write_to_disk(self, handle: str, stored: str) -> None:
        """可选落盘。失败时只影响"离线翻查"，不影响本次读取（内存里有）。"""
        try:
            path = self.directory / f"{handle}.txt"
            path.write_text(stored, encoding="utf-8")
        except OSError:
            pass

    # ---------- 读取 ----------

    def read(self, handle: str, *, offset: int = 0, limit: int = 0) -> ReadResult:
        """按 offset/limit 分页读取。offset 以**字符**计（不是字节）。"""
        key = str(handle or "").strip()
        with self._lock:
            entry = self._entries.get(key)
            body = self._bodies.get(key)
        if entry is None or body is None:
            return ReadResult(
                ok=False,
                handle=key,
                error=(
                    f"未找到溢写内容 {key!r}。句柄只在**产生它的那次运行**内有效，"
                    "且必须是工具输出里给出的完整句柄（形如 SO-<32 位十六进制>）。"
                ),
            )
        start = max(0, int(offset or 0))
        size = int(limit or 0)
        if size <= 0:
            size = MAX_READ_CHARS
        size = min(size, MAX_READ_CHARS)
        total = len(body)
        end = min(total, start + size)
        return ReadResult(
            ok=True,
            handle=key,
            text=body[start:end],
            start=start,
            end=end,
            total_chars=total,
            has_more=end < total,
            metadata=entry.to_dict(),
        )

    def search(self, handle: str, needle: str, *, limit: int = MAX_SEARCH_HITS) -> dict[str, Any]:
        """**字面量**搜索（不是正则）。

        刻意不做正则：模型给的正则很容易写出灾难性回溯（ReDoS），而这里的真实
        用法是"在日志里找一行已知的字符串"。字面量足够，且不可能超时。
        """
        key = str(handle or "").strip()
        text = str(needle or "")
        with self._lock:
            entry = self._entries.get(key)
            body = self._bodies.get(key)
        if entry is None or body is None:
            return {"ok": False, "error": f"未找到溢写内容 {key!r}。", "hits": []}
        if not text:
            return {"ok": False, "error": "搜索串为空。", "hits": []}
        hits: list[dict[str, Any]] = []
        start = 0
        while len(hits) < max(1, min(int(limit or 0) or MAX_SEARCH_HITS, MAX_SEARCH_HITS)):
            index = body.find(text, start)
            if index < 0:
                break
            line_no = body.count("\n", 0, index) + 1
            line_start = body.rfind("\n", 0, index) + 1
            line_end = body.find("\n", index)
            if line_end < 0:
                line_end = len(body)
            hits.append(
                {
                    "offset": index,
                    "line": line_no,
                    "text": body[line_start:line_end][:400],
                }
            )
            start = index + max(1, len(text))
        return {
            "ok": True,
            "handle": key,
            "needle": text,
            "hits": hits,
            "truncated": len(hits) >= MAX_SEARCH_HITS,
            "total_chars": len(body),
        }

    def handles(self) -> list[str]:
        with self._lock:
            return list(self._order)

    def entry(self, handle: str) -> SpillEntry | None:
        with self._lock:
            return self._entries.get(str(handle or "").strip())

    def usage(self) -> dict[str, Any]:
        """本存储的用量与配额状态（报告与 `spill_read` 的提示用）。"""
        with self._lock:
            return {
                "entries": len(self._entries),
                "used_bytes": self._used_bytes,
                "run_quota_bytes": self.max_run_bytes,
                "total_quota_bytes": self.total_budget_bytes,
                "max_entry_bytes": self.max_entry_bytes,
                "rejected": self._rejected,
                "last_rejection": self._last_rejection,
                "persisted": self.persist,
            }


#: 进程级共享的**总量**账本（跨运行）。
#:
#: 为什么要跨运行累计：单次运行有 32 MiB 上限，但一个 CI 里跑几十次、或者
#: 一个长驻 GUI 会话跑上百次，累计就能把磁盘/内存吃满。这里记录已用总量，
#: 超过 `MAX_TOTAL_BYTES` 时新存储**立刻**进入"不再溢写"模式（而不是等到
#: 单次运行配额用完才发现）。
class _GlobalSpillBudget:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.used_bytes = 0
        self.runs = 0

    def reserve_run(self) -> bool:
        with self._lock:
            if self.used_bytes >= MAX_TOTAL_BYTES:
                return False
            self.runs += 1
            return True

    def add(self, count: int) -> None:
        with self._lock:
            self.used_bytes = max(0, self.used_bytes + int(count))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "used_bytes": self.used_bytes,
                "total_quota_bytes": MAX_TOTAL_BYTES,
                "runs": self.runs,
            }


GLOBAL_SPILL_BUDGET = _GlobalSpillBudget()


def make_store(
    *,
    label: str = "",
    persist: bool = False,
    directory: Any = None,
    max_run_bytes: int = MAX_RUN_BYTES,
) -> SpillStore:
    """按全局配额决定是否启用溢写。

    全局配额用尽时返回一个 `max_run_bytes=0` 的存储——它仍然**接受**调用
    （工具不会因此报错），但会明确记录"配额用尽、未保存"，
    因此报告里能看到"这次的工具输出没有被保存"，而不是静默丢失。
    """
    if not GLOBAL_SPILL_BUDGET.reserve_run():
        return SpillStore(label=label, persist=False, max_run_bytes=0)
    return SpillStore(
        label=label, persist=persist, directory=directory, max_run_bytes=max_run_bytes
    )


__all__ = [
    "GLOBAL_SPILL_BUDGET",
    "HANDLE_PREFIX",
    "MAX_ENTRY_BYTES",
    "MAX_READ_CHARS",
    "MAX_RUN_BYTES",
    "MAX_SEARCH_HITS",
    "MAX_TOTAL_BYTES",
    "ReadResult",
    "SpillEntry",
    "SpillStore",
    "is_handle",
    "make_store",
    "new_handle",
]
