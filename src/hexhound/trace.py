"""可离线审计的运行轨迹（trace）与报告重建快照（snapshot）。

为什么需要（对应 HANDOVER §10 与 README 路线图里的缺口）：

`hexhound report --run latest` 已经能做到"不发请求、不调 LLM 地重渲染报告"，
但它**只**从 `surface.json` + `tasks.json` 重建 `AgentResult`。于是重渲染出来的
报告缺了执行轨迹、工具证据附录、覆盖闸门、预算快照、沙箱状态——
一段"离线审计"看不见这些，就等于只看到结论、看不到结论是怎么来的。

本模块补三件事：

1. **trace.jsonl**：每行一个事件（模型步骤、工具调用、参数摘要、时间、
   状态、证据引用）。它是**追加写**的，因此进程被中断也不会丢掉已经发生的事；
   同时第一行写 schema 版本，供未来的迁移逻辑判断格式。
2. **snapshot.json**：一次运行结束时的完整 `AgentResult` 持久化视图，
   报告渲染需要的每个字段都在里面。离线重渲染读它，而不是重新探测目标。
3. **脱敏**：trace 会被长期保留、可能被贴进 issue 或提交包，因此写入前
   对敏感字段（Authorization / Cookie / Set-Cookie / api key / token / password）
   做掩码——**只掩码值，保留键名与长度**，这样还能看出"当时带了这个头"。

与两个参考项目的关系（见 `docs/research-notes/strix-pentagi-refresh-2026.md` §C5）：
Strix 是"磁盘优先、可重放"（`agents.json` + SQLite session），没有 OTel/Langfuse；
PentAGI 走 OTel + Langfuse，链路持久化在数据库里。
HexHound 保持零依赖，取 Strix 那一路：**磁盘上的运行目录本身就够重建报告**。
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

#: trace 格式版本。**改变事件结构时必须递增**，并同时在 `migrate_snapshot`
#: 里加一条迁移分支——否则旧运行目录会在新版本里渲染出错误内容。
TRACE_SCHEMA_VERSION = 1

#: 单条事件里字段值的最大长度（trace 是给审计看的，不是原文仓库；
#: 原文在 spill store 与证据里，这里只留能定位的摘要）。
MAX_FIELD_CHARS = 2000

#: 需要掩码的字段名（比较时忽略大小写与连字符/下划线差异）。
SENSITIVE_KEYS: frozenset[str] = frozenset({
    "authorization", "cookie", "setcookie", "proxyauthorization",
    "apikey", "xapikey", "accesstoken", "refreshtoken", "idtoken",
    "token", "password", "passwd", "pwd", "secret", "clientsecret",
    "privatekey", "session", "sessionid", "jwt", "auth", "credentials",
    "llmapikey", "visionapikey",
})

#: 掩码后保留的明文前缀长度（便于确认"用的是哪个 key"，又不足以还原）。
MASK_KEEP = 4

#: 疑似密钥的**值**形态（键名不敏感但值看起来是密钥时也要掩码）。
_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

#: 自由文本里的 `名字=值` 形态，名字带会话/令牌/口令语义。
#:
#: 为什么必须有这一条：观察文本是**原样**的一段字符串，里面可能嵌着
#: `Cookie: hh_session=user:tok-user-demo` 这种"键值对在正文里"的形式。
#: 只按键名掩码挡不住它——实测就是这么漏的（`tok-user-demo` 原样写进了 trace）。
#: 掩码时**只替换值**、保留名字与分隔符，这样审计仍然看得出"这里有个会话令牌"。
_INLINE_ASSIGNMENT_RE = re.compile(
    r"(?P<name>\b[a-z0-9_]*(?:session|token|secret|password|passwd|pwd|api[_-]?key|"
    r"auth|jwt|credential|private[_-]?key)[a-z0-9_]*\s*[:=]\s*)"
    r"(?P<value>[^\s;,'\"\]\)}]{4,})",
    re.I,
)


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key or "").lower())


def mask_value(value: str, *, keep: int = MASK_KEEP) -> str:
    """把敏感值掩码成 `前4位…(长度 N)`。

    保留长度是有意的：`Authorization: Bearer sk-…`（长度 51）与
    `Authorization: Basic …`（长度 30）在审计里是两个不同的东西，
    而掩码后**无法还原**原值。
    """
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= keep:
        return "…" + f"(长度 {len(text)})"
    return f"{text[:keep]}…(长度 {len(text)})"


def redact(value: Any, *, key: str = "", depth: int = 0) -> Any:
    """递归脱敏：按键名掩码，按值形态掩码，并限制字符串长度。

    - 键名命中 `SENSITIVE_KEYS` → 整值掩码（不管是 dict、list 还是标量）；
    - 值本身长得像密钥（`sk-…`、JWT、AWS key、PEM 私钥头）→ 掩码；
    - 其它字符串：截断到 `MAX_FIELD_CHARS` 并标注原长。
    """
    if depth > 12:  # 防自引用/异常深的嵌套
        return "…(嵌套过深已省略)"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            name = str(raw_key)
            if _normalize_key(name) in SENSITIVE_KEYS:
                result[name] = mask_value(raw_value if isinstance(raw_value, str) else str(raw_value))
            else:
                result[name] = redact(raw_value, key=name, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [redact(item, key=key, depth=depth + 1) for item in value]
    if isinstance(value, str):
        text = value
        for pattern in _VALUE_PATTERNS:
            text = pattern.sub(lambda match: mask_value(match.group(0)), text)
        # 自由文本里的 `session=…` / `token: …`：只掩码值，保留名字
        text = _INLINE_ASSIGNMENT_RE.sub(
            lambda match: match.group("name") + mask_value(match.group("value")), text
        )
        if len(text) > MAX_FIELD_CHARS:
            return text[:MAX_FIELD_CHARS] + f"…(共 {len(text)} 字符，trace 只留前 {MAX_FIELD_CHARS})"
        return text
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:MAX_FIELD_CHARS]


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


@dataclass
class TraceEvent:
    """一条 trace 事件。"""

    seq: int
    kind: str
    at: str
    elapsed: float
    task: str = ""
    role: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "seq": self.seq,
            "kind": self.kind,
            "at": self.at,
            "elapsed": round(self.elapsed, 3),
        }
        if self.task:
            payload["task"] = self.task
        if self.role:
            payload["role"] = self.role
        payload["data"] = redact(self.data)
        return payload


class TraceRecorder:
    """一次运行的 trace 记录器（线程安全，追加写 JSONL）。

    写入策略：**每条事件立即 flush**。理由是这个文件的用途恰恰包括
    "运行被中断后回看发生了什么"；攒在内存里最后一次性写出，
    在最需要它的场景下正好什么都没有。
    （代价是多次小写；每次运行的事件数是几百条量级，可以接受。）
    """

    def __init__(
        self,
        path: Path | str | None = None,
        *,
        enabled: bool = True,
        target: str = "",
        goal: str = "",
        mode: str = "",
        models: dict[str, str] | None = None,
    ) -> None:
        self.path = Path(path) if path else None
        self.enabled = bool(enabled and self.path is not None)
        self._lock = threading.Lock()
        self._seq = 0
        self._started = time.monotonic()
        self._events: list[dict[str, Any]] = []
        self._error = ""
        # header 始终写（即使 trace 不落盘）：它是 schema 版本与运行上下文的
        # 唯一来源，内存事件流里缺了它，`summarize_trace` 就会报 schema v0。
        self._write_header(target=target, goal=goal, mode=mode, models=models)

    # ---------- 写入 ----------

    def _write_header(self, **payload: Any) -> None:
        header = {
            "kind": "trace_header",
            "schema_version": TRACE_SCHEMA_VERSION,
            "at": _now_iso(),
            "product": "hexhound",
            **{key: redact(value) for key, value in payload.items()},
        }
        self._append(header)

    def record(self, kind: str, *, task: str = "", role: str = "", **data: Any) -> dict[str, Any]:
        """追加一条事件，返回写入的字典（也保留在内存里供报告使用）。"""
        with self._lock:
            self._seq += 1
            event = TraceEvent(
                seq=self._seq,
                kind=str(kind),
                at=_now_iso(),
                elapsed=time.monotonic() - self._started,
                task=str(task or ""),
                role=str(role or ""),
                data=data,
            ).to_dict()
        self._append(event)
        return event

    def record_step(self, step: dict[str, Any], *, task: str = "", role: str = "") -> dict[str, Any]:
        """记录一个模型步骤：动作、参数摘要、观察摘要、阶段、证据引用。"""
        action_input = step.get("action_input")
        if not isinstance(action_input, dict):
            action_input = {"value": action_input}
        observation = str(step.get("observation") or "")
        return self.record(
            "model_step",
            task=task,
            role=role,
            step=step.get("step"),
            phase=step.get("phase") or "probe",
            action=step.get("action"),
            thought=str(step.get("thought") or "")[:600],
            action_input=action_input,
            observation=observation[:1200],
            observation_chars=len(observation),
            # 证据编号形态：`W1-T3`（带 worker 前缀）或裸 `T3`（模型复述时
            # 常把前缀省掉）。两种都要抽出来，否则"按编号回查"就查不到。
            evidence_refs=sorted(set(re.findall(r"\b(?:[A-Z]\d+-)?[RTCS]\d+\b", observation))),
            tool_error=observation.startswith("工具执行出错") or "错误：" in observation[:40],
        )

    def record_tool_call(
        self,
        *,
        task: str,
        evidence_id: str,
        tool: str,
        command: str = "",
        ok: bool = False,
        exit_code: Any = None,
        duration: float = 0.0,
        output_chars: int = 0,
        spill_handle: str = "",
        error: str = "",
        scope_checked: bool = True,
    ) -> dict[str, Any]:
        """记录一次真工具调用（参数摘要 + 状态 + 证据编号 + 溢写句柄）。"""
        return self.record(
            "tool_call",
            task=task,
            evidence_id=evidence_id,
            tool=tool,
            command=command[:1000],
            ok=bool(ok),
            exit_code=exit_code,
            duration=round(float(duration or 0.0), 2),
            output_chars=int(output_chars or 0),
            spill_handle=spill_handle,
            error=str(error or "")[:400],
            scope_checked=bool(scope_checked),
        )

    def record_finding(self, finding: dict[str, Any], *, task: str = "") -> dict[str, Any]:
        return self.record(
            "finding",
            task=task,
            finding_id=finding.get("id"),
            title=str(finding.get("title") or "")[:200],
            severity=finding.get("severity"),
            status=finding.get("status"),
            url=str(finding.get("url") or "")[:300],
            param=finding.get("param"),
            evidence_refs=finding.get("evidence_ref") or [],
        )

    def record_coverage(self, target: str, status: str, *, detail: str = "", task: str = "") -> dict[str, Any]:
        return self.record(
            "coverage", task=task, target=str(target)[:300], status=status, detail=str(detail)[:400]
        )

    def record_budget(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        return self.record("budget", **snapshot)

    def record_error(self, message: str, *, task: str = "", kind: str = "error") -> dict[str, Any]:
        return self.record(kind, task=task, message=str(message)[:800])

    def _append(self, event: dict[str, Any]) -> None:
        self._events.append(event)
        if not self.enabled:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError as exc:
            # 落盘失败只影响"离线审计"，不该让审计本身失败。
            self._error = f"{type(exc).__name__}: {exc}"
            self.enabled = False

    # ---------- 读取 ----------

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def digest(self) -> str:
        """trace 内容摘要（sha256），写进 snapshot 便于"这份报告对应哪份 trace"。"""
        body = "\n".join(json.dumps(event, ensure_ascii=False, sort_keys=True) for event in self.events())
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "path": str(self.path) if self.path else "",
            "events": len(self._events),
            "schema_version": TRACE_SCHEMA_VERSION,
            "error": self._error,
        }


def load_trace(path: Path | str) -> list[dict[str, Any]]:
    """读回一条 trace（JSONL）。**坏行跳过并记录，不让整份 trace 读不出来。**"""
    target = Path(path)
    if not target.is_file():
        return []
    events: list[dict[str, Any]] = []
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            events.append({"kind": "trace_corrupt_line", "raw": line[:200]})
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
    return events


def trace_schema_version(events: Iterable[dict[str, Any]]) -> int:
    """从 trace 里取 schema 版本（缺失返回 0）。"""
    for event in events:
        if event.get("kind") == "trace_header":
            try:
                return int(event.get("schema_version") or 0)
            except (TypeError, ValueError):
                return 0
    return 0


def summarize_trace(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """trace 统计摘要（报告里"这次到底发生了什么"的一行版）。

    注意字段位置：`seq/kind/at/elapsed/task/role` 在事件**顶层**，
    业务字段（`tool` / `evidence_id` / `action` …）在 `data` 里。
    早先这里从顶层读 `tool`，于是统计出来的工具名全是 `?`——
    摘要看着有内容、其实什么都没统计到。
    """
    counts: dict[str, int] = {}
    tasks: set[str] = set()
    tools: dict[str, int] = {}
    actions: dict[str, int] = {}
    for event in events:
        kind = str(event.get("kind") or "?")
        counts[kind] = counts.get(kind, 0) + 1
        if event.get("task"):
            tasks.add(str(event["task"]))
        data = event.get("data")
        if not isinstance(data, dict):
            continue
        if kind == "tool_call":
            name = str(data.get("tool") or "?")
            tools[name] = tools.get(name, 0) + 1
        elif kind == "model_step":
            action = str(data.get("action") or "?")
            actions[action] = actions.get(action, 0) + 1
    return {
        "events": sum(counts.values()),
        "kinds": counts,
        "tasks": sorted(tasks),
        "tools": dict(sorted(tools.items(), key=lambda item: (-item[1], item[0]))),
        "actions": dict(sorted(actions.items(), key=lambda item: (-item[1], item[0]))),
        "schema_version": trace_schema_version(events),
    }


# ---------------------------------------------------------------------------
# 报告重建快照（snapshot.json）
# ---------------------------------------------------------------------------
#
# 为什么不用 trace.jsonl 直接重建报告：trace 是**事件流**，为了可审计性
# 每条事件只留摘要（观察截断到 1200 字符、命令截断到 1000 字符）。
# 而报告要展示完整证据（HTTP 原文、工具输出、脚本正文）。
# 两者用途不同，因此各存一份：trace 给"过程审计"，snapshot 给"报告重建"。
#
# snapshot 里**不重复存 surface 数据**：findings/coverage/attempts 已经在
# surface.json 里，重复存会让运行目录体积翻倍。快照只存"报告需要、而
# surface.json 里没有"的那部分（steps / tool_log / tasks / budget / 闸门…）。

#: snapshot 格式版本。与 trace 版本独立演进（两者可以分别迁移）。
SNAPSHOT_SCHEMA_VERSION = 2


def _snapshot_path(run_dir: Path | str) -> Path:
    return Path(run_dir) / "snapshot.json"


def write_snapshot(
    run_dir: Path | str,
    result: Any,
    *,
    goal: str = "",
    target: str = "",
    mode: str = "",
    budget: dict[str, Any] | None = None,
    trace_digest: str = "",
    trace_events: int = 0,
    run_dir_name: str = "",
) -> Path | None:
    """把一次运行的可重建状态写进 `<run_dir>/snapshot.json`。

    返回写入路径；失败返回 None（快照是"离线重建能力"，不该让一次成功的
    审计因为它失败而报错）。
    """
    path = _snapshot_path(run_dir)
    payload = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "generated_at": _now_iso(),
        "target": str(target or ""),
        "goal": str(goal or ""),
        "mode": str(mode or ""),
        "run_dir": str(run_dir_name or Path(run_dir).name),
        "trace": {"digest": trace_digest, "events": int(trace_events)},
        "result": _result_to_snapshot(result),
        "budget": redact(budget or {}),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except OSError:
        return None
    return path


def _result_to_snapshot(result: Any) -> dict[str, Any]:
    """把 `AgentResult` 展成可 JSON 化的字典（渲染报告需要的字段都在）。"""
    if result is None:
        return {}
    getter = getattr(result, "to_snapshot", None)
    if callable(getter):
        return redact(getter())
    return redact(
        {
            "steps": getattr(result, "steps", []) or [],
            "findings": getattr(result, "findings", []) or [],
            "final_summary": getattr(result, "final_summary", "") or "",
            "finish_reason": getattr(result, "finish_reason", "") or "",
            "prompt_tokens": getattr(result, "prompt_tokens", 0),
            "completion_tokens": getattr(result, "completion_tokens", 0),
            "cache_hit_tokens": getattr(result, "cache_hit_tokens", 0),
            "cache_miss_tokens": getattr(result, "cache_miss_tokens", 0),
            "total_tokens": getattr(result, "total_tokens", 0),
            "estimated_cost": getattr(result, "estimated_cost", 0.0),
            "steps_used": getattr(result, "steps_used", 0),
            "tasks": getattr(result, "tasks", []) or [],
            "artifacts_dir": getattr(result, "artifacts_dir", "") or "",
            "poc_paths": getattr(result, "poc_paths", {}) or {},
            "models": getattr(result, "models", {}) or {},
            "sandbox": getattr(result, "sandbox", {}) or {},
            "tool_log": getattr(result, "tool_log", []) or [],
            "coverage_gate": getattr(result, "coverage_gate", {}) or {},
            "deduped": getattr(result, "deduped", 0),
            "previous_findings": getattr(result, "previous_findings", []) or [],
            "previous_run_at": getattr(result, "previous_run_at", "") or "",
            "closing": getattr(result, "closing", {}) or {},
            "usage": getattr(result, "usage", {}) or {},
        }
    )


def load_snapshot(run_dir: Path | str) -> dict[str, Any]:
    """读回 snapshot（不存在或损坏时返回 {}）。"""
    path = _snapshot_path(run_dir)
    if not path.is_file():
        return {}
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


@dataclass
class RestoreOutcome:
    """一次离线重建的结果：快照内容 + 它是怎么来的（供 CLI 说明）。"""

    payload: dict[str, Any] = field(default_factory=dict)
    source: str = ""          # snapshot / legacy / none
    migrated_from: int = 0    # 原始 schema 版本（0 = 没有版本字段的旧格式）
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.payload)


def migrate_snapshot(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """把旧格式快照升到当前 schema。

    **旧格式必须能读**（HANDOVER §5 的"离线重渲染"能力依赖它）：
    v0.5 及以前的运行目录里根本没有 `snapshot.json`，只有
    `surface.json` + `tasks.json` + `run.json`。那种情况由调用方走
    "legacy" 分支（`cli.report_cmd` 从这三个文件拼一个最小快照）。

    这里处理的是"有 snapshot.json 但 schema 版本更老"的情况。
    返回 `(升级后的快照, 警告列表)`。
    """
    warnings: list[str] = []
    data = dict(payload or {})
    try:
        version = int(data.get("schema_version") or 0)
    except (TypeError, ValueError):
        version = 0

    if version > SNAPSHOT_SCHEMA_VERSION:
        warnings.append(
            f"快照 schema 版本 {version} 高于本程序支持的 {SNAPSHOT_SCHEMA_VERSION}："
            "字段可能缺失，报告里缺的部分会标注「未记录」。建议用生成它的版本重渲染。"
        )
        return data, warnings

    if version == 0:
        # 无版本字段 = 最早的手写格式：结果字段直接平铺在顶层。
        warnings.append("快照没有 schema 版本字段（旧格式），已按 v1 结构解析。")
        result = {key: data.get(key) for key in _RESULT_FIELDS if key in data}
        upgraded = {
            "schema_version": 1,
            "generated_at": data.get("generated_at", ""),
            "target": data.get("target", ""),
            "goal": data.get("goal", ""),
            "mode": data.get("mode", ""),
            "result": result,
        }
        data = upgraded
        version = 1

    if version == 1:
        # v1 → v2：新增 closing / usage / trace 三个块。缺的补空值，
        # 报告里对应的段落标注「未记录」，而不是渲染出错误内容。
        warnings.append("快照已从 v1 迁移到 v2（closing/usage/trace 段落为「未记录」）。")
        result = dict(data.get("result") or {})
        result.setdefault("closing", {})
        result.setdefault("usage", {})
        result.setdefault("tool_log", [])
        result.setdefault("coverage_gate", {})
        data = {**data, "schema_version": 2, "result": result}
        data.setdefault("trace", {})
        version = 2

    return data, warnings


#: 旧格式（无版本字段）里被识别为结果字段的键名。
_RESULT_FIELDS: tuple[str, ...] = (
    "steps", "findings", "final_summary", "finish_reason", "prompt_tokens",
    "completion_tokens", "cache_hit_tokens", "cache_miss_tokens", "total_tokens",
    "estimated_cost", "steps_used", "tasks", "artifacts_dir", "poc_paths",
    "models", "sandbox", "tool_log", "coverage_gate", "deduped",
    "previous_findings", "previous_run_at",
)


def restore_run(run_dir: Path | str) -> RestoreOutcome:
    """从运行目录恢复"可重建报告的状态"。

    优先级：
    1. `snapshot.json`（v2+，字段最全）——迁移后使用；
    2. **legacy**：没有 snapshot 时，由调用方传入 surface/tasks 拼装。

    **不会发起任何网络请求，也不会调用 LLM**——这正是离线重渲染的前提。
    """
    directory = Path(run_dir)
    payload = load_snapshot(directory)
    if payload:
        migrated, warnings = migrate_snapshot(payload)
        try:
            original = int(payload.get("schema_version") or 0)
        except (TypeError, ValueError):
            original = 0
        return RestoreOutcome(
            payload=migrated, source="snapshot", migrated_from=original, warnings=warnings
        )
    return RestoreOutcome(
        payload={},
        source="legacy",
        warnings=[
            "运行目录里没有 snapshot.json（v0.5 及以前格式）："
            "将从 surface.json + tasks.json 重建，执行轨迹与工具证据附录不可用。"
        ],
    )


def legacy_snapshot(
    *,
    surface: Any,
    tasks: list[dict[str, Any]],
    run_summary: dict[str, Any] | None = None,
    target: str = "",
    goal: str = "",
    mode: str = "",
) -> dict[str, Any]:
    """用旧格式的三个文件拼一个当前 schema 的快照。

    明确标注 `legacy=True`，报告里据此说明"轨迹与工具证据未记录"——
    而不是让读者以为那部分本来就是空的。
    """
    summary = dict(run_summary or {})
    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "generated_at": summary.get("generated_at", ""),
        "target": str(target or summary.get("target") or ""),
        "goal": str(goal or summary.get("goal") or ""),
        "mode": str(mode or summary.get("mode") or ""),
        "legacy": True,
        "trace": {},
        "result": {
            "steps": [],
            "findings": list(getattr(surface, "finding_dicts", lambda: [])()),
            "final_summary": "（旧格式运行目录：没有保存执行轨迹与工具证据）",
            "finish_reason": "legacy",
            "tasks": tasks,
            "models": summary.get("models") or {},
            "sandbox": summary.get("sandbox") or {},
            "tool_log": [],
            "coverage_gate": summary.get("coverage") and {} or {},
            "deduped": summary.get("deduped", 0),
            "artifacts_dir": "",
            "poc_paths": {},
            "closing": {},
            "usage": {},
        },
        "budget": summary.get("usage") or {},
    }


__all__ = [
    "MAX_FIELD_CHARS",
    "MASK_KEEP",
    "RestoreOutcome",
    "SENSITIVE_KEYS",
    "SNAPSHOT_SCHEMA_VERSION",
    "TRACE_SCHEMA_VERSION",
    "TraceEvent",
    "TraceRecorder",
    "legacy_snapshot",
    "load_snapshot",
    "load_trace",
    "mask_value",
    "migrate_snapshot",
    "redact",
    "restore_run",
    "summarize_trace",
    "trace_schema_version",
    "write_snapshot",
]
