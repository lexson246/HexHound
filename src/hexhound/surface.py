"""攻击面模型（Attack Surface）：整次运行的共享工作记忆。

对标 PentAGI 的 flow→task→subtask 分层产物与 Strix 的 worker 共享工作区：
所有子代理把侦察结果（端点/参数/表单/指纹）、尝试记录（避免重复劳动）
与发现（含复核状态）写进同一个 AttackSurface，读完再写回，避免各 worker
重复爬同一个页面、重复打同一组 payload。

设计约束：
- 单进程、纯标准库（json / threading / dataclasses）。
- 线程安全：并发子代理会同时读写，所有变更走 `_lock`。
- 可落盘：`save()` / `load()` 写 `~/.hexhound/runs/<host>/surface.json`，
  同一目标二次运行可直接复用上次的攻面与已验证结论。
"""
from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from .apispec import Operation, SpecImport, build_operation_url  # noqa: F401

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

# 高价值端点关键词：排序时优先交给 LLM 看，避免上下文被垃圾路径淹没。
HIGH_VALUE_HINTS = (
    "admin", "api", "upload", "user", "account", "auth", "login", "token",
    "order", "pay", "file", "download", "export", "redirect", "url", "debug",
    "console", "manage", "system", "internal", "graphql", "swagger",
)

# 静态资源后缀：不进端点清单。
_ASSET_SUFFIX = re.compile(
    r"\.(js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|mp4|webp|avif)$", re.I
)

_DIGIT = re.compile(r"\d+")

#: URI 路径里不允许出现的字符（RFC 3986：空白与控制字符一律不算路径内容）。
#:
#: 为什么要在攻面入口挡这一层：实测有工具把自己"给人看的"命中文本当成端点登记，
#: 于是覆盖率表里出现 `/admin（受保护，值得进一步探测）` 这类**假端点**——
#: 端点覆盖数字虚高，读者以为测过的东西其实不存在。根因已在调用方修掉，
#: 这里是边界防线：任何调用方都不该能把一句话塞进端点表。
_INVALID_IN_URL = re.compile(r"[\s\x00-\x1f\x7f]")


def looks_like_url(value: str) -> bool:
    """这个值能不能当作 URL/路径登记（挡住"一句话被当成端点"）。

    判据刻意保守：只拒绝**不可能是 URL** 的东西——含空白或控制字符、
    或者（去掉 query/fragment 后）路径里出现成对的中文括号。
    合法的百分号编码路径（`/%E4%B8%AD%E6%96%87`）不受影响。

    注意：这里**不**因为非 ASCII 就拒绝——IRI 里中文路径是合法的，
    真正的问题是"人话"混进来了，而人话一定有空白或全角标点。
    """
    text = str(value or "").strip()
    if not text:
        return False
    if _INVALID_IN_URL.search(text):
        return False
    parsed = urlparse(text if "://" in text else "//" + text)
    path = parsed.path or ""
    # 全角括号只会出现在中文说明里（URL 里要用也会被百分号编码）
    return not any(char in path for char in "（）")


def normalize_path(url: str) -> str:
    """把 URL 归一成「同一条路径」：去掉 host、数字段折叠为 {n}、去掉末尾斜杠。"""
    parsed = urlparse(url if "://" in url else "//" + url)
    path = parsed.path or "/"
    path = _DIGIT.sub("{n}", path)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path or "/"


def normalize_endpoint(url: str, keep_host: bool = True) -> str:
    """端点归一化：保留 scheme+host（可选），路径参数段折叠，丢弃 query/fragment。

    相对路径（无 host）在攻面里没有意义：与绝对 URL 端点无法比对、无法直接请求，
    因此统一返回空串让调用方丢弃（表单 action 会先用 base_url 补全）。

    含空白/全角标点的"人话"同样返回空串（见 `looks_like_url`）：这类值一定不是
    端点，而它一旦进入 `attempt_key` 就会变成一条"探过某个不存在的端点"的记录。
    """
    value = str(url or "").strip()
    if not value or "://" not in value or not looks_like_url(value):
        return ""
    parsed = urlparse(value)
    if not parsed.netloc:
        return ""
    path = normalize_path(value)
    if keep_host:
        return f"{parsed.scheme or 'http'}://{parsed.netloc}{path}"
    return path


def host_of(url: str) -> str:
    """取出 URL 的主机名（小写）。"""
    return (urlparse(url if "://" in url else "//" + url).hostname or "").lower()


def is_asset(url: str) -> bool:
    """判断是否为静态资源（不入攻面清单）。"""
    return bool(_ASSET_SUFFIX.search(urlparse(url).path or ""))


def param_names(url: str, extra: Iterable[str] = ()) -> list[str]:
    """从 URL query 与额外名字里取出参数名（保序去重）。"""
    names: list[str] = []
    for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if key and key not in names:
            names.append(key)
    for key in extra:
        key = str(key or "").strip()
        if key and key not in names:
            names.append(key)
    return names


def sort_urls(urls: Iterable[str], limit: int | None = None) -> list[str]:
    """按「高价值优先 → 路径浅优先 → 字典序」排序，可截断。"""
    def key(url: str) -> tuple[int, int, str]:
        low = url.lower()
        hint = 0 if any(token in low for token in HIGH_VALUE_HINTS) else 1
        depth = (urlparse(url).path or "/").count("/")
        return (hint, depth, url)

    ordered = sorted(set(urls), key=key)
    return ordered[:limit] if limit else ordered


@dataclass
class Endpoint:
    """一个已发现的端点（含已知参数与来源）。"""

    url: str
    methods: list[str] = field(default_factory=list)
    params: list[str] = field(default_factory=list)
    source: str = ""
    status: int = 0
    note: str = ""
    first_seen: float = field(default_factory=time.time)

    def merge(self, other: Endpoint) -> None:
        for method in other.methods:
            if method not in self.methods:
                self.methods.append(method)
        for param in other.params:
            if param not in self.params:
                self.params.append(param)
        if other.status and not self.status:
            self.status = other.status
        if other.note and other.note not in self.note:
            self.note = (self.note + " " + other.note).strip()
        if other.source and other.source not in self.source:
            self.source = (self.source + "," + other.source).strip(",")


@dataclass
class Attempt:
    """一次已执行的攻击尝试：(端点, 参数, 类别) → 结果，用于去重与续跑。"""

    endpoint: str
    param: str = ""
    category: str = ""
    payload: str = ""
    outcome: str = "signal"  # signal / no_signal / error
    detail: str = ""
    at: float = field(default_factory=time.time)


@dataclass
class Finding:
    """一条漏洞记录：Discovery（候选）→ Verification（复核）→ 入库。"""

    id: str
    title: str
    severity: str
    confidence: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    vuln_type: str = ""
    url: str = ""
    param: str = ""
    status: str = "candidate"  # candidate / verified
    verified_by: str = ""
    verification: str = ""
    dedupe_key: str = ""
    duplicate_of: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        """展开成旧版 finding dict（保持 report/submission 兼容）。"""
        data: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "status": self.status,
            "verified_by": self.verified_by,
            "verification": self.verification,
            "dedupe_key": self.dedupe_key,
        }
        if self.vuln_type:
            data["vuln_type"] = self.vuln_type
        if self.url:
            data["url"] = self.url
        if self.param:
            data["param"] = self.param
        if self.duplicate_of:
            data["duplicate_of"] = self.duplicate_of
        data.update(self.extra)
        return data


class AttackSurface:
    """一次运行共享的攻面状态（线程安全）。"""

    def __init__(self, target: str = "", mode: str = "blackbox", path: Path | None = None) -> None:
        self.target = target
        self.mode = mode
        self.host = host_of(target)
        self.path = path
        self._lock = threading.RLock()
        self.endpoints: dict[str, Endpoint] = {}
        self.forms: dict[str, dict[str, Any]] = {}
        self.tech: dict[str, str] = {}
        self.notes: list[str] = []
        self.attempts: dict[tuple[str, str, str], Attempt] = {}
        self.candidates: dict[str, Finding] = {}
        self.findings: list[Finding] = []
        self.extra_paths: list[str] = []
        # 覆盖率记录（对标 Strix 的 record_coverage / 负面结论追踪）：
        # 记录「测过什么、结论是什么」，让报告能说清覆盖到哪、哪里没覆盖。
        self.coverage: dict[str, dict[str, Any]] = {}
        self.agent_notes: list[dict[str, Any]] = []
        # API 合约导入（OpenAPI/Swagger）：记录导入了哪些接口、每个接口声明了
        # 哪些参数。用途有两层——提示词里给出"该测什么"，覆盖率闸门据此形成
        # **参数级**盲区清单（导入但不测，报告里必须看得见）。
        self.api_specs: list[dict[str, Any]] = []
        self.api_spec_endpoints: set[str] = set()
        self.api_spec_params: list[tuple[str, str]] = []
        self.started_at = time.time()

    # ---------- 覆盖率 / 笔记 ----------

    def record_coverage(
        self,
        target: str,
        status: str,
        *,
        detail: str = "",
        owasp: str = "",
    ) -> None:
        """记录一处「已测/未测/排除」的覆盖面。

        对标 Strix 的 coverage + 负面结论追踪：`status` 取值
        `reported`（已报漏洞）/ `no_issue_found` / `ruled_out`（确认不可利用）/
        `not_tested` / `blocked`。没有这层记录，报告只能列"发现了什么"，
        说不清"还有哪些没覆盖"。
        """
        target = str(target or "").strip()[:200]
        if not target:
            return
        status = str(status or "no_issue_found").strip().lower()
        if status not in ("reported", "no_issue_found", "ruled_out", "not_tested", "blocked"):
            status = "no_issue_found"
        with self._lock:
            key = f"{status}|{target}"
            entry = self.coverage.get(key)
            if entry is None:
                self.coverage[key] = {
                    "target": target,
                    "status": status,
                    "detail": str(detail or "")[:300],
                    "owasp": str(owasp or "")[:16],
                    "at": time.time(),
                }
            elif detail and detail[:60] not in str(entry.get("detail", "")):
                entry["detail"] = (str(entry.get("detail", "")) + " | " + str(detail))[:300]

    def coverage_summary(self) -> dict[str, int]:
        with self._lock:
            counts: dict[str, int] = {}
            for entry in self.coverage.values():
                counts[entry["status"]] = counts.get(entry["status"], 0) + 1
        return counts

    def coverage_lines(self, limit: int = 40) -> list[str]:
        with self._lock:
            items = list(self.coverage.values())
        order = {"not_tested": 0, "blocked": 1, "ruled_out": 2, "no_issue_found": 3, "reported": 4}
        items.sort(key=lambda item: (order.get(item["status"], 9), item["target"]))
        lines = []
        for entry in items[:limit]:
            line = f"[{entry['status']}] {entry['target']}"
            if entry.get("owasp"):
                line += f" ({entry['owasp']})"
            if entry.get("detail"):
                line += f" — {entry['detail'][:120]}"
            lines.append(line)
        return lines

    def add_agent_note(self, worker: str, text: str) -> None:
        """子代理留下的一条结论/线索（跨代理可读，对标 Strix 的 notes 工具）。"""
        text = str(text or "").strip()[:400]
        if not text:
            return
        with self._lock:
            self.agent_notes.append({"worker": str(worker or "?"), "text": text, "at": time.time()})
            del self.agent_notes[:-40]

    def note_lines(self, limit: int = 12) -> list[str]:
        with self._lock:
            items = list(self.agent_notes)[-limit:]
        return [f"[{item['worker']}] {item['text']}" for item in items]

    # ---------- 写入 ----------

    def add_endpoint(
        self,
        url: str,
        *,
        methods: Iterable[str] = (),
        params: Iterable[str] = (),
        source: str = "",
        status: int = 0,
        note: str = "",
    ) -> str | None:
        """登记一个端点，返回归一化后的 key（静态资源或非法值返回 None）。"""
        if not url or is_asset(url) or not looks_like_url(url):
            return None
        key = normalize_endpoint(url)
        if not key:
            return None
        entry = Endpoint(
            url=key,
            methods=[str(m).upper() for m in methods if m],
            params=param_names(url, params),
            source=source,
            status=int(status or 0),
            note=note,
        )
        with self._lock:
            existing = self.endpoints.get(key)
            if existing is None:
                self.endpoints[key] = entry
            else:
                existing.merge(entry)
        return key

    def add_endpoints(self, urls: Iterable[str], source: str = "") -> int:
        """批量登记端点，返回新增数量。"""
        with self._lock:
            before = len(self.endpoints)
        for url in urls:
            self.add_endpoint(url, source=source)
        with self._lock:
            return len(self.endpoints) - before

    def add_api_spec(self, spec_import: Any) -> dict[str, Any]:
        """把一个 API 合约导入（`apispec.SpecImport`）登记进攻击面。

        为什么必须进攻面（而不是只放进提示词）：注册了才算"待覆盖"，
        覆盖率闸门才会**强制**有人去测这些接口。只写进提示词的话，
        模型可以整份忽略，而报告里的覆盖率数字完全不体现——
        "导入了 80 个接口，一个都没测"会看起来和"没导入"一样。

        三件事：
        1. 每个 operation 登记成端点（带 method 与参数名），来源标 `api_spec`；
        2. 参数按位置记进 `api_params`（覆盖闸门据此形成**参数级**盲区清单）；
        3. 记 spec 元信息（版本、规范声明的 servers、被跳过的条目）供报告使用。

        **不把接口标记为"已测试"**：导入的是"应该测什么"，不是"已经测过"。
        """
        registered: list[str] = []
        param_pairs: list[tuple[str, str]] = []
        operations_registered = 0
        for operation in getattr(spec_import, "operations", []) or []:
            try:
                url = build_operation_url(
                    str(getattr(spec_import, "target", "") or ""),
                    str(getattr(operation, "normalized_path", "") or operation.path),
                )
            except Exception:  # noqa: BLE001 单条接口构造失败不该让整次导入失败
                continue
            names = [
                str(item.get("name"))
                for item in (getattr(operation, "params", None) or [])
                if isinstance(item, dict) and item.get("name")
            ]
            key = self.add_endpoint(
                url,
                methods=[str(getattr(operation, "method", "GET"))],
                params=names,
                source="api_spec",
                note=str(getattr(operation, "summary", "") or "")[:120],
            )
            if key is None:
                continue
            registered.append(key)
            operations_registered += 1
            for name in names:
                param_pairs.append((key, name))
            # 接口文档已经给出了方法/参数，对"表单"这一层也登记一份，
            # 让 injection 角色知道该按表单还是按 JSON 体发请求。
            if getattr(operation, "has_body", False) and names:
                self.add_form(key, str(getattr(operation, "method", "POST")), key, names)

        with self._lock:
            self.api_specs.append(dict(spec_import.to_dict()))
            existing = set(self.api_spec_params)
            for pair in param_pairs:
                if pair not in existing:
                    self.api_spec_params.append(pair)
                    existing.add(pair)
            self.api_spec_endpoints.update(registered)
        self.add_note(
            f"已从 API 规范导入 {operations_registered} 个接口"
            f"（{getattr(spec_import, 'kind', None) and spec_import.kind.label or '未知格式'}，"
            f"来源 {getattr(spec_import, 'source', '')}）——"
            "这些接口已进入覆盖率闸门，必须有结论（finding 或 record_coverage）。"
        )
        return {
            # 两个数字含义不同，都要给：同一路径的不同方法算"一个端点、多个接口"。
            "operations": operations_registered,
            "endpoints": len(set(registered)),
            "params": len(param_pairs),
            "skipped": len(getattr(spec_import, "skipped", []) or []),
        }

    def api_spec_summary(self) -> dict[str, Any]:
        """API 规范导入的汇总（报告里单独一节）。"""
        with self._lock:
            imports = list(self.api_specs)
            endpoints = sorted(self.api_spec_endpoints)
            params = list(self.api_spec_params)
        return {
            "imports": imports,
            "endpoints": len(endpoints),
            "params": len(params),
            "endpoint_sample": endpoints[:20],
        }

    def add_form(
        self, url: str, method: str, action: str, inputs: Iterable[str], base_url: str = ""
    ) -> None:
        """登记一个表单（endpoint + method + 参数名）。

        action 可能是相对路径（`/login`）或空串，统一用 base_url 补成绝对 URL，
        否则攻面里会同时出现「绝对 URL 端点」和「相对路径端点」，端点去重与
        「未测端点」统计都会失真。
        """
        resolved = action or url
        if base_url and not str(resolved).lower().startswith(("http://", "https://")):
            from urllib.parse import urljoin

            resolved = urljoin(base_url, str(resolved) or "")
        key = normalize_endpoint(str(resolved))
        if not key:
            return
        with self._lock:
            entry = self.forms.setdefault(
                key, {"url": key, "method": str(method or "GET").upper(), "params": []}
            )
            for name in inputs:
                name = str(name or "").strip()
                if name and name not in entry["params"]:
                    entry["params"].append(name)
        self.add_endpoint(key, methods=[method or "GET"], params=inputs, source="form")

    def add_tech(self, name: str, value: str = "") -> None:
        """登记技术栈指纹（Server / X-Powered-By / Generator / 中间件版本）。"""
        name = str(name or "").strip()
        if not name:
            return
        with self._lock:
            self.tech[name] = str(value or "").strip() or self.tech.get(name, "")

    def add_note(self, text: str, limit: int = 200) -> None:
        """记一条自由观察（异常报错、可疑行为等）。"""
        text = str(text or "").strip().replace("\n", " ")
        if not text:
            return
        with self._lock:
            if text[:limit] not in (item[:limit] for item in self.notes):
                self.notes.append(text[:limit])
            del self.notes[:-60]

    def add_extra_paths(self, paths: Iterable[str]) -> int:
        """记录非 404 的探测路径（enumerate 命中）。

        只收"像 URL/路径"的值：这一层曾被展示文本污染
        （`/admin（受保护，值得进一步探测）` 被当成一条探测到的路径）。
        """
        added = 0
        with self._lock:
            for path in paths:
                path = str(path or "").strip()
                if path and looks_like_url(path) and path not in self.extra_paths:
                    self.extra_paths.append(path)
                    added += 1
        return added

    # ---------- 尝试记录（去重核心）----------

    @staticmethod
    def attempt_key(
        endpoint: str, param: str = "", category: str = "", payload: str = ""
    ) -> tuple[str, str, str, str]:
        """尝试指纹：端点 + 参数 + 类别 + payload。

        带上 payload 是必要的：同一 (端点, 参数, 类别) 下往往要试多个 payload
        （单引号触发报错、布尔盲注、时间盲注…），只按前三者去重会把后面的 payload
        全部误判为「已试过」——这曾在自检里直接吃掉 SSTI/命令注入的检出率。
        """
        return (
            normalize_endpoint(endpoint),
            str(param or ""),
            str(category or ""),
            str(payload or "")[:120],
        )

    def mark_attempt(
        self,
        endpoint: str,
        category: str,
        *,
        param: str = "",
        payload: str = "",
        outcome: str = "signal",
        detail: str = "",
    ) -> None:
        """记录一次尝试；`outcome=no_signal` 的同一组合（同 payload）不再重试。"""
        key = self.attempt_key(endpoint, param, category, payload)
        with self._lock:
            existing = self.attempts.get(key)
            if existing is not None and existing.outcome == "signal":
                # 已经命中过，保留命中记录（含细节），不降级。
                if detail and detail not in existing.detail:
                    existing.detail = (existing.detail + " | " + detail)[:500]
                return
            self.attempts[key] = Attempt(
                endpoint=key[0], param=key[1], category=key[2],
                payload=str(payload or "")[:200], outcome=outcome, detail=str(detail or "")[:300],
            )

    def tried_outcome(
        self, endpoint: str, category: str, param: str = "", payload: str = ""
    ) -> Attempt | None:
        """返回该组合已有的尝试记录（None = 没试过）。"""
        with self._lock:
            return self.attempts.get(self.attempt_key(endpoint, param, category, payload))

    def is_tried(
        self, endpoint: str, category: str, param: str = "", payload: str = ""
    ) -> bool:
        """该组合（含 payload）是否已有结论（命中或无信号都算）。

        命中也算「已试」：并发子代理里 A 打到命中后，B 不该重复发同一个 payload，
        而应直接去看 A 留下的证据（`tried_outcome`）并进入复核阶段。
        """
        return self.tried_outcome(endpoint, category, param, payload) is not None

    def tried_summary(self, limit: int = 40) -> list[str]:
        """给 LLM 看的「已试过什么」，避免重复劳动（按端点+参数+类别聚合）。"""
        with self._lock:
            items = list(self.attempts.values())
        grouped: dict[tuple[str, str, str], list[Attempt]] = {}
        for item in items:
            grouped.setdefault((item.endpoint, item.param, item.category), []).append(item)
        lines = []
        for (endpoint, param, category), group in grouped.items():
            target = endpoint + (f"?{param}=" if param else "")
            hits = [g for g in group if g.outcome == "signal"]
            if hits:
                lines.append(f"{target} [{category or '-'}] 命中 {len(hits)} 次：{hits[0].detail[:80]}")
            else:
                lines.append(f"{target} [{category or '-'}] 无信号（已试 {len(group)} 个 payload）")
        return sorted(set(lines))[:limit]

    # ---------- 发现（候选 / 已复核）----------

    def next_finding_id(self) -> str:
        with self._lock:
            used = {f.id for f in self.findings} | set(self.candidates)
            index = len(self.findings) + len(self.candidates) + 1
            while f"HH-{index:03d}" in used:
                index += 1
            return f"HH-{index:03d}"

    def add_candidate(self, finding: Finding) -> Finding:
        """登记候选（同一指纹只留一条，证据更长者胜）。"""
        with self._lock:
            existing = next(
                (f for f in self.candidates.values() if f.dedupe_key == finding.dedupe_key),
                None,
            )
            if existing is not None:
                if len(finding.evidence) > len(existing.evidence):
                    existing.evidence = finding.evidence
                    existing.confidence = finding.confidence or existing.confidence
                existing.extra.setdefault("merged_count", 1)
                existing.extra["merged_count"] = int(existing.extra["merged_count"]) + 1
                return existing
            if not finding.id:
                finding.id = self.next_finding_id()
            self.candidates[finding.id] = finding
            return finding

    def claim_candidate(self, ref: str) -> Finding | None:
        """按 id 或去重指纹取出候选。"""
        ref = str(ref or "").strip()
        if not ref:
            return None
        with self._lock:
            if ref in self.candidates:
                return self.candidates[ref]
            for item in self.candidates.values():
                if ref == item.dedupe_key:
                    return item
        return None

    def promote(self, finding: Finding, verified_by: str, verification: str) -> str:
        """把候选提升为已复核漏洞并入库。返回 'new'（新条目）或 'merged'（并入已有）。"""
        with self._lock:
            finding.status = "verified"
            finding.verified_by = verified_by
            finding.verification = verification
            if not finding.id:
                finding.id = self.next_finding_id()
            for existing in self.findings:
                if existing.dedupe_key and existing.dedupe_key == finding.dedupe_key:
                    if len(finding.evidence) > len(existing.evidence):
                        existing.evidence = finding.evidence
                        existing.verification = verification or existing.verification
                    existing.extra.setdefault("merged_count", 1)
                    existing.extra["merged_count"] = int(existing.extra["merged_count"]) + 1
                    self.candidates.pop(finding.id, None)
                    return "merged"
            self.findings.append(finding)
            self.candidates.pop(finding.id, None)
            return "new"

    def merge_finding(self, finding: Finding) -> str:
        """直接并入一条已确认漏洞（用于报告合并阶段）。"""
        with self._lock:
            if not finding.id:
                finding.id = self.next_finding_id()
            for existing in self.findings:
                if existing.dedupe_key and existing.dedupe_key == finding.dedupe_key:
                    return "merged"
            self.findings.insert(0, finding)
        return "new"

    def pending_candidates(self) -> list[Finding]:
        with self._lock:
            return list(self.candidates.values())

    def verified_findings(self) -> list[Finding]:
        with self._lock:
            return list(self.findings)

    def finding_dicts(self, include_candidates: bool = True) -> list[dict[str, Any]]:
        """导出为旧版 finding dict 列表（按严重度排序）。"""
        with self._lock:
            items = list(self.findings) + (list(self.candidates.values()) if include_candidates else [])
        items.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.id))
        return [item.to_dict() for item in items]

    # ---------- 给 LLM 的紧凑视图 ----------

    def touched_endpoints(self) -> set[str]:
        """"确实被碰过"的端点集合（归一化后的绝对 URL）。

        三个来源都要算，否则会把"已经出结论的端点"误报成盲区（实测踩过：
        `/api/users` 有已复核漏洞，却因为判据只看 attempts 而被列进盲区）：
        1. `attempts` —— fuzz/compare/http_request 记的尝试；
        2. `findings` / `candidates` —— 有 finding 说明肯定被测过；
        3. `coverage` —— 有覆盖记录说明给出了结论（target 可能是自由文本，用 URL 正则提取）。

        这同时是"跨运行 diff 能否判 fixed"的唯一依据：**只有这里返回的端点，
        才允许说上次的问题"已修复"**，其余一律 unknown。
        """
        touched: set[str] = set()
        with self._lock:
            for key in self.attempts:
                touched.add(key[0])
            for collection in (self.findings, self.candidates.values()):
                for item in collection:
                    if item.url:
                        touched.add(normalize_endpoint(item.url))
            for entry in self.coverage.values():
                # `not_tested` / `blocked` 是"**没测**"的记录，不能当成覆盖过：
                # 把它们算进来，会让跨运行 diff 拿"明确记录为未测"的端点去判"疑似已修复"。
                if str(entry.get("status") or "") in ("not_tested", "blocked"):
                    continue
                match = re.search(r"https?://\S+", str(entry.get("target") or ""))
                if match:
                    touched.add(normalize_endpoint(match.group(0)))
        return {url for url in touched if url}

    def reported_endpoints(self) -> set[str]:
        """覆盖记录里标了 `reported` 的端点——**本轮在这里观察到过问题**。

        为什么单独取出来：模型有时用 `record_coverage(status="reported")` 记录"我已上报"，
        却没有真的调 record_finding（实测发生过：`/api/users` 未授权在覆盖里标了 reported、
        但 findings 里没有它）。跨运行 diff 若只看 findings，就会把上一次的同位置结论判成
        "疑似已修复"——**明明这次也看到了问题**。所以 reported 的端点必须参与判据。
        """
        found: set[str] = set()
        with self._lock:
            for entry in self.coverage.values():
                if str(entry.get("status") or "") != "reported":
                    continue
                match = re.search(r"https?://\S+", str(entry.get("target") or ""))
                if match:
                    found.add(normalize_endpoint(match.group(0)))
        return {url for url in found if url}

    def _param_universe(self) -> tuple[set[tuple[str, str]], list[tuple[str, str]]]:
        """参数宇宙：`(被试过的集合, 全部 (端点, 参数) 列表)`。

        参数从哪里来（**四个来源都必须算**，否则闸门会因为"侦察没登记参数"而静默放行）：
        1. `Endpoint.params` —— crawl/表单/fuzz 登记进来的；
        2. URL query 里的参数名 —— 端点是以 `/login?username=x` 形式登记的；
        3. 表单参数（POST，URL 里看不到）；
        4. attempt 记录里的参数 —— 试过就等于存在（不必再登记一次）。

        "被试过"的判据：attempt 里出现过该 `(端点, 参数)`，或已经出过带 param 的
        finding/候选（出了结论当然说明打过）。
        """
        with self._lock:
            attempted: set[tuple[str, str]] = {
                (key[0], key[1])
                for key, item in self.attempts.items()
                if item.outcome != "error"
            }
            for collection in (self.findings, self.candidates.values()):
                for item in collection:
                    if item.url and item.param:
                        attempted.add((normalize_endpoint(item.url), str(item.param)))

            pairs: list[tuple[str, str]] = []
            seen: set[tuple[str, str]] = set()

            def consider(url: str, param: str) -> None:
                key = (normalize_endpoint(url) or str(url), str(param or "").strip())
                if not key[0] or not key[1] or key in seen:
                    return
                seen.add(key)
                pairs.append(key)

            for url, endpoint in self.endpoints.items():
                for param in endpoint.params:
                    consider(url, param)
                for param in param_names(url):
                    consider(url, param)
            for form in self.forms.values():
                for param in form.get("params") or []:
                    consider(str(form.get("url") or ""), param)
            for key in self.attempts:
                if key[1]:
                    consider(key[0], key[1])
        return attempted, pairs

    def param_coverage(self) -> tuple[int, int]:
        """`(被试过的参数个数, 已登记参数总数)`。"""
        attempted, pairs = self._param_universe()
        tried = sum(1 for key in pairs if key in attempted)
        return tried, len(pairs)

    def unattacked_params(self, limit: int | None = None) -> list[tuple[str, str]]:
        """登记了参数、但**从未被任何 attempt 攻击过**的 `(端点, 参数)`。

        与 `untested_endpoints()` 的区别：那个判据是"端点被请求过没有"，这个判据是
        "**参数被试过没有**"。实测踩过：侦察子代理 GET 过 `/ping?ip=1`、`/ssti?name=x`
        （端点因此算"已覆盖"），但没人对 `ip` / `name` 做过注入尝试——报告显示 100% 覆盖，
        命令注入与 SSTS 却根本没测。这是比"端点没碰过"更隐蔽的一类盲区。

        排序：高价值路径优先（login/search/detail…），再按路径浅→字典序。
        """
        attempted, pairs = self._param_universe()
        pending = [key for key in pairs if key not in attempted]
        order = {url: index for index, url in enumerate(sort_urls({url for url, _ in pending}))}
        pending.sort(key=lambda item: (order.get(item[0], 999), item[1]))
        return pending[:limit] if limit else pending

    def untested_endpoints(self, limit: int = 40) -> list[str]:
        """还没被任何 attempt 覆盖过的端点（优先高价值），用于任务计划。"""
        with self._lock:
            tried = {key[0] for key, item in self.attempts.items() if item.outcome != "error"}
            pending = [url for url in self.endpoints if url not in tried]
        return sort_urls(pending, limit)

    def to_llm_summary(self, endpoint_limit: int = 12, param_limit: int = 10) -> str:
        """压缩成一段纯文本（喂给规划 / 复核阶段的提示词）。"""
        with self._lock:
            endpoints = list(self.endpoints.values())
            forms = list(self.forms.values())
            tech = dict(self.tech)
            notes = list(self.notes)[-8:]
            attempts = list(self.attempts.values())
            findings = list(self.findings)
            candidates = list(self.candidates.values())

        ranked = sort_urls([item.url for item in endpoints])
        by_url = {item.url: item for item in endpoints}
        lines = [f"目标：{self.target or '（未设置）'}（模式 {self.mode}）"]
        if tech:
            lines.append("技术栈：" + "; ".join(f"{k}={v}" for k, v in list(tech.items())[:8]))
        lines.append(f"已发现端点 {len(endpoints)} 个，展示 {min(endpoint_limit, len(ranked))} 个：")
        for url in ranked[:endpoint_limit]:
            item = by_url[url]
            params = ",".join(item.params[:param_limit]) or "-"
            status = f" HTTP{item.status}" if item.status else ""
            lines.append(f"  {url}{status} 参数[{params}] 来源[{item.source or '-'}]")
        if len(ranked) > endpoint_limit:
            lines.append(f"  ...（另有 {len(ranked) - endpoint_limit} 个端点）")
        if forms:
            lines.append("表单：")
            for form in forms[:8]:
                lines.append(f"  {form['method']} {form['url']} 参数[{','.join(form['params'][:param_limit])}]")
        if self.extra_paths:
            lines.append("探测命中路径：" + ", ".join(self.extra_paths[:12]))
        hit_lines = [
            f"  {a.endpoint} 参数[{a.param}] 类别[{a.category}]"
            for a in attempts if a.outcome == "signal"
        ]
        if hit_lines:
            lines.append(f"已有疑似信号 {len(hit_lines)} 条：")
            lines.extend(hit_lines[:10])
        if candidates:
            lines.append(f"待复核候选 {len(candidates)} 条：")
            for item in candidates[:8]:
                lines.append(f"  {item.id} {item.title}（{item.severity}, {item.vuln_type or '-'}）")
        if findings:
            lines.append(f"已入库漏洞 {len(findings)} 条：")
            for item in findings[:8]:
                lines.append(f"  {item.id} {item.title}（{item.severity}）")
        if self.agent_notes:
            lines.append("其他子代理留下的线索：")
            lines.extend(f"  {item}" for item in self.note_lines(6))
        if self.coverage:
            summary = self.coverage_summary()
            lines.append("覆盖情况：" + "，".join(f"{k}={v}" for k, v in sorted(summary.items())))
        if notes:
            lines.append("观察记录：")
            lines.extend(f"  {note}" for note in notes)
        return "\n".join(lines)

    # ---------- 统计 / 持久化 ----------

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "endpoints": len(self.endpoints),
                "forms": len(self.forms),
                "attempts": len(self.attempts),
                "signals": sum(1 for a in self.attempts.values() if a.outcome == "signal"),
                "candidates": len(self.candidates),
                "findings": len(self.findings),
                "coverage": len(self.coverage),
                "notes": len(self.agent_notes),
            }

    def covered_owasp(self) -> dict[str, int]:
        """按 OWASP 类别统计已入库漏洞数量（报告覆盖矩阵用）。"""
        mapping = {
            "A01": ("越权", "idor", "访问控制", "未授权"),
            "A02": ("加密", "明文", "密钥", "敏感信息"),
            "A03": ("注入", "sqli", "sql", "xss", "ssti", "命令注入", "遍历"),
            "A05": ("配置", "安全头", "敏感文件", "报错", "信息泄露"),
            "A06": ("组件", "版本", "cve"),
            "A07": ("认证", "凭据", "弱口令", "cookie", "会话"),
            "A10": ("ssrf", "服务端请求"),
        }
        counts = {key: 0 for key in mapping}
        for item in self.verified_findings():
            text = f"{item.vuln_type} {item.title} {item.description}".lower()
            for code, tokens in mapping.items():
                if any(token in text for token in tokens):
                    counts[code] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "target": self.target,
                "mode": self.mode,
                "started_at": self.started_at,
                "endpoints": [asdict(item) for item in self.endpoints.values()],
                "forms": list(self.forms.values()),
                "tech": dict(self.tech),
                "notes": list(self.notes),
                "extra_paths": list(self.extra_paths),
                "attempts": [asdict(item) for item in self.attempts.values()],
                "coverage": list(self.coverage.values()),
                "agent_notes": list(self.agent_notes),
                "candidates": [item.to_dict() | {"dedupe_key": item.dedupe_key} for item in self.candidates.values()],
                "findings": [item.to_dict() | {"dedupe_key": item.dedupe_key} for item in self.findings],
                "api_specs": list(self.api_specs),
                "api_spec_endpoints": sorted(self.api_spec_endpoints),
                "api_spec_params": [list(pair) for pair in self.api_spec_params],
                "stats": self.stats(),
            }

    def save(self, path: str | Path | None = None) -> Path | None:
        """把攻面落盘（供二次运行复用）。失败不抛错，返回 None。"""
        target = Path(path) if path else self.path
        if target is None:
            return None
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            return None
        return target

    @classmethod
    def load(cls, path: str | Path, target: str = "", mode: str = "blackbox") -> AttackSurface:
        """从磁盘恢复攻面；文件不存在或损坏时返回空攻面。"""
        surface = cls(target=target, mode=mode, path=Path(path))
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return surface
        for item in raw.get("endpoints", []) or []:
            key = surface.add_endpoint(
                str(item.get("url") or ""),
                methods=item.get("methods") or [],
                params=item.get("params") or [],
                source=str(item.get("source") or "restored"),
                status=int(item.get("status") or 0),
                note=str(item.get("note") or ""),
            )
            if key is None:
                continue
        for item in raw.get("forms", []) or []:
            surface.add_form(
                str(item.get("url") or ""),
                str(item.get("method") or "GET"),
                str(item.get("url") or ""),
                item.get("params") or [],
            )
        for name, value in (raw.get("tech") or {}).items():
            surface.add_tech(str(name), str(value))
        for note in raw.get("notes", []) or []:
            surface.add_note(str(note))
        for entry in raw.get("coverage", []) or []:
            surface.record_coverage(
                str(entry.get("target") or ""),
                str(entry.get("status") or "no_issue_found"),
                detail=str(entry.get("detail") or ""),
                owasp=str(entry.get("owasp") or ""),
            )
        for entry in raw.get("agent_notes", []) or []:
            surface.add_agent_note(str(entry.get("worker") or "?"), str(entry.get("text") or ""))
        surface.add_extra_paths(raw.get("extra_paths") or [])
        for item in raw.get("attempts", []) or []:
            surface.mark_attempt(
                str(item.get("endpoint") or ""),
                str(item.get("category") or ""),
                param=str(item.get("param") or ""),
                payload=str(item.get("payload") or ""),
                outcome=str(item.get("outcome") or "no_signal"),
                detail=str(item.get("detail") or ""),
            )
        for item in raw.get("findings", []) or []:
            surface.findings.append(_finding_from_dict(item, default_status="verified"))
        for item in raw.get("candidates", []) or []:
            surface.candidates[str(item.get("id") or surface.next_finding_id())] = _finding_from_dict(
                item, default_status="candidate"
            )
        # API 合约导入元信息（不重新解析规范——离线重渲染不该依赖原始规范文件）
        surface.api_specs = [item for item in (raw.get("api_specs") or []) if isinstance(item, dict)]
        surface.api_spec_endpoints = {
            str(item) for item in (raw.get("api_spec_endpoints") or []) if item
        }
        surface.api_spec_params = [
            (str(item[0]), str(item[1]))
            for item in (raw.get("api_spec_params") or [])
            if isinstance(item, (list, tuple)) and len(item) == 2
        ]
        return surface

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        stats = self.stats()
        return (
            f"<AttackSurface {self.target or '-'} endpoints={stats['endpoints']} "
            f"candidates={stats['candidates']} findings={stats['findings']}>"
        )


_KNOWN_FINDING_FIELDS = {
    "id", "title", "severity", "confidence", "evidence", "description", "remediation",
    "vuln_type", "url", "param", "status", "verified_by", "verification",
    "dedupe_key", "duplicate_of", "at", "merged_count",
}


def _finding_from_dict(data: dict[str, Any], default_status: str = "candidate") -> Finding:
    """从 dict 还原 Finding，未知字段收进 extra（保真 round-trip）。"""
    extra = {
        key: value for key, value in data.items()
        if key not in _KNOWN_FINDING_FIELDS and value not in (None, "", [], {})
    }
    merged = data.get("merged_count")
    if merged:
        extra["merged_count"] = merged
    return Finding(
        id=str(data.get("id") or ""),
        title=str(data.get("title") or ""),
        severity=str(data.get("severity") or "info").lower(),
        confidence=str(data.get("confidence") or ""),
        evidence=str(data.get("evidence") or ""),
        description=str(data.get("description") or ""),
        remediation=str(data.get("remediation") or ""),
        vuln_type=str(data.get("vuln_type") or ""),
        url=str(data.get("url") or ""),
        param=str(data.get("param") or ""),
        status=str(data.get("status") or default_status),
        verified_by=str(data.get("verified_by") or ""),
        verification=str(data.get("verification") or ""),
        dedupe_key=str(data.get("dedupe_key") or ""),
        duplicate_of=str(data.get("duplicate_of") or ""),
        extra=extra,
        at=float(data.get("at") or time.time()),
    )


def finding_from_dict(data: dict[str, Any], default_status: str = "candidate") -> Finding:
    """公开的 dict → Finding 还原（供报告合并阶段使用）。"""
    return _finding_from_dict(data, default_status)
