"""记忆层：一次运行的产物目录（artifacts）+ 跨运行的主机记忆（host memory）。

对标 PentAGI 的三层记忆（long-term vector / working context / episodic history），
但用零依赖的落地方式实现：

- **working context**  → `AttackSurface`（见 surface.py，进程内共享 + 落盘 surface.json）
- **episodic history** → `TaskLedger`（哪个任务做了什么、花了多少、找到什么）
- **long-term memory** → `HostMemory`（`~/.hexhound/memory/<host>.json`：
  历次运行沉淀的指纹、有效参数类别、已验证漏洞摘要，下次规划时作为简报注入）

另外 `RunArtifacts` 负责把每次运行的证据落盘到 `~/.hexhound/runs/<host>-<ts>/`，
包括可复现的 PoC 脚本（Strix 的「可复现 PoC 才算数」）。
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_HOME = Path.home() / ".hexhound"


def data_home(home: Path | None = None) -> Path:
    """数据根目录：显式参数 > `HEXHOUND_HOME` 环境变量 > `~/.hexhound`。

    支持环境变量覆盖是为了让测试/CI 用临时目录，不污染真实运行产物，
    也方便把产物放到指定盘符。
    """
    if home is not None:
        return Path(home)
    override = os.getenv("HEXHOUND_HOME", "").strip()
    return Path(override) if override else DEFAULT_HOME


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _safe_name(text: str) -> str:
    keep = [ch if (ch.isalnum() or ch in "-_.") else "-" for ch in str(text or "target")]
    return "".join(keep).strip("-")[:60] or "target"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict[str, Any]) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        return False
    return True


@dataclass
class TaskRecord:
    """一次子代理任务的执行记录（episodic history 的一条）。"""

    task_id: str
    role: str
    objective: str
    status: str = "pending"  # pending / running / done / failed / skipped
    steps: int = 0
    llm_calls: int = 0
    tool_calls: int = 0
    total_tokens: int = 0
    estimated_cost: float = 0.0
    summary: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0
    error: str = ""
    model: str = ""  # 该子任务实际使用的 提供商/模型（便于复现一次运行）

    def duration(self) -> float:
        if not self.started_at:
            return 0.0
        end = self.finished_at or time.time()
        return round(end - self.started_at, 1)


class TaskLedger:
    """任务台账（线程安全）：编排器与子代理都往里写。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, TaskRecord] = {}
        self._order: list[str] = []

    def add(self, task_id: str, role: str, objective: str, model: str = "") -> TaskRecord:
        with self._lock:
            record = TaskRecord(task_id=task_id, role=role, objective=objective, model=model)
            self._records[task_id] = record
            self._order.append(task_id)
            return record

    def start(self, task_id: str) -> None:
        with self._lock:
            record = self._records.get(task_id)
            if record is not None:
                record.status = "running"
                record.started_at = time.time()

    def update_usage(
        self,
        task_id: str,
        *,
        steps: int = 0,
        llm_calls: int = 0,
        tool_calls: int = 0,
        total_tokens: int = 0,
        estimated_cost: float = 0.0,
    ) -> None:
        with self._lock:
            record = self._records.get(task_id)
            if record is None:
                return
            record.steps += int(steps)
            record.llm_calls += int(llm_calls)
            record.tool_calls += int(tool_calls)
            record.total_tokens += int(total_tokens)
            record.estimated_cost += float(estimated_cost)

    def finish(self, task_id: str, status: str = "done", summary: str = "", error: str = "") -> None:
        with self._lock:
            record = self._records.get(task_id)
            if record is None:
                return
            record.status = status
            record.summary = str(summary or "")[:500]
            record.error = str(error or "")[:300]
            record.finished_at = time.time()

    def records(self) -> list[TaskRecord]:
        with self._lock:
            return [self._records[tid] for tid in self._order if tid in self._records]

    def to_dicts(self) -> list[dict[str, Any]]:
        result = []
        for record in self.records():
            data = asdict(record)
            data["duration"] = record.duration()
            result.append(data)
        return result

    def summary_lines(self) -> list[str]:
        lines = []
        for record in self.records():
            flag = {"done": "[OK]", "failed": "[XX]", "skipped": "[--]", "running": "[..]"}.get(record.status, "[??]")
            lines.append(
                f"{flag} [{record.task_id}] {record.role}: {record.objective[:70]} "
                f"({record.steps} 步 / {record.total_tokens} tokens / ¥{record.estimated_cost:.4f})"
                + (f" — {record.error}" if record.error else "")
            )
        return lines


class HostMemory:
    """跨运行的主机记忆：`~/.hexhound/memory/<host>.json`。"""

    def __init__(self, host: str, home: Path | None = None) -> None:
        self.host = _safe_name(host)
        self.home = data_home(home)
        self.path = self.home / "memory" / f"{self.host}.json"
        self.data: dict[str, Any] = _read_json(self.path) or {
            "host": host,
            "runs": 0,
            "tech": {},
            "notes": [],
            "param_lessons": {},
            "findings": [],
            "endpoints": 0,
            "updated_at": "",
        }
        self._lock = threading.Lock()
        self.data.setdefault("tech", {})
        self.data.setdefault("notes", [])
        self.data.setdefault("param_lessons", {})
        self.data.setdefault("findings", [])
        self.data.setdefault("endpoints", 0)

    # ---------- 写入 ----------

    def record_run(
        self,
        *,
        tech: dict[str, str] | None = None,
        notes: Iterable[str] = (),
        attempts: Iterable[dict[str, Any]] = (),
        findings: Iterable[dict[str, Any]] = (),
        endpoints: int = 0,
    ) -> None:
        """把一次运行沉淀进长期记忆（幂等：同一条内容不重复堆积）。"""
        with self._lock:
            self.data["runs"] = int(self.data.get("runs", 0)) + 1
            self.data["updated_at"] = _now_iso()
            self.data["endpoints"] = max(int(self.data.get("endpoints", 0)), int(endpoints))
            for name, value in (tech or {}).items():
                if value:
                    self.data["tech"][str(name)] = str(value)
            existing_notes = set(self.data["notes"])
            for note in notes:
                note = str(note or "").strip()[:200]
                if note and note not in existing_notes:
                    self.data["notes"].append(note)
                    existing_notes.add(note)
            self.data["notes"] = self.data["notes"][-40:]
            for attempt in attempts:
                if str(attempt.get("outcome") or "") != "signal":
                    continue
                param = str(attempt.get("param") or "").strip()
                category = str(attempt.get("category") or "").strip()
                if not param or not category:
                    continue
                bucket = self.data["param_lessons"].setdefault(param.lower(), {})
                bucket[category] = int(bucket.get(category, 0)) + 1
            seen = {(str(f.get("id") or ""), str(f.get("title") or "")) for f in self.data["findings"]}
            for finding in findings:
                key = (str(finding.get("id") or ""), str(finding.get("title") or ""))
                if key in seen:
                    continue
                self.data["findings"].append(
                    {
                        "id": str(finding.get("id") or ""),
                        "title": str(finding.get("title") or "")[:160],
                        "severity": str(finding.get("severity") or ""),
                        "vuln_type": str(finding.get("vuln_type") or ""),
                        "url": str(finding.get("url") or "")[:200],
                        "status": str(finding.get("status") or ""),
                        # param / dedupe_key 必须一起存：跨运行 diff 靠指纹比对判断
                        # "仍存在 / 已修复"。历史文件里没有这两个字段时，diff 会退化为
                        # 「类别+路径」的放宽匹配（见 diff._coarse）。
                        "param": str(finding.get("param") or "")[:64],
                        "dedupe_key": str(finding.get("dedupe_key") or "")[:160],
                        "at": _now_iso(),
                    }
                )
                seen.add(key)
            self.data["findings"] = self.data["findings"][-60:]
        self.save()

    def save(self) -> bool:
        with self._lock:
            payload = json.loads(json.dumps(self.data, ensure_ascii=False))
        return _write_json(self.path, payload)

    # ---------- 读取 ----------

    def top_param_lessons(self, limit: int = 8) -> list[str]:
        """历史上命中率高的「参数 → 类别」组合（规划时优先复用）。"""
        with self._lock:
            lessons = dict(self.data.get("param_lessons", {}))
        scored: list[tuple[int, str]] = []
        for param, categories in lessons.items():
            for category, count in (categories or {}).items():
                if int(count) > 0:
                    scored.append((int(count), f"{param} → {category}（历史命中 {count} 次）"))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [text for _, text in scored[:limit]]

    def known_findings(self, limit: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.data.get("findings", []))[-limit:]

    # ---------- 清理（跨运行 diff 的信噪比维护）----------

    def forget(
        self,
        *,
        ids: Iterable[str] = (),
        before: str = "",
        reset: bool = False,
    ) -> dict[str, int]:
        """删除历史条目：按 id / 按上报时间 / 整体清空。

        为什么需要：`findings` 是只增不减的累积文件。里面混着旧版本格式、早期脚本模型
        试跑留下的条目，它们会在**每一次**跨运行 diff 里以"状态未知"重复出现，把真正
        的回归结论淹没。清理入口必须存在，否则 diff 用几次就没人看了。

        不清 `tech` / `param_lessons` / `notes`（那是"这个目标的经验"，与漏洞条目无关）；
        `reset=True` 才会把整个文件恢复成初始状态。
        """
        wanted = {str(item).strip() for item in ids if str(item).strip()}
        cutoff = str(before or "").strip()
        with self._lock:
            findings = list(self.data.get("findings", []))
            if reset:
                kept: list[dict[str, Any]] = []
            else:
                kept = []
                for item in findings:
                    if wanted and str(item.get("id") or "") in wanted:
                        continue
                    # 时间戳是 ISO 字符串，字典序即时间序；缺时间的条目在 --before 时不删
                    if cutoff and str(item.get("at") or "") and str(item["at"]) < cutoff:
                        continue
                    kept.append(item)
            removed = len(findings) - len(kept)
            self.data["findings"] = kept
            if reset:
                self.data["runs"] = 0
                self.data["updated_at"] = ""
        if removed or reset:
            self.save()
        return {"removed": removed, "kept": len(kept)}

    def stats(self) -> dict[str, Any]:
        """记忆概览：给 `hexhound memory` 与排障用。"""
        with self._lock:
            findings = list(self.data.get("findings", []))
            return {
                "host": self.data.get("host", ""),
                "path": str(self.path),
                "runs": int(self.data.get("runs", 0)),
                "endpoints": int(self.data.get("endpoints", 0)),
                "findings": len(findings),
                "tech": len(self.data.get("tech", {}) or {}),
                "notes": len(self.data.get("notes", []) or []),
                "updated_at": str(self.data.get("updated_at") or ""),
            }

    def briefing(self, limit: int = 6) -> str:
        """生成一段简报，注入规划提示词（长期记忆的落地形式）。"""
        with self._lock:
            runs = int(self.data.get("runs", 0))
            tech = dict(self.data.get("tech", {}))
            notes = list(self.data.get("notes", []))[-limit:]
            findings = list(self.data.get("findings", []))[-limit:]
        if not runs:
            return ""
        lines = [f"本目标历史运行 {runs} 次："]
        if tech:
            lines.append("  已知技术栈：" + "; ".join(f"{k}={v}" for k, v in list(tech.items())[:6]))
        lessons = self.top_param_lessons(4)
        if lessons:
            lines.append("  历史命中参数：" + "; ".join(lessons))
        if findings:
            lines.append("  历史已报漏洞：")
            lines.extend(
                f"    {item.get('id')} {item.get('title')}（{item.get('severity')}, {item.get('status')}）"
                for item in findings
            )
        if notes:
            lines.append("  历史观察：" + " | ".join(notes))
        return "\n".join(lines)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self.data, ensure_ascii=False))


class RunArtifacts:
    """一次运行的产物目录与落盘接口。"""

    def __init__(self, target: str, home: Path | None = None, enabled: bool = True) -> None:
        self.enabled = enabled
        self.home = data_home(home)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.dir = self.home / "runs" / f"{_safe_name(target)}-{stamp}"
        self.surface_path = self.dir / "surface.json"
        self.ledger_path = self.dir / "tasks.json"
        self.summary_path = self.dir / "run.json"
        if self.enabled:
            try:
                self.dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                self.enabled = False

    def write_artifact(self, name: str, content: str) -> str | None:
        """把任意文本内容写进产物目录（payload 字典 / 脚本片段 / 笔记）。"""
        if not self.enabled:
            return None
        safe = _safe_name(name)
        if "." not in safe:
            safe += ".txt"
        path = self.dir / "artifacts" / safe
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(content), encoding="utf-8")
        except OSError:
            return None
        return str(path)

    def write_poc(self, finding: dict[str, Any]) -> str | None:
        """把一条 finding 的证据写成可复现的 PoC 脚本（curl / python）。"""
        if not self.enabled:
            return None
        exchanges = finding.get("http_evidence") or []
        if not exchanges:
            return None
        finding_id = _safe_name(finding.get("id") or "finding")
        paths: list[str] = []
        try:
            script = self.dir / "poc" / f"{finding_id}.sh"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(_render_curl_poc(finding, exchanges), encoding="utf-8")
            paths.append(str(script))
            for exchange in exchanges:
                raw = self.dir / "poc" / f"{finding_id}_{exchange.get('id', 'R')}.http"
                raw.parent.mkdir(parents=True, exist_ok=True)
                raw.write_text(
                    _render_raw_exchange(exchange), encoding="utf-8"
                )
                paths.append(str(raw))
        except OSError:
            return None
        return paths[0] if paths else None

    def save_surface(self, surface: Any) -> str | None:
        if not self.enabled:
            return None
        path = surface.save(self.surface_path)
        return str(path) if path else None

    def save_summary(self, payload: dict[str, Any]) -> str | None:
        if not self.enabled:
            return None
        payload = dict(payload)
        payload.setdefault("generated_at", _now_iso())
        return str(self.summary_path) if _write_json(self.summary_path, payload) else None

    def save_ledger(self, ledger: TaskLedger) -> str | None:
        if not self.enabled:
            return None
        return str(self.ledger_path) if _write_json(self.ledger_path, {"tasks": ledger.to_dicts()}) else None


def _render_raw_exchange(exchange: dict[str, Any]) -> str:
    """把一次请求/响应快照渲染成原始 HTTP 文本。"""
    from urllib.parse import urlparse

    parsed = urlparse(str(exchange.get("url") or ""))
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    lines = [
        f"{exchange.get('method', 'GET')} {target} HTTP/1.1",
        f"Host: {parsed.netloc}",
    ]
    for key, value in (exchange.get("request_headers") or {}).items():
        if str(key).lower() == "host":
            continue
        lines.append(f"{key}: {value}")
    body = str(exchange.get("request_body") or "")
    if body:
        lines += ["", body]
    lines.append("")
    lines.append(f"HTTP/1.1 {exchange.get('status_code', 0)} {exchange.get('reason', '')}".rstrip())
    for key, value in (exchange.get("response_headers") or {}).items():
        lines.append(f"{key}: {value}")
    response_body = str(exchange.get("response_body") or "")
    if response_body:
        lines += ["", response_body]
    return "\n".join(lines) + "\n"


def _assertions_for(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """从 finding 的证据里推导出**可机器校验的断言**。

    这是 PoC 自校验的核心：与其生成"重放请求给你看"的脚本，不如让它自己判断
    "漏洞是否仍然成立"。断言来源（按可靠性排序）：
    1. 显式给出的 expected（模型/人工写的，最可靠）
    2. 响应状态码（500 型注入、200 型信息泄露）
    3. 响应体/工具输出里的特征串（SQL 报错、敏感文件特征、injectable 标记）
    """
    assertions: list[dict[str, Any]] = []

    for item in finding.get("expected") or []:
        if isinstance(item, dict) and item.get("type"):
            assertions.append(dict(item))

    for exchange in finding.get("http_evidence") or []:
        ref = str(exchange.get("id") or "")
        status = exchange.get("status_code")
        if status and not any(
            a.get("type") == "status" and a.get("ref") == ref for a in assertions
        ):
            assertions.append(
                {"type": "status", "ref": ref, "value": int(status),
                 "text": f"{ref} 仍返回 HTTP {status}"}
            )
        marker = _body_marker(str(exchange.get("response_body") or ""))
        if marker:
            assertions.append(
                {"type": "contains", "ref": ref, "value": marker,
                 "text": f"{ref} 响应仍包含 {marker[:50]!r}"}
            )

    for entry in finding.get("tool_evidence") or []:
        ref = str(entry.get("id") or "")
        output = str(entry.get("output") or "")
        low = output.lower()
        if "injectable" in low or "is vulnerable" in low:
            assertions.append(
                {"type": "contains", "ref": ref, "value": "injectable",
                 "text": f"{ref} 的工具输出仍显示 injectable"}
            )
        for token in ("back-end DBMS", "banner:", "Table: "):
            if token in output:
                assertions.append(
                    {"type": "contains", "ref": ref, "value": token,
                     "text": f"{ref} 的工具输出仍包含 {token!r}"}
                )
                break
    return assertions


#: 能区分"漏洞成立"与"正常响应"的特征串（要求足够具体，避免误判成永远成立）
_ASSERTION_MARKERS: tuple[str, ...] = (
    "SQL 错误", "sql syntax", "unrecognized token", "syntax error",
    "root:", "[extensions]", "nt authority\\", "uid=",
    "Traceback (most recent call last)", "stack trace",
    "idcard", "身份证", "hh_session",
)


def _body_marker(body: str) -> str:
    """从响应体里挑一个足够具体的特征串作为断言（挑不到返回空串）。"""
    lowered = str(body or "").lower()
    for marker in _ASSERTION_MARKERS:
        if marker.lower() in lowered:
            return marker
    return ""


def _render_curl_poc(finding: dict[str, Any], exchanges: list[dict[str, Any]]) -> str:
    """生成 shell PoC：重放证据请求**并断言漏洞是否仍然成立**。

    与"只重放"的区别：脚本自己判断结果并给出退出码——
    0 = 漏洞仍可复现，1 = 已修复/无法复现，2 = 请求都发不出去。
    这样它既能当复现脚本，也能当回归检查（修完再跑一次就知道有没有真修掉）。
    """
    assertions = _assertions_for(finding)
    lines = [
        "#!/usr/bin/env bash",
        "# HexHound PoC — 由 Agent 自动生成，仅用于授权测试目标。",
        f"# 漏洞：{finding.get('title', '')}",
        f"# 编号：{finding.get('id', '')}  严重度：{finding.get('severity', '')}",
        f"# 类型：{finding.get('vuln_type', '') or '-'}",
        f"# 验证方式：{finding.get('verification', '') or '(未记录)'}",
        f"# 受影响 URL：{finding.get('url', '') or '-'}",
        "#",
        "# 退出码：0 = 漏洞仍可复现；1 = 已修复或无法复现；2 = 请求失败（目标不可达）",
        "",
        "set -u",
        f'echo "== {finding.get("id", "finding")}: {finding.get("title", "")} =="',
        "PASS=0; FAIL=0; REQ_FAIL=0",
        "",
    ]
    for index, exchange in enumerate(exchanges, 1):
        method = str(exchange.get("method") or "GET").upper()
        url = str(exchange.get("url") or "")
        ref = str(exchange.get("id") or f"R{index}")
        headers = {
            str(k): str(v)
            for k, v in (exchange.get("request_headers") or {}).items()
            if str(k).lower() not in ("host", "content-length", "accept-encoding")
        }
        body = str(exchange.get("request_body") or "")
        lines.append(f'echo "-- 步骤 {index}：{method} {url}（证据 {ref}）"')
        command = [
            "curl -sS -i -o /tmp/hh_poc_body.txt -w '%{http_code}'",
            "-X", method, f"'{url}'",
        ]
        for key, value in headers.items():
            command.append(f"-H '{key}: {value}'")
        if body:
            command.append(f"--data-raw '{body}'")
        lines += [
            f"HTTP_CODE=$({' '.join(command)} 2>/dev/null)",
            'if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" = "000" ]; then',
            '  echo "   [跳过] 请求失败（目标不可达）"; REQ_FAIL=$((REQ_FAIL+1))',
            "else",
            '  echo "   实际状态码：$HTTP_CODE"',
        ]
        for assertion in assertions:
            if str(assertion.get("ref") or "") != ref:
                continue
            if assertion["type"] == "status":
                lines += [
                    f'  if [ "$HTTP_CODE" = "{assertion["value"]}" ]; then',
                    f'    echo "   [成立] {assertion["text"]}"; PASS=$((PASS+1))',
                    "  else",
                    f'    echo "   [不成立] 期望 HTTP {assertion["value"]}，实际 $HTTP_CODE"; '
                    "FAIL=$((FAIL+1))",
                    "  fi",
                ]
            elif assertion["type"] == "contains":
                needle = str(assertion["value"]).replace("'", "'\"'\"'")
                lines += [
                    f"  if grep -qF '{needle}' /tmp/hh_poc_body.txt 2>/dev/null; then",
                    f'    echo "   [成立] {assertion["text"]}"; PASS=$((PASS+1))',
                    "  else",
                    f'    echo "   [不成立] 响应里已找不到 {needle[:40]}"; FAIL=$((FAIL+1))',
                    "  fi",
                ]
        lines += ["fi", ""]
    lines += [
        'echo ""',
        'echo "== 结论：成立 $PASS 项 / 不成立 $FAIL 项 / 请求失败 $REQ_FAIL 项 =="',
        'if [ "$PASS" -gt 0 ] && [ "$FAIL" -eq 0 ]; then',
        '  echo ">>> 漏洞仍可复现（未修复）"; exit 0',
        'elif [ "$PASS" -eq 0 ] && [ "$FAIL" -gt 0 ]; then',
        '  echo ">>> 漏洞已修复或无法复现"; exit 1',
        "else",
        '  echo ">>> 请求失败：目标不可达或网络异常"; exit 2',
        "fi",
    ]
    return "\n".join(lines) + "\n"
