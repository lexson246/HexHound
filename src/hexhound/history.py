"""任务历史：把 `~/.hexhound/runs/<host>-<ts>/` 里的产物目录读成"能看的历史"。

存在的原因：审计结果原先只在**内存**里（`STATE`），程序一关就没了。
`~/.hexhound/runs/` 其实一直有产物，但没有入口可看——用户想复盘上一次跑了什么、
花了多少、报告在哪，只能自己去翻目录。这里给出一个**只读**入口。

两条硬约束（都属于"证据不能被事后改写"）：

1. **只看磁盘**：列表与详情都从产物目录读取，不调用模型、不访问目标。
   复盘历史绝不能产生新的流量或费用。
2. **报告优先用当时写下的那一份**（`report.md`），没有才用
   `snapshot.json` 离线重渲染。重渲染是"尽力而为"，并且会在报告里写明
   它是重建的——不能让重建的报告看起来像原始报告。
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .memory import data_home

#: 列表里最多回多少条（目录可能很多，界面不需要全部）。
DEFAULT_LIMIT = 30

#: 一次运行的状态取值（与界面文案一致）。
STATUS_DONE = "done"
STATUS_PARTIAL = "partial"
STATUS_UNKNOWN = "unknown"

STATUS_LABEL = {
    STATUS_DONE: "已完成",
    STATUS_PARTIAL: "未完成（中断或异常）",
    STATUS_UNKNOWN: "状态未知",
}


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _iso(mtime: float) -> str:
    try:
        return datetime.fromtimestamp(mtime).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return ""


#: 这些收尾原因说明"这次没跑完"，历史里必须显示为未完成。
PARTIAL_FINISH_REASONS = frozenset({
    "cancelled", "stopped", "budget", "supervisor_abort", "provider_error",
    "failed", "closing_no_finish",
})

#: 报告里的中断标记（用户主动停止时写入正文，见 gui._mark_partial）。
INTERRUPTED_MARKERS = ("本次运行被中断", "报告不完整")


def _status_of(run_dir: Path) -> str:
    """判断这次运行是否完整收尾。

    三条判据（按可靠性排序）：

    1. **报告正文里的中断标记**——最直接：报告说"不完整"就是不完整；
    2. **记录下来的收尾原因**（`snapshot.json` 的 `result.finish_reason` 或
       `run.json` 的 `finish_reason`）落在 `PARTIAL_FINISH_REASONS` 里；
    3. 没有 `snapshot.json`（中断/异常时编排器可能来不及写）。

    为什么要看前两条：编排器在用户按停止时只是跳出波次循环、然后照常收尾，
    于是 `snapshot.json` 照样会写出来——只看"有没有快照"会把一次被中断的运行
    说成"已完成"（第四轮实测踩到）。宁可说"未完成"，也不能把半份结果说成完整审计。
    """
    if not (run_dir / "run.json").exists() and not (run_dir / "snapshot.json").exists():
        return STATUS_UNKNOWN
    report = run_dir / "report.md"
    try:
        head = report.read_text(encoding="utf-8", errors="replace")[:4000] if report.exists() else ""
    except OSError:
        head = ""
    if any(marker in head for marker in INTERRUPTED_MARKERS):
        return STATUS_PARTIAL
    snapshot = _load_json(run_dir / "snapshot.json")
    recorded = str((snapshot.get("result") or {}).get("finish_reason") or "")
    if not recorded:
        recorded = str(_load_json(run_dir / "run.json").get("finish_reason") or "")
    if recorded in PARTIAL_FINISH_REASONS:
        return STATUS_PARTIAL
    if not (run_dir / "snapshot.json").exists():
        return STATUS_PARTIAL if (run_dir / "run.json").exists() else STATUS_UNKNOWN
    return STATUS_DONE


def list_runs(
    *, home: Path | None = None, limit: int = DEFAULT_LIMIT, target: str = ""
) -> list[dict[str, Any]]:
    """列出历史运行（最新的在前）。只读磁盘。"""
    runs_root = data_home(home) / "runs"
    if not runs_root.is_dir():
        return []
    entries: list[dict[str, Any]] = []
    try:
        candidates = [item for item in runs_root.iterdir() if item.is_dir()]
    except OSError:
        return []
    for run_dir in candidates:
        summary = _load_json(run_dir / "run.json")
        recorded_target = str(summary.get("target") or "")
        if target and recorded_target != target:
            continue
        try:
            mtime = run_dir.stat().st_mtime
        except OSError:
            mtime = 0.0
        usage = summary.get("usage") or {}
        stats = summary.get("stats") or {}
        report = run_dir / "report.md"
        legacy_report = run_dir / "artifacts" / "report.md"
        report_path = report if report.exists() else (legacy_report if legacy_report.exists() else None)
        entries.append(
            {
                "id": run_dir.name,
                "dir": str(run_dir),
                "target": recorded_target,
                "mode": str(summary.get("mode") or ""),
                "status": _status_of(run_dir),
                "finished_at": _iso(mtime),
                "findings": int(stats.get("findings") or 0),
                "endpoints": int(stats.get("endpoints") or 0),
                "tokens": int(usage.get("total_tokens") or 0),
                "cost": float(usage.get("estimated_cost") or 0.0),
                "llm_calls": int(usage.get("llm_calls") or 0),
                "tool_calls": int(usage.get("tool_calls") or 0),
                #: 这次运行的报告文件在磁盘上的位置（界面直接显示，省得用户去翻目录）。
                "report_path": str(report_path) if report_path else "",
                "report_available": report_path is not None,
                "snapshot_available": (run_dir / "snapshot.json").exists(),
                "trace_available": (run_dir / "trace.jsonl").exists(),
            }
        )
    entries.sort(key=lambda item: (item["finished_at"], item["id"]), reverse=True)
    return entries[: max(1, int(limit))] if limit else entries


def find_run(run_id: str, *, home: Path | None = None) -> Path | None:
    """按目录名定位一次运行（拒绝路径穿越：只接受 `runs/` 下的直接子目录名）。"""
    name = str(run_id or "").strip()
    if not name or name != Path(name).name or name in (".", ".."):
        return None
    candidate = data_home(home) / "runs" / name
    return candidate if candidate.is_dir() else None


def run_detail(run_id: str, *, home: Path | None = None) -> dict[str, Any] | None:
    """一次运行的详情（含报告文本）。找不到返回 `None`。"""
    run_dir = find_run(run_id, home=home)
    if run_dir is None:
        return None
    entry = next(
        (item for item in list_runs(home=home, limit=0) if item["id"] == run_dir.name),
        {"id": run_dir.name, "dir": str(run_dir), "status": STATUS_UNKNOWN},
    )
    markdown, source = render_run_report(run_dir)
    detail = dict(entry)
    detail["markdown"] = markdown
    detail["markdown_source"] = source
    return detail


def run_findings(run_id: str, *, home: Path | None = None) -> list[dict[str, Any]]:
    """读回某次运行的发现列表（离线，不调模型、不访问目标）。

    来源优先级：`snapshot.json`（字段最全，含去重指纹）→ `surface.json`
    （旧格式：findings 在 surface 里）。两者都没有时返回空列表——
    "这次运行没留下发现"与"产物读不出来"在界面上是两件事，
    因此调用方还会拿到 `source` 字段（见 `run_findings_with_source`）。
    """
    return run_findings_with_source(run_id, home=home)[0]


def run_findings_with_source(
    run_id: str, *, home: Path | None = None
) -> tuple[list[dict[str, Any]], str]:
    """读回某次运行的发现列表，并说明是从哪读到的。

    返回值 `(findings, source)`，`source` ∈ {snapshot, surface, none}。
    """
    run_dir = find_run(run_id, home=home)
    if run_dir is None:
        return [], "none"
    snapshot_file = run_dir / "snapshot.json"
    if snapshot_file.exists():
        payload = _load_json(snapshot_file)
        result = payload.get("result") or {}
        findings = result.get("findings")
        if isinstance(findings, list):
            return [item for item in findings if isinstance(item, dict)], "snapshot"
    surface_file = run_dir / "surface.json"
    if surface_file.exists():
        payload = _load_json(surface_file)
        findings = payload.get("findings")
        if isinstance(findings, list):
            return [item for item in findings if isinstance(item, dict)], "surface"
        # 旧格式把发现放在 candidates/verified 两个列表里
        merged: list[dict[str, Any]] = []
        for key in ("verified", "candidates"):
            items = payload.get(key)
            if isinstance(items, list):
                merged.extend(item for item in items if isinstance(item, dict))
        if merged:
            return merged, "surface"
    return [], "none"


def run_summary(run_id: str, *, home: Path | None = None) -> dict[str, Any]:
    """一次运行的汇总字段（目标/模式/用量/统计），找不到返回空字典。"""
    run_dir = find_run(run_id, home=home)
    if run_dir is None:
        return {}
    return _load_json(run_dir / "run.json")


def render_run_report(run_dir: Path) -> tuple[str, str]:
    """取回这次运行的报告文本，返回 `(markdown, 来源)`。

    来源取值：
    * `report`——当时写下的那一份（最可信）；
    * `snapshot`——用 `snapshot.json` 离线重渲染（报告里会写明是重建的）；
    * `none`——两者都没有。

    查找顺序：运行目录根的 `report.md`（现在的写法）→ `artifacts/report.md`
    （早期构建把副本写进了子目录）→ 快照重渲染。
    两个位置都认，是为了让**已经跑过的历史运行**也能显示原文，
    而不是把"路径约定变过"变成用户看到的"原文丢了"。
    """
    for candidate in (run_dir / "report.md", run_dir / "artifacts" / "report.md"):
        if candidate.exists():
            try:
                return candidate.read_text(encoding="utf-8"), "report"
            except OSError:
                continue
    markdown = _rerender_from_snapshot(run_dir)
    if markdown:
        return markdown, "snapshot"
    return "", "none"


def _rerender_from_snapshot(run_dir: Path) -> str:
    """用快照离线重渲染报告。**不碰网络、不调模型**。"""
    if not (run_dir / "snapshot.json").exists():
        return ""
    try:
        from .agent import AgentResult
        from .report import to_markdown
        from .surface import AttackSurface
        from .trace import restore_run

        restored = restore_run(run_dir)
        if not restored.ok:
            return ""
        payload = restored.payload
        target = str(payload.get("target") or "")
        surface_file = run_dir / "surface.json"
        surface = (
            AttackSurface.load(surface_file, target=target, mode="blackbox")
            if surface_file.exists()
            else AttackSurface(target=target, mode="blackbox")
        )
        result = AgentResult.from_snapshot(payload.get("result") or {}, surface=surface)
        goal = str(payload.get("goal") or f"离线重渲染自 {run_dir.name}")
        markdown = to_markdown(result, goal)
    except Exception:  # noqa: BLE001 重渲染失败不该让"看历史"整体不可用
        return ""
    banner = (
        f"> 本报告由运行产物**离线重渲染**自 `{run_dir.name}`（未调用模型、未访问目标）。\n"
        "> 当时的原始报告文件不存在，内容可能与当日交付的报告略有差异。\n\n"
    )
    return banner + markdown
