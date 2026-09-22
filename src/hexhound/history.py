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


def _status_of(run_dir: Path) -> str:
    """判断这次运行是否完整收尾。

    判据：有 `snapshot.json` 且没有"未收尾标记"。中断/异常时收尾路径仍会写
    报告，但 `snapshot.json` 只在编排器正常收口时写（见 orchestrator 尾部），
    因此缺它就是没跑完。状态宁可说"未完成"，也不要把半份结果说成完整审计。
    """
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
                "report_available": report.exists(),
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


def render_run_report(run_dir: Path) -> tuple[str, str]:
    """取回这次运行的报告文本，返回 `(markdown, 来源)`。

    来源取值：
    * `report`——当时写下的那一份（最可信）；
    * `snapshot`——用 `snapshot.json` 离线重渲染（报告里会写明是重建的）；
    * `none`——两者都没有。
    """
    report = run_dir / "report.md"
    if report.exists():
        try:
            return report.read_text(encoding="utf-8"), "report"
        except OSError:
            pass
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
