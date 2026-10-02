"""任务历史测试：历史只读本机产物，**不调模型、不访问目标**。

为什么这两条要写成断言：复盘历史时最容易顺手"重新跑一次"或"重新抓一次页面"，
那会凭空产生费用与流量，还会让"历史"变成不可信的东西。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound import history  # noqa: E402


def _make_run(
    home: Path,
    name: str,
    *,
    target: str = "http://127.0.0.1:5000",
    report: str | None = "## 报告\n\n正文\n",
    snapshot: bool = True,
    usage: dict | None = None,
) -> Path:
    run_dir = home / "runs" / name
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text(
        json.dumps(
            {
                "target": target,
                "mode": "blackbox",
                "usage": usage if usage is not None else {"total_tokens": 1234, "estimated_cost": 0.42},
                "stats": {"findings": 2, "endpoints": 7},
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    if report is not None:
        (run_dir / "report.md").write_text(report, encoding="utf-8")
    if snapshot:
        (run_dir / "snapshot.json").write_text(
            json.dumps({"schema_version": 2, "target": target, "goal": "g", "result": {}}),
            encoding="utf-8",
        )
    return run_dir


def test_list_runs_reads_disk_entries(tmp_path: Path) -> None:
    _make_run(tmp_path, "127.0.0.1-20260101-101010")
    _make_run(tmp_path, "127.0.0.1-20260102-101010", target="http://localhost:8080")
    runs = history.list_runs(home=tmp_path)
    assert len(runs) == 2
    entry = next(item for item in runs if item["target"] == "http://127.0.0.1:5000")
    assert entry["id"] == "127.0.0.1-20260101-101010"
    assert entry["findings"] == 2
    assert entry["endpoints"] == 7
    assert entry["tokens"] == 1234
    assert entry["cost"] == pytest.approx(0.42)
    assert entry["status"] == history.STATUS_DONE
    assert entry["report_available"] is True
    assert entry["finished_at"]


def test_missing_snapshot_marks_the_run_as_unfinished(tmp_path: Path) -> None:
    """没有 snapshot.json = 没正常收口 → 状态必须说"未完成"，不能说成完整审计。"""
    _make_run(tmp_path, "run-partial", snapshot=False)
    runs = history.list_runs(home=tmp_path)
    assert runs[0]["status"] == history.STATUS_PARTIAL
    assert history.STATUS_LABEL[runs[0]["status"]] != history.STATUS_LABEL[history.STATUS_DONE]


def test_list_is_empty_without_any_runs(tmp_path: Path) -> None:
    assert history.list_runs(home=tmp_path) == []


def test_interrupted_run_is_not_reported_as_done(tmp_path: Path) -> None:
    """被中断的运行必须显示"未完成"——哪怕 snapshot.json 已经写出来了。

    第四轮实测：用户在界面上按停止（或直接关窗口）时，编排器只是跳出波次循环、
    然后照常收尾，所以 `snapshot.json` 照样会生成；只看"有没有快照"会把一次
    被中断的运行说成"已完成"，而报告正文明明写着"不完整"。
    """
    run_dir = _make_run(tmp_path, "stopped-by-user")
    (run_dir / "report.md").write_text(
        "## 总结\n\n【本次运行被中断，报告不完整】\n", encoding="utf-8"
    )
    runs = history.list_runs(home=tmp_path)
    assert runs[0]["status"] == history.STATUS_PARTIAL
    assert history.STATUS_LABEL[runs[0]["status"]] != history.STATUS_LABEL[history.STATUS_DONE]


def test_recorded_finish_reason_decides_without_report_marker(tmp_path: Path) -> None:
    """报告正文没有标记时也要能判：看记录下来的收尾原因。"""
    run_dir = _make_run(tmp_path, "cancelled-reason", report=None)
    (run_dir / "snapshot.json").write_text(
        json.dumps({"schema_version": 2, "result": {"finish_reason": "cancelled"}}),
        encoding="utf-8",
    )
    done_dir = _make_run(tmp_path, "normal-finish", report=None)
    (done_dir / "snapshot.json").write_text(
        json.dumps({"schema_version": 2, "result": {"finish_reason": "finish"}}),
        encoding="utf-8",
    )
    statuses = {entry["id"]: entry["status"] for entry in history.list_runs(home=tmp_path)}
    assert statuses["cancelled-reason"] == history.STATUS_PARTIAL
    assert statuses["normal-finish"] == history.STATUS_DONE


def test_list_can_filter_by_target(tmp_path: Path) -> None:
    _make_run(tmp_path, "a", target="http://127.0.0.1:5000")
    _make_run(tmp_path, "b", target="http://localhost:8080")
    runs = history.list_runs(home=tmp_path, target="http://localhost:8080")
    assert [item["id"] for item in runs] == ["b"]


def test_detail_returns_the_report_written_at_the_time(tmp_path: Path) -> None:
    _make_run(tmp_path, "run-1", report="## 当时的报告\n\n这是一份原文。\n")
    detail = history.run_detail("run-1", home=tmp_path)
    assert detail is not None
    assert detail["markdown_source"] == "report"
    assert "这是一份原文" in detail["markdown"]


def test_detail_rerenders_offline_when_report_is_gone(tmp_path: Path) -> None:
    """原文没了就用快照离线重渲染，并**写明是重建的**。"""
    _make_run(tmp_path, "run-2", report=None, snapshot=True)
    detail = history.run_detail("run-2", home=tmp_path)
    assert detail is not None
    assert detail["markdown_source"] in {"snapshot", "none"}
    if detail["markdown_source"] == "snapshot":
        assert "离线重渲染" in detail["markdown"]


def test_detail_missing_run_is_none(tmp_path: Path) -> None:
    assert history.run_detail("nope", home=tmp_path) is None


@pytest.mark.parametrize("bad", ["../secrets", "..", ".", "a/b", ""])
def test_run_id_cannot_escape_the_runs_directory(tmp_path: Path, bad: str) -> None:
    """目录名来自 URL；路径穿越必须挡住（历史接口读的是本机文件）。"""
    assert history.find_run(bad, home=tmp_path) is None


def test_history_never_touches_the_network_or_the_model(tmp_path: Path, monkeypatch) -> None:
    """列出 + 读详情时，任何 LLM 客户端构造与 HTTP 请求都应该发生 0 次。"""
    import socket

    _make_run(tmp_path, "run-3")

    def boom(*args, **kwargs):  # pragma: no cover - 触发即失败
        raise AssertionError("历史查看不得调用模型或访问网络")

    monkeypatch.setattr(socket.socket, "connect", boom)
    from hexhound import llm

    monkeypatch.setattr(llm, "LLMClient", boom)
    runs = history.list_runs(home=tmp_path)
    assert runs and runs[0]["id"] == "run-3"
    detail = history.run_detail("run-3", home=tmp_path)
    assert detail is not None and detail["markdown"]


def test_unreadable_run_json_does_not_break_the_list(tmp_path: Path) -> None:
    """产物目录里混进坏文件时，历史列表整体仍要能打开。"""
    _make_run(tmp_path, "good")
    broken = tmp_path / "runs" / "broken"
    broken.mkdir(parents=True)
    (broken / "run.json").write_text("{not json", encoding="utf-8")
    runs = history.list_runs(home=tmp_path)
    assert {item["id"] for item in runs} == {"good", "broken"}
    entry = next(item for item in runs if item["id"] == "broken")
    # 有 run.json 但没有 snapshot.json → "未完成"（不是"状态未知"，更不是"已完成"）
    assert entry["status"] == history.STATUS_PARTIAL


def test_directory_without_any_summary_is_unknown(tmp_path: Path) -> None:
    """空目录（或只有零散文件）不能说成"已完成"，也不能说成"中断"。"""
    (tmp_path / "runs" / "empty").mkdir(parents=True)
    runs = history.list_runs(home=tmp_path)
    assert runs[0]["status"] == history.STATUS_UNKNOWN


def test_archived_report_is_found_at_the_real_path(tmp_path: Path, monkeypatch) -> None:
    """**真实路径**回归：审计收尾写的副本，历史必须能当作"原文"读到。

    这条用例存在的原因（实测漏洞）：`_archive_report()` 早期走
    `RunArtifacts.write_artifact()`，把副本写进了运行目录的 `artifacts/` 子目录，
    而 `render_run_report()` 读的是运行目录根 —— 于是"优先用当时写下的报告原文"
    静默失效，界面显示成"由快照重渲染"。当时的测试把报告直接放在根目录，
    所以没抓到；这里改成**调用真实的归档函数**再看历史能不能找到。
    """
    from hexhound import gui as gui_module
    from hexhound.memory import RunArtifacts

    monkeypatch.setattr(gui_module.history, "data_home", lambda home=None: tmp_path)
    artifacts = RunArtifacts("http://127.0.0.1:5000", home=tmp_path)
    assert artifacts.enabled, "产物目录应可用"
    (artifacts.dir / "run.json").write_text(
        json.dumps({"target": "http://127.0.0.1:5000", "mode": "blackbox"}, ensure_ascii=False),
        encoding="utf-8",
    )
    delivered = tmp_path / "delivered-report.md"
    delivered.write_text("## 当时写下的报告\n\n正文\n", encoding="utf-8")

    gui_module._archive_report(artifacts, delivered)

    detail = history.run_detail(artifacts.dir.name, home=tmp_path)
    assert detail is not None
    assert detail["markdown_source"] == "report", detail
    assert "当时写下的报告" in detail["markdown"]
    entry = history.list_runs(home=tmp_path)[0]
    assert entry["report_available"] is True
    assert entry["report_path"].endswith("report.md"), entry["report_path"]


def test_legacy_artifacts_subdir_report_still_reads(tmp_path: Path) -> None:
    """早期构建把副本写在 `artifacts/report.md`：已跑过的运行也要能显示原文。"""
    run_dir = _make_run(tmp_path, "legacy-run", report=None, snapshot=True)
    legacy = run_dir / "artifacts"
    legacy.mkdir(parents=True, exist_ok=True)
    (legacy / "report.md").write_text("## 旧位置的原文\n\n内容\n", encoding="utf-8")
    detail = history.run_detail("legacy-run", home=tmp_path)
    assert detail is not None
    assert detail["markdown_source"] == "report"
    assert "旧位置的原文" in detail["markdown"]
    entry = history.list_runs(home=tmp_path)[0]
    assert "artifacts" in entry["report_path"].replace("\\", "/")
