"""关窗护栏端到端验证（零模型额度）：关窗口真的会写出"不完整报告"。

用法（在仓库根目录）：
    python tools/verify_close_guard.py

验证的不是单元逻辑，而是**真实链路**：
真实 Flask 应用（`create_app`）→ 真实 `/api/run` 启动审计（脚本 LLM，零额度）
→ 运行到一半调用桌面关窗护栏 `desktop.stop_running_audit(STATE, …)`
→ 断言报告文件真的写出来了、且写明"本次运行被中断，报告不完整"、
  未测端点没有被写成"测过没问题"。

这正是用户踩过的边界：直接关窗口时进程被杀、连部分报告都没有。
产物写到 `.tmp/close-guard-home`，不污染真实运行历史。
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

HOME = ROOT / ".tmp" / "close-guard-home"
os.environ["HEXHOUND_HOME"] = str(HOME)
os.environ["HEXHOUND_TEST_ROOT"] = str(ROOT / ".tmp" / "pytest-root")

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


def main() -> int:
    try:
        import flask  # noqa: F401
    except ImportError:
        print("需要 flask（pip install -e \".[gui]\"）才能跑这个端到端验证。")
        return 2
    if getattr(sys.modules.get("flask"), "__hexhound_flask_stub__", False):
        print("检测到 flask 替身，无法进行端到端验证。")
        return 2

    from unittest.mock import patch

    from hexhound import cli as cli_module
    from hexhound import desktop, gui
    from hexhound.mockllm import ScriptedLLM

    target = os.getenv("VERIFY_TARGET", "http://127.0.0.1:5000")
    settings = {
        **gui.DEFAULTS,
        "provider": "scripted", "model": "scripted-policy",
        "base_url": "http://127.0.0.1:9/v1",
        "target": target, "allowed_hosts": "127.0.0.1,localhost",
        "swarm": "1", "max_steps": "20", "task_steps": "8",
        "output": str(ROOT / ".tmp" / "close-guard-out" / "report.md"),
    }

    app = gui.create_app()
    client = app.test_client()
    headers = {gui.TOKEN_HEADER: app.config["HEXHOUND_LOCAL_TOKEN"]}

    print("=== 通过真实 /api/run 启动审计（脚本 LLM，零额度）===")
    with patch.object(cli_module, "_build_llm_pool", return_value=(ScriptedLLM(), {})), \
         patch.object(gui, "_provider_keys", return_value={}), \
         patch.object(gui, "_save_settings"):
        # 注意：/api/run 收的是**扁平**的设置对象（界面就是这么发的）
        response = client.post("/api/run", json=settings, headers=headers)
    check("/api/run 启动成功", response.status_code == 200, str(response.status_code))

    # 等它真的跑起来
    deadline = time.time() + 20
    running = False
    while time.time() < deadline:
        snapshot = client.get("/api/status", headers=headers).get_json() or {}
        if snapshot.get("running"):
            running = True
            break
        if snapshot.get("status") in ("done", "failed", "cancelled"):
            break
        time.sleep(0.2)
    check("审计确实在运行", running, "未能观察到运行中状态")

    # 关键动作：等价于"用户直接关窗口"
    outcome = desktop.stop_running_audit(gui.STATE, timeout=desktop.close_grace_seconds())
    check("关窗护栏完成收尾", outcome == "saved", f"outcome={outcome}")

    snapshot = client.get("/api/status", headers=headers).get_json() or {}
    check("状态进入终止态", snapshot.get("status") == "cancelled", str(snapshot.get("status")))
    report_path = Path(str(snapshot.get("output_path") or settings["output"]))
    check("报告文件已写出", report_path.exists(), str(report_path))

    text = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    check("报告写明被中断/不完整", "本次运行被中断" in text and "不完整" in text)
    check("报告没有把未测写成'没问题'", "no_issue_found" not in text or "未完成" in text)

    # 运行产物目录里也应有一份（历史里还能看到当时那份报告）
    run_json = sorted((HOME / "runs").glob("*/run.json"))
    check("运行记录已落盘", bool(run_json), f"{len(run_json)} 份")
    if run_json:
        data = json.loads(run_json[-1].read_text(encoding="utf-8"))
        check("运行记录里有沙箱状态", "sandbox" in data)
        # 历史判定必须说"未完成"：不能把被中断的运行说成完整收尾
        from hexhound import history

        runs = history.list_runs(home=HOME)
        entry = next((item for item in runs if item.get("id") == run_json[-1].parent.name), None)
        check("历史里判定为未完成", bool(entry) and entry.get("status") == history.STATUS_PARTIAL,
              str((entry or {}).get("status")))
        # 历史里能读到那份被中断的报告（而不是回退成"没有报告"）
        rendered, source = history.render_run_report(run_json[-1].parent)
        check("历史里能读回中断报告", "本次运行被中断" in rendered, source)
        snapshot = json.loads((run_json[-1].parent / "snapshot.json").read_text(encoding="utf-8"))
        check("快照记录 finish_reason=cancelled",
              str((snapshot.get("result") or {}).get("finish_reason")) == "cancelled",
              str((snapshot.get("result") or {}).get("finish_reason")))

    print()
    if FAILURES:
        print(f"关窗护栏验证未通过：{len(FAILURES)} 项 —— " + "；".join(FAILURES))
        return 1
    print(f"关窗护栏验证通过：中断后报告与运行记录都已写盘（{report_path}）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
