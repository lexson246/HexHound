"""取消正在执行的沙箱命令（外部评审第 4 条）+ CLI 中断也标"不完整"。

要解决的真实场景：关窗口/按停止时，正在跑的往往是一条几百秒的 `sqlmap`。
只置"停止标志"没用——子代理要等工具调用返回才会看它，于是只能干等到
`HEXHOUND_CLOSE_GRACE` 超时退出，报告可能还没写。

本文件用**真的子进程**验证取消链路（不依赖 WSL/Docker）：

1. `Sandbox.cancel_current()` 能在命令跑完之前把它杀掉，并如实返回数量；
2. 被杀掉的那次执行**不会被当成"跑过了"**（`ok=False`、有 exit_code）；
3. `RunState.stop_current()` 会调用沙箱取消，并写一条可见事件；
4. CLI 的 `report.mark_partial` 与桌面用的是同一份实现（中断 → "不完整"）。
"""
from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound import report  # noqa: E402
from hexhound.agent import AgentResult  # noqa: E402
from hexhound.sandbox import Sandbox  # noqa: E402


def _sleep_command(seconds: int = 30) -> list[str]:
    """一条会阻塞指定秒数的跨平台命令（不需要 WSL/Docker）。"""
    if sys.platform == "win32":
        return ["cmd", "/c", f"ping -n {seconds} 127.0.0.1 > NUL"]
    return ["sleep", str(seconds)]


class CancelCurrentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sandbox = Sandbox(allowed_hosts=frozenset({"127.0.0.1"}), map_loopback=False)

    def test_cancel_current_kills_a_running_command(self) -> None:
        holder: dict = {}

        def run_long() -> None:
            holder["result"] = self.sandbox._run_host(_sleep_command(30), timeout=60)

        worker = threading.Thread(target=run_long, daemon=True)
        worker.start()
        # 等命令真的跑起来（最多 5 秒）
        deadline = time.time() + 5
        while time.time() < deadline and self.sandbox.active_commands() == 0:
            time.sleep(0.05)
        self.assertEqual(self.sandbox.active_commands(), 1, "命令应当处于执行中")

        started = time.time()
        cancelled = self.sandbox.cancel_current("测试：用户停止")
        self.assertEqual(cancelled, 1)
        worker.join(timeout=15)
        self.assertLess(time.time() - started, 12.0, "取消必须立刻生效，不能干等 30 秒")
        self.assertFalse(worker.is_alive(), "命令线程应当已经结束")
        self.assertNotEqual(holder.get("result").returncode, 0, "被取消的命令不能算成功")

    def test_cancel_with_nothing_running_is_a_noop(self) -> None:
        self.assertEqual(self.sandbox.cancel_current("空跑"), 0)

    def test_cancel_leaves_no_active_process_behind(self) -> None:
        """取消之后不能留下"活跃进程"记录（否则后续取消会去杀已死的进程）。"""
        holder: dict = {}
        worker = threading.Thread(
            target=lambda: holder.update(
                result=self.sandbox._run_host(_sleep_command(30), timeout=60)
            ),
            daemon=True,
        )
        worker.start()
        deadline = time.time() + 5
        while time.time() < deadline and self.sandbox.active_commands() == 0:
            time.sleep(0.05)
        self.sandbox.cancel_current("测试")
        worker.join(timeout=15)
        self.assertEqual(self.sandbox.active_commands(), 0)
        self.assertNotEqual(holder["result"].returncode, 0)
        self.assertEqual(holder["result"].stdout, "")


class RunStateCancelTests(unittest.TestCase):
    def test_stop_current_cancels_the_active_sandbox(self) -> None:
        from hexhound import gui

        calls: list[str] = []

        class FakeSandbox:
            def cancel_current(self, reason: str = "") -> int:
                calls.append(reason)
                return 2

        state = gui.RunState()
        token = state.start()
        state.sandbox = FakeSandbox()
        state.stop_current()
        self.assertEqual(calls, ["用户停止"])
        self.assertTrue(state.is_stopped(token))
        messages = " ".join(str(item) for item in (state.snapshot().get("phases") or []))
        self.assertIn("已中断 2 条", messages)

    def test_stop_current_survives_a_broken_sandbox(self) -> None:
        from hexhound import gui

        class Broken:
            def cancel_current(self, reason: str = "") -> int:
                raise RuntimeError("沙箱炸了")

        state = gui.RunState()
        token = state.start()
        state.sandbox = Broken()
        state.stop_current()  # 不该抛
        self.assertTrue(state.is_stopped(token))


class CliPartialTests(unittest.TestCase):
    def test_mark_partial_is_the_same_implementation_for_cli_and_gui(self) -> None:
        from hexhound import gui

        result = AgentResult(final_summary="之前的总结", finish_reason="finish")
        marked = report.mark_partial(result)
        self.assertEqual(marked.finish_reason, "cancelled")
        self.assertIn("本次运行被中断", marked.final_summary)
        self.assertIn("之前的总结", marked.final_summary)
        # 桌面的薄包装必须指向同一个实现
        again = gui._mark_partial(AgentResult(final_summary="x"), {})
        self.assertEqual(again.finish_reason, "cancelled")

    def test_cli_installs_a_sigint_handler(self) -> None:
        """CLI 必须接管 Ctrl+C（否则中断时报告根本不写）。"""
        source = Path(SRC / "hexhound" / "cli.py").read_text(encoding="utf-8")
        self.assertIn("signal.signal(signal.SIGINT", source)
        self.assertIn("cancel_current", source)
        self.assertIn("mark_partial", source)


if __name__ == "__main__":
    unittest.main()
