"""桌面关窗护栏：**关窗口也要把成果落盘**（第四轮剩余边界）。

用户报过的真实后果：审计跑到一半直接关窗口 → 进程退出、daemon 线程被杀 →
连"不完整报告"都没有；而按界面上的"停止"按钮却会正常写出报告。
同一个动作两种关法结果完全不同，等于把跑了几十分钟的成果丢掉。

这里钉住三件事：
1. 没在跑 → 不拦截关闭（不能让用户"关不掉窗口"）；
2. 在跑 → 拦截一次、请求停止、等报告写完、再自己销毁窗口（第二次不拦）；
3. 等不到也不卡死（超时后照常退出，并说明原因）。

全部用替身（假窗口/假状态），不需要真的打开 WebView。
"""
from __future__ import annotations

import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound import desktop  # noqa: E402


class FakeState:
    """只提供 `snapshot()` / `stop_current()` 的最小替身。"""

    def __init__(self, running: bool, stop_delay: float = 0.0) -> None:
        self.running = running
        self.stop_delay = stop_delay
        self.stop_calls = 0

    def snapshot(self) -> dict:
        return {"running": self.running, "status": "running" if self.running else "cancelled"}

    def stop_current(self) -> None:
        self.stop_calls += 1
        if self.stop_delay <= 0:
            self.running = False
            return

        def finish() -> None:
            time.sleep(self.stop_delay)
            self.running = False

        threading.Thread(target=finish, daemon=True).start()


class _Slot:
    """模拟 pywebview 的事件槽：支持 `events.closing += handler`。"""

    def __init__(self, handlers: list) -> None:
        self._handlers = handlers

    def __iadd__(self, handler):  # noqa: ANN001
        self._handlers.append(handler)
        return self


class FakeEvents:
    def __init__(self) -> None:
        self.handlers: list = []
        self.closing = _Slot(self.handlers)


class FakeWindow:
    def __init__(self) -> None:
        self.events = FakeEvents()
        self.destroyed = 0
        self.js: list[str] = []

    def destroy(self) -> None:
        self.destroyed += 1

    def evaluate_js(self, script: str) -> None:
        self.js.append(script)

    def fire_closing(self) -> bool:
        """触发 closing 事件；返回 False 表示这次关闭被取消。"""
        result = True
        for handler in list(self.events.handlers):
            if handler() is False:
                result = False
        return result


class CloseGuardTests(unittest.TestCase):
    """关窗语义：**一律放行关闭**，但在放行前立刻请求停止 + 中断沙箱命令。

    真机（打包 exe）验收推翻过一版设计：早先"取消第一次关闭 → 收尾完再由工作线程
    `window.destroy()`"在真机上**关不掉**——pywebview 的窗口方法必须由 GUI 主线程
    调用，工作线程里调用既不生效也不报错（异常被吞），于是窗口永远关不掉、进程一直活着。
    单元测试当时给了假信心，因为替身的 `destroy()` 无条件"成功"。

    现在的契约（`main()` 的 finally 负责等报告）：

    1. 没在跑 → 放行，什么都不做；
    2. 在跑 → 放行 **且** 已在放行前请求停止（含中断沙箱命令）；
    3. 状态读不到 / 沙箱炸了 → 仍然放行（用户想关就能关）。
    """

    def test_idle_state_is_allowed_without_side_effects(self) -> None:
        window, state = FakeWindow(), FakeState(running=False)
        desktop.install_close_guard(window, state, timeout=0.5)
        self.assertTrue(window.fire_closing(), "没在跑就直接放行")
        self.assertEqual(state.stop_calls, 0)
        self.assertEqual(window.destroyed, 0)

    def test_running_audit_is_allowed_but_stop_is_requested_first(self) -> None:
        window, state = FakeWindow(), FakeState(running=True, stop_delay=0.2)
        desktop.install_close_guard(window, state, timeout=5.0)
        self.assertTrue(window.fire_closing(), "关窗必须被放行（不能出现关不掉）")
        self.assertEqual(state.stop_calls, 1, "放行前必须先请求停止")
        # 回调里**不能**碰页面：closing 是 UI 线程上的同步回调，evaluate_js 会自锁
        self.assertEqual(window.js, [], "关窗回调里不得调用 evaluate_js（真机上会自锁）")

    def test_second_close_is_a_noop(self) -> None:
        window, state = FakeWindow(), FakeState(running=True, stop_delay=0.05)
        desktop.install_close_guard(window, state, timeout=2.0)
        window.fire_closing()
        self.assertTrue(window.fire_closing())
        self.assertEqual(state.stop_calls, 1, "重复关窗不该重复请求停止")

    def test_timeout_still_exits(self) -> None:
        """`main()` 的 finally 等待是有上限的：审计卡死也不能把进程钉住。"""
        state = FakeState(running=True, stop_delay=5.0)
        started = time.monotonic()
        outcome = desktop.stop_running_audit(state, timeout=0.3)
        self.assertEqual(outcome, "timeout")
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertEqual(state.stop_calls, 1)

    def test_idle_audit_reports_idle(self) -> None:
        self.assertEqual(desktop.stop_running_audit(FakeState(running=False), timeout=1.0), "idle")

    def test_saved_after_run_finishes(self) -> None:
        self.assertEqual(
            desktop.stop_running_audit(FakeState(running=True, stop_delay=0.2), timeout=5.0),
            "saved",
        )

    def test_close_grace_is_configurable_and_sane(self) -> None:
        with patch.dict("os.environ", {"HEXHOUND_CLOSE_GRACE": "5"}):
            self.assertEqual(desktop.close_grace_seconds(), 5.0)
        with patch.dict("os.environ", {"HEXHOUND_CLOSE_GRACE": "not-a-number"}):
            self.assertEqual(desktop.close_grace_seconds(), desktop.CLOSE_GRACE_SECONDS)
        with patch.dict("os.environ", {"HEXHOUND_CLOSE_GRACE": "-3"}):
            self.assertEqual(desktop.close_grace_seconds(), 0.0)

    def test_broken_state_does_not_block_shutdown(self) -> None:
        class Broken:
            def snapshot(self):
                raise RuntimeError("boom")

        window = FakeWindow()
        desktop.install_close_guard(window, Broken(), timeout=0.3)
        self.assertTrue(window.fire_closing(), "状态读不到时也不能把窗口卡住")

    def test_event_registration_failure_is_swallowed(self) -> None:
        class NoEvents:
            @property
            def events(self):
                raise AttributeError("no events")

            def destroy(self) -> None:
                raise AssertionError("不该被调用")

        desktop.install_close_guard(NoEvents(), FakeState(running=True), timeout=0.2)

    def test_startup_logging_is_optional_and_safe(self) -> None:
        """windowed 构建没有控制台：`HEXHOUND_DESKTOP_LOG` 是唯一的排查线索。"""
        with patch.dict("os.environ", {"HEXHOUND_DESKTOP_LOG": ""}):
            desktop.log_line("不该写任何东西")  # 未设置 → 静默
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "desktop.log"
            with patch.dict("os.environ", {"HEXHOUND_DESKTOP_LOG": str(target)}):
                desktop.log_line("启动里程碑")
            self.assertIn("启动里程碑", target.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
