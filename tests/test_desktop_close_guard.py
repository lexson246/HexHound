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
    def test_idle_state_is_not_blocked(self) -> None:
        window, state = FakeWindow(), FakeState(running=False)
        desktop.install_close_guard(window, state, timeout=0.5)
        self.assertTrue(window.fire_closing(), "没在跑就不该拦着用户关窗口")
        self.assertEqual(state.stop_calls, 0)
        self.assertEqual(window.destroyed, 0)

    def test_running_audit_is_stopped_and_reported_before_exit(self) -> None:
        window, state = FakeWindow(), FakeState(running=True, stop_delay=0.4)
        desktop.install_close_guard(window, state, timeout=5.0)
        self.assertFalse(window.fire_closing(), "运行中必须取消这次关闭，先落盘")
        self.assertEqual(state.stop_calls, 1)
        deadline = time.time() + 5
        while window.destroyed == 0 and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(window.destroyed, 1, "收尾完成后应当自己销毁窗口，避免关不掉")
        self.assertTrue(window.js, "页面上要提示正在保存不完整报告")

    def test_second_close_is_not_blocked(self) -> None:
        window, state = FakeWindow(), FakeState(running=True, stop_delay=0.05)
        desktop.install_close_guard(window, state, timeout=2.0)
        window.fire_closing()
        self.assertTrue(window.fire_closing(), "第二次关闭不能再拦（否则窗口关不掉）")
        self.assertEqual(state.stop_calls, 1)

    def test_timeout_still_exits(self) -> None:
        """审计卡在长工具调用里时不能把窗口钉死：超时就照常退出。"""
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
        self.assertTrue(window.fire_closing(), "状态读不到时不能把窗口卡住")

    def test_event_registration_failure_is_swallowed(self) -> None:
        class NoEvents:
            @property
            def events(self):
                raise AttributeError("no events")

            def destroy(self) -> None:
                raise AssertionError("不该被调用")

        desktop.install_close_guard(NoEvents(), FakeState(running=True), timeout=0.2)


if __name__ == "__main__":
    unittest.main()
