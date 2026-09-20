"""GUI 运行状态（RunState）的单元测试。

注意：这里**只**打桩真正的外部依赖（flask 的渲染函数），不再打桩 hexhound 自己的
内部模块——之前那样做会让"内部模块改名/新增函数"在测试里静默通过，直到真实运行时
才炸（v0.2 重构时就踩到了：`agent.extract_json` 被移到别处，打桩版测试仍全绿）。
"""
from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))


def _stub_flask() -> None:
    """只替换 flask 的模板渲染与响应对象，保留真实模块结构。"""
    try:
        import flask  # noqa: F401

        return
    except ImportError:
        pass
    flask = types.ModuleType("flask")
    flask.Flask = object
    flask.jsonify = lambda data, *a, **k: data
    flask.render_template_string = lambda *a, **k: ""
    flask.request = object
    flask.send_file = object
    sys.modules["flask"] = flask


_stub_flask()

from hexhound import gui  # noqa: E402


class RunStateTests(unittest.TestCase):
    def test_start_returns_increasing_tokens(self) -> None:
        state = gui.RunState()
        first = state.start()
        second = state.start()
        self.assertGreater(second, first)
        self.assertFalse(state.is_stopped(second))
        self.assertTrue(state.is_stopped(first))

    def test_stop_current_marks_running_token_stopped(self) -> None:
        state = gui.RunState()
        token = state.start()
        state.add_step({"step": 1}, token)
        state.stop_current()
        self.assertTrue(state.is_stopped(token))
        self.assertEqual(state.snapshot()["status"], "idle")

    def test_stale_token_cannot_mutate_new_state(self) -> None:
        state = gui.RunState()
        old_token = state.start()
        new_token = state.start()
        state.add_step({"step": "old"}, old_token)
        self.assertEqual(state.snapshot()["steps"], [])
        state.add_step({"step": "new"}, new_token)
        self.assertEqual(state.snapshot()["steps"], [{"step": "new"}])

    def test_events_render_as_phases(self) -> None:
        state = gui.RunState()
        token = state.start()
        state.add_event({"kind": "plan", "tasks": [{"id": "T1", "role": "recon", "objective": "爬首页"}]}, token)
        state.add_event({"kind": "wave", "wave": 1, "count": 1}, token)
        state.add_event(
            {"kind": "task_end", "task": {"id": "T1", "outcome": "done", "summary": "完成"}}, token
        )
        phases = state.snapshot()["phases"]
        self.assertTrue(any("计划" in line for line in phases))
        self.assertTrue(any("第 1 波" in line for line in phases))
        self.assertTrue(any("[OK] [T1]" in line for line in phases))

    def test_stale_token_events_ignored(self) -> None:
        state = gui.RunState()
        old = state.start()
        new = state.start()
        state.add_event({"kind": "wave", "wave": 9, "count": 9}, old)
        self.assertEqual(state.snapshot()["phases"], [])
        state.add_event({"kind": "wave", "wave": 1, "count": 1}, new)
        self.assertNotEqual(state.snapshot()["phases"], [])


if __name__ == "__main__":
    unittest.main()
