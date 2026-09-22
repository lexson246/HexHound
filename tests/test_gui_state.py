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


#: 打桩模块上的标记：让**别的测试文件**能分辨"真 flask"与"这个假替身"。
#:
#: 为什么必须有这个标记（CI 抓到的真问题）：这里的替身会把假的 `flask` 塞进
#: `sys.modules`，于是同一次 pytest 进程里别的文件 `import flask` 也会成功——
#: 接着 `Flask(__name__)` 在 `Flask = object` 上炸出
#: `TypeError: object() takes no arguments`。缺 flask 时 `test_providers` 的
#: 界面用例本该"跳过"，却变成了 12 个 ERROR。
STUB_MARKER = "__hexhound_flask_stub__"


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
    setattr(flask, STUB_MARKER, True)
    sys.modules["flask"] = flask


_stub_flask()

from hexhound import gui  # noqa: E402


class _FakeResult:
    """最小审计结果替身：只提供 `RunState.finish()` 真正读取的字段。"""

    findings = [{"title": "已确认的问题"}]
    final_summary = "中断前已完成 1 个子任务"
    prompt_tokens = 10
    completion_tokens = 5
    cache_hit_tokens = 1
    cache_miss_tokens = 2
    estimated_cost = 0.01
    total_tokens = 15


class RunStateTests(unittest.TestCase):
    def test_start_returns_increasing_tokens(self) -> None:
        state = gui.RunState()
        first = state.start()
        second = state.start()
        self.assertGreater(second, first)
        self.assertFalse(state.is_stopped(second))
        self.assertTrue(state.is_stopped(first))

    def test_stop_current_is_transitional_not_terminal(self) -> None:
        """停止请求只把状态推进到 `stopping`，收尾完成后才是 `cancelled`。

        旧行为是 `stop_current()` 立刻把状态写回 `idle`：界面上"跑到一半停下"
        与"什么都没跑"长得一模一样，而且立刻又允许启动新任务，两个审计线程
        会同时写同一份攻面与产物目录。这里把正确的迁移链钉死。
        """
        state = gui.RunState()
        token = state.start()
        state.add_step({"step": 1}, token)
        state.stop_current()
        self.assertTrue(state.is_stopped(token))
        snapshot = state.snapshot()
        self.assertEqual(snapshot["status"], "stopping")
        self.assertEqual(snapshot["status_label"], "正在停止")
        self.assertTrue(snapshot["running"], "收尾期间仍算占用运行名额")
        # 收尾期间不允许再起一个任务
        self.assertFalse(state.try_begin())

    def test_finish_after_stop_records_partial_result(self) -> None:
        """中断收尾：状态转 `cancelled`，但成果（步骤/发现/报告路径）必须保留。"""
        state = gui.RunState()
        token = state.start()
        state.add_step({"step": 1}, token)
        state.stop_current()
        state.finish(_FakeResult(), "runs/x/report.md", token, partial=True)
        snapshot = state.snapshot()
        self.assertEqual(snapshot["status"], "cancelled")
        self.assertEqual(snapshot["status_label"], "已中断（部分结果已保存）")
        self.assertTrue(snapshot["partial"])
        self.assertFalse(snapshot["running"])
        self.assertEqual(snapshot["findings"], [{"title": "已确认的问题"}])
        self.assertEqual(snapshot["summary"], "中断前已完成 1 个子任务")
        self.assertEqual(snapshot["output_path"], "runs/x/report.md")
        self.assertEqual(snapshot["steps"], [{"step": 1}])
        # 真正结束后才重新开放名额
        self.assertTrue(state.try_begin())

    def test_try_begin_blocks_overlapping_runs(self) -> None:
        """运行期间（含 stopping 收尾期）拒绝重叠启动，结束后才放行。"""
        state = gui.RunState()
        self.assertTrue(state.try_begin())
        self.assertFalse(state.try_begin(), "占位期间不得重复启动")
        state.start()
        self.assertFalse(state.try_begin())
        state.stop_current()
        self.assertFalse(state.try_begin(), "收尾期间不得重复启动")
        state.finish(_FakeResult(), "", 1, partial=True)
        self.assertEqual(state.snapshot()["status"], "cancelled")
        self.assertTrue(state.try_begin(), "结束后必须能再启动")

    def test_abort_begin_releases_only_the_placeholder(self) -> None:
        """`try_begin` 成功后若保存设置等步骤失败，必须能回滚占位。"""
        state = gui.RunState()
        self.assertTrue(state.try_begin())
        state.abort_begin()
        self.assertTrue(state.try_begin(), "回滚占位后应重新可占用")

    def test_failure_is_a_terminal_state(self) -> None:
        state = gui.RunState()
        token = state.start()
        state.fail("模型不可用", token)
        snapshot = state.snapshot()
        self.assertEqual(snapshot["status"], "failed")
        self.assertEqual(snapshot["error"], "模型不可用")
        self.assertFalse(snapshot["running"])
        self.assertTrue(state.try_begin())

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
