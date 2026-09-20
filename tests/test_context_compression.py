"""ReAct 循环的上下文压缩与预算行为测试。

设计说明：这里用**真实的** hexhound 模块（只打桩 LLM 与工具注册表），
不再伪造内部模块——伪造内部模块会让重构后的接口漂移无法被发现。
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound import agent  # noqa: E402
from hexhound.budget import Budget, BudgetLimits  # noqa: E402
from hexhound.surface import AttackSurface  # noqa: E402


class FakeTools:
    """最小工具注册表替身（接口与 ToolRegistry 对齐）。"""

    mode = "source"

    def __init__(self) -> None:
        self.surface = AttackSurface(mode="source")
        self.poc_paths: dict[str, str] = {}
        self.findings: list[dict] = []
        self.budget = Budget()
        self.calls: list[str] = []

    def describe(self) -> str:
        return "tools"

    def execute(self, name: str, action_input: dict) -> str:
        self.calls.append(name)
        # 真实 ToolRegistry 会在 execute 里记一次工具调用；替身必须同样记账，
        # 否则预算类测试会"假绿"（上限永远到不了）。
        self.budget.add_tool_call()
        return f"observation for {name}"


class FakeLLM:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, messages: list[dict]) -> tuple[str, int]:
        self.calls += 1
        if self.calls == 1:
            return json.dumps({"action": "http_request", "action_input": {}}), 0
        return json.dumps({"action": "finish", "action_input": {"summary": "done"}}), 0


class UsageFakeLLM:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, messages: list[dict]) -> tuple[str, SimpleNamespace]:
        self.calls += 1
        content = (
            {"action": "http_request", "action_input": {}}
            if self.calls == 1
            else {"action": "finish", "action_input": {"summary": "done"}}
        )
        return json.dumps(content), SimpleNamespace(
            prompt_tokens=10, completion_tokens=5, total_tokens=15
        )


class NeverFinishingLLM:
    """永远调用工具、从不收尾——用于验证预算闸与步数上限。"""

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, messages: list[dict]) -> tuple[str, SimpleNamespace]:
        self.calls += 1
        return json.dumps({"action": "http_request", "action_input": {"url": "x"}}), SimpleNamespace(
            prompt_tokens=100, completion_tokens=50, total_tokens=150
        )


class ContextCompressionTests(unittest.TestCase):
    def test_summarize_steps(self) -> None:
        steps = [
            {"step": 1, "action": "http_request", "thought": "check", "observation": "ok"},
            {
                "step": 2,
                "action": "record_finding",
                "action_input": {"title": "SQL injection"},
                "observation": "recorded",
            },
        ]
        summary = agent._summarize_steps(steps)
        self.assertIn("Step 1 http_request", summary)
        self.assertIn("SQL injection", summary)

    def test_summarize_prioritises_key_actions(self) -> None:
        steps = [
            {"step": index, "action": "http_request", "observation": "noise " * 20}
            for index in range(1, 6)
        ] + [{"step": 6, "action": "record_coverage", "observation": "覆盖：/login no_issue_found"}]
        summary = agent._summarize_steps(steps, limit=400)
        self.assertIn("record_coverage", summary)

    def test_compress_history_keeps_head_and_recent(self) -> None:
        messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "task"},
        ] + [
            {"role": "assistant" if i % 2 == 0 else "user", "content": "x" * 100}
            for i in range(10)
        ]
        steps = [{"step": 1, "action": "http_request", "observation": "ok"}]
        compressed = agent._compress_history(
            messages, steps, max_context_chars=500, keep_recent_messages=4
        )
        self.assertEqual(compressed[0]["role"], "system")
        self.assertEqual(compressed[1]["role"], "user")
        self.assertIn("[压缩历史]", compressed[2]["content"])
        self.assertEqual(compressed[-1], messages[-1])

    def test_agent_run_with_compression(self) -> None:
        runner = agent.ReActAgent(
            FakeLLM(),
            FakeTools(),
            max_steps=3,
            max_context_chars=10,
            keep_recent_messages=4,
        )
        result = runner.run("goal")
        self.assertEqual(result.final_summary, "done")
        self.assertEqual(result.steps[-1]["action"], "finish")
        self.assertEqual(result.finish_reason, "finish")

    def test_agent_accumulates_prompt_and_completion_tokens(self) -> None:
        usage_seen: list[dict] = []
        runner = agent.ReActAgent(UsageFakeLLM(), FakeTools(), max_steps=3)
        result = runner.run("goal", on_usage=usage_seen.append)
        self.assertEqual(result.prompt_tokens, 20)
        self.assertEqual(result.completion_tokens, 10)
        self.assertEqual(result.total_tokens, 30)
        self.assertEqual(usage_seen[-1]["total_tokens"], 30)

    def test_finish_task_is_a_valid_stop_action(self) -> None:
        """子代理用 finish_task 收尾（与 finish 等价）。"""
        class FinishTaskLLM:
            def complete(self, messages):
                return json.dumps(
                    {"action": "finish_task", "action_input": {"summary": "子任务完成"}}
                ), SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2)

        result = agent.ReActAgent(FinishTaskLLM(), FakeTools(), max_steps=2).run("goal")
        self.assertEqual(result.final_summary, "子任务完成")
        self.assertEqual(result.finish_reason, "finish")

    def test_budget_hard_stop_ends_loop(self) -> None:
        """预算越线后不再请求 LLM，直接优雅收尾。"""
        tools = FakeTools()
        budget = Budget(BudgetLimits(max_tool_calls=2))
        tools.budget = budget  # 工具记账与 agent 检查必须共用同一个账本
        llm = NeverFinishingLLM()
        runner = agent.ReActAgent(llm, tools, max_steps=20, budget=budget)
        result = runner.run("goal")
        self.assertEqual(result.finish_reason, "budget")
        self.assertIn("预算用尽", result.final_summary)
        # 3 次工具调用后越线：第 3 次迭代开头就应停止，不再请求模型。
        self.assertLessEqual(llm.calls, 3)
        self.assertTrue(budget.stop_reasons())

    def test_budget_warning_band_injected(self) -> None:
        """到达预警带时把收尾指令插进对话（on_notice 回调可见）。"""
        notices: list[tuple[str, str]] = []
        # 上限 5 次 LLM 调用：第 4 次时用量 80% → 命中 URGENT 预警带。
        budget = Budget(BudgetLimits(max_llm_calls=5))
        runner = agent.ReActAgent(
            NeverFinishingLLM(),
            FakeTools(),
            max_steps=20,
            budget=budget,
            on_notice=lambda level, directive: notices.append((level, directive)),
        )
        runner.run("goal")
        self.assertTrue(notices, "预算预警带应当被触发")
        self.assertIn(notices[0][0], ("NOTICE", "URGENT", "CRITICAL"))
        self.assertIn("预算", notices[0][1])

    def test_max_steps_marks_reason(self) -> None:
        result = agent.ReActAgent(
            NeverFinishingLLM(), FakeTools(), max_steps=2, budget=Budget()
        ).run("goal")
        self.assertEqual(result.finish_reason, "max_steps")
        self.assertEqual(result.steps_used, 2)

    def test_parse_failure_twice_stops(self) -> None:
        class GarbageLLM:
            def complete(self, messages):
                return "这不是 JSON", SimpleNamespace(
                    prompt_tokens=1, completion_tokens=1, total_tokens=2
                )

        result = agent.ReActAgent(GarbageLLM(), FakeTools(), max_steps=5).run("goal")
        self.assertEqual(result.finish_reason, "parse_error")
        self.assertTrue(any(step["action"] == "parse_error" for step in result.steps))


class ExtractJsonTests(unittest.TestCase):
    def test_extract_from_fenced_block(self) -> None:
        parsed = agent.extract_json('```json\n{"action": "finish"}\n```')
        self.assertEqual(parsed["action"], "finish")

    def test_extract_with_surrounding_text(self) -> None:
        parsed = agent.extract_json('思考如下 {"action": "crawl", "action_input": {"url": "x"}} 完毕')
        self.assertEqual(parsed["action_input"]["url"], "x")

    def test_extract_raises_on_garbage(self) -> None:
        with self.assertRaises(ValueError):
            agent.extract_json("no object here")


if __name__ == "__main__":
    unittest.main()
