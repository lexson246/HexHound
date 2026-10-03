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
        # 真实 ToolRegistry 会在 execute 里**原子**占用工具调用名额；替身必须同样记账，
        # 否则预算类测试会"假绿"（上限永远到不了）。
        granted, reason = self.budget.reserve_tool_call()
        if not granted:
            return f"错误：预算已用尽，本次 {name} 调用未执行（{reason}）。"
        return f"observation for {name}"

    def tool_names(self) -> list[str]:
        return ["http_request", "think", "finish_task"]


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
        """步数用尽 + 收尾回合内仍不收尾 → 明确终态 `closing_no_finish`。

        v0.6 起"达到步数上限"不再是一个终态：正常步数用尽后会先给
        `MAX_CLOSING_ROUNDS` 个**受限收尾回合**（只能 record_finding /
        record_coverage / leave_note / finish_task）。模型连收尾回合都不收尾时，
        状态是 `closing_no_finish`（系统代写总结、产出全部保留），
        而不是原先那句含糊的 `max_steps`。
        """
        result = agent.ReActAgent(
            NeverFinishingLLM(), FakeTools(), max_steps=2, budget=Budget()
        ).run("goal")
        self.assertEqual(result.finish_reason, "closing_no_finish")
        # 2 个正常步 + 2 个收尾回合，全部执行过
        self.assertEqual(result.steps_used, 2 + agent.MAX_CLOSING_ROUNDS)
        self.assertEqual(result.closing["attempted"], agent.MAX_CLOSING_ROUNDS)
        self.assertFalse(result.closing["closed"])
        # 摘要必须存在（系统代写），否则报告里这个子任务看起来"无产出"
        self.assertTrue(result.final_summary)
        self.assertIn("系统代写总结", result.final_summary)

    def test_closing_rounds_reject_probing_actions(self) -> None:
        """收尾回合里模型要探测 → 拒绝执行，且不消耗真实工具调用。

        判据是"工具没被执行"：FakeTools 记录收到的动作，
        收尾回合里出现的 http_request 不应留下执行痕迹。
        """
        tools = FakeTools()
        budget = Budget()
        tools.budget = budget
        result = agent.ReActAgent(
            NeverFinishingLLM(), tools, max_steps=1, budget=budget
        ).run("goal")
        closing_steps = [s for s in result.steps if s.get("phase") == "closing"]
        self.assertTrue(closing_steps, "应当存在收尾回合")
        for step in closing_steps:
            self.assertIn("收尾阶段不接受", step["observation"])
        # 收尾回合里被拒的动作没有执行 → 工具调用数只来自正常步
        self.assertEqual(budget.usage.tool_calls, 1)

    def test_closing_round_saves_evidence_then_finishes(self) -> None:
        """收尾回合应当能把产出固化下来（record_finding / record_coverage）。"""

        class ClosingLLM:
            """正常步一直探测；进入收尾后记录一条结论并 finish。"""

            def __init__(self) -> None:
                self.calls = 0

            def complete(self, messages):
                self.calls += 1
                text = "\n".join(str(m.get("content", "")) for m in messages)
                usage = SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2)
                if "收尾回合" in text:
                    return json.dumps(
                        {
                            "action": "finish_task",
                            "action_input": {"summary": "收尾回合内完成收尾"},
                        }
                    ), usage
                return json.dumps(
                    {"action": "think", "action_input": {"note": "继续探测"}}
                ), usage

        result = agent.ReActAgent(
            ClosingLLM(), FakeTools(), max_steps=2, budget=Budget()
        ).run("goal")
        self.assertEqual(result.finish_reason, "finish")
        self.assertTrue(result.closing["closed"])
        self.assertEqual(result.closing["attempted"], 1)
        self.assertEqual(result.final_summary, "收尾回合内完成收尾")

    def test_final_step_is_reserved_for_closing(self) -> None:
        """**最后一步正常步**只接受收尾动作（给模型一次自己交总结的机会）。

        实测数据支撑：收尾回合上线后 `max_steps` 终态归零，但仍有约 10% 的子任务
        落在 `closing_no_finish`（系统代写总结）——模型把最后一步继续花在探测上。
        把最后一步的用途收窄，模型才有机会在**自己的预算内**交出总结。

        判据必须落在"探测动作没有执行"上（而不是只看提示词里说了什么）。
        """
        tools = FakeTools()
        result = agent.ReActAgent(
            NeverFinishingLLM(), tools, max_steps=4, budget=Budget()
        ).run("goal")
        final_probe = [s for s in result.steps if s.get("step") == 4]
        self.assertTrue(final_probe, "第 4 步应当存在")
        self.assertIn("最后一步", final_probe[0]["observation"])
        # 前 3 步真的探测过；第 4 步的探测被拒绝（没有留下执行痕迹）
        self.assertEqual(tools.calls.count("http_request"), 3)

    def test_reserved_final_step_can_still_finish(self) -> None:
        """模型在第 4 步交出总结 → 终态是它自己收的尾（`finish`，不是代写）。"""

        class FinishesOnFinalStep:
            def __init__(self) -> None:
                self.calls = 0

            def complete(self, messages):
                self.calls += 1
                usage = SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2)
                if self.calls >= 4:
                    return json.dumps(
                        {"action": "finish_task", "action_input": {"summary": "我自己收的尾"}}
                    ), usage
                return json.dumps({"action": "think", "action_input": {"note": "继续"}}), usage

        result = agent.ReActAgent(
            FinishesOnFinalStep(), FakeTools(), max_steps=4, budget=Budget()
        ).run("goal")
        self.assertEqual(result.finish_reason, "finish")
        self.assertEqual(result.final_summary, "我自己收的尾")
        self.assertEqual(result.closing["attempted"], 0, "不该用到收尾回合")

    def test_tiny_budgets_are_not_locked_down(self) -> None:
        """步数预算太小时不预留最后一步——否则整个子任务一步都探测不了。"""
        tools = FakeTools()
        agent.ReActAgent(NeverFinishingLLM(), tools, max_steps=2, budget=Budget()).run("goal")
        self.assertGreaterEqual(tools.calls.count("http_request"), 2)

    def test_provider_error_is_a_terminal_state_with_output_preserved(self) -> None:
        """provider 故障必须形成明确终态，且**保住已记录的发现**。"""

        class FlakyLLM:
            def __init__(self) -> None:
                self.calls = 0

            def complete(self, messages):
                self.calls += 1
                if self.calls >= 2:
                    raise RuntimeError("provider down")
                return json.dumps(
                    {"action": "think", "action_input": {"note": "先想一想"}}
                ), SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2)

        result = agent.ReActAgent(FlakyLLM(), FakeTools(), max_steps=5).run("goal")
        self.assertEqual(result.finish_reason, "provider_error")
        self.assertIn("provider down", result.final_summary)
        # 中断前的步骤仍然在结果里（不是空壳）
        self.assertTrue(result.steps)
        self.assertEqual(result.steps[0]["action"], "think")

    def test_closing_rounds_are_bounded(self) -> None:
        """收尾回合**最多** MAX_CLOSING_ROUNDS 个——不能变成"再跑一轮"。"""
        llm = NeverFinishingLLM()
        result = agent.ReActAgent(llm, FakeTools(), max_steps=3, budget=Budget()).run("goal")
        self.assertEqual(llm.calls, 3 + agent.MAX_CLOSING_ROUNDS)
        self.assertLessEqual(result.closing["attempted"], agent.MAX_CLOSING_ROUNDS)

    def test_parse_failure_twice_stops(self) -> None:
        class GarbageLLM:
            def complete(self, messages):
                return "这不是 JSON", SimpleNamespace(
                    prompt_tokens=1, completion_tokens=1, total_tokens=2
                )

        result = agent.ReActAgent(GarbageLLM(), FakeTools(), max_steps=5).run("goal")
        self.assertEqual(result.finish_reason, "parse_error")
        self.assertTrue(any(step["action"] == "parse_error" for step in result.steps))


class ClosingHandoffTests(unittest.TestCase):
    """`closing_no_finish` 的对症修法：写完记录后**补授一个只许交总结的回合**。

    实测数据（四轮 live 评测、25 个未收尾子任务）：**100% 的最后一步都是记录类动作**
    （record_coverage 12 / leave_note 11 / record_finding 2），
    而所有正常收尾的任务最后一步都是 `finish_task`。
    模型不是不肯交总结，而是把收尾回合全花在写东西上，写到没步数了。

    边界同样重要：只对**记录类**动作补授（试图探测的那种保持原样——再给一轮也只是重复），
    上限**一次**，且该回合只接受 `finish_task`（不可能变成新一轮扫描）。
    """

    class RecordingLLM:
        """正常步探测；进收尾后一直写记录——直到被要求交总结。"""

        def __init__(self, finish_when_told: bool = True) -> None:
            self.calls = 0
            self.finish_when_told = finish_when_told
            self.saw_handoff = False

        def complete(self, messages):
            self.calls += 1
            text = "\n".join(str(m.get("content", "")) for m in messages)
            usage = SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2)
            if "<handoff>" in text:
                self.saw_handoff = True
                if self.finish_when_told:
                    return json.dumps(
                        {"action": "finish_task", "action_input": {"summary": "写完记录后交总结"}}
                    ), usage
                return json.dumps(
                    {"action": "record_coverage",
                     "action_input": {"target": "/x", "status": "no_issue_found"}}
                ), usage
            if "收尾回合" in text or "最后一步" in text:
                return json.dumps(
                    {"action": "record_coverage",
                     "action_input": {"target": "/x", "status": "no_issue_found"}}
                ), usage
            return json.dumps({"action": "http_request", "action_input": {"url": "x"}}), usage

    def test_recording_on_the_last_step_earns_one_handoff_round(self) -> None:
        llm = self.RecordingLLM()
        result = agent.ReActAgent(llm, FakeTools(), max_steps=2, budget=Budget()).run("goal")
        self.assertTrue(llm.saw_handoff, "应当补授交总结的回合")
        self.assertEqual(result.finish_reason, "finish", "补授后应当由模型自己收尾")
        self.assertEqual(result.final_summary, "写完记录后交总结")
        self.assertTrue(result.closing["handoff"])

    def test_handoff_round_accepts_only_finish_task(self) -> None:
        """补授回合里再写记录 → 拒绝，且**不执行**（否则又变成写东西的回合）。"""
        llm = self.RecordingLLM(finish_when_told=False)
        tools = FakeTools()
        result = agent.ReActAgent(llm, tools, max_steps=2, budget=Budget()).run("goal")
        handoff_steps = [s for s in result.steps if s.get("handoff")]
        self.assertTrue(handoff_steps, "应当留下补授回合的步骤记录")
        for step in handoff_steps:
            # 步骤里记的是"模型尝试了什么"，观察结果是拒绝——关键是它没被执行
            self.assertIn("只接受 finish_task", step["observation"])
        # 收尾回合里的记录动作照常执行；**补授回合里的**一次都不许执行
        tried = [s for s in result.steps if s["action"] == "record_coverage"]
        handoff_tried = [s for s in tried if s.get("handoff")]
        self.assertTrue(handoff_tried, "补授回合应当有被拒的记录动作")
        self.assertEqual(
            tools.calls.count("record_coverage"), len(tried) - len(handoff_tried),
            "补授回合里的记录动作不该被执行",
        )

    def test_handoff_happens_at_most_once(self) -> None:
        llm = self.RecordingLLM(finish_when_told=False)
        result = agent.ReActAgent(llm, FakeTools(), max_steps=3, budget=Budget()).run("goal")
        # 3 个正常步 + 2 个收尾回合 + 1 个补授回合；补授回合里可能因解析/拒绝重试
        self.assertLessEqual(llm.calls, 3 + agent.MAX_CLOSING_ROUNDS + 1 + 1)
        handoff = [s for s in result.steps if s.get("handoff")]
        self.assertLessEqual(len({s["step"] for s in handoff}), 1, "补授只发生一次")
        self.assertEqual(result.finish_reason, "closing_no_finish", "没交出总结仍是未收尾")

    def test_probing_on_the_last_step_gets_no_handoff(self) -> None:
        """最后一步在**试图探测**（被拒绝）→ 不补授：再给一轮也只是重复。"""
        llm = NeverFinishingLLM()
        agent.ReActAgent(llm, FakeTools(), max_steps=3, budget=Budget()).run("goal")
        self.assertEqual(llm.calls, 3 + agent.MAX_CLOSING_ROUNDS)

    def test_finishing_on_the_last_step_gets_no_handoff(self) -> None:
        class Finishing:
            def __init__(self) -> None:
                self.calls = 0

            def complete(self, messages):
                self.calls += 1
                usage = SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2)
                if self.calls >= 2:
                    return json.dumps(
                        {"action": "finish_task", "action_input": {"summary": "正常收尾"}}
                    ), usage
                return json.dumps(
                    {"action": "record_coverage",
                     "action_input": {"target": "/x", "status": "no_issue_found"}}
                ), usage

        llm = Finishing()
        result = agent.ReActAgent(llm, FakeTools(), max_steps=2, budget=Budget()).run("goal")
        self.assertEqual(result.finish_reason, "finish")
        self.assertFalse(result.closing["handoff"], "正常收尾不该花补授回合")
        self.assertEqual(llm.calls, 2)

    def test_no_handoff_when_budget_cannot_pay_for_it(self) -> None:
        """预算已经花光 → 不补授（补授是"把总结要回来"，不是"超额再跑一轮"）。"""
        budget = Budget(BudgetLimits(max_llm_calls=4))
        llm = self.RecordingLLM()
        result = agent.ReActAgent(llm, FakeTools(), max_steps=4, budget=budget).run("goal")
        self.assertFalse(result.closing["handoff"])
        self.assertLessEqual(llm.calls, 4)


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
