"""预算记账与任务收敛测试：原子扣减、单调时钟、波次时间闸门、收尾终态。

这一层要防的是**静默的超额**：
- 并发 worker 同时越过 `--max-tool-calls`（经典 TOCTOU）；
- 单任务用量被邻居污染（全局快照前后差值）；
- 系统校时把墙钟 deadline 拉飞；
- 收尾回合退化成"又一轮扫描"。

每个用例都对应一个具体的失败模式，不是"接口能不能调通"。
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

from hexhound.budget import Budget, BudgetLimits, TaskUsage  # noqa: E402
from hexhound.llm import LLMUsage  # noqa: E402

TARGET = "http://hexhound-test.invalid"
ALLOWED = frozenset({"127.0.0.1", "localhost", "hexhound-test.invalid"})


class AtomicToolCallTests(unittest.TestCase):
    """`reserve_tool_call()` 必须让"检查 + 扣减"不可分割。

    早先的写法是 `budget.can_spend()` 然后事后 `add_tool_call()`：
    两步之间没有互斥，N 个 worker 能**一起**通过检查、**一起**记账，
    于是 `--max-tool-calls 300` 在 3 个并发子代理下能跑出 300+N 次。
    """

    def test_reserve_stops_exactly_at_the_limit(self) -> None:
        budget = Budget(BudgetLimits(max_tool_calls=3))
        results = [budget.reserve_tool_call() for _ in range(5)]
        granted = [ok for ok, _ in results]
        self.assertEqual(granted, [True, True, True, False, False])
        self.assertEqual(budget.usage.tool_calls, 3)

    def test_concurrent_reservations_never_exceed_the_limit(self) -> None:
        """并发测试：40 个线程抢 10 个名额，成功数必须**恰好**是 10。"""
        limit = 10
        budget = Budget(BudgetLimits(max_tool_calls=limit))
        successes = 0
        failures = 0
        lock = threading.Lock()
        barrier = threading.Barrier(40)

        def worker() -> None:
            nonlocal successes, failures
            barrier.wait()  # 对齐起跑线，最大化竞争
            ok, _ = budget.reserve_tool_call()
            with lock:
                if ok:
                    successes += 1
                else:
                    failures += 1

        threads = [threading.Thread(target=worker) for _ in range(40)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(successes, limit, "成功占用数必须精确等于上限")
        self.assertEqual(failures, 40 - limit)
        self.assertEqual(budget.usage.tool_calls, limit)

    def test_concurrent_batch_reservations_do_not_overshoot(self) -> None:
        """批量占用（count>1）同样不能超：20 个线程各要 3 个，上限 10 → 最多 3 次成功。"""
        budget = Budget(BudgetLimits(max_tool_calls=10))
        successes: list[int] = []
        lock = threading.Lock()
        barrier = threading.Barrier(20)

        def worker() -> None:
            barrier.wait()
            ok, _ = budget.reserve_tool_call(3)
            if ok:
                with lock:
                    successes.append(3)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertLessEqual(budget.usage.tool_calls, 10)
        self.assertEqual(budget.usage.tool_calls, 3 * len(successes))

    def test_failed_reservation_does_not_consume_quota(self) -> None:
        """拒绝时**不能**扣额度：否则并发下剩余名额会被白吃掉。"""
        budget = Budget(BudgetLimits(max_tool_calls=2))
        self.assertTrue(budget.reserve_tool_call()[0])
        ok, _ = budget.reserve_tool_call(2)  # 1 + 2 > 2 → 拒绝
        self.assertFalse(ok)
        self.assertEqual(budget.usage.tool_calls, 1)
        # 额度还在，下一个 1 个名额的请求应当成功
        self.assertTrue(budget.reserve_tool_call()[0])
        self.assertEqual(budget.usage.tool_calls, 2)

    def test_reservation_is_refused_when_another_limit_is_exhausted(self) -> None:
        """非工具类限制已越线时，工具名额也不该继续放行。"""
        budget = Budget(BudgetLimits(max_tool_calls=100, max_cost=0.01))
        budget.usage.estimated_cost = 0.02
        ok, reason = budget.reserve_tool_call()
        self.assertFalse(ok)
        self.assertIn("费用", reason)
        self.assertEqual(budget.usage.tool_calls, 0)

    def test_llm_reservation_is_atomic_too(self) -> None:
        budget = Budget(BudgetLimits(max_llm_calls=5))
        successes = 0
        lock = threading.Lock()
        barrier = threading.Barrier(30)

        def worker() -> None:
            nonlocal successes
            barrier.wait()
            if budget.reserve_llm_call()[0]:
                with lock:
                    successes += 1

        threads = [threading.Thread(target=worker) for _ in range(30)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(successes, 5)

    def test_reserve_records_into_task_usage(self) -> None:
        budget = Budget(BudgetLimits(max_tool_calls=10))
        usage = TaskUsage(label="T1")
        budget.reserve_tool_call(2, task=usage)
        self.assertEqual(usage.tool_calls, 2)
        self.assertEqual(budget.usage.tool_calls, 2)


class PerTaskUsageTests(unittest.TestCase):
    """每个任务必须有自己的账本——并发下全局前后差值会把邻居算进来。"""

    def test_task_usage_accumulates_independently(self) -> None:
        budget = Budget()
        first = TaskUsage(label="T1")
        second = TaskUsage(label="T2")
        budget.add_usage(LLMUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150), task=first)
        budget.add_usage(LLMUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15), task=second)
        budget.add_usage(LLMUsage(prompt_tokens=1, completion_tokens=1, total_tokens=2))

        self.assertEqual(first.total_tokens, 150)
        self.assertEqual(first.llm_calls, 1)
        self.assertEqual(second.total_tokens, 15)
        self.assertEqual(second.llm_calls, 1)
        # 全局账本包含全部三次
        self.assertEqual(budget.usage.total_tokens, 167)
        self.assertEqual(budget.usage.llm_calls, 3)

    def test_task_usage_survives_concurrent_accounting(self) -> None:
        """并发累加：每个任务的账本只包含自己的消耗。"""
        budget = Budget()
        usages = [TaskUsage(label=f"T{index}") for index in range(8)]
        barrier = threading.Barrier(8)

        def worker(usage: TaskUsage) -> None:
            barrier.wait()
            for _ in range(20):
                budget.add_usage(
                    LLMUsage(prompt_tokens=10, completion_tokens=0, total_tokens=10),
                    task=usage,
                )

        threads = [threading.Thread(target=worker, args=(u,)) for u in usages]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        for usage in usages:
            self.assertEqual(usage.total_tokens, 200)
            self.assertEqual(usage.llm_calls, 20)
        self.assertEqual(budget.usage.llm_calls, 8 * 20)

    def test_task_usage_serialises(self) -> None:
        usage = TaskUsage(label="T1")
        usage.add_tools(3)
        data = usage.to_dict()
        self.assertEqual(data["label"], "T1")
        self.assertEqual(data["tool_calls"], 3)
        self.assertIn("estimated_cost", data)


class MonotonicClockTests(unittest.TestCase):
    """墙钟 deadline 必须走单调时钟：系统校时不该让预算失效或误触发。"""

    def test_wall_clock_jump_does_not_affect_deadline(self) -> None:
        """回归：`time.time()` 被 NTP 向前拉 1 小时后，max_seconds 曾被瞬间判超时。"""
        budget = Budget(BudgetLimits(max_seconds=600))
        self.assertFalse(budget.exhausted_reason())
        # 模拟墙上时钟被向前拉 1 小时
        with patch("hexhound.budget.time.time", return_value=time.time() + 3600):
            self.assertFalse(budget.exhausted_reason(), "墙钟跳变不该影响预算判定")
            self.assertLess(budget.usage_ratio(), 1.0)

    def test_wall_clock_jump_backwards_does_not_disable_the_limit(self) -> None:
        budget = Budget(BudgetLimits(max_seconds=1))
        # 单调时钟被推进 5 秒 → 必然越线（不看墙上时钟）
        with patch("hexhound.budget.time.monotonic", return_value=time.monotonic() + 5):
            self.assertIn("时间预算用尽", budget.exhausted_reason())

    def test_elapsed_uses_monotonic(self) -> None:
        budget = Budget()
        with patch("hexhound.budget.time.monotonic", return_value=budget._started_monotonic + 42):
            self.assertAlmostEqual(budget.elapsed_seconds(), 42.0, places=3)

    def test_remaining_seconds(self) -> None:
        budget = Budget(BudgetLimits(max_seconds=100))
        with patch("hexhound.budget.time.monotonic", return_value=budget._started_monotonic + 30):
            self.assertAlmostEqual(budget.remaining_seconds(), 70.0, places=3)
        # 不设上限时返回 None（表示"没有时间约束"，不是"剩余 0"）
        self.assertIsNone(Budget().remaining_seconds())

    def test_remaining_seconds_never_negative(self) -> None:
        budget = Budget(BudgetLimits(max_seconds=10))
        with patch("hexhound.budget.time.monotonic", return_value=budget._started_monotonic + 99):
            self.assertEqual(budget.remaining_seconds(), 0.0)

    def test_started_at_kept_for_display(self) -> None:
        """展示用的墙钟起点仍然保留（报告里写"开始于何时"有意义）。"""
        budget = Budget()
        self.assertGreater(budget.started_at, 0)
        self.assertIn("elapsed_seconds", budget.snapshot())


class WaveTimeGuardTests(unittest.TestCase):
    """波次边界的时间闸门：时间不够就不开新的一波。

    HANDOVER §10 第 4 条："运行时长无界"——两轮补扫 × (端点 + 参数)
    实测能拖到 20 分钟。`MAX_SECONDS` 只在工具调用之间生效，
    管不住"要不要再开一波"。
    """

    def make(self, **overrides):
        from hexhound.mockllm import ScriptedLLM
        from hexhound.orchestrator import Orchestrator

        settings = {
            "target": TARGET,
            "goal": "测试波次时间闸门",
            "mode": "blackbox",
            "base_dir": Path("."),
            "allowed_hosts": ALLOWED,
            "timeout": 1,
            "max_tasks": 2,
            "task_steps": 4,
            "parallel": 1,
            "budget": Budget(BudgetLimits(max_tool_calls=200)),
        }
        settings.update(overrides)
        return Orchestrator(ScriptedLLM(), **settings)

    def test_no_time_limit_always_allows(self) -> None:
        orchestrator = self.make()
        self.assertTrue(orchestrator._may_start_wave("任意阶段"))

    def test_plenty_of_time_allows(self) -> None:
        orchestrator = self.make(budget=Budget(BudgetLimits(max_seconds=3600)))
        self.assertTrue(orchestrator._may_start_wave("任意阶段"))

    def test_insufficient_time_refuses_and_records_an_event(self) -> None:
        budget = Budget(BudgetLimits(max_seconds=100))
        orchestrator = self.make(budget=budget)
        with patch("hexhound.budget.time.monotonic", return_value=budget._started_monotonic + 99):
            self.assertFalse(orchestrator._may_start_wave("覆盖率补扫第 2 轮"))
        events = [event for event in orchestrator.events if event["kind"] == "time_budget_stop"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["stage"], "覆盖率补扫第 2 轮")
        self.assertIn("已跳过该波次", events[0]["message"])

    def test_user_stop_also_refuses(self) -> None:
        from hexhound.orchestrator import SwarmCallbacks

        orchestrator = self.make(callbacks=SwarmCallbacks(should_stop=lambda: True))
        self.assertFalse(orchestrator._may_start_wave("任意阶段"))

    def test_exhausted_budget_refuses(self) -> None:
        """工具名额已用尽 → 不再开新波（注意 0 = 不限制，必须给非零上限）。"""
        budget = Budget(BudgetLimits(max_tool_calls=5))
        budget.usage.tool_calls = 5
        orchestrator = self.make(budget=budget)
        self.assertFalse(orchestrator._may_start_wave("任意阶段"))

    def test_zero_limit_means_unlimited(self) -> None:
        """守护约定：0 = 不限制。若有人把 0 改成"零容忍"，这条会红。"""
        budget = Budget(BudgetLimits(max_tool_calls=0))
        budget.usage.tool_calls = 9999
        self.assertFalse(budget.exhausted_reason())
        self.assertTrue(self.make(budget=budget)._may_start_wave("任意阶段"))

    def test_run_skips_late_waves_when_time_runs_out(self) -> None:
        """端到端：时间不够时后面的补扫波不执行，但运行**正常结束**并出报告。"""
        budget = Budget(BudgetLimits(max_tool_calls=200, max_seconds=1))
        orchestrator = self.make(budget=budget, max_tasks=3)
        orchestrator.surface.add_endpoint(TARGET + "/a?q=1", params=["q"], source="crawl")
        orchestrator.surface.add_endpoint(TARGET + "/b?q=1", params=["q"], source="crawl")
        with patch("hexhound.budget.time.monotonic", return_value=budget._started_monotonic + 999):
            result = orchestrator.run()
        self.assertIsNotNone(result)
        # 第一个波次也不该开始
        self.assertFalse(orchestrator._may_start_wave("任意阶段"))
        skipped = [event for event in orchestrator.events if event["kind"] == "time_budget_stop"]
        self.assertTrue(skipped)


class ClosingRoundIntegrationTests(unittest.TestCase):
    """收尾回合在**编排层**的终态映射：`closing_no_finish` 算"已收尾"。"""

    def test_outcome_mapping(self) -> None:
        from hexhound.agent import AgentResult
        from hexhound.orchestrator import (
            CLOSED_OUTCOMES,
            INCOMPLETE_OUTCOMES,
            OUTCOME_LABEL,
            _outcome_for,
        )

        self.assertEqual(_outcome_for(AgentResult(finish_reason="finish")), "done")
        self.assertEqual(
            _outcome_for(AgentResult(finish_reason="closing_no_finish")),
            "closing_no_finish",
        )
        self.assertEqual(_outcome_for(AgentResult(finish_reason="budget")), "budget")
        # closing_no_finish 属于"已收尾"，但展示文案明确区分两种收尾方式
        self.assertIn("closing_no_finish", CLOSED_OUTCOMES)
        self.assertNotIn("closing_no_finish", INCOMPLETE_OUTCOMES)
        self.assertNotEqual(OUTCOME_LABEL["done"], OUTCOME_LABEL["closing_no_finish"])

    def test_every_terminal_state_has_a_label(self) -> None:
        """任何终态都必须有中文文案——报告里出现裸 `closing_failed` 是缺陷。"""
        from hexhound.agent import CLOSE_REASON_SYNTHESIZED, CLOSE_REASON_UNCLOSED
        from hexhound.orchestrator import OUTCOME_LABEL

        for state in (
            "done", "pending", "max_steps", CLOSE_REASON_SYNTHESIZED, CLOSE_REASON_UNCLOSED,
            "budget", "supervisor_abort", "stopped", "parse_error", "provider_error",
            "failed", "skipped",
        ):
            self.assertIn(state, OUTCOME_LABEL, f"终态 {state} 缺少展示文案")

    def test_ledger_usage_comes_from_the_task_not_a_global_delta(self) -> None:
        """回归：并发时全局前后差值会把邻居的消耗记到本任务头上。

        实测现象：一个 0 步任务的台账里出现几万 token。
        """
        from hexhound.mockllm import ScriptedLLM
        from hexhound.orchestrator import Orchestrator

        budget = Budget(BudgetLimits(max_tool_calls=300))
        orchestrator = Orchestrator(
            ScriptedLLM(),
            target=TARGET,
            goal="台账用量",
            mode="blackbox",
            base_dir=Path("."),
            allowed_hosts=ALLOWED,
            timeout=1,
            max_tasks=2,
            task_steps=4,
            parallel=2,
            budget=budget,
        )
        # 伪造"别人的消耗"：如果实现仍用全局差值，它会被算进本任务
        budget.usage.total_tokens = 999_999
        budget.usage.estimated_cost = 12.34
        orchestrator.run()
        records = orchestrator.ledger.records()
        self.assertTrue(records)
        for record in records:
            self.assertLess(record.total_tokens, 999_999)
            self.assertLess(record.estimated_cost, 12.34)
        # 各任务台账用量之和 **小于等于** 本次真实新增用量：
        # 差值来自**规划阶段**的 LLM 调用——它不属于任何子任务，
        # 因此永远不会出现在明细里（这一点是刻意的，不是漏记）。
        real_spend = budget.usage.total_tokens - 999_999
        attributed = sum(record.total_tokens for record in records)
        self.assertLessEqual(attributed, real_spend)
        self.assertGreater(attributed, 0)
        # 关键回归：归属量必须远小于"全局差值"式的错误记账
        self.assertLess(attributed, 999_999)


if __name__ == "__main__":
    unittest.main()
