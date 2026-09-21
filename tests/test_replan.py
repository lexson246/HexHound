"""有界动态重规划与监督器测试。

需求里逐条对应的用例：
- 只允许在 wave 边界重规划（由编排器保证，这里验证政策与判定）；
- 结构化 patch 表达 add/update/remove；
- 新增任务数、重规划次数、总任务数、深度上限；
- 不允许通过重规划扩大授权目标范围；
- 任务 ID、依赖关系确定且可重放；
- 每次变化写入 trace；
- supervisor 检测重复工具调用、长期无进展、相同失败循环；
- 达到阈值后先干预，再优雅结束（不是直接崩掉）。
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.replan import (  # noqa: E402
    MAX_DEPENDENCY_DEPTH,
    MAX_NEW_TASKS_PER_PATCH,
    MAX_REPLAN_ROUNDS,
    MAX_TOTAL_TASKS,
    MUTABLE_FIELDS,
    PatchResult,
    PlanEntry,
    ReplanError,
    ReplanPolicy,
    apply_patch,
    check_scope_unchanged,
    detect_dependency_cycle,
    deterministic_task_id,
    parse_patch,
    ready_tasks,
)
from hexhound.supervisor import (  # noqa: E402
    FAILURE_ABORT,
    REPEAT_ABORT,
    REPEAT_WARN,
    STALL_ABORT_STEPS,
    STALL_WARN_STEPS,
    Supervisor,
)

ALLOWED = frozenset({"127.0.0.1", "localhost", "other.example.com"})
TARGET = "http://127.0.0.1:5000"
TARGET_HOST = "127.0.0.1"


def make_plan() -> list[PlanEntry]:
    return [
        PlanEntry(id="T1", role="recon", objective="侦察", url=TARGET, steps=8),
        PlanEntry(id="T2", role="injection", objective="注入", url=TARGET + "/a", steps=6),
    ]


class DeterministicIdTests(unittest.TestCase):
    """任务 ID 必须确定且可重放。"""

    def test_same_input_same_id(self) -> None:
        first = deterministic_task_id("recon", TARGET, "看看首页")
        second = deterministic_task_id("recon", TARGET, "看看首页")
        self.assertEqual(first, second)

    def test_different_input_different_id(self) -> None:
        first = deterministic_task_id("recon", TARGET, "看看首页")
        second = deterministic_task_id("recon", TARGET, "看看登录页")
        self.assertNotEqual(first, second)

    def test_id_is_short_and_marked_as_replanned(self) -> None:
        task_id = deterministic_task_id("injection", TARGET, "测 id 参数")
        self.assertTrue(task_id.startswith("R-"))
        self.assertLessEqual(len(task_id), 12)

    def test_add_without_id_gets_the_deterministic_one(self) -> None:
        ops = parse_patch(
            {"ops": [{"op": "add", "role": "recon", "objective": "看首页", "url": TARGET}]}
        )
        first, _ = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        second, _ = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertEqual(
            [entry.id for entry in first], [entry.id for entry in second],
            "同一输入必须产出同一组 id（可重放）",
        )


class PatchParsingTests(unittest.TestCase):
    def test_ops_wrapper_form(self) -> None:
        ops = parse_patch({"ops": [{"op": "add", "role": "recon", "objective": "x"}]})
        self.assertEqual(len(ops), 1)
        self.assertEqual(ops[0]["op"], "add")

    def test_bare_array_form(self) -> None:
        ops = parse_patch([{"op": "remove", "id": "T1"}])
        self.assertEqual(ops[0]["op"], "remove")

    def test_operations_alias(self) -> None:
        ops = parse_patch({"operations": [{"op": "remove", "id": "T1"}]})
        self.assertEqual(len(ops), 1)

    def test_unknown_op_is_rejected(self) -> None:
        with self.assertRaises(ReplanError) as ctx:
            parse_patch({"ops": [{"op": "rewrite_everything"}]})
        self.assertIn("不受支持", str(ctx.exception))

    def test_missing_ops_is_rejected(self) -> None:
        with self.assertRaises(ReplanError) as ctx:
            parse_patch({"thought": "我随便改改"})
        self.assertIn("ops", str(ctx.exception))

    def test_empty_ops_is_rejected(self) -> None:
        with self.assertRaises(ReplanError):
            parse_patch({"ops": []})

    def test_non_object_operation_is_rejected(self) -> None:
        with self.assertRaises(ReplanError):
            parse_patch({"ops": ["add a task"]})


class AddOperationTests(unittest.TestCase):
    def test_add_appends_a_task(self) -> None:
        ops = parse_patch(
            {"ops": [{"op": "add", "role": "auth", "objective": "越权测试",
                      "url": TARGET + "/admin", "steps": 8}]}
        )
        plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertTrue(result.ok)
        self.assertEqual(len(plan), 3)
        self.assertEqual(plan[-1].role, "auth")
        self.assertEqual(plan[-1].source, "replan")
        self.assertEqual(len(result.applied), 1)

    def test_new_tasks_per_patch_is_capped(self) -> None:
        ops = parse_patch(
            {"ops": [
                {"op": "add", "role": "recon", "objective": f"任务 {index}", "url": TARGET}
                for index in range(MAX_NEW_TASKS_PER_PATCH + 3)
            ]}
        )
        plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        added = [item for item in result.applied if item["op"] == "add"]
        self.assertEqual(len(added), MAX_NEW_TASKS_PER_PATCH)
        self.assertEqual(len(result.rejected), 3)
        self.assertTrue(all("上限" in item["reason"] for item in result.rejected))
        self.assertEqual(len(plan), 2 + MAX_NEW_TASKS_PER_PATCH)

    def test_total_task_cap_is_enforced(self) -> None:
        ops = parse_patch(
            {"ops": [{"op": "add", "role": "recon", "objective": "x", "url": TARGET}]}
        )
        _plan, result = apply_patch(
            make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST,
            total_tasks=MAX_TOTAL_TASKS,
        )
        self.assertFalse(result.applied)
        self.assertTrue(any("总数已达上限" in item["reason"] for item in result.rejected))

    def test_invalid_role_is_rejected(self) -> None:
        ops = parse_patch({"ops": [{"op": "add", "role": "hacker", "objective": "x"}]})
        _plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertTrue(any("不是合法角色" in item["reason"] for item in result.rejected))

    def test_missing_objective_is_rejected(self) -> None:
        ops = parse_patch({"ops": [{"op": "add", "role": "recon", "objective": "  "}]})
        _plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertTrue(any("objective" in item["reason"] for item in result.rejected))

    def test_steps_are_clamped(self) -> None:
        ops = parse_patch(
            {"ops": [{"op": "add", "role": "recon", "objective": "x", "url": TARGET, "steps": 999}]}
        )
        plan, _result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertLessEqual(plan[-1].steps, 20)
        self.assertGreaterEqual(plan[-1].steps, 4)

    def test_dependency_on_missing_task_is_rejected(self) -> None:
        ops = parse_patch(
            {"ops": [{"op": "add", "role": "recon", "objective": "x", "url": TARGET,
                      "depends_on": ["T999"]}]}
        )
        _plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertTrue(any("依赖的任务不存在" in item["reason"] for item in result.rejected))

    def test_dependency_depth_is_capped(self) -> None:
        ops = parse_patch(
            {"ops": [{"op": "add", "role": "recon", "objective": "x", "url": TARGET,
                      "depends_on": ["T1"] * (MAX_DEPENDENCY_DEPTH + 2)}]}
        )
        _plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertTrue(any("依赖数" in item["reason"] for item in result.rejected))

    def test_duplicate_id_is_rejected(self) -> None:
        """add 不能覆盖已有任务——那会静默替换掉一个可能已经跑过的任务。"""
        ops = parse_patch(
            {"ops": [{"op": "add", "id": "T1", "role": "recon", "objective": "x", "url": TARGET}]}
        )
        _plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertTrue(any("已存在" in item["reason"] for item in result.rejected))

    def test_add_with_existing_id_from_run_is_rejected(self) -> None:
        ops = parse_patch(
            {"ops": [{"op": "add", "id": "S1", "role": "recon", "objective": "x", "url": TARGET}]}
        )
        _plan, result = apply_patch(
            make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST,
            existing_ids=["S1"],
        )
        self.assertTrue(any("已存在" in item["reason"] for item in result.rejected))


class UpdateOperationTests(unittest.TestCase):
    def test_update_changes_mutable_fields(self) -> None:
        ops = parse_patch(
            {"ops": [{"op": "update", "id": "T2",
                      "changes": {"objective": "改成测 id 参数", "steps": 12}}]}
        )
        plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        updated = next(entry for entry in plan if entry.id == "T2")
        self.assertEqual(updated.objective, "改成测 id 参数")
        self.assertEqual(updated.steps, 12)
        self.assertTrue(result.ok)

    def test_update_cannot_change_id_role_or_url(self) -> None:
        """改 id/role/url 会让台账、证据归属或攻击目标与已发生的执行对不上。"""
        for field, value in (("id", "T9"), ("role", "auth"), ("url", "http://other.example.com/x")):
            ops = parse_patch({"ops": [{"op": "update", "id": "T1", "changes": {field: value}}]})
            _plan, result = apply_patch(
                make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST
            )
            self.assertTrue(
                any("不允许修改字段" in item["reason"] for item in result.rejected),
                f"{field} 必须不可改：{result.rejected}",
            )

    def test_mutable_fields_are_exactly_documented(self) -> None:
        """守护常量：可改字段集合变了，测试必须跟着变。"""
        self.assertEqual(set(MUTABLE_FIELDS), {"objective", "steps", "depends_on", "priority"})

    def test_update_unknown_task_is_rejected(self) -> None:
        ops = parse_patch({"ops": [{"op": "update", "id": "T999", "changes": {"steps": 5}}]})
        _plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertTrue(any("没有任务" in item["reason"] for item in result.rejected))

    def test_update_without_changes_is_rejected(self) -> None:
        ops = parse_patch({"ops": [{"op": "update", "id": "T1"}]})
        _plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertTrue(any("changes" in item["reason"] for item in result.rejected))

    def test_out_of_range_steps_is_rejected(self) -> None:
        for value in (0, -3, 99):
            ops = parse_patch({"ops": [{"op": "update", "id": "T1", "changes": {"steps": value}}]})
            _plan, result = apply_patch(
                make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST
            )
            self.assertTrue(result.rejected, f"steps={value} 应当被拒")

    def test_non_integer_steps_is_rejected(self) -> None:
        ops = parse_patch({"ops": [{"op": "update", "id": "T1", "changes": {"steps": "很多"}}]})
        _plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertTrue(any("不是整数" in item["reason"] for item in result.rejected))


class RemoveOperationTests(unittest.TestCase):
    def test_remove_drops_the_task(self) -> None:
        ops = parse_patch({"ops": [{"op": "remove", "id": "T2"}]})
        plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertEqual([entry.id for entry in plan], ["T1"])
        self.assertEqual(result.applied[0]["op"], "remove")

    def test_remove_unknown_task_is_rejected(self) -> None:
        ops = parse_patch({"ops": [{"op": "remove", "id": "T404"}]})
        _plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertTrue(any("没有任务" in item["reason"] for item in result.rejected))

    def test_remove_without_id_is_rejected(self) -> None:
        ops = parse_patch({"ops": [{"op": "remove"}]})
        _plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertTrue(any("缺少 id" in item["reason"] for item in result.rejected))


class ScopeUnchangedTests(unittest.TestCase):
    """**重规划不能扩大授权目标范围**——这是这一层最重要的约束。"""

    def test_same_host_passes(self) -> None:
        self.assertEqual(check_scope_unchanged(TARGET + "/x", ALLOWED, TARGET_HOST), "")
        self.assertEqual(check_scope_unchanged("", ALLOWED, TARGET_HOST), "")

    def test_foreign_host_is_refused(self) -> None:
        reason = check_scope_unchanged("http://evil.example.com/x", ALLOWED, TARGET_HOST)
        self.assertIn("不在白名单", reason)

    def test_allowlisted_but_different_host_is_refused(self) -> None:
        """白名单里**也有**别的主机时，仍然只能打本次授权的那一个。

        实测场景：一次运行的白名单同时含 `127.0.0.1` 与生产域名。
        重规划把任务指到另一个，虽然"在白名单内"，但已经越过了本次
        用户明确指定的范围。
        """
        reason = check_scope_unchanged("http://other.example.com/x", ALLOWED, TARGET_HOST)
        self.assertIn("与本次授权目标", reason)

    def test_relative_or_missing_scheme_is_refused(self) -> None:
        for value in ("/api/users", "127.0.0.1:5000/x", "//evil.example.com/x"):
            reason = check_scope_unchanged(value, ALLOWED, TARGET_HOST)
            self.assertTrue(reason, f"{value} 应当被拒")

    def test_add_to_foreign_host_is_rejected_in_patch(self) -> None:
        ops = parse_patch(
            {"ops": [{"op": "add", "role": "injection", "objective": "打外部站",
                      "url": "http://evil.example.com/x"}]}
        )
        plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertEqual(len(plan), 2, "非法任务不得进入计划")
        self.assertTrue(any("不在白名单" in item["reason"] for item in result.rejected))

    def test_add_to_allowlisted_other_host_is_rejected_in_patch(self) -> None:
        ops = parse_patch(
            {"ops": [{"op": "add", "role": "injection", "objective": "横向移动",
                      "url": "http://other.example.com/x"}]}
        )
        plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertEqual(len(plan), 2)
        self.assertTrue(any("与本次授权目标" in item["reason"] for item in result.rejected))


class DependencyTests(unittest.TestCase):
    def test_cycle_is_detected(self) -> None:
        plan = [
            PlanEntry(id="A", role="recon", objective="a", depends_on=["B"]),
            PlanEntry(id="B", role="recon", objective="b", depends_on=["A"]),
        ]
        cycle = detect_dependency_cycle(plan)
        self.assertTrue(cycle)
        self.assertIn("A", cycle)
        self.assertIn("B", cycle)

    def test_self_cycle_is_detected(self) -> None:
        plan = [PlanEntry(id="A", role="recon", objective="a", depends_on=["A"])]
        self.assertTrue(detect_dependency_cycle(plan))

    def test_no_cycle_returns_empty(self) -> None:
        plan = [
            PlanEntry(id="A", role="recon", objective="a"),
            PlanEntry(id="B", role="recon", objective="b", depends_on=["A"]),
        ]
        self.assertEqual(detect_dependency_cycle(plan), [])

    def test_patch_creating_a_cycle_is_rolled_back(self) -> None:
        """带环的计划无法可靠调度 → 整份 patch 回滚。"""
        ops = parse_patch({"ops": [{"op": "update", "id": "T1", "changes": {"depends_on": ["T2"]}},
                                   {"op": "update", "id": "T2", "changes": {"depends_on": ["T1"]}}]})
        plan, result = apply_patch(make_plan(), ops, allowed_hosts=ALLOWED, target_host=TARGET_HOST)
        self.assertFalse(result.ok)
        self.assertIn("依赖环", result.reason)
        self.assertEqual([entry.id for entry in plan], ["T1", "T2"], "必须回滚到原计划")

    def test_ready_tasks_respects_dependencies(self) -> None:
        plan = [
            PlanEntry(id="A", role="recon", objective="a"),
            PlanEntry(id="B", role="injection", objective="b", depends_on=["A"]),
            PlanEntry(id="C", role="auth", objective="c", depends_on=["A", "B"]),
        ]
        self.assertEqual([entry.id for entry in ready_tasks(plan, [])], ["A"])
        self.assertEqual([entry.id for entry in ready_tasks(plan, ["A"])], ["B"])
        self.assertEqual([entry.id for entry in ready_tasks(plan, ["A", "B"])], ["C"])
        # 跑完的任务不再"可执行"（否则调用方会重复派发）
        self.assertEqual([entry.id for entry in ready_tasks(plan, ["A", "B", "C"])], [])

    def test_ready_tasks_ordering_is_deterministic(self) -> None:
        """没有确定性排序，"可重放"就不成立（字典顺序会漂移）。"""
        plan = [
            PlanEntry(id="B", role="recon", objective="b", priority=1),
            PlanEntry(id="A", role="recon", objective="a", priority=1),
            PlanEntry(id="C", role="recon", objective="c", priority=5),
        ]
        first = [entry.id for entry in ready_tasks(plan, [])]
        second = [entry.id for entry in ready_tasks(list(reversed(plan)), [])]
        self.assertEqual(first, second)
        self.assertEqual(first[0], "C", "高优先级优先")

    def test_dependency_on_absent_task_is_treated_as_satisfied(self) -> None:
        """依赖不在计划里（已被移除）视为已满足，而不是永远不就绪。"""
        plan = [PlanEntry(id="B", role="recon", objective="b", depends_on=["GONE"])]
        self.assertEqual([entry.id for entry in ready_tasks(plan, [])], ["B"])


class ReplanPolicyTests(unittest.TestCase):
    def test_round_cap(self) -> None:
        policy = ReplanPolicy(max_rounds=2)
        self.assertTrue(policy.can_replan())
        policy.take()
        policy.take()
        self.assertFalse(policy.can_replan())

    def test_default_round_cap_is_bounded(self) -> None:
        self.assertGreaterEqual(MAX_REPLAN_ROUNDS, 1)
        self.assertLessEqual(MAX_REPLAN_ROUNDS, 10)

    def test_triggers_on_new_gaps(self) -> None:
        policy = ReplanPolicy(min_new_gaps=2)
        before = {"untouched": 5, "params_unattacked": 3}
        after = {"untouched": 9, "params_unattacked": 3}
        should, reason = policy.should_replan(before, after)
        self.assertTrue(should)
        self.assertIn("新盲区", reason)

    def test_does_not_trigger_without_meaningful_growth(self) -> None:
        policy = ReplanPolicy(min_new_gaps=2)
        before = {"untouched": 5, "params_unattacked": 3}
        after = {"untouched": 5, "params_unattacked": 4}
        should, reason = policy.should_replan(before, after)
        self.assertFalse(should)
        self.assertIn("没有明显增长", reason)

    def test_does_not_trigger_when_rounds_are_used_up(self) -> None:
        policy = ReplanPolicy(max_rounds=1)
        policy.take()
        should, reason = policy.should_replan(
            {"untouched": 0, "params_unattacked": 0}, {"untouched": 99, "params_unattacked": 99}
        )
        self.assertFalse(should)
        self.assertIn("轮数已用完", reason)

    def test_summary_shape(self) -> None:
        policy = ReplanPolicy()
        policy.take()
        data = policy.to_dict()
        self.assertEqual(data["rounds_used"], 1)
        self.assertIn("max_rounds", data)


class SupervisorTests(unittest.TestCase):
    """监督器判定：重复 / 停滞 / 相同失败循环，先干预再终止。"""

    def test_normal_steps_produce_no_verdict(self) -> None:
        supervisor = Supervisor()
        for index in range(3):
            verdict = supervisor.observe(
                {"action": "http_request", "action_input": {"url": f"/p{index}"},
                 "observation": f"新增端点 {index}"}
            )
            self.assertEqual(verdict.level, "ok")

    def test_repeat_warn_then_abort(self) -> None:
        supervisor = Supervisor()
        step = {"action": "crawl", "action_input": {"url": "/a"}, "observation": "新增端点 1"}
        levels = [supervisor.observe(step).level for _ in range(REPEAT_ABORT)]
        self.assertEqual(levels[REPEAT_WARN - 1], "warn")
        self.assertEqual(levels[REPEAT_ABORT - 1], "abort")

    def test_identical_arguments_hash_consistently(self) -> None:
        """参数顺序不同但内容相同 → 必须算同一个签名。"""
        supervisor = Supervisor(repeat_warn=2, repeat_abort=99)
        supervisor.observe({"action": "x", "action_input": {"a": 1, "b": 2}})
        verdict = supervisor.observe({"action": "x", "action_input": {"b": 2, "a": 1}})
        self.assertEqual(verdict.level, "warn")

    def test_different_arguments_do_not_count_as_repeats(self) -> None:
        supervisor = Supervisor()
        for index in range(10):
            verdict = supervisor.observe(
                {"action": "http_request", "action_input": {"url": f"/u{index}"},
                 "observation": "200 OK 普通页面"}
            )
            if verdict.level == "abort" and verdict.kind == "repeat":
                self.fail("参数不同不该被判为重复调用")
        # 但会因"无进展"被判停滞 —— 那是另一条判据
        self.assertIn("stall", {item["kind"] for item in supervisor.interventions})

    def test_stall_warn_then_abort(self) -> None:
        supervisor = Supervisor()
        verdicts = []
        for index in range(STALL_ABORT_STEPS):
            verdicts.append(
                supervisor.observe(
                    {"action": "http_request", "action_input": {"url": f"/s{index}"},
                     "observation": "200 OK"}
                )
            )
        self.assertEqual(verdicts[STALL_WARN_STEPS - 1].level, "warn")
        self.assertEqual(verdicts[STALL_ABORT_STEPS - 1].level, "abort")
        self.assertEqual(verdicts[-1].kind, "stall")

    def test_progress_resets_stall(self) -> None:
        supervisor = Supervisor()
        for index in range(STALL_WARN_STEPS):
            supervisor.observe(
                {"action": "http_request", "action_input": {"url": f"/s{index}"},
                 "observation": "200 OK"}
            )
        self.assertGreater(supervisor.stall_steps, 0)
        supervisor.observe(
            {"action": "record_finding", "action_input": {"title": "x"}, "observation": "已记录"}
        )
        self.assertEqual(supervisor.stall_steps, 0)

    def test_state_changing_requests_count_as_progress(self) -> None:
        """回归：**误杀**——一次业务逻辑任务被"无进展"判据中止了。

        实测现场的 7 步（每一步都在推进）：
            1-4  GET 探路 / POST /login 拿会话 / POST /cart 加购
            5    GET /catalog → 观察 1602 字符（真的取回了商品目录）
            6-7  继续 POST 下单
        全部被判"无进展" → 连续 8 步后直接中止。原因是旧判据只看
        "record_* 动作 + 少数中文进展词"，而多步业务逻辑靠 POST 推进、
        既不产生命中信号也不含那些标记。

        该收尾的被中止、该中止的没被中止，是同一类失效。
        """
        supervisor = Supervisor()
        steps = [
            {"action": "http_request", "action_input": {"url": "/cart"}, "observation": "401"},
            {"action": "http_request",
             "action_input": {"url": "/login", "method": "POST", "data": {"username": "x"}},
             "observation": "登录成功"},
            {"action": "http_request",
             "action_input": {"url": "/cart", "method": "POST",
                              "data": {"sku": "SKU-1002", "qty": 1, "price": 0.01}},
             "observation": "已加入购物车"},
            {"action": "http_request", "action_input": {"url": "/catalog"},
             "observation": "x" * 1602},
        ]
        for step in steps:
            verdict = supervisor.observe(step)
            self.assertNotEqual(verdict.kind, "stall", verdict.reason)
        self.assertEqual(supervisor.stall_steps, 0)

    def test_substantial_observation_counts_as_progress(self) -> None:
        supervisor = Supervisor()
        supervisor.observe(
            {"action": "http_request", "action_input": {"url": "/catalog"},
             "observation": "商品目录内容 " * 100}
        )
        self.assertEqual(supervisor.stall_steps, 0)

    def test_request_body_without_method_counts_as_progress(self) -> None:
        """没写 method 但带了 data → 实际语义是提交，也算推进。"""
        supervisor = Supervisor()
        supervisor.observe(
            {"action": "http_request",
             "action_input": {"url": "/cart", "data": {"sku": "SKU-1001"}},
             "observation": "ok"}
        )
        self.assertEqual(supervisor.stall_steps, 0)

    def test_short_get_responses_still_count_as_no_progress(self) -> None:
        """放宽判据**不能**把真停滞也放过：短响应的重复 GET 仍应触发停滞。"""
        supervisor = Supervisor()
        verdicts = []
        for index in range(STALL_ABORT_STEPS):
            verdicts.append(
                supervisor.observe(
                    {"action": "http_request",
                     "action_input": {"url": f"/nope{index}", "method": "GET"},
                     "observation": "404 NOT FOUND"}
                )
            )
        self.assertEqual(verdicts[-1].kind, "stall")
        self.assertTrue(verdicts[-1].abort)

    def test_progress_markers_count_too(self) -> None:
        """观察文本里出现"新增端点"也算进展（模型不必显式调记录类工具）。"""
        supervisor = Supervisor()
        supervisor.observe(
            {"action": "crawl", "action_input": {"url": "/a"}, "observation": "新增端点 3 个"}
        )
        self.assertEqual(supervisor.stall_steps, 0)

    def test_failure_loop_warn_then_abort(self) -> None:
        supervisor = Supervisor()
        levels = []
        for index in range(FAILURE_ABORT):
            levels.append(
                supervisor.observe(
                    {"action": "sqlmap_scan", "action_input": {"url": f"/f{index}"},
                     "observation": "工具执行出错：Timeout"}
                ).level
            )
        self.assertIn("warn", levels)
        self.assertEqual(levels[-1], "abort")

    def test_different_failures_break_the_loop(self) -> None:
        supervisor = Supervisor()
        for index, observation in enumerate(
            ["工具执行出错：Timeout", "请求失败：拒绝", "错误：参数", "工具执行出错：Timeout"]
        ):
            verdict = supervisor.observe(
                {"action": "http_request", "action_input": {"url": f"/d{index}"},
                 "observation": observation}
            )
            self.assertFalse(verdict.abort and verdict.kind == "failure_loop")

    def test_finish_actions_are_not_supervised(self) -> None:
        supervisor = Supervisor()
        for _ in range(20):
            verdict = supervisor.observe({"action": "finish_task", "action_input": {}})
            self.assertEqual(verdict.level, "ok")

    def test_interventions_are_recorded_once_per_kind(self) -> None:
        """同一种干预只记一次——重复记录会让 trace 与报告噪音化。"""
        supervisor = Supervisor(repeat_warn=2, repeat_abort=99)
        step = {"action": "crawl", "action_input": {"url": "/a"}, "observation": "新增端点"}
        for _ in range(6):
            supervisor.observe(step)
        repeats = [
            item for item in supervisor.interventions
            if item["kind"] == "repeat" and item["level"] == "warn"
        ]
        self.assertEqual(len(repeats), 1)

    def test_abort_carries_an_actionable_directive(self) -> None:
        """终止不是"崩掉"：必须给出一条可执行的方向。"""
        supervisor = Supervisor()
        step = {"action": "crawl", "action_input": {"url": "/a"}, "observation": "普通"}
        verdict = None
        for _ in range(REPEAT_ABORT):
            verdict = supervisor.observe(step)
        self.assertTrue(verdict.abort)
        self.assertTrue(verdict.directive)
        self.assertIn("finish_task", verdict.directive)
        self.assertTrue(verdict.reason)

    def test_summary_shape(self) -> None:
        supervisor = Supervisor()
        supervisor.observe({"action": "x", "action_input": {}, "observation": "y"})
        summary = supervisor.summary()
        for key in ("interventions", "stall_steps", "repeat_thresholds",
                    "stall_thresholds", "failure_thresholds"):
            self.assertIn(key, summary)

    def test_thresholds_are_ordered(self) -> None:
        self.assertLess(REPEAT_WARN, REPEAT_ABORT)
        self.assertLess(STALL_WARN_STEPS, STALL_ABORT_STEPS)


class OrchestratorReplanIntegrationTests(unittest.TestCase):
    """编排层接线：重规划只在波次边界发生，且每次变化都写进 trace。

    用脚本 LLM + 打桩的 planner 返回值驱动，**不访问网络**。
    """

    TARGET = "http://hexhound-test.invalid"
    ALLOWED = frozenset({"127.0.0.1", "localhost", "hexhound-test.invalid"})

    def make(self, **overrides):
        from hexhound.budget import Budget, BudgetLimits
        from hexhound.mockllm import ScriptedLLM
        from hexhound.orchestrator import Orchestrator

        settings = {
            "target": self.TARGET,
            "goal": "测试重规划",
            "mode": "blackbox",
            "base_dir": Path("."),
            "allowed_hosts": self.ALLOWED,
            "timeout": 1,
            "max_tasks": 2,
            "task_steps": 3,
            "parallel": 1,
            "budget": Budget(BudgetLimits(max_tool_calls=300)),
        }
        settings.update(overrides)
        return Orchestrator(ScriptedLLM(), **settings)

    def test_replan_adds_a_task_at_a_wave_boundary(self) -> None:
        orchestrator = self.make()
        patch = {
            "ops": [
                {
                    "op": "add",
                    "role": "injection",
                    "objective": "对 /extra 做注入验证",
                    "url": self.TARGET + "/extra",
                    "steps": 6,
                }
            ]
        }

        class PlannerStub:
            def complete(self, messages):
                import json
                from types import SimpleNamespace

                return (
                    json.dumps(patch, ensure_ascii=False),
                    SimpleNamespace(prompt_tokens=10, completion_tokens=5, total_tokens=15),
                )

        orchestrator.llm_pool["planner"] = PlannerStub()
        gate = {"untouched": 5, "params_unattacked": 4, "touched": 1, "total": 6}
        added = orchestrator._run_replan_round(gate, [], [])

        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].role, "injection")
        self.assertTrue(added[0].id.startswith("R-"))
        self.assertEqual(orchestrator.replan_policy.rounds_used, 1)

    def test_replan_writes_trace_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            from hexhound.budget import Budget, BudgetLimits
            from hexhound.memory import RunArtifacts
            from hexhound.mockllm import ScriptedLLM
            from hexhound.orchestrator import Orchestrator
            from hexhound.trace import load_trace

            artifacts = RunArtifacts(self.TARGET, home=Path(tmp))
            orchestrator = Orchestrator(
                ScriptedLLM(),
                target=self.TARGET,
                goal="trace 重规划",
                mode="blackbox",
                base_dir=Path("."),
                allowed_hosts=self.ALLOWED,
                timeout=1,
                max_tasks=2,
                task_steps=3,
                parallel=1,
                budget=Budget(BudgetLimits(max_tool_calls=300)),
                artifacts=artifacts,
            )

            class PlannerStub:
                def complete(self, messages):
                    import json
                    from types import SimpleNamespace

                    return (
                        json.dumps(
                            {"ops": [{"op": "remove", "id": "T404"}]}, ensure_ascii=False
                        ),
                        SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2),
                    )

            orchestrator.llm_pool["planner"] = PlannerStub()
            orchestrator._run_replan_round(
                {"untouched": 5, "params_unattacked": 4}, [], []
            )
            events = load_trace(artifacts.dir / "trace.jsonl")
            kinds = {event.get("kind") for event in events}
            self.assertIn("replan_request", kinds)
            self.assertIn("replan_applied", kinds)
            # 被拒的操作必须留下原因（否则"模型想加但没加"永远查不出来）
            applied = [event for event in events if event.get("kind") == "replan_applied"]
            self.assertTrue(applied)
            self.assertTrue(applied[0]["data"]["rejected"])

    def test_replan_rounds_are_capped(self) -> None:
        orchestrator = self.make()
        orchestrator.replan_policy.rounds_used = MAX_REPLAN_ROUNDS
        added = orchestrator._run_replan_round({"untouched": 9}, [], [])
        self.assertEqual(added, [], "轮数用完后不得再重规划")

    def test_foreign_host_in_replan_is_refused(self) -> None:
        """端到端：模型想在重规划里打别的主机 —— 必须被拒。"""
        orchestrator = self.make()

        class PlannerStub:
            def complete(self, messages):
                import json
                from types import SimpleNamespace

                return (
                    json.dumps(
                        {
                            "ops": [
                                {
                                    "op": "add",
                                    "role": "injection",
                                    "objective": "打外部站",
                                    "url": "http://evil.example.com/x",
                                }
                            ]
                        },
                        ensure_ascii=False,
                    ),
                    SimpleNamespace(prompt_tokens=1, completion_tokens=1, total_tokens=2),
                )

        orchestrator.llm_pool["planner"] = PlannerStub()
        added = orchestrator._run_replan_round({"untouched": 5}, [], [])
        self.assertEqual(added, [], "越界任务不得进入计划")
        messages = [
            event.get("message", "")
            for event in orchestrator.events
            if event.get("kind") == "replan_rejected"
        ]
        self.assertTrue(any("不在白名单" in item for item in messages), messages)

    def test_garbage_replan_output_is_ignored_not_fatal(self) -> None:
        orchestrator = self.make()

        class GarbagePlanner:
            def complete(self, messages):
                from types import SimpleNamespace

                return "我改主意了，全部重写", SimpleNamespace(
                    prompt_tokens=1, completion_tokens=1, total_tokens=2
                )

        orchestrator.llm_pool["planner"] = GarbagePlanner()
        added = orchestrator._run_replan_round({"untouched": 5}, [], [])
        self.assertEqual(added, [])
        self.assertTrue(
            any(event.get("kind") == "replan_rejected" for event in orchestrator.events)
        )

    def test_replan_provider_error_is_not_fatal(self) -> None:
        orchestrator = self.make()

        class BrokenPlanner:
            def complete(self, messages):
                raise RuntimeError("provider down")

        orchestrator.llm_pool["planner"] = BrokenPlanner()
        added = orchestrator._run_replan_round({"untouched": 5}, [], [])
        self.assertEqual(added, [])
        self.assertTrue(
            any(event.get("kind") == "replan_error" for event in orchestrator.events)
        )


class RealRunRegressionTests(unittest.TestCase):
    """回归：一次**真实运行**暴露的三个缺陷（都不是靠读代码想出来的）。

    实测现场：一次对靶场的 audit 里，两个子任务的 trace 记录抛
    `TypeError: TraceRecorder.record() got multiple values for argument 'kind'`
    （被判成"未预期错误中断"），随后波次边界的重规划抛
    `AttributeError: 'WorkerTask' object has no attribute 'outcome_label'`
    ——**整次 audit 以 exit 1 结束**，而那次运行其实已经发现了路径穿越与 SSRF
    两条 critical 结论。

    这些用例的共同点：**必须传入非空的 done 列表**才会走到出问题的那一行。
    早先的测试都传 `done=[]`，于是分支根本没被执行到。
    """

    TARGET = "http://hexhound-test.invalid"
    ALLOWED = frozenset({"127.0.0.1", "localhost", "hexhound-test.invalid"})

    def make(self, **overrides):
        from hexhound.budget import Budget, BudgetLimits
        from hexhound.mockllm import ScriptedLLM
        from hexhound.orchestrator import Orchestrator

        settings = {
            "target": self.TARGET,
            "goal": "回归：真实运行暴露的缺陷",
            "mode": "blackbox",
            "base_dir": Path("."),
            "allowed_hosts": self.ALLOWED,
            "timeout": 1,
            "max_tasks": 3,
            "task_steps": 4,
            "parallel": 1,
            "budget": Budget(BudgetLimits(max_tool_calls=300)),
        }
        settings.update(overrides)
        return Orchestrator(ScriptedLLM(), **settings)

    def make_done(self, outcomes: list[str]):
        """造一批**已执行过**的子任务（带 outcome），这才是真实运行的样子。"""
        from hexhound.orchestrator import WorkerTask

        return [
            WorkerTask(
                id=f"T{index}",
                role="recon",
                objective="测试",
                url=self.TARGET,
                outcome=outcome,
            )
            for index, outcome in enumerate(outcomes, 1)
        ]

    def test_replan_brief_handles_unfinished_tasks(self) -> None:
        """回归：`outcome_label` 是 `to_dict()` 的派生字段，不是属性。

        直接 `t.outcome_label` 会 AttributeError。
        """
        orchestrator = self.make()
        done = self.make_done(["done", "max_steps", "closing_failed", "budget"])
        brief = orchestrator._replan_brief(
            {"touched": 1, "total": 4, "params_attempted": 0, "params_total": 2}, done
        )
        self.assertIn("已完成子任务：1 个", brief)
        self.assertIn("未收尾：3 个", brief)
        # 未收尾的任务要列出 id 与**可读**状态
        self.assertIn("T2", brief)
        self.assertIn("达到步数上限", brief)

    def test_replan_brief_handles_all_closed_tasks(self) -> None:
        orchestrator = self.make()
        brief = orchestrator._replan_brief(
            {"touched": 2, "total": 2, "params_attempted": 1, "params_total": 1},
            self.make_done(["done", "closing_no_finish"]),
        )
        self.assertIn("未收尾：0 个", brief)

    def test_replan_brief_with_empty_done(self) -> None:
        orchestrator = self.make()
        brief = orchestrator._replan_brief({"touched": 0, "total": 0}, [])
        self.assertIn("<current_state>", brief)

    def test_replan_round_routes_through_the_safe_wrapper(self) -> None:
        """回归：重规划里任何异常都必须被兜住，不能冒到 CLI。

        判据：故意让 `_replan_round_inner` 抛异常，外层必须返回 `[]` 并记录
        `replan_error` 事件——而不是把整次 audit 变成 traceback。
        """
        from unittest.mock import patch

        orchestrator = self.make()
        with patch.object(
            type(orchestrator),
            "_replan_round_inner",
            side_effect=AttributeError("'WorkerTask' object has no attribute 'outcome_label'"),
        ):
            added = orchestrator._run_replan_round({"untouched": 5}, [], [])
        self.assertEqual(added, [])
        errors = [
            event for event in orchestrator.events if event.get("kind") == "replan_error"
        ]
        self.assertTrue(errors, "重规划出错必须留下事件")
        self.assertIn("AttributeError", errors[0]["message"])

    def test_supervisor_verdict_does_not_collide_with_trace_kind(self) -> None:
        """回归：`Verdict.to_dict()` 的 `kind` 与 `record(kind=...)` 撞名。

        现场报错：`TraceRecorder.record() got multiple values for argument 'kind'`。
        这里用一个会在第一步就告警的场景触发它（重复调用同一工具）。
        """
        import tempfile

        from hexhound.memory import RunArtifacts
        from hexhound.mockllm import ScriptedLLM
        from hexhound.orchestrator import Orchestrator, TaskWorker, WorkerTask
        from hexhound.surface import AttackSurface
        from hexhound.trace import load_trace

        with tempfile.TemporaryDirectory() as tmp:
            artifacts = RunArtifacts(self.TARGET, home=Path(tmp))
            recorder = Orchestrator(
                ScriptedLLM(),
                target=self.TARGET,
                goal="trace kind 撞名",
                mode="blackbox",
                base_dir=Path("."),
                allowed_hosts=self.ALLOWED,
                timeout=1,
                budget=__import__("hexhound.budget", fromlist=["Budget"]).Budget(),
                artifacts=artifacts,
            ).trace
            task = WorkerTask(id="T1", role="recon", objective="x", steps=8)
            worker = TaskWorker(
                ScriptedLLM(),
                task=task,
                base_dir=Path("."),
                allowed_hosts=self.ALLOWED,
                timeout=1,
                surface=AttackSurface(target=self.TARGET),
                budget=SearchBudget(),
                artifacts=None,
                auth_profiles={},
                trace=recorder,
            )
            step = {"action": "http_request", "action_input": {"url": self.TARGET + "/x"},
                    "observation": "普通响应"}
            for _ in range(4):  # 触发 stall 告警
                worker._supervise(step, [])
            events = load_trace(artifacts.dir / "trace.jsonl")
            supervisor_events = [e for e in events if e.get("kind") == "supervisor"]
            self.assertTrue(supervisor_events, "监督器判定必须写进 trace（且不能抛异常）")
            self.assertIn("verdict_kind", supervisor_events[0]["data"])

    def test_orchestrator_events_reach_the_trace(self) -> None:
        """回归：编排事件里的 `kind` 同样会与 `record(kind=...)` 撞名。"""
        import tempfile

        from hexhound.memory import RunArtifacts
        from hexhound.mockllm import ScriptedLLM
        from hexhound.orchestrator import Orchestrator
        from hexhound.trace import load_trace

        with tempfile.TemporaryDirectory() as tmp:
            artifacts = RunArtifacts(self.TARGET, home=Path(tmp))
            orchestrator = Orchestrator(
                ScriptedLLM(),
                target=self.TARGET,
                goal="编排事件进 trace",
                mode="blackbox",
                base_dir=Path("."),
                allowed_hosts=self.ALLOWED,
                timeout=1,
                max_tasks=1,
                task_steps=3,
                parallel=1,
                budget=SearchBudget(),
                artifacts=artifacts,
            )
            orchestrator._event(kind="custom_stage", message="测试事件", count=7)
            events = load_trace(artifacts.dir / "trace.jsonl")
            custom = [e for e in events if e.get("kind") == "orchestrator_custom_stage"]
            self.assertTrue(custom)
            self.assertEqual(custom[0]["data"]["message"], "测试事件")
            self.assertEqual(custom[0]["data"]["count"], 7)


def SearchBudget():
    from hexhound.budget import Budget, BudgetLimits

    return Budget(BudgetLimits(max_tool_calls=300))


class PatchResultShapeTests(unittest.TestCase):
    def test_result_serialises_for_trace(self) -> None:
        result = PatchResult(ok=True, applied=[{"op": "add", "id": "R-1"}], rejected=[])
        data = result.to_dict()
        self.assertIn("applied", data)
        self.assertIn("rejected", data)
        self.assertTrue(data["ok"])
        import json

        json.dumps(data, ensure_ascii=False)  # 必须可 JSON 化（要写进 trace）


if __name__ == "__main__":
    unittest.main()
