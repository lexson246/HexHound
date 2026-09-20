"""编排层单元测试：规划解析、分波执行、复核波、合并去重、预算与监督。

用 `ScriptedLLM`（确定性脚本模型）驱动，不依赖网络与真实 LLM。
靶场地址不会真的被请求——所有 target 都指向一个不可达端口，
工具会返回"请求失败"，正好用来验证编排逻辑本身。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.budget import Budget, BudgetLimits  # noqa: E402
from hexhound.mockllm import ScriptedLLM  # noqa: E402
from hexhound.orchestrator import (  # noqa: E402
    Orchestrator,
    StepAbort,
    SwarmCallbacks,
    TaskWorker,
    WorkerTask,
    _fallback_plan,
    _looks_like_auth,
    _parse_plan,
    summarise_events,
)
from hexhound.surface import AttackSurface  # noqa: E402

# 刻意用解析不了的域名（而不是空闲端口）：Windows 防火墙会让空闲端口的连接静默
# 挂满超时，每个用例会慢到一分钟。DNS 失败是立刻返回的，编排逻辑照样能验证。
TARGET = "http://hexhound-test.invalid"
ALLOWED = frozenset({"127.0.0.1", "localhost", "hexhound-test.invalid"})


class PlanParsingTests(unittest.TestCase):
    def test_parse_valid_plan(self) -> None:
        text = (
            '{"thought": "拆分", "tasks": ['
            '{"id": "T1", "role": "recon", "objective": "爬首页", "steps": 8},'
            '{"role": "injection", "objective": "测 id 参数", "steps": 99}'
            "]}"
        )
        tasks = _parse_plan(text, TARGET, AttackSurface(target=TARGET), 6)
        self.assertEqual([task.role for task in tasks], ["recon", "injection"])
        self.assertEqual(tasks[0].id, "T1")
        self.assertEqual(tasks[1].id, "T2")
        # 步数被夹在 4..20
        self.assertEqual(tasks[1].steps, 20)

    def test_invalid_role_and_empty_objective_dropped(self) -> None:
        text = (
            '{"tasks": ['
            '{"role": "hacker", "objective": "乱来"},'
            '{"role": "recon", "objective": "   "},'
            '{"role": "recon", "objective": "有效任务"}'
            "]}"
        )
        tasks = _parse_plan(text, TARGET, AttackSurface(target=TARGET), 6)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0].objective, "有效任务")

    def test_garbage_falls_back_to_deterministic_plan(self) -> None:
        tasks = _parse_plan("不是 JSON", TARGET, AttackSurface(target=TARGET), 6)
        self.assertTrue(tasks)
        self.assertEqual(tasks[0].role, "recon")

    def test_fallback_plan_uses_discovered_endpoints(self) -> None:
        surface = AttackSurface(target=TARGET)
        surface.add_endpoint(TARGET + "/api/user?uid=1", source="crawl")
        surface.add_form(TARGET + "/", "POST", "/login", ["username"], base_url=TARGET + "/")
        tasks = _fallback_plan(TARGET, surface, 6)
        roles = [task.role for task in tasks]
        self.assertEqual(roles[0], "recon")
        self.assertIn("injection", roles)
        self.assertIn("auth", roles)
        self.assertTrue(any("/api/user" in task.url for task in tasks if task.role == "injection"))

    def test_looks_like_auth_detects_login_and_api(self) -> None:
        surface = AttackSurface(target=TARGET)
        self.assertFalse(_looks_like_auth(surface))
        surface.add_endpoint(TARGET + "/login", source="crawl")
        self.assertTrue(_looks_like_auth(surface))


class OrchestratorTests(unittest.TestCase):
    def make(self, **overrides) -> Orchestrator:
        settings = {
            "target": TARGET,
            "goal": "测试编排",
            "mode": "blackbox",
            "base_dir": Path("."),
            "allowed_hosts": ALLOWED,
            "timeout": 1,
            "max_tasks": 3,
            "task_steps": 5,
            "parallel": 2,
            "budget": Budget(BudgetLimits(max_tool_calls=200)),
        }
        settings.update(overrides)
        return Orchestrator(ScriptedLLM(), **settings)

    def test_plan_uses_scripted_llm(self) -> None:
        orchestrator = self.make()
        tasks = orchestrator.plan()
        self.assertEqual([task.role for task in tasks], ["recon", "auth"])
        events = [event for event in orchestrator.events if event["kind"] == "plan"]
        self.assertEqual(len(events), 1)

    def test_plan_falls_back_when_llm_raises(self) -> None:
        class BrokenLLM:
            def complete(self, messages):
                raise RuntimeError("provider down")

        orchestrator = self.make()
        orchestrator.llm = BrokenLLM()
        tasks = orchestrator.plan()
        self.assertTrue(tasks)
        self.assertTrue(any(event["kind"] == "plan_error" for event in orchestrator.events))

    def test_run_completes_with_task_ledger(self) -> None:
        orchestrator = self.make()
        result = orchestrator.run()
        self.assertTrue(result.tasks)
        # 台账里每个任务都有记录与用量
        records = orchestrator.ledger.records()
        self.assertEqual(len(records), len(result.tasks))
        self.assertTrue(all(record.status in ("done", "failed", "skipped") for record in records))
        self.assertTrue(any(record.steps >= 1 for record in records))

    def test_surface_shared_across_workers(self) -> None:
        orchestrator = self.make()
        result = orchestrator.run()
        self.assertIs(result.surface, orchestrator.surface)

    def test_budget_stop_skips_remaining_tasks(self) -> None:
        budget = Budget(BudgetLimits(max_tool_calls=1))
        orchestrator = self.make(budget=budget, max_tasks=4)
        result = orchestrator.run()
        self.assertTrue(budget.stop_reasons())
        self.assertIn(result.finish_reason, ("budget", "finish"))
        skipped = [task for task in result.tasks if task["outcome"] == "skipped"]
        self.assertTrue(skipped or result.steps_used >= 1)

    def test_should_stop_callback_halts(self) -> None:
        orchestrator = self.make(
            callbacks=SwarmCallbacks(should_stop=lambda: True),
        )
        result = orchestrator.run()
        tasks = result.tasks or []
        self.assertTrue(all(task["outcome"] in ("skipped", "done", "failed") for task in tasks))

    def test_verification_tasks_created_from_candidates(self) -> None:
        orchestrator = self.make()
        from hexhound.surface import Finding

        for index in range(4):
            orchestrator.surface.add_candidate(
                Finding(
                    id="",
                    title=f"候选 {index}",
                    severity="high",
                    evidence="e",
                    dedupe_key=f"k{index}",
                )
            )
        verify_tasks = orchestrator.verification_tasks()
        self.assertTrue(verify_tasks)
        self.assertTrue(all(task.role == "verify" for task in verify_tasks))
        self.assertLessEqual(len(verify_tasks), 2)

    def test_no_candidates_means_no_verify_wave(self) -> None:
        orchestrator = self.make()
        self.assertEqual(orchestrator.verification_tasks(), [])

    def test_events_are_readable(self) -> None:
        orchestrator = self.make()
        orchestrator.run()
        text = summarise_events(orchestrator.events)
        self.assertIn("计划", text)
        self.assertIn("波", text)


class ParamCoverageTests(unittest.TestCase):
    """参数级覆盖率：端点被读过、参数没被试过 —— 比端点盲区更隐蔽的那一类。"""

    def make(self, **overrides) -> Orchestrator:
        settings = {
            "target": TARGET,
            "goal": "测试参数覆盖",
            "mode": "blackbox",
            "base_dir": Path("."),
            "allowed_hosts": ALLOWED,
            "timeout": 1,
            "max_tasks": 1,
            "task_steps": 4,
            "parallel": 1,
            "budget": Budget(BudgetLimits(max_tool_calls=200)),
        }
        settings.update(overrides)
        return Orchestrator(ScriptedLLM(), **settings)

    def test_param_read_but_not_attacked_is_reported(self) -> None:
        """复现实测场景：/ping?ip= 被 GET 过一次（端点算已覆盖），参数 ip 从未被试。"""
        orchestrator = self.make()
        surface = orchestrator.surface
        surface.add_endpoint(TARGET + "/ping?ip=1", params=["ip"], source="crawl")
        surface.mark_attempt(TARGET + "/ping", "read", param="", outcome="no_signal")

        params = surface.unattacked_params()
        self.assertEqual(params, [(TARGET + "/ping", "ip")])
        gate = orchestrator.coverage_gate()
        self.assertEqual(gate["params_total"], 1)
        self.assertEqual(gate["params_unattacked"], 1)
        self.assertEqual(gate["params_attempted"], 0)
        self.assertIn("参数[ip]", gate["unattacked_sample"][0])
        # 端点级判据认为它已被碰过 —— 这正是需要第二层判据的原因
        self.assertEqual(surface.touched_endpoints(), {TARGET + "/ping"})

    def test_attacked_param_clears_the_gap(self) -> None:
        orchestrator = self.make()
        surface = orchestrator.surface
        surface.add_endpoint(TARGET + "/ping?ip=1", params=["ip"], source="crawl")
        surface.mark_attempt(TARGET + "/ping", "cmd", param="ip", payload=";id")
        self.assertEqual(surface.unattacked_params(), [])
        self.assertEqual(orchestrator.coverage_gate()["params_unattacked"], 0)

    def test_form_params_count_too(self) -> None:
        """POST 表单参数（URL 里看不到）同样算进参数覆盖。"""
        orchestrator = self.make()
        surface = orchestrator.surface
        surface.add_form(TARGET + "/", "POST", "/login", ["username", "password"], base_url=TARGET + "/")
        surface.mark_attempt(TARGET + "/login", "sqli", param="username")
        self.assertEqual(surface.unattacked_params(), [(TARGET + "/login", "password")])

    def test_url_query_params_count_without_explicit_registration(self) -> None:
        """端点以 `/login?username=x` 登记、没单独声明参数时，闸门也不能静默放行。

        实测踩过：一次运行里侦察只登记了 URL、没登记参数，`params_total` 变成 0，
        参数覆盖那一行**整行消失**——闸门看起来"通过"，其实什么都没检查。
        """
        orchestrator = self.make()
        surface = orchestrator.surface
        surface.add_endpoint(TARGET + "/login?username=alice", source="crawl")
        self.assertEqual(surface.unattacked_params(), [(TARGET + "/login", "username")])
        gate = orchestrator.coverage_gate()
        self.assertEqual(gate["params_total"], 1)
        self.assertEqual(gate["params_unattacked"], 1)

    def test_param_coverage_counts_attempt_only_params(self) -> None:
        """只出现在 attempt 里（从未登记）的参数也算存在，且算作已试过。"""
        orchestrator = self.make()
        orchestrator.surface.mark_attempt(TARGET + "/x", "sqli", param="q")
        self.assertEqual(orchestrator.surface.param_coverage(), (1, 1))
        self.assertEqual(orchestrator.surface.unattacked_params(), [])

    def test_param_sweep_tasks_target_unattacked_params(self) -> None:
        orchestrator = self.make()
        surface = orchestrator.surface
        surface.add_endpoint(TARGET + "/ssti?name=x", params=["name"], source="crawl")
        tasks = orchestrator.param_sweep_tasks()
        self.assertTrue(tasks)
        self.assertTrue(all(task.role == "injection" for task in tasks))
        self.assertIn("参数[name]", tasks[0].objective)
        self.assertIn("record_coverage", tasks[0].objective)

    def test_no_unattacked_params_no_sweep(self) -> None:
        orchestrator = self.make()
        self.assertEqual(orchestrator.param_sweep_tasks(), [])

    def test_sweep_ids_do_not_collide_across_rounds(self) -> None:
        """补扫最多跑两轮：两轮的任务编号必须不同，否则台账/事件里会撞车。"""
        orchestrator = self.make()
        surface = orchestrator.surface
        for index in range(12):
            surface.add_endpoint(TARGET + f"/p{index}?q=1", params=["q"], source="crawl")
        first = orchestrator.param_sweep_tasks(round_index=0)
        second = orchestrator.param_sweep_tasks(round_index=1)
        self.assertTrue(first and second)
        self.assertFalse({task.id for task in first} & {task.id for task in second})
        endpoints_first = orchestrator.coverage_sweep_tasks(round_index=0)
        endpoints_second = orchestrator.coverage_sweep_tasks(round_index=1)
        self.assertTrue(endpoints_first and endpoints_second)
        self.assertFalse(
            {task.id for task in endpoints_first} & {task.id for task in endpoints_second}
        )


class SpecialClassTaskTests(unittest.TestCase):
    """竞态/认证实现任务的**确定性**派发。

    实测教训（v0.4 首跑）：侦察角色发现了 /wallet，还在 leave_note 里写了"可用泄露的
    jwt secret 伪造令牌"，但没有任何角色去执行——提示词给了能力、没人负责用。
    所以这两类必须按攻面特征机械派任务，和"有带参端点就强制 sqlmap"同一个道理。
    """

    def make(self, sandbox=None, **overrides) -> Orchestrator:
        settings = {
            "target": TARGET,
            "goal": "测试特殊类别任务",
            "mode": "blackbox",
            "base_dir": Path("."),
            "allowed_hosts": ALLOWED,
            "timeout": 1,
            "max_tasks": 3,
            "task_steps": 6,
            "parallel": 1,
            "budget": Budget(BudgetLimits(max_tool_calls=200)),
            "sandbox": sandbox,
        }
        settings.update(overrides)
        return Orchestrator(ScriptedLLM(), **settings)

    class _ReadySandbox:
        """最小替身：沙箱可用且装了 python3。"""

        def available(self) -> bool:
            return True

        def tool_status(self) -> dict[str, bool]:
            return {"python3": True, "sqlmap": True}

    class _NoPySandbox(_ReadySandbox):
        def tool_status(self) -> dict[str, bool]:
            return {"python3": False}

    def test_no_sandbox_means_no_special_tasks(self) -> None:
        """脚本通道不可用时不要派任务——那只会烧步数换来一句"工具不可用"。"""
        orchestrator = self.make(sandbox=None)
        orchestrator.surface.add_endpoint(TARGET + "/coupon?code=x", params=["code"])
        self.assertEqual(orchestrator.special_class_tasks(), [])

    def test_missing_python3_means_no_special_tasks(self) -> None:
        orchestrator = self.make(sandbox=self._NoPySandbox())
        orchestrator.surface.add_endpoint(TARGET + "/coupon?code=x", params=["code"])
        self.assertEqual(orchestrator.special_class_tasks(), [])

    def test_state_changing_endpoint_triggers_race_task(self) -> None:
        orchestrator = self.make(sandbox=self._ReadySandbox())
        orchestrator.surface.add_endpoint(TARGET + "/coupon?code=HH-1", params=["code"], source="crawl")
        orchestrator.surface.add_endpoint(TARGET + "/about", source="crawl")
        tasks = orchestrator.special_class_tasks()
        self.assertEqual([task.id for task in tasks], ["S1"])
        self.assertEqual(tasks[0].role, "injection")
        self.assertIn("sandbox_script", tasks[0].objective)
        self.assertIn("/coupon", tasks[0].objective)
        self.assertIn("串行", tasks[0].objective)

    def test_race_objective_forbids_reusing_the_one_shot_input(self) -> None:
        """回归：串行基线不能和并发突发用同一张券。

        实测踩过——任务原先只写"先串行 1 次"，模型照做，把单次券消费掉了；
        随后并发打同一张券全部被拒，于是得出"没有竞态"。那是**测试设计错误**：
        串行那一次本身就会消耗掉一次性输入。
        """
        orchestrator = self.make(sandbox=self._ReadySandbox())
        orchestrator.surface.add_endpoint(TARGET + "/coupon?code=x", params=["code"])
        objective = orchestrator.special_class_tasks()[0].objective
        self.assertIn("两份不同的输入", objective)
        self.assertIn("券 A", objective)
        self.assertIn("券 B", objective)

    def test_leak_plus_protected_triggers_forge_task(self) -> None:
        orchestrator = self.make(sandbox=self._ReadySandbox())
        orchestrator.surface.add_endpoint(TARGET + "/actuator/env", source="crawl")
        orchestrator.surface.add_endpoint(TARGET + "/admin", source="crawl", status=403)
        self.assertEqual(orchestrator._leak_sources(), [TARGET + "/actuator/env"])
        self.assertEqual(orchestrator._protected_endpoints(), [TARGET + "/admin"])
        tasks = orchestrator.special_class_tasks()
        self.assertEqual([task.id for task in tasks], ["K1"])
        self.assertEqual(tasks[0].role, "auth")
        self.assertIn("alg=none", tasks[0].objective)

    def test_protected_without_leak_does_not_forge(self) -> None:
        """只有 403、没有任何泄露来源时不该硬编一个"伪造令牌"任务（那是瞎猜）。"""
        orchestrator = self.make(sandbox=self._ReadySandbox())
        orchestrator.surface.add_endpoint(TARGET + "/admin", source="crawl", status=403)
        self.assertEqual(orchestrator.special_class_tasks(), [])

    def test_both_classes_but_limit_one(self) -> None:
        orchestrator = self.make(sandbox=self._ReadySandbox())
        orchestrator.surface.add_endpoint(TARGET + "/coupon?code=x", params=["code"])
        orchestrator.surface.add_endpoint(TARGET + "/actuator/env")
        orchestrator.surface.add_endpoint(TARGET + "/admin", status=403)
        tasks = orchestrator.special_class_tasks(limit=1)
        self.assertEqual([task.id for task in tasks], ["S1"])

    def test_state_change_detection_ignores_static_paths(self) -> None:
        orchestrator = self.make(sandbox=self._ReadySandbox())
        for path in ("/static/app.js", "/login", "/reflect?name=x"):
            orchestrator.surface.add_endpoint(TARGET + path, source="crawl")
        self.assertEqual(orchestrator._race_targets(), [])


class WorkerSupervisionTests(unittest.TestCase):
    def make_worker(self) -> TaskWorker:
        task = WorkerTask(id="T1", role="recon", objective="测试", url=TARGET, steps=8)
        return TaskWorker(
            ScriptedLLM(),
            task=task,
            base_dir=Path("."),
            allowed_hosts=ALLOWED,
            timeout=1,
            surface=AttackSurface(target=TARGET),
            budget=Budget(),
            artifacts=None,
            auth_profiles={},
        )

    def test_repeat_calls_warn_then_abort(self) -> None:
        worker = self.make_worker()
        messages: list[dict[str, str]] = []
        step = {"action": "http_request", "action_input": {"url": TARGET + "/x"}}
        worker._supervise(step, messages)  # 1
        worker._supervise(step, messages)  # 2
        worker._supervise(step, messages)  # 3 → 告警
        self.assertTrue(any("完全相同的参数" in item["content"] for item in messages))
        worker._supervise(step, messages)  # 4
        with self.assertRaises(StepAbort):
            worker._supervise(step, messages)  # 5 → 中止

    def test_finish_actions_are_not_supervised(self) -> None:
        worker = self.make_worker()
        messages: list[dict[str, str]] = []
        for _ in range(10):
            worker._supervise({"action": "finish_task", "action_input": {}}, messages)
        self.assertEqual(messages, [])

    def test_step_notice_fires_near_the_limit_once(self) -> None:
        """接近步数上限要提醒收尾（否则子代理会一路探测到硬上限、结论来不及写）。"""
        worker = self.make_worker()  # steps=8
        messages: list[dict[str, str]] = []
        step = {"action": "http_request", "action_input": {"url": TARGET + "/a"}, "step": 5}
        worker._supervise(step, messages)  # 剩 3 → 提前收敛提醒
        self.assertTrue(any("只剩 3 步" in item["content"] for item in messages))
        count_after_first = len(messages)
        worker._supervise(step, messages)  # 同一档位不重复刷屏
        self.assertEqual(len(messages), count_after_first)
        worker._supervise(
            {"action": "http_request", "action_input": {"url": TARGET + "/b"}, "step": 6},
            messages,
        )  # 剩 2 → 收口提醒
        self.assertTrue(any("只剩 2 步" in item["content"] for item in messages))
        worker._supervise(
            {"action": "http_request", "action_input": {"url": TARGET + "/c"}, "step": 8},
            messages,
        )  # 到顶 → 必须交回总结
        self.assertTrue(any("已到步数上限" in item["content"] for item in messages))

    def test_step_notice_emits_event(self) -> None:
        events: list[dict] = []
        task = WorkerTask(id="T1", role="recon", objective="测试", url=TARGET, steps=5)
        worker = TaskWorker(
            ScriptedLLM(),
            task=task,
            base_dir=Path("."),
            allowed_hosts=ALLOWED,
            timeout=1,
            surface=AttackSurface(target=TARGET),
            budget=Budget(),
            artifacts=None,
            auth_profiles={},
            callbacks=SwarmCallbacks(on_event=events.append),
        )
        worker._supervise(
            {"action": "http_request", "action_input": {"url": "x"}, "step": 5}, []
        )
        self.assertTrue(any(event.get("kind") == "notice" for event in events))


if __name__ == "__main__":
    unittest.main()
