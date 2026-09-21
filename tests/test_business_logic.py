"""业务逻辑靶场与确定性派发测试。

对应需求：
- lab 至少加入 /cart、/order/confirm、客户端价格篡改、负数或异常数量、
  订单步骤跳过、服务端未重新计算金额、重复提交或状态机绕过；
- 先写**确定性的人工验证脚本**证明漏洞真实存在，再让 Agent 检测
  （脚本在 `tools/verify_lab_business_logic.sh`，这里验证靶场行为本身）；
- finding 必须包含完整请求/响应/影响/可复现步骤；
- 修复或未测试的漏洞不能错误标记为 confirmed。

靶场用 Flask 的测试客户端直接驱动（不起真实进程、不访问网络）。
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC))


def load_lab():
    """导入靶场模块（`vulnlab/app.py`），失败则返回 None。"""
    path = ROOT / "vulnlab" / "app.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location("hexhound_lab_under_test", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:  # noqa: BLE001 缺少 flask 等情况直接跳过
        return None
    return module


LAB = load_lab()


@unittest.skipIf(LAB is None, "靶场模块不可导入（需要 flask）")
class LabBusinessLogicTests(unittest.TestCase):
    """/cart 与 /order/confirm 的**行为**（漏洞是否真的在）。"""

    def setUp(self) -> None:
        LAB.app.config["TESTING"] = True
        self.client = LAB.app.test_client()
        LAB._reset_shop()
        self.user = "biz-tester"
        # Flask 的测试客户端默认主机是 `localhost`，不要传 domain 参数——
        # 传了 `127.0.0.1` 会让 cookie 不生效，于是每个请求都变成匿名（401）。
        self.client.set_cookie("hh_session", f"{self.user}:tok-{self.user}-demo")

    def add(self, **payload):
        return self.client.post("/cart", json=payload)

    # ---------- 价格篡改 ----------

    def test_client_supplied_price_is_accepted(self) -> None:
        """价格篡改：客户端说的价就是成交价。"""
        response = self.add(sku="SKU-1002", qty=1, price=0.01)
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["client_price"], 0.01)
        self.assertEqual(body["server_price"], 1299.0)

    def test_total_uses_the_client_price_not_the_catalog(self) -> None:
        self.add(sku="SKU-1002", qty=1, price=0.01)
        total = self.client.get("/cart/total").get_json()
        self.assertEqual(total["priced_by"], "client")
        self.assertEqual(total["total"], 0.01)
        self.assertLess(total["total"], 1299.0 / 100)

    def test_confirm_charges_the_client_price(self) -> None:
        """最终成交金额同样是客户端价格——这才叫"服务端没有重算"。"""
        self.add(sku="SKU-1002", qty=1, price=0.5)
        order = self.client.post("/order/confirm", json={}).get_json()
        self.assertEqual(order["code"], 0)
        self.assertEqual(order["total"], 0.5)
        self.assertEqual(order["priced_by"], "client")
        line = order["lines"][0]
        self.assertEqual(line["paid_price"], 0.5)
        self.assertEqual(line["server_price"], 1299.0)

    # ---------- 负数 / 异常数量 ----------

    def test_negative_quantity_is_accepted(self) -> None:
        response = self.add(sku="SKU-1002", qty=-5, price=1299)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["qty"], -5)

    def test_negative_quantity_makes_the_total_negative(self) -> None:
        self.add(sku="SKU-1002", qty=-5, price=1299)
        total = self.client.get("/cart/total").get_json()
        self.assertLess(total["total"], 0)

    def test_zero_quantity_is_accepted(self) -> None:
        """0 件也能加购：服务端没有任何范围校验。

        顺带锁住一个实现细节：`qty=0` **不能**被 `data.get("qty") or 1` 这种写法
        静默变成 1——那会让"0 件加购"这个边界条件根本到不了服务端逻辑，
        测试也就测不到真实行为。
        """
        response = self.add(sku="SKU-1003", qty=0, price=29)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["qty"], 0)

    def test_zero_price_is_accepted_and_not_coerced(self) -> None:
        """`price=0` 是攻击者一定会试的值，不能被 `or` 吞成服务端单价。"""
        response = self.add(sku="SKU-1002", qty=1, price=0)
        self.assertEqual(response.get_json()["client_price"], 0)
        total = self.client.get("/cart/total").get_json()
        self.assertEqual(total["total"], 0)

    def test_huge_quantity_is_accepted(self) -> None:
        response = self.add(sku="SKU-1003", qty=10**9, price=29)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["qty"], 10**9)

    # ---------- 跳过步骤 ----------

    def test_confirm_without_adding_to_cart_succeeds(self) -> None:
        """跳过步骤：购物车为空、没调 /order/prepare，直接确认也能下单。"""
        order = self.client.post(
            "/order/confirm", json={"sku": "SKU-1001", "qty": 1, "price": 0.01}
        ).get_json()
        self.assertEqual(order["code"], 0)
        self.assertIn("ORD-", order["order_id"])
        self.assertEqual(order["total"], 0.01)

    def test_prepare_step_is_not_required(self) -> None:
        """/order/prepare 存在但**不被校验**——这正是"跳过步骤"的定义。"""
        prepare = self.client.post("/order/prepare", json={}).get_json()
        self.assertEqual(prepare["next_required_step"], "/order/confirm")
        # 不调 prepare 一样能确认（上一条已证明）；这里证明反向也成立：
        # 调了 prepare 之后，购物车仍是空的——步骤之间没有状态绑定
        self.assertEqual(self.client.get("/cart").get_json()["cart"], {})

    # ---------- 重复提交 / 无幂等 ----------

    def test_repeated_confirm_creates_multiple_orders(self) -> None:
        self.add(sku="SKU-1003", qty=1, price=29)
        order_ids = [
            self.client.post("/order/confirm", json={}).get_json()["order_id"]
            for _ in range(3)
        ]
        self.assertEqual(len(set(order_ids)), 3, "重复提交应当产生多张订单")

    def test_repeated_confirm_keeps_deducting_stock(self) -> None:
        stock_before = LAB.CATALOG["SKU-1003"]["stock"]
        self.add(sku="SKU-1003", qty=1, price=29)
        for _ in range(3):
            self.client.post("/order/confirm", json={})
        self.assertEqual(LAB.CATALOG["SKU-1003"]["stock"], stock_before - 3)

    def test_orders_are_queryable(self) -> None:
        """订单真的落库（不是假成功）——finding 的可复现步骤要靠它。"""
        self.add(sku="SKU-1003", qty=1, price=29)
        order_id = self.client.post("/order/confirm", json={}).get_json()["order_id"]
        detail = self.client.get(f"/order/{order_id}").get_json()
        self.assertEqual(detail["data"]["order_id"], order_id)

    def test_cart_requires_login(self) -> None:
        """业务逻辑缺陷不等于"完全没有鉴权"——未登录仍然该被挡。"""
        anonymous = LAB.app.test_client()
        self.assertEqual(anonymous.get("/cart").status_code, 401)
        self.assertEqual(anonymous.post("/order/confirm", json={}).status_code, 401)

    def test_shop_reset_requires_admin_and_restores_state(self) -> None:
        self.add(sku="SKU-1003", qty=2, price=29)
        # 普通用户不能重置
        self.assertEqual(
            self.client.post("/admin/shop/reset").status_code, 403
        )
        admin = LAB.app.test_client()
        admin.set_cookie("hh_session", "admin:tok-admin-demo")
        self.assertEqual(admin.post("/admin/shop/reset").status_code, 200)
        self.assertEqual(LAB.CATALOG["SKU-1003"]["stock"], 50)
        self.assertEqual(LAB.CARTS, {})


class BusinessLogicDispatchTests(unittest.TestCase):
    """确定性派发：认出下单链路就必须派任务，认不出来就不派（不瞎猜）。"""

    TARGET = "http://hexhound-test.invalid"
    ALLOWED = frozenset({"127.0.0.1", "localhost", "hexhound-test.invalid"})

    def make(self, **overrides):
        from hexhound.budget import Budget, BudgetLimits
        from hexhound.mockllm import ScriptedLLM
        from hexhound.orchestrator import Orchestrator

        settings = {
            "target": self.TARGET,
            "goal": "测试业务逻辑派发",
            "mode": "blackbox",
            "base_dir": Path("."),
            "allowed_hosts": self.ALLOWED,
            "timeout": 1,
            "max_tasks": 3,
            "task_steps": 6,
            "parallel": 1,
            "budget": Budget(BudgetLimits(max_tool_calls=200)),
        }
        settings.update(overrides)
        return Orchestrator(ScriptedLLM(), **settings)

    def test_no_commerce_surface_means_no_task(self) -> None:
        orchestrator = self.make()
        orchestrator.surface.add_endpoint(self.TARGET + "/about", source="crawl")
        self.assertEqual(orchestrator.business_logic_tasks(), [])

    def test_cart_endpoint_triggers_a_business_task(self) -> None:
        orchestrator = self.make()
        orchestrator.surface.add_endpoint(
            self.TARGET + "/cart", methods=["POST"], source="crawl"
        )
        tasks = orchestrator.business_logic_tasks()
        self.assertEqual([task.id for task in tasks], ["B1"])
        self.assertEqual(tasks[0].role, "injection")

    def test_objective_covers_all_four_defect_classes(self) -> None:
        """任务目标必须点名这四类，否则模型只会试其中一两类。"""
        orchestrator = self.make()
        orchestrator.surface.add_endpoint(self.TARGET + "/cart", source="crawl")
        orchestrator.surface.add_endpoint(self.TARGET + "/order/confirm", source="crawl")
        objective = orchestrator.business_logic_tasks()[0].objective
        for token in ("价格篡改", "负数", "跳过步骤", "重复提交"):
            self.assertIn(token, objective, f"任务目标缺少 {token}")
        self.assertIn("/order/confirm", objective)
        self.assertIn("/cart", objective)

    def test_objective_demands_evidence_not_just_no_error(self) -> None:
        """业务逻辑结论最容易"看起来对但其实没证据"——目标里必须要求对照。"""
        orchestrator = self.make()
        orchestrator.surface.add_endpoint(self.TARGET + "/order/confirm", source="crawl")
        objective = orchestrator.business_logic_tasks()[0].objective
        self.assertIn("evidence_ref", objective)
        self.assertIn("前后状态对比", objective)
        self.assertIn("record_coverage", objective)

    def test_confirm_only_surface_still_triggers(self) -> None:
        orchestrator = self.make()
        orchestrator.surface.add_endpoint(self.TARGET + "/order/confirm", source="crawl")
        self.assertTrue(orchestrator.business_logic_tasks())

    def test_does_not_need_the_script_channel(self) -> None:
        """业务逻辑用 http_request 串行就能测，不该像竞态那样依赖 sandbox_script。"""
        orchestrator = self.make(sandbox=None)
        orchestrator.surface.add_endpoint(self.TARGET + "/cart", source="crawl")
        self.assertTrue(orchestrator.business_logic_tasks())

    def test_commerce_surface_groups(self) -> None:
        orchestrator = self.make()
        for path in ("/cart", "/order/confirm", "/order/prepare", "/order/1001"):
            orchestrator.surface.add_endpoint(self.TARGET + path, source="crawl")
        groups = orchestrator._commerce_surface()
        self.assertEqual(len(groups["cart"]), 1)
        self.assertEqual(len(groups["confirm"]), 1)
        self.assertEqual(len(groups["prepare"]), 1)
        self.assertEqual(len(groups["detail"]), 1)

    def test_task_is_dispatched_during_a_run(self) -> None:
        """端到端：跑一次编排，业务逻辑任务应当被派出去。"""
        orchestrator = self.make(max_tasks=2, task_steps=3)
        orchestrator.surface.add_endpoint(self.TARGET + "/cart", source="crawl")
        orchestrator.surface.add_endpoint(self.TARGET + "/order/confirm", source="crawl")
        orchestrator.run()
        dispatched = [
            event for event in orchestrator.events
            if event.get("kind") == "business_logic_tasks"
        ]
        self.assertTrue(dispatched, "编排过程中应当派发业务逻辑任务")

    # ---------- 确定性侦察兜底（业务入口的**上游**）----------
    #
    # 实测踩了三次的真正根因：业务逻辑/竞态任务**全部以攻面为输入**，
    # 而攻面里有没有 /cart 取决于"这一轮有没有哪个子代理真的去 crawl 首页"。
    # 规划者是 LLM，看到历史记忆里的回归目标时完全可能一个 recon 都不排，
    # 于是入口发现不了 → 业务任务派不出来 → 报告看不出根因。

    def test_recon_is_added_when_the_plan_has_none(self) -> None:
        orchestrator = self.make(max_tasks=4)
        from hexhound.orchestrator import WorkerTask

        plan = [
            WorkerTask(id="T1", role="injection", objective="复测已知注入", url=self.TARGET),
            WorkerTask(id="T2", role="auth", objective="复测已知越权", url=self.TARGET),
        ]
        refined = orchestrator._refine_plan(plan)
        self.assertTrue(
            any(task.role == "recon" for task in refined),
            "没有侦察任务的计划必须被补上侦察",
        )
        recon = next(task for task in refined if task.role == "recon")
        # 目标里要点名业务入口，否则 recon 只会爬首页、抓不到下游路径
        for token in ("/cart", "coupon", "wallet"):
            self.assertIn(token, recon.objective)
        self.assertIn("leave_note", recon.objective)

    def test_existing_recon_is_left_alone(self) -> None:
        orchestrator = self.make(max_tasks=4)
        from hexhound.orchestrator import WorkerTask

        plan = [
            WorkerTask(id="T1", role="recon", objective="我自己的侦察计划", url=self.TARGET),
        ]
        refined = orchestrator._refine_plan(plan)
        recons = [task for task in refined if task.role == "recon"]
        self.assertEqual(len(recons), 1)
        self.assertEqual(recons[0].id, "T1", "已有侦察任务时不应再插一个")

    def test_recon_guard_rewrites_the_weakest_task_when_full(self) -> None:
        """名额满了要**改写**最弱的注入/认证任务，而不是硬塞——max_tasks 是软约束。

        回归：早先的改写条件是 `len(objective) < 120`，而真实运行里规划者产出的
        目标普遍在 200 字符上下（它会把"复测哪几个端点、用什么 payload"写全），
        于是**一条都没匹配上、改写分支静默失效**——实测那次 3 个任务全是回归复测、
        一个侦察都没有，`/cart` 因此从未进入攻面，业务逻辑一条都没测。
        """
        orchestrator = self.make(max_tasks=3)
        from hexhound.orchestrator import WorkerTask

        long_objective = "复测已知注入端点并给出结论：" + "要点" * 80  # 远超 120 字符
        plan = [
            WorkerTask(id="T1", role="injection", objective=long_objective, url=self.TARGET),
            WorkerTask(id="T2", role="injection", objective=long_objective, url=self.TARGET),
            WorkerTask(id="T3", role="auth", objective=long_objective, url=self.TARGET),
        ]
        refined = orchestrator._refine_plan(plan)
        # 不超名额，但必须有侦察
        self.assertLessEqual(len(refined), 3)
        recons = [task for task in refined if task.role == "recon"]
        self.assertEqual(len(recons), 1, "无论目标多长，都必须有一个侦察任务")
        self.assertIn("/cart", recons[0].objective)
        # 改写必须留下事件，否则"为什么这个任务变了"查不出来
        self.assertTrue(
            any(event.get("kind") == "plan_refine" for event in orchestrator.events)
        )

    def test_recon_guard_inserts_when_nothing_can_be_rewritten(self) -> None:
        """只剩 verify/source 角色且名额已满时，仍然插入侦察。

        `max_tasks` 是预算软约束；而"没有攻面"会让后面所有以攻面为输入的
        确定性派发（业务逻辑/竞态/认证）**全部失效**——那个代价更大。
        """
        orchestrator = self.make(max_tasks=1)
        from hexhound.orchestrator import WorkerTask

        plan = [WorkerTask(id="V1", role="verify", objective="复核候选", url=self.TARGET)]
        refined = orchestrator._refine_plan(plan)
        self.assertEqual(refined[0].role, "recon")
        self.assertEqual(refined[0].id, "R0")

    def test_recon_objective_names_the_business_path_tier(self) -> None:
        """侦察目标要明确让模型去枚举 business 档位（词表里有券码/订单词汇）。"""
        orchestrator = self.make(max_tasks=4)
        refined = orchestrator._refine_plan([])
        recon = next(task for task in refined if task.role == "recon")
        self.assertIn("business", recon.objective)
        self.assertIn("enumerate_common", recon.objective)
        self.assertIn("read_urls", recon.objective)


class VerifyScriptTests(unittest.TestCase):
    """人工验证脚本必须存在且覆盖四类缺陷（脚本本身在 WSL 里跑）。"""

    def setUp(self) -> None:
        self.path = ROOT / "tools" / "verify_lab_business_logic.sh"

    def test_script_exists_and_is_executable_content(self) -> None:
        self.assertTrue(self.path.is_file(), "缺少业务逻辑人工验证脚本")
        text = self.path.read_text(encoding="utf-8")
        self.assertIn("#!/usr/bin/env bash", text)

    def test_script_covers_all_four_defects(self) -> None:
        text = self.path.read_text(encoding="utf-8")
        for token in ("价格篡改", "负数数量", "跳过步骤", "重复提交"):
            self.assertIn(token, text, f"脚本未覆盖 {token}")

    def test_script_resets_lab_state(self) -> None:
        """脚本必须可重复运行——结束前重置靶场状态。"""
        text = self.path.read_text(encoding="utf-8")
        self.assertIn("/admin/shop/reset", text)

    def test_script_fails_loudly_on_expectation_mismatch(self) -> None:
        """判据不成立时必须以非零码退出（否则 CI 会把失败当成功）。"""
        text = self.path.read_text(encoding="utf-8")
        self.assertIn('[ "$FAIL" -eq 0 ]', text)


if __name__ == "__main__":
    unittest.main()
