"""越权面（IDOR/BOLA）：端点没有参数信息时，候选参数名靠路径推测 + 确定性派任务。

事实经过（`docs/EVAL.md` §4.1 第 2 条，三轮 live 评测）：`/api/order`（只凭 order_id
就能读他人订单）**端点被字典枚举发现了**（这是上一批修好的），但登记时**参数为空**
——字典只知道路径。于是"用 order_id 去测越权"只能靠模型自己想到，三轮都没想到。
第三轮 87.5%（7/8）唯一的漏报就是它。

这一批把链路接上：路径名词 → 候选标识参数名（**推测**，永不混进 `params`）→
确定性派一个 auth 任务去确认真实参数名并做 A/B 对比。

界面上必须能分辨"探到的"与"猜的"：`to_llm_summary` 里前者是 `参数[...]`，
后者是 `推测参数[...](按路径名词推测，未验证)`。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound import knowledge as KB  # noqa: E402
from hexhound.budget import Budget, BudgetLimits  # noqa: E402
from hexhound.mockllm import ScriptedLLM  # noqa: E402
from hexhound.orchestrator import Orchestrator  # noqa: E402
from hexhound.surface import AttackSurface  # noqa: E402

TARGET = "http://hexhound-test.invalid"
ALLOWED = frozenset({"127.0.0.1", "localhost", "hexhound-test.invalid"})


class SuggestIdParamsTests(unittest.TestCase):
    def test_maps_resource_nouns_to_likely_id_params(self) -> None:
        for url, expected in (
            ("http://h/api/order", ["order_id", "id"]),
            ("http://h/api/orders/1001", ["order_id", "id"]),
            ("http://h/api/user", ["uid", "id", "user_id"]),
            ("http://h/api/users", ["uid", "id", "user_id"]),
            ("http://h/api/invoice/detail", ["invoice_id", "id"]),
            ("http://h/coupon", ["coupon_id", "code", "id"]),
        ):
            with self.subTest(url=url):
                self.assertEqual(KB.suggest_id_params(url), expected)

    def test_action_paths_get_no_suggestion(self) -> None:
        """动作/页面路径不该猜参数——给模型一个凭空捏造的参数名比不给更糟。"""
        for url in (
            "http://h/login", "http://h/api/search", "http://h/", "http://h/static/app.js",
            "http://h/api/v1/auth/token", "http://h/health",
        ):
            with self.subTest(url=url):
                self.assertEqual(KB.suggest_id_params(url), [])

    def test_limit_is_respected(self) -> None:
        self.assertEqual(KB.suggest_id_params("http://h/api/user", limit=1), ["uid"])


class EndpointSuggestionTests(unittest.TestCase):
    def make(self) -> AttackSurface:
        return AttackSurface(target="http://h", mode="blackbox")

    def test_suggestions_are_stored_separately_from_discovered_params(self) -> None:
        """推测参数进 `suggested_params`，**永不**混进 `params`（那是事实层）。"""
        surface = self.make()
        surface.add_endpoint("http://h/api/order", source="enumerate")
        endpoint = surface.endpoints["http://h/api/order"]
        self.assertEqual(endpoint.params, [])
        self.assertEqual(endpoint.suggested_params, ["order_id", "id"])

    def test_discovered_params_win_and_no_suggestion_is_made(self) -> None:
        surface = self.make()
        surface.add_endpoint("http://h/api/order?order_id=1", source="crawl")
        endpoint = surface.endpoints["http://h/api/order"]
        self.assertEqual(endpoint.params, ["order_id"])
        self.assertEqual(endpoint.suggested_params, [], "已经有真参数了就不该再猜")

    def test_llm_summary_labels_the_guess(self) -> None:
        surface = self.make()
        surface.add_endpoint("http://h/api/order", source="enumerate")
        text = surface.to_llm_summary()
        self.assertIn("推测参数[order_id,id]", text)
        self.assertIn("未验证", text)

    def test_survives_save_and_load(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            surface = self.make()
            surface.add_endpoint("http://h/api/order", source="enumerate")
            path = Path(tmp) / "surface.json"
            surface.save(path)
            restored = AttackSurface.load(path)
        self.assertEqual(
            restored.endpoints["http://h/api/order"].suggested_params, ["order_id", "id"]
        )


class IdorCandidatesTests(unittest.TestCase):
    def make(self) -> AttackSurface:
        surface = AttackSurface(target="http://h", mode="blackbox")
        surface.add_endpoint("http://h/api/order", source="enumerate")
        surface.add_endpoint("http://h/login", source="enumerate")
        return surface

    def test_untested_endpoint_is_a_candidate(self) -> None:
        self.assertEqual(
            self.make().idor_candidates(), [("http://h/api/order", [], ["order_id", "id"])]
        )

    def test_enumeration_probe_does_not_count_as_a_param_test(self) -> None:
        """枚举时那次 GET（param 为空）不算"试过参数"——否则候选面会自己消失。"""
        surface = self.make()
        surface.mark_attempt("http://h/api/order", "enumerate", outcome="no_signal")
        self.assertEqual(len(surface.idor_candidates()), 1)

    def test_trying_all_candidate_params_removes_the_endpoint(self) -> None:
        surface = self.make()
        for param in ("order_id", "id"):
            surface.mark_attempt("http://h/api/order", "idor", param=param, outcome="no_signal")
        self.assertEqual(surface.idor_candidates(), [], "两个候选都试过了才该消失")

    def test_partially_tried_keeps_the_remaining_candidate(self) -> None:
        surface = self.make()
        surface.mark_attempt("http://h/api/order", "idor", param="order_id", outcome="no_signal")
        picks = surface.idor_candidates()
        self.assertEqual(picks, [("http://h/api/order", [], ["id"])])

    def test_injection_fuzz_does_not_count_as_an_authorization_test(self) -> None:
        """**第 7 轮的教训**：`order_id` 被 sqli/cmd/ssti 各 fuzz 过 25 次，
        但那都是拿无效值的 payload 试注入——越权从来没测过。
        参数"被发现了/被试过"不等于"被当作对象标识测过"。"""
        surface = self.make()
        for category in ("sqli", "cmd", "ssti", "path", "xss", "nosqli"):
            surface.mark_attempt(
                "http://h/api/order", category, param="order_id", payload="'", outcome="no_signal",
            )
        picks = surface.idor_candidates()
        self.assertEqual(picks, [("http://h/api/order", [], ["order_id", "id"])])

    def test_discovered_id_param_is_also_a_candidate(self) -> None:
        """探到的真参数照样可能是越权面（第 7 轮的教训）。"""
        surface = AttackSurface(target="http://h", mode="blackbox")
        surface.add_endpoint("http://h/api/order?order_id=1", source="crawl")
        picks = surface.idor_candidates()
        self.assertEqual(picks, [("http://h/api/order", ["order_id"], [])])

    def test_discovered_non_id_param_is_not_a_candidate(self) -> None:
        """有参数、但没有一个像对象标识 → 不是越权面的形状，别浪费任务。"""
        surface = AttackSurface(target="http://h", mode="blackbox")
        surface.add_endpoint("http://h/search?q=hello&page=1", source="crawl")
        self.assertEqual(surface.idor_candidates(), [])

    def test_reported_endpoints_are_not_candidates(self) -> None:
        surface = self.make()
        surface.record_coverage("http://h/api/order", "reported", detail="越权")
        self.assertEqual(surface.idor_candidates(), [])

    def test_api_candidates_come_first_and_order_is_deterministic(self) -> None:
        """`/api/` 下的接口（JSON/PII 高发）优先，且排序**确定**。

        不能靠字典插入顺序：那样"哪个端点被列进任务"取决于扫描先后 = 交给运气。
        """
        surface = AttackSurface(target="http://h", mode="blackbox")
        for path in ("/coupon", "/order/prepare", "/invoice/detail", "/api/users", "/api/order"):
            surface.add_endpoint("http://h" + path, source="enumerate")
        picks = [url.split("http://h")[-1] for url, _d, _s in surface.idor_candidates(limit=3)]
        self.assertEqual(picks[:2], ["/api/order", "/api/users"])
        again = [url.split("http://h")[-1] for url, _d, _s in surface.idor_candidates(limit=3)]
        self.assertEqual(picks, again, "排序必须稳定")

    def test_limit_truncates_after_prioritising(self) -> None:
        surface = AttackSurface(target="http://h", mode="blackbox")
        for path in ("/coupon", "/api/order", "/api/invoice"):
            surface.add_endpoint("http://h" + path, source="enumerate")
        picks = surface.idor_candidates(limit=1)
        self.assertEqual(len(picks), 1)
        self.assertTrue(
            picks[0][0].endswith("/api/invoice") or picks[0][0].endswith("/api/order")
        )


class IdorSweepTaskTests(unittest.TestCase):
    def make(self, **overrides) -> Orchestrator:
        settings = {
            "target": TARGET,
            "goal": "测试越权派发",
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

    def test_no_candidates_no_task(self) -> None:
        self.assertEqual(self.make().idor_sweep_tasks(), [])

    def test_task_names_the_candidate_params_and_marks_them_as_guesses(self) -> None:
        orchestrator = self.make()
        orchestrator.surface.add_endpoint(TARGET + "/api/order", source="enumerate")
        tasks = orchestrator.idor_sweep_tasks()
        self.assertEqual(len(tasks), 1)
        task = tasks[0]
        self.assertEqual(task.role, "auth")
        self.assertEqual(task.id, "I1")
        self.assertIn("/api/order", task.objective)
        self.assertIn("order_id", task.objective)
        self.assertIn("推测", task.objective)
        self.assertIn("越权", task.objective)
        # 必须有"每个端点都要有结论"的硬要求，否则又会留下"没测"的静默盲区
        self.assertIn("record_coverage", task.objective)

    def test_objective_teaches_value_discovery_and_404_semantics(self) -> None:
        """第 4 轮 live 评测踩到的坑，必须写进任务目标里。

        事实经过：I1 真的试了 `/api/order?order_id=1` → 404
        `{"code":1,"msg":"订单不存在"}`，于是**把它记成 ruled_out 走了**。
        参数名已经猜对了，错在**值**：靶场的订单是 1001/1002，
        而"不带参数请求会返回默认对象 1001"这条线索它没利用。
        """
        orchestrator = self.make()
        orchestrator.surface.add_endpoint(TARGET + "/api/order", source="enumerate")
        objective = orchestrator.idor_sweep_tasks()[0].objective
        self.assertIn("先不带任何参数请求一次", objective)
        self.assertIn("抄下来", objective)
        self.assertIn("compare_responses", objective)
        self.assertIn("404", objective)
        self.assertIn("值不对", objective)

    def test_round_index_keeps_task_ids_unique(self) -> None:
        orchestrator = self.make()
        orchestrator.surface.add_endpoint(TARGET + "/api/order", source="enumerate")
        # 每轮 3 个编号（limit 默认 3）：第二轮从 I4 起，不会与上一轮撞号
        self.assertEqual(orchestrator.idor_sweep_tasks(round_index=1)[0].id, "I4")

    def test_one_task_per_endpoint(self) -> None:
        """**一个端点一个任务**（第 5 轮实测）：一个任务列 3 个端点时，
        模型把 9 步全花在第一个上就自认为完成收尾了，另外两个一步没测。
        任务粒度=端点，就没有"挑一个交差"的余地。"""
        orchestrator = self.make()
        for path in ("/api/order", "/api/user", "/api/invoice", "/coupon"):
            orchestrator.surface.add_endpoint(TARGET + path, source="enumerate")
        tasks = orchestrator.idor_sweep_tasks(limit=3)
        self.assertEqual([task.id for task in tasks], ["I1", "I2", "I3"])
        self.assertEqual(len({task.url for task in tasks}), 3, "每个任务只盯一个端点")
        for task in tasks:
            self.assertIn("推测参数：", task.objective)
            self.assertEqual(task.objective.count("推测参数："), 1)
            self.assertIn(task.url, task.objective)
            self.assertIn("只做这一个端点", task.objective)

    def test_objective_separates_discovered_and_guessed_params(self) -> None:
        """探到的参数与猜的参数必须分开写——并提醒"被发现了 ≠ 被当作对象标识测过"。"""
        orchestrator = self.make()
        orchestrator.surface.add_endpoint(TARGET + "/api/order?order_id=1", source="crawl")
        objective = orchestrator.idor_sweep_tasks()[0].objective
        self.assertIn("已发现参数：order_id", objective)
        self.assertNotIn("推测参数：order_id", objective)
        self.assertIn("注入类 fuzz", objective)

    def test_limit_bounds_the_number_of_tasks(self) -> None:
        orchestrator = self.make()
        for path in ("/api/order", "/api/user", "/api/invoice", "/coupon"):
            orchestrator.surface.add_endpoint(TARGET + path, source="enumerate")
        self.assertEqual(len(orchestrator.idor_sweep_tasks(limit=2)), 2)
        self.assertEqual(len(orchestrator.idor_sweep_tasks(limit=10)), 4, "候选只有 4 个")

    def test_api_candidates_are_dispatched_first(self) -> None:
        """清单顺序即派发顺序：`/api/` 下的越权面先测（它们最可能是 BOLA）。"""
        orchestrator = self.make()
        for path in ("/coupon", "/api/order"):
            orchestrator.surface.add_endpoint(TARGET + path, source="enumerate")
        tasks = orchestrator.idor_sweep_tasks(limit=3)
        self.assertTrue(tasks[0].url.endswith("/api/order"), [t.url for t in tasks])


if __name__ == "__main__":
    unittest.main()
