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
        self.assertEqual(self.make().idor_candidates(), [("http://h/api/order", ["order_id", "id"])])

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
        self.assertEqual(picks, [("http://h/api/order", ["id"])])

    def test_reported_endpoints_are_not_candidates(self) -> None:
        surface = self.make()
        surface.record_coverage("http://h/api/order", "reported", detail="越权")
        self.assertEqual(surface.idor_candidates(), [])

    def test_endpoints_with_real_params_are_out_of_scope(self) -> None:
        """有真参数的端点走参数补扫那条路，不由这里派活（避免重复派任务烧钱）。"""
        surface = AttackSurface(target="http://h", mode="blackbox")
        surface.add_endpoint("http://h/api/order?order_id=1", source="crawl")
        self.assertEqual(surface.idor_candidates(), [])


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

    def test_round_index_keeps_task_ids_unique(self) -> None:
        orchestrator = self.make()
        orchestrator.surface.add_endpoint(TARGET + "/api/order", source="enumerate")
        self.assertEqual(orchestrator.idor_sweep_tasks(round_index=1)[0].id, "I2")

    def test_limit_bounds_the_listing(self) -> None:
        orchestrator = self.make()
        for path in ("/api/order", "/api/user", "/api/invoice", "/coupon"):
            orchestrator.surface.add_endpoint(TARGET + path, source="enumerate")
        task = orchestrator.idor_sweep_tasks(limit=2)[0]
        self.assertEqual(task.objective.count("候选参数："), 2)

    def test_steps_scale_with_the_number_of_endpoints(self) -> None:
        orchestrator = self.make()
        orchestrator.surface.add_endpoint(TARGET + "/api/order", source="enumerate")
        one = orchestrator.idor_sweep_tasks(limit=1)[0]
        orchestrator.surface.add_endpoint(TARGET + "/api/user", source="enumerate")
        two = orchestrator.idor_sweep_tasks(limit=2)[0]
        self.assertGreaterEqual(two.steps, one.steps)


if __name__ == "__main__":
    unittest.main()
