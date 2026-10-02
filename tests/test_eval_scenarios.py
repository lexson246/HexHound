"""评测口径本身要有测试——指标算错比没有指标更糟。

这些用例只测**纯函数**（判定归类、汇总、标准答案匹配），不发任何请求：
指标定义是评测的可信度来源，必须能在改动后一分钟内回归。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import eval_scenarios as ev  # noqa: E402


class ClassifyTests(unittest.TestCase):
    def test_expected_signal(self) -> None:
        self.assertEqual(ev.classify_engine_outcome(["signal"], "signal")[0], "detected")
        self.assertEqual(ev.classify_engine_outcome(["no_signal"], "signal")[0], "missed")

    def test_expected_quiet(self) -> None:
        self.assertEqual(ev.classify_engine_outcome(["no_signal"], "none")[0], "true_negative")
        self.assertEqual(ev.classify_engine_outcome(["signal"], "none")[0], "false_positive")

    def test_reflection_only_is_not_a_false_positive(self) -> None:
        """字符串层的反射不算误报：只有浏览器能判它可不可执行。"""
        self.assertEqual(
            ev.classify_engine_outcome(["signal"], "reflection_only")[0], "reflection_only_flagged"
        )

    def test_blocked_is_inconclusive_not_missed(self) -> None:
        """被限流/阻断时**不能算漏报**——没测成和测了没中是两件事。"""
        for outcomes in (["blocked"], ["error"], ["blocked", "error"], []):
            with self.subTest(outcomes=outcomes):
                self.assertEqual(ev.classify_engine_outcome(outcomes, "signal")[0], "inconclusive")

    def test_partial_blocked_still_counts_as_detected(self) -> None:
        self.assertEqual(
            ev.classify_engine_outcome(["blocked", "signal"], "signal")[0], "detected"
        )


class SummaryTests(unittest.TestCase):
    def make(self, verdict: str, scenario_id: str = "s") -> ev.ScenarioResult:
        return ev.ScenarioResult(id=scenario_id, name=scenario_id, expected="signal", verdict=verdict)

    def test_rates_and_denominators(self) -> None:
        results = [
            self.make("detected", "a"), self.make("detected", "b"), self.make("missed", "c"),
            self.make("true_negative", "d"), self.make("false_positive", "e"),
            self.make("inconclusive", "f"), self.make("reflection_only_flagged", "g"),
        ]
        metrics = ev.summarize(results)
        self.assertEqual(metrics["detected"], 2)
        self.assertEqual(metrics["missed"], 1)
        self.assertAlmostEqual(metrics["detection_rate"], 2 / 3, places=4)
        self.assertAlmostEqual(metrics["false_positive_rate"], 1 / 2, places=4)
        self.assertEqual(metrics["inconclusive"], 1)
        self.assertEqual(metrics["reflection_only_flagged"], 1)
        # 无结论不进任何分母
        self.assertEqual(metrics["detected"] + metrics["missed"], 3)
        self.assertEqual(metrics["missed_ids"], ["c"])
        self.assertEqual(metrics["false_positive_ids"], ["e"])

    def test_empty_and_all_inconclusive_do_not_divide_by_zero(self) -> None:
        self.assertIsNone(ev.summarize([])["detection_rate"])
        metrics = ev.summarize([self.make("inconclusive", "a")])
        self.assertIsNone(metrics["detection_rate"])
        self.assertIsNone(metrics["false_positive_rate"])


class MatchingTests(unittest.TestCase):
    SCENARIO = {
        "id": "sqli-login", "endpoint": "/login", "ground_truth": "SQL注入", "expected": "signal",
    }

    def test_matches_by_path_and_type(self) -> None:
        class Finding:
            url = "http://127.0.0.1:5000/login?username=alice"
            title = "登录接口 SQL 注入"
            vuln_type = "SQL注入"
            description = ""

        self.assertTrue(ev.finding_matches(self.SCENARIO, Finding()))

    def test_same_path_but_wrong_type_does_not_match(self) -> None:
        class Finding:
            url = "http://127.0.0.1:5000/login"
            title = "缺少安全响应头"
            vuln_type = "配置问题"
            description = ""

        self.assertFalse(ev.finding_matches(self.SCENARIO, Finding()))

    def test_query_and_trailing_slash_are_ignored(self) -> None:
        class Finding:
            url = "http://127.0.0.1:5000/login/"
            title = "SQL 注入"
            vuln_type = ""
            description = ""

        self.assertTrue(ev.finding_matches(self.SCENARIO, Finding()))

    def test_dict_findings_are_supported(self) -> None:
        self.assertTrue(ev.finding_matches(
            self.SCENARIO, {"url": "http://127.0.0.1:5000/login", "title": "SQL 注入"}
        ))


class ScenarioFileTests(unittest.TestCase):
    def test_repository_scenario_file_is_valid(self) -> None:
        data = ev.load_scenarios(ROOT / "evals" / "scenarios.json")
        scenarios = data["scenarios"]
        self.assertGreaterEqual(len(scenarios), 8)
        ids = [item["id"] for item in scenarios]
        self.assertEqual(len(ids), len(set(ids)), "场景 id 不能重复")
        for item in scenarios:
            self.assertIn(item["expected"], ("signal", "none", "reflection_only"))
            self.assertTrue(str(item.get("endpoint") or "").startswith("/"))
            if item["expected"] == "signal":
                self.assertTrue(item.get("ground_truth"), "应命中的场景必须有标准答案")
        # 误报判据要有货：至少两个"应当安静"的场景
        quiet = [item for item in scenarios if item["expected"] == "none"]
        self.assertGreaterEqual(len(quiet), 2)

    def test_bad_file_is_rejected_loudly(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text('{"nope": 1}', encoding="utf-8")
            with self.assertRaises(ValueError):
                ev.load_scenarios(path)


if __name__ == "__main__":
    unittest.main()
