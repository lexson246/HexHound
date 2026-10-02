"""评测口径本身要有测试——指标算错比没有指标更糟。

这些用例只测**纯函数**（判定归类、汇总、标准答案匹配），不发任何请求：
指标定义是评测的可信度来源，必须能在改动后一分钟内回归。
"""
from __future__ import annotations

import os
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


class CoverageScoringTests(unittest.TestCase):
    """回归复核型运行要把"仍成立"读成命中（第一次 live 评测暴露的口径问题）。

    事实经过：live 评测第一轮检出 75%，两条"漏报"（`/api/order`、`/api/users`）
    查下去发现子代理**确实找到了**——只是那轮被规划成"回归复核历史漏洞"，
    结论写进了任务总结与覆盖记录（带证据编号），没有再 `record_finding` 一次。
    只认 findings 的评分口径会把这种情况算成漏报。

    这里钉住：只认**结构化**信号（`status == reported` + 端点路径 + **类型关键词**），
    不从自由文本里猜。

    "类型也要对得上"是第二次踩出来的：脚本 LLM 那档给 `/ssti`、`/file` 都写了
    `status=reported`，但 detail 是同一句"sqli 注入（脚本 LLM 确认）"——只看
    "端点 + reported"会把这两条算成命中，检出率从 12.5% 虚高到 37.5%。
    """

    SCENARIO = {"id": "unauth-users", "endpoint": "/api/users", "ground_truth": "未授权访问"}

    def test_reported_coverage_counts_as_detected(self) -> None:
        rows = [
            {"status": "no_issue_found", "target": "http://127.0.0.1:5000/api/users 注入排查"},
            {"status": "reported", "target": "http://127.0.0.1:5000/api/users（参数 uid）",
             "detail": "未授权访问：匿名可读全部用户 PII"},
        ]
        self.assertIn("匿名可读", ev.coverage_mentions(self.SCENARIO, rows))

    def test_wrong_vuln_type_on_the_right_endpoint_does_not_count(self) -> None:
        """端点对、类型错 = 自相矛盾的记录，不构成"发现了该漏洞"。

        真实数据：脚本 LLM 给 `/ssti`（SSTI 场景）写的是"sqli 注入（脚本 LLM 确认）"。
        """
        ssti = {"id": "ssti-name", "endpoint": "/ssti", "ground_truth": "SSTI"}
        rows = [{"status": "reported", "target": "http://127.0.0.1:5000/ssti（参数 name）",
                 "detail": "sqli 注入（脚本 LLM 确认）"}]
        self.assertEqual(ev.coverage_mentions(ssti, rows), "")
        # 同一行换个说法（模板注入）就算命中——判据是类型关键词，不是措辞
        rows[0]["detail"] = "模板注入：{{7*7}} → 49"
        self.assertIn("模板注入", ev.coverage_mentions(ssti, rows))

    def test_other_statuses_and_other_endpoints_do_not_count(self) -> None:
        rows = [
            {"status": "no_issue_found", "target": "http://127.0.0.1:5000/api/users"},
            {"status": "reported", "target": "http://127.0.0.1:5000/other",
             "detail": "未授权访问"},
            {"status": "blocked", "target": "http://127.0.0.1:5000/api/users",
             "detail": "未授权访问"},
        ]
        self.assertEqual(ev.coverage_mentions(self.SCENARIO, rows), "")

    def test_free_text_only_is_not_enough(self) -> None:
        """没有结构化状态就不算命中——否则指标会变成"文本里提过就算"。"""
        rows = [{"status": "not_tested", "target": "http://127.0.0.1:5000/api/users",
                 "detail": "总结里提到过 /api/users 可能有问题"}]
        self.assertEqual(ev.coverage_mentions(self.SCENARIO, rows), "")


class MemoryIsolationTests(unittest.TestCase):
    """评测必须**从零开始**：不许读到这台机器的历史（第一次 live 评测的教训）。

    事实经过：live 第一轮的计划里写着"回归复核历史漏洞"——因为 `HostMemory`
    解析的是用户真实的 `~/.hexhound`，靶场之前扫过，于是整轮变成复测旧账：
    子代理确实找到了越权，但走"复核"路径没重新记录，评分算成漏报。
    分数取决于这台机器以前跑过什么 = 评测无效。

    这里钉住两件事：① `HEXHOUND_HOME` 被指到本轮产物目录；
    ② 真的按这个环境变量读记忆的调用方（`HostMemory(host)` 不传 home）
    拿到的是空记忆，而不是上一轮/用户真实的历史。
    """

    def setUp(self) -> None:
        self._saved = os.environ.get("HEXHOUND_HOME")

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("HEXHOUND_HOME", None)
        else:
            os.environ["HEXHOUND_HOME"] = self._saved

    def test_home_points_at_this_runs_artifacts(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            returned = ev.isolate_run_memory(home)
            self.assertEqual(returned, home)
            self.assertEqual(os.environ["HEXHOUND_HOME"], str(home))

    def test_never_points_at_the_real_user_home(self) -> None:
        import tempfile

        from hexhound.memory import DEFAULT_HOME, data_home

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "evals" / "20261003-040256" / "home"
            ev.isolate_run_memory(home)
            self.assertNotEqual(data_home(), DEFAULT_HOME)
            self.assertTrue(str(data_home()).startswith(tmp))

    def test_caller_reading_data_home_gets_empty_memory(self) -> None:
        """关键回归：`HostMemory(host)`（评测里的真实调用方式）必须读不到历史。"""
        import tempfile

        from hexhound.memory import HostMemory

        with tempfile.TemporaryDirectory() as tmp:
            target = "http://127.0.0.1:5000"
            # 上一轮：记忆里记着"报过这些"（用公开 API 写入，不碰内部结构）
            ev.isolate_run_memory(Path(tmp) / "run1" / "home")
            previous = HostMemory(target)
            previous.record_run(findings=[
                {"id": "F1", "title": "越权读取 /api/order", "status": "verified"}
            ])
            self.assertEqual(len(previous.known_findings()), 1, "上一轮记忆应当能落盘")

            # 本轮：换一个产物目录 = 全新审计
            ev.isolate_run_memory(Path(tmp) / "run2" / "home")
            fresh = HostMemory(target)
            self.assertEqual(fresh.known_findings(), [],
                             "新一轮不许继承上一轮的记忆")

    def test_different_runs_get_different_homes(self) -> None:
        """两次评测的产物目录不同 = 第二轮不会读到第一轮的账。"""
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            first = ev.isolate_run_memory(Path(tmp) / "20261003-040256" / "home")
            second = ev.isolate_run_memory(Path(tmp) / "20261003-050000" / "home")
            self.assertNotEqual(first, second)


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
