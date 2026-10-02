"""限流（429/503）不得被当成"测过了"，更不能推出"已修复"。

外部评审指出的误判链（本文件逐段钉住）：

    429 → 记成 no_signal → 同一组合被去重跳过 → 端点算"本次覆盖过"
        → 跨运行 diff 判 **已修复**

安全报告里最严重的方向就是把"仍然存在"说成"修好了"。所以这里用一个**真实回环服务**
（返回 429 + `Retry-After`）跑完整链路，断言：

1. 429 记为 `blocked`（不是 `no_signal`）；
2. 同一组合**不会被跳过**（换身份/重试仍会真的发出去）；
3. 被限流的端点**不算覆盖**（`touched_endpoints()` 排除它）；
4. 因此跨运行 diff 只能给 `unknown`，绝不能给 `fixed`；
5. 报告里会出现限流披露，`surface.stats()["throttled"] > 0`。
"""
from __future__ import annotations

import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.diff import build_diff_from_memory  # noqa: E402
from hexhound.report import to_markdown  # noqa: E402
from hexhound.surface import AttackSurface  # noqa: E402
from hexhound.tools import ToolRegistry  # noqa: E402

#: 服务端开关：`throttle_until` 之前一直回 429（模拟"限流窗口"）。
STATE = {"throttle": True, "hits": 0}


class _Handler(BaseHTTPRequestHandler):
    def _respond(self, method: str) -> None:
        STATE["hits"] += 1
        if STATE["throttle"]:
            body = b"Too Many Requests"
            self.send_response(429)
            self.send_header("Retry-After", "30")
        else:
            body = b"You have an error in your SQL syntax near '''"
            self.send_response(500)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 标准库回调名
        self._respond("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._respond("POST")

    def log_message(self, *args) -> None:  # noqa: D102 静音
        return


class RateLimitTests(unittest.TestCase):
    server: ThreadingHTTPServer
    base = ""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def setUp(self) -> None:
        STATE["throttle"] = True
        STATE["hits"] = 0
        self.surface = AttackSurface(target=self.base, mode="blackbox")
        self.registry = ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1", "localhost"}),
            timeout=10,
            mode="blackbox",
            surface=self.surface,
        )

    # ---------- 1. 记 blocked，而不是 no_signal ----------

    def test_fuzz_marks_throttled_attempt_as_blocked(self) -> None:
        output = self.registry.execute("fuzz_params", {
            "url": f"{self.base}/item", "params": {"id": "1"},
            "categories": ["sqli"], "per_category": 1,
        })
        outcomes = {attempt.outcome for attempt in self.surface.attempts.values()}
        self.assertEqual(outcomes, {"blocked"}, f"429 不该被记成 {outcomes}：{output}")
        self.assertIn("限流", output)
        self.assertGreater(self.surface.stats()["throttled"], 0)

    def test_compare_responses_refuses_to_conclude_under_throttling(self) -> None:
        output = self.registry.execute("compare_responses", {
            "url": f"{self.base}/item", "params": {"id": "1"},
            "inject_params": {"id": "'"}, "category": "sqli",
        })
        self.assertTrue("未成立" in output or "不可用" in output, output)
        for attempt in self.surface.attempts.values():
            self.assertNotEqual(attempt.outcome, "no_signal")

    def test_security_headers_does_not_report_pass_when_throttled(self) -> None:
        output = self.registry.execute("check_security_headers", {"url": f"{self.base}/"})
        self.assertIn("未成立", output)
        self.assertNotIn("安全响应头检查通过", output)

    def test_enumerate_common_does_not_invent_endpoints_when_throttled(self) -> None:
        output = self.registry.execute("enumerate_common", {
            "base_url": self.base, "tiers": ["core"], "limit_per_tier": 3,
        })
        self.assertIn("未执行", output)
        self.assertEqual(list(self.surface.endpoints), [], "限流下不能登记任何端点")

    # ---------- 2. 不会被去重跳过 ----------

    def test_throttled_attempt_is_retried_after_the_limit_lifts(self) -> None:
        url = f"{self.base}/item"
        self.registry.execute("fuzz_params", {
            "url": url, "params": {"id": "1"}, "categories": ["sqli"], "per_category": 1,
        })
        self.assertTrue(self.surface.attempts, "第一次应当留下 blocked 记录")
        STATE["throttle"] = False  # 限流窗口结束，目标开始真的报 SQL 错误
        output = self.registry.execute("fuzz_params", {
            "url": url, "params": {"id": "1"}, "categories": ["sqli"], "per_category": 1,
        })
        self.assertNotIn("已由其他子代理命中", output)
        self.assertIn("命中 SQL 错误特征", output, f"限流解除后必须真的重测：{output}")
        self.assertTrue(any(a.outcome == "signal" for a in self.surface.attempts.values()))

    # ---------- 3/4. 不算覆盖 → diff 只能 unknown ----------

    def test_throttled_endpoint_is_not_counted_as_touched(self) -> None:
        url = f"{self.base}/admin"
        self.surface.mark_attempt(url, "sqli", param="id", payload="'", outcome="no_signal")
        self.assertIn(url, self.surface.touched_endpoints())
        self.surface.mark_throttled(url, "HTTP 429 限流")
        self.assertNotIn(
            url, self.surface.touched_endpoints(),
            "被限流过的端点不能算'本次覆盖过'",
        )

    def test_diff_never_says_fixed_for_a_throttled_endpoint(self) -> None:
        url = f"{self.base}/admin"
        previous = [{
            "title": "SQL 注入", "severity": "high", "url": url, "status": "verified",
            "vuln_type": "SQL注入", "param": "id",
        }]
        # 本次"覆盖过"该端点（有 no_signal），但端点被限流过
        self.surface.mark_attempt(url, "sqli", param="id", payload="'", outcome="no_signal")
        self.surface.mark_throttled(url, "HTTP 429 限流")
        diff = build_diff_from_memory(
            previous, [], touched_endpoints=self.surface.touched_endpoints(),
        )
        self.assertEqual(len(diff.fixed), 0, f"限流下不能说已修复：{diff.fixed}")
        self.assertEqual(len(diff.unknown), 1)
        self.assertIn("不要当作已修复", diff.unknown[0]["reason"])

    # ---------- 5. 报告披露 ----------

    def test_report_discloses_throttling(self) -> None:
        self.registry.execute("fuzz_params", {
            "url": f"{self.base}/item", "params": {"id": "1"},
            "categories": ["sqli"], "per_category": 1,
        })
        from hexhound.agent import AgentResult

        markdown = to_markdown(AgentResult(surface=self.surface), "测试")
        self.assertIn("目标限流/熔断", markdown)
        self.assertIn("不算本次覆盖过", markdown)


if __name__ == "__main__":
    unittest.main()
