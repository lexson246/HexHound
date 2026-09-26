"""连通性诊断测试：把"Connection error."变成可判定的结论。

背景（真实事故）：一次运行只留下 `APIConnectionError: Connection error.`——
SDK 的摘要把底层原因（DNS 失败 / 连接被拒 / 证书被替换 / 代理端口写错）全吞了，
事后无法判定是谁的问题。这些用例钉住两件事：

1. `describe_exception` 必须摊开因果链，`classify_error` 要据此给出**不同的**建议；
2. `probe_endpoint` 分步探测（DNS/TCP/TLS/HTTP）**不发凭据**，
   因此它绝不消耗模型额度——这一点由"只访问本地临时服务"的测试保证。
"""
from __future__ import annotations

import json
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.diagnose import (  # noqa: E402
    describe_exception,
    exception_chain,
    format_probe,
    list_models,
    probe_endpoint,
    proxy_environment,
)
from hexhound.llm import classify_error  # noqa: E402


def _chained(outer: Exception, inner: Exception) -> Exception:
    outer.__cause__ = inner
    return outer


class ExceptionChainTests(unittest.TestCase):
    def test_chain_flattens_cause_and_context(self) -> None:
        inner = OSError(10061, "由于目标计算机积极拒绝，无法连接。")
        middle = ConnectionError("TCP 层失败")
        middle.__cause__ = inner
        outer = _chained(RuntimeError("Connection error."), middle)
        chain = exception_chain(outer)
        self.assertEqual(len(chain), 3)
        self.assertIn("RuntimeError: Connection error.", chain[0])
        self.assertIn("10061", chain[2])

    def test_describe_exception_keeps_the_actionable_tail(self) -> None:
        exc = _chained(RuntimeError("Connection error."), socket.gaierror(-2, "Name or service not known"))
        text = describe_exception(exc)
        self.assertIn("Connection error.", text)
        # 关键：底层原因必须出现在字符串里，否则"为什么失败"永远答不出来
        self.assertIn("gaierror", text)
        self.assertIn("Name or service not known", text)

    def test_chain_is_cycle_safe(self) -> None:
        first = RuntimeError("a")
        second = RuntimeError("b")
        first.__cause__ = second
        second.__cause__ = first  # 人为造环
        chain = exception_chain(first)
        self.assertEqual(len(chain), 2)

    def test_single_exception_needs_no_arrow(self) -> None:
        self.assertEqual(describe_exception(ValueError("简单错误")), "ValueError: 简单错误")


class ClassifyUsesTheChainTests(unittest.TestCase):
    """分类必须看底层原因——否则 DNS 失败与代理端口写错会得到同一条建议。"""

    def test_dns_failure_is_told_apart_from_connection_refused(self) -> None:
        dns = _chained(RuntimeError("Connection error."), socket.gaierror(-2, "Name or service not known"))
        refused = _chained(RuntimeError("Connection error."), OSError(10061, "连接被积极拒绝"))
        dns_category, dns_advice = classify_error(dns)
        refused_category, refused_advice = classify_error(refused)
        self.assertEqual(dns_category, "network")
        self.assertEqual(refused_category, "network")
        self.assertIn("域名解析失败", dns_advice)
        self.assertIn("连接被拒", refused_advice)
        self.assertNotEqual(dns_advice, refused_advice)

    def test_advice_points_at_the_doctor_command(self) -> None:
        exc = _chained(RuntimeError("Connection error."), OSError(10061, "拒绝"))
        _category, advice = classify_error(exc)
        self.assertIn("hexhound doctor", advice)

    def test_tls_failure_mentions_certificate_interception(self) -> None:
        exc = _chained(RuntimeError("Connection error."), ValueError("certificate verify failed"))
        category, advice = classify_error(exc)
        self.assertEqual(category, "network")
        self.assertIn("证书", advice)


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 标准库回调名
        self.send_response(401)  # 与真实提供商的"未认证"响应一致
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args) -> None:  # noqa: D102 静音
        return


class ProbeEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def test_local_endpoint_is_reachable_and_reports_each_step(self) -> None:
        probe = probe_endpoint(self.base, timeout=5)
        names = [step.name for step in probe.steps]
        self.assertEqual(names[:2], ["解析主机名", "TCP 连接"])
        self.assertTrue(probe.reachable)
        self.assertIn("HTTP 401", format_probe(probe)[-3])

    def test_closed_port_is_reported_as_tcp_failure(self) -> None:
        probe = probe_endpoint("http://127.0.0.1:9", timeout=3)  # discard 端口，通常无人监听
        self.assertFalse(probe.reachable)
        verdict = probe.verdict()
        self.assertIn("TCP 连接 失败", verdict)

    def test_unresolvable_host_is_reported_as_dns_failure(self) -> None:
        probe = probe_endpoint("https://no-such-host.invalid", timeout=5)
        self.assertFalse(probe.reachable)
        self.assertIn("解析主机名 失败", probe.verdict())
        self.assertEqual([step.name for step in probe.steps], ["解析主机名"])

    def test_empty_base_url_is_rejected_clearly(self) -> None:
        probe = probe_endpoint("")
        self.assertFalse(probe.reachable)
        self.assertIn("主机名", probe.steps[0].detail)

    def test_probe_never_sends_credentials(self) -> None:
        """诊断只做"通不通"的判断：**不发 Authorization**（因此不消耗额度）。

        用一个会记录请求头的本地服务来证明：请求里不能出现任何凭据头。
        """
        seen: list[dict] = []

        class _Recorder(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                seen.append({k.lower(): v for k, v in self.headers.items()})
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args) -> None:  # noqa: D102
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            probe_endpoint(f"http://127.0.0.1:{server.server_port}", timeout=5)
        finally:
            server.shutdown()
        self.assertTrue(seen, "探测应当发出一个未认证请求")
        for headers in seen:
            self.assertNotIn("authorization", headers)

    def test_proxy_environment_is_surfaced(self) -> None:
        """代理环境变量要报出来：httpx/openai 默认 trust_env=True，会真的走它们。"""
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:7892"}, clear=False):
            self.assertEqual(proxy_environment().get("HTTPS_PROXY"), "http://127.0.0.1:7892")
            probe = probe_endpoint(self.base, timeout=5)
        self.assertIn("HTTPS_PROXY", probe.proxy_env)
        self.assertIn("trust_env", "\n".join(format_probe(probe)))


class ListModelsTests(unittest.TestCase):
    """`GET /v1/models` 是核对模型名最便宜的手段（不计费）——但要能正确解析与报错。"""

    @classmethod
    def setUpClass(cls) -> None:
        class _Models(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.headers.get("Authorization") == "Bearer sk-good":
                    body = json.dumps({"data": [{"id": "deepseek-flash"}, {"id": "deepseek-v4-pro"}]}).encode()
                    self.send_response(200)
                else:
                    body = b'{"error":"invalid key"}'
                    self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args) -> None:  # noqa: D102
                return

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Models)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def test_parses_model_ids(self) -> None:
        models, error = list_models(self.base, "sk-good", timeout=5)
        self.assertEqual(error, "")
        self.assertEqual(models, ["deepseek-flash", "deepseek-v4-pro"])

    def test_bad_key_is_reported_not_raised(self) -> None:
        models, error = list_models(self.base, "sk-bad", timeout=5)
        self.assertEqual(models, [])
        self.assertIn("401", error)

    def test_missing_key_short_circuits(self) -> None:
        models, error = list_models(self.base, "", timeout=5)
        self.assertEqual(models, [])
        self.assertIn("没有可用的 API key", error)

    def test_error_never_contains_the_key(self) -> None:
        """报错里绝不能带 key（这个字符串会进日志与界面）。"""
        _models, error = list_models(self.base, "sk-secret-value", timeout=5)
        self.assertNotIn("sk-secret-value", error)


if __name__ == "__main__":
    unittest.main()
