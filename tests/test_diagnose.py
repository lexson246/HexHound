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
import os
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound import diagnose  # noqa: E402
from hexhound.diagnose import (  # noqa: E402
    describe_exception,
    exception_chain,
    format_probe,
    list_models,
    probe_endpoint,
    proxy_environment,
)
from hexhound.llm import classify_error  # noqa: E402
from hexhound.surface import AttackSurface  # noqa: E402
from hexhound.tools import ToolRegistry  # noqa: E402


def _chained(outer: Exception, inner: Exception) -> Exception:
    outer.__cause__ = inner
    return outer


def _fake_probe():
    """一个固定的探测结果（避免测试真的去连网络）。"""
    from hexhound.diagnose import EndpointProbe, ProbeStep

    probe = EndpointProbe(base_url="http://127.0.0.1:1", host="127.0.0.1", port=1)
    probe.steps = [
        ProbeStep("解析主机名", True, "127.0.0.1", 1),
        ProbeStep("TCP 连接", False, "ConnectionRefusedError: 拒绝", 2),
    ]
    return probe


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
        text = "\n".join(format_probe(probe))
        self.assertIn("代理环境变量", text)
        self.assertIn("httpx 实际会用的代理", text, "必须报告 httpx 真正会用的代理，而不只是环境变量")


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


class SelfDiagnosisOnFailureTests(unittest.TestCase):
    """失败现场要**自动取证**：网络类错误必须带上分步探测结果。

    为什么放在这里测：真实事故只留下 `APIConnectionError: Connection error.`，
    用户既不知道原因也不知道下一步做什么。失败那一刻是唯一能观察到现场的时刻，
    所以 agent/orchestrator 必须在收尾前自动探测一次（不发凭据、不消耗额度）。
    """

    def test_is_network_error_matches_connection_failures_only(self) -> None:
        from hexhound.diagnose import is_network_error

        network_like = _chained(RuntimeError("Connection error."), OSError(10061, "拒绝"))
        self.assertTrue(is_network_error(network_like))
        dns_like = _chained(RuntimeError("Connection error."), socket.gaierror(-2, "not known"))
        self.assertTrue(is_network_error(dns_like))
        auth_like = RuntimeError("Error code: 401 - invalid api key")
        self.assertFalse(is_network_error(auth_like), "401 不该触发连通性探测")
        model_like = RuntimeError("model_not_found: deepseek-v4-flash")
        self.assertFalse(is_network_error(model_like))

    def test_probe_lines_are_indented_and_conclusive(self) -> None:
        from hexhound.diagnose import probe_lines

        with patch.object(diagnose, "probe_endpoint", lambda url, timeout=6.0: _fake_probe()):
            lines = probe_lines("http://127.0.0.1:1", indent="  ")
        self.assertTrue(all(line.startswith("  ") for line in lines), lines)
        self.assertTrue(any("结论" in line for line in lines))

    def test_probe_failure_does_not_break_wrapup(self) -> None:
        """探测本身炸了也不能影响收尾——失败现场最忌讳"诊断把程序弄挂"。"""
        from hexhound.diagnose import probe_lines

        def boom(url, timeout=6.0):
            raise RuntimeError("探测内部错误")

        with patch.object(diagnose, "probe_endpoint", boom):
            lines = probe_lines("http://127.0.0.1:1")
        self.assertEqual(len(lines), 1)
        self.assertIn("未能完成", lines[0])

    def test_agent_reports_chain_and_probe_on_provider_error(self) -> None:
        """端到端（打桩模型）：agent 的失败文案要含因果链 + 现场探测。"""
        from hexhound.agent import ReActAgent

        class _BoomLLM:
            base_url = "http://127.0.0.1:1"

            def complete(self, messages):
                raise _chained(RuntimeError("Connection error."), socket.gaierror(-2, "Name or service not known"))

        registry = ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1"}),
            timeout=5,
            mode="blackbox",
            surface=AttackSurface(target="http://127.0.0.1:5000", mode="blackbox"),
            role="recon",
        )
        agent = ReActAgent(_BoomLLM(), registry, max_steps=2, verbose=False,
                           target="http://127.0.0.1:5000", role="recon")
        with patch.object(diagnose, "probe_endpoint", lambda url, timeout=6.0: _fake_probe()):
            result = agent.run("测试目标")
        summary = str(getattr(result, "final_summary", "") or "")
        self.assertIn("gaierror", summary, "必须带底层原因")
        self.assertIn("连通性现场探测", summary)
        self.assertEqual(getattr(result, "finish_reason", ""), "provider_error")


class LocalNetworkFactsTests(unittest.TestCase):
    """"为什么只有挂 VPN 才行"这一类问题，靠解析本机路由/适配器来回答。

    最常见的成因：VPN 客户端退出/crash 后留下一条指向死隧道的默认路由，
    于是**换任何网络都不通**，而重新打开 VPN 又"好了"。
    这里用真实命令输出片段钉住解析逻辑（不执行命令、不联网）。
    """

    WINDOWS_ROUTE = """
===========================================================================
Interface List
 12...aa bb cc dd ee ff ......Intel(R) Wi-Fi 6E AX210 160MHz
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0   10.134.173.147   10.134.173.236     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
===========================================================================
"""

    WINDOWS_ROUTE_DOUBLE = WINDOWS_ROUTE.replace(
        "===========================================================================\n\nIPv4 Route Table",
        "          0.0.0.0          0.0.0.0      10.0.0.1      10.0.0.5     5\n"
        "===========================================================================\n\nIPv4 Route Table",
    )

    def test_parses_single_windows_default_route(self) -> None:
        routes = diagnose.parse_default_routes(self.WINDOWS_ROUTE)
        self.assertEqual(routes, [("10.134.173.147", "10.134.173.236")])

    def test_parses_linux_default_route(self) -> None:
        routes = diagnose.parse_default_routes(
            "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"
            "192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.20\n"
        )
        self.assertEqual(routes, [("192.168.1.1", "wlan0")])

    def test_ignores_non_default_routes(self) -> None:
        routes = diagnose.parse_default_routes(self.WINDOWS_ROUTE)
        self.assertEqual(len(routes), 1, "只应取默认路由")

    def test_adapter_names_from_ipconfig(self) -> None:
        names = diagnose.parse_adapter_names(
            "Windows IP Configuration\n\n"
            "Ethernet adapter 以太网:\n   Media State . . . . . . . . . . . : Media disconnected\n\n"
            "Unknown adapter Tailscale:\n   Media State . . . . . . . . . . . : Media disconnected\n"
        )
        self.assertIn("Tailscale", names)
        self.assertIn("以太网", names)

    def test_two_default_routes_are_flagged(self) -> None:
        """多条默认路由必须报警——这正是"只有挂 VPN 才行"的典型残留。"""
        with patch("subprocess.run") as run:
            run.side_effect = [
                _Proc(self.WINDOWS_ROUTE_DOUBLE),
                _Proc("Unknown adapter Tailscale:\n"),
            ]
            facts = diagnose.local_network_facts()
        joined = "\n".join(facts)
        self.assertIn("默认路由 2 条", joined)
        self.assertIn("[!!]", joined)

    def test_command_failure_does_not_raise(self) -> None:
        with patch("subprocess.run", side_effect=OSError("no route cmd")):
            facts = diagnose.local_network_facts()
        self.assertTrue(facts)
        self.assertIn("读取失败", "\n".join(facts))


class _Proc:
    """subprocess.run 的最小替身（只用到 stdout）。"""

    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


class EffectiveProxyTests(unittest.TestCase):
    """系统代理（Windows 注册表）也必须看见——这是"只有挂 VPN 才行"的真实成因。

    事故链条（已受控复现，见 docs/WORK-REPORT-ROUND3.md）：
    代理客户端（Clash/V2Ray 那类）把系统代理设成 127.0.0.1:7892；
    退出时**没复位**；httpx 经 urllib.request.getproxies() 读到它 →
    请求全打到没人监听的端口 → SDK 重试 3 次 → ~7.3 秒后 APIConnectionError、0 token。
    系统代理是用户级/机器级设置，**与当前连哪个网络无关**，
    所以"换任何网络都不行"这个观察完全对得上。
    """

    def test_effective_proxy_reflects_what_httpx_uses(self) -> None:
        from unittest.mock import patch

        with patch(
            "urllib.request.getproxies",
            lambda: {"http": "http://127.0.0.1:7892", "https": "http://127.0.0.1:7892"},
        ):
            self.assertEqual(
                diagnose.effective_proxy(),
                {"http": "http://127.0.0.1:7892", "https": "http://127.0.0.1:7892"},
            )
        with patch("urllib.request.getproxies", lambda: {}):
            self.assertEqual(diagnose.effective_proxy(), {})

    def test_dead_proxy_is_detected(self) -> None:
        with patch("socket.socket") as sock_cls:
            sock_cls.return_value.connect.side_effect = ConnectionRefusedError(10061, "拒绝")
            dead, detail = diagnose.proxy_health({"https": "http://127.0.0.1:7892"})
        self.assertTrue(dead)
        self.assertIn("连不上", detail)
        self.assertIn("7892", detail)

    def test_live_proxy_is_not_flagged(self) -> None:
        with patch("socket.socket") as sock_cls:
            sock_cls.return_value.connect.return_value = None
            dead, detail = diagnose.proxy_health({"https": "http://127.0.0.1:7892"})
        self.assertFalse(dead)
        self.assertIn("可连", detail)

    def test_no_proxy_configured_is_not_flagged(self) -> None:
        dead, detail = diagnose.proxy_health({})
        self.assertFalse(dead)
        self.assertEqual(detail, "")

    def test_proxy_report_names_the_registry_state(self) -> None:
        from unittest.mock import patch

        with patch.object(diagnose, "effective_proxy", lambda: {"https": "http://127.0.0.1:7892"}), \
             patch.object(diagnose, "proxy_health", lambda proxies=None, timeout=1.5: (True, "代理 http://127.0.0.1:7892 **连不上**")), \
             patch.object(diagnose, "registry_proxy_state", lambda: {"ProxyEnable": 1, "ProxyServer": "127.0.0.1:7892"}):
            text = "\n".join(diagnose.proxy_report())
        self.assertIn("httpx 实际会用的代理", text)
        self.assertIn("连不上", text)
        self.assertIn("ProxyEnable=1", text)

    def test_dead_proxy_is_bypassed_by_the_llm_client(self) -> None:
        """死代理下客户端要自动直连（并留下说明），而不是白等 7 秒后失败。"""
        from unittest.mock import patch

        from hexhound.llm import LLMClient

        def boom(url, timeout=6.0):
            raise RuntimeError("探测失败")

        with patch.object(diagnose, "proxy_health", lambda proxies=None, timeout=1.5: (True, "代理 http://127.0.0.1:7892 **连不上**")), \
             patch.object(diagnose, "effective_proxy", lambda: {"https": "http://127.0.0.1:7892"}):
            client = LLMClient("sk-fake", "https://api.deepseek.com", "deepseek-flash", provider="deepseek")
        self.assertIn("已改为直连", client.network_note)
        self.assertIn("7892", client.network_note)

    def test_live_proxy_keeps_default_behaviour(self) -> None:
        from unittest.mock import patch

        from hexhound.llm import LLMClient

        with patch.object(diagnose, "proxy_health", lambda proxies=None, timeout=1.5: (False, "代理可连")):
            client = LLMClient("sk-fake", "https://api.deepseek.com", "deepseek-flash", provider="deepseek")
        self.assertEqual(client.network_note, "", "代理正常时不该改动任何行为")
        with patch.object(diagnose, "proxy_health", side_effect=RuntimeError("boom")):
            client2 = LLMClient("sk-fake", "https://api.deepseek.com", "deepseek-flash", provider="deepseek")
        self.assertEqual(client2.network_note, "", "诊断异常时保守：不动 SDK 默认行为")


class BrokenNoProxyTests(unittest.TestCase):
    """坏掉的 `NO_PROXY` 不能把客户端构造搞崩（Round4 实测事故）。

    真实环境：代理工具把 `NO_PROXY=localhost,127.0.0.1,::1,[::1]` 写进环境变量，
    httpx 解析 `[::1]` 这个条目时抛 `InvalidURL: Invalid port: ':1]'`——
    **请求还没发出去**，诊断和 LLM 客户端构造就一起失败了，
    用户看到的是一句与网络状况毫无关系的报错。
    """

    POISONED = "localhost,127.0.0.1,*.local,::1,[::1]"

    def test_host_matcher_tolerates_unparseable_entries(self) -> None:
        from hexhound.llm import _host_in_no_proxy

        with patch.dict(os.environ, {"NO_PROXY": self.POISONED, "no_proxy": self.POISONED}):
            self.assertTrue(_host_in_no_proxy("127.0.0.1"))
            self.assertTrue(_host_in_no_proxy("::1"))
            self.assertTrue(_host_in_no_proxy("api.internal.local"))
            self.assertFalse(_host_in_no_proxy("api.deepseek.com"))

    def test_diagnostic_client_works_with_a_poisoned_no_proxy(self) -> None:
        from hexhound.diagnose import diagnostic_client

        with patch.dict(os.environ, {"NO_PROXY": self.POISONED, "no_proxy": self.POISONED}):
            client = diagnostic_client("http://127.0.0.1:5000", timeout=2)
            try:
                # 关键点：**构造成功**（坏 NO_PROXY 下 httpx 自己构造会抛 InvalidURL）
                self.assertEqual(client.timeout.read, 2)
            finally:
                client.close()

    def test_loopback_targets_never_use_the_proxy(self) -> None:
        """诊断本机服务却经过代理毫无意义（而且代理多半连不上回环地址）。"""
        from hexhound.llm import _proxy_for_target

        with patch.dict(os.environ, {
            "HTTP_PROXY": "http://127.0.0.1:7892", "ALL_PROXY": "http://127.0.0.1:7892",
        }):
            self.assertEqual(_proxy_for_target("http://127.0.0.1:5000"), "")
            self.assertEqual(_proxy_for_target("http://localhost:5000"), "")

    def test_remote_target_uses_the_configured_proxy(self) -> None:
        from hexhound.llm import _proxy_for_target

        with patch.dict(os.environ, {
            "HTTP_PROXY": "http://127.0.0.1:7892", "ALL_PROXY": "http://127.0.0.1:7892",
            "NO_PROXY": "", "no_proxy": "",
        }), patch.object(diagnose, "effective_proxy", lambda: {"http": "http://127.0.0.1:7892"}):
            self.assertEqual(_proxy_for_target("https://api.deepseek.com"), "http://127.0.0.1:7892")

    def test_llm_client_can_be_constructed_under_a_poisoned_no_proxy(self) -> None:
        """最关键的一条：这种环境下客户端必须**能构造出来**（否则整个应用起不来）。"""
        from hexhound.llm import LLMClient

        with patch.dict(os.environ, {"NO_PROXY": self.POISONED, "no_proxy": self.POISONED}), \
             patch.object(diagnose, "proxy_health", lambda proxies=None, timeout=1.5: (False, "代理可连")):
            client = LLMClient("sk-fake", "https://api.deepseek.com", "deepseek-flash", provider="deepseek")
        self.assertEqual(client.network_note, "", "代理正常时不该改动行为、也不该多嘴")


class ConsoleDecodingTests(unittest.TestCase):
    """本机命令输出不一定是 UTF-8（中文 Windows 是 GBK）。

    实测事故：`subprocess.run(..., text=True)` 按 UTF-8 解 `route`/`ipconfig` 的
    GBK 输出，读取线程里抛 `UnicodeDecodeError`，输出被截断；调用方只看到一条
    `PytestUnhandledThreadExceptionWarning`，根本看不出是编码问题。
    """

    GBK_TEXT = (
        "接口列表\r\n"
        "  1...aa bb cc dd ......Realtek PCIe GbE Family Controller\r\n"
        "   默认网关. . . . . . . . . . . . . : 192.168.1.1\r\n"
    )

    def test_gbk_bytes_decode_without_exception(self) -> None:
        from hexhound.diagnose import _decode_console

        decoded = _decode_console(self.GBK_TEXT.encode("gbk"))
        self.assertIn("接口列表", decoded)
        self.assertIn("Default".replace("Default", "网关"), decoded)

    def test_utf8_and_empty_still_work(self) -> None:
        from hexhound.diagnose import _decode_console

        self.assertEqual(_decode_console("接口列表".encode()), "接口列表")
        self.assertEqual(_decode_console(b""), "")
        # 既不是 UTF-8 也不是系统编码的字节：宁可乱码也不能抛
        self.assertIsInstance(_decode_console(b"\xff\xfe\x00\xd2\xbb"), str)

    def test_network_facts_never_raise_on_gbk_output(self) -> None:
        from unittest.mock import patch

        class _Proc:
            stdout = ConsoleDecodingTests.GBK_TEXT.encode("gbk")

        with patch("subprocess.run", return_value=_Proc()):
            facts = diagnose.local_network_facts()
        self.assertTrue(facts)
        self.assertTrue(any("默认路由" in item or "适配器" in item for item in facts))


if __name__ == "__main__":
    unittest.main()
