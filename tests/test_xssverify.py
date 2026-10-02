"""浏览器 XSS 验证测试：反射 / DOM / 执行 三级判据与作用域约束。

三层测试：
1. **判据层**（纯函数 `classify`）——不需要 Playwright，覆盖全部分级逻辑；
2. **作用域与可用性层**——浏览器未安装/目标越界时的行为；
3. **真实浏览器层**——装了 Playwright 才跑（`skipUnless`），
   对着靶场里那组"都会回显但只有一个会执行"的对照组验证判据是否正确。
   这一层是"反射 ≠ 执行"的**实证**，不是推理。
"""
from __future__ import annotations

import os
import re
import sys
import threading
import unittest
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.xssverify import (  # noqa: E402
    CONFIRMED_LEVEL,
    DEFAULT_PAYLOADS,
    MARKER_ATTRIBUTE,
    BrowserUnavailable,
    BrowserVerifier,
    PageObservation,
    ScopeRefused,
    XssVerdict,
    _validate_browser_url,
    build_payloads,
    classify,
    new_marker,
    playwright_available,
    summarize_verdict,
    verification_payloads,
)

ALLOWED = frozenset({"127.0.0.1", "localhost"})
PAYLOAD = DEFAULT_PAYLOADS[0]
LAB = os.getenv("HEXHOUND_LAB_URL", "http://127.0.0.1:5000")


class ClassifyTests(unittest.TestCase):
    """分级判据：**顺序与含义**都不许含糊。"""

    def test_execution_flag_wins_over_everything(self) -> None:
        """观测到执行就是 executed，哪怕 DOM/响应里因为编码看不到原样 payload。

        这是刻意的：`onerror` 类载荷执行后，原始 payload 可能已经被浏览器
        改写或移除；此时若还按"字符串在不在"判定，就会把一个**真的执行了**
        的 XSS 判成"没反射"。
        """
        level = classify(
            payload=PAYLOAD,
            raw_body="<h1>你好，&lt;img ...&gt;</h1>",
            rendered_html="<h1>你好，</h1>",
            executed_flags={MARKER_ATTRIBUTE: True},
        )
        self.assertEqual(level, "executed")

    def test_execution_signal_alone_is_enough(self) -> None:
        level = classify(
            payload=PAYLOAD, raw_body="", rendered_html="",
            execution_signals=["页面弹出了对话框"],
        )
        self.assertEqual(level, "executed")

    def test_dom_without_execution_is_dom(self) -> None:
        """进了渲染后的 DOM 但没执行 —— **不能**报成确认的 XSS。"""
        level = classify(
            payload=PAYLOAD,
            raw_body=f"<textarea>{PAYLOAD}</textarea>",
            rendered_html=f"<textarea>{PAYLOAD}</textarea>",
        )
        self.assertEqual(level, "dom")

    def test_reflected_only_is_reflected(self) -> None:
        """只在原始响应里出现（text/plain 之类）—— 只是反射。"""
        level = classify(
            payload=PAYLOAD,
            raw_body=f"你好，{PAYLOAD}",
            rendered_html="<html><body>你好，</body></html>",
        )
        self.assertEqual(level, "reflected")

    def test_absent_when_nowhere(self) -> None:
        level = classify(
            payload=PAYLOAD, raw_body="<h1>你好</h1>", rendered_html="<h1>你好</h1>"
        )
        self.assertEqual(level, "absent")

    def test_csp_block_is_reported_as_blocked(self) -> None:
        level = classify(
            payload=PAYLOAD,
            raw_body=f"<h1>{PAYLOAD}</h1>",
            rendered_html="<h1></h1>",
            console=[{"type": "error", "text": "Refused to execute inline script because it "
                                                "violates the following Content Security Policy directive"}],
        )
        self.assertEqual(level, "blocked")

    def test_empty_payload_never_matches(self) -> None:
        """空 payload 会让 `"" in anything` 恒真 —— 必须显式挡住。"""
        self.assertEqual(classify(payload="", raw_body="x", rendered_html="x"), "absent")

    def test_only_executed_is_confirmed(self) -> None:
        for level in ("absent", "blocked", "reflected", "dom"):
            verdict = XssVerdict(level=level, payload=PAYLOAD, url="http://127.0.0.1/")
            self.assertFalse(verdict.confirmed, f"{level} 不得算确认")
        confirmed = XssVerdict(level="executed", payload=PAYLOAD, url="http://127.0.0.1/")
        self.assertTrue(confirmed.confirmed)
        self.assertEqual(CONFIRMED_LEVEL, "executed")


class StatementTests(unittest.TestCase):
    """措辞：报告里怎么写由代码决定，不给模型自由发挥的空间。"""

    def test_executed_statement_says_confirmed(self) -> None:
        verdict = XssVerdict(
            level="executed", payload=PAYLOAD, url="u", execution_signals=["DOM 标记"]
        )
        self.assertIn("确认执行", verdict.statement())

    def test_dom_statement_explicitly_denies_confirmation(self) -> None:
        verdict = XssVerdict(level="dom", payload=PAYLOAD, url="u")
        self.assertIn("没有观测到执行", verdict.statement())
        self.assertIn("不能报成确认的 XSS", verdict.statement())

    def test_reflected_statement_forbids_calling_it_xss(self) -> None:
        verdict = XssVerdict(level="reflected", payload=PAYLOAD, url="u")
        self.assertIn("不能报成 XSS", verdict.statement())

    def test_summary_carries_the_wording_constraints(self) -> None:
        verdict = XssVerdict(level="reflected", payload=PAYLOAD, url="u")
        text = summarize_verdict(verdict)
        self.assertIn("措辞约束", text)
        self.assertIn("只有 `executed` 才能写「确认的 XSS」", text)

    def test_summary_lists_evidence_flags(self) -> None:
        verdict = XssVerdict(
            level="executed", payload=PAYLOAD, url="u",
            in_response=True, in_dom=True, executed=True,
            execution_signals=["DOM 上出现了执行标记属性"],
        )
        text = summarize_verdict(verdict)
        self.assertIn("原始响应里出现载荷：是", text)
        self.assertIn("渲染后 DOM 里出现载荷：是", text)
        self.assertIn("观测到执行：是", text)


class PayloadTests(unittest.TestCase):
    def test_default_payloads_are_non_destructive(self) -> None:
        """默认载荷不能改目标数据——它只给自己的 DOM 打标记。"""
        for payload in DEFAULT_PAYLOADS:
            lowered = payload.lower()
            for dangerous in ("document.cookie", "fetch(", "xmlhttprequest", "eval(",
                              "localstorage", "window.location=", "form"):
                self.assertNotIn(
                    dangerous, lowered, f"载荷 {payload!r} 含潜在破坏性调用 {dangerous}"
                )
            self.assertIn(MARKER_ATTRIBUTE, payload)

    def test_default_payloads_avoid_alert(self) -> None:
        """`alert()` 在 headless 里会阻塞页面，不能当默认载荷。"""
        for payload in DEFAULT_PAYLOADS:
            self.assertNotIn("alert(", payload)

    def test_payloads_cover_multiple_contexts(self) -> None:
        joined = " ".join(DEFAULT_PAYLOADS)
        self.assertIn("onerror", joined)   # 属性/标签上下文
        self.assertIn("onload", joined)    # 引号闭合后的标签上下文
        self.assertIn("<script", joined)   # 直接注入正文

    def test_verification_payloads_helper(self) -> None:
        self.assertEqual(verification_payloads(), list(DEFAULT_PAYLOADS))
        self.assertEqual(len(verification_payloads(1)), 1)


class ScopeTests(unittest.TestCase):
    """浏览器只允许访问授权范围内的目标。"""

    def test_allowlisted_host_passes(self) -> None:
        self.assertEqual(_validate_browser_url("http://127.0.0.1:5000/reflect", ALLOWED), "")

    def test_foreign_host_is_refused(self) -> None:
        error = _validate_browser_url("http://evil.example.com/", ALLOWED)
        self.assertIn("不在白名单", error)

    def test_file_scheme_is_refused(self) -> None:
        """`file://` 会越过作用域（读本地文件），必须拒绝。"""
        error = _validate_browser_url("file:///etc/passwd", ALLOWED)
        self.assertIn("只允许 http/https", error)

    def test_data_scheme_is_refused(self) -> None:
        error = _validate_browser_url("data:text/html,<script>x</script>", ALLOWED)
        self.assertIn("只允许 http/https", error)

    def test_javascript_scheme_is_refused(self) -> None:
        error = _validate_browser_url("javascript:alert(1)", ALLOWED)
        self.assertIn("只允许 http/https", error)

    def test_empty_url_is_refused(self) -> None:
        self.assertTrue(_validate_browser_url("", ALLOWED))

    def test_observe_refuses_out_of_scope_before_opening(self) -> None:
        """范围校验必须发生在**打开页面之前**，且即使没装浏览器也先生效。"""
        verifier = BrowserVerifier(allowed_hosts=ALLOWED)
        with self.assertRaises(ScopeRefused):
            verifier.observe("http://evil.example.com/")

    def test_observe_refuses_file_scheme(self) -> None:
        verifier = BrowserVerifier(allowed_hosts=ALLOWED)
        with self.assertRaises(ScopeRefused):
            verifier.observe("file:///etc/passwd")


class AvailabilityTests(unittest.TestCase):
    def test_playwright_probe_returns_reason(self) -> None:
        ready, reason = playwright_available()
        self.assertIsInstance(ready, bool)
        if not ready:
            self.assertIn("playwright", reason.lower())
            self.assertIn("pip install", reason)

    def test_unavailable_raises_a_clear_error(self) -> None:
        ready, _ = playwright_available()
        verifier = BrowserVerifier(allowed_hosts=ALLOWED)
        if ready:
            self.skipTest("Playwright 已安装，本条只在未安装时验证提示")
        with self.assertRaises(BrowserUnavailable):
            verifier.observe("http://127.0.0.1:5000/reflect")

    def test_tool_is_dropped_when_playwright_is_missing(self) -> None:
        """没装浏览器时不下发 `browser_verify_xss`（能做什么才给什么）。"""
        from hexhound.surface import AttackSurface
        from hexhound.tools import ToolRegistry

        registry = ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=ALLOWED,
            mode="blackbox",
            role="injection",
            surface=AttackSurface(target=LAB),
        )
        ready, _ = playwright_available()
        self.assertEqual(registry.has("browser_verify_xss"), ready)

    def test_xss_fuzz_still_available_without_playwright(self) -> None:
        """没装浏览器不等于"XSS 不用测"：字符串反射级别的检测仍然可用。"""
        from hexhound.surface import AttackSurface
        from hexhound.tools import ToolRegistry

        registry = ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=ALLOWED,
            mode="blackbox",
            role="injection",
            surface=AttackSurface(target=LAB),
        )
        self.assertTrue(registry.has("fuzz_params"))


class EscapedOutputTests(unittest.TestCase):
    """被转义的输出点仍然是输出点 —— 判成 `absent` 是**低估**风险。

    实测踩到：服务端转义后 payload 在响应/DOM 里是 `&lt;img ...&gt;`，
    纯原样子串匹配什么都匹配不到，于是判成"未反射"。
    而真相是"这里是一个输出点，只是当前上下文被转义了"，
    换个上下文（属性、JS 字符串、innerHTML）就可能成立——
    读者看到"未反射"就不会再跟进这个参数。
    """

    def test_html_escaped_payload_is_detected(self) -> None:
        import html as html_module

        escaped = html_module.escape(PAYLOAD, quote=True)
        level = classify(
            payload=PAYLOAD,
            raw_body=f"<textarea>{escaped}</textarea>",
            rendered_html=f"<textarea>{escaped}</textarea>",
        )
        self.assertEqual(level, "dom")

    def test_mixed_encoding_from_a_real_browser_is_detected(self) -> None:
        """`page.content()` 实测返回**混合编码**：`&lt;` 保持转义、`&#39;` 已解码。

        枚举"几种固定转义写法"永远会漏掉这种组合，因此判据是
        "把待查文本解码后再匹配"。
        """
        mixed = (
            '<html><body><textarea name="msg">'
            '&lt;img src=x onerror="document.documentElement.setAttribute'
            "('data-hexhound-xss','1')\"&gt;</textarea></body></html>"
        )
        self.assertEqual(
            classify(payload=PAYLOAD, raw_body=mixed, rendered_html=mixed), "dom"
        )

    def test_url_encoded_payload_is_detected(self) -> None:

        encoded = quote(PAYLOAD, safe="")
        level = classify(
            payload=PAYLOAD,
            raw_body=f'<a href="?next={encoded}">x</a>',
            rendered_html=f'<a href="?next={encoded}">x</a>',
        )
        self.assertEqual(level, "dom")

    def test_absent_still_means_absent(self) -> None:
        """解码匹配不能变成"什么都能匹配"：真没出现还是要判 absent。"""
        level = classify(
            payload=PAYLOAD,
            raw_body="<h1>完全没有关系的内容</h1>",
            rendered_html="<h1>完全没有关系的内容</h1>",
        )
        self.assertEqual(level, "absent")

    def test_decoded_match_does_not_upgrade_to_executed(self) -> None:
        """判定"出现在了 DOM 里"**不得**提升成"执行了"。"""
        import html as html_module

        escaped = html_module.escape(PAYLOAD, quote=True)
        level = classify(
            payload=PAYLOAD, raw_body=escaped, rendered_html=escaped
        )
        self.assertNotEqual(level, "executed")


class ToolIntegrationTests(unittest.TestCase):
    """工具返回值必须带措辞约束，且不把低级别结论说成高级别。

    注意：Playwright 未安装时 `ToolRegistry` **不会下发** `browser_verify_xss`
    （见 `_drop_unavailable_browser_tools`），因此这里直接调用处理函数，
    绕开注册表的裁剪——这一层要验的是**提示文案本身**。
    """

    def make_registry(self, *, with_browser: bool = True):
        from hexhound.surface import AttackSurface
        from hexhound.tools import ToolRegistry

        return ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=ALLOWED,
            mode="blackbox",
            role="injection",
            surface=AttackSurface(target=LAB),
        )

    def invoke_handler(self, registry, args: dict) -> str:
        from hexhound.tools import _browser_verify_xss

        return _browser_verify_xss(registry, args)

    def test_tool_refuses_out_of_scope_url(self) -> None:
        registry = self.make_registry()
        text = self.invoke_handler(registry, {"url": "http://evil.example.com/x"})
        # 作用域校验先于一切：即便浏览器可用也不该打开它
        self.assertIn("拒绝", text)

    def test_tool_refuses_file_scheme(self) -> None:
        registry = self.make_registry()
        text = self.invoke_handler(registry, {"url": "file:///etc/passwd"})
        self.assertIn("拒绝", text)

    def test_tool_explains_when_playwright_is_missing(self) -> None:
        from unittest.mock import patch

        registry = self.make_registry()
        with patch(
            "hexhound.xssverify.playwright_available",
            return_value=(
                False,
                "未安装 Playwright：浏览器执行验证不可用。\n"
                "安装：pip install playwright && python -m playwright install chromium",
            ),
        ):
            text = self.invoke_handler(registry, {"url": f"{LAB}/reflect?name=x"})
        self.assertIn("不可用", text)
        self.assertIn("pip install", text)
        # 必须明确禁止把反射写成确认结论
        self.assertIn("不得", text)
        self.assertIn("确认的 XSS", text)

    def test_tool_requires_url(self) -> None:
        from unittest.mock import patch

        registry = self.make_registry()
        with patch(
            "hexhound.xssverify.playwright_available", return_value=(True, "")
        ):
            text = self.invoke_handler(registry, {})
        self.assertIn("需要 url", text)

    def test_tool_requires_param_for_post(self) -> None:
        """表单型验证必须给字段名：工具要直接说清缺什么，而不是给个空结论。"""
        from unittest.mock import patch

        registry = self.make_registry()
        with patch("hexhound.xssverify.playwright_available", return_value=(True, "")):
            text = self.invoke_handler(registry, {"url": f"{LAB}/form", "method": "POST"})
        self.assertIn("param", text)
        self.assertIn("fields", text)

    def test_tool_passes_method_and_fields_through(self) -> None:
        """工具层要把 method/fields 原样传给验证器（否则表单型永远只有 GET）。"""
        from unittest.mock import patch

        captured: dict = {}

        class FakeVerifier:
            def __init__(self, **kwargs) -> None:
                pass

            def verify_xss(self, url, *, payload="", param="", method="GET", fields=None):
                captured.update(
                    {"url": url, "param": param, "method": method, "fields": fields}
                )
                return XssVerdict(level="absent", payload=payload or "p", url=url)

        registry = self.make_registry()
        with (
            patch("hexhound.xssverify.playwright_available", return_value=(True, "")),
            patch("hexhound.xssverify.BrowserVerifier", FakeVerifier),
        ):
            self.invoke_handler(
                registry,
                {
                    "url": f"{LAB}/form",
                    "param": "name",
                    "method": "post",
                    "fields": {"csrf": "t0ken"},
                },
            )
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["param"], "name")
        self.assertEqual(captured["fields"], {"csrf": "t0ken"})


def _lab_available() -> bool:
    ready, _ = playwright_available()
    if not ready:
        return False
    try:
        import httpx

        response = httpx.get(f"{LAB}/", timeout=2.0, trust_env=False)
        return response.status_code == 200
    except Exception:  # noqa: BLE001 靶场没起就跳过真实浏览器层
        return False


@unittest.skipUnless(
    playwright_available()[0],
    "未安装 Playwright：跳过真实浏览器验证层",
)
class RealBrowserTests(unittest.TestCase):
    """**真实浏览器**验证：靶场里那组"都会回显、只有一个会执行"的对照组。

    这一层存在的意义就是证伪"反射 = XSS"：四个端点字符串级别一模一样，
    判据必须给出四种不同的结论。没有这一层，整个分级机制就只是推理。
    """

    channel: str | None = None

    @classmethod
    def setUpClass(cls) -> None:
        if not _lab_available():
            raise unittest.SkipTest(f"靶场未运行（{LAB}）：跳过真实浏览器验证层")
        # 浏览器频道必须**探测**而不是写死 `msedge`：写死的话，在 Linux 上
        # （只有 Playwright 自带的 chromium）会直接
        # `Chromium distribution 'msedge' is not found`，把整层测试挂在环境上。
        cls.channel = _pick_channel()

    def make_verifier(self) -> BrowserVerifier:
        return BrowserVerifier(allowed_hosts=ALLOWED, channel=self.channel or "", timeout_ms=15000)

    def test_html_context_executes(self) -> None:
        """`/reflect` 把 payload 放进 HTML 正文 → 应当判为 executed。"""
        verdict = self.make_verifier().verify_xss(
            f"{LAB}/reflect", param="name", baseline=False
        )
        self.assertEqual(verdict.level, "executed", verdict.statement())
        self.assertTrue(verdict.confirmed)
        self.assertTrue(verdict.execution_signals)

    def test_plain_text_context_does_not_execute(self) -> None:
        """`/reflect-text` 原样回显但 Content-Type 是 text/plain → 只是反射。"""
        verdict = self.make_verifier().verify_xss(
            f"{LAB}/reflect-text", param="name", baseline=False
        )
        self.assertNotEqual(verdict.level, "executed", verdict.statement())
        self.assertFalse(verdict.confirmed)

    def test_textarea_context_lands_in_dom_but_does_not_execute(self) -> None:
        """`/reflect-dom` payload 进了 DOM 的 textarea → dom（不是 executed）。"""
        verdict = self.make_verifier().verify_xss(
            f"{LAB}/reflect-dom", param="name", baseline=False
        )
        self.assertNotEqual(verdict.level, "executed", verdict.statement())
        self.assertFalse(verdict.confirmed)
        self.assertTrue(verdict.in_dom, "payload 应当出现在渲染后的 DOM 里")

    def test_csp_blocks_execution(self) -> None:
        """`/reflect-csp` 原样回显但 CSP 禁止内联脚本 → 不该判成 executed。"""
        verdict = self.make_verifier().verify_xss(
            f"{LAB}/reflect-csp", param="name", baseline=False
        )
        self.assertNotEqual(verdict.level, "executed", verdict.statement())
        self.assertFalse(verdict.confirmed)

    def test_four_endpoints_get_four_different_verdicts(self) -> None:
        """汇总判据：同一份 payload 在四个端点上必须给出**不同的**结论。"""
        verifier = self.make_verifier()
        levels = {}
        for path in ("/reflect", "/reflect-text", "/reflect-dom", "/reflect-csp"):
            levels[path] = verifier.verify_xss(
                f"{LAB}{path}", param="name", baseline=False
            ).level
        self.assertEqual(levels["/reflect"], "executed", levels)
        self.assertGreater(
            len(set(levels.values())), 1,
            f"四个端点不该得到同一个结论（那就说明判据没起作用）：{levels}",
        )

    def test_screenshot_is_captured_as_evidence(self) -> None:
        verdict = self.make_verifier().verify_xss(
            f"{LAB}/reflect", param="name", baseline=False
        )
        self.assertTrue(verdict.screenshot, "应当保存截图作为证据")
        self.assertTrue(verdict.screenshot.startswith(b"\x89PNG"))

    def test_console_and_network_are_recorded(self) -> None:
        verifier = self.make_verifier()
        observation = verifier.observe(f"{LAB}/reflect?name=hello")
        data = observation.to_dict()
        for key in ("console", "console_errors", "dialogs", "requests",
                    "navigation", "executed_flags", "cookies", "status"):
            self.assertIn(key, data)
        self.assertTrue(observation.requests, "应当记录网络请求")
        self.assertTrue(observation.raw_body, "应当记录原始响应体")

    def test_scope_refusal_on_out_of_scope_target(self) -> None:
        with self.assertRaises(ScopeRefused):
            self.make_verifier().observe("http://outside.example.com/")

    def test_in_scope_target_is_opened(self) -> None:
        """白名单内不该被前置校验挡住（对照上一条）。"""
        observation = self.make_verifier().observe(f"{LAB}/")
        self.assertEqual(observation.status, 200)


class MarkerCorrelationTests(unittest.TestCase):
    """执行标记必须归因到**本次**验证（P0-3 的判据层，不需要浏览器）。

    旧判据是"DON 上有没有这个属性/有没有弹窗"，与本 payload 无关的信号
    也能把结论推成 `executed`——那是确认级误报。
    """

    def test_marker_from_another_run_is_not_evidence(self) -> None:
        level = classify(
            payload=build_payloads("hhthisrun")[0],
            raw_body="",
            rendered_html="",
            executed_flags={MARKER_ATTRIBUTE: "hhpreviousrun"},
            marker_value="hhthisrun",
        )
        self.assertNotEqual(level, "executed", "上一次验证残留的标记不算本次执行")

    def test_matching_marker_is_evidence(self) -> None:
        level = classify(
            payload=build_payloads("hhthisrun")[0],
            raw_body="",
            rendered_html="",
            executed_flags={MARKER_ATTRIBUTE: "hhthisrun"},
            marker_value="hhthisrun",
        )
        self.assertEqual(level, "executed")

    def test_without_marker_the_legacy_truthy_flag_still_works(self) -> None:
        """纯判据调用（没给 nonce）保持原语义：真值即执行。"""
        level = classify(
            payload=PAYLOAD, raw_body="", rendered_html="",
            executed_flags={MARKER_ATTRIBUTE: True},
        )
        self.assertEqual(level, "executed")

    def test_payloads_carry_a_unique_marker_per_run(self) -> None:
        first, second = new_marker(), new_marker()
        self.assertNotEqual(first, second)
        self.assertIn(first, build_payloads(first)[0])
        # 对外稳定的默认载荷不受影响
        self.assertEqual(verification_payloads(), list(DEFAULT_PAYLOADS))


class DialogAttributionTests(unittest.TestCase):
    """普通弹窗不得被当成本次载荷的执行证据（P0-3 回归，打桩观测层）。

    实测场景：页面自己 `alert('请输入用户名')`，同时把参数回显进 `<textarea>`
    （根本不会执行）。旧判据看到"有 dialog"就给出 `executed` + `confirmed=True`，
    而且还会附上"对话框内容包含 payload"——因为那行代码查的是函数参数
    `payload`（默认空串），`"" in 任何文本` 恒真。
    """

    def verifier_with(self, builder) -> BrowserVerifier:
        """把 `observe` 换成给定页面的构造器（不起浏览器，判据逻辑照跑）。"""
        verifier = BrowserVerifier(allowed_hosts=ALLOWED)
        verifier.observe = (  # type: ignore[method-assign]
            lambda url, wait_ms=None, method="GET", post_data="": builder(url)
        )
        return verifier

    @staticmethod
    def injected(url: str) -> str:
        """取出被注入的载荷（`verify_xss` 会把它放进查询串）。"""
        return parse_qs(urlsplit(url).query).get("name", [""])[0]

    def test_unrelated_dialog_does_not_confirm_execution(self) -> None:
        def page(url: str) -> PageObservation:
            injected = self.injected(url)
            return PageObservation(
                url=url,
                status=200,
                raw_body=f"<textarea>{injected}</textarea>",
                rendered_html=f"<textarea>{injected}</textarea>",
                dialogs=["请输入用户名"],  # 页面自己的提示，与载荷无关
                executed_flags={},
            )

        verdict = self.verifier_with(page).verify_xss(
            "http://127.0.0.1:5000/reflect-dom", param="name", baseline=False
        )
        self.assertNotEqual(verdict.level, "executed", verdict.statement())
        self.assertFalse(verdict.confirmed)
        self.assertEqual(verdict.level, "dom")
        self.assertTrue(
            any("无关" in note for note in verdict.notes),
            f"应当说明该弹窗与载荷无关：{verdict.notes}",
        )

    def test_query_injection_replaces_all_original_values_and_preserves_fragment(self) -> None:
        visited: list[str] = []

        def page(url: str) -> PageObservation:
            visited.append(url)
            return PageObservation(url=url, status=200)

        self.verifier_with(page).verify_xss(
            "http://127.0.0.1/reflect?name=old&keep=&name=second#form",
            param="name", payload="new payload", baseline=False,
        )
        parsed = urlsplit(visited[0])
        self.assertEqual(parse_qs(parsed.query, keep_blank_values=True), {"name": ["new payload"], "keep": [""]})
        self.assertEqual(parsed.fragment, "form")

    def test_dialog_carrying_the_payload_is_evidence(self) -> None:
        """页面把注入的参数送进了 dialog（`alert(参数)`）→ 可归因，算执行证据。"""

        def page(url: str) -> PageObservation:
            injected = self.injected(url)
            return PageObservation(
                url=url,
                status=200,
                raw_body=f"<textarea>{injected}</textarea>",
                rendered_html=f"<textarea>{injected}</textarea>",
                dialogs=[injected],
                executed_flags={},
            )

        verdict = self.verifier_with(page).verify_xss(
            "http://127.0.0.1:5000/dialog", param="name", baseline=False
        )
        self.assertEqual(verdict.level, "executed", verdict.statement())
        self.assertTrue(verdict.confirmed)

    def test_baseline_dialog_is_subtracted(self) -> None:
        """基线页面本来就弹的对话框不能算在本次载荷头上。"""
        dialogs = ["欢迎回来"]

        def page(url: str) -> PageObservation:
            injected = self.injected(url)
            return PageObservation(
                url=url,
                status=200,
                raw_body=f"<textarea>{injected}</textarea>",
                rendered_html=f"<textarea>{injected}</textarea>",
                dialogs=list(dialogs),
                executed_flags={},
            )

        verdict = self.verifier_with(page).verify_xss(
            "http://127.0.0.1:5000/welcome", param="name", baseline=True
        )
        self.assertNotEqual(verdict.level, "executed", verdict.statement())

    def test_stale_marker_attribute_is_not_evidence(self) -> None:
        """DOM 上留着上一轮的标记属性 → 不构成本次执行证据。"""

        def page(url: str) -> PageObservation:
            injected = self.injected(url)
            return PageObservation(
                url=url,
                status=200,
                raw_body=f"<textarea>{injected}</textarea>",
                rendered_html=f"<textarea>{injected}</textarea>",
                executed_flags={MARKER_ATTRIBUTE: "hhfrompreviousrun"},
            )

        verdict = self.verifier_with(page).verify_xss(
            "http://127.0.0.1:5000/reflect-dom", param="name", baseline=False
        )
        self.assertNotEqual(verdict.level, "executed", verdict.statement())

    def test_marker_attribute_of_this_run_is_evidence(self) -> None:
        """本次 nonce 打在 DOM 上 → 执行证据（阳性对照，防止判据被修废）。

        模拟真实执行：注入的载荷确实跑了，于是 DOM 上出现了**本次** nonce。
        nonce 从注入的载荷里取出来（真实浏览器里就是载荷执行的结果）。
        """

        def page(url: str) -> PageObservation:
            injected = self.injected(url)
            found = re.search(r"data-hexhound-xss','(hh[0-9a-f]+)'", injected)
            value = found.group(1) if found else "missing"
            return PageObservation(
                url=url,
                status=200,
                raw_body=f"<div>{injected}</div>",
                rendered_html="<div>x</div>",  # 执行后原样载荷已不在 DOM 里
                executed_flags={MARKER_ATTRIBUTE: value},
            )

        verdict = self.verifier_with(page).verify_xss(
            "http://127.0.0.1:5000/reflect", param="name", baseline=False
        )
        self.assertEqual(verdict.level, "executed", verdict.statement())
        self.assertTrue(verdict.confirmed)
        self.assertTrue(
            any("data-hexhound-xss" in signal for signal in verdict.execution_signals),
            verdict.execution_signals,
        )


def _skip_or_fail(reason: str) -> None:
    """缺少浏览器时：本地跳过，CI（`HEXHOUND_REQUIRE_GUI=1`）**失败**。

    与 `tests/test_gui_frontend.py` 同一个开关：CI 里必须让"没装浏览器"
    变成红灯，否则整层真实浏览器验证可以静默消失。
    """
    if os.environ.get("HEXHOUND_REQUIRE_GUI", "").strip():
        raise AssertionError(f"浏览器依赖缺失，但本环境要求必须运行：{reason}")
    raise unittest.SkipTest(reason)


def _pick_channel() -> str:
    """挑一个**真的能启动**的浏览器频道。

    为什么不能写死：Windows 开发机上通常只有系统 Edge（`msedge`），
    Linux/CI 上只有 Playwright 自带的 chromium——写死任一个，
    另一侧的整层测试就会挂在环境上而不是被测代码上。
    返回 `""` 表示用自带的 chromium。
    """
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        for candidate in ("", "msedge", "chrome"):
            try:
                kwargs: dict[str, Any] = {"headless": True}
                if candidate:
                    kwargs["channel"] = candidate
                playwright.chromium.launch(**kwargs).close()
                return candidate
            except Exception:  # noqa: BLE001 这个候选不可用，换下一个
                continue
    _skip_or_fail("没有可用的浏览器（chromium / msedge / chrome）")
    return ""  # 不可达：_skip_or_fail 一定抛出


class _LocalPageLab:
    """临时本地测试页（随机端口，只跑在本机），用于真实浏览器回归。"""

    @classmethod
    def start(cls) -> tuple[Any, str]:
        from flask import Flask, redirect, request
        from werkzeug.serving import make_server

        app = Flask("hexhound-xss-regression")
        received: list[dict[str, Any]] = []

        @app.route("/auth-echo", methods=["GET", "POST"])
        def auth_echo():
            if request.headers.get("Authorization") != "Bearer local-test" or request.cookies.get("session") != "local-test":
                return "authentication required", 401
            fields = request.form if request.method == "POST" else request.args
            return "<html><body><div>" + fields.get("name", "") + "</div></body></html>"

        @app.route("/storage")
        def storage():
            return (
                "<html><body><script>"
                "if (localStorage.getItem('local-auth') === 'local-test' && "
                "sessionStorage.getItem('session-auth') === 'local-test') "
                "document.body.setAttribute('data-auth-ready', 'yes');"
                "</script></body></html>"
            )

        @app.route("/redirect-localhost")
        def redirect_localhost():
            return redirect(request.host_url.replace("127.0.0.1", "localhost") + "receiver")

        @app.route("/redirect-other-port")
        def redirect_other_port():
            return redirect("http://127.0.0.1:" + request.args["port"] + "/receiver")

        @app.route("/receiver")
        def receiver():
            received.append({"authorized": bool(request.headers.get("Authorization")), "cookie": bool(request.cookies.get("session"))})
            return "receiver"

        @app.route("/dialog-textarea")
        def dialog_textarea():
            """页面自己弹一个无关对话框 + payload 落在 textarea（不执行）。"""
            name = request.args.get("name", "")
            return (
                "<html><body><script>alert('请输入用户名');</script>"
                f"<textarea>{name}</textarea></body></html>"
            )

        @app.route("/dialog-exec")
        def dialog_exec():
            """同样弹无关对话框，但 payload 落在可执行上下文（阳性对照）。"""
            name = request.args.get("name", "")
            return (
                "<html><body><script>alert('请输入用户名');</script>"
                f"<div>{name}</div></body></html>"
            )

        @app.route("/form-echo", methods=["POST"])
        def form_echo():
            """表单型注入点：把 POST 字段回显进 HTML 正文（可执行上下文）。"""
            name = request.form.get("name", "")
            extra = request.form.get("extra", "")
            return (
                "<html><body><form method=post><input name=name></form>"
                f"<div>你好 {name}</div><span>{extra}</span></body></html>"
            )

        @app.route("/form-textarea", methods=["POST"])
        def form_textarea():
            """表单回显进 textarea（进了 DOM 但不执行）→ 只能判 dom。"""
            name = request.form.get("name", "")
            return (
                "<html><body>"
                f"<textarea>{name}</textarea></body></html>"
            )

        @app.route("/form-get-only", methods=["GET"])
        def form_get_only():
            """只接受 GET：POST 到它会得到 405，用来证明"POST 确实发出去了"。"""
            return "<html><body>GET only</body></html>", 200

        server = make_server("127.0.0.1", 0, app, threaded=True)
        server.test_received = received
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, f"http://127.0.0.1:{server.server_port}"


class DialogFalsePositiveBrowserTests(unittest.TestCase):
    """真实浏览器层：普通弹窗不得导致确认级 XSS 误报（P0-3 端到端回归）。

    只访问本机临时测试页——不碰靶场、不碰任何真实目标。
    """

    server: Any = None
    base = ""
    #: None = 还没探测；"" = 用打包的 chromium；"msedge"/"chrome" = 系统浏览器
    channel: str | None = None

    @classmethod
    def setUpClass(cls) -> None:
        ready, reason = playwright_available()
        if not ready:
            _skip_or_fail(reason)
        cls.channel = _pick_channel()
        cls.server, cls.base = _LocalPageLab.start()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.server is not None:
            cls.server.shutdown()

    def verifier(self) -> BrowserVerifier:
        return BrowserVerifier(
            allowed_hosts=frozenset({"127.0.0.1", "localhost"}),
            channel=self.channel,
            timeout_ms=15000,
        )

    def test_unrelated_dialog_plus_textarea_is_not_confirmed_xss(self) -> None:
        verdict = self.verifier().verify_xss(
            f"{self.base}/dialog-textarea", param="name", baseline=False
        )
        self.assertNotEqual(
            verdict.level,
            "executed",
            f"普通弹窗不得当成本次载荷执行：{verdict.statement()}",
        )
        self.assertFalse(verdict.confirmed)
        self.assertTrue(verdict.in_dom, "payload 应当在渲染后的 DOM 里")

    def test_real_execution_is_still_detected(self) -> None:
        """修好假阳之后，真执行必须仍然判得出来（否则就是把判据修废了）。"""
        verdict = self.verifier().verify_xss(
            f"{self.base}/dialog-exec", param="name", baseline=False
        )
        self.assertEqual(verdict.level, "executed", verdict.statement())
        self.assertTrue(verdict.confirmed)
        self.assertTrue(verdict.execution_signals)


class PostFormXssBrowserTests(unittest.TestCase):
    """表单型（POST）注入的真实浏览器回归。

    此前浏览器验证只覆盖 GET 查询串——表单型 XSS 完全没测过，
    而真实漏洞里 POST 表单是常见形态。
    """

    server: Any = None
    base = ""
    channel: str | None = None

    @classmethod
    def setUpClass(cls) -> None:
        ready, reason = playwright_available()
        if not ready:
            _skip_or_fail(reason)
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            for candidate in ("", "msedge", "chrome"):
                try:
                    kwargs: dict[str, Any] = {"headless": True}
                    if candidate:
                        kwargs["channel"] = candidate
                    playwright.chromium.launch(**kwargs).close()
                    cls.channel = candidate
                    break
                except Exception:  # noqa: BLE001
                    continue
        if cls.channel is None:
            _skip_or_fail("没有可用的浏览器（chromium / msedge / chrome）")
        cls.server, cls.base = _LocalPageLab.start()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.server is not None:
            cls.server.shutdown()

    def verifier(self) -> BrowserVerifier:
        return BrowserVerifier(
            allowed_hosts=frozenset({"127.0.0.1", "localhost"}),
            channel=self.channel,
            timeout_ms=15000,
        )

    def test_post_form_reflection_executes(self) -> None:
        """表单字段回显进 HTML 正文 → executed（POST 注入真的送到了服务端）。"""
        verdict = self.verifier().verify_xss(
            f"{self.base}/form-echo", param="name", method="POST", baseline=False
        )
        self.assertEqual(verdict.level, "executed", verdict.statement())
        self.assertTrue(verdict.confirmed)

    def test_post_from_get_only_endpoint_is_not_executed(self) -> None:
        """只接受 GET 的端点收到 POST 会 405 → 不能判成 executed（证明是真 POST）。"""
        verdict = self.verifier().verify_xss(
            f"{self.base}/form-get-only", param="name", method="POST", baseline=False
        )
        self.assertNotEqual(verdict.level, "executed", verdict.statement())
        self.assertEqual(verdict.observation.get("status"), 405)

    def test_post_into_textarea_is_dom_not_executed(self) -> None:
        verdict = self.verifier().verify_xss(
            f"{self.base}/form-textarea", param="name", method="POST", baseline=False
        )
        self.assertNotEqual(verdict.level, "executed", verdict.statement())
        self.assertTrue(verdict.in_dom, "payload 应当进了 DOM")

    def test_extra_form_fields_are_submitted(self) -> None:
        """其它表单字段要一起提交（真实表单几乎都需要 csrf/用户名等字段）。

        直接在 `observe()` 层断言：`verify_xss` 返回的观测是**摘要**（不含响应体），
        而这里要看的就是服务端到底收到了哪些字段。
        """
        observation = self.verifier().observe(
            f"{self.base}/form-echo",
            method="POST",
            post_data="name=hello&extra=EXTRA-FIELD-VALUE",
        )
        self.assertIn("EXTRA-FIELD-VALUE", observation.rendered_html)
        self.assertIn("hello", observation.rendered_html)

    def test_verify_xss_accepts_fields_and_reports_executed(self) -> None:
        verdict = self.verifier().verify_xss(
            f"{self.base}/form-echo",
            param="name",
            method="POST",
            fields={"extra": "EXTRA-FIELD-VALUE"},
            baseline=False,
        )
        self.assertEqual(verdict.level, "executed", verdict.statement())

    def test_baseline_post_works_without_payload(self) -> None:
        """带基线（默认）也要能跑通 POST 路径。"""
        verdict = self.verifier().verify_xss(f"{self.base}/form-echo", param="name", method="POST")
        self.assertEqual(verdict.level, "executed", verdict.statement())

    def test_post_requires_param(self) -> None:
        """没有字段名的 POST 测不到注入点 → 明确报错，而不是给个假的 absent。"""
        with self.assertRaises(ValueError) as ctx:
            self.verifier().verify_xss(f"{self.base}/form-echo", method="POST")
        self.assertIn("param", str(ctx.exception))


class BrowserAuthenticationTests(unittest.TestCase):
    """登录态回归仅使用本机临时页面和测试凭据。"""

    @classmethod
    def setUpClass(cls) -> None:
        ready, reason = playwright_available()
        if not ready:
            _skip_or_fail(reason)
        cls.channel = _pick_channel()
        cls.server, cls.base = _LocalPageLab.start()
        cls.other_server, cls.other_base = _LocalPageLab.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.other_server.shutdown()

    def setUp(self) -> None:
        self.server.test_received.clear()
        self.other_server.test_received.clear()

    def verifier(self, **kwargs: Any) -> BrowserVerifier:
        return BrowserVerifier(
            allowed_hosts=ALLOWED, channel=self.channel, timeout_ms=3000, wait_ms=50,
            auth_headers={"Authorization": "Bearer local-test", "Cookie": "session=local-test"},
            **kwargs,
        )

    def test_authenticated_get_and_post_xss_preserve_account_and_nonce(self) -> None:
        for method in ("GET", "POST"):
            with self.subTest(method=method):
                verdict = self.verifier().verify_xss(
                    self.base + "/auth-echo?name=old", param="name", method=method,
                )
                self.assertEqual(verdict.observation["status"], 200)
                self.assertTrue(verdict.confirmed, verdict.statement())

    def test_browser_imports_only_target_origin_storage(self) -> None:
        observation = self.verifier(
            storage_state={"cookies": [], "origins": [
                {"origin": self.base, "localStorage": [{"name": "local-auth", "value": "local-test"}]},
                {"origin": self.other_base, "localStorage": [{"name": "foreign", "value": "excluded"}]},
            ]},
            session_storage={"session-auth": "local-test"},
        ).observe(self.base + "/storage")
        self.assertIn('data-auth-ready="yes"', observation.rendered_html)

    def test_auth_headers_and_cookies_are_not_sent_to_another_allowed_host(self) -> None:
        self.verifier().observe(self.base + "/redirect-localhost")
        self.assertEqual(self.server.test_received, [{"authorized": False, "cookie": False}])

    def test_cookie_auth_does_not_cross_ports_on_the_same_host(self) -> None:
        self.verifier().observe(
            self.base + "/redirect-other-port?port=" + str(self.other_server.server_port)
        )
        self.assertEqual(self.other_server.test_received, [])

    def test_out_of_scope_redirect_is_blocked_before_request(self) -> None:
        verifier = self.verifier()
        verifier.allowed_hosts = frozenset({"127.0.0.1"})
        try:
            verifier.observe(self.base + "/redirect-localhost")
        except ScopeRefused:
            pass
        self.assertEqual(self.server.test_received, [])

    def test_dynamic_scan_uses_the_same_authenticated_context(self) -> None:
        from unittest.mock import patch

        from hexhound.browser import dynamic_scan

        with patch.dict(os.environ, {"HEXHOUND_BROWSER_CHANNEL": self.channel}):
            result = dynamic_scan(
                self.base + "/auth-echo?name=authenticated", wait_ms=0,
                allowed_hosts=ALLOWED,
                auth_headers={"Authorization": "Bearer local-test", "Cookie": "session=local-test"},
            )
        self.assertIn("authenticated", result["html"])


class RedirectPolicyTests(unittest.TestCase):
    """重定向策略（纯函数，不需要浏览器即可验证）。

    为什么单独测：浏览器跟随重定向时**不会再经过路由拦截器**（Round4 实测：
    route 回调只被调用一次），所以"越界目标收到请求"和"cookie 被交给同一主机的
    另一个端口"这两件事只能靠**在响应里摘掉 Location** 来阻止。
    """

    def allowed(self, request_url: str, location: str, hosts=None, target_host="127.0.0.1"):
        from hexhound.browser import _redirect_target_allowed

        return _redirect_target_allowed(
            request_url, location,
            allowed_hosts=frozenset(hosts or {"127.0.0.1", "localhost"}), target_host=target_host,
        )

    def test_out_of_scope_redirect_is_refused(self) -> None:
        ok, reason = self.allowed("http://127.0.0.1:1/a", "https://evil.example.com/b")
        self.assertFalse(ok)
        self.assertIn("授权范围外", reason)

    def test_same_host_other_port_is_refused(self) -> None:
        """cookie 按主机发送：跟随它等于把登录态交给该主机的另一个端口。"""
        ok, reason = self.allowed("http://127.0.0.1:1/a", "http://127.0.0.1:2/b")
        self.assertFalse(ok)
        self.assertIn("另一个源", reason)

    def test_non_http_scheme_is_refused(self) -> None:
        for location in ("file:///etc/passwd", "javascript:alert(1)", "data:text/html,x"):
            with self.subTest(location=location):
                ok, _ = self.allowed("http://127.0.0.1:1/a", location)
                self.assertFalse(ok)

    def test_other_allowed_host_and_same_origin_are_followed(self) -> None:
        ok, reason = self.allowed("http://127.0.0.1:1/a", "http://localhost:1/b")
        self.assertTrue(ok, reason)
        ok, reason = self.allowed("http://127.0.0.1:1/a", "/b")
        self.assertTrue(ok, reason)
        ok, reason = self.allowed("http://127.0.0.1:1/a", "")
        self.assertTrue(ok, reason)


if __name__ == "__main__":
    unittest.main()
