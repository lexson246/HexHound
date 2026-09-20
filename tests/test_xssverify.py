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
import sys
import unittest
from pathlib import Path
from urllib.parse import quote

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.xssverify import (  # noqa: E402
    CONFIRMED_LEVEL,
    DEFAULT_PAYLOADS,
    EXECUTION_FLAG,
    MARKER_ATTRIBUTE,
    BrowserUnavailable,
    BrowserVerifier,
    ScopeRefused,
    XssVerdict,
    _validate_browser_url,
    classify,
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
        from urllib.parse import quote

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

    @classmethod
    def setUpClass(cls) -> None:
        if not _lab_available():
            raise unittest.SkipTest(f"靶场未运行（{LAB}）：跳过真实浏览器验证层")

    def make_verifier(self) -> BrowserVerifier:
        return BrowserVerifier(allowed_hosts=ALLOWED, channel="msedge", timeout_ms=15000)

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


if __name__ == "__main__":
    unittest.main()
