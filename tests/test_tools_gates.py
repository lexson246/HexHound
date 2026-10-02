"""工具层单元测试：角色工具边界、复核门、证据编号校验、输出治理、CVSS。

全部离线运行（不发真实请求）：只测"闸门"逻辑，实际检测能力由
`examples/tool_selftest.py` 对着靶场跑。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.budget import Budget  # noqa: E402
from hexhound.surface import AttackSurface  # noqa: E402
from hexhound.tools import (  # noqa: E402
    GOVERNOR_ARG_LIMIT,
    GOVERNOR_SMALL_LIMIT,
    ROLE_TOOLS,
    ToolRegistry,
    _cvss_score,
    _govern,
    _truncate_args,
)


def make_registry(role: str = "verify", budget: Budget | None = None) -> ToolRegistry:
    return ToolRegistry(
        base_dir=Path("."),
        allowed_hosts=frozenset({"127.0.0.1"}),
        timeout=5,
        mode="blackbox",
        surface=AttackSurface(target="http://127.0.0.1:5000", mode="blackbox"),
        budget=budget or Budget(),
        role=role,
        worker_id="W9",
    )


class RoleBoundaryTests(unittest.TestCase):
    def test_recon_cannot_record_findings(self) -> None:
        """侦察角色没有 record_finding/record_coverage——防止"侦察者下结论"。"""
        names = make_registry("recon").tool_names()
        self.assertIn("crawl", names)
        self.assertNotIn("record_finding", names)
        self.assertNotIn("fuzz_params", names)

    def test_injection_cannot_declare_verified_without_tools(self) -> None:
        names = make_registry("injection").tool_names()
        self.assertIn("fuzz_params", names)
        self.assertIn("record_finding", names)
        self.assertNotIn("check_default_creds", names)

    def test_verify_has_review_but_no_new_attack_surface(self) -> None:
        names = make_registry("verify").tool_names()
        self.assertIn("review_candidates", names)
        self.assertNotIn("fuzz_params", names)
        self.assertNotIn("enumerate_common", names)

    def test_every_role_can_finish(self) -> None:
        for role in ROLE_TOOLS:
            self.assertIn("finish_task", make_registry(role).tool_names(), role)

    def test_unknown_tool_reports_available(self) -> None:
        result = make_registry("recon").execute("record_finding", {"title": "x"})
        self.assertIn("未知工具", result)
        self.assertIn("可用工具", result)


class VerificationGateTests(unittest.TestCase):
    def base_args(self) -> dict:
        return {
            "title": "SQL 注入",
            "severity": "high",
            "confidence": "medium",
            "evidence": "单引号触发报错",
            "description": "username 拼接进 SQL",
            "remediation": "参数化查询",
            "vuln_type": "SQL注入",
            "url": "http://127.0.0.1:5000/login",
        }

    def test_unverified_goes_to_candidate_pool(self) -> None:
        registry = make_registry()
        result = registry.execute("record_finding", self.base_args())
        self.assertIn("候选", result)
        self.assertEqual(len(registry.surface.pending_candidates()), 1)
        self.assertEqual(registry.surface.verified_findings(), [])

    def test_verified_without_evidence_is_downgraded(self) -> None:
        registry = make_registry()
        args = self.base_args() | {"verified": True, "verification": "重放确认"}
        result = registry.execute("record_finding", args)
        self.assertIn("降级", result)
        self.assertEqual(registry.surface.verified_findings(), [])

    def test_verified_without_verification_note_is_downgraded(self) -> None:
        registry = make_registry()
        registry.http_log.append({"id": "W9-R1", "url": "http://127.0.0.1:5000/login",
                                  "method": "POST", "request_headers": {}, "request_body": "",
                                  "status_code": 500, "reason": "", "response_headers": {},
                                  "response_body": ""})
        args = self.base_args() | {"verified": True, "evidence_ref": ["W9-R1"]}
        result = registry.execute("record_finding", args)
        self.assertIn("verification", result)
        self.assertEqual(registry.surface.verified_findings(), [])

    def test_unknown_evidence_ref_is_rejected(self) -> None:
        registry = make_registry()
        args = self.base_args() | {
            "verified": True,
            "verification": "重放",
            "evidence_ref": ["W9-R999"],
        }
        result = registry.execute("record_finding", args)
        self.assertIn("不存在", result)
        self.assertIn("拒绝", result)
        self.assertEqual(registry.surface.finding_dicts(), [])

    def test_high_confidence_requires_rationale(self) -> None:
        registry = make_registry()
        registry.http_log.append({"id": "W9-R1", "url": "http://127.0.0.1:5000/login",
                                  "method": "POST", "request_headers": {}, "request_body": "",
                                  "status_code": 500, "reason": "", "response_headers": {},
                                  "response_body": ""})
        args = self.base_args() | {
            "confidence": "high",
            "verified": True,
            "verification": "重放 [W9-R1] 复现",
            "evidence_ref": ["W9-R1"],
        }
        result = registry.execute("record_finding", args)
        self.assertIn("medium", result)
        self.assertEqual(registry.surface.verified_findings()[0].confidence, "medium")

    def test_verified_with_evidence_is_recorded(self) -> None:
        registry = make_registry()
        registry.http_log.append({"id": "W9-R1", "url": "http://127.0.0.1:5000/login",
                                  "method": "POST", "request_headers": {}, "request_body": "",
                                  "status_code": 500, "reason": "", "response_headers": {},
                                  "response_body": ""})
        args = self.base_args() | {
            "verified": True,
            "verification": "重放 [W9-R1] 得到 SQL 报错",
            "evidence_ref": ["W9-R1"],
            "confidence_rationale": "报错内容与注入直接相关",
            "counterevidence": "未确认是否可由未授权用户触达",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
        result = registry.execute("record_finding", args)
        self.assertIn("已记录并复核", result)
        findings = registry.surface.verified_findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "verified")
        self.assertEqual(findings[0].extra["cvss_vector"].startswith("CVSS:3.1"), True)
        self.assertEqual(findings[0].extra["cvss"], "9.8")
        self.assertTrue(findings[0].dedupe_key)

    def test_duplicate_report_is_merged(self) -> None:
        registry = make_registry()
        registry.http_log.append({"id": "W9-R1", "url": "http://127.0.0.1:5000/login",
                                  "method": "POST", "request_headers": {}, "request_body": "",
                                  "status_code": 500, "reason": "", "response_headers": {},
                                  "response_body": ""})
        args = self.base_args() | {
            "verified": True,
            "verification": "v",
            "evidence_ref": ["W9-R1"],
            "url": "http://127.0.0.1:5000/login?username=a",
        }
        registry.execute("record_finding", args)
        again = dict(args)
        again["url"] = "http://127.0.0.1:5000/login?username=b"
        result = registry.execute("record_finding", again)
        # 已复核的同指纹上报会被合并（提示语可能是"合并"或"累计上报 N 次"）
        self.assertTrue("累计上报" in result or "合并" in result, result)
        self.assertEqual(len(registry.surface.verified_findings()), 1)

    def test_param_argument_matches_url_query(self) -> None:
        """显式 param 与 URL query 推出同一参数时，指纹必须一致（否则去重失效）。"""
        registry = make_registry()
        registry.http_log.append({"id": "W9-R1", "url": "http://127.0.0.1:5000/api/user",
                                  "method": "GET", "request_headers": {}, "request_body": "",
                                  "status_code": 200, "reason": "", "response_headers": {},
                                  "response_body": ""})
        registry.execute("record_finding", self.base_args() | {
            "url": "http://127.0.0.1:5000/api/user", "param": "uid",
            "vuln_type": "IDOR越权", "verified": True,
            "verification": "重放确认", "evidence_ref": ["W9-R1"],
        })
        result = registry.execute("record_finding", self.base_args() | {
            "url": "http://127.0.0.1:5000/api/user?uid=3",
            "vuln_type": "IDOR越权", "verified": True,
            "verification": "重放确认", "evidence_ref": ["W9-R1"],
        })
        self.assertTrue("累计上报" in result or "合并" in result, result)
        self.assertEqual(len(registry.surface.verified_findings()), 1)

    def test_missing_required_fields_rejected(self) -> None:
        registry = make_registry()
        result = registry.execute("record_finding", {"title": "x"})
        self.assertIn("缺少必填字段", result)

    def test_bad_severity_rejected(self) -> None:
        registry = make_registry()
        result = registry.execute("record_finding", self.base_args() | {"severity": "urgent"})
        self.assertIn("severity", result)


class CoverageAndNoteTests(unittest.TestCase):
    def test_record_coverage_validates_status(self) -> None:
        registry = make_registry("recon")
        bad = registry.execute("record_coverage", {"target": "/login", "status": "maybe"})
        self.assertIn("status 必须是", bad)
        good = registry.execute(
            "record_coverage", {"target": "/login", "status": "ruled_out", "detail": "403"}
        )
        self.assertIn("已记录覆盖", good)
        self.assertEqual(registry.surface.coverage_summary()["ruled_out"], 1)

    def test_leave_note_and_think_are_shared(self) -> None:
        registry = make_registry("recon")
        registry.execute("leave_note", {"text": "/api/user 不校验归属"})
        registry.execute("think", {"thought": "先验证越权再验证注入"})
        notes = registry.surface.note_lines()
        self.assertTrue(any("不校验归属" in line for line in notes))
        self.assertTrue(any("先验证越权" in line for line in notes))

    def test_task_list_flow(self) -> None:
        registry = make_registry("recon")
        self.assertIn("已建立任务清单", registry.execute("task_create", {"items": ["a", "b"]}))
        self.assertIn("T1", registry.execute("task_update", {"id": "T1", "status": "done"}))
        listing = registry.execute("task_list", {})
        # 输出用纯 ASCII 标记（中文 Windows 控制台默认 GBK，符号会崩）
        self.assertIn("[x] T1", listing)
        self.assertIn("未完成 1 项", listing)
        self.assertIn("没有任务", registry.execute("task_update", {"id": "T9", "status": "done"}))


class EndpointHarvestTests(unittest.TestCase):
    """读取即登记：从 JS/HTML 抽出的路径必须进攻击面。

    实测动机：侦察读了 `/static/app.js`（里面有 `fetch("/coupon")`），摘要里也写了
    `/coupon`，但攻面里始终没有——而"按攻面特征派发竞态/伪造任务"正是以攻面为输入，
    于是那两类任务一次都没派出去。所以把这件事从 discover_endpoints 抽出来，
    让 read_urls 这类**模型真的会调**的工具顺手完成。
    """

    class _Ctx:
        def __init__(self) -> None:
            self.surface = AttackSurface(target="http://t.example")

    def test_extracts_business_paths_from_js(self) -> None:
        from hexhound.tools import _harvest_endpoints

        ctx = self._Ctx()
        js = (
            'var BASE="/api";\n'
            'fetch("/coupon", {method:"POST"});\n'
            'fetch("/wallet").then(r=>r.json());\n'
            'fetch("/api/reset_token");\n'
            'var img = "/static/logo.png";\n'
            'var x = "/assets/app.js";\n'
        )
        found = _harvest_endpoints(
            ctx, js, base_url="http://t.example/static/app.js", host="t.example", source="read_urls"
        )
        self.assertIn("/coupon", found)
        self.assertIn("/wallet", found)
        self.assertIn("/api/reset_token", found)
        # 静态资源与噪音目录不算接口
        self.assertNotIn("/static/logo.png", found)
        self.assertNotIn("/assets/app.js", found)
        # 登记进攻击面（覆盖率与特殊任务都靠它）
        self.assertIn("http://t.example/coupon", ctx.surface.endpoints)

    def test_ignores_foreign_hosts(self) -> None:
        from hexhound.tools import _harvest_endpoints

        ctx = self._Ctx()
        found = _harvest_endpoints(
            ctx,
            'fetch("https://evil.com/steal"); fetch("http://t.example/ok");',
            base_url="http://t.example/",
            host="t.example",
            source="read_urls",
        )
        self.assertIn("http://t.example/ok", found)
        self.assertNotIn("https://evil.com/steal", found)
        self.assertFalse([url for url in ctx.surface.endpoints if "evil.com" in url])

    def test_empty_and_noise_only_text_returns_nothing(self) -> None:
        from hexhound.tools import _harvest_endpoints

        ctx = self._Ctx()
        self.assertEqual(
            _harvest_endpoints(ctx, "", base_url="http://t.example/", host="t.example", source="x"),
            [],
        )
        self.assertEqual(
            _harvest_endpoints(
                ctx, 'fetch("/static"); fetch("/api");', base_url="http://t.example/",
                host="t.example", source="x",
            ),
            [],
        )


class GovernorTests(unittest.TestCase):
    def test_small_output_passes_through(self) -> None:
        text, structured = _govern("crawl", "小输出")
        self.assertEqual(text, "小输出")
        self.assertEqual(structured["llm"], "小输出")

    def test_large_output_is_compressed_with_head_and_tail(self) -> None:
        payload = "A" * GOVERNOR_SMALL_LIMIT + "MIDDLE" * 5000 + "Z" * 100
        text, _ = _govern("http_request", payload)
        self.assertIn("[输出治理]", text)
        self.assertIn("省略", text)
        self.assertLess(len(text), len(payload))

    def test_structured_result_keeps_full_data(self) -> None:
        result = {"llm": "短", "secrets": ["AKIA..."]}
        text, structured = _govern("read_urls", result)
        self.assertEqual(text, "短")
        self.assertEqual(structured["secrets"], ["AKIA..."])

    def test_long_argument_is_truncated(self) -> None:
        cleaned = _truncate_args({"body": "x" * (GOVERNOR_ARG_LIMIT + 500)})
        self.assertLess(len(cleaned["body"]), GOVERNOR_ARG_LIMIT + 80)
        self.assertIn("参数过长已截断", cleaned["body"])

    def test_long_list_is_truncated(self) -> None:
        cleaned = _truncate_args({"urls": [f"http://h/{index}" for index in range(80)]})
        self.assertEqual(len(cleaned["urls"]), 51)


class CvssTests(unittest.TestCase):
    def test_critical_vector(self) -> None:
        self.assertEqual(_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)

    def test_scope_changed_vector(self) -> None:
        score = _cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
        self.assertIsNotNone(score)
        self.assertGreater(score, 4.0)

    def test_low_severity_vector(self) -> None:
        self.assertEqual(_cvss_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"), 1.8)

    def test_invalid_vector_returns_none(self) -> None:
        self.assertIsNone(_cvss_score("not-a-vector"))
        self.assertIsNone(_cvss_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))


class SharedSessionCaptureTests(unittest.TestCase):
    """会话必须在子代理之间共享。

    实测现场（这是"业务逻辑测不出来"的根因）：一次运行里 `T3(auth)` 用 SQLi
    绕过了 `/login` 并拿到 `Set-Cookie`，而同一轮 `B1(injection)` 要测 `/cart`
    却一直 401——它自己试了常见口令 / SQL 绕过 / actuator 泄露的口令 /
    `/api/jwt_login` 全都不通，最后把业务逻辑四项如实记成 `blocked`。
    **同一个进程里，一个子代理已经拿到的会话，另一个子代理完全不知道。**
    """

    def make_registry(self, *, profiles=None, role: str = "injection", worker: str = "W1"):
        return ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1"}),
            mode="blackbox",
            role=role,
            worker_id=worker,
            surface=AttackSurface(target="http://127.0.0.1:5000"),
            auth_profiles=profiles if profiles is not None else {},
        )

    def _fake_response(self, *, cookies=(), body="{}"):
        import httpx

        request = httpx.Request("POST", "http://127.0.0.1:5000/login")
        return httpx.Response(
            200, headers=[("set-cookie", c) for c in cookies], text=body, request=request
        )

    def test_set_cookie_is_registered_as_account_c(self) -> None:
        from hexhound.tools import _capture_session

        registry = self.make_registry()
        note = _capture_session(
            registry,
            "http://127.0.0.1:5000/login",
            self._fake_response(cookies=["hh_session=alice:tok-alice-demo; Path=/; HttpOnly"]),
        )
        self.assertIn("账号 C", note)
        cookie = registry.auth_profiles["C"]["Cookie"]
        self.assertIn("hh_session=alice:tok-alice-demo", cookie)
        # cookie 的 Path/HttpOnly 属性不该进请求头
        self.assertNotIn("HttpOnly", cookie)

    def test_token_in_body_is_registered(self) -> None:
        from hexhound.tools import _capture_session

        registry = self.make_registry()
        _capture_session(
            registry,
            "http://127.0.0.1:5000/api/jwt_login",
            self._fake_response(body='{"code":0,"token":"eyJhbGciOiJIUzI1NiJ9.abc.def"}'),
        )
        self.assertIn("Bearer eyJhbGci", registry.auth_profiles["C"]["Authorization"])

    def test_response_without_session_registers_nothing(self) -> None:
        from hexhound.tools import _capture_session

        registry = self.make_registry()
        note = _capture_session(
            registry, "http://127.0.0.1:5000/", self._fake_response(body="<h1>hi</h1>")
        )
        self.assertEqual(note, "")
        self.assertNotIn("C", registry.auth_profiles)

    def test_existing_profiles_are_not_clobbered(self) -> None:
        """账号 A/B 是模型显式设置的身份，不能被自动登记覆盖。"""
        from hexhound.tools import _capture_session

        registry = self.make_registry(profiles={"A": {"Cookie": "a=1"}, "B": {"Cookie": "b=2"}})
        _capture_session(
            registry,
            "http://127.0.0.1:5000/login",
            self._fake_response(cookies=["hh_session=x:tok-x-demo"]),
        )
        self.assertEqual(registry.auth_profiles["A"], {"Cookie": "a=1"})
        self.assertEqual(registry.auth_profiles["B"], {"Cookie": "b=2"})
        self.assertIn("C", registry.auth_profiles)

    def test_capture_is_recorded_once_per_url(self) -> None:
        from hexhound.tools import _capture_session

        registry = self.make_registry()
        for _ in range(3):
            _capture_session(
                registry,
                "http://127.0.0.1:5000/login",
                self._fake_response(cookies=["hh_session=x:tok-x-demo"]),
            )
        self.assertEqual(len(registry.session_notes), 1)

    def test_profiles_are_shared_between_workers(self) -> None:
        """编排器把同一个 auth_profiles 字典注入每个子代理 → 一处登记处处可见。"""
        from hexhound.tools import _capture_session

        shared: dict = {}
        auth_worker = self.make_registry(profiles=shared, role="auth", worker="W1")
        _capture_session(
            auth_worker,
            "http://127.0.0.1:5000/login",
            self._fake_response(cookies=["hh_session=alice:tok-alice-demo"]),
        )
        injection_worker = self.make_registry(profiles=shared, role="injection", worker="W2")
        self.assertIn(
            "hh_session=alice:tok-alice-demo",
            injection_worker.auth_profiles["C"]["Cookie"],
            "另一子代理必须能看到已登记的会话",
        )

    def test_injection_role_can_switch_accounts(self) -> None:
        """回归：`use_account` 曾经**不在 injection 角色的工具集里**。

        后果很直接：注入/业务逻辑常常要先登录才碰得到逻辑（购物车、订单、券码），
        而会话是 auth 角色拿到的——没有 `use_account`，注入角色只能看着 401
        反复重试，最后把业务逻辑记成 `blocked`。实测就是这么发生的
        （见 docs/WORK-REPORT-ROUND2.md §4.1）。
        """
        from hexhound.tools import ROLE_TOOLS

        self.assertIn("use_account", ROLE_TOOLS["injection"])
        for role in ("auth", "verify"):
            self.assertIn("use_account", ROLE_TOOLS[role])

    def test_use_account_lists_available_identities(self) -> None:
        """切换失败时要列出**已有身份**，让模型知道 C 已经存在。"""
        from hexhound.tools import _use_account

        registry = self.make_registry(profiles={"C": {"Cookie": "hh_session=x:tok-x-demo"}})
        message = _use_account(registry, {"account": "A"})
        self.assertIn("已有身份", message)
        self.assertIn("C", message)
        self.assertIn("自动注册", message)

    def test_use_account_switches_to_c(self) -> None:
        from hexhound.tools import _use_account

        registry = self.make_registry(profiles={"C": {"Cookie": "hh_session=x:tok-x-demo"}})
        message = _use_account(registry, {"account": "C"})
        self.assertEqual(registry.active_account, "C")
        self.assertIn("Cookie", message)


class RealToolVerdictTests(unittest.TestCase):
    """真工具结论解析：**"没测出注入"绝不能被读成"测出注入"**。

    外部代码评审点名的 P5：`sqlmap_scan` 的结论判定曾经是子串匹配，
    sqlmap 的否定句（"all tested parameters do not appear to be injectable"、
    "does not seem to be injectable"）里同样含有 "injectable" 字样，
    于是"没注入"被判成"注入成立"，直接把误报写进报告。

    这里用替身沙箱喂真实 sqlmap 输出，验证正/负两类输出分别落到哪个结论。
    """

    class FakeSandbox:
        def __init__(self, output: str) -> None:
            self.output = output
            self.calls: list[str] = []

        def available(self) -> bool:
            return True

        def probe(self) -> dict:
            return {"ok": True, "runtime": "fixture"}

        def tool_status(self) -> dict:
            return {"sqlmap": True, "nmap": True, "nuclei": True, "python3": True}

        def sqlmap(self, url, **kwargs):
            from hexhound.sandbox import ExecResult

            self.calls.append(url)
            return ExecResult(
                ok=True, command=f"sqlmap -u {url}", exit_code=0,
                stdout=self.output, stderr="", duration=1.0,
            )

    NEGATIVE_OUTPUTS = (
        "[INFO] testing connection to the target URL\n"
        "[WARNING] the web server responded with an HTTP error code (500)\n"
        "[CRITICAL] all tested parameters do not appear to be injectable. "
        "Try to increase --level/--risk values\n"
        "[WARNING] HTTP error codes detected during run: 500 (1)\n",
        "[INFO] testing if GET parameter 'id' is dynamic\n"
        "[WARNING] GET parameter 'id' does not seem to be injectable\n"
        "[CRITICAL] all tested parameters do not appear to be injectable.\n",
    )

    POSITIVE_OUTPUTS = (
        "[INFO] GET parameter 'id' is 'MySQL >= 5.0 AND error-based' injectable\n"
        "sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:\n"
        "---\nParameter: id (GET)\n    Type: boolean-based blind\n    Payload: id=1 AND 1=1\n---\n",
        "sqlmap identified the following injection point(s) with a total of 12 HTTP(s) requests:\n"
        "Parameter: q (GET)\n    Type: time-based blind\n    Title: MySQL >= 5.0.12 AND time-based blind\n",
    )

    def run_scan(self, output: str) -> str:
        sandbox = self.FakeSandbox(output)
        registry = ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1", "localhost"}),
            timeout=5,
            mode="blackbox",
            surface=AttackSurface(target="http://127.0.0.1:5000", mode="blackbox"),
            role="injection",
            worker_id="W-sqlmap",
            # 沙箱必须在**构造时**就位：注册表会在构造期按环境能力裁剪工具集
            sandbox=sandbox,
        )
        return registry.execute(
            "sqlmap_scan", {"url": "http://127.0.0.1:5000/item?id=1", "timeout": 30}
        )

    def test_sqlmap_tool_is_actually_available_in_this_fixture(self) -> None:
        """前置校验：夹具本身必须真的下发了 sqlmap_scan，否则下面的断言毫无意义。"""
        text = self.run_scan("\n".join(self.POSITIVE_OUTPUTS))
        self.assertNotIn("未知工具", text)

    def test_negative_output_is_not_reported_as_injectable(self) -> None:
        for output in self.NEGATIVE_OUTPUTS:
            with self.subTest(output=output.splitlines()[-2][:40]):
                text = self.run_scan(output)
                self.assertIn("未确认注入", text)
                self.assertNotIn("注入成立", text)

    def test_positive_output_is_reported_as_injectable(self) -> None:
        for output in self.POSITIVE_OUTPUTS:
            with self.subTest(output=output.splitlines()[0][:40]):
                text = self.run_scan(output)
                self.assertIn("注入成立", text)


class CandidateReviewFlowTests(unittest.TestCase):
    """候选 → 复核 → 提升 的闭环（用户点名的验收项之一）。

    子代理在没有证据时只登记**候选**；复核角色必须能看见它，
    并且只有带证据引用 + 复现说明才能提升为正式结论。
    """

    def setUp(self) -> None:
        self.surface = AttackSurface(
            target="http://127.0.0.1:5000", mode="blackbox",
            path=Path(".") / "surface.json",
        )

    def registry(self, role: str) -> ToolRegistry:
        return ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1"}),
            timeout=5,
            mode="blackbox",
            surface=self.surface,
            role=role,
            worker_id=f"W-{role}",
        )

    @staticmethod
    def finding(**overrides) -> dict:
        base = {
            "title": "/item 的 id 参数存在布尔盲注", "severity": "high",
            "vuln_type": "sqli", "url": "http://127.0.0.1:5000/item", "param": "id",
            "evidence": "布尔差异稳定", "description": "疑似注入",
            "confidence": "medium", "remediation": "参数化查询",
        }
        base.update(overrides)
        return base

    def test_candidate_is_visible_to_the_review_role_and_can_be_promoted(self) -> None:
        injection = self.registry("injection")
        registered = injection.execute("record_finding", self.finding())
        self.assertIn("候选", registered, registered)
        self.assertEqual(len(self.surface.pending_candidates()), 1)
        self.assertEqual(len(self.surface.findings), 0, "没有证据时不得直接入库")

        verify = self.registry("verify")
        listed = verify.execute("review_candidates", {})
        self.assertIn("布尔盲注", listed)
        self.assertIn("id", listed)

        promoted = verify.execute("record_finding", self.finding(
            verified=True, evidence_ref=[], verification="重放两次对比",
        ))
        # 没有真实证据编号 → 仍不得提升（复核门优先于模型的自述）
        self.assertEqual(len(self.surface.findings), 0, promoted)

    def test_verified_with_real_evidence_is_promoted(self) -> None:
        verify = self.registry("verify")
        # 证据编号必须是**真实存在过的**：这里手工登记一条 HTTP 交换，
        # 模拟"复核角色先重放了证据请求，再引用它提升候选"。
        exchange_id = verify.new_evidence_id("R")
        verify.http_log.append({"id": exchange_id, "url": "http://127.0.0.1:5000/item?id=1"})
        promoted = verify.execute("record_finding", self.finding(
            verified=True, evidence_ref=[exchange_id], verification="重放对比",
        ))
        self.assertEqual(len(self.surface.findings), 1, promoted)
        finding = self.surface.findings[0]
        self.assertEqual(getattr(finding, "severity", ""), "high")
        self.assertNotEqual(getattr(finding, "status", ""), "candidate")


class ToolFailureStatsTests(unittest.TestCase):
    """工具失败统计：报告要能回答"这一轮为什么没测出东西"。

    四类必须分开（外部评审 P7 的要求）：`unknown` = 环境缺工具（提示词/模型想调但没下发），
    `crashed` = 我们自己的 bug，`returned` = 工具正常返回错误（多为 scope 拒绝），
    `budget` = 预算用尽。混成一个"失败 N 次"，读者无法据此行动。
    """

    def registry(self, role: str = "injection") -> ToolRegistry:
        return ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1"}),
            timeout=5,
            mode="blackbox",
            surface=AttackSurface(target="http://127.0.0.1:5000", mode="blackbox"),
            role=role,
            worker_id="W-stats",
        )

    def test_unknown_tool_is_counted_by_name(self) -> None:
        registry = self.registry()
        registry.execute("sandbox_script", {})
        registry.execute("port_scan", {})
        registry.execute("port_scan", {})
        stats = registry.tool_failure_stats()
        self.assertEqual(stats["unknown"], {"sandbox_script": 1, "port_scan": 2})
        self.assertEqual(stats["total"], 3)
        self.assertGreater(stats["tools_available"], 0)

    def test_crash_and_returned_error_are_separate_buckets(self) -> None:
        registry = self.registry()
        # 工具内部抛异常 → crashed
        from hexhound.tools import Tool

        broken = Tool(
            name="http_request",
            description="test",
            func=lambda args: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        with patch.dict(registry._tools, {"http_request": broken}):
            registry.execute("http_request", {"url": "http://127.0.0.1:5000/"})
        # 参数校验失败 → returned（工具正常返回了一句错误）
        registry.execute("record_finding", {})
        stats = registry.tool_failure_stats()
        self.assertEqual(stats["crashed"], {"http_request": 1})
        self.assertEqual(stats["returned"], {"record_finding": 1})
        self.assertFalse(stats.get("unknown"))

    def test_budget_refusal_is_counted(self) -> None:
        from hexhound.budget import BudgetLimits

        registry = self.registry()
        registry.budget = Budget(BudgetLimits(max_tool_calls=1))
        registry.execute("http_request", {"url": "http://127.0.0.1:5000/"})
        registry.execute("http_request", {"url": "http://127.0.0.1:5000/"})
        self.assertEqual(registry.tool_failure_stats()["budget"], {"http_request": 1})

    def test_clean_run_reports_zero(self) -> None:
        registry = self.registry()
        stats = registry.tool_failure_stats()
        self.assertEqual(stats["total"], 0)
        self.assertFalse(stats.get("unknown"))

    def test_run_summary_carries_the_stats(self) -> None:
        """统计必须落到 run.json / 报告里，而不是只活在内存里。"""
        from hexhound.report import _tool_failure_lines

        lines = _tool_failure_lines({
            "unknown": {"sandbox_script": 2}, "returned": {"sqlmap_scan": 1},
            "total": 3, "tools_available": 10,
        })
        text = "\n".join(lines)
        self.assertIn("3 次", text)
        self.assertIn("sandbox_script×2", text)
        self.assertIn("sqlmap_scan×1", text)
        self.assertIn("环境缺少对应能力", text)
        self.assertEqual(_tool_failure_lines({}), [])
        self.assertEqual(_tool_failure_lines({"total": 0}), [])


if __name__ == "__main__":
    unittest.main()
