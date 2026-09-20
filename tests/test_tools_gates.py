"""工具层单元测试：角色工具边界、复核门、证据编号校验、输出治理、CVSS。

全部离线运行（不发真实请求）：只测"闸门"逻辑，实际检测能力由
`examples/tool_selftest.py` 对着靶场跑。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
