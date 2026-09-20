"""跨运行 diff 单元测试。

核心不变量（这是本模块存在的理由）：
**"本次没测到" 绝不能渲染成 "已修复"**——安全报告里最常见的误导。
所以这里把 unknown 与 fixed 的边界单独钉死。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.agent import AgentResult  # noqa: E402
from hexhound.diff import diff_findings, render_diff_markdown  # noqa: E402
from hexhound.report import build_diff, to_json, to_markdown  # noqa: E402
from hexhound.surface import AttackSurface  # noqa: E402

TARGET = "http://hexhound-test.invalid"


def _finding(fid: str, path: str, *, kind: str = "sqli", param: str = "id",
             severity: str = "high", status: str = "verified") -> dict:
    return {
        "id": fid,
        "title": f"{kind} on {path}",
        "severity": severity,
        "url": f"{TARGET}{path}",
        "param": param,
        "vuln_type": kind,
        "status": status,
        "dedupe_key": f"{kind}|{path}|{param}",
    }


class DiffClassificationTests(unittest.TestCase):
    def test_new_and_persisting(self) -> None:
        previous = [_finding("P1", "/login")]
        current = [_finding("V1", "/login"), _finding("V2", "/search", kind="xss", param="q")]
        diff = diff_findings(previous, current, target=TARGET)
        self.assertEqual([item["id"] for item in diff.new], ["V2"])
        self.assertEqual([item["id"] for item in diff.persisting], ["V1"])
        self.assertFalse(diff.fixed)
        self.assertFalse(diff.unknown)
        self.assertEqual(diff.counts(), {"new": 1, "persisting": 1, "fixed": 0, "unknown": 0})

    def test_missing_but_untouched_is_unknown_not_fixed(self) -> None:
        """上次报过、本次没再出现，且**没覆盖该端点** → unknown（不是 fixed）。"""
        previous = [_finding("P1", "/admin/users")]
        diff = diff_findings(previous, [], touched_endpoints={"http://hexhound-test.invalid/login"})
        self.assertFalse(diff.fixed)
        self.assertEqual([item["id"] for item in diff.unknown], ["P1"])
        # 未知项自带反误导说明，报告章节的引言同样点明"不是已修复"
        self.assertIn("不要当作已修复", diff.unknown[0]["reason"])
        self.assertIn("无法判定", diff.note)
        self.assertIn("不是已修复", "\n".join(render_diff_markdown(diff)))

    def test_missing_and_touched_is_fixed(self) -> None:
        """本次确实覆盖了该端点且问题不再出现 → 才允许判 fixed。"""
        previous = [_finding("P1", "/admin/users")]
        diff = diff_findings(
            previous, [], touched_endpoints={f"{TARGET}/admin/users"},
        )
        self.assertEqual([item["id"] for item in diff.fixed], ["P1"])
        self.assertFalse(diff.unknown)
        self.assertFalse(diff.note)  # 没有未知项就不该有警告

    def test_no_touched_set_means_everything_unknown(self) -> None:
        """一个端点都没覆盖（例如全被预算掐断）→ 全部 unknown，绝不谎报修复。"""
        previous = [_finding("P1", "/a"), _finding("P2", "/b")]
        diff = diff_findings(previous, [])
        self.assertEqual(len(diff.unknown), 2)
        self.assertFalse(diff.fixed)

    def test_query_form_difference_still_matches(self) -> None:
        """上次 URL 带 query、本次不带，归一化后仍算同一个端点 → persisting。"""
        previous = [_finding("P1", "/item")]
        current = [_finding("V1", "/item")]
        current[0]["url"] = f"{TARGET}/item?id=1"
        diff = diff_findings(previous, current)
        self.assertEqual(len(diff.persisting), 1)

    def test_render_is_empty_for_no_history(self) -> None:
        diff = diff_findings([], [])
        self.assertTrue(diff.is_empty())
        self.assertEqual(render_diff_markdown(diff), [])

    def test_legacy_memory_without_param_still_matches(self) -> None:
        """旧版记忆没有 param/dedupe_key：POST 表单漏洞也必须认出来"仍存在"，
        而不是因为指纹算不出 param 就被误报成 unknown。"""
        legacy = [{  # 旧格式：只有 id/title/severity/vuln_type/url/status
            "id": "P1",
            "title": "登录接口 SQL 注入",
            "severity": "high",
            "vuln_type": "SQL注入",
            "url": f"{TARGET}/login",
            "status": "verified",
        }]
        current = [_finding("V1", "/login", kind="sqli", param="username")]
        diff = diff_findings(legacy, current)
        self.assertEqual(len(diff.persisting), 1)
        self.assertFalse(diff.new)
        self.assertFalse(diff.unknown)
        self.assertIn("参数可能不同", diff.persisting[0]["reason"])

    def test_different_vuln_class_on_same_path_is_new_not_persisting(self) -> None:
        """放宽匹配只放宽参数，不放宽漏洞类别——同路径换类别必须是新增。"""
        previous = [_finding("P1", "/login", kind="sqli", param="username")]
        current = [_finding("V1", "/login", kind="xss", param="username")]
        diff = diff_findings(previous, current)
        self.assertEqual([item["id"] for item in diff.new], ["V1"])
        self.assertEqual([item["id"] for item in diff.unknown], ["P1"])
        # 关键：该端点本次仍报出问题 → 绝不能说"已修复"（实测踩过的假修复）
        self.assertFalse(diff.fixed)
        self.assertIn("仍报出其他问题", diff.unknown[0]["reason"])

    def test_endpoint_still_vulnerable_blocks_false_fixed(self) -> None:
        """实测场景复现：历史把 /fetch 的 SSRF 归成"路径穿越"（标题含"任意文件读取"），
        本次归类为 ssrf。指纹对不上，但端点仍报出问题——不得谎报"疑似已修复"。"""
        legacy = [_finding("P1", "/fetch", kind="path_traversal", param="url")]
        current = [_finding("V1", "/fetch", kind="ssrf", param="url")]
        diff = diff_findings(
            legacy, current, touched_endpoints={f"{TARGET}/fetch"},
        )
        self.assertFalse(diff.fixed)
        self.assertEqual([item["id"] for item in diff.unknown], ["P1"])

    def test_ssrf_beats_traversal_in_classification(self) -> None:
        """归类顺序：标题同时提到 SSRF 与"任意文件读取"时必须算 ssrf，
        否则同一漏洞在两次运行里会被算成两类，diff 直接失效。"""
        from hexhound.dedupe import vuln_class

        self.assertEqual(
            vuln_class({"title": "SSRF（支持 file:// 任意文件读取）"}), "ssrf"
        )
        self.assertEqual(vuln_class({"title": "任意文件读取"}), "path_traversal")
        self.assertEqual(vuln_class({"title": "目录穿越可读 /etc/passwd"}), "path_traversal")

    def test_reported_at_kept_for_duplicate_ids(self) -> None:
        """不同运行会复用 HH-00x 编号，条目必须带上报时间才能分辨是哪一次。"""
        previous = [dict(_finding("HH-002", "/file"), at="2026-09-19 08:23:43 UTC")]
        diff = diff_findings(previous, [], touched_endpoints={f"{TARGET}/file"})
        self.assertEqual(diff.fixed[0]["reported_at"], "2026-09-19 08:23:43 UTC")
        self.assertIn("上报于 2026-09-19", "\n".join(render_diff_markdown(diff)))

    def test_original_status_kept_separate_from_diff_status(self) -> None:
        previous = [_finding("P1", "/login", status="candidate")]
        current = [_finding("V1", "/login", status="candidate")]
        diff = diff_findings(previous, current)
        entry = diff.persisting[0]
        self.assertEqual(entry["status"], "persisting")
        self.assertEqual(entry["original_status"], "candidate")
        self.assertIn("候选", "\n".join(render_diff_markdown(diff)))


class MemoryPersistenceTests(unittest.TestCase):
    def test_record_run_keeps_param_and_fingerprint(self) -> None:
        """写记忆时必须存 param + dedupe_key，否则下次 diff 只能靠放宽匹配。"""
        import tempfile

        from hexhound.memory import HostMemory

        with tempfile.TemporaryDirectory() as tmp:
            memory = HostMemory("hexhound-test.invalid", home=Path(tmp))
            memory.record_run(findings=[_finding("V1", "/login", param="username")])
            stored = memory.known_findings(5)
            self.assertEqual(stored[0]["param"], "username")
            self.assertEqual(stored[0]["dedupe_key"], "sqli|/login|username")
            # 落盘的指纹能直接与本次 finding 精确对上（走 persisting 而非放宽分支）
            diff = diff_findings(stored, [_finding("V2", "/login", param="username")])
            self.assertEqual(diff.persisting[0]["reason"], "上次已报过，本次仍在")
            self.assertFalse(diff.new)


class ReportDiffWiringTests(unittest.TestCase):
    def _result(self) -> AgentResult:
        surface = AttackSurface(target=TARGET)
        surface.mark_attempt(f"{TARGET}/login?id=1", "sqli", param="id", outcome="signal")
        surface.record_coverage(f"{TARGET}/login", status="reported", detail="SQLi")
        result = AgentResult(surface=surface)
        result.findings = [_finding("V1", "/login")]
        result.previous_findings = [
            _finding("P1", "/login"),                      # 仍存在
            _finding("P2", "/gone"),                       # 未覆盖 → unknown
        ]
        result.previous_run_at = "2025-01-01 00:00:00 UTC"
        return result

    def test_build_diff_uses_surface_coverage(self) -> None:
        diff = build_diff(self._result())
        self.assertIsNotNone(diff)
        self.assertEqual(diff.counts()["persisting"], 1)
        self.assertEqual(diff.counts()["unknown"], 1)
        self.assertEqual(diff.previous_at, "2025-01-01 00:00:00 UTC")

    def test_no_previous_findings_means_no_diff_block(self) -> None:
        result = self._result()
        result.previous_findings = []
        self.assertIsNone(build_diff(result))
        self.assertNotIn("与上次运行的差异", to_markdown(result, TARGET))

    def test_markdown_and_json_include_diff(self) -> None:
        result = self._result()
        markdown = to_markdown(result, TARGET)
        self.assertIn("## 与上次运行的差异", markdown)
        self.assertIn("仍存在 **1**", markdown)
        payload = to_json(result, TARGET)
        self.assertEqual(payload["diff"]["counts"]["unknown"], 1)
        self.assertEqual(payload["diff"]["previous_at"], "2025-01-01 00:00:00 UTC")

    def test_reported_coverage_blocks_false_fixed(self) -> None:
        """实测场景：模型用 record_coverage(reported) 记了"这里有问题"却没写 finding。

        若只按 findings 判断"本次还有没有问题"，上一轮的同位置结论会被误判成
        "疑似已修复"——而这次其实也看到了问题。
        """
        previous = [_finding("P1", "/api/users", kind="idor", param="")]
        surface = AttackSurface(target=TARGET)
        surface.record_coverage(
            f"{TARGET}/api/users 未授权访问", status="reported", detail="匿名可读全量 PII"
        )
        result = AgentResult(surface=surface)
        result.findings = []            # 本次没写 finding
        result.previous_findings = previous
        diff = build_diff(result)
        self.assertFalse(diff.fixed)
        self.assertEqual([item["id"] for item in diff.unknown], ["P1"])
        self.assertIn("仍报出其他问题", diff.unknown[0]["reason"])

    def test_not_tested_coverage_is_not_coverage(self) -> None:
        """`not_tested` / `blocked` 是"没测"的记录，不能被当成"覆盖过"。

        否则一个明确写着"未测试"的端点会让跨运行 diff 得出"疑似已修复"。
        """
        surface = AttackSurface(target=TARGET)
        surface.record_coverage(f"{TARGET}/admin", status="not_tested", detail="预算耗尽")
        surface.record_coverage(f"{TARGET}/debug", status="blocked", detail="被 WAF 拦")
        self.assertEqual(surface.touched_endpoints(), set())
        self.assertEqual(sorted(surface.reported_endpoints()), [])

    def test_reported_endpoints_extracted_from_free_text(self) -> None:
        surface = AttackSurface(target=TARGET)
        surface.record_coverage(f"{TARGET}/api/user 未授权 读他人资料", status="reported")
        surface.record_coverage(f"{TARGET}/x", status="no_issue_found")
        self.assertEqual(surface.reported_endpoints(), {f"{TARGET}/api/user"})

    def test_report_wiring_passes_still_affected(self) -> None:
        """接线检查：report.build_diff 必须把 reported 覆盖一起传进去。"""
        surface = AttackSurface(target=TARGET)
        surface.record_coverage(f"{TARGET}/api/users", status="reported", detail="未授权")
        result = AgentResult(surface=surface)
        result.findings = []
        result.previous_findings = [_finding("P1", "/api/users", kind="idor", param="")]
        diff = build_diff(result)
        self.assertIsNotNone(diff)
        self.assertEqual(len(diff.unknown), 1)
        self.assertFalse(diff.fixed)

    def test_surface_touched_endpoints_unions_three_sources(self) -> None:
        """三来源并集：attempt / finding / coverage 都算"碰过"。"""
        surface = AttackSurface(target=TARGET)
        surface.mark_attempt(f"{TARGET}/attempted", "sqli", param="id")
        surface.record_coverage(f"{TARGET}/covered 无问题", status="no_issue_found")
        touched = surface.touched_endpoints()
        self.assertIn(f"{TARGET}/attempted", touched)
        self.assertIn(f"{TARGET}/covered", touched)
        self.assertTrue(all(url.startswith("http") for url in touched))


if __name__ == "__main__":
    unittest.main()
