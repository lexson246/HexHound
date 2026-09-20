"""攻面模型与漏洞去重的单元测试（纯本地，无网络）。"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.dedupe import dedupe_findings, dedupe_key, vuln_class  # noqa: E402
from hexhound.surface import (  # noqa: E402
    AttackSurface,
    Finding,
    normalize_endpoint,
    normalize_path,
    param_names,
    sort_urls,
)


class NormalizeTests(unittest.TestCase):
    def test_path_collapses_numeric_segments(self) -> None:
        self.assertEqual(normalize_path("http://h/user/1"), "/user/{n}")
        self.assertEqual(normalize_path("http://h/user/42/profile"), "/user/{n}/profile")

    def test_endpoint_drops_query_and_requires_host(self) -> None:
        key = normalize_endpoint("http://h/api/item?id=3&x=1")
        self.assertEqual(key, "http://h/api/item")
        # 相对路径没有意义（无法比对、无法请求）→ 返回空串
        self.assertEqual(normalize_endpoint("/login"), "")

    def test_param_names_preserve_order(self) -> None:
        self.assertEqual(param_names("http://h/x?a=1&b=2&a=3"), ["a", "b"])
        self.assertEqual(param_names("http://h/x", ["z", "a", "z"]), ["z", "a"])

    def test_sort_urls_prioritises_high_value(self) -> None:
        urls = ["http://h/static/x", "http://h/login", "http://h/api/user", "http://h/admin"]
        ordered = sort_urls(urls)
        self.assertEqual(len(ordered), 4)
        self.assertTrue(ordered[0].endswith(("/admin", "/api/user", "/login")))


class AttackSurfaceTests(unittest.TestCase):
    def make(self) -> AttackSurface:
        return AttackSurface(target="http://h", mode="blackbox")

    def test_add_endpoint_merges_params_and_skips_assets(self) -> None:
        surface = self.make()
        surface.add_endpoint("http://h/a?id=1", source="crawl", methods=["GET"])
        surface.add_endpoint("http://h/a?id=2&b=3", source="form", methods=["POST"])
        self.assertEqual(len(surface.endpoints), 1)
        entry = surface.endpoints["http://h/a"]
        self.assertEqual(entry.params, ["id", "b"])
        self.assertEqual(sorted(entry.methods), ["GET", "POST"])
        self.assertIsNone(surface.add_endpoint("http://h/app.js", source="crawl"))

    def test_form_action_resolved_against_base_url(self) -> None:
        surface = self.make()
        surface.add_form("http://h/", "POST", "/login", ["username"], base_url="http://h/")
        self.assertIn("http://h/login", surface.endpoints)
        self.assertEqual(surface.forms["http://h/login"]["params"], ["username"])

    def test_attempt_dedup_is_payload_aware(self) -> None:
        surface = self.make()
        surface.mark_attempt("http://h/a", "sqli", param="id", payload="'", outcome="no_signal")
        self.assertTrue(surface.is_tried("http://h/a", "sqli", "id", "'"))
        # 同类别的另一个 payload 不应被当作已试（否则会吃掉检出率）
        self.assertFalse(surface.is_tried("http://h/a", "sqli", "id", "1 AND 1=2"))
        # 命中同样算"已有结论"
        surface.mark_attempt("http://h/a", "sqli", param="id", payload="1 AND 1=2", outcome="signal")
        self.assertTrue(surface.is_tried("http://h/a", "sqli", "id", "1 AND 1=2"))

    def test_hit_is_not_downgraded_by_later_miss(self) -> None:
        surface = self.make()
        surface.mark_attempt("http://h/a", "xss", param="q", payload="<b>", outcome="signal", detail="回显")
        surface.mark_attempt("http://h/a", "xss", param="q", payload="<b>", outcome="no_signal")
        self.assertEqual(surface.tried_outcome("http://h/a", "xss", "q", "<b>").outcome, "signal")

    def test_candidate_merge_and_promote(self) -> None:
        surface = self.make()
        first = Finding(id="", title="SQL 注入", severity="high", url="http://h/a?id=1",
                        evidence="short", dedupe_key="sqli|/a|id")
        surface.add_candidate(first)
        second = Finding(id="", title="SQL 注入（重复）", severity="high", url="http://h/a?id=2",
                         evidence="a much longer evidence body", dedupe_key="sqli|/a|id")
        surface.add_candidate(second)
        self.assertEqual(len(surface.pending_candidates()), 1)
        self.assertEqual(surface.pending_candidates()[0].extra["merged_count"], 2)
        # 合并时保留证据更充分的那份
        self.assertIn("longer", surface.pending_candidates()[0].evidence)

        result = surface.promote(surface.pending_candidates()[0], "W2", "重放确认")
        self.assertEqual(result, "new")
        self.assertEqual(len(surface.findings), 1)
        self.assertEqual(surface.pending_candidates(), [])
        self.assertEqual(surface.findings[0].status, "verified")

    def test_promote_merges_duplicate_verified(self) -> None:
        surface = self.make()
        finding = Finding(id="", title="t", severity="high", dedupe_key="k", evidence="x")
        surface.findings.append(finding)
        again = Finding(id="", title="t2", severity="high", dedupe_key="k", evidence="x")
        self.assertEqual(surface.promote(again, "W3", "v"), "merged")
        self.assertEqual(len(surface.findings), 1)

    def test_coverage_records_negative_results(self) -> None:
        surface = self.make()
        surface.record_coverage("http://h/login", "no_issue_found", detail="默认凭据未命中")
        surface.record_coverage("http://h/admin", "ruled_out", detail="403")
        surface.record_coverage("http://h/upload", "not_tested", detail="无上传入口")
        summary = surface.coverage_summary()
        self.assertEqual(summary["no_issue_found"], 1)
        self.assertEqual(summary["ruled_out"], 1)
        self.assertEqual(summary["not_tested"], 1)
        self.assertTrue(any("ruled_out" in line for line in surface.coverage_lines()))

    def test_llm_summary_mentions_key_facts(self) -> None:
        surface = self.make()
        surface.add_endpoint("http://h/api/user?uid=1", source="crawl")
        surface.add_tech("server", "nginx/1.24")
        surface.mark_attempt("http://h/api/user", "idor", param="uid", outcome="signal", detail="读到他人资料")
        surface.record_coverage("http://h/x", "no_issue_found")
        surface.add_agent_note("W1", "上传接口未测")
        text = surface.to_llm_summary()
        for token in ("技术栈", "nginx", "疑似信号", "覆盖情况", "线索"):
            self.assertIn(token, text)

    def test_save_and_load_round_trip(self) -> None:
        surface = self.make()
        surface.add_endpoint("http://h/a?id=1", source="crawl")
        surface.add_form("http://h/", "POST", "/login", ["username"], base_url="http://h/")
        surface.mark_attempt("http://h/a", "sqli", param="id", payload="'", outcome="signal", detail="err")
        surface.record_coverage("http://h/a", "no_issue_found")
        surface.add_agent_note("W1", "注意 /a")
        finding = Finding(id="HH-001", title="SQL", severity="high", url="http://h/a?id=1",
                          evidence="e", dedupe_key="sqli|/a|id", status="verified")
        surface.findings.append(finding)
        candidate = Finding(id="HH-002", title="cand", severity="low", dedupe_key="x", evidence="e")
        surface.candidates["HH-002"] = candidate

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "surface.json"
            surface.save(path)
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["stats"]["endpoints"], 2)
            restored = AttackSurface.load(path, target="http://h")
        self.assertEqual(len(restored.endpoints), 2)
        self.assertEqual(len(restored.forms), 1)
        self.assertEqual(len(restored.attempts), 1)
        self.assertEqual(len(restored.findings), 1)
        self.assertEqual(len(restored.candidates), 1)
        self.assertEqual(restored.coverage_summary().get("no_issue_found"), 1)
        self.assertEqual(restored.note_lines(), ["[W1] 注意 /a"])
        self.assertTrue(restored.is_tried("http://h/a", "sqli", "id", "'"))

    def test_load_missing_file_returns_empty(self) -> None:
        surface = AttackSurface.load(Path("does-not-exist.json"), target="http://h")
        self.assertEqual(surface.stats()["endpoints"], 0)


class BusinessPathTierTests(unittest.TestCase):
    """业务路径档（business）：竞态/业务逻辑问题的唯一发现入口。

    实测动机：多次实跑里 `/coupon` **从未**被发现过——连首页都链着它，
    但通用字典里没有任何"会改状态"的路径词汇，于是"按攻面特征派发竞态任务"
    的机制根本没有输入可用（S1 任务一次都没被派出去）。
    """

    def test_business_tier_exists_with_enough_words(self) -> None:
        from hexhound import knowledge as KB

        self.assertIn("business", KB.PATH_TIERS)
        self.assertGreaterEqual(len(KB.PATH_TIERS["business"]), 60)

    def test_business_tier_covers_state_changing_vocabulary(self) -> None:
        from hexhound import knowledge as KB

        joined = " ".join(KB.PATH_TIERS["business"])
        for keyword in (
            "coupon", "redeem", "wallet", "balance", "points", "transfer",
            "order", "refund", "checkout", "subscribe", "invite", "claim",
            "reset_password", "verify", "quota",
        ):
            self.assertIn(keyword, joined, keyword)

    def test_enumerate_common_documents_business_tier(self) -> None:
        """工具描述必须写明 business 档：模型按描述选档位，不写就不会用。"""
        from hexhound.tools import _DESC_ENUMERATE_COMMON

        self.assertIn("business", _DESC_ENUMERATE_COMMON)
        self.assertIn("会改状态", _DESC_ENUMERATE_COMMON)


class DedupeTests(unittest.TestCase):
    def test_vuln_class_detection(self) -> None:
        self.assertEqual(vuln_class({"vuln_type": "SQL注入"}), "sqli")
        self.assertEqual(vuln_class({"title": "反射型 XSS"}), "xss")
        self.assertEqual(vuln_class({"title": "未授权访问敏感接口"}), "idor")
        self.assertEqual(vuln_class({"title": "任意文件读取"}), "path_traversal")

    def test_same_root_cause_collapses_across_ids(self) -> None:
        left = {"vuln_type": "SQL注入", "url": "http://h/user/1?id=3"}
        right = {"vuln_type": "SQL注入", "url": "http://h/user/2?id=9"}
        self.assertEqual(dedupe_key(left), dedupe_key(right))

    def test_different_endpoints_stay_separate(self) -> None:
        left = {"vuln_type": "SQL注入", "url": "http://h/login", "param": "username"}
        right = {"vuln_type": "SQL注入", "url": "http://h/api/user", "param": "uid"}
        self.assertNotEqual(dedupe_key(left), dedupe_key(right))

    def test_url_less_findings_use_host(self) -> None:
        finding = {"vuln_type": "信息安全", "unit_name": "example.com"}
        self.assertIn("example.com", dedupe_key(finding))

    def test_dedupe_keeps_richest_and_counts(self) -> None:
        findings = [
            {"id": "HH-001", "vuln_type": "SQL注入", "url": "http://h/a?id=1",
             "severity": "high", "evidence": "short", "status": "candidate"},
            {"id": "HH-002", "vuln_type": "SQL注入", "url": "http://h/a?id=2",
             "severity": "high", "evidence": "a much longer evidence", "status": "verified"},
            {"id": "HH-003", "vuln_type": "XSS", "url": "http://h/b?q=1",
             "severity": "medium", "evidence": "x", "status": "verified"},
        ]
        kept, merged = dedupe_findings(findings)
        self.assertEqual(merged, 1)
        self.assertEqual(len(kept), 2)
        sqli = next(item for item in kept if item["id"] == "HH-002")
        self.assertEqual(sqli["merged_count"], 2)
        self.assertEqual(sqli["duplicate_ids"], ["HH-001"])
        # 严重度排序：high 在前
        self.assertEqual(kept[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
