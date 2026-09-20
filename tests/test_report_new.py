"""报告渲染测试：结论分区、覆盖矩阵、任务台账、PoC 与补天字段。"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.agent import AgentResult  # noqa: E402
from hexhound.report import to_json, to_markdown, write_report  # noqa: E402
from hexhound.surface import AttackSurface, Finding  # noqa: E402


def build_result() -> AgentResult:
    surface = AttackSurface(target="http://127.0.0.1:5000", mode="blackbox")
    surface.add_endpoint("http://127.0.0.1:5000/login", source="crawl", params=["username"])
    surface.record_coverage("http://127.0.0.1:5000/admin", "ruled_out", detail="403 拒绝", owasp="A01")
    surface.record_coverage("http://127.0.0.1:5000/upload", "not_tested", detail="无上传入口")
    surface.add_tech("server", "Werkzeug/3.1.8")

    verified = {
        "id": "HH-001",
        "title": "错误型 SQL 注入（登录接口）",
        "severity": "high",
        "status": "verified",
        "verified_by": "W2",
        "verification": "重放 [W2-R1]，响应 500 且回显 SQL 错误",
        "confidence": "high",
        "confidence_rationale": "报错内容包含注入的原始片段",
        "counterevidence": "未确认生产环境是否关闭详细报错",
        "vuln_type": "SQL注入",
        "url": "http://127.0.0.1:5000/login",
        "param": "username",
        "evidence": "单引号触发 SQL 报错并回显完整查询",
        "description": "username 参数直接拼接进 SQL 语句",
        "remediation": "使用参数化查询",
        "dedupe_key": "sqli|/login|username",
        "merged_count": 2,
        "duplicate_ids": ["HH-002"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss": "9.8",
        "owasp": "A03",
        "poc_path": "/tmp/poc/HH-001.sh",
        "http_evidence": [
            {
                "id": "W2-R1",
                "method": "POST",
                "url": "http://127.0.0.1:5000/login",
                "request_headers": {"Host": "127.0.0.1:5000"},
                "request_body": "username='&password=x",
                "status_code": 500,
                "reason": "Internal Server Error",
                "response_headers": {"content-type": "text/html"},
                "response_body": "SQL 错误：unrecognized token",
            }
        ],
        "screenshot_evidence": [
            {
                "id": "S1",
                "label": "注入截图",
                "mime_type": "image/png",
                "data_base64": base64.b64encode(b"png").decode("ascii"),
            }
        ],
    }
    candidate = {
        "id": "HH-003",
        "title": "疑似 SSRF",
        "severity": "medium",
        "status": "candidate",
        "vuln_type": "SSRF",
        "url": "http://127.0.0.1:5000/fetch?url=",
        "param": "url",
        "evidence": "注入内网地址后响应体变大",
        "description": "url 参数由服务端发起请求",
        "remediation": "白名单校验目标地址",
        "dedupe_key": "ssrf|/fetch|url",
    }
    return AgentResult(
        steps=[
            {"step": 1, "action": "crawl", "thought": "摸面", "observation": "拿到表单", "task": "T1",
             "role": "recon"},
            {"step": 1, "action": "fuzz_params", "thought": "打注入", "observation": "疑似信号",
             "task": "T2", "role": "injection"},
        ],
        findings=[verified, candidate],
        final_summary="[T1/recon] 已摸清攻面\n[T2/injection] 确认一条 SQL 注入",
        prompt_tokens=1000,
        completion_tokens=200,
        total_tokens=1200,
        estimated_cost=0.0012,
        steps_used=2,
        finish_reason="finish",
        surface=surface,
        tasks=[
            {"id": "T1", "role": "recon", "objective": "爬首页", "outcome": "done", "summary": "完成"},
            {"id": "T2", "role": "injection", "objective": "测 login", "outcome": "done", "summary": "命中"},
        ],
        artifacts_dir="/tmp/run",
        poc_paths={"HH-001": "/tmp/poc/HH-001.sh"},
        deduped=1,
    )


class ToolEvidenceAppendixTests(unittest.TestCase):
    """附录必须能按 finding 引用的 T 编号回查——否则"证据可复核"是空话。

    实测踩过：附录早先渲染的是沙箱内部日志（X1、X2…），而 finding 引用的是
    `W2-T9` 这类编号，两边对不上，复核者按编号查不到命令。
    """

    def _result(self, tool_log) -> AgentResult:
        result = AgentResult(surface=AttackSurface(target="http://t.example"))
        result.tool_log = tool_log
        return result

    def test_appendix_renders_t_id_tool_and_purpose(self) -> None:
        result = self._result(
            [
                {
                    "id": "W2-T9",
                    "tool": "python3（自定义脚本）",
                    "command": "python3 -c '...'",
                    "original_command": "print(1)",
                    "script": "import threading\nprint('race')",
                    "exit_code": 0,
                    "ok": True,
                    "duration": 1.2,
                    "note": "验证优惠券并发重复兑换",
                    "output": "success 6",
                }
            ]
        )
        markdown = to_markdown(result, "http://t.example")
        self.assertIn("**W2-T9**", markdown)
        self.assertIn("python3（自定义脚本）", markdown)
        self.assertIn("验证优惠券并发重复兑换", markdown)
        # 脚本要作为 python 代码块渲染（而不是 base64 一长串）
        self.assertIn("```python", markdown)
        self.assertIn("import threading", markdown)

    def test_appendix_renders_plain_command_as_bash(self) -> None:
        result = self._result(
            [
                {
                    "id": "W1-T1",
                    "tool": "sqlmap",
                    "command": "sqlmap -u http://t.example/x",
                    "original_command": "sqlmap -u http://t.example/x",
                    "exit_code": 0,
                    "duration": 3.0,
                    "note": "确认注入",
                    "output": "injectable",
                }
            ]
        )
        markdown = to_markdown(result, "http://t.example")
        self.assertIn("```bash", markdown)
        self.assertIn("sqlmap -u http://t.example/x", markdown)
        self.assertNotIn("```python", markdown)


class ReportTests(unittest.TestCase):
    def test_markdown_separates_verified_and_candidate(self) -> None:
        text = to_markdown(build_result(), "对靶场做黑盒评估")
        self.assertIn("## 已复核漏洞", text)
        self.assertIn("## 待复核候选", text)
        self.assertIn("HH-001", text)
        self.assertIn("HH-003", text)
        # 候选区必须明示"没有通过复核门"
        self.assertIn("没有**通过复核门", text)

    def test_markdown_contains_evidence_and_governance_fields(self) -> None:
        text = to_markdown(build_result(), "goal")
        for token in (
            "复核方式", "置信度理由", "反证", "去重指纹", "合并上报",
            "CVSS", "可复现 PoC", "请求原文（W2-R1）", "响应原文（W2-R1）", "截图证据",
        ):
            self.assertIn(token, text, token)

    def test_markdown_has_task_ledger_and_coverage(self) -> None:
        text = to_markdown(build_result(), "goal")
        self.assertIn("## 子任务台账", text)
        self.assertIn("## OWASP 覆盖矩阵", text)
        self.assertIn("## 覆盖面明细", text)
        self.assertIn("ruled_out", text)
        self.assertIn("not_tested", text)

    def test_json_report_shape(self) -> None:
        payload = to_json(build_result(), "goal")
        self.assertEqual(payload["verified_count"], 1)
        self.assertEqual(payload["candidate_count"], 1)
        self.assertEqual(len(payload["verified_findings"]), 1)
        self.assertEqual(len(payload["candidate_findings"]), 1)
        self.assertEqual(payload["tasks"][0]["id"], "T1")
        self.assertEqual(payload["coverage"]["ruled_out"], 1)
        self.assertEqual(payload["poc_paths"]["HH-001"], "/tmp/poc/HH-001.sh")
        self.assertEqual(payload["deduped"], 1)
        # 必须可 JSON 序列化（GUI/CI 会直接 dump）
        json.dumps(payload, ensure_ascii=False)

    def test_write_report_dispatch_by_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            markdown_path = write_report(build_result(), "goal", Path(tmp) / "a" / "r.md")
            json_path = write_report(build_result(), "goal", Path(tmp) / "r.json")
            self.assertTrue(markdown_path.exists())
            self.assertIn("# HexHound 安全审计报告", markdown_path.read_text(encoding="utf-8"))
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["goal"], "goal")

    def test_empty_findings_report_is_explicit(self) -> None:
        result = AgentResult(findings=[], final_summary="没有发现", surface=AttackSurface())
        text = to_markdown(result, "goal")
        self.assertIn("无已复核漏洞", text)
        self.assertIn("没有发现", text)


if __name__ == "__main__":
    unittest.main()
