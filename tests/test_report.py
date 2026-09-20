"""报告底层渲染细节（HTTP 原文折叠）。"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound import report  # noqa: E402


class HttpEvidenceRenderingTests(unittest.TestCase):
    def test_short_http_evidence_is_not_collapsed(self) -> None:
        lines = report._http_evidence_lines("请求", "GET / HTTP/1.1")
        self.assertEqual(lines[0], "请求")
        self.assertEqual(lines[1], "```http")
        self.assertNotIn("<details>", "\n".join(lines))

    def test_long_http_evidence_is_collapsed(self) -> None:
        lines = report._http_evidence_lines("响应", "x" * 5001)
        self.assertIn("<details>", lines[1])
        self.assertIn("```http", lines)
        self.assertEqual(lines[-1], "</details>")

    def test_raw_request_rendering(self) -> None:
        text = report._format_raw_request(
            {
                "method": "POST",
                "url": "http://h:5000/login?x=1",
                "request_headers": {"Host": "h:5000", "User-Agent": "hh"},
                "request_body": "a=1",
            }
        )
        self.assertIn("POST /login?x=1 HTTP/1.1", text)
        self.assertIn("Host: h:5000", text)
        self.assertIn("a=1", text)
        # Host 头不应重复（原文里已经有了）
        self.assertEqual(text.count("Host:"), 1)

    def test_raw_response_rendering(self) -> None:
        text = report._format_raw_response(
            {
                "status_code": 500,
                "reason": "Internal Server Error",
                "response_headers": {"content-type": "text/html"},
                "response_body": "boom",
            }
        )
        self.assertIn("HTTP/1.1 500 Internal Server Error", text)
        self.assertIn("content-type: text/html", text)
        self.assertIn("boom", text)

    def test_cell_escapes_table_separators(self) -> None:
        self.assertEqual(report._cell("a|b\nc"), "a/b c")


if __name__ == "__main__":
    unittest.main()
