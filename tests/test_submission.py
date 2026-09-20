from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace


SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.submission import write_butian_package  # noqa: E402


class SubmissionTests(unittest.TestCase):
    def test_butian_package_contains_evidence_and_json(self) -> None:
        finding = {
            "id": "HH-001",
            "title": "SQL注入",
            "severity": "high",
            "vuln_type": "SQL注入",
            "url": "http://127.0.0.1/login",
            "description": "desc",
            "evidence": "evidence",
            "remediation": "fix",
            "code_evidence": [
                {
                    "id": "C1",
                    "file": "app.py",
                    "start": 10,
                    "end": 12,
                    "snippet": "query = f\"SELECT * FROM users WHERE id = {uid}\"",
                }
            ],
            "screenshot_evidence": [
                {
                    "id": "S1",
                    "label": "截图",
                    "url": "http://127.0.0.1/login",
                    "mime_type": "image/png",
                    "data_base64": base64.b64encode(b"png").decode("ascii"),
                }
            ],
            "http_evidence": [
                {
                    "id": "R1",
                    "method": "POST",
                    "url": "http://127.0.0.1/login",
                    "request_headers": {},
                    "request_body": "username='",
                    "status_code": 500,
                    "reason": "Internal Server Error",
                    "response_headers": {},
                    "response_body": "SQL error",
                }
            ],
        }
        result = SimpleNamespace(findings=[finding])
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "reports" / "report.md"
            report_path.parent.mkdir()
            report_path.write_text("# report", encoding="utf-8")
            package = write_butian_package(result, report_path)
            self.assertIsNotNone(package)
            self.assertTrue(package.exists())
            with zipfile.ZipFile(package) as archive:
                names = archive.namelist()
                payload = json.loads(archive.read("butian_submissions.json"))
            self.assertIn("butian_submissions.json", names)
            self.assertIn("submissions/HH-001.md", names)
            self.assertIn("report.md", names)
            self.assertTrue(any(name.startswith("evidence/") and name.endswith(".txt") for name in names))
            self.assertTrue(any(name.startswith("evidence/") and name.endswith(".png") for name in names))
            self.assertIn("evidence/HH-001_R1.request.http", names)
            self.assertIn("evidence/HH-001_R1.response.http", names)
            self.assertEqual(payload[0]["漏洞类别"], "web漏洞")
            self.assertEqual(payload[0]["漏洞类型（事件型/通用型）"], "事件型")
            self.assertEqual(payload[0]["具体漏洞类型"], "SQL注入")
            self.assertIn("存在SQL注入", payload[0]["漏洞名称"])
            self.assertIn("evidence/HH-001_C1.txt", payload[0]["详细细节"])
            self.assertIn("evidence/HH-001_S1.png", payload[0]["详细细节"])
            self.assertIn("evidence/HH-001_R1.request.http", payload[0]["详细细节"])


if __name__ == "__main__":
    unittest.main()
