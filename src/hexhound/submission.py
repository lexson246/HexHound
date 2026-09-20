from __future__ import annotations

import base64
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .butian import attach_evidence_paths, build_butian_entry, build_butian_markdown
from .report import _format_raw_request, _format_raw_response


def _write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _target_host(finding: dict[str, Any]) -> str:
    parsed = urlparse(str(finding.get("url") or ""))
    return parsed.hostname or ""


def write_butian_package(result: Any, report_path: str | Path) -> Path | None:
    """把审计结果打包成适合补天手动提交的 ZIP 提交包。"""
    if not result.findings:
        return None

    report_path = Path(report_path)
    package_dir = report_path.parent / "butian"
    package_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="hexhound-butian-") as tmp:
        staging = Path(tmp)
        evidence_dir = staging / "evidence"
        evidence_dir.mkdir()
        submissions_dir = staging / "submissions"
        submissions_dir.mkdir()

        entries: list[dict[str, Any]] = []
        for finding in result.findings:
            code_files: list[dict[str, Any]] = []
            for code in finding.get("code_evidence", []):
                filename = f"{finding.get('id', 'finding')}_{code.get('id', 'code')}.txt"
                content = (
                    f"{code.get('file', '')}:{code.get('start', '')}-{code.get('end', '')}\n\n"
                    f"{code.get('snippet', '')}"
                )
                _write_text(evidence_dir / filename, content)
                code_files.append(
                    {
                        "file": f"evidence/{filename}",
                        "id": code.get("id"),
                        "source_file": code.get("file"),
                        "lines": f"{code.get('start', '')}-{code.get('end', '')}",
                    }
                )

            screenshot_files: list[dict[str, Any]] = []
            for shot in finding.get("screenshot_evidence", []):
                filename = f"{finding.get('id', 'finding')}_{shot.get('id', 'shot')}.png"
                data = base64.b64decode(shot.get("data_base64", ""))
                (evidence_dir / filename).write_bytes(data)
                screenshot_files.append(
                    {
                        "file": f"evidence/{filename}",
                        "id": shot.get("id"),
                        "label": shot.get("label", ""),
                        "url": shot.get("url", ""),
                    }
                )

            http_files: list[dict[str, Any]] = []
            for index, exchange in enumerate(finding.get("http_evidence", []), 1):
                exchange_id = exchange.get("id") or f"R{index}"
                request_name = f"{finding.get('id', 'finding')}_{exchange_id}.request.http"
                response_name = f"{finding.get('id', 'finding')}_{exchange_id}.response.http"
                _write_text(evidence_dir / request_name, _format_raw_request(exchange))
                _write_text(evidence_dir / response_name, _format_raw_response(exchange))
                http_files.append({"file": f"evidence/{request_name}", "kind": "request"})
                http_files.append({"file": f"evidence/{response_name}", "kind": "response"})

            entry = build_butian_entry(finding, _target_host(finding))
            entry = attach_evidence_paths(entry, code_files, screenshot_files, http_files)
            markdown = build_butian_markdown(entry, code_files, screenshot_files, http_files)
            _write_text(submissions_dir / f"{finding.get('id', 'finding')}.md", markdown)
            entries.append(entry)

        _write_text(
            staging / "butian_submissions.json",
            json.dumps(entries, ensure_ascii=False, indent=2),
        )
        if report_path.exists():
            shutil.copy2(report_path, staging / "report.md")

        readme = (
            "# 补天提交包说明\n\n"
            "1. 先阅读 report.md，确认每个漏洞的描述、证据和修复建议。\n"
            "2. butian_submissions.json 是按补天提交格式生成的结构化数据。\n"
            "3. submissions/ 目录为每条漏洞的补天格式 Markdown 文案。\n"
            "4. evidence/ 目录包含相关代码片段、截图和 HTTP 请求/响应原文，请在上传时作为附件提交。\n"
            "5. 请在补天平台中逐条手动提交，提交前再次确认目标属于授权范围。\n"
        )
        _write_text(staging / "README.md", readme)

        archive_base = package_dir / "hexhound_butian_submission"
        zip_path = archive_base.with_suffix(".zip")
        if zip_path.exists():
            zip_path.unlink()
        shutil.make_archive(str(archive_base), "zip", root_dir=staging)
        return zip_path.resolve()
