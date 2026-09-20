from __future__ import annotations

from typing import Any

WEB = "web漏洞"
IOT = "IoT漏洞"
ICS = "工控漏洞"
OS = "操作系统及通用软件漏洞"
CATEGORIES = {WEB, IOT, ICS, OS}


def _component_text(component: dict[str, Any]) -> str:
    if not component:
        return ""
    parts: list[str] = []
    name = str(component.get("name") or "").strip()
    version = str(component.get("version") or "").strip()
    fingerprint = str(component.get("fingerprint") or "").strip()
    if name:
        parts.append(name)
    if version:
        parts.append(f"版本 {version}")
    if fingerprint:
        parts.append(f"指纹 {fingerprint}")
    return " ".join(parts)


def _derive_name(finding: dict[str, Any], target_host: str) -> str:
    explicit = str(finding.get("vuln_name") or "").strip()
    if explicit:
        return explicit
    unit = str(finding.get("unit_name") or target_host or "目标系统").strip()
    vuln_type = str(finding.get("vuln_type") or "安全漏洞").strip()
    return f"{unit}存在{vuln_type}"


def build_butian_entry(finding: dict[str, Any], target_host: str = "") -> dict[str, str]:
    """把一条 HexHound finding 转成补天平台提交字段。"""
    category = str(finding.get("category") or WEB).strip()
    if category not in CATEGORIES:
        category = WEB
    component_text = _component_text(finding.get("component") or {})

    vuln_kind = str(finding.get("vuln_kind") or "").strip()
    if not vuln_kind:
        vuln_kind = "通用型" if category == OS or finding.get("vuln_number") else "事件型"
    entry: dict[str, str] = {
        "漏洞类别": category,
        "漏洞名称": _derive_name(finding, target_host),
        "漏洞类型（事件型/通用型）": vuln_kind,
        "具体漏洞类型": str(
            finding.get("platform_vuln_type") or finding.get("vuln_type") or ""
        ).strip(),
        "简要描述": str(
            finding.get("brief_description") or finding.get("description") or ""
        ).strip(),
        "详细细节": str(finding.get("detail") or finding.get("evidence") or "").strip(),
        "修复方案": str(finding.get("remediation") or "").strip(),
    }

    if category == WEB:
        entry["漏洞URL"] = str(finding.get("url") or "").strip()
    elif category in (IOT, ICS):
        entry["受影响的产品及版本"] = (
            str(finding.get("affected_product") or "").strip() or component_text
        )
    else:
        entry["受影响的组件及版本"] = (
            str(finding.get("affected_component") or "").strip() or component_text
        )
        vuln_number = str(finding.get("vuln_number") or "").strip()
        if vuln_number:
            entry["漏洞编号"] = vuln_number
    return entry


def attach_evidence_paths(
    entry: dict[str, str],
    code_paths: list[dict[str, Any]],
    screenshot_paths: list[dict[str, Any]],
    http_paths: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    """把提交包内证据文件路径追加到详细细节中。"""
    refs = [str(item.get("file") or "") for item in code_paths + screenshot_paths + (http_paths or [])]
    refs = [ref for ref in refs if ref]
    if not refs:
        return entry
    detail = entry.get("详细细节", "").rstrip()
    attachment_block = "\n\n证据附件：\n" + "\n".join(f"- {ref}" for ref in refs)
    entry["详细细节"] = detail + attachment_block
    return entry


def build_butian_markdown(
    entry: dict[str, str],
    code_paths: list[dict[str, Any]],
    screenshot_paths: list[dict[str, Any]],
    http_paths: list[dict[str, Any]] | None = None,
) -> str:
    """渲染单个补天提交条目的 Markdown 文本。"""
    lines = [
        f"# {entry.get('漏洞名称', '')}",
        "",
        f"- 漏洞类别：{entry.get('漏洞类别', '')}",
        f"- 漏洞类型（事件型/通用型）：{entry.get('漏洞类型（事件型/通用型）', '')}",
        f"- 具体漏洞类型：{entry.get('具体漏洞类型', '')}",
    ]
    for key in (
        "漏洞URL",
        "受影响的产品及版本",
        "受影响的组件及版本",
        "漏洞编号",
    ):
        if entry.get(key):
            lines.append(f"- {key}：{entry[key]}")
    lines += [
        "",
        "## 简要描述",
        "",
        entry.get("简要描述", ""),
        "",
        "## 详细细节",
        "",
        entry.get("详细细节", ""),
        "",
        "## 修复方案",
        "",
        entry.get("修复方案", ""),
    ]
    attachments = [str(item.get("file") or "") for item in code_paths + screenshot_paths + (http_paths or [])]
    attachments = [item for item in attachments if item]
    if attachments:
        lines += [
            "",
            "## 证据附件",
            "",
            *[f"- {item}" for item in attachments],
        ]
    lines.append("")
    return "\n".join(lines)
