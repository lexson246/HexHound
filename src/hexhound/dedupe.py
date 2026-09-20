"""漏洞去重：把「同一处根因」的重复上报折叠成一条。

对标 Strix / PentAGI 的 findings 去重：多个子代理并行时必然会重复上报
（不同 worker 打同一个 ?id= 参数会各自记一条 SQL 注入），需要在入库前折叠。

指纹策略（三级，逐级放宽）：
1. `(vuln_class, path, param)` —— 最强：同路径同参数同类漏洞视为重复；
2. `(vuln_class, path)`       —— 参数未知（如未授权访问整页）时按路径合并；
3. 无 URL 的（如"缺少安全头"）按 `(vuln_class, host_or_target)` 合并。

`vuln_class` 由漏洞类型/标题关键词归类，`path` 用 surface.normalize_path 归一，
因此 `/user/1` 与 `/user/2` 会被视为同一处 IDOR（符合"同一根因"的直觉）。
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from .surface import SEVERITY_RANK, host_of, normalize_path, param_names

# 关键词 → 漏洞类别。顺序敏感：先匹配到的类别胜出。
_CLASS_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sqli", ("sql", "sqli", "注入点", "数据库注入")),
    ("cmd", ("命令注入", "命令执行", "rce", "code execution", "command injection")),
    ("ssti", ("ssti", "模板注入", "template injection")),
    # ssrf 必须排在 path_traversal 之前：实测标题 "SSRF（支持 file:// 任意文件读取）"
    # 同时命中两边，若按路径穿越归类，跨运行 diff 会把它与本次的 ssrf 记录判成两条，
    # 从而谎报"疑似已修复"。协议类漏洞优先于"它读到了什么文件"。
    ("ssrf", ("ssrf", "服务端请求伪造", "server-side request")),
    ("path_traversal", ("目录遍历", "路径穿越", "目录穿越", "path traversal", "directory traversal", "任意文件读")),
    ("idor", ("idor", "越权", "未授权访问", "访问控制", "水平越权", "垂直越权", "broken access")),
    ("xss", ("xss", "跨站脚本", "跨站")),
    ("auth", ("弱口令", "默认凭据", "默认口令", "认证绕过", "暴力破解", "会话固定")),
    ("info_leak", ("信息泄露", "信息泄漏", "敏感信息", "报错泄露", "版本泄露", "错误页面", "源码泄露")),
    ("misconfig", ("配置错误", "安全头", "cors", "加固", "misconfiguration", "缺少")),
    ("component", ("组件", "cve", "版本漏洞", "已知漏洞", "脆弱组件")),
    ("csrf", ("csrf", "跨站请求伪造")),
    ("upload", ("上传", "upload")),
    ("redirect", ("跳转", "redirect", "开放重定向")),
)

# 参数名里的常见对象标识（用于 IDOR 归一）。
_ID_PARAM = re.compile(r"(?i)^(id|uid|user_?id|order_?id|pid|gid|no|num|key|uuid|account)$")

_WORD_SPLIT = re.compile(r"[\s/|,，、;；:：()（）\[\]{}]+")


def vuln_class(finding: dict[str, Any]) -> str:
    """把一条 finding 归到稳定的漏洞类别（用于去重与报告分组）。"""
    text = " ".join(
        str(finding.get(key) or "")
        for key in ("vuln_type", "platform_vuln_type", "title", "category", "description")
    ).lower()
    for name, tokens in _CLASS_RULES:
        if any(token in text for token in tokens):
            return name
    words = [w for w in _WORD_SPLIT.split(text) if w]
    return words[0][:16] if words else "unknown"


def _primary_param(finding: dict[str, Any]) -> str:
    """确定参与指纹的参数名：显式 param 优先，其次 URL query，最后 URL 里的 {n} 段。"""
    explicit = str(finding.get("param") or "").strip()
    if explicit:
        return explicit.lower()
    url = str(finding.get("url") or "")
    names = param_names(url)
    if names:
        return names[0].lower()
    if "{n}" in normalize_path(url):
        return "{id}"
    return ""


def dedupe_key(finding: dict[str, Any]) -> str:
    """计算去重指纹。"""
    cls = vuln_class(finding)
    url = str(finding.get("url") or "").strip()
    if not url:
        target = str(finding.get("target") or finding.get("unit_name") or finding.get("host") or "-")
        return f"{cls}|-|{host_of(target) or target or '-'}"
    path = normalize_path(url)
    param = _primary_param(finding)
    if not param and not _ID_PARAM.search(path):
        return f"{cls}|{path}"
    return f"{cls}|{path}|{param}"


def _richness(finding: dict[str, Any]) -> tuple[int, int, int, int]:
    """比较两条重复 finding 谁更值得保留：证据 > 复核状态 > 严重度 > 描述长度。"""
    evidence_len = len(str(finding.get("evidence") or ""))
    verified = 1 if str(finding.get("status") or "") == "verified" else 0
    severity = -SEVERITY_RANK.get(str(finding.get("severity") or "info").lower(), 9)
    body_len = len(str(finding.get("description") or "")) + len(str(finding.get("remediation") or ""))
    return (evidence_len, verified, severity, body_len)


def dedupe_findings(findings: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """折叠重复 finding，返回 (去重后列表, 被合并数量)。

    保留证据最充分的一条；被合并的条数写进 `merged_count`，
    并记录 `duplicate_ids` 便于报告里说明"由 N 条上报合并"。
    """
    kept: dict[str, dict[str, Any]] = {}
    merged = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        item = dict(finding)
        key = str(item.get("dedupe_key") or dedupe_key(item))
        item["dedupe_key"] = key
        existing = kept.get(key)
        if existing is None:
            kept[key] = item
            continue
        merged += 1
        winner, loser = (
            (item, existing) if _richness(item) > _richness(existing) else (existing, item)
        )
        winner = dict(winner)
        winner["merged_count"] = int(winner.get("merged_count") or 1) + int(
            loser.get("merged_count") or 1
        )
        duplicate_ids = list(winner.get("duplicate_ids") or [])
        if loser.get("id"):
            duplicate_ids.append(str(loser["id"]))
        duplicate_ids.extend(loser.get("duplicate_ids") or [])
        winner["duplicate_ids"] = sorted(set(duplicate_ids))
        kept[key] = winner

    ordered = sorted(
        kept.values(),
        key=lambda f: (SEVERITY_RANK.get(str(f.get("severity") or "info").lower(), 9), str(f.get("id") or "")),
    )
    return ordered, merged


def merge_finding_dicts(groups: Iterable[Iterable[dict[str, Any]]]) -> tuple[list[dict[str, Any]], int]:
    """把多组 finding（如各子代理的产出）合并去重后返回。"""
    flat: list[dict[str, Any]] = []
    for group in groups:
        flat.extend(item for item in group if isinstance(item, dict))
    return dedupe_findings(flat)
