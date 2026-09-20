"""报告渲染：Markdown 与 JSON 两种输出。

v0.2 的报告结构（对标 Strix 的 findings/coverage 分离与 PentAGI 的层级视图）：

1. **元信息**：目标、模式、耗时、token、费用、任务台账、去重统计；
2. **结论区**：已复核漏洞（verified）与待复核候选（candidate）**分开列**——
   「疑似」不能和「成立」混在一起，这是 Strix「只上报可复现漏洞」的落点；
3. **每条漏洞**：证据编号、复核方式、反证、CVSS/OWASP/CWE、可复现 PoC 路径、
   HTTP 原文、截图、代码证据；
4. **覆盖矩阵**：OWASP 各类别命中数 + 覆盖面明细（含"测过没问题"的负面结论）；
5. **执行轨迹与任务台账**：哪个子代理做了什么、花了多少。
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from .agent import AgentResult
from .butian import build_butian_entry
from .diff import build_diff_from_memory, render_diff_markdown
from .sanitize import sanitize_terminal_text


def build_diff(result: AgentResult):
    """用跨运行记忆 + 本次结果 + 本次覆盖到的端点，构建 diff。

    覆盖集合来自攻面的 attempts/findings/coverage——**只有本次确实碰过的端点才允许
    判断"已修复"**，没碰过的一律记 unknown（"没测到"不等于"修好了"）。
    """
    previous = getattr(result, "previous_findings", None) or []
    if not previous:
        return None
    surface = result.surface
    touched = surface.touched_endpoints() if surface is not None else set()
    # "本次仍观察到问题"的端点：入库的 finding ∪ 覆盖记录里标了 reported 的端点。
    # 少了后半部分，模型"记了覆盖但没写 finding"的位置会被误判成"疑似已修复"（实测踩过）。
    still = surface.reported_endpoints() if surface is not None else set()
    return build_diff_from_memory(
        previous,
        result.findings or [],
        touched_endpoints=touched,
        still_affected=still,
        target=str(surface.target if surface else ""),
        previous_at=getattr(result, "previous_run_at", "") or "",
    )

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "⚪",
}

# 补天 / 国内 SRC 通用等级命名。
SEVERITY_BUTIAN = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "低危",
}

STATUS_LABEL = {
    "verified": "已复核（有证据可复现）",
    "candidate": "待复核（疑似，未确认可复现）",
}

COVERAGE_LABEL = {
    "reported": "已报漏洞",
    "no_issue_found": "测过未发现",
    "ruled_out": "已排除",
    "not_tested": "未测试",
    "blocked": "受阻无法测试",
}

_OWASP_TITLES = {
    "A01": "访问控制失效",
    "A02": "加密失败",
    "A03": "注入",
    "A05": "安全配置错误",
    "A06": "脆弱组件",
    "A07": "认证失效",
    "A10": "SSRF",
}

#: 补齐覆盖矩阵里"该测但没测"的 OWASP 类别（黑盒可测项）。
_OWASP_EXPECTED = ("A01", "A02", "A03", "A05", "A06", "A07", "A10")


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _cell(text: object) -> str:
    """把单元格内容压成单行并转义 markdown 表格分隔符。"""
    return str(text).replace("\n", " ").replace("|", "/")


def _format_raw_request(exchange: dict) -> str:
    """把一次请求快照渲染成 HTTP 请求原文。"""
    parsed = urlparse(exchange.get("url", ""))
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    lines = [f"{exchange.get('method', 'GET')} {target} HTTP/1.1", f"Host: {parsed.netloc}"]
    for key, value in exchange.get("request_headers", {}).items():
        if key.lower() == "host":
            continue
        lines.append(f"{key}: {value}")
    body = exchange.get("request_body", "")
    if body:
        lines += ["", body]
    return "\n".join(lines)


def _format_raw_response(exchange: dict) -> str:
    """把一次响应快照渲染成 HTTP 响应原文。"""
    lines = [f"HTTP/1.1 {exchange.get('status_code', 0)} {exchange.get('reason', '')}"]
    for key, value in exchange.get("response_headers", {}).items():
        lines.append(f"{key}: {value}")
    body = exchange.get("response_body", "")
    if body:
        lines += ["", body]
    return "\n".join(lines)


def _http_evidence_lines(label: str, block: str, collapse_chars: int = 5000) -> list[str]:
    """渲染一段 HTTP 原文；超过阈值时用 <details> 折叠，避免报告过长。"""
    if len(block) <= collapse_chars:
        return [label, "```http", block, "```"]
    summary = f"<details><summary>点击展开完整 HTTP 原文（{len(block)} 字符）</summary>"
    return [label, summary, "", "```http", block, "```", "", "</details>"]


def to_json(result: AgentResult, goal: str) -> dict:
    """结构化 JSON 报告（含任务台账、覆盖矩阵与统计）。

    工具证据的 `command` / `output` / `script` 也会清洗：JSON 里 `\\u001b` 虽然是
    合法转义，但下游（GUI 展示、补天提交包、编辑器）拿到它就是乱码。
    清洗发生在**副本**上，`result.tool_log` 本身保持原样——
    调用方可能还要拿它做别的渲染，不该在这里产生副作用。
    """
    findings = result.findings or []
    verified = [item for item in findings if item.get("status") != "candidate"]
    candidates = [item for item in findings if item.get("status") == "candidate"]
    surface = result.surface
    diff = build_diff(result)
    return {
        "goal": goal,
        "generated_at": _now(),
        "total_steps": len(result.steps),
        "steps_used": result.steps_used,
        "finish_reason": result.finish_reason,
        "prompt_tokens": result.prompt_tokens,
        "completion_tokens": result.completion_tokens,
        "cache_hit_tokens": result.cache_hit_tokens,
        "cache_miss_tokens": result.cache_miss_tokens,
        "estimated_cost": round(result.estimated_cost, 6),
        "total_tokens": result.total_tokens,
        "verified_count": len(verified),
        "candidate_count": len(candidates),
        "deduped": result.deduped,
        "findings": findings,
        "verified_findings": verified,
        "candidate_findings": candidates,
        "tasks": result.tasks,
        "artifacts_dir": result.artifacts_dir,
        "poc_paths": result.poc_paths,
        "sandbox": result.sandbox,
        "tool_log": [_clean_tool_entry(entry) for entry in (result.tool_log or [])],
        "surface_stats": surface.stats() if surface else {},
        "coverage": surface.coverage_summary() if surface else {},
        "coverage_detail": surface.coverage_lines(200) if surface else [],
        "coverage_gate": result.coverage_gate,
        "diff": diff.to_dict() if diff else None,
        "owasp_coverage": surface.covered_owasp() if surface else {},
        "final_summary": _clean(result.final_summary),
        "steps": [_clean_step(step) for step in (result.steps or [])],
        # 可审计轨迹摘要（本体在 run 目录的 trace.jsonl 里）
        "trace_summary": dict(result.trace_summary or {}),
    }


#: 工具证据里需要清洗的字段（其余字段是数字/短标识，不需要动）。
_TOOL_TEXT_FIELDS = ("command", "original_command", "output", "script", "stdout", "stderr", "error")


def _clean_tool_entry(entry: dict) -> dict:
    """复制一条工具证据并清洗其文本字段。"""
    if not isinstance(entry, dict):
        return entry
    cleaned = dict(entry)
    for field in _TOOL_TEXT_FIELDS:
        if field in cleaned and cleaned[field]:
            cleaned[field] = sanitize_terminal_text(str(cleaned[field]))
    return cleaned


def _clean_step(step: dict) -> dict:
    """复制一条执行轨迹并清洗其文本字段（思考/观察都是模型与工具产出的原文）。"""
    if not isinstance(step, dict):
        return step
    cleaned = dict(step)
    for field in ("thought", "observation"):
        if cleaned.get(field):
            cleaned[field] = sanitize_terminal_text(str(cleaned[field]))
    return cleaned


def _clean(text: object) -> str:
    """报告里的自由文本统一清洗：剥掉终端控制序列并归一换行。

    报告是给人读的。真工具输出里的 SGR 配色、`\\x1b[?1049h`、裸 `\\r`
    在 Markdown 里只会变成乱码（HANDOVER §7 记录的已知缺陷）。
    """
    return sanitize_terminal_text(str(text or "")).strip()


def _tool_output_lines(entry: dict, *, collapse_chars: int) -> list[str]:
    """渲染一条工具输出；超长时折叠，但**字符数按清理后计**。

    统计口径必须与显示内容一致：先清理再判断长度，否则控制序列会把
    "3000 字符"的阈值提前触发，读者看到的实际内容比标称的少。

    有溢写记录时额外给一行"完整输出去哪了"——句柄、原始大小、sha256。
    否则读者看到被截断的输出会以为那就是全部（这正是 spill 要解决的问题）。
    """
    lines: list[str] = []
    spill = entry.get("spill") or {}
    if spill:
        handle = str(spill.get("handle") or "")
        lines.append(
            f"> **完整输出已保存**：`{handle}` · 原文 {spill.get('original_size', 0)} 字节 / "
            f"{spill.get('total_chars', 0)} 字符 · {spill.get('lines', 0)} 行 · "
            f"sha256 `{str(spill.get('sha256') or '')[:16]}…`"
            + ("（**本条超单条上限，保存的是头尾**）" if spill.get("truncated") else "")
        )
        if spill.get("note"):
            lines.append(f"> ⚠ {spill['note']}")
        lines.append("")
    output = _clean(entry.get("output"))
    if not output:
        return lines
    if len(output) > collapse_chars:
        lines += [
            f"<details><summary>工具输出（{len(output)} 字符，点击展开）</summary>",
            "",
            "```",
            output,
            "```",
            "",
            "</details>",
            "",
        ]
    else:
        lines += ["```", output, "```", ""]
    return lines


def _tool_command_block(entry: dict) -> list[str]:
    """渲染一条真工具命令；有地址映射时把原始目标写成注释，避免读者误判。

    自定义脚本（sandbox_script）走单独分支：读者要看的是**脚本本身**——
    并发怎么发的、伪造令牌怎么签的，光给一条 base64 启动命令等于没给证据。

    文本一律经 `sanitize_terminal_text` 清洗：真工具的命令回显里可能带
    ANSI/OSC 序列（sqlmap 的 `\\x1b[?1049h` 就出现在 stderr 里），
    报告是给人读的，控制序列在 Markdown 里就是乱码。
    """
    script = sanitize_terminal_text(str(entry.get("script") or ""))
    command = sanitize_terminal_text(str(entry.get("command") or ""))
    original = sanitize_terminal_text(str(entry.get("original_command") or ""))
    if script:
        lines = ["```python", script.rstrip(), "```"]
        # 只有**确实发生过地址映射**时才加说明。脚本正文的第一行不是"原始目标"——
        # 早先按 original_command 渲染会写出「原始目标：import requests」这种废话。
        if entry.get("mapped"):
            lines += [
                "",
                "> 脚本里的回环地址在沙箱内已映射为宿主可达地址"
                "（沙箱与目标不在同一个网络命名空间）。",
            ]
        return lines
    lines: list[str] = ["```bash"]
    if original and original != command:
        lines.append(f"# 原始目标：{original}")
        lines.append("# 沙箱在独立网络命名空间内，回环地址已自动映射为宿主可达地址")
    lines.append(command)
    lines.append("```")
    return lines


def _finding_section(finding: dict, goal: str, index: int) -> list[str]:
    """渲染单条漏洞（含补天字段、证据、反证与 PoC）。"""
    severity = finding.get("severity", "")
    emoji = SEVERITY_EMOJI.get(severity, "❓")
    butian_level = SEVERITY_BUTIAN.get(severity, "低危")
    status = str(finding.get("status") or "candidate")
    target_host = urlparse(str(finding.get("url") or "")).hostname or ""
    butian_entry = build_butian_entry(finding, target_host)
    lines = [
        f"### {emoji} {finding.get('id', '')}：{finding.get('title', '')}",
        "",
        f"- **状态**：{STATUS_LABEL.get(status, status)}"
        + (f"（复核人 {finding.get('verified_by')}）" if finding.get("verified_by") else ""),
        f"- **漏洞标题**：{finding.get('title', '')}",
        f"- **漏洞类型**：{finding.get('vuln_type', '') or '（请补填：SQL注入 / XSS / 越权 / SSRF / 信息泄露 …）'}",
        f"- **漏洞 URL**：{finding.get('url', '') or '（请补填受影响的完整 URL）'}",
        f"- **漏洞等级**：{butian_level}（severity: {severity}）",
    ]
    if finding.get("param"):
        lines.append(f"- **参数**：{finding['param']}")
    if finding.get("cvss_vector") or finding.get("cvss"):
        lines.append(
            f"- **CVSS**：{finding.get('cvss_vector') or ''} {finding.get('cvss') or ''}".strip()
        )
    if finding.get("owasp") or finding.get("cwe"):
        lines.append(
            f"- **分类**：{finding.get('owasp') or ''} {finding.get('cwe') or ''}".strip()
        )
    if finding.get("dedupe_key"):
        lines.append(f"- **去重指纹**：{finding['dedupe_key']}")
    if finding.get("merged_count") and int(finding["merged_count"]) > 1:
        lines.append(
            f"- **合并上报**：{finding['merged_count']} 次"
            + (f"（原编号 {', '.join(finding.get('duplicate_ids') or [])}）"
               if finding.get("duplicate_ids") else "")
        )
    lines += [
        f"- **漏洞描述**：{finding.get('description', '')}",
        f"- **漏洞证明 / 复现步骤**：{finding.get('evidence', '')}",
    ]
    if finding.get("verification"):
        lines.append(f"- **复核方式**：{finding['verification']}")
    if finding.get("confidence_rationale"):
        lines.append(f"- **置信度理由**：{finding['confidence_rationale']}")
    if finding.get("counterevidence"):
        lines.append(f"- **反证 / 未排除的可能**：{finding['counterevidence']}")
    if finding.get("severity_change_conditions"):
        lines.append(f"- **等级变化条件**：{finding['severity_change_conditions']}")
    if finding.get("poc_path"):
        lines.append(f"- **可复现 PoC**：`{finding['poc_path']}`")

    lines += ["", "#### 补天提交字段", ""]
    for key, value in butian_entry.items():
        if value:
            lines += [f"**{key}**：", value, ""]
    component = finding.get("component") or {}
    if component:
        lines += ["**利用到的组件**："]
        lines += [f"- {key}: {value}" for key, value in component.items()]
        lines.append("")
    code_evidence = finding.get("code_evidence", [])
    if code_evidence:
        lines += ["**相关代码**："]
        for item in code_evidence:
            lines.append(f"- {item.get('file', '')}:{item.get('start', '')}-{item.get('end', '')}")
            lines += ["```", item.get("snippet", ""), "```"]
        lines.append("")
    screenshots = finding.get("screenshot_evidence", [])
    if screenshots:
        lines += ["**截图证据**："]
        for shot in screenshots:
            mime = shot.get("mime_type", "image/png")
            data = shot.get("data_base64", "")
            label = shot.get("label") or shot.get("id", "截图")
            lines.append(f"![{label}](data:{mime};base64,{data})")
        lines.append("")
    for exchange in finding.get("http_evidence", []):
        lines += [""]
        lines += _http_evidence_lines(
            f"请求原文（{exchange.get('id', '')}）：", _format_raw_request(exchange)
        )
        lines += [""]
        lines += _http_evidence_lines(
            f"响应原文（{exchange.get('id', '')}）：", _format_raw_response(exchange)
        )

    # 真工具证据：这是"证明级"证据（sqlmap 的 payload/类型/DBMS、数据导出等）
    tool_evidence = finding.get("tool_evidence", [])
    if tool_evidence:
        lines += ["", "#### 真工具执行证据", ""]
        for entry in tool_evidence:
            tool = str(entry.get("tool") or "tool")
            status = "成功" if entry.get("exit_code") == 0 else f"退出码 {entry.get('exit_code')}"
            headline = (
                f"**{entry.get('id', '')}** · `{tool}` · {status}"
                f" · {entry.get('duration', 0)}s"
            )
            if entry.get("note"):
                headline += f" · {entry['note']}"
            lines += [headline, ""]
            command = str(entry.get("command") or "")
            if command:
                lines += _tool_command_block(entry)
                lines.append("")
            lines += _tool_output_lines(entry, collapse_chars=3000)
        lines += [
            "> 以上命令可在隔离执行环境（容器 / WSL）中直接重跑复现。",
            "",
        ]

    reproduce = finding.get("reproduce_commands") or []
    if reproduce and not tool_evidence:
        lines += ["", "**复现命令**：", ""]
        lines += ["```bash", *[str(item) for item in reproduce], "```", ""]
    lines += ["", f"**修复建议**：{finding.get('remediation', '')}", ""]
    return lines


def to_markdown(result: AgentResult, goal: str) -> str:
    """Markdown 报告。"""
    findings = result.findings or []
    verified = [item for item in findings if item.get("status") != "candidate"]
    candidates = [item for item in findings if item.get("status") == "candidate"]
    surface = result.surface
    stats = surface.stats() if surface else {}
    lines = [
        "# HexHound 安全审计报告",
        "",
        f"- 生成时间：{_now()}",
        f"- 审计目标：{goal}",
        f"- 模式：{getattr(surface, 'mode', '') or '-'}｜结束原因：{result.finish_reason or '-'}",
        f"- 子任务：{len(result.tasks)} 个｜执行步数：{result.steps_used or len(result.steps)}",
        (
            f"- 结论：已复核 {len(verified)} 条 / 待复核 {len(candidates)} 条"
            + (f"｜去重合并 {result.deduped} 条" if result.deduped else "")
        ),
        (
            f"- Token 消耗：输入 {result.prompt_tokens} / "
            f"输出 {result.completion_tokens} / 总计 {result.total_tokens} / "
            f"缓存命中 {result.cache_hit_tokens} / 未命中 {result.cache_miss_tokens}"
        ),
        f"- 预估费用：¥{result.estimated_cost:.6f}",
    ]
    if stats:
        lines.append(
            "- 攻面：端点 {endpoints} 个｜表单 {forms} 个｜尝试 {attempts} 次"
            "（命中信号 {signals}）｜覆盖记录 {coverage} 条".format(**stats)
        )
    if result.artifacts_dir:
        lines.append(f"- 运行产物目录：`{result.artifacts_dir}`")

    # 覆盖率闸门：把"扫了多少、漏了多少"钉在报告开头，不允许静默
    gate = result.coverage_gate or {}
    if gate.get("total"):
        total = int(gate.get("total") or 0)
        touched = int(gate.get("touched") or 0)
        untouched = int(gate.get("untouched") or 0)
        ratio = float(gate.get("ratio") or 0.0)
        lines.append(
            f"- 端点覆盖：**{touched}/{total}**（{ratio:.0%}）"
            + (f"｜**{untouched} 个端点从未被触碰**" if untouched else "｜无盲区")
        )
    if gate.get("params_total"):
        p_total = int(gate["params_total"])
        p_tried = int(gate.get("params_attempted") or 0)
        p_left = int(gate.get("params_unattacked") or 0)
        lines.append(
            f"- 参数覆盖：**{p_tried}/{p_total}**（{float(gate.get('params_ratio') or 0):.0%}）"
            + (f"｜**{p_left} 个参数从未被攻击过**" if p_left else "｜无盲区")
        )

    # 真工具能力：必须让读者一眼看出这次是"完整能力"还是"仅 HTTP 探测"
    sandbox = result.sandbox or {}
    if sandbox:
        if sandbox.get("enabled"):
            tools = ", ".join(sandbox.get("tools", {}).keys()) or "（无）"
            lines.append(f"- 真工具沙箱：**已启用**（{sandbox.get('runtime', '?')}）｜已装工具：{tools}")
            if sandbox.get("host_gateway"):
                lines.append(f"  - 回环目标映射到宿主地址：{sandbox['host_gateway']}")
            if sandbox.get("exec_count"):
                lines.append(f"  - 本次执行真工具命令 {sandbox['exec_count']} 次")
        else:
            lines.append(
                f"- 真工具沙箱：**未启用/不可用**（{sandbox.get('reason', '未说明')}）"
                "——本次仅有内置 HTTP 探测能力，覆盖深度低于挂载真工具的运行"
            )
    lines.append("")

    # 跨运行对比：放在台账之前——"这次比上次好了还是坏了"是读者最先要看的结论之一
    diff = build_diff(result)
    if diff is not None and not diff.is_empty():
        lines += render_diff_markdown(diff)

    # API 合约导入单独成节：读者必须能看出"这次带了接口清单",
    # 以及"规范里声明的 servers 被忽略了"——否则会以为接口是爬出来的。
    api_summary = surface.api_spec_summary() if surface is not None else {}
    if api_summary.get("imports"):
        lines += ["## API 合约导入", ""]
        for entry in api_summary["imports"]:
            lines.append(
                f"- **{entry.get('spec_label') or '未知格式'}**"
                f"｜标题：{entry.get('title') or '（未命名）'}"
                f"｜来源：`{entry.get('source')}`"
                f"｜接口：{entry.get('operations')} 个"
            )
            if entry.get("security_schemes"):
                lines.append(
                    "  - 规范声明的认证方案：" + "、".join(entry["security_schemes"][:10])
                )
            if entry.get("declared_servers"):
                lines.append(
                    "  - ⚠ 规范里声明了 servers/host（"
                    + "、".join(f"`{item}`" for item in entry["declared_servers"][:5])
                    + "）——**这些值已被忽略**。所有接口都锚定到本次的 `--target`，"
                    "规范不能扩大授权范围。"
                )
            for note in entry.get("notes") or []:
                # servers/basePath 的说明上面已经渲染过一份（带实际值），
                # 这里跳过同义重复，避免报告里同一件事说两遍。
                if "已被忽略" in note:
                    continue
                lines.append(f"  - {note}")
            if entry.get("skipped"):
                lines.append(f"  - ⚠ 有 {len(entry['skipped'])} 条没能导入：")
                lines += [f"    - {item}" for item in entry["skipped"][:10]]
        lines += [
            "",
            f"导入的接口共 **{api_summary.get('endpoints', 0)}** 个端点、"
            f"**{api_summary.get('params', 0)}** 个已声明参数，"
            "已进入覆盖率闸门（导入 ≠ 已测试；未形成结论的会出现在下面的覆盖盲区里）。",
            "",
        ]

    if result.tasks:
        lines += ["## 子任务台账", "", "| 任务 | 角色 | 目标 | 状态 | 总结 |", "| --- | --- | --- | --- | --- |"]
        for task in result.tasks:
            lines.append(
                f"| {_cell(task.get('id'))} | {_cell(task.get('role'))} "
                f"| {_cell(str(task.get('objective'))[:80])} "
                f"| {_cell(task.get('outcome_label') or task.get('outcome'))} "
                f"| {_cell(str(task.get('summary') or task.get('error') or '')[:80])} |"
            )
        lines.append("")
        # 收尾方式单独说明：`closing_no_finish` 是"系统给了受限收尾回合才收的尾"，
        # 与"模型自己交的总结"含义不同，读者需要能区分（否则会高估模型的自律程度）。
        assisted = [
            task for task in result.tasks
            if str(task.get("outcome")) == "closing_no_finish"
        ]
        if assisted:
            lines += [
                f"> 其中 {len(assisted)} 个子任务（"
                + "、".join(str(task.get("id")) for task in assisted)
                + "）在正常步数用尽后，由**受限收尾回合**固化产出并代写了总结；"
                "它们的结论与其它任务同样有效，但日志中未主动收尾这一点如实保留。",
                "",
            ]

    # 可审计轨迹：回答"这次运行到底发生了什么"，而不是只有结论。
    # 轨迹本体在 run 目录的 trace.jsonl 里；这里放摘要与定位信息。
    trace = result.trace_summary or {}
    if trace:
        lines += ["## 运行轨迹（可离线审计）", ""]
        lines.append(
            f"- 事件总数：**{trace.get('events', 0)}**"
            f"｜schema v{trace.get('schema_version', 0)}"
            f"｜子任务：{len(trace.get('tasks') or [])} 个"
        )
        kinds = trace.get("kinds") or {}
        if kinds:
            lines.append(
                "- 事件构成：" + "、".join(f"{name}×{count}" for name, count in sorted(kinds.items()))
            )
        tools = trace.get("tools") or {}
        if tools:
            # 措辞要准确：这里是**所有**工具调用（含内置 HTTP 工具与沙箱真工具），
            # 早先写成"真工具调用"会让人以为 sqlmap/nmap 跑了这么多次。
            lines.append(
                "- 工具调用（含内置探测工具）："
                + "、".join(f"{name}×{count}" for name, count in tools.items())
            )
        actions = trace.get("actions") or {}
        if actions:
            lines.append(
                "- 动作分布：" + "、".join(f"{name}×{count}" for name, count in actions.items())
            )
        if result.artifacts_dir:
            lines.append(
                f"- 轨迹文件：`{result.artifacts_dir}/trace.jsonl`"
                "（每行一个事件，含模型步骤、工具调用、参数摘要、证据引用；"
                "敏感字段已掩码）"
            )
            lines.append(
                f"- 重建快照：`{result.artifacts_dir}/snapshot.json`"
                "（`hexhound report --run <目录>` 从这里离线重渲染，不访问目标、不调用模型）"
            )
        lines += [
            "",
            "> 轨迹只记录**摘要**（观察截断、命令截断），完整原文在工具证据与溢写存储里，"
            "按编号/句柄回查。这样做是为了让轨迹本身足够小、可以长期保留。",
            "",
        ]

    lines += ["## 已复核漏洞", ""]
    if not verified:
        lines.append("无已复核漏洞（候选结论见下节；仅凭疑似信号不入库，这是刻意设计）。")
        lines.append("")

    # 覆盖盲区单独成节：读者不该在"结论区"看不到的地方才发现还有没测的端点/参数
    if gate.get("untouched") or gate.get("params_unattacked"):
        lines += ["## ⚠ 覆盖盲区（本轮没测到的地方）", ""]
        if gate.get("untouched"):
            lines += [
                f"### 端点未触碰：{gate['untouched']} 个",
                "",
                "以下端点在本轮**没有被请求过**（可能因为步数/预算耗尽，或补扫未覆盖到）。"
                "**它们不代表安全**，请人工跟进或加大预算重跑：",
                "",
            ]
            lines += [f"- {item}" for item in gate.get("untouched_sample") or []]
            lines += [""]
        if gate.get("params_unattacked"):
            lines += [
                f"### 参数未攻击：{gate['params_unattacked']} 个"
                f"（共 {gate.get('params_total', 0)} 个已登记参数）",
                "",
                "以下参数**被读过、但从没被真正攻击过**（没有 SQL/命令/模板注入/穿越/XSS 的尝试记录）。"
                "端点级覆盖会把这类面算成「已覆盖」，所以它比端点盲区更隐蔽——"
                "实际案例：`/ping?ip=`（命令注入）与 `/ssti?name=`（模板注入）在侦察阶段就被发现，"
                "却因为没人试过参数而完全没被测试：",
                "",
            ]
            lines += [f"- {item}" for item in gate.get("unattacked_sample") or []]
            lines += [""]
        lines += [""]

    for index, finding in enumerate(verified, 1):
        lines += _finding_section(finding, goal, index)

    if candidates:
        lines += [
            "## 待复核候选（疑似，尚未确认可复现）",
            "",
            "> 这些结论**没有**通过复核门：请人工按证据编号重放请求确认后再决定是否提交。",
            "",
            "| 编号 | 严重度 | 标题 | URL | 参数 | 指纹 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for finding in candidates:
            lines.append(
                f"| {_cell(finding.get('id'))} | {_cell(finding.get('severity'))} "
                f"| {_cell(str(finding.get('title'))[:60])} | {_cell(finding.get('url'))} "
                f"| {_cell(finding.get('param'))} | {_cell(finding.get('dedupe_key'))} |"
            )
        lines.append("")

    # 同根因提示：同一路径上的多条漏洞往往只是同一处代码缺陷的不同参数/不同 payload，
    # 提交平台可能判重。这里只做**提示**，不替使用者合并（合并需要人工判断修复位置）。
    groups: dict[str, list[dict]] = {}
    for finding in verified:
        key = str(finding.get("dedupe_key") or "")
        if not key:
            continue
        path_key = "|".join(key.split("|")[:2])
        groups.setdefault(path_key, []).append(finding)
    same_root = {key: items for key, items in groups.items() if len(items) > 1}
    if same_root:
        lines += [
            "## 同根因提示（可能被提交平台判重）",
            "",
            "以下条目落在同一个规范化路径与同类漏洞上，很可能修复点是同一处代码：",
            "",
        ]
        for key, items in sorted(same_root.items()):
            names = "、".join(f"{item.get('id')}（参数 {item.get('param') or '-'}）" for item in items)
            lines.append(f"- `{key}` → {names}")
        lines.append("")

    # 覆盖矩阵
    covered = surface.covered_owasp() if surface else {}
    if covered:
        lines += ["## OWASP 覆盖矩阵", "", "| 类别 | 说明 | 已复核漏洞数 |", "| --- | --- | --- |"]
        for code in _OWASP_EXPECTED:
            mark = covered.get(code, 0)
            lines.append(f"| {code} | {_OWASP_TITLES.get(code, '')} | {mark or '—'} |")
        lines.append("")
    coverage_lines = surface.coverage_lines(60) if surface else []
    if coverage_lines:
        lines += ["## 覆盖面明细（含「测过没问题」的负面结论）", ""]
        lines += [f"- {item}" for item in coverage_lines]
        lines.append("")

    lines += [
        "## 执行轨迹",
        "",
        "| 任务 | 步 | 动作 | 思考 | 观察（截断） |",
        "| --- | --- | --- | --- | --- |",
    ]
    for step in result.steps:
        lines.append(
            f"| {_cell(step.get('task', step.get('worker', '')))} "
            f"| {_cell(step.get('step', ''))} "
            f"| {_cell(step.get('action', ''))} "
            f"| {_cell(step.get('thought', ''))} "
            f"| {_cell(step.get('observation', ''))[:120]} |"
        )

    # 真工具执行附录：这是"证明级"证据的来源，单独成节便于复核
    if result.tool_log:
        lines += [
            "",
            "## 真工具执行记录",
            "",
            "以下命令在隔离执行环境（容器 / WSL）内运行，是工具级证据的来源。"
            "**编号与 finding 里引用的 `T` 编号一致**，可直接按编号回查：",
            "",
        ]
        for entry in result.tool_log[:40]:
            tool = _cell(entry.get("tool") or "tool")
            status = "成功" if entry.get("exit_code") == 0 else f"退出码 {entry.get('exit_code')}"
            purpose = str(entry.get("note") or "").strip()
            headline = f"**{entry.get('id', '')}** · `{tool}` · {status} · {entry.get('duration', 0)}s"
            if purpose and purpose not in ("sandbox_script", "raw"):
                headline += f" · {_cell(purpose[:80])}"
            lines += [headline, "", *_tool_command_block(entry), ""]
            lines += _tool_output_lines(entry, collapse_chars=2000)

    lines += [
        "",
        "## 总结",
        "",
        result.final_summary or "(无)",
        "",
        "---",
        "",
        "> 本报告由 HexHound 自动生成，仅用于授权测试与自建靶场，请勿用于未授权目标。",
        "",
    ]
    return "\n".join(lines)


def write_report(result: AgentResult, goal: str, path: str | Path) -> Path:
    """按扩展名分派渲染器写报告，自动创建父目录。"""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.suffix.lower() == ".json":
        content = json.dumps(to_json(result, goal), ensure_ascii=False, indent=2)
    else:
        content = to_markdown(result, goal)
    target.write_text(content + "\n", encoding="utf-8")
    return target
