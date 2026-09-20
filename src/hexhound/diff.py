"""跨运行 diff：这次相比上次，新增了什么、修好了什么、还有什么没变。

为什么需要：HexHound 已经会跑 PoC 自校验（退出码 0/1/2），而 `HostMemory` 里存着
历次运行的 findings。把两者拼起来，就能回答甲方最关心的三个问题：

- **新增**（new）：本次才发现的问题
- **仍存在**（persisting）：上次报过、这次还在
- **疑似已修复**（fixed）：上次报过、本次的同指纹问题消失或 PoC 已判定不可复现
- **待确认**（unknown）：上次报过、本次没覆盖到对应端点（不能当成"已修复"）

**关键原则：不把"没测到"当成"已修复"。** 这是安全报告里最常见的误导——
所以 `unknown` 与 `fixed` 严格区分，且只有在**本次确实覆盖了该端点**时才敢说 fixed。

对标说明：Strix 与 PentAGI 都没有跨运行对比（PentAGI 连结构化漏洞模型都没有），
这一层是 HexHound 独有的——因为它的 finding 带确定性指纹，且 PoC 能自校验。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .dedupe import dedupe_key, vuln_class

#: 指纹前缀 → 人读的类别名（复用 dedupe 的分类规则）
_LABEL = {
    "sqli": "SQL 注入",
    "xss": "XSS",
    "cmd": "命令注入",
    "ssti": "模板注入",
    "path_traversal": "路径穿越",
    "ssrf": "SSRF",
    "idor": "越权/未授权",
    "auth": "认证问题",
    "info_leak": "信息泄露",
    "misconfig": "配置问题",
    "component": "脆弱组件",
    "csrf": "CSRF",
    "upload": "上传",
    "redirect": "开放重定向",
    "unknown": "其他",
}


def _label(fingerprint: str) -> str:
    return _LABEL.get(str(fingerprint).split("|", 1)[0], "其他")


def _coarse(fingerprint: str) -> str:
    """放宽到「类别 + 路径」，对齐 dedupe 的第二级指纹。

    为什么需要这层兜底：历史记忆是**旧版本写下的**（早期只存 id/title/url，
    没有 param 与 dedupe_key）。若只按完整指纹比对，POST 表单类漏洞
    （param 来自请求体、URL 里没有 query）在历史侧会算成 `sqli|/login`、
    在本次侧算成 `sqli|/login|username`，于是被误判成"本次未覆盖"，
    凭空多出一堆 unknown。放宽到类别+路径后，同一处根因仍能对上。
    """
    parts = str(fingerprint).split("|")
    return "|".join(parts[:2]) if len(parts) >= 2 else str(fingerprint)


def _endpoint_of(finding: dict[str, Any]) -> str:
    """取 finding 的归一化端点（不含 query），用于判断"本次是否覆盖了这个位置"。"""
    from .surface import normalize_endpoint

    url = str(finding.get("url") or "")
    return normalize_endpoint(url) if url else ""


@dataclass
class RunDiff:
    """两次运行之间的差异。"""

    target: str = ""
    previous_at: str = ""
    current_at: str = ""
    new: list[dict[str, Any]] = field(default_factory=list)
    persisting: list[dict[str, Any]] = field(default_factory=list)
    fixed: list[dict[str, Any]] = field(default_factory=list)
    unknown: list[dict[str, Any]] = field(default_factory=list)
    note: str = ""

    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "persisting": len(self.persisting),
            "fixed": len(self.fixed),
            "unknown": len(self.unknown),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "previous_at": self.previous_at,
            "current_at": self.current_at,
            "counts": self.counts(),
            "new": self.new,
            "persisting": self.persisting,
            "fixed": self.fixed,
            "unknown": self.unknown,
            "note": self.note,
        }

    def is_empty(self) -> bool:
        return not any((self.new, self.persisting, self.fixed, self.unknown))


def _entry(finding: dict[str, Any], status: str, reason: str = "") -> dict[str, Any]:
    fingerprint = str(finding.get("dedupe_key") or dedupe_key(finding))
    return {
        "status": status,
        "id": str(finding.get("id") or ""),
        "title": str(finding.get("title") or "")[:160],
        "severity": str(finding.get("severity") or ""),
        "type": _label(fingerprint),
        "url": str(finding.get("url") or ""),
        "fingerprint": fingerprint,
        # 该条在历次运行里的原始状态（verified/candidate），与 diff 状态区分开：
        # 上次只是"候选"的问题，本次仍出现也不该被读成"已确认漏洞"。
        "original_status": str(finding.get("status") or ""),
        # 记忆里记的上报时间：不同运行会复用 HH-00x 编号，只有时间能区分是哪一次。
        "reported_at": str(finding.get("at") or ""),
        "reason": reason,
    }


def diff_findings(
    previous: list[dict[str, Any]],
    current: list[dict[str, Any]],
    *,
    touched_endpoints: set[str] | None = None,
    still_affected: set[str] | None = None,
    target: str = "",
) -> RunDiff:
    """对比两次运行的 finding 列表。

    `touched_endpoints`：本次实际覆盖到的端点集合。判定顺序（**顺序本身就是正确性**）：

    1. 指纹精确相同 → `persisting`；
    2. 指纹不同但「类别+路径」相同 → `persisting`（历史条目常常缺 param）；
    3. 上次报过、本次消失，且该端点**本次仍报出问题** → `unknown`（不能判定修复）；
    4. 上次报过、本次消失，且该端点本次被覆盖过且无任何问题 → `fixed`；
    5. 其余（该端点本次没碰过）→ `unknown`。

    第 3 条是实测补上的：指纹不匹配不等于修好了，可能只是归类换了。
    `still_affected` 是"本次仍观察到问题"的端点（含**只有覆盖记录、没入库 finding** 的情况）——
    实测踩过：模型用 record_coverage(reported) 记了 /api/users 未授权却没写 finding，
    若只按 findings 判断，上一轮的同位置结论就会被误判成"疑似已修复"。
    """
    touched = {str(item) for item in (touched_endpoints or set())}
    still = {str(item) for item in (still_affected or set())}
    result = RunDiff(
        target=target,
        current_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    def fingerprint_of(item: dict[str, Any]) -> str:
        return str(item.get("dedupe_key") or dedupe_key(item))

    # 保序去重：同一指纹可能出现多次（旧记忆按 (id, title) 去重，指纹未必唯一）
    previous_items: list[dict[str, Any]] = []
    previous_fps: list[str] = []
    for item in previous:
        if not isinstance(item, dict):
            continue
        fp = fingerprint_of(item)
        if fp in previous_fps:
            continue
        previous_fps.append(fp)
        previous_items.append(item)
    previous_map = dict(zip(previous_fps, previous_items))

    current_items: list[dict[str, Any]] = []
    seen_current: set[str] = set()
    for item in current:
        if not isinstance(item, dict):
            continue
        fp = fingerprint_of(item)
        if fp in seen_current:
            continue
        seen_current.add(fp)
        current_items.append(item)

    previous_coarse: dict[str, list[str]] = {}
    for fp in previous_fps:
        previous_coarse.setdefault(_coarse(fp), []).append(fp)

    matched: set[str] = set()

    for item in current_items:
        fp = fingerprint_of(item)
        if fp in previous_map:
            matched.add(fp)
            result.persisting.append(_entry(item, "persisting", "上次已报过，本次仍在"))
            continue
        # 放宽匹配：同路径同类别（历史记录缺 param 时靠这层兜住）
        twin = next(
            (c for c in previous_coarse.get(_coarse(fp), []) if c not in matched), None
        )
        if twin is not None:
            matched.add(twin)
            result.persisting.append(
                _entry(item, "persisting", "上次报过同路径同类问题，本次仍复现（参数可能不同）")
            )
            continue
        result.new.append(_entry(item, "new", "本次新发现"))

    # 本次仍在报出问题的端点（与漏洞类别无关）。
    # 为什么要这层：实测踩过——历史条目写的是 "SSRF（支持 file:// 任意文件读取）"（旧归类
    # 算成路径穿越），本次同类问题归类为 ssrf，指纹对不上；若只看"端点碰过 + 指纹没出现"
    # 就判"疑似已修复"，就会把**仍然存在**的 SSRF 说成修好了——安全报告里最严重的错误方向。
    # 因此：该端点本次仍报出任何问题 → 一律降级为 unknown（可能是同一处根因换了归类）。
    current_endpoints = {
        endpoint for endpoint in (_endpoint_of(item) for item in current_items) if endpoint
    } | still

    for fp in previous_fps:
        if fp in matched:
            continue
        item = previous_map[fp]
        endpoint = _endpoint_of(item)
        # 顺序有讲究：先看"该端点本次仍报出问题"——它本身就是端点被碰过的证据，
        # 不依赖 touched 集合，且必须压过"已修复"的判定。
        if endpoint and endpoint in current_endpoints:
            result.unknown.append(
                _entry(
                    item, "unknown",
                    "本次该端点仍报出其他问题（同一处根因可能换了归类），"
                    "不能据此判定已修复",
                )
            )
        elif touched and endpoint and endpoint in touched:
            result.fixed.append(
                _entry(item, "fixed", "本次覆盖了该端点，但同指纹问题未再出现")
            )
        else:
            result.unknown.append(
                _entry(
                    item, "unknown",
                    "本次未覆盖该端点，无法判断是否已修复（**不要当作已修复**）",
                )
            )

    if result.unknown:
        result.note = (
            f"有 {len(result.unknown)} 条上次报过的问题本次**无法判定**：端点没被覆盖，"
            "或该端点本次仍报出其他问题。两种都不等于已修复，请按每条后面的说明处理。"
        )
    elif not previous:
        result.note = "没有历史运行记录，本次全部计为新增。"
    return result


def build_diff_from_memory(
    memory_findings: list[dict[str, Any]],
    current_findings: list[dict[str, Any]],
    *,
    touched_endpoints: set[str] | None = None,
    still_affected: set[str] | None = None,
    target: str = "",
    previous_at: str = "",
) -> RunDiff:
    """从 HostMemory 里读到的历史 findings 与本次结果构建 diff。"""
    diff = diff_findings(
        memory_findings, current_findings,
        touched_endpoints=touched_endpoints, still_affected=still_affected, target=target,
    )
    diff.previous_at = previous_at or "（历史记录，时间未知）"
    return diff


def render_diff_markdown(diff: RunDiff, limit: int = 20) -> list[str]:
    """把 diff 渲染成报告章节。"""
    if diff.is_empty():
        return []
    counts = diff.counts()
    lines = [
        "## 与上次运行的差异",
        "",
        f"- 上次运行：{diff.previous_at or '（无记录）'}",
        f"- 本次运行：{diff.current_at}",
        f"- 新增 **{counts['new']}** ｜仍存在 **{counts['persisting']}** ｜"
        f"疑似已修复 **{counts['fixed']}** ｜状态未知 **{counts['unknown']}**",
        "",
    ]
    if diff.note:
        lines += [f"> {diff.note}", ""]

    def block(title: str, items: list[dict[str, Any]], hint: str = "") -> None:
        if not items:
            return
        lines.append(f"### {title}（{len(items)}）")
        lines.append("")
        if hint:
            # 注意：必须用 extend 而不是 `lines += [...]`——后者会让 `lines` 变成
            # block 的局部变量（augmented assignment），外层列表反被遮蔽。
            lines.extend([f"> {hint}", ""])
        for item in items[:limit]:
            label = "候选" if item.get("original_status") == "candidate" else ""
            when = str(item.get("reported_at") or "")[:19]
            lines.append(
                f"- `{item['id']}` [{item['severity']}] {item['title']} "
                f"（{item['type']}{'/' + label if label else ''}）"
                f"{item['url'] or '（历史记录缺 URL）'}"
                + (f"｜上报于 {when}" if when else "")
                + (f" — {item['reason']}" if item.get("reason") else "")
            )
        if len(items) > limit:
            lines.append(f"- …（还有 {len(items) - limit} 条）")
        lines.append("")

    block("新增问题", diff.new, "本次才发现的，优先处理")
    block("仍然存在", diff.persisting, "上次已报、本次仍可复现")
    block("疑似已修复", diff.fixed, "本次覆盖了对应端点且问题未再出现——仍建议人工确认")
    block(
        "状态未知（不能判定为已修复）",
        diff.unknown,
        "**这些不是已修复**：对应端点本次没测到，或该端点仍报出其他问题；请按条目说明逐条处理",
    )
    return lines
