"""工具注册表与工具实现。

与 v0.1 的差别（对标 Strix / PentAGI）：

1. **按角色注册工具**：不再把所有工具塞给一个 agent。`role` 决定可见工具集
   （recon / injection / auth / verify / source / full），子代理只看得到自己该用的工具，
   减少误用与提示词噪音。
2. **接入共享攻面**：crawl / discover / enumerate / fuzz 的结果写进 `AttackSurface`，
   并发子代理不会重复爬同一页、重复打同一组 payload；已试过且无信号的组合会被跳过。
3. **候选 → 复核 → 入库**：`record_finding` 默认只登记「候选」；
   只有带真实请求证据并显式 `verified=true`（或复核子代理 promote）才进正式报告，
   对应 Strix「只上报能复现的漏洞」。
4. **工具输出结构化**：证据带全局唯一编号（W2-R3 形式），跨子代理不冲突；
   fuzz 命中返回「下一步该复现什么」的精确指令。
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import httpx

from . import knowledge as KB
from .dedupe import dedupe_key, vuln_class
from .memory import RunArtifacts
from .sanitize import sanitize_terminal_text
from .screenshot import capture_url
from .surface import (
    AttackSurface,
    Finding,
    SEVERITIES,
    host_of,
    normalize_endpoint,
    param_names,
    sort_urls,
)

# 目录遍历 / 审计时要跳过的目录与文件。
IGNORED_DIRS = {    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", ".env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    ".eggs", "build", "dist", ".idea", ".vscode", "reports",
}

# 常见源码 / 配置文件扩展名，用于 search_code 限定搜索范围。
SOURCE_EXTENSIONS = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".java",
    ".go", ".rb", ".php", ".c", ".h", ".cpp", ".cc", ".cs", ".sh", ".bash",
    ".sql", ".html", ".htm", ".xml", ".json", ".yaml", ".yml", ".toml",
    ".md", ".txt", ".cfg", ".ini", ".conf", ".env", ".properties",
}

# http_request 返回的关键响应头。
_KEY_HEADERS = {
    "content-type", "content-length", "location", "server", "set-cookie",
    "x-frame-options", "x-content-type-options", "www-authenticate",
    "x-powered-by", "access-control-allow-origin", "content-security-policy",
}

# 兼容旧引用（词表已迁到 knowledge.py）。
COMMON_PATHS = KB.COMMON_PATHS
FUZZ_PAYLOADS = KB.FUZZ_PAYLOADS
DEFAULT_CREDS = KB.DEFAULT_CREDS
SEVERITIES = set(SEVERITIES)

_REDIRECT_STATUS = {301, 302, 303, 307, 308}

# --- 工具输出治理（Governor）------------------------------------------------
# 对标 PentAGI 的 pkg/tools/executor.go：大输出不能原样进上下文，否则
# 「工具输出淹没上下文窗口」会直接吃掉后续推理能力（自述最痛的失败模式之一）。
# 这里的分档与 PentAGI 一致：≤16KB 原样；>16KB 走摘要（无 LLM 时退化为硬截断）；
# >32KB 头部 + 尾部保留中间省略；并给出继续读取的精确参数。
#
# 与 PentAGI 的区别（也是对标 Strix 的补强）：**被压缩掉的内容不丢**。
# 超过 16 KiB 时整段原文进本运行的 spill store，模型拿到一个 opaque 句柄，
# 可以用 `spill_read` 按 offset/limit 分页读回、或做字面量搜索。
# PentAGI 只做"摘要或截断"，Strix 落盘但只能靠通用 shell 读回；
# 这里两条都补上（见 spill.py 的说明）。
GOVERNOR_SMALL_LIMIT = 16 * 1024
GOVERNOR_HARD_LIMIT = 32 * 1024
GOVERNOR_KEEP_HEAD = 12 * 1024
GOVERNOR_KEEP_TAIL = 4 * 1024
GOVERNOR_ARG_LIMIT = 1024

#: 单条工具证据在报告/JSON 里内联保留的字符数；超出部分进溢写存储。
#: 与 `GOVERNOR_SMALL_LIMIT`（给模型的正文上限）分开：证据是给**人**看的，
#: 保留得比上下文多一点（12 KB 与 16 KB 同量级，够放完整 sqlmap 结论）。
EVIDENCE_OUTPUT_CHARS = 12_000

#: 连接阶段的超时上限（秒）。整体读超时仍由 REQUEST_TIMEOUT 控制，
#: 但"连不上"这件事不该等满 REQUEST_TIMEOUT——被防火墙静默丢弃的端口会一直挂着。
CONNECT_TIMEOUT_CAP = 5.0


# ---------------------------------------------------------------------------
# 通用工具函数
# ---------------------------------------------------------------------------


def _is_ignored_dir(name: str) -> bool:
    return name in IGNORED_DIRS or name.startswith(".") or name.endswith(".egg-info")


def _is_ignored_file(name: str) -> bool:
    return name.startswith(".") or name.endswith(".pyc") or name == ".DS_Store"


def _resolve_within(base: Path, sub: str) -> Path | None:
    """把 sub 解析到 base 目录内部，越界返回 None（防目录穿越）。"""
    try:
        base_resolved = base.resolve()
        candidate = (base / sub).resolve()
        candidate.relative_to(base_resolved)
    except (OSError, ValueError):
        return None
    return candidate


def _spill_prefix() -> str:
    """溢写句柄前缀（延迟读，避免模块级循环依赖）。"""
    from .spill import HANDLE_PREFIX

    return HANDLE_PREFIX


def _summarize_args(action_input: dict[str, Any], limit: int = 400) -> str:
    """把工具参数压成一行摘要，用于 trace（不是给模型看的，是给审计看的）。

    用 `json.dumps(..., sort_keys=True)` 而不是 `str(dict)`：
    前者在同一次运行的两次相同调用之间产生**完全一致**的字符串，
    于是"模型是不是在用同样的参数重复调用"这件事可以直接比对。
    """
    try:
        text = json.dumps(action_input, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = str(action_input)
    if len(text) > limit:
        return text[:limit] + f"…(共 {len(text)} 字符)"
    return text


def _validate_url(ctx: "ToolRegistry", url: str) -> tuple[Any, str | None]:
    """校验 URL 的主机白名单与协议，返回 (parsed, 错误信息)。"""
    return validate_url_against(url, ctx.allowed_hosts)


def validate_url_against(url: str, allowed_hosts: Any) -> tuple[Any, str | None]:
    """`_validate_url` 的**无上下文**版本：只按给定的白名单校验。

    为什么单独抽一个：API 规范导入（`apispec.load_spec_source` / 远程 `$ref`）
    需要在**没有工具注册表**的地方做同一套校验。复制一份判断逻辑迟早会漂移
    （一处改了另一处忘），所以两边共用这一个实现——
    "规范 URL 与目标请求走同一份范围校验"必须是真的同一份。
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return parsed, f"错误：无法从 URL 解析主机：{url}"
    if host not in allowed_hosts:
        allowed = ", ".join(sorted(allowed_hosts))
        return parsed, f"拒绝：主机 {host!r} 不在白名单（{allowed}）内，已阻止该请求。"
    if parsed.scheme not in ("http", "https"):
        return parsed, f"拒绝：不支持的协议 {parsed.scheme!r}。"
    return parsed, None


@dataclass(frozen=True)
class Tool:
    """一个可被 agent 调用的工具。"""

    name: str
    description: str
    func: Callable[[dict[str, Any]], str]
    roles: tuple[str, ...] = ()  # 空表示所有角色可用


def _truncate_args(args: dict[str, Any]) -> dict[str, Any]:
    """把超长参数值截断（对应 PentAGI 的 maxArgValueLength=1024）。

    防止 LLM 把整页 HTML 塞进参数里：既浪费上下文，也会让工具报错难读。
    """
    cleaned: dict[str, Any] = {}
    for key, value in args.items():
        if isinstance(value, str) and len(value) > GOVERNOR_ARG_LIMIT:
            cleaned[key] = (
                value[:GOVERNOR_ARG_LIMIT]
                + f"…(参数过长已截断，原长 {len(value)} 字符)"
            )
        elif isinstance(value, list) and len(value) > 50:
            cleaned[key] = value[:50] + [f"…(共 {len(value)} 项，仅保留前 50)"]
        else:
            cleaned[key] = value
    return cleaned


def _govern(name: str, result: Any, ctx: "ToolRegistry | None" = None) -> tuple[str, dict[str, Any]]:
    """工具输出治理：返回 (给 LLM 的文本, 结构化结果)。

    结构化结果保留完整数据（报告与统计用），文本按体积分档压缩。

    **清理在裁剪之前**：先剥掉 ANSI/OSC 与裸 `\\r`，再判断体积。
    顺序反了会导致"控制序列撑大了体积、真正的结论被截掉"——
    真工具输出里塞满 SGR 配色时，这几十个字节足以把结论行挤出保留窗口。

    **超过单次正文上限时把整段原文存进 spill store**，并在给模型的文本里
    附上 opaque 句柄与读回方法。这样"上下文有界"与"证据不丢"同时成立：
    模型想看的细节一定读得到，但不会因为一次 `read_urls` 就把上下文塞满。
    """
    if isinstance(result, dict) and "llm" in result:
        text = str(result.get("llm") or "")
        structured = result
    else:
        text = str(result)
        structured = {"llm": text}
    text = sanitize_terminal_text(text)
    if len(text) <= GOVERNOR_SMALL_LIMIT:
        return text, structured

    total = len(text)
    # 原文整段进溢写（存的是清理后的可读版本；原始大小与 sha256 记在元数据里）。
    notice = ""
    if ctx is not None:
        entry = ctx.spill(text, label=name, reasons=["governor_compressed"])
        if entry.stored_bytes:
            notice = (
                f"\n[完整输出已保存] 句柄 {entry.handle}"
                f"（{entry.total_chars} 字符 / {entry.original_bytes} 字节，"
                f"sha256 {entry.sha256[:16]}…）。\n"
                f"  读回方式：spill_read(handle=\"{entry.handle}\", offset=0, limit=8000) "
                "分页读取；或 spill_read(handle=..., search=\"关键字\") 做字面量搜索。\n"
            )
        elif entry.reasons and "run_quota_exceeded" in entry.reasons:
            notice = (
                "\n[注意] 本次运行的溢写配额已用尽，这段输出的完整内容**未保存**；"
                "下面的摘要即全部可用内容。\n"
            )

    if len(text) > GOVERNOR_HARD_LIMIT:
        excerpt = (
            text[:GOVERNOR_KEEP_HEAD]
            + f"\n…[输出过大：共 {total} 字符，此处省略中间 "
            + f"{total - GOVERNOR_KEEP_HEAD - GOVERNOR_KEEP_TAIL} 字符]…\n"
            + text[-GOVERNOR_KEEP_TAIL:]
        )
    else:
        excerpt = text
    hint = ""
    if name == "read_urls":
        hint = "（提示：用 max_bytes 或分段 urls 缩小单次读取量）"
    elif name == "read_file":
        hint = "（提示：用 start/end 指定行区间继续读取）"
    elif name in ("enumerate_common", "discover_endpoints"):
        hint = "（提示：用 limit_per_tier / max_js 收窄范围，或对最可疑的几条先验证）"
    elif name == "http_request":
        hint = "（提示：响应体过大，考虑只看关键字段或换更小的端点）"
    governed = (
        f"[输出治理] {name} 返回 {total} 字符，已压缩为摘要（保留头尾，中间省略）{hint}"
        + notice
        + "\n"
        + excerpt
    )
    return governed, structured


# ---------------------------------------------------------------------------
# 源码审计工具（source 模式 / source 角色）
# ---------------------------------------------------------------------------


def _list_files(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    sub = str(args.get("path") or ".")
    target = _resolve_within(ctx.base_dir, sub)
    if target is None:
        return "错误：路径越界，只允许访问审计目标目录内部。"
    if not target.exists():
        return f"错误：路径不存在：{sub}"
    if not target.is_dir():
        return f"错误：不是目录：{sub}"
    lines: list[str] = []
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = sorted(d for d in dirnames if not _is_ignored_dir(d))
        rel_dir = Path(dirpath).relative_to(target)
        for d in dirnames:
            lines.append(f"[dir]  {(rel_dir / d).as_posix()}/")
        for f in sorted(filenames):
            if _is_ignored_file(f):
                continue
            full = Path(dirpath) / f
            try:
                size = full.stat().st_size
            except OSError:
                size = 0
            lines.append(f"[file] {(rel_dir / f).as_posix()} ({size} bytes)")
        if len(lines) >= 500:
            lines.append("...(列表被截断)")
            break
    return "\n".join(lines) if lines else "(空目录)"


def _read_file(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    sub = str(args.get("path") or "")
    if not sub:
        return "错误：缺少 path 参数。"
    target = _resolve_within(ctx.base_dir, sub)
    if target is None:
        return "错误：路径越界，拒绝访问审计目录之外的路径。"
    if not target.is_file():
        return f"错误：文件不存在或不是文件：{sub}"
    try:
        raw = target.read_bytes()
    except OSError as exc:
        return f"读取失败：{exc}"
    if b"\x00" in raw[:1024]:
        return f"跳过：{sub} 疑似二进制文件。"
    lines = raw.decode("utf-8", errors="replace").splitlines()
    total = len(lines)

    def _to_int(value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    start = max(1, _to_int(args.get("start"), 1))
    end = _to_int(args.get("end"), start + 499)
    end = min(total, end)
    if end - start + 1 > 500:
        end = start + 499
    if end < start:
        end = min(total, start + 499)
    selected = lines[start - 1 : end]
    raw_selected = "\n".join(selected)
    code_id = ctx.new_evidence_id("C")
    ctx.code_evidence.append(
        {
            "id": code_id,
            "file": sub,
            "start": start,
            "end": end,
            "snippet": raw_selected,
        }
    )
    body = "\n".join(f"{i + start:6d} | {line}" for i, line in enumerate(selected))
    header = f"[code:{code_id}] [read_file] {sub} 行 {start}-{end} / 共 {total} 行"
    return f"{header}\n{body}" if body else f"{header}\n(该区间无内容)"


def _iter_source_files(base: Path):
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if not _is_ignored_dir(d))
        for fname in sorted(filenames):
            if _is_ignored_file(fname):
                continue
            if Path(fname).suffix.lower() in SOURCE_EXTENSIONS:
                yield Path(dirpath) / fname


def _search_code(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    pattern = str(args.get("pattern") or "")
    if not pattern:
        return "错误：缺少 pattern 参数。"
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        return f"错误：无效正则：{exc}"
    limit = max(1, min(int(args.get("limit") or 50), 200))
    matches: list[str] = []
    for path in _iter_source_files(ctx.base_dir):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if regex.search(line):
                rel = path.relative_to(ctx.base_dir).as_posix()
                matches.append(f"{rel}:{lineno}: {line.strip()[:200]}")
                if len(matches) >= limit:
                    break
        if len(matches) >= limit:
            break
    if not matches:
        return "未找到匹配。"
    return f"找到 {len(matches)} 处匹配（最多显示 {limit}）：\n" + "\n".join(matches)


# ---------------------------------------------------------------------------
# HTTP 基础设施：请求、证据登记、限速
# ---------------------------------------------------------------------------


def _proxy_kwargs() -> dict[str, Any]:
    """目标流量的代理设置：**默认不使用任何环境/系统代理**，除非显式配置。

    为什么必须这样（实测踩过，代价是整轮扫描废掉）：httpx 的 `trust_env=True`
    会通过 `urllib.request.getproxies()` 读到 **Windows 注册表里的系统代理**
    （本机是 `http://127.0.0.1:7892`，环境变量里什么都没有）。于是所有目标请求都被
    送进那个本地代理，返回 502：
        httpx trust_env=True  -> 502
        httpx trust_env=False -> 200
    对一次授权扫描来说，把流量交给一个不受控的第三方代理既没必要也不安全
    （它可能改写响应、也可能根本到不了回环/内网目标）。因此默认直连；
    确实需要走代理（例如目标只在某个出口可达）时，显式设 `HEXHOUND_HTTP_PROXY`。

    注意范围：这里只影响**打目标**的 HTTP。LLM 调用走的是另一个客户端
    （`llm.py` / openai SDK），仍然尊重系统代理——否则用中转网关的人会连不上模型。
    """
    explicit = (os.getenv("HEXHOUND_HTTP_PROXY") or "").strip()
    if explicit:
        return {"proxy": explicit, "trust_env": False}
    return {"trust_env": False}


def _send(
    ctx: "ToolRegistry",
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    data: Any = None,
    headers: dict[str, str] | None = None,
    json_body: Any = None,
    timeout: float | None = None,
) -> httpx.Response | None:
    """统一出口：限速 + 异常吞掉（返回 None 由调用方转可读错误）。

    连接超时单独设上限（`CONNECT_TIMEOUT_CAP`）：被防火墙静默丢弃的端口会让
    TCP 连接一直挂到整体超时，一次探测就能拖掉十几秒——连接阶段不需要那么久。

    工具调用计数在 `ToolRegistry.execute` 里统一记一次；这里不再重复计数，
    否则一次 http_request 会被记成 2 次（`execute` + `_send`）。
    """
    ctx.throttle()
    total = float(timeout or ctx.timeout)
    limits = httpx.Timeout(
        total, connect=min(CONNECT_TIMEOUT_CAP, total), pool=min(CONNECT_TIMEOUT_CAP, total)
    )
    try:
        return httpx.request(
            method=str(method or "GET").upper(),
            url=url,
            params=params,
            data=data,
            json=json_body,
            headers=headers or None,
            timeout=limits,
            verify=False,
            follow_redirects=False,
            **_proxy_kwargs(),
        )
    except httpx.HTTPError:
        return None


def _log_exchange(ctx: "ToolRegistry", response: httpx.Response, note: str = "") -> str:
    """把一次 HTTP 请求/响应完整快照存入日志，返回编号（如 W1-R3）。"""
    request = response.request
    exchange_id = ctx.new_evidence_id("R", store=False)
    ctx.http_log.append(
        {
            "id": exchange_id,
            "worker": ctx.worker_id,
            "note": note,
            "method": request.method,
            "url": str(request.url),
            "request_headers": dict(request.headers),
            "request_body": request.content.decode("utf-8", errors="replace")
            if request.content
            else "",
            "status_code": response.status_code,
            "reason": response.reason_phrase,
            "response_headers": dict(response.headers),
            "response_body": response.text,
            "at": time.time(),
        }
    )
    return exchange_id


def _pick_tool_evidence(ctx: "ToolRegistry", refs: Any) -> list[dict[str, Any]]:
    """按 evidence_ref 挑选真工具执行记录（T 编号），未指定时用最近一次。

    真工具证据的价值在于**工具级的可复现性**：sqlmap 给出的不只是"有注入"，
    而是确切的 payload、注入类型、后端 DBMS 版本。这类证据应当能像 HTTP 证据
    一样被 record_finding 引用，否则"证明级"结论就落不到报告里。
    """
    log = getattr(ctx, "sandbox_log", None) or []
    if not log:
        return []
    if refs is None:
        return []
    if isinstance(refs, str):
        refs = [refs]
    by_id = {str(item.get("id")): item for item in log}
    return [by_id[str(ref)] for ref in refs if str(ref) in by_id]


def _pick_http_evidence(ctx: "ToolRegistry", refs: Any) -> list[dict[str, Any]]:
    """按 evidence_ref 挑选要附到漏洞上的请求/响应，未指定时用最近一次。"""
    if not ctx.http_log:
        return []
    if refs is None:
        return [ctx.http_log[-1]]
    if isinstance(refs, str):
        refs = [refs]
    by_id = {item["id"]: item for item in ctx.http_log}
    selected = []
    for ref in refs:
        item = by_id.get(str(ref))
        if item is not None:
            selected.append(item)
    return selected


def _pick_code_evidence(ctx: "ToolRegistry", refs: Any) -> list[dict[str, Any]]:
    """按 code_ref 挑选代码证据，未指定时用最近一次 read_file。"""
    if not ctx.code_evidence:
        return []
    if refs is None:
        return [ctx.code_evidence[-1]]
    if isinstance(refs, str):
        refs = [refs]
    by_id = {item["id"]: item for item in ctx.code_evidence}
    return [by_id[str(ref)] for ref in refs if str(ref) in by_id]


def _pick_screenshots(ctx: "ToolRegistry", refs: Any) -> list[dict[str, Any]]:
    """按 screenshot_ref 挑选截图，未指定时用最近一张截图。"""
    if not ctx.screenshots:
        return []
    if refs is None:
        return [ctx.screenshots[-1]]
    if isinstance(refs, str):
        refs = [refs]
    by_id = {item["id"]: item for item in ctx.screenshots}
    return [by_id[str(ref)] for ref in refs if str(ref) in by_id]


def _merge_auth_headers(
    ctx: "ToolRegistry", headers: dict[str, Any], account: Any
) -> dict[str, str]:
    """按 account 参数合并账号 A/B 的 Cookie/Authorization 等请求头。"""
    merged = {str(key): str(value) for key, value in headers.items()}
    name = str(account or ctx.active_account or "").strip().upper()
    profile = ctx.auth_profiles.get(name) or {}
    for key, value in profile.items():
        merged[str(key)] = str(value)
    return merged


def _detect_tech(ctx: "ToolRegistry", response: httpx.Response, body: str) -> None:
    """登记技术栈指纹，并提示可能的高危版本（组件类证据）。"""
    for header in ("server", "x-powered-by", "x-aspnet-version", "via"):
        value = response.headers.get(header)
        if value:
            ctx.surface.add_tech(header, value)
    generator = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I
    )
    if generator:
        ctx.surface.add_tech("generator", generator.group(1))
    haystack = body[:20000] + "\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    for name, pattern in KB.VERSION_PATTERNS:
        match = pattern.search(haystack)
        if match:
            ctx.surface.add_tech(name, match.group(1))


def _analyze_body(ctx: "ToolRegistry", url: str, body: str) -> list[str]:
    """从响应体里抽取可用的情报（报错泄露 / PII / 技术栈版本）。"""
    notes: list[str] = []
    if KB.ERROR_PAGE_SIGNAL.search(body):
        notes.append("响应含详细报错（可能泄露栈信息/路径）")
    for name, pattern in KB.PII_PATTERNS:
        match = pattern.search(body)
        if match:
            notes.append(f"响应含疑似{name}：{match.group(0)[:40]}")
            break
    for note in notes:
        ctx.surface.add_note(f"{url} → {note}")
    return notes


# ---------------------------------------------------------------------------
# 侦察类工具
# ---------------------------------------------------------------------------


def _request_fingerprint(
    method: str, url: str, *, params: Any, data: Any, headers: dict[str, str], json_body: Any
) -> str:
    """同一请求的指纹（用于识别"重复发同一个请求"）。"""
    try:
        payload = json.dumps(
            {"m": method.upper(), "u": url, "p": params, "d": data, "h": headers, "j": json_body},
            ensure_ascii=False, sort_keys=True, default=str,
        )
    except (TypeError, ValueError):
        payload = f"{method} {url} {params} {data}"
    return hashlib.sha1(payload.encode("utf-8", errors="replace")).hexdigest()


def _http_request(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    url = str(args.get("url") or "")
    _, err = _validate_url(ctx, url)
    if err:
        return err
    method = str(args.get("method") or "GET").upper()
    params = args.get("params") or {}
    data = args.get("data") or {}
    headers = args.get("headers") or {}
    json_body = args.get("json")
    if not all(isinstance(v, dict) for v in (params, data, headers)):
        return "错误：params / data / headers 必须是对象（dict）。"
    headers = _merge_auth_headers(ctx, headers, args.get("account"))

    # 重复请求短路：同样的请求在同一任务里发第二次时直接复用上次的响应快照。
    # 并发子代理经常"忘了别人已经请求过这个端点"，重发既费 token 又给目标添负载。
    # 想强制重发（例如验证是否已修复）传 refresh=true。
    refresh = args.get("refresh") is True or str(args.get("refresh") or "").lower() in ("1", "true", "yes")
    fingerprint = _request_fingerprint(
        method, url, params=params or None, data=data or None,
        headers=headers, json_body=json_body,
    )
    if not refresh:
        with ctx._lock:
            cached_id = ctx.request_cache.get(fingerprint)
            if cached_id:
                cached = next(
                    (item for item in ctx.http_log if item["id"] == cached_id), None
                )
                if cached is not None:
                    ctx.request_cache_hits += 1
                    body = str(cached.get("response_body") or "")
                    key_headers = {
                        k: v for k, v in (cached.get("response_headers") or {}).items()
                        if k.lower() in _KEY_HEADERS
                    }
                    return (
                        f"[{cached_id}]（复用：本任务已发过完全相同的请求，未重复发送；"
                        f"如需强制重发请加 refresh=true）\n"
                        f"HTTP {cached.get('status_code')} {cached.get('reason', '')}\n"
                        f"关键响应头：{json.dumps(key_headers, ensure_ascii=False)}\n"
                        f"响应体（前 2000 字符）：\n{body[:2000]}"
                        + (" ...(已截断)" if len(body) > 2000 else "")
                    )

    response = _send(
        ctx, method, url, params=params or None, data=data or None,
        headers=headers, json_body=json_body,
    )
    if response is None:
        ctx.surface.mark_attempt(url, "http_request", outcome="error", detail="请求失败")
        return "请求失败：目标不可达或超时（可用 http_request 重试一次，仍失败请换端点）。"
    note = str(args.get("note") or "").strip()
    exchange_id = _log_exchange(ctx, response, note=note)
    with ctx._lock:
        ctx.request_cache[fingerprint] = exchange_id
    body = response.text
    _detect_tech(ctx, response, body)
    notes = _analyze_body(ctx, url, body)
    ctx.surface.add_endpoint(
        url, methods=[method], params=param_names(url), source="http_request",
        status=response.status_code,
    )
    key_headers = {k: v for k, v in response.headers.items() if k.lower() in _KEY_HEADERS}
    preview = body[:2000]
    truncated = " ...(已截断)" if len(body) > 2000 else ""
    lines = [
        f"[{exchange_id}] HTTP {response.status_code} {response.reason_phrase}",
        f"关键响应头：{json.dumps(key_headers, ensure_ascii=False)}",
        f"响应体（前 2000 字符）：\n{preview}{truncated}",
    ]
    if notes:
        lines.append("情报：" + "；".join(notes))
    return "\n".join(lines)


def _compare_responses(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """基线 vs 注入请求的精确对比：差异点即漏洞证据。

    比「人眼比对两段 HTML」可靠得多：返回状态码、长度、响应头差异与
    首个差异片段，让 LLM 直接引用差异作为证据。
    """
    url = str(args.get("url") or "")
    _, err = _validate_url(ctx, url)
    if err:
        return err
    method = str(args.get("method") or "GET").upper()
    base_params = args.get("params") or {}
    inject_params = args.get("inject_params") or {}
    data = args.get("data") or {}
    if not isinstance(base_params, dict) or not isinstance(inject_params, dict):
        return "错误：params / inject_params 必须是对象（dict）。"
    merged = dict(base_params)
    merged.update(inject_params)
    headers = _merge_auth_headers(ctx, args.get("headers") or {}, args.get("account"))

    baseline = _send(
        ctx, method, url,
        params=base_params if method != "POST" else None,
        data=data if method == "POST" else None,
        headers=headers,
    )
    if baseline is None:
        return "对比失败：基线请求不可达。"
    baseline_id = _log_exchange(ctx, baseline, note="baseline")
    injected = _send(
        ctx, method, url,
        params=merged if method != "POST" else None,
        data={**data, **inject_params} if method == "POST" else None,
        headers=headers,
    )
    if injected is None:
        return f"对比失败：注入请求不可达（基线 [{baseline_id}]）。"
    injected_id = _log_exchange(ctx, injected, note=f"inject {inject_params}")

    base_text, inj_text = baseline.text, injected.text
    differences: list[str] = []
    if baseline.status_code != injected.status_code:
        differences.append(f"状态码 {baseline.status_code} → {injected.status_code}")
    if abs(len(base_text) - len(inj_text)) > 30:
        differences.append(f"响应长度 {len(base_text)} → {len(inj_text)}")
    for header in ("location", "content-type", "set-cookie", "www-authenticate"):
        before, after = baseline.headers.get(header), injected.headers.get(header)
        if before != after:
            differences.append(f"响应头 {header}: {before!r} → {after!r}")
    snippet = _first_difference(base_text, inj_text)
    if snippet:
        differences.append(f"内容差异：{snippet}")
    for name, pattern in KB.PII_PATTERNS:
        before = bool(pattern.search(base_text))
        after = bool(pattern.search(inj_text))
        if after and not before:
            differences.append(f"注入后新增{name}泄露")
    category = str(args.get("category") or "")
    if category:
        signal = _fuzz_signal(category, str(inject_params), injected)
        if signal:
            differences.append(f"特征命中（{category}）：{signal}")
    ctx.surface.mark_attempt(
        url, category or "compare", param=",".join(inject_params) or "",
        payload=json.dumps(inject_params, ensure_ascii=False)[:200],
        outcome="signal" if differences else "no_signal",
        detail="; ".join(differences)[:300],
    )
    if not differences:
        return (
            f"[{baseline_id} vs {injected_id}] 基线与注入响应无实质差异"
            "（该参数大概率不存在该漏洞，请换参数或换端点）。"
        )
    return (
        f"[{baseline_id} baseline / {injected_id} injected] 发现 {len(differences)} 处差异：\n"
        + "\n".join(f"- {item}" for item in differences)
        + "\n若差异可稳定复现，用 record_finding 记录候选并把 evidence_ref 设为 "
        f'["{baseline_id}","{injected_id}"]，verified=true 需确认差异由注入直接导致。'
    )


def _first_difference(before: str, after: str, window: int = 120) -> str:
    """找出两段文本的首个差异片段（上下文各 window 字符）。"""
    limit = min(len(before), len(after))
    index = 0
    while index < limit and before[index] == after[index]:
        index += 1
    if index >= limit and len(before) == len(after):
        return ""
    start = max(0, index - window // 2)
    left = before[start : index + window].replace("\n", " ")
    right = after[start : index + window].replace("\n", " ")
    return f"基线 …{left}… / 注入 …{right}…"


class _PageParser(HTMLParser):
    """提取页面标题、链接、表单（含输入参数名）与脚本地址。"""

    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._in_title = False
        self._title_parts: list[str] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "title":
            self._in_title = True
        elif tag == "a":
            href = attr.get("href")
            if href:
                self.links.append(href)
        elif tag == "script" and attr.get("src"):
            self.scripts.append(str(attr["src"]))
        elif tag == "form":
            self._form = {
                "method": str(attr.get("method") or "get").upper(),
                "action": attr.get("action") or "",
                "inputs": [],
            }
        elif tag == "input" and self._form is not None:
            name = attr.get("name")
            if name:
                self._form["inputs"].append((name, attr.get("type") or "text"))
        elif tag in ("textarea", "select") and self._form is not None:
            name = attr.get("name")
            if name:
                self._form["inputs"].append((name, tag))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
            self.title = "".join(self._title_parts).strip()
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _same_host(url: str, host: str) -> bool:
    return host_of(url) == host


def _crawl(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    parsed, err = _validate_url(ctx, str(args.get("url") or ""))
    if err:
        return err
    url = parsed.geturl()
    host = (parsed.hostname or "").lower()
    response = _send(ctx, "GET", url)
    if response is None:
        return "请求失败：页面不可达。"
    exchange_id = _log_exchange(ctx, response, note="crawl")
    body = response.text
    parser = _PageParser()
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # noqa: BLE001 容错解析
        pass
    _detect_tech(ctx, response, body)
    notes = _analyze_body(ctx, url, body)

    ctx.surface.add_endpoint(url, methods=["GET"], source="crawl", status=response.status_code)
    links: list[str] = []
    seen: set[str] = set()
    for href in parser.links:
        joined = urljoin(url, href)
        link = urlparse(joined)
        if (link.hostname or "").lower() == host and link.scheme in ("http", "https"):
            if joined not in seen:
                seen.add(joined)
                links.append(joined)
    added = ctx.surface.add_endpoints(links, source="crawl")
    for form in parser.forms:
        action = urljoin(url, form["action"]) if form["action"] else url
        if _same_host(action, host):
            ctx.surface.add_form(
                url, form["method"], action, [name for name, _ in form["inputs"]],
                base_url=url,
            )
    script_urls = [
        urljoin(url, src) for src in parser.scripts if _same_host(urljoin(url, src), host)
    ]
    ctx.surface.add_endpoints(script_urls, source="script")

    lines = [f"[{exchange_id}] [crawl] {url} -> HTTP {response.status_code} {response.reason_phrase}"]
    if parser.title:
        lines.append(f"标题：{parser.title}")
    for header in ("server", "x-powered-by"):
        if response.headers.get(header):
            lines.append(f"{header}: {response.headers[header]}")
    tech = ctx.surface.tech
    if tech:
        lines.append("技术栈指纹：" + "; ".join(f"{k}={v}" for k, v in list(tech.items())[:8]))
    lines.append(f"新增端点 {added} 个（累计 {len(ctx.surface.endpoints)}），同域链接：")
    lines += [f"  {link}" for link in sort_urls(links, 40)]
    if len(links) > 40:
        lines.append(f"  ...（还有 {len(links) - 40} 个）")
    lines.append(f"表单（{len(parser.forms)} 个）：")
    for form in parser.forms[:20]:
        action = urljoin(url, form["action"]) if form["action"] else url
        inputs = ", ".join(f"{n}({t})" for n, t in form["inputs"]) or "(无命名输入)"
        lines.append(f"  {form['method']} {action} -> 参数: {inputs}")
    if script_urls:
        lines.append(f"同域 JS（{len(script_urls)} 个，可用 read_urls 读取）：")
        lines += [f"  {item}" for item in script_urls[:15]]
    if notes:
        lines.append("情报：" + "；".join(notes))
    lines.append("建议下一步：对上面的表单/带参端点直接试 fuzz_params（已自动跳过试过的组合）。")
    return "\n".join(lines)


_API_PATTERNS = (
    r'["\'](/api/[^"\'\s]+)',
    r'["\'](/v[0-9]+/[^"\'\s]+)',
    r'["\'](/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-/]+(?:/[a-zA-Z0-9_\-/{}]+)+)["\']',
    r"fetch\(\s*['\"]([^'\"]+)",
    r"axios\.(?:get|post|put|delete)\(\s*['\"]([^'\"]+)",
    r"url\s*[:=]\s*['\"]([^'\"]+)",
    r'["\'](https?://[^"\'\s]+)',
    # 单段路径（`"/coupon"`、`'/wallet'`）——业务入口常常就是一段词，
    # 上面那些要求 `/api/` 或多级路径的模式全都抓不到（实测漏掉了 /coupon）。
    r'["\'](/[a-zA-Z][a-zA-Z0-9_\-]{2,40})["\']',
)

#: 提取端点时要排除的路径（目录噪音、静态资源目录、版本号之类）
_HARVEST_NOISE = frozenset(
    {
        "/api", "/static", "/assets", "/public", "/dist", "/build", "/node_modules",
        "/favicon", "/index", "/home", "/main", "/app", "/src", "/lib", "/css", "/js",
        "/img", "/images", "/fonts", "/media", "/v1", "/v2", "/v3", "/true", "/false",
        "/null", "/undefined", "/get", "/post", "/put", "/delete",
    }
)


def _harvest_endpoints(
    ctx: "ToolRegistry", text: str, *, base_url: str, host: str, source: str
) -> list[str]:
    """从一段文本（HTML / JS / 配置）里提取同域路径并登记进攻面。

    为什么要把这件事从 `discover_endpoints` 里抽出来共用：**模型不会主动去调它**。
    实测多轮：侦察读了 `/static/app.js`（里面明明有 `fetch("/coupon")`、`/wallet`），
    摘要里也写了这些端点，但攻面里始终没有它们——而"按攻面特征派发竞态/伪造任务"
    的机制正是以攻面为输入，于是那两类任务一次都没派出去。
    读取即登记（读取工具顺手做掉），比指望模型多调一次工具可靠得多。
    """
    found: set[str] = set()
    for pattern in _API_PATTERNS:
        for match in re.findall(pattern, text or "", re.I):
            value = str(match).strip()
            if value.startswith("/"):
                if re.search(r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|map)$", value, re.I):
                    continue
                if value.rstrip("/").lower() in _HARVEST_NOISE:
                    continue
                found.add(value)
            elif value.startswith("http") and _same_host(value, host):
                found.add(value)
    if not found:
        return []
    absolute = [urljoin(base_url, item) for item in found]
    ctx.surface.add_endpoints(absolute, source=source)
    return sort_urls(found, 60)


def _discover_endpoints(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """从页面与同域 JS 中提取疑似 API/接口路径，并写入攻面。"""
    parsed, err = _validate_url(ctx, str(args.get("url") or ""))
    if err:
        return err
    url = parsed.geturl()
    host = (parsed.hostname or "").lower()
    response = _send(ctx, "GET", url)
    if response is None:
        return "请求失败：页面不可达。"
    _log_exchange(ctx, response, note="discover_endpoints")
    html = response.text
    inline_scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.S | re.I)
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)
    text_parts = [html, "\n".join(inline_scripts)]
    max_js = max(0, min(int(args.get("max_js") or 5), 20))
    fetched: list[str] = []
    for src in script_srcs[:max_js]:
        joined = urljoin(url, src)
        if not _same_host(joined, host):
            continue
        js_response = _send(ctx, "GET", joined)
        if js_response is None:
            continue
        _log_exchange(ctx, js_response, note="js")
        text_parts.append(js_response.text)
        fetched.append(joined)
    combined = "\n".join(text_parts)
    harvest = _harvest_endpoints(ctx, combined, base_url=url, host=host, source="discover")
    endpoints = set(harvest)
    added = ctx.surface.add_endpoints([urljoin(url, item) for item in endpoints], source="discover")
    if not endpoints:
        return f"[discover_endpoints] 未从 {url} 的 HTML/JS 中发现明显 API 路径（JS 读取 {len(fetched)} 个）。"
    ordered = sort_urls(endpoints, 80)
    lines = [
        f"[discover_endpoints] 从 {url} 提取 {len(ordered)} 个疑似接口（新增端点 {added} 个），"
        "以下按「高价值优先」排序：",
    ]
    lines += [f"  {item}" for item in ordered]
    lines.append("建议下一步：对形如 /api/xxx?id= 的接口用 fuzz_params 或 compare_responses 验证。")
    return "\n".join(lines)


def _enumerate_common(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """分档探测常见/敏感路径，并用随机路径基线过滤「假 404」。"""
    parsed, err = _validate_url(ctx, str(args.get("base_url") or ""))
    if err:
        return err
    origin = f"{parsed.scheme}://{parsed.netloc}"
    tiers = args.get("tiers")
    if isinstance(tiers, str):
        tiers = [tiers]
    if not tiers:
        # business 档默认打开：竞态/业务逻辑类问题只出现在这些路径上，
        # 不主动扫就永远发现不了（实测 7 次运行都没发现首页链着的 /coupon）。
        tiers = ["core", "leak", "admin", "framework", "business"]
    unknown = [t for t in tiers if t not in KB.PATH_TIERS]
    if unknown:
        return (
            f"错误：未知档位 {unknown}。可用档位：{', '.join(KB.PATH_TIERS)}"
            "（core=基础探测 / leak=源码配置备份 / admin=后台运维 / framework=框架中间件 / "
            "api=接口入口 / business=会改状态的业务入口：券码·余额·积分·下单·退款·限额·一次性令牌）"
        )
    per_tier = max(1, min(int(args.get("limit_per_tier") or 40), 200))
    words: list[str] = []
    for tier in tiers:
        words.extend(KB.PATH_TIERS[tier][:per_tier])
    words = list(dict.fromkeys(words))

    baseline = _send(ctx, "GET", origin + KB.FAKE_404_RANDOM_PATHS[0])
    baseline_status = baseline.status_code if baseline is not None else 404
    baseline_len = len(baseline.text) if baseline is not None else 0
    fanout = baseline_status == 200

    hits: list[str] = []
    soft_hits: list[str] = []
    for path in words:
        url = origin + path
        response = _send(ctx, "GET", url)
        if response is None:
            continue
        status = response.status_code
        if status in _REDIRECT_STATUS:
            location = response.headers.get("location", "")
            if location.rstrip("/") not in (url.rstrip("/"), origin.rstrip("/")):
                hits.append(f"{status} -> {location}  {url}")
            continue
        if status == 404 or status >= 500 and status != 500:
            continue
        body = response.text
        if status == 200:
            if fanout and abs(len(body) - baseline_len) < 64:
                continue  # 与随机路径响应几乎一致 → 大概率是自定义 404
            marker = _content_marker(path, body)
            if fanout and not marker:
                soft_hits.append(f"{status}  {url}（长度 {len(body)}，无内容特征）")
                continue
            hits.append(f"{status}  {url}" + (f"  特征: {marker}" if marker else ""))
        elif status in (401, 403):
            hits.append(f"{status}  {url}（受保护，值得进一步探测）")
        elif status == 500:
            hits.append(f"{status}  {url}（服务端报错，可能存在注入/未处理输入）")
        else:
            hits.append(f"{status}  {url}")

    paths = [item.split("  ")[-1] for item in hits]
    ctx.surface.add_extra_paths(paths)
    ctx.surface.add_endpoints(paths, source="enumerate")
    for item in hits:
        ctx.surface.mark_attempt(item.split("  ")[-1], "enumerate", outcome="signal", detail=item[:120])
    lines = [
        f"[enumerate_common] 探测 {len(words)} 个路径（档位 {'+'.join(tiers)}，随机路径基线 HTTP {baseline_status}）"
    ]
    if fanout:
        lines.append("注意：本站对任意路径都返回 200（疑似 SPA/自定义错误页），已用随机路径基线过滤。")
    if hits:
        lines.append(f"命中 {len(hits)} 个：")
        lines += [f"  {item}" for item in hits[:60]]
    else:
        lines.append("未命中任何有效路径。")
    if soft_hits:
        lines.append(f"疑似软 404（低置信，仅供参考）{len(soft_hits)} 个：")
        lines += [f"  {item}" for item in soft_hits[:10]]
    if hits:
        lines.append(
            "建议下一步：对命中路径用 http_request 读取内容确认真实性"
            "（.git/.env/备份文件泄露可直接作为证据；/actuator 等看返回体）。"
        )
    return "\n".join(lines)


def _content_marker(path: str, body: str) -> str:
    """按路径类型检查内容特征，返回命中的特征描述（空串表示无特征）。"""
    lowered = path.lower()
    for token, signature in KB.PATH_CONTENT_SIGNATURES.items():
        if token in lowered and signature in body:
            return f"含 {token} 特征"
    if path.endswith(".zip") or path.endswith(".tar.gz"):
        return "返回压缩包"
    if path.endswith(".sql") and re.search(r"(?i)(INSERT INTO|CREATE TABLE|DROP TABLE)", body):
        return "含 SQL 语句"
    if ".env" in lowered and re.search(r"(?m)^[A-Z0-9_]{3,}=", body):
        return "含环境变量定义"
    if ".git/config" in lowered and "repositoryformatversion" in body:
        return "Git 仓库配置"
    return ""


def _read_urls(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """批量读取白名单内的文本资源（JS / 配置 / robots），用于提取线索与密钥。"""
    urls = args.get("urls")
    if isinstance(urls, str):
        urls = [urls]
    if not isinstance(urls, list) or not urls:
        return "错误：urls 必须是非空数组。"
    max_bytes = max(500, min(int(args.get("max_bytes") or 6000), 40000))
    lines: list[str] = []
    secrets_found: list[str] = []
    harvested: list[str] = []
    for raw in urls[:10]:
        url = str(raw)
        parsed, err = _validate_url(ctx, url)
        if err:
            lines.append(err)
            continue
        response = _send(ctx, "GET", url)
        if response is None:
            lines.append(f"读取失败：{url}")
            continue
        exchange_id = _log_exchange(ctx, response, note="read_urls")
        body = response.text
        lines.append(f"[{exchange_id}] {url} -> HTTP {response.status_code}（{len(body)} 字符）")
        lines.append(body[:max_bytes] + (" ...(已截断)" if len(body) > max_bytes else ""))
        for name, pattern in KB.PII_PATTERNS:
            match = pattern.search(body)
            if match:
                secrets_found.append(f"{url}: 疑似{name} {match.group(0)[:40]}")
        if re.search(r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"][^'\"]{6,}", body):
            secrets_found.append(f"{url}: 疑似硬编码密钥/凭据")
        ctx.surface.add_endpoint(url, source="read_urls", status=response.status_code)
        # 读取即登记：JS/HTML 里出现的路径直接进攻击面（否则模型读了也不用）
        harvested.extend(
            _harvest_endpoints(
                ctx, body,
                base_url=url,
                host=(parsed.hostname or "").lower(),
                source="read_urls",
            )
        )
    if harvested:
        unique = sort_urls(set(harvested), 40)
        lines.append("")
        lines.append(f"从读取内容里提取到 {len(unique)} 个接口路径，已写入共享攻面：")
        lines += [f"  {item}" for item in unique]
    if secrets_found:
        lines.append("")
        lines.append("敏感信息线索（需进一步核实是否真实有效）：")
        lines += [f"  {item}" for item in dict.fromkeys(secrets_found)]
        ctx.surface.add_note("；".join(dict.fromkeys(secrets_found))[:200])
    return {
        "llm": "\n".join(lines),
        "urls": [str(item) for item in urls[:10]],
        "secrets": list(dict.fromkeys(secrets_found)),
        "total_chars": sum(len(line) for line in lines),
    }


def _capture_screenshot(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    url = str(args.get("url") or "")
    _, err = _validate_url(ctx, url)
    if err:
        return err
    label = str(args.get("label") or "漏洞验证截图").strip()
    try:
        data = capture_url(url, timeout=max(ctx.timeout, 15))
    except Exception as exc:  # noqa: BLE001 截图失败返回可读错误，Agent 可继续
        return f"截图失败：{type(exc).__name__}: {exc}"
    shot_id = ctx.new_evidence_id("S")
    ctx.screenshots.append(
        {
            "id": shot_id,
            "url": url,
            "label": label,
            "mime_type": "image/png",
            "data_base64": base64.b64encode(data).decode("ascii"),
        }
    )
    return f"[{shot_id}] 已截图 {url}（PNG，{len(data)} 字节，label={label}）"


def _dynamic_crawl(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """用无头浏览器真实执行页面，收集渲染 DOM、截图与网络请求。"""
    url = str(args.get("url") or "")
    _, err = _validate_url(ctx, url)
    if err:
        return err
    try:
        from .browser import dynamic_scan
    except ImportError:
        return "错误：未安装 playwright，无法进行动态执行（pip install playwright && playwright install chromium）。"

    wait_ms = max(0, min(int(args.get("wait_ms") or 2500), 10000))
    execute_js = str(args.get("execute_js") or "").strip() or None
    try:
        result = dynamic_scan(url, wait_ms=wait_ms, execute_js=execute_js)
    except Exception as exc:  # noqa: BLE001 浏览器/页面异常转成可读错误
        return f"动态执行失败：{type(exc).__name__}: {exc}"

    shot_id = ctx.new_evidence_id("S")
    ctx.screenshots.append(
        {
            "id": shot_id,
            "url": url,
            "label": str(args.get("label") or "动态执行截图").strip(),
            "mime_type": "image/png",
            "data_base64": base64.b64encode(result["screenshot"]).decode("ascii"),
        }
    )
    requests = result.get("requests") or []
    api_urls = result.get("api_urls") or []
    ctx.surface.add_endpoints(
        [item if str(item).startswith("http") else urljoin(url, str(item)) for item in api_urls],
        source="dynamic",
    )
    lines = [f"[dynamic_crawl] {url} 动态执行完成，截图 [{shot_id}]"]
    dialogs = result.get("dialogs") or []
    if dialogs:
        lines.append(f"检测到弹窗：{'; '.join(dialogs[:10])}")
        ctx.surface.add_note(f"{url} 执行时弹出对话框：{'; '.join(dialogs[:3])}")
    lines.append(f"网络请求 {len(requests)} 个，响应 {len(result.get('responses') or [])} 个")
    if api_urls:
        lines.append(f"疑似 API 请求 {len(api_urls)} 个：")
        lines += [f"  {item}" for item in api_urls[:60]]
    lines.append("渲染后 HTML（前 6000 字符）：")
    lines.append((result.get("html") or "")[:6000])
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 注入 / 认证类工具
# ---------------------------------------------------------------------------


def _fuzz_signal(category: str, payload: str, response: httpx.Response) -> str:
    """判定一次注入是否产生可观测的异常信号。"""
    body = response.text
    if category == "sqli":
        match = KB.SQLI_ERROR.search(body)
        return f"命中 SQL 错误特征：{match.group(0)!r}" if match else ""
    if category == "xss":
        if payload and payload in body:
            return "payload 原样回显（未转义），疑似反射型 XSS"
        return ""
    if category == "ssti":
        for candidate, expected in KB.SSTI_EXPECTED.items():
            if candidate in str(payload) and expected in body:
                return f"模板表达式被求值（{candidate} -> {expected}），疑似 SSTI"
        match = KB.SSTI_EXTRA_SIGNAL.search(body)
        return f"命中模板引擎报错：{match.group(0)!r}" if match else ""
    if category == "cmd":
        match = KB.CMD_OUTPUT.search(body)
        return f"命中命令输出特征：{match.group(0)!r}" if match else ""
    if category == "path":
        match = KB.PASSWD_OUTPUT.search(body)
        if match:
            return f"命中敏感文件内容：{match.group(0)!r}"
        match = KB.INI_OUTPUT.search(body)
        if match:
            return f"命中 windows/ini 内容：{match.group(0)!r}"
        # 通用回退：读取到的内容像配置文件/密钥（配合 .env、*.txt 等路径使用）。
        if payload and _looks_like_secret_dump(body):
            return "响应体含配置/密钥样式内容（疑似任意文件读取）"
        return ""
    if category == "ssrf":
        for token in KB.SSRF_CANARY_TOKENS:
            if token in body:
                return f"服务端抓取了 canary 地址并回显结果（{token}）"
        if isinstance(payload, str) and payload in body and payload.startswith(("http", "file")):
            return f"响应体回显了注入的地址 {payload!r}（疑似服务端正在处理该 URL）"
        match = KB.SSRF_SIGNAL.search(body)
        return f"疑似服务端发起请求：{match.group(0)!r}" if match else ""
    if category == "fmt":
        match = KB.FMT_SIGNAL.search(body)
        if match:
            return f"格式化字符串被求值：{match.group(0)!r}"
        if "{name.__class__}" in str(payload) and "str" in body and "class" in body:
            return "格式化占位符被解析（疑似格式化字符串注入）"
        return ""
    if category == "nosqli":
        match = KB.NOSQLI_SIGNAL.search(body)
        return f"命中 NoSQL 报错：{match.group(0)!r}" if match else ""
    if category == "xxe":
        match = KB.XXE_SIGNAL.search(body)
        return f"命中 XML 实体解析特征：{match.group(0)!r}" if match else ""
    if category == "redirect":
        location = response.headers.get("location", "")
        if "example.invalid" in location:
            return f"Location 被劫持到外部域：{location!r}"
        return ""
    if category == "crlf":
        for key in response.headers:
            if key.lower() == "hexhound-injected":
                return "响应头被注入（CRLF）"
        return ""
    return ""


def _payloads_for(category: str) -> list[str]:
    return KB.FUZZ_PAYLOADS.get(category, [])


def _looks_like_secret_dump(body: str) -> bool:
    """判断响应体是否像「读到了配置文件/密钥」（任意文件读取的通用判据）。"""
    if len(body) < 12:
        return False
    has_assignments = len(re.findall(r"(?m)^[A-Za-z_][A-Za-z0-9_]{2,}\s*=\s*\S+", body)) >= 2
    sensitive_names = re.search(
        r"(?i)(password|passwd|secret|api[_-]?key|token|db_|jwt|aws_)", body
    )
    if has_assignments and sensitive_names:
        return True
    return bool(re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", body))


def _reflects_and_ran(
    payload: Any, response: httpx.Response, baseline: httpx.Response
) -> bool:
    """弱判据：payload 出现在「执行结果」里，且响应带命令执行特征。

    很多系统的回显里会打印「即将执行的命令」，因此 payload 出现本身不算证据；
    这里要求同时出现命令输出特征（Ping 统计、Windows 版本、whoami 输出等），
    且这些特征在基线响应里不存在。真正的确认仍应交给 compare_responses。
    """
    payload_text = str(payload or "")
    if not payload_text or payload_text not in response.text:
        return False
    matched = KB.CMD_OUTPUT.search(response.text) or KB.CMD_PROBE_SIGNAL.search(response.text)
    if matched is None:
        return False
    marker = matched.group(0)
    return marker not in baseline.text


def _fuzz_params(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """对参数批量注入 payload；按参数语义选类别，并跳过已试过的组合。"""
    url = str(args.get("url") or "")
    _, err = _validate_url(ctx, url)
    if err:
        return err
    method = str(args.get("method") or "GET").upper()
    params = args.get("params")
    if not isinstance(params, dict) or not params:
        return '错误：params 必须是 {"参数名": "示例值"} 的非空对象（示例值给正常值即可）。'
    categories = args.get("categories")
    if isinstance(categories, str):
        categories = [categories]
    if categories:
        bad = [c for c in categories if c not in KB.FUZZ_PAYLOADS]
        if bad:
            return f"错误：未知类别 {bad}。可用：{', '.join(KB.FUZZ_PAYLOADS)}"
    per_category = max(1, min(int(args.get("per_category") or 4), 12))
    headers = _merge_auth_headers(ctx, args.get("headers") or {}, args.get("account"))
    hint_params = {name: str(value) for name, value in params.items()}
    # 被 fuzz 的端点也是攻面的一部分（否则「未测端点」统计会漏掉它）。
    ctx.surface.add_endpoint(
        url, methods=[method], params=list(params), source="fuzz"
    )

    def send(payload_map: dict[str, Any]):
        return _send(
            ctx, method, url,
            params=payload_map if method != "POST" else None,
            data={**hint_params, **payload_map} if method == "POST" else None,
            headers=headers,
        )

    hits: list[str] = []
    already_hit: list[str] = []
    tried = 0
    skipped = 0
    for name, sample in list(params.items())[:8]:
        chosen: list[str] = list(categories) if categories else list(
            KB.PARAM_PAYLOAD_HINTS.get(str(name).lower(), ())
        )
        if not chosen:
            chosen = ["sqli", "xss", "ssti", "fmt", "path"] if method == "GET" else ["sqli", "xss", "cmd"]
        for category in chosen:
            payloads = _payloads_for(category)[:per_category]
            for payload in payloads:
                previous = ctx.surface.tried_outcome(url, category, str(name), payload)
                if previous is not None:
                    skipped += 1
                    if previous.outcome == "signal":
                        already_hit.append(
                            f"[{category}] 参数 {name} 且 payload {payload!r} 已由其他子代理命中："
                            f"{previous.detail[:100]}（无需重复发送，可直接进入复核）"
                        )
                    continue
                baseline = send(dict(params))
                payload_map = dict(params)
                payload_map[name] = payload
                response = send(payload_map)
                tried += 1
                if response is None:
                    continue
                _log_exchange(ctx, response, note=f"fuzz {name}={payload[:40]!r} ({category})")
                signal = _fuzz_signal(category, payload, response)
                if not signal and baseline is not None and _reflects_and_ran(payload, response, baseline):
                    signal = (
                        "payload 原样出现在执行结果中，且响应含命令执行特征"
                        "（疑似命令注入，请用 compare_responses 对比确认）"
                    )
                if signal:
                    hits.append(
                        f"[{category}] 参数 {name} 注入 {payload!r} -> HTTP {response.status_code}：{signal}"
                    )
                    ctx.surface.mark_attempt(
                        url, category, param=str(name), payload=payload,
                        outcome="signal", detail=signal,
                    )
                else:
                    ctx.surface.mark_attempt(
                        url, category, param=str(name), payload=payload, outcome="no_signal"
                    )
        # SSRF 内网地址注入：只有"语义上就是 URL/主机"的参数才试——
        # 名字命中 SSRF_PARAM_TOKENS，或该参数的建议类别里本来就有 ssrf。
        # （给 path/file 这类参数注入 URL 只会命中服务端"文件不存在"的错误特征。）
        is_urlish = any(token in str(name).lower() for token in KB.SSRF_PARAM_TOKENS) or (
            "ssrf" in chosen
        )
        if is_urlish:
            for canary in (
                f"http://127.0.0.1:1{KB.SSRF_CANARY_PATH}",
                f"http://127.0.0.1{KB.SSRF_CANARY_PATH}",
            ):
                previous = ctx.surface.tried_outcome(url, "ssrf", str(name), canary)
                if previous is not None:
                    skipped += 1
                    if previous.outcome == "signal":
                        already_hit.append(
                            f"[ssrf] 参数 {name} 的 canary 已由其他子代理命中：{previous.detail[:100]}"
                        )
                    continue
                payload_map = dict(params)
                payload_map[name] = canary
                baseline_map = dict(params)
                baseline = send(baseline_map)
                response = send(payload_map)
                tried += 2
                if response is None:
                    continue
                _log_exchange(ctx, response, note=f"fuzz ssrf {name}={canary}")
                signal = _fuzz_signal("ssrf", canary, response)
                if not signal and baseline is not None:
                    # 回退判据：响应体显著变大 → 服务端可能真的取回了内容。
                    delta = len(response.text) - len(baseline.text)
                    if delta > 400:
                        signal = f"注入内网地址后响应体增大 {delta} 字节（疑似服务端发起请求，需带外确认）"
                if signal:
                    hits.append(
                        f"[ssrf] 参数 {name} 注入 {canary!r} -> HTTP {response.status_code}：{signal}"
                    )
                    ctx.surface.mark_attempt(
                        url, "ssrf", param=str(name), payload=canary,
                        outcome="signal", detail=signal,
                    )
                else:
                    ctx.surface.mark_attempt(
                        url, "ssrf", param=str(name), payload=canary, outcome="no_signal"
                    )

    # 记录 URL 自带参数（部分接口用 query 而非表单）。
    for name in param_names(url):
        if name not in params:
            ctx.surface.add_endpoint(url, source="fuzz")
    header = f"fuzz 完成：本次发出 {tried} 个请求"
    if skipped:
        header += f"，跳过 {skipped} 个已有结论的组合"
    if already_hit:
        header += f"（其中 {len(already_hit)} 个是共享攻面里已存在的命中）"
    if not hits and not already_hit:
        return header + "：未发现异常响应信号（该类参数已标记为已试，请换端点或换参数名）。"
    lines = [header]
    if already_hit:
        lines.append("共享攻面已有的命中（不要重复发送，直接进入复核）：")
        lines += [f"  {item}" for item in already_hit[:10]]
    if hits:
        lines.append(f"本次新发现 {len(hits)} 个疑似信号：")
        lines += [f"  {item}" for item in hits]
    lines.append(
        "命中只是「疑似」：请对每条命中用 compare_responses 做基线/注入对比，"
        "差异稳定后再 record_finding（候选）；确认可复现后由复核阶段置为 verified。"
    )
    return "\n".join(lines)


def _check_security_headers(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    url = str(args.get("url") or "")
    _, err = _validate_url(ctx, url)
    if err:
        return err
    response = _send(ctx, "GET", url)
    if response is None:
        return "请求失败：页面不可达。"
    exchange_id = _log_exchange(ctx, response, note="security_headers")
    headers = {k.lower(): v for k, v in response.headers.items()}
    issues: list[str] = []
    csp = headers.get("content-security-policy", "")
    for name, message in KB.SECURITY_HEADERS:
        if name == "x-frame-options" and ("frame-ancestors" in csp):
            continue
        if name not in headers:
            issues.append(message)
    if url.lower().startswith("https://") and "strict-transport-security" not in headers:
        issues.append("HTTPS 但缺少 Strict-Transport-Security（A02/A05）")
    if "x-powered-by" in headers:
        issues.append(f"泄露技术栈 X-Powered-By: {headers['x-powered-by']}（A06）")
    if "server" in headers:
        issues.append(f"泄露 Server: {headers['server']}（A06）")
    cors = headers.get("access-control-allow-origin", "")
    if cors == "*":
        issues.append("CORS 允许任意来源（Access-Control-Allow-Origin: *），若搭配凭据则风险更高")
    for raw in response.headers.get_list("set-cookie"):
        low = raw.lower()
        cname = raw.split("=", 1)[0]
        missing = []
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "secure" not in low:
            missing.append("Secure")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            issues.append(f"Cookie {cname} 缺少 {', '.join(missing)}（A07）")
    ctx.surface.add_endpoint(url, methods=["GET"], source="headers", status=response.status_code)
    ctx.surface.mark_attempt(url, "security_headers", outcome="signal" if issues else "no_signal")
    if not issues:
        return f"安全响应头检查通过（{url}，HTTP {response.status_code}，证据 [{exchange_id}]）。"
    return (
        f"[{exchange_id}] 安全头检查发现 {len(issues)} 项问题（{url}）：\n"
        + "\n".join(f"- {item}" for item in issues)
        + "\n提醒：配置加固类（缺安全头/Cookie 标志）通常不属于可提交漏洞，"
        "仅当能证明实际影响（如配合 XSS 的会话窃取）时才 record_finding。"
    )


def _login_success_reason(
    response: httpx.Response, baseline: httpx.Response, base_text: str
) -> str:
    """判定一次登录响应是否与失败基线不同，返回原因（空串表示无差异）。"""
    if response.status_code in _REDIRECT_STATUS:
        return f"重定向到 {response.headers.get('location', '?')}"
    if response.headers.get("set-cookie"):
        return "设置了会话 Cookie"
    if response.status_code != baseline.status_code:
        return f"状态码变化 {baseline.status_code} -> {response.status_code}"
    resp_text = response.text.lower()
    for marker in KB.SUCCESS_MARKERS:
        if marker in resp_text and marker not in base_text:
            return f"响应出现成功标记 {marker!r}"
    for marker in KB.FAIL_MARKERS:
        if marker in base_text and marker not in resp_text:
            return f"失败标记 {marker!r} 消失"
    if abs(len(resp_text) - len(base_text)) > 200:
        return f"响应体长度显著变化 {len(base_text)} -> {len(resp_text)}"
    return ""


def _check_default_creds(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """尝试常见默认凭据；命中的会话会自动注册为账号 C（供越权对比）。"""
    url = str(args.get("url") or "")
    _, err = _validate_url(ctx, url)
    if err:
        return err
    user_field = str(args.get("username_field") or "")
    pass_field = str(args.get("password_field") or "")
    extra = args.get("extra_fields") or {}
    if not isinstance(extra, dict):
        return "错误：extra_fields 必须是对象（dict）。"
    # 自动猜字段名：未指定时按常见命名顺序试（返回 404/400 说明字段名猜错了）。
    if not user_field or not pass_field:
        guessed: tuple[str, str] | None = None
        for candidate in KB.DEFAULT_USER_FIELDS:
            for pass_candidate in KB.DEFAULT_PASS_FIELDS:
                test = _send(
                    ctx, "POST", url,
                    data={candidate: "__hh_probe__", pass_candidate: "__hh_probe__", **extra},
                )
                if test is not None and test.status_code not in (400, 404, 405, 415, 422):
                    guessed = (candidate, pass_candidate)
                    break
            if guessed:
                break
        user_field, pass_field = guessed or ("username", "password")

    def post(user: str, password: str) -> httpx.Response | None:
        return _send(
            ctx, "POST", url,
            data={user_field: user, pass_field: password, **extra},
        )

    baseline = post("__hexhound_bad_user__", "__hexhound_bad_pass__")
    if baseline is None:
        return "请求失败：登录端点不可达，无法建立基线。"
    baseline_id = _log_exchange(ctx, baseline, note="login baseline")
    base_text = baseline.text.lower()
    found: list[str] = []
    registered = ""
    for user, password in DEFAULT_CREDS:
        response = post(user, password)
        if response is None:
            continue
        exchange_id = _log_exchange(ctx, response, note=f"login {user}:{password}")
        reason = _login_success_reason(response, baseline, base_text)
        if reason:
            found.append(f"{user}:{password} -> {reason}（证据 [{exchange_id}]）")
            if not registered:
                cookies = response.headers.get_list("set-cookie")
                profile: dict[str, str] = {}
                if cookies:
                    profile["Cookie"] = "; ".join(item.split(";", 1)[0] for item in cookies)
                token = re.search(
                    r'"(?:token|access_token|accessToken)"\s*:\s*"([^"]{8,})"', response.text
                )
                if token:
                    profile["Authorization"] = f"Bearer {token.group(1)}"
                if profile:
                    ctx.auth_profiles["C"] = profile
                    registered = "、".join(profile)
    ctx.surface.mark_attempt(url, "default_creds", outcome="signal" if found else "no_signal")
    if not found:
        return (
            f"未发现常见默认凭据可登录（字段 {user_field}/{pass_field}，已测 {len(DEFAULT_CREDS)} 组，"
            f"基线 [{baseline_id}]）。"
        )
    lines = [
        f"疑似默认凭据（字段 {user_field}/{pass_field}，基线 [{baseline_id}]）：",
        *[f"  {item}" for item in found],
    ]
    if registered:
        lines.append(
            f"已把命中会话注册为账号 C（{registered}）：可用 use_account('C') 切到该身份，"
            "再用 auth_test / compare_responses 验证越权。"
        )
    lines.append(
        "注意：命中不等同于漏洞成立——请用 http_request(account=\"C\") 访问一个需要登录的页面，"
        "确认返回的是业务数据而非登录页，再 record_finding。"
    )
    return "\n".join(lines)


def _use_account(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """切换当前默认账号（A/B/C），后续请求自动带上该身份。"""
    name = str(args.get("account") or "").strip().upper()
    if name not in ("A", "B", "C", ""):
        return "错误：account 只能是 A / B / C 或空（清空）。"
    known = {key: value for key, value in ctx.auth_profiles.items() if value}
    if name and name not in known:
        return (
            f"错误：账号 {name} 未配置。已有身份：{', '.join(sorted(known)) or '无'}。"
            "账号 A/B 在 GUI 的「登录态」里手动抓取或粘贴 Cookie；账号 C 由 check_default_creds 命中后自动注册。"
        )
    ctx.active_account = name
    if not name:
        return "已清空当前身份（后续请求为匿名）。"
    fields = ", ".join(sorted(known[name]))
    return f"当前身份已切换为账号 {name}（请求头字段：{fields}）。之后 http_request / compare_responses / auth_test 默认使用它。"


def _auth_test(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """用两个账号发起同一请求并比较响应，辅助发现越权/IDOR。"""
    url = str(args.get("url") or "")
    _, err = _validate_url(ctx, url)
    if err:
        return err
    method = str(args.get("method") or "GET").upper()
    params = args.get("params") or {}
    data = args.get("data") or {}
    account_a = str(args.get("account_a") or "A").strip().upper()
    account_b = str(args.get("account_b") or "B").strip().upper()
    if not all(isinstance(item, dict) for item in (params, data)):
        return "错误：params / data 必须是对象（dict）。"

    def send(account: str) -> httpx.Response | None:
        headers = _merge_auth_headers(ctx, {}, account)
        return _send(
            ctx, method, url,
            params=params if method != "POST" else None,
            data=data if method == "POST" else None,
            headers=headers,
        )

    response_a = send(account_a)
    response_b = send(account_b)
    if response_a is None or response_b is None:
        return "越权测试失败：其中一个账号的请求不可达（检查账号是否已配置）。"
    exchange_a = _log_exchange(ctx, response_a, note=f"auth_test {account_a}")
    exchange_b = _log_exchange(ctx, response_b, note=f"auth_test {account_b}")
    differences: list[str] = []
    if response_a.status_code != response_b.status_code:
        differences.append(f"状态码 {response_a.status_code} -> {response_b.status_code}")
    if abs(len(response_a.text) - len(response_b.text)) > 200:
        differences.append(f"响应长度 {len(response_a.text)} -> {len(response_b.text)}")
    if response_b.status_code == 200 and account_b == "":
        differences.append("匿名请求同样返回 200（疑似未授权访问）")
    for name, pattern in KB.PII_PATTERNS:
        a_has, b_has = bool(pattern.search(response_a.text)), bool(pattern.search(response_b.text))
        if a_has != b_has:
            differences.append(f"{name}出现情况不同（{account_a}={a_has}, {account_b}={b_has}）")
    category = "idor" if str(args.get("category") or "") != "auth" else "auth"
    ctx.surface.mark_attempt(
        url, category, param=param_names(url)[0] if param_names(url) else "",
        outcome="signal" if differences else "no_signal",
        detail="; ".join(differences)[:300],
    )
    if not differences:
        return f"{account_a}/{account_b} 响应无明显差异（{exchange_a}/{exchange_b}）。"
    return (
        f"[{exchange_a} vs {exchange_b}] 发现 {account_a}/{account_b} 响应差异"
        "（疑似越权/IDOR，需人工确认）：\n"
        + "\n".join(f"- {item}" for item in differences)
        + "\n判定要点：账号 B 能读到账号 A 的私有数据（姓名/手机号/订单）才算越权；"
        "仅长度不同不足以成立。确认后用 record_finding（evidence_ref 填这两个编号）。"
    )


# ---------------------------------------------------------------------------
# 记录 / 复核类工具
# ---------------------------------------------------------------------------


def _record_finding(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """记录一条漏洞。

    - 默认（verified 未显式设为 true）：登记为**候选**，进报告但标注「待复核」；
    - `verified=true`：必须带 `verification` 说明复现方式与至少一条 http 证据，
      否则降级为候选并说明原因（对应 Strix 的「只上报能复现的漏洞」）。
    """
    required = ["title", "severity", "confidence", "evidence", "description", "remediation"]
    missing = [k for k in required if not str(args.get(k) or "").strip()]
    if missing:
        return f"错误：缺少必填字段：{', '.join(missing)}。"
    severity = str(args.get("severity")).strip().lower()
    if severity not in SEVERITIES:
        allowed = ", ".join(sorted(SEVERITIES))
        return f"错误：severity 必须为 {allowed} 之一，收到 {severity!r}。"

    url = str(args.get("url") or "").strip()
    # 参数优先级：URL query 里的参数名 > LLM 显式给的 param。
    # 反过来的话，"同一处注入" 会因为一次给了 param、一次没给而算出两个指纹，
    # 去重直接失效（自检里就是这样漏掉一条重复上报的）。
    url_param = ""
    if url:
        names = param_names(url)
        url_param = names[0] if names else ""
    param = url_param or str(args.get("param") or "").strip()

    # Strix 式证据编号校验：引用了不存在的编号直接拒绝，避免"编造证据"。
    # 三类编号都认：HTTP 交换（R）、代码片段（C）、**真工具执行（T）**。
    known_ids = (
        {str(item.get("id")) for item in ctx.http_log}
        | {str(item.get("id")) for item in ctx.code_evidence}
        | {str(item.get("id")) for item in (getattr(ctx, "sandbox_log", None) or [])}
    )
    requested = args.get("evidence_ref")
    if requested is not None:
        if isinstance(requested, str):
            requested = [requested]
        if isinstance(requested, list):
            unknown = [str(ref) for ref in requested if str(ref) not in known_ids]
            if unknown:
                sample = ", ".join(sorted(known_ids)[:8]) or "（本任务还没有任何证据编号）"
                return (
                    f"错误：证据编号 {unknown} 不存在，已拒绝记录（不要编造编号）。"
                    f"本任务已有编号：{sample}。请先用 http_request / compare_responses / "
                    "sqlmap_scan 等取得真实证据。"
                )

    # 证据挑选：显式 ref > 最近一次请求；没有 http 证据的 web 漏洞只能是候选。
    refs = args.get("evidence_ref")
    if refs is None and url:
        # 同一端点最近一次请求更相关（并发下 http_log 末尾可能来自别的 worker）。
        candidates = [
            item for item in ctx.http_log
            if normalize_endpoint(str(item.get("url") or "")) == normalize_endpoint(url)
        ]
        refs = [candidates[-1]["id"]] if candidates else None
    http_evidence = _pick_http_evidence(ctx, refs)
    tool_evidence = _pick_tool_evidence(ctx, refs)
    code_evidence = _pick_code_evidence(ctx, args.get("code_ref"))
    screenshots = _pick_screenshots(ctx, args.get("screenshot_ref"))

    verified = args.get("verified") is True or str(args.get("verified") or "").lower() in ("true", "1", "yes")
    verification = str(args.get("verification") or "").strip()
    counterevidence = str(args.get("counterevidence") or "").strip()
    confidence_rationale = str(args.get("confidence_rationale") or "").strip()
    confidence = str(args.get("confidence") or "").strip()
    reason = ""
    if verified and not http_evidence and not tool_evidence:
        verified = False
        reason = (
            "缺少证据（evidence_ref）：既没有 HTTP 请求证据（R 编号）也没有真工具执行证据"
            "（T 编号），无法确认可复现，已降级为候选。"
        )
    elif verified and not verification:
        verified = False
        reason = "verified=true 但未提供 verification（复现方式），已降级为候选。"
    elif not verified:
        reason = "未声明 verified，已登记为候选，需复核（可用 review_candidate 或 record_finding 带 verified=true 提升）。"
    # 对标 Strix 的置信度纪律：声称 high 必须给出理由；任何结论都鼓励写反证。
    if verified and confidence.lower() == "high" and not confidence_rationale:
        confidence = "medium"
        reason += " confidence=high 但未提供 confidence_rationale，已下调为 medium。"
    if verified and not counterevidence:
        reason += " 未记录 counterevidence（反证/排除依据）——复核阶段会优先复查这一条。"

    # 只在「已复核 + 高严重度 + web 漏洞」时自动补截图：
    # 截图要拉起无头浏览器，每条漏洞都截会把运行时间拖长一个量级。
    if (
        verified
        and url
        and severity in ("critical", "high")
        and not screenshots
        and args.get("auto_screenshot", True) is not False
    ):
        _capture_screenshot(ctx, {"url": url, "label": f"{args.get('title')} 验证截图"})
        screenshots = _pick_screenshots(ctx, args.get("screenshot_ref"))

    finding = Finding(
        id="",
        title=str(args.get("title")).strip(),
        severity=severity,
        # 用归一化后的 confidence（可能因缺 confidence_rationale 被下调）。
        confidence=confidence or str(args.get("confidence") or "").strip(),        evidence=str(args.get("evidence")).strip(),
        description=str(args.get("description")).strip(),
        remediation=str(args.get("remediation")).strip(),
        vuln_type=str(args.get("vuln_type") or "").strip(),
        url=url,
        param=param,
        status="verified" if verified else "candidate",
        verified_by=ctx.worker_id if verified else "",
        verification=verification,
    )
    component = args.get("component")
    if isinstance(component, dict) and component:
        finding.extra["component"] = {
            str(key): str(value).strip() for key, value in component.items() if str(value).strip()
        }
    elif component:
        finding.extra["component"] = {"name": str(component).strip()}
    for key in (
        "category", "vuln_name", "unit_name", "vuln_kind", "platform_vuln_type",
        "affected_product", "affected_component", "vuln_number", "brief_description",
        "detail", "cvss", "owasp", "cwe",
    ):
        value = str(args.get(key) or "").strip()
        if value:
            finding.extra[key] = value
    if counterevidence:
        finding.extra["counterevidence"] = counterevidence
    if confidence_rationale:
        finding.extra["confidence_rationale"] = confidence_rationale
    severity_change = str(args.get("severity_change_conditions") or "").strip()
    if severity_change:
        finding.extra["severity_change_conditions"] = severity_change
    cvss_vector = str(args.get("cvss_vector") or "").strip()
    if cvss_vector:
        finding.extra["cvss_vector"] = cvss_vector
        score = _cvss_score(cvss_vector)
        if score is not None:
            finding.extra.setdefault("cvss", f"{score}")
    if http_evidence:
        finding.extra["http_evidence"] = http_evidence
    if tool_evidence:
        finding.extra["tool_evidence"] = tool_evidence
        # 真工具证据 = 工具级确认，置信度至少 medium；给出可复现命令
        finding.extra["reproduce_commands"] = [
            str(item.get("command") or "") for item in tool_evidence if item.get("command")
        ]
    if code_evidence:
        finding.extra["code_evidence"] = code_evidence
    if screenshots:
        finding.extra["screenshot_evidence"] = screenshots
    finding.dedupe_key = dedupe_key(
        {"vuln_type": finding.vuln_type, "title": finding.title, "url": url, "param": param,
         "description": finding.description}
    )

    # 已存在同一指纹的候选：合并而不是新增。
    existing = None
    for item in ctx.surface.pending_candidates():
        if item.dedupe_key == finding.dedupe_key:
            existing = item
            break
    for item in ctx.surface.verified_findings():
        if item.dedupe_key == finding.dedupe_key:
            existing = item
            break
    if existing is not None and not verified:
        if len(finding.evidence) > len(existing.evidence):
            existing.evidence = finding.evidence
            existing.description = finding.description or existing.description
        existing.extra["merged_count"] = int(existing.extra.get("merged_count") or 1) + 1
        return (
            f"该漏洞已存在（{existing.id}，指纹 {finding.dedupe_key}），已合并本次上报"
            f"（累计 {existing.extra['merged_count']} 次）。当前状态：{existing.status}。"
            "请勿重复记录，继续找别的面。"
        )
    if existing is not None and verified:
        finding.id = existing.id
        finding.extra["merged_count"] = int(existing.extra.get("merged_count") or 1) + 1
        ctx.surface.promote(finding, ctx.worker_id, verification)
        ctx.poc_paths[finding.id] = ctx.artifacts.write_poc(finding.to_dict()) or ""
        return (
            f"已把候选 {finding.id} 提升为「已复核」（{finding.dedupe_key}）：{finding.title}。"
            f"累计上报 {finding.extra.get('merged_count', 1)} 次；"
            f"可复现 PoC：{ctx.poc_paths.get(finding.id) or '（未生成）'}。"
        )

    if verified:
        ctx.surface.findings.append(finding)
        if not finding.id:
            finding.id = ctx.surface.next_finding_id()
        ctx.poc_paths[finding.id] = ctx.artifacts.write_poc(finding.to_dict()) or ""
        ev_kind = "真工具证据" if tool_evidence else "HTTP 证据"
        return (
            f"已记录并复核漏洞 {finding.id}（{severity}，verified by {ctx.worker_id}）：{finding.title}。"
            f"目前共 {len(ctx.surface.findings)} 条已复核漏洞。"
            f"证据类型：{ev_kind}。"
            f"PoC：{ctx.poc_paths.get(finding.id) or '（未生成，缺 http 证据）'}"
            + (f"\n注意：{reason.strip()}" if reason.strip() else "")
        )

    candidate = ctx.surface.add_candidate(finding)
    ctx.surface.mark_attempt(
        url or "candidate", vuln_class({"vuln_type": finding.vuln_type, "title": finding.title}),
        param=param, outcome="signal", detail=finding.title,
    )
    return (
        f"已登记候选 {candidate.id}（{severity}）：{finding.title}。{reason}\n"
        f"复核方式：用 http_request 重放证据请求确认仍可复现，然后 "
        f'record_finding(verified=true, evidence_ref=["R编号"], verification="复现步骤一句话")；'
        f"或交给复核角色处理。当前候选池 {len(ctx.surface.pending_candidates())} 条。"
    )


def screenshot_available(ctx: "ToolRegistry", args: dict[str, Any]) -> bool:
    """是否已有截图证据（避免重复截图）。"""
    if args.get("screenshot_ref") is not None:
        return True
    return bool(ctx.screenshots)


def _review_candidates(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """列出候选池（复核角色用）：返回指纹、证据编号与建议复核动作。"""
    include_tried = bool(args.get("include_tried"))
    candidates = ctx.surface.pending_candidates()
    lines: list[str] = []
    if candidates:
        lines.append(f"待复核候选 {len(candidates)} 条：")
        for item in candidates:
            refs = [
                str(ex.get("id"))
                for ex in (item.extra.get("http_evidence") or [])
            ]
            lines.append(
                f"  [{item.id}] {item.title} | 严重度 {item.severity} | 类型 {item.vuln_type or '-'} "
                f"| URL {item.url or '-'} | 参数 {item.param or '-'} | 指纹 {item.dedupe_key} "
                f"| 证据 {refs or '无'}"
            )
            lines.append(f"      证据说明：{item.evidence[:200]}")
    else:
        lines.append("候选池为空。")
    if include_tried:
        tried = ctx.surface.tried_summary()
        lines.append(f"已尝试组合 {len(tried)} 条（避免重复）：")
        lines += [f"  {item}" for item in tried[:40]]
    lines.append(
        "复核要求：对每条候选重放证据请求（http_request 精确复现）；只有仍可复现的才 "
        'record_finding(verified=true, evidence_ref=[...], verification="...")；'
        "不可复现的保持候选并在 description 里写明「复现失败」，不要谎报复核通过。"
    )
    return "\n".join(lines)


def _cvss_score(vector: str) -> float | None:
    """解析 CVSS v3.1 向量并算出基础分（不依赖第三方库）。

    支持形如 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`。
    评分公式与 FIRST 官方规范一致；解析失败返回 None（不影响记录，只是不自动补分）。
    """
    vector = str(vector or "").strip().upper()
    if not vector.startswith("CVSS:3"):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            key, _, value = part.partition(":")
            metrics[key.strip()] = value.strip()
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        scope_changed = metrics.get("S", "U") == "C"
        pr = (
            {"N": 0.85, "L": 0.68, "H": 0.50}
            if scope_changed
            else {"N": 0.85, "L": 0.62, "H": 0.27}
        )[metrics["PR"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        impact = {"H": 0.56, "L": 0.22, "N": 0.0}
        c, i, a = impact[metrics["C"]], impact[metrics["I"]], impact[metrics["A"]]
    except KeyError:
        return None
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact_score = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact_score = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact_score <= 0:
        return 0.0
    total = (
        min(1.08 * (impact_score + exploitability), 10)
        if scope_changed
        else min(impact_score + exploitability, 10)
    )
    import math

    return math.ceil(total * 10) / 10


def _task_create(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """建立任务清单（对标 Strix 的 todos）：把要做的事显式写下来，逐条推进。"""
    items = args.get("items")
    if isinstance(items, str):
        items = [items]
    if not isinstance(items, list) or not items:
        return '错误：items 必须是非空数组，例如 {"items": ["摸清登录接口", "验证 SQL 注入"]}。'
    created: list[str] = []
    for raw in items[:20]:
        text = str(raw or "").strip()
        if not text:
            continue
        item_id = f"T{len(ctx.task_list) + 1}"
        ctx.task_list.append({"id": item_id, "title": text[:160], "status": "pending"})
        created.append(f"{item_id}={text[:60]}")
    if not created:
        return "错误：items 里没有有效内容。"
    return "已建立任务清单：" + "；".join(created) + "。用 task_update 推进状态，用 task_list 查看。"


def _task_list_tool(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """查看任务清单与状态。"""
    if not ctx.task_list:
        return "任务清单为空（可用 task_create 建立）。"
    lines = []
    for item in ctx.task_list:
        flag = {"pending": "[ ]", "doing": "[>]", "done": "[x]", "blocked": "[!]"}.get(
            item["status"], "[?]"
        )
        lines.append(f"{flag} {item['id']} {item['title']}")
    pending = sum(1 for item in ctx.task_list if item["status"] in ("pending", "doing"))
    lines.append(f"共 {len(ctx.task_list)} 项，未完成 {pending} 项。")
    return "\n".join(lines)


def _task_update(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """更新任务状态（pending / doing / done / blocked）。"""
    item_id = str(args.get("id") or "").strip()
    status = str(args.get("status") or "").strip().lower()
    if status not in ("pending", "doing", "done", "blocked"):
        return "错误：status 只能是 pending / doing / done / blocked。"
    for item in ctx.task_list:
        if item["id"] == item_id:
            item["status"] = status
            note = str(args.get("note") or "").strip()
            return f"{item_id} 已标记为 {status}。{note}".strip()
    return f"错误：没有任务 {item_id!r}（用 task_list 查看现有编号）。"


def _think(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """显式思考（对标 Strix 的 think 工具）：把推理写下来但不产生副作用。

    对弱模型很有用：强制它先梳理「已知事实 → 假设 → 下一步」，减少乱打工具。
    """
    thought = str(args.get("thought") or "").strip()
    if not thought:
        return "错误：需要 thought 参数。"
    ctx.surface.add_agent_note(ctx.worker_id, f"[思考] {thought[:300]}")
    return (
        "已记录你的推理。请基于它给出下一步的具体动作（工具 + 参数），"
        "不要再重复思考同一件事。"
    )


def _leave_note(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """给其他子代理留条线索（写在共享攻面上，跨代理可读）。"""
    text = str(args.get("text") or "").strip()
    if not text:
        return "错误：需要 text 参数。"
    ctx.surface.add_agent_note(ctx.worker_id, text)
    return f"已记录线索（{len(ctx.surface.agent_notes)} 条），其他子代理与复核阶段可见。"


def _record_coverage(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """记录覆盖结论（对标 Strix 的 record_coverage），让报告能说清"没发现"的部分。"""
    target = str(args.get("target") or "").strip()
    status = str(args.get("status") or "").strip().lower()
    if not target:
        return "错误：需要 target（被测对象：URL / 参数 / 功能点）。"
    allowed = ("reported", "no_issue_found", "ruled_out", "not_tested", "blocked")
    if status not in allowed:
        return f"错误：status 必须是 {', '.join(allowed)} 之一。"
    ctx.surface.record_coverage(
        target, status, detail=str(args.get("detail") or ""), owasp=str(args.get("owasp") or "")
    )
    summary = ctx.surface.coverage_summary()
    return (
        f"已记录覆盖：{target} → {status}。当前覆盖统计："
        + "，".join(f"{k}={v}" for k, v in sorted(summary.items()))
    )


def _save_artifact(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """把内容存进本次运行的产物目录（payload 列表、字典、脚本片段）。"""
    name = str(args.get("name") or "").strip()
    content = str(args.get("content") or "")
    if not name or not content:
        return "错误：需要 name 与 content。"
    path = ctx.artifacts.write_artifact(name, content)
    if path is None:
        return "错误：产物目录不可写（已跳过保存，不影响审计继续）。"
    return f"已保存产物：{path}（{len(content)} 字符）"


def _finish_task(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """结束当前子任务并给出结论（子代理的标准收尾动作）。"""
    summary = str(args.get("summary") or "").strip()
    ctx.finish_summary = summary
    return f"任务结束。{summary}" if summary else "任务结束。"


# ---------------------------------------------------------------------------
# 真工具（容器 / WSL 沙箱）—— 这是"检测"与"证明"的分界线
# ---------------------------------------------------------------------------


def _sandbox_ready(ctx: "ToolRegistry", tool: str) -> tuple[Any, str]:
    """检查沙箱与指定工具是否可用，返回 (sandbox, 错误信息)。"""
    sandbox = getattr(ctx, "sandbox", None)
    if sandbox is None:
        return None, (
            "错误：本次运行没有启用真工具沙箱。"
            "用 `hexhound sandbox status` 查看环境，`hexhound sandbox install` 安装工具链。"
        )
    if not sandbox.available():
        probe = sandbox.probe()
        return None, (
            "错误：执行环境不可用："
            + str(probe.get("reason") or "未知原因")
            + ("（提示：" + str(probe["hint"]) + "）" if probe.get("hint") else "")
        )
    status = sandbox.tool_status()
    if tool and not status.get(tool, False):
        available = sorted(name for name, ok in status.items() if ok)
        return None, (
            f"错误：该环境里没有安装 {tool}。已安装：{', '.join(available) or '（无）'}。"
            "运行 `hexhound sandbox install` 安装全部工具。"
        )
    return sandbox, ""


def _record_tool_evidence(ctx: "ToolRegistry", result: Any, note: str) -> str:
    """把一次工具执行记成证据，返回证据编号（可被 record_finding 引用）。

    **失败的、超时的、只有部分输出的执行同样记录**——它们恰恰是最需要回看的：
    "sqlmap 为什么没跑出结果"通常只能从它的报错里看出来。

    输出超过 `EVIDENCE_OUTPUT_CHARS` 时，整段原文进本任务的溢写存储，
    证据里只留裁剪版 + 一个 `spill` 元数据块（含句柄、原始大小、sha256）。
    这样报告不用塞进几百 KB，而"原始输出在哪、怎么读回来"仍然可查。
    """
    if result is None:
        return ""
    exchange_id = ctx.new_evidence_id("T")
    command = str(getattr(result, "command", "") or "")
    script = str(getattr(result, "script", "") or "")
    # 工具名从命令首词取（注意：命令可能被引号包裹或被 shell 前缀污染）
    tool = ""
    stripped = command.strip()
    if stripped:
        for token in stripped.replace("'", " ").split():
            candidate = token.rsplit("/", 1)[-1]
            if candidate and candidate[0].isalpha():
                tool = candidate
                break
    output = sanitize_terminal_text(str(getattr(result, "output", "") or ""))
    spill_meta: dict[str, Any] = {}
    stored_output = output
    if len(output) > EVIDENCE_OUTPUT_CHARS:
        entry = ctx.spill(output, label=f"{exchange_id} {note}".strip())
        spill_meta = entry.to_dict()
        stored_output = output[:EVIDENCE_OUTPUT_CHARS]
        if not entry.stored_bytes:
            spill_meta["note"] = "溢写配额用尽，本段输出未保存完整版本"
    ctx.sandbox_log.append(
        {
            "id": exchange_id,
            # 实际执行的命令（含宿主地址映射后的结果）
            "command": command,
            # 原始命令（映射前）：报告里用来说明"原本打的是哪个目标"，
            # 否则读者看到 192.168.160.1 会以为打错了地方
            "original_command": str(getattr(result, "original_command", "") or command),
            "mapped": bool(getattr(result, "original_command", "") or "") and
                      str(getattr(result, "original_command", "")) != command,
            "tool": (tool or "tool") + ("（自定义脚本）" if script else ""),
            # 自定义脚本正文：报告里直接贴脚本，读者能一眼看懂并发/多步逻辑
            "script": script,
            "exit_code": getattr(result, "exit_code", None),
            "ok": bool(getattr(result, "ok", False)),
            "output": stored_output,
            # 完整输出的定位信息（含 sha256，便于确认"拿到的就是当时那段"）
            "spill": spill_meta,
            # 执行失败的原因（超时 / 作用域拒绝 / 退出码），报告里要能看见
            "error": str(getattr(result, "error", "") or ""),
            "truncated": bool(getattr(result, "truncated", False)) or bool(spill_meta),
            "note": note,
            "duration": round(float(getattr(result, "duration", 0.0) or 0.0), 2),
        }
    )
    return exchange_id


def _port_scan(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """nmap 端口与服务发现（真工具）。"""
    sandbox, err = _sandbox_ready(ctx, "nmap")
    if err:
        return err
    host = str(args.get("host") or "").strip()
    if not host:
        return "错误：需要 host（IP 或域名，必须在白名单内）。"
    ports = str(args.get("ports") or "top").strip()
    result = sandbox.nmap(host, ports=ports)
    exchange_id = _record_tool_evidence(ctx, result, f"nmap {host}")
    if not result.ok and not result.output:
        return f"[{exchange_id}] nmap 失败：{result.error or '无输出'}"
    ctx.surface.add_note(f"nmap {host}：{result.output.splitlines()[-1][:120] if result.output else ''}")
    return (
        f"[{exchange_id}] nmap 结果（host={host} ports={ports}，耗时 {result.duration:.0f}s）：\n"
        + (result.output[:4000] or "（无输出）")
        + "\n判定提示：开放的端口/服务版本是攻击面；版本信息可用于判断已知 CVE（属 A06）。"
    )


def _sqlmap_scan(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """sqlmap 注入确认与只读取证（真工具）。

    这是 HexHound 从"疑似信号"跨到"证明"的关键：sqlmap 会给出可复现的 payload、
    注入类型、后端 DBMS 版本，必要时还能导出数据作为影响实证。
    """
    sandbox, err = _sandbox_ready(ctx, "sqlmap")
    if err:
        return err
    url = str(args.get("url") or "").strip()
    if not url:
        return "错误：需要 url（带参数的完整 URL，必须在白名单内）。"
    data = str(args.get("data") or "").strip()
    extra = str(args.get("extra") or "").strip()
    dump = bool(args.get("dump"))
    timeout = int(args.get("timeout") or 900)

    parts: list[str] = []
    if data:
        parts.append(f'--data="{data}"')
    # 只读约束：不给 sqlmap 任何写/提权选项，只做确认与（可选）导出
    parts.append("--level=2 --risk=1 --threads=2")
    if dump:
        parts.append("--tables --dump --stop 200")
    else:
        parts.append("--banner --current-db")
    if extra:
        parts.append(extra)
    result = sandbox.sqlmap(url, extra=" ".join(parts), timeout=timeout)
    exchange_id = _record_tool_evidence(ctx, result, f"sqlmap {url}")
    output = result.output
    if not output.strip():
        return f"[{exchange_id}] sqlmap 无输出（{result.error or '可能目标不可达'}）。"

    # 抽取关键结论行，避免把几百行日志灌给模型
    keywords = (
        "injectable", "vulnerable", "type:", "title:", "payload:", "back-end dbms",
        "banner", "database:", "table:", "entries", "retrieved", "fetched",
        "not injectable", "all tested parameters", "does not seem to be injectable",
    )
    key_lines = [
        line.rstrip() for line in output.splitlines()
        if any(token in line.lower() for token in keywords)
    ]
    body = "\n".join(key_lines[:60]) or output[:2500]

    if "is vulnerable" in output or "injectable" in output.lower():
        ctx.surface.add_note(f"sqlmap 确认注入：{url} {data}".strip())
        verdict = (
            "结论：**注入成立**（工具级证据）。把上面的 payload 与类型写进 record_finding 的 "
            "evidence，evidence_ref 引用本条编号，verification 写「sqlmap 复现 + 具体 payload」，"
            "然后 verified=true 入库。"
        )
    else:
        verdict = (
            "结论：sqlmap 未确认注入（可能参数不可注入，或需要 cookie/其他参数）。"
            "可以用 record_coverage 记 ruled_out，或换参数再试。"
        )
    return f"[{exchange_id}] sqlmap 结果（{url}，耗时 {result.duration:.0f}s）：\n{body}\n\n{verdict}"


def _template_scan(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """nuclei 模板化扫描（真工具）。"""
    sandbox, err = _sandbox_ready(ctx, "nuclei")
    if err:
        return err
    url = str(args.get("url") or "").strip()
    if not url:
        return "错误：需要 url（必须在白名单内）。"
    severity = str(args.get("severity") or "medium,high,critical").strip()
    categories = args.get("categories")
    if isinstance(categories, list):
        categories = tuple(str(item) for item in categories)
    result = sandbox.nuclei(
        url,
        severity=severity,
        categories=categories,
        timeout=int(args.get("timeout") or 900),
    )
    exchange_id = _record_tool_evidence(ctx, result, f"nuclei {url}")
    output = result.output.strip()
    if not output or "no templates provided" in output.lower():
        return (
            f"[{exchange_id}] nuclei 无输出或模板缺失。"
            "若提示模板缺失，运行 `hexhound sandbox templates` 安装模板库。"
        )
    # 过滤 nuclei 的进度/统计行，只留真实命中
    hits = [
        line for line in output.splitlines()
        if line.strip().startswith("[")
        and not line.startswith(("[INF]", "[WRN]", "[FTL]", "[ERR]", "[DBG]"))
    ]
    if not hits:
        return (
            f"[{exchange_id}] nuclei 无命中（severity>={severity}，耗时 {result.duration:.0f}s）。\n"
            "注意：nuclei 覆盖的是**公开模板**针对的已知问题；0 命中**不代表目标安全**——"
            "业务逻辑、自定义代码漏洞通常没有模板。请用 record_coverage 记为"
            "「nuclei 模板扫描无命中」而不是「无漏洞」。"
        )
    for line in hits[:20]:
        ctx.surface.add_note(f"nuclei: {line[:150]}")
    return (
        f"[{exchange_id}] nuclei 命中 {len(hits)} 条（severity>={severity}，"
        f"耗时 {result.duration:.0f}s）：\n"
        + "\n".join(hits[:60])
        + "\n\n说明：nuclei 命中是**强信号**（模板带验证逻辑），但仍要确认影响；"
        "入库时 evidence_ref 引用本条编号。"
    )


def _dir_bruteforce(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """ffuf 目录爆破（真工具）。"""
    sandbox, err = _sandbox_ready(ctx, "ffuf")
    if err:
        return err
    url = str(args.get("url") or "").strip()
    if not url:
        return "错误：需要 url（站点根 URL，必须在白名单内）。"
    wordlist = str(args.get("wordlist") or "/usr/share/wordlists/hexhound-common.txt").strip()
    result = sandbox.ffuf(url, wordlist=wordlist, timeout=int(args.get("timeout") or 600))
    exchange_id = _record_tool_evidence(ctx, result, f"ffuf {url}")
    output = result.output.strip()
    if not output:
        return f"[{exchange_id}] ffuf 无命中（词表 {wordlist}）。"
    found: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped:
            found.append(stripped)
            # 记录到攻面，供后续角色直接验证
            if "/" in stripped:
                token = stripped.split()[-1] if stripped.split() else ""
                if token.startswith("/"):
                    ctx.surface.add_endpoint(url.rstrip("/") + token, source="ffuf")
    return (
        f"[{exchange_id}] ffuf 目录爆破命中 {len(found)} 条：\n"
        + "\n".join(found[:80])
        + "\n\n判定提示：200/403/401 的路径最值得跟进（403 常意味着存在但需权限）；"
        "命中的路径已写入共享攻面，其它角色可直接验证。"
    )


def _web_fingerprint(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """whatweb 技术栈指纹（真工具）。"""
    sandbox, err = _sandbox_ready(ctx, "whatweb")
    if err:
        return err
    url = str(args.get("url") or "").strip()
    if not url:
        return "错误：需要 url（必须在白名单内）。"
    result = sandbox.whatweb(url, timeout=int(args.get("timeout") or 240))
    exchange_id = _record_tool_evidence(ctx, result, f"whatweb {url}")
    # 只取 stdout：stderr 是环境噪音（实测 WSL 会打印 "localhost 代理未镜像" 警告），
    # 早先拿 result.output（stdout+stderr 合并）去分段解析，结果被警告行截断，
    # tech 里出现 `Werkzeug: 3.0.1]\n\nwsl: 检测到…` 这种垃圾值。
    output = sanitize_terminal_text(result.stdout).strip()
    if not output:
        # 空输出必须说清是"没扫到"还是"命令本身产出为空"。
        # 实测教训：`whatweb -q` 连结果行一起吞掉，工具一直返回"无输出"，
        # 而调用方看起来只是"这个目标没什么指纹"——静默失效。
        if result.ok:
            return (
                f"[{exchange_id}] whatweb 退出码 0 但没有任何输出（可能是 `-q` 之类的"
                "参数把结果一起吞掉了）。请检查 sandbox.whatweb 的参数组合。"
            )
        return f"[{exchange_id}] whatweb 执行失败：{result.error or '未知原因'}"
    plugins = _parse_whatweb_plugins(output)
    for name, version in plugins:
        ctx.surface.add_tech(name, version)
    lines = [f"[{exchange_id}] whatweb 指纹：", output[:2500]]
    if plugins:
        named = "、".join(f"{name}{f'/{v}' if v else ''}" for name, v in plugins[:12])
        lines.append(f"\n已登记到技术栈面：{named}")
    lines.append(
        "\n判定提示：识别出组件与版本后，比对已知 CVE 属于 A06（脆弱组件），"
        "证据里要注明版本来源。"
    )
    return "\n".join(lines)


#: whatweb 里描述**目标本身**而非"组件"的插件名——它们不是技术栈，
#: 登记进 tech 只会污染 A06 判断（`Country[RESERVED]` 不是"脆弱组件"）。
_WHATWEB_NON_TECH = frozenset({
    "country", "ip", "title", "script", "meta-author", "meta-generator",
    "html5", "open-graph", "cookies", "redirectlocation", "uncommonheaders",
    "email", "account", "password", "httpvary", "httpd", "x-powered-by",
    "robots", "frameset", "frame", "object", "passwordfield", "comment",
})

#: whatweb 的单个插件段：`Name[value]`。名字只允许字母数字与 `-_.+`，
#: 避免把结束括号之后的内容（换行、警告行）吃进来。
_WHATWEB_PLUGIN_RE = re.compile(r"(?<![\w\-.])([A-Za-z][A-Za-z0-9\-_.+]{1,40})\[([^\]\n]*)\]")


def _parse_whatweb_plugins(output: str) -> list[tuple[str, str]]:
    """从 whatweb 输出里提取 `(组件名, 版本)`。

    实测输出形态（本机 WSL，靶场在 127.0.0.1:5000）::

        http://127.0.0.1:5000/ [200 OK] Country[RESERVED][ZZ], HTML5,
        HTTPServer[Werkzeug/3.0.1 Python/3.12.3], IP[127.0.0.1],
        Python[3.12.3], Script, Title[HexHound 靶场], Werkzeug[3.0.1]

    要点：

    1. **不能按 `,` 分段**：`Title[HexHound 靶场]` 里的标题本身可能含逗号，
       而且早先的实现把 stdout+stderr 合并后分段，一条警告就能把分段吃歪
       （tech 里因此出现过 `Werkzeug: 3.0.1]\\n\\nwsl: 检测到…`）。
       这里用正则直接匹配 `Name[value]` 结构，与分段方式无关。
    2. 跳过描述目标本身而非组件的插件（Country/IP/Title/Script…）。
    3. `HTTPServer[Werkzeug/3.0.1 Python/3.12.3]` 这种"一个槽里塞多个组件"
       的值不进 tech（值里带 `/` 或空格说明它是描述而非版本号），
       但同名组件在别处会以 `Werkzeug[3.0.1]` 单独出现，那条才是我们想要的。
    """
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_name, raw_value in _WHATWEB_PLUGIN_RE.findall(str(output or "")):
        name = raw_name.strip()
        value = raw_value.strip()
        if name.lower() in _WHATWEB_NON_TECH:
            continue
        if name.lower() in seen:
            continue
        if " " in value or "/" in value:
            # 复合值（"Werkzeug/3.0.1 Python/3.12.3"）——不是干净的版本号，跳过。
            continue
        seen.add(name.lower())
        found.append((name, value[:40]))
    return found


def _sandbox_status(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """报告真工具沙箱状态：执行环境、已安装工具、宿主地址映射。"""
    sandbox = getattr(ctx, "sandbox", None)
    if sandbox is None:
        return (
            "真工具沙箱：**未启用**。\n"
            "影响：只能用内置 HTTP 工具做探测，无法调用 sqlmap/nmap/nuclei 等真工具。\n"
            "启用方式：\n"
            "  1) hexhound sandbox status       查看当前环境探测结果\n"
            "  2) hexhound sandbox install      在 WSL/容器里安装工具链（sqlmap/nmap/ffuf/nuclei…）\n"
            "  3) 或启动 Docker Desktop 后重跑"
        )
    probe = sandbox.probe()
    if not probe.get("ok"):
        lines = [
            "真工具沙箱：**不可用**。",
            f"原因：{probe.get('reason', '未知')}",
        ]
        if probe.get("hint"):
            lines.append(f"建议：{probe['hint']}")
        return "\n".join(lines)
    tools = probe.get("tools") or {}
    present = sorted(name for name, ok in tools.items() if ok)
    missing = sorted(name for name, ok in tools.items() if not ok)
    lines = [
        "真工具沙箱：**可用**。",
        f"- 执行环境：{probe.get('runtime', '?')}",
        f"- 已装工具：{', '.join(present) or '（无）'}",
    ]
    if missing:
        lines.append(f"- 缺失工具：{', '.join(missing)}（用 `hexhound sandbox install` 补装）")
    if sandbox.runtime_kind == "wsl" and sandbox.map_loopback:
        lines.append(f"- 回环目标会被映射到宿主地址：{sandbox.host_gateway()}")
    elif sandbox.runtime_kind == "wsl":
        lines.append("- 目标就在同一环境内，不做地址映射（直接打 127.0.0.1）")
    return "\n".join(lines)


def _raw_command(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """在沙箱里执行一条白名单工具命令（受作用域与禁止参数双重约束）。"""
    sandbox = getattr(ctx, "sandbox", None)
    if sandbox is None or not sandbox.available():
        return _sandbox_ready(ctx, "")[1]
    command = str(args.get("command") or "").strip()
    if not command:
        return "错误：需要 command。"
    result = sandbox.run(command, timeout=int(args.get("timeout") or 600))
    exchange_id = _record_tool_evidence(ctx, result, "raw")
    status = "成功" if result.ok else f"失败（{result.error}）"
    return (
        f"[{exchange_id}] 命令{status}（耗时 {result.duration:.0f}s）：\n$ {result.command}\n"
        + (result.output[:4000] or "（无输出）")
    )


def _spill_read(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """读回被输出治理压缩掉的那部分原文（按句柄，分页或字面量搜索）。

    三种用法（`handle` 必填，来自工具输出里的 `[完整输出已保存] 句柄 SO-…`）：

    - `handle` + `offset`/`limit`：分页读取（offset 以字符计）；
    - `handle` + `search`：字面量搜索，返回命中行的行号与偏移；
    - `handle` 单独给：返回该条输出的元数据与开头一段。

    **只能读本 RUN 里由工具写入的内容**：入口只有句柄，没有路径参数，
    所以这个工具无法被诱导去读任意文件（对比：给模型一个通用 shell 让它
    `sed -n` 读溢写文件，同时也给了它读 `/etc/passwd` 的能力）。
    """
    handle = str(args.get("handle") or "").strip()
    if not handle:
        handles = ctx.spill_store().handles()
        if not handles:
            return (
                "错误：需要 handle。当前这次运行里还没有任何输出被压缩保存"
                "（只有超过 16 KiB 的工具输出才会生成句柄）。"
            )
        listing = "、".join(handles[:10])
        return f"错误：需要 handle。本次运行已保存的句柄：{listing}"

    search = str(args.get("search") or "")
    if search:
        outcome = ctx.spill_store().search(handle, search, limit=int(args.get("limit") or 50))
        if not outcome.get("ok"):
            return f"错误：{outcome.get('error')}"
        hits = outcome.get("hits") or []
        head = (
            f"[{handle}] 字面量搜索 {search!r}：命中 {len(hits)} 处"
            + ("（已达上限，只显示前 50 处）" if outcome.get("truncated") else "")
            + f"（原文共 {outcome.get('total_chars', 0)} 字符）"
        )
        if not hits:
            return head + "\n（没有匹配。注意是**字面量**匹配，不是正则。）"
        lines = [head]
        for item in hits[:50]:
            lines.append(
                f"  line {item['line']} @ offset {item['offset']}: {item['text']}"
            )
        lines.append(
            f"\n要继续看命中处的上下文，用 spill_read(handle=\"{handle}\", "
            f"offset=<命中偏移 - 200>, limit=1000)。"
        )
        return "\n".join(lines)

    result = ctx.spill_store().read(
        handle, offset=int(args.get("offset") or 0), limit=int(args.get("limit") or 0)
    )
    if not result.ok:
        return f"错误：{result.error}"
    meta = result.metadata
    lines = [
        f"[{handle}] {meta.get('label') or '工具输出'} · "
        f"原文 {meta.get('original_size')} 字节 / {result.total_chars} 字符"
        + ("（本条超单条上限，已截断保存）" if meta.get("truncated") else "")
        + f" · sha256 {str(meta.get('sha256') or '')[:16]}…",
        f"本次返回字符 [{result.start}, {result.end})"
        + (f"，后面还有 {result.total_chars - result.end} 字符" if result.has_more else "（已到末尾）"),
    ]
    if result.has_more:
        lines.append(
            f"继续读：spill_read(handle=\"{handle}\", offset={result.end}, limit={MAX_SPILL_PAGE})"
        )
    lines.append("")
    lines.append(result.text)
    return "\n".join(lines)


#: `spill_read` 的默认分页大小（提示里给出的值，与 spill.MAX_READ_CHARS 一致）。
MAX_SPILL_PAGE = 8000


def _sandbox_script(ctx: "ToolRegistry", args: dict[str, Any]) -> str:
    """在沙箱里跑一段自定义 Python 脚本（用于并发竞态 / 多步状态机 / 密文分析）。

    为什么单开一个工具而不是让模型随便写命令：这三类问题**一条命令表达不出来**——
    竞态要同时发 N 个请求并比对响应差异，业务逻辑要走多步状态机，加密实现要对密文
    做统计或爆破。以前模型只能用内置 HTTP 探测（一次一个请求），所以这些面从来没被
    真正测过。
    """
    sandbox, error = _sandbox_ready(ctx, "python3")
    if sandbox is None:
        return error
    script = str(args.get("script") or "")
    if not script.strip():
        return "错误：需要 script（完整的 Python 源码）。"
    purpose = str(args.get("purpose") or "").strip()
    result = sandbox.run_script(
        script, timeout=int(args.get("timeout") or 180)
    )
    exchange_id = _record_tool_evidence(
        ctx, result, purpose or "sandbox_script"
    )
    status = "执行成功" if result.ok else f"执行失败（{result.error}）"
    head = f"[{exchange_id}] 自定义脚本{status}（耗时 {result.duration:.0f}s，{len(script)} 字符）"
    if not result.ok and not result.output:
        # 校验类失败（白名单外主机 / 禁止片段）没有 stdout，直接把原因给模型
        return f"{head}\n{result.error}"
    return f"{head}\n{result.output[:6000] or '（无输出）'}"


# ---------------------------------------------------------------------------
# 工具描述
# ---------------------------------------------------------------------------

_DESC_LIST_FILES = (
    "列出目录内容（递归）。参数：{\"path\": \"相对路径，默认 \\\".\\\"\"}。"
    "返回文件/目录清单（相对路径 + 大小），跳过 .git/node_modules/venv/__pycache__ 等。"
)
_DESC_READ_FILE = (
    "读取文本文件（带行号，单次最多 500 行）。参数：{\"path\": \"相对路径\", "
    "\"start\": 起始行(默认 1), \"end\": 结束行(默认 start+499)}。拒绝越界路径。"
)
_DESC_SEARCH_CODE = (
    "按正则搜索源码。参数：{\"pattern\": \"正则表达式\", \"limit\": 最多条数(默认50)}。"
    "用于找 SQL 拼接/模板渲染/subprocess/open 用户输入等可疑模式。"
)
_DESC_HTTP_REQUEST = (
    "发送 HTTP 请求（仅限白名单主机）。参数：{\"method\": \"GET/POST/...\", \"url\": 完整URL, "
    "\"params\": {查询参数}, \"data\": {表单}, \"json\": {JSON体}, \"headers\": {请求头}, "
    "\"account\": \"A/B/C\"(可选，用指定身份), \"note\": \"这次请求的目的\"(可选), "
    "\"refresh\": true(可选，强制重发)}。"
    "返回 [R编号] + 状态码 + 关键响应头 + 响应体前 2000 字符；不跟随重定向、不校验证书。"
    "**同一请求重复发送会直接复用上次结果**（标注「复用」），想强制重发加 refresh=true。"
    "请求/响应会被完整保存，供 record_finding 作为证据。"
)
_DESC_COMPARE_RESPONSES = (
    "基线/注入响应精确对比（找差异=找证据）。参数：{\"url\": 端点, \"method\": \"GET/POST\", "
    "\"params\": {原始参数}, \"inject_params\": {要覆盖的参数: payload}, \"data\": {POST 表单}, "
    "\"category\": \"sqli/xss/ssti/cmd/path/ssrf/nosqli/xxe/redirect/crlf\"(可选，附加特征判定)}。"
    "返回状态码/长度/响应头/内容差异与首个差异片段，并给出两个证据编号。"
    "强烈建议：fuzz 命中后先用本工具确认差异稳定，再 record_finding。"
)
_DESC_CRAWL = (
    "爬取页面并提取攻击面。参数：{\"url\": 页面URL}。返回状态码、标题、Server/X-Powered-By、"
    "技术栈指纹、同域链接（高价值优先）、表单（方法/action/参数名）、同域 JS 地址。"
    "结果会写入共享攻面，其他子代理可直接复用，不要重复爬同一页。"
)
_DESC_DISCOVER_ENDPOINTS = (
    "从页面与同域 JS 中提取疑似 API/接口路径。参数：{\"url\": 页面URL, \"max_js\": 最多读几个JS(默认5)}。"
    "适合发现隐藏接口与前端调用的 /api 路径。"
)
_DESC_ENUMERATE_COMMON = (
    "分档探测敏感/常见路径（带随机路径基线过滤假 404）。参数：{\"base_url\": 站点根URL, "
    "\"tiers\": [\"core\",\"leak\",\"admin\",\"framework\",\"api\",\"business\"], "
    "\"limit_per_tier\": 每档条数(默认40)}。"
    "默认档位含 **business**（券码/余额/积分/下单/退款/限额/一次性令牌这类**会改状态**的入口）——"
    "竞态与业务逻辑问题只可能出现在这些路径上，别把它关掉。"
    "返回非 404 命中（含内容特征），并对命中路径自动带出下一步建议。"
)
_DESC_READ_URLS = (
    "批量读取白名单内的文本资源（JS/配置/robots）。参数：{\"urls\": [URL...], \"max_bytes\": 每个上限(默认6000)}。"
    "会自动扫描硬编码密钥/AK/邮箱/身份证等敏感信息线索。"
)
_DESC_FUZZ_PARAMS = (
    "对参数批量注入 payload（按参数语义自动选类别，已试过且无信号的组合自动跳过）。参数："
    "{\"url\": 端点, \"method\": \"GET/POST\", \"params\": {参数名: 正常示例值}, "
    "\"categories\": [\"sqli\",\"xss\",\"ssti\",\"cmd\",\"path\",\"ssrf\",\"redirect\",\"crlf\",\"nosqli\",\"xxe\"](可选), "
    "\"per_category\": 每类几条(默认4)}。返回命中信号 + 明确的复现指引。命中仅为「疑似」。"
)
_DESC_CHECK_HEADERS = (
    "检查安全响应头/Cookie 标志/CORS（对应 A02/A05/A06/A07）。参数：{\"url\": 页面URL}。"
    "配置加固类通常不可提交，仅作参考。"
)
_DESC_CHECK_DEFAULT_CREDS = (
    "对登录端点尝试常见默认凭据。参数：{\"url\": 登录端点, \"username_field\": 用户名字段(可选，自动猜), "
    "\"password_field\": 密码字段(可选), \"extra_fields\": {其它必填字段}}。"
    "命中后会把会话自动注册为账号 C，可用 use_account 切换身份继续验证越权。"
)
_DESC_USE_ACCOUNT = (
    "切换当前默认身份。参数：{\"account\": \"A\"/\"B\"/\"C\"/\"\"}。"
    "A/B 来自 GUI 登录态捕获，C 来自 check_default_creds 命中会话；切换后 http_request 等自动带该身份。"
)
_DESC_AUTH_TEST = (
    "用两个账号对同一接口发请求并比较响应，发现越权/IDOR。参数：{\"url\": 完整URL, \"method\": \"GET/POST\", "
    "\"params\": {}, \"data\": {}, \"account_a\": \"A\", \"account_b\": \"B\"}。"
    "可用 account_b=\"\" 测匿名未授权访问。"
)
_DESC_RECORD_FINDING = (
    "记录漏洞。参数：{\"title\", \"severity\": critical/high/medium/low/info, \"confidence\", \"evidence\", "
    "\"description\", \"remediation\", \"vuln_type\", \"url\", \"param\", "
    "\"evidence_ref\": [\"R1\",\"R2\"](要附的请求编号; 必须是真实存在过的编号，编造会被拒绝), "
    "\"verified\": true/false, \"verification\": \"复现方式一句话\", "
    "\"counterevidence\": \"反证/排除依据(强烈建议填写)\", "
    "\"confidence_rationale\": \"置信度理由(confidence=high 时必填，否则自动降为 medium)\", "
    "\"cvss_vector\": \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\", \"cvss\", \"owasp\", \"cwe\", "
    "\"severity_change_conditions\": \"什么情况下等级会变化\", "
    "\"component\": {name/version/cve/fingerprint}, \"code_ref\", \"screenshot_ref\"}。"
    "**verified=true 必须同时给出 evidence_ref 与 verification**，否则会被降级为候选。"
    "同一处漏洞重复上报会自动合并，不要重复记录。"
)
_DESC_REVIEW_CANDIDATES = (
    "列出待复核候选池（复核角色用）。参数：{\"include_tried\": true/false}。"
    "返回每条候选的指纹、证据编号与复核指引。"
)
_DESC_SAVE_ARTIFACT = (
    "把内容保存到本次运行产物目录（留存 payload/字典/脚本片段）。参数：{\"name\": 文件名, \"content\": 内容}。"
)
_DESC_THINK = (
    "显式推理（不产生任何副作用）。参数：{\"thought\": \"已知事实 → 假设 → 下一步\"}。"
    "适合在拿不准时先梳理思路，避免盲目打工具。"
)
_DESC_LEAVE_NOTE = (
    "给其他子代理/复核阶段留一条线索。参数：{\"text\": \"线索内容\"}。"
    "例如「/api/user 不校验归属，uid 可枚举」——避免其他人重复发现同一件事。"
)
_DESC_RECORD_COVERAGE = (
    "记录覆盖结论（让报告能说清哪些没覆盖）。参数：{\"target\": 被测对象(URL/参数/功能), "
    "\"status\": \"reported\"|\"no_issue_found\"|\"ruled_out\"|\"not_tested\"|\"blocked\", "
    "\"detail\": 依据, \"owasp\": \"A01\" 等(可选)}。"
    "重点：测过没问题也要记（no_issue_found），确认不可利用记 ruled_out，没条件测记 not_tested。"
)
_DESC_TASK_CREATE = (
    "建立任务清单。参数：{\"items\": [\"任务1\", \"任务2\"]}。把计划显式写下来再逐条推进。"
)
_DESC_TASK_LIST = "查看任务清单与状态。参数：{}。"
_DESC_TASK_UPDATE = (
    "更新任务状态。参数：{\"id\": \"T1\", \"status\": \"pending/doing/done/blocked\", \"note\": 说明(可选)}。"
)
_DESC_FINISH_TASK = (
    "结束当前子任务并总结（子代理收尾动作）。参数：{\"summary\": \"这个任务做了什么、发现了什么、下一步建议\"}。"
)

# --- 真工具（沙箱）--------------------------------------------------------
_DESC_PORT_SCAN = (
    "【真工具 nmap】端口与服务发现。参数：{\"host\": \"白名单内的 IP/域名\", "
    "\"ports\": \"top\" 或 \"80,443,8000-8100\"}。"
    "返回开放端口与服务版本——版本可用来判断已知 CVE（A06）。首次扫描一个目标时优先用。"
)
_DESC_SQLMAP_SCAN = (
    "【真工具 sqlmap】注入确认与只读取证。参数：{\"url\": 带参数的完整 URL, "
    "\"data\": \"POST 表单数据如 username=a&password=b\"(可选), \"dump\": true 时会尝试导出表数据(可选), "
    "\"extra\": 额外 sqlmap 参数(可选，不能含写入/提权选项), \"timeout\": 秒(默认900)}。"
    "**这是把「疑似注入」变成「证明」的关键工具**：它会给出可复现的 payload、注入类型、后端 DBMS 版本；"
    "开了 dump 还能拿到真实数据作为影响实证。返回里带证据编号，record_finding 时引用它。"
)
_DESC_TEMPLATE_SCAN = (
    "【真工具 nuclei】模板化漏洞扫描（针对**已知 CVE / 暴露面 / 默认口令 / 后台面板**）。"
    "参数：{\"url\": 完整 URL, \"severity\": \"medium,high,critical\"(默认), "
    "\"categories\": \"full\" 或 [\"http/cves\",\"http/exposures\"…](可选), \"timeout\": 秒}。"
    "**成本提示**：默认跑 4 个高性价比类目（约 900 模板 / 60~70 秒）；"
    "传 categories=\"full\" 会跑 4400+ 模板、数分钟、近万请求——只在明确要查已知 CVE 时用。"
    "**局限**：它扫的是公开模板覆盖的问题，对业务逻辑类、自定义代码漏洞通常没有模板，"
    "打靶场这类目标可能是 0 命中——0 命中不代表没有漏洞，别据此下结论。"
)
_DESC_DIR_BRUTEFORCE = (
    "【真工具 ffuf】目录/路径爆破。参数：{\"url\": 站点根 URL, \"wordlist\": 词表路径(可选)}。"
    "命中的路径会自动写入共享攻面；200/401/403 最值得跟进。"
)
_DESC_WEB_FINGERPRINT = (
    "【真工具 whatweb】技术栈与组件指纹。参数：{\"url\": 完整 URL}。"
    "识别出的组件与版本会写入攻面，并可用于 A06 脆弱组件判定。"
)
_DESC_RAW_COMMAND = (
    "【沙箱命令】在隔离环境里执行一条预置工具命令（sqlmap/nmap/ffuf/gobuster/nuclei/nikto/whatweb/curl/python3）。"
    "参数：{\"command\": \"完整命令\", \"timeout\": 秒(默认600)}。"
    "限制：命令行里出现白名单外的主机会被**直接拒绝执行**；破坏性/提权/反弹类参数同样会被拒绝。"
    "仅在预置工具覆盖不到的情况使用。"
)
_DESC_SANDBOX_SCRIPT = (
    "【自定义脚本】在沙箱里跑一段完整的 Python 源码——**竞态、业务逻辑、加密实现这三类"
    "问题只能这样测**（一条命令表达不出并发与多步序列）。"
    '参数：{"script": "完整 Python 源码", "purpose": "这段脚本要证明什么", "timeout": 秒(默认180)}。'
    "适用场景（附判据）：\n"
    "1) **竞态/并发**：优惠券重复兑换、余额双花、限额绕过、一次性令牌并发消费。"
    "用 threading 同时发 N 个请求（N 先 5~10），比对「串行只成功 1 次、并发成功多次」"
    "且**状态持久变化**（余额/计数/发放记录）。\n"
    "2) **业务逻辑**：多步状态机重放（跳过/重排/重复步骤）、客户端算价、负数与舍入、"
    "越权改参后状态仍生效。\n"
    "3) **加密/认证实现**：JWT alg=none 或弱密钥伪造（拿到泄露密钥后自己签一个）、"
    "可预测会话令牌、AES-ECB 的重复块特征、填充 oracle 的响应差异。\n"
    "限制：只能连白名单内主机（脚本正文与运行时都会校验，拼接域名也绕不过）；"
    "禁止破坏性操作、反弹 shell 与起子进程；仍属**只读验证**，不许改目标数据以外的状态。"
    "脚本里的回环地址会自动映射为沙箱可达的宿主地址，直接用 http://127.0.0.1:5000 写即可。"
)
_DESC_SANDBOX_STATUS = (
    "查看真工具沙箱状态（执行环境类型、已安装工具、宿主映射）。参数：{}。"
    "不确定某个工具能不能用时先调它。"
)
_DESC_CAPTURE_SCREENSHOT = (
    "对白名单内的目标 URL 截图并保存为证据。参数：{\"url\": 完整URL, \"label\": 截图说明(可选)}。"
    "返回截图编号 [Sn]，record_finding 可用 screenshot_ref 引用。"
)
_DESC_SPILL_READ = (
    "读回被输出治理压缩掉的**完整工具输出**。参数：{\"handle\": \"SO-…（必填）\", "
    "\"offset\": 起始字符位置(默认0), \"limit\": 读取字符数(默认8000，上限16384), "
    "\"search\": 字面量搜索串(可选，给了就按搜索模式)}。"
    "当某个工具的输出被压缩时，返回文本里会给出 `[完整输出已保存] 句柄 SO-…`，"
    "用那个句柄读回即可。**只能读本次运行里保存过的输出**（没有路径参数，"
    "不能读任意文件，也不能跨运行读）。搜索是字面量匹配，不是正则。"
)
_DESC_DYNAMIC_CRAWL = (
    "用无头浏览器真实执行页面并抓取渲染后 HTML、截图与网络请求（需 playwright）。"
    "参数：{\"url\": 页面URL, \"wait_ms\": 等待毫秒(默认2500), \"execute_js\": 要执行的JS(可选), "
    "\"label\": 截图说明(可选)}。可发现 JS 渲染内容、前端 API、弹窗。"
)


# 角色 → 工具名（未列出的角色拥有全部工具）。
# 设计依据（PentAGI 的 delegation-only orchestrator）：编排者不该有手脚，
# 侦察者不该直接写结论，复核者不该再开拓新面——工具白名单就是这条纪律的代码化。
#
# 真工具（沙箱）按角色下发：侦察者拿指纹/端口/目录爆破，注入者拿 sqlmap/nuclei，
# 复核者可以重跑工具确认（这是"复核"最强的形式）。
#: 每个角色都能用的"读回被压缩掉的输出"工具。
#: 输出治理是所有角色都会遇到的（侦察读 JS、注入跑 sqlmap、复核重跑工具都
#: 可能产生大输出），所以它不属于任何专用角色，而是共享基础设施。
_SPILL_TOOL = ("spill_read",)

ROLE_TOOLS: dict[str, tuple[str, ...]] = {
    "recon": (
        "http_request", "compare_responses", "crawl", "discover_endpoints",
        "enumerate_common", "read_urls", "check_security_headers", "capture_screenshot",
        "dynamic_crawl", "think", "leave_note", "record_coverage",
        "task_create", "task_list", "task_update", "save_artifact", "finish_task",
        # 真工具
        "port_scan", "web_fingerprint", "dir_bruteforce", "template_scan",
        "sandbox_status", "raw_command",
    ) + _SPILL_TOOL,
    "injection": (
        "http_request", "compare_responses", "fuzz_params", "read_urls",
        "record_finding", "think", "leave_note", "record_coverage",
        "task_create", "task_list", "task_update", "save_artifact", "finish_task",
        # 真工具
        "sqlmap_scan", "template_scan", "raw_command", "sandbox_status",
        # 自定义脚本：竞态（并发窗口）与密文分析只能靠脚本表达
        "sandbox_script",
    ) + _SPILL_TOOL,
    "auth": (
        "http_request", "compare_responses", "auth_test", "check_default_creds",
        "use_account", "record_finding", "think", "leave_note", "record_coverage",
        "task_create", "task_list", "task_update", "save_artifact", "finish_task",
        # 真工具
        "sqlmap_scan", "port_scan", "sandbox_status", "raw_command",
        # 自定义脚本：会话/令牌伪造、多步状态机重放
        "sandbox_script",
    ) + _SPILL_TOOL,
    "verify": (
        "http_request", "compare_responses", "review_candidates", "record_finding",
        "capture_screenshot", "think", "leave_note", "record_coverage",
        "task_create", "task_list", "task_update", "finish_task",
        # 复核者可以重跑真工具——最硬的复核方式
        "sqlmap_scan", "template_scan", "raw_command", "sandbox_status",
        # 竞态类结论必须能复跑同一段并发脚本才算复核
        "sandbox_script",
    ) + _SPILL_TOOL,
    "source": (
        "list_files", "read_file", "search_code", "http_request", "compare_responses",
        "record_finding", "think", "leave_note", "record_coverage",
        "task_create", "task_list", "task_update", "capture_screenshot", "finish_task",
        "sandbox_status", "raw_command",
    ) + _SPILL_TOOL,
}

#: 依赖沙箱的工具（沙箱不可用时这些不下发，避免模型反复调用拿到"不可用"）
SANDBOX_TOOLS: dict[str, str] = {
    "port_scan": "nmap",
    "sqlmap_scan": "sqlmap",
    "template_scan": "nuclei",
    "dir_bruteforce": "ffuf",
    "web_fingerprint": "whatweb",
    "raw_command": "",          # 空 = 只要求沙箱可用
    "sandbox_script": "python3",  # 脚本通道需要解释器
    "sandbox_status": "",       # 总是可用（用于自检）
}
#: sandbox_status 不依赖工具，任何情况下都注册
ALWAYS_TOOLS = {"sandbox_status"}


class ToolRegistry:
    """持有工具集合与共享状态（攻面、预算、证据、账号身份、模式、角色）。"""

    def __init__(
        self,
        base_dir: Path,
        allowed_hosts: frozenset[str],
        timeout: int = 10,
        mode: str = "source",
        auth_profiles: dict[str, dict[str, str]] | None = None,
        *,
        surface: AttackSurface | None = None,
        budget: Any = None,
        worker_id: str = "W1",
        role: str = "full",
        artifacts: RunArtifacts | None = None,
        rate_limit: float = 0.0,
        sandbox: Any = None,
        task_usage: Any = None,
        trace: Any = None,
    ) -> None:
        self.base_dir = Path(base_dir).resolve()
        self.allowed_hosts = allowed_hosts
        self.timeout = timeout
        self.mode = mode
        self.auth_profiles = {k: dict(v) for k, v in (auth_profiles or {}).items()}
        self.active_account = ""
        self.worker_id = str(worker_id or "W1")
        self.role = role
        self.surface = surface if surface is not None else AttackSurface(mode=mode)
        self.artifacts = (
            artifacts if isinstance(artifacts, RunArtifacts)
            else RunArtifacts("", enabled=False)
        )
        self.rate_limit = max(0.0, float(rate_limit or 0.0))
        self._lock = threading.RLock()
        self._last_request = 0.0
        self.http_log: list[dict[str, Any]] = []
        self.code_evidence: list[dict[str, Any]] = []
        self.screenshots: list[dict[str, Any]] = []
        self.pending_finding_ids: list[Any] = []
        self.poc_paths: dict[str, str] = {}
        self.finish_summary = ""
        self.last_result: dict[str, Any] = {}
        self.task_list: list[dict[str, str]] = []
        self._evidence_counter = 0
        #: 真工具沙箱（None = 本次运行没有容器/WSL 环境，相关工具不下发）
        self.sandbox = sandbox
        self.sandbox_log: list[dict[str, Any]] = []
        #: 请求指纹 → 证据编号（识别重复请求，避免重发同一个请求）
        self.request_cache: dict[str, str] = {}
        self.request_cache_hits = 0
        #: 本任务的溢写存储（懒创建；见 `spill_store`）。
        self._spill: Any = None
        from .budget import Budget

        self.budget = budget if budget is not None else Budget()
        #: 本任务自己的用量账本（并发下由任务自己累计，见 budget.TaskUsage）。
        self.task_usage = task_usage
        #: 可审计轨迹（trace.TraceRecorder）；None = 不记录。
        #:
        #: 为什么在**注册表**这一层记而不是在沙箱层记：沙箱工具（sqlmap/nmap…）
        #: 有自己的证据记录路径，但内置 HTTP 工具（http_request / fuzz_params /
        #: crawl / auth_test…）才是绝大多数请求的来源，它们**没有**经过沙箱。
        #: 早先 trace 只记沙箱工具，于是"工具调用"事件在纯 HTTP 运行里是空的——
        #: 一份没有工具调用的审计轨迹，等于什么都没审计。
        #: 在 execute() 里统一记，两个来源都覆盖到，且天然带时长与成败。
        self.trace = trace
        self._tools: dict[str, Tool] = {}
        self._register_defaults()

    # ---------- 共享状态访问 ----------

    @property
    def findings(self) -> list[dict[str, Any]]:
        """已入库（含候选）漏洞的 dict 视图（兼容旧调用方）。"""
        items = self.surface.finding_dicts()
        for item in items:
            item.setdefault("poc_path", self.poc_paths.get(str(item.get("id")), ""))
        return items

    @property
    def candidate_count(self) -> int:
        return len(self.surface.pending_candidates())

    def new_evidence_id(self, prefix: str, store: bool = True) -> str:
        """生成全局唯一证据编号：<worker>-<prefix><n>（如 W2-R3）。"""
        with self._lock:
            self._evidence_counter += 1
            return f"{self.worker_id}-{prefix}{self._evidence_counter}"

    def throttle(self) -> None:
        """简单请求间隔限速（同一进程内串行化，避免打崩目标）。"""
        if self.rate_limit <= 0:
            return
        with self._lock:
            wait = self.rate_limit - (time.time() - self._last_request)
            if wait > 0:
                time.sleep(min(wait, 5.0))
            self._last_request = time.time()

    # ---------- 溢写存储（超长工具输出）----------

    def spill_store(self) -> Any:
        """取本任务的溢写存储（懒创建，线程安全）。

        每个 **worker** 一个存储：`run_dir` 相同但 worker_id 不同的两个任务
        各自记账，句柄不会互相碰撞，"跨任务读取"也无从发生——
        一个任务拿不到另一个任务的句柄（句柄是 128 位随机串，且只在
        自己注册表的字典里查得到）。
        """
        with self._lock:
            if self._spill is None:
                from .spill import make_store

                directory = None
                if self.artifacts is not None and getattr(self.artifacts, "enabled", False):
                    directory = Path(self.artifacts.dir) / "spill"
                self._spill = make_store(
                    label=self.worker_id, directory=directory, persist=directory is not None
                )
            return self._spill

    def spill(self, content: str, *, label: str = "", reasons: list[str] | None = None) -> Any:
        """把一段输出存进本任务的溢写存储，返回 `SpillEntry`。"""
        return self.spill_store().store(content, label=label, reasons=reasons)

    # ---------- 工具注册 ----------

    def _register_defaults(self) -> None:
        registry: dict[str, Tool] = {}

        def add(name: str, description: str, func: Callable[[dict[str, Any]], str]) -> None:
            registry[name] = Tool(name, description, func)

        add("list_files", _DESC_LIST_FILES, lambda a: _list_files(self, a))
        add("read_file", _DESC_READ_FILE, lambda a: _read_file(self, a))
        add("search_code", _DESC_SEARCH_CODE, lambda a: _search_code(self, a))
        add("http_request", _DESC_HTTP_REQUEST, lambda a: _http_request(self, a))
        add("compare_responses", _DESC_COMPARE_RESPONSES, lambda a: _compare_responses(self, a))
        add("crawl", _DESC_CRAWL, lambda a: _crawl(self, a))
        add("discover_endpoints", _DESC_DISCOVER_ENDPOINTS, lambda a: _discover_endpoints(self, a))
        add("enumerate_common", _DESC_ENUMERATE_COMMON, lambda a: _enumerate_common(self, a))
        add("read_urls", _DESC_READ_URLS, lambda a: _read_urls(self, a))
        add("fuzz_params", _DESC_FUZZ_PARAMS, lambda a: _fuzz_params(self, a))
        add("check_security_headers", _DESC_CHECK_HEADERS, lambda a: _check_security_headers(self, a))
        add("check_default_creds", _DESC_CHECK_DEFAULT_CREDS, lambda a: _check_default_creds(self, a))
        add("use_account", _DESC_USE_ACCOUNT, lambda a: _use_account(self, a))
        add("auth_test", _DESC_AUTH_TEST, lambda a: _auth_test(self, a))
        add("record_finding", _DESC_RECORD_FINDING, lambda a: _record_finding(self, a))
        add("review_candidates", _DESC_REVIEW_CANDIDATES, lambda a: _review_candidates(self, a))
        add("think", _DESC_THINK, lambda a: _think(self, a))
        add("leave_note", _DESC_LEAVE_NOTE, lambda a: _leave_note(self, a))
        add("record_coverage", _DESC_RECORD_COVERAGE, lambda a: _record_coverage(self, a))
        add("task_create", _DESC_TASK_CREATE, lambda a: _task_create(self, a))
        add("task_list", _DESC_TASK_LIST, lambda a: _task_list_tool(self, a))
        add("task_update", _DESC_TASK_UPDATE, lambda a: _task_update(self, a))
        add("save_artifact", _DESC_SAVE_ARTIFACT, lambda a: _save_artifact(self, a))
        add("finish_task", _DESC_FINISH_TASK, lambda a: _finish_task(self, a))
        add("capture_screenshot", _DESC_CAPTURE_SCREENSHOT, lambda a: _capture_screenshot(self, a))
        add("dynamic_crawl", _DESC_DYNAMIC_CRAWL, lambda a: _dynamic_crawl(self, a))
        # --- 真工具（沙箱）---
        add("port_scan", _DESC_PORT_SCAN, lambda a: _port_scan(self, a))
        add("sqlmap_scan", _DESC_SQLMAP_SCAN, lambda a: _sqlmap_scan(self, a))
        add("template_scan", _DESC_TEMPLATE_SCAN, lambda a: _template_scan(self, a))
        add("dir_bruteforce", _DESC_DIR_BRUTEFORCE, lambda a: _dir_bruteforce(self, a))
        add("web_fingerprint", _DESC_WEB_FINGERPRINT, lambda a: _web_fingerprint(self, a))
        add("raw_command", _DESC_RAW_COMMAND, lambda a: _raw_command(self, a))
        add("sandbox_script", _DESC_SANDBOX_SCRIPT, lambda a: _sandbox_script(self, a))
        add("sandbox_status", _DESC_SANDBOX_STATUS, lambda a: _sandbox_status(self, a))
        # --- 输出治理配套：读回被压缩掉的原文 ---
        add("spill_read", _DESC_SPILL_READ, lambda a: _spill_read(self, a))

        if self.role in ROLE_TOOLS:
            allowed = set(ROLE_TOOLS[self.role])
            self._tools = {k: v for k, v in registry.items() if k in allowed}
        elif self.mode == "blackbox":
            # full/未定义角色：黑盒模式下不下发源码审计工具。
            self._tools = {
                k: v for k, v in registry.items()
                if k not in ("list_files", "read_file", "search_code")
            }
        else:
            self._tools = registry
        self._drop_unavailable_sandbox_tools()

    def _drop_unavailable_sandbox_tools(self) -> None:
        """沙箱或具体工具不可用时，把对应工具从本角色的工具集里摘掉。

        为什么要摘而不是留着报错：模型看到一个工具就会去调，
        每次得到"不可用"都是在烧 token 与步数。**能做什么就只给它什么**。
        """
        for name, required in SANDBOX_TOOLS.items():
            if name not in self._tools:
                continue
            if name in ALWAYS_TOOLS:
                continue
            if self.sandbox is None:
                self._tools.pop(name, None)
                continue
            status = {}
            try:
                if not self.sandbox.available():
                    self._tools.pop(name, None)
                    continue
                status = self.sandbox.tool_status() if required else {}
            except Exception:  # noqa: BLE001 探测失败就当作不可用，别让注册表崩
                self._tools.pop(name, None)
                continue
            if required and not status.get(required, False):
                self._tools.pop(name, None)

    def sandbox_summary(self) -> dict[str, Any]:
        """本注册表看到的沙箱能力（写进提示词与报告）。"""
        if self.sandbox is None:
            return {"enabled": False}
        try:
            probe = self.sandbox.probe()
        except Exception:  # noqa: BLE001
            return {"enabled": False}
        return {
            "enabled": bool(probe.get("ok")),
            "runtime": probe.get("runtime", ""),
            "tools": sorted(name for name, ok in (probe.get("tools") or {}).items() if ok),
        }

    def sandbox_briefing(self) -> str:
        """给模型看的"真工具说明书"（只描述本次实际下发给它的工具）。

        这一段很关键：模型不会主动发现"我还有个 sqlmap 能用"。
        按工具实际可用性动态生成，并且明确写出「该在什么场景优先用它」。
        """
        lines: list[str] = []
        if self.has("sqlmap_scan"):
            lines.append(
                "- `sqlmap_scan`：**参数疑似注入时优先用它**。它给出可复现 payload、注入类型、"
                "后端 DBMS 版本；`dump=true` 还能导出表数据作为影响实证。"
                "拿到结果后把 payload 写进 record_finding 的 evidence 并引用证据编号。"
            )
        if self.has("port_scan"):
            lines.append(
                "- `port_scan`（nmap）：**首次接触一个目标时先用它**，确认开放端口与服务版本；"
                "版本信息用于 A06 脆弱组件判断。"
            )
        if self.has("dir_bruteforce"):
            lines.append(
                "- `dir_bruteforce`（ffuf）：需要找隐藏路径时用，命中会自动写入共享攻面。"
            )
        if self.has("template_scan"):
            lines.append(
                "- `template_scan`（nuclei）：模板化扫已知问题（CVE/配置/泄露），命中是强信号，"
                "但仍需复现确认影响。"
            )
        if self.has("web_fingerprint"):
            lines.append("- `web_fingerprint`（whatweb）：需要技术栈与组件版本时用。")
        if self.has("raw_command"):
            lines.append(
                "- `raw_command`：预置工具覆盖不到时用（命令里的主机必须在白名单内，"
                "破坏性/提权/反弹类参数会被拒绝）。"
            )
        if self.has("sandbox_script"):
            lines.append(
                "- `sandbox_script`：**竞态 / 业务逻辑 / 加密实现这三类只用它**。"
                "写一段 Python 在沙箱里跑，能做内置工具做不到的事：多线程并发打同一接口"
                "（证明「串行只成功一次、并发成功多次」）、重放多步状态机、自己签 JWT 验证"
                "弱密钥或 alg=none、比对密文块找 ECB 特征。"
                "看到「优惠券/余额/积分/限额/一次性令牌/重置密码」这类**先查后写**的接口，"
                "不要只用单发请求下结论——用并发脚本实测是否可重复消费。"
            )
        if not lines:
            return ""
        header = (
            "<real_tools>\n"
            "本次运行挂载了**真渗透工具沙箱**，下列工具优先于内置 HTTP 探测使用"
            "（它们给的是工具级证据，比自写 payload 更强）：\n"
        )
        footer = (
            "\n注意：真工具较慢（sqlmap 可能跑几分钟），一次任务里别重复跑同一个目标的同一工具；"
            "工具输出过长时会被自动压缩，关键结论行会保留。\n</real_tools>"
        )
        return header + "\n".join(lines) + footer

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def has(self, name: str) -> bool:
        return name in self._tools

    def tool_names(self) -> list[str]:
        return sorted(self._tools)

    def describe(self) -> str:
        """返回供系统提示词使用的工具清单描述。"""
        return "\n".join(
            f"- {name}: {self._tools[name].description}" for name in sorted(self._tools)
        )

    def execute(self, name: str, action_input: Any) -> str:
        """执行工具，统一捕获异常并返回可读的错误字符串。

        工具调用名额用 `budget.reserve_tool_call()` **原子**占用（检查 + 扣减
        在同一把锁里）。早先的 `can_spend()` + 事后 `add_tool_call()` 是两步，
        N 个并发 worker 能一起穿过检查、一起记账，于是 `--max-tool-calls`
        会被超出（经典 TOCTOU）。

        每次成功执行都会写一条 trace 的 `tool_call` 事件（名称、参数摘要、
        时长、成败、输出大小、错误、溢写句柄）。**"拒绝执行"不写**——
        没有发生的事不该出现在轨迹里。
        """
        tool = self._tools.get(name)
        if tool is None:
            available = ", ".join(sorted(self._tools))
            return f"错误：未知工具 {name!r}。当前角色的可用工具：{available}。"
        if not isinstance(action_input, dict):
            action_input = {}
        granted, reason = self.budget.reserve_tool_call(task=self.task_usage)
        if not granted:
            return (
                f"错误：预算已用尽，本次 {name} 调用未执行（{reason}）。"
                "请立刻用 finish_task 交回已有结论，不要再发起新的工具调用。"
            )
        started = time.time()
        error = ""
        try:
            result = tool.func(_truncate_args(action_input))
        except Exception as exc:  # noqa: BLE001 工具层兜底：任何异常都转成字符串喂回 agent
            error = f"{type(exc).__name__}: {exc}"
            self._trace_tool(name, action_input, started, output="", error=error)
            return f"工具执行出错：{error}"
        text, structured = _govern(name, result, self)
        if structured is not result:
            self.last_result = structured
        self._trace_tool(name, action_input, started, output=text)
        return text

    def _trace_tool(
        self,
        name: str,
        action_input: dict[str, Any],
        started: float,
        *,
        output: str = "",
        error: str = "",
    ) -> None:
        """把一次工具调用写进 trace（参数摘要 + 时长 + 结果规模 + 成败）。"""
        if self.trace is None:
            return
        try:
            handle = ""
            # 输出里若出现溢写句柄，一并记下来——审计时能直接顺着句柄找完整原文。
            match = re.search(rf"{_spill_prefix()}[0-9a-f]{{32}}", str(output or ""))
            if match:
                handle = match.group(0)
            self.trace.record_tool_call(
                task=self.worker_id,
                evidence_id="",  # 内置工具的证据编号在工具自己的返回值里（R/T 编号）
                tool=name,
                command=_summarize_args(action_input),
                ok=not error,
                exit_code=None if not error else -1,
                duration=time.time() - started,
                output_chars=len(str(output or "")),
                spill_handle=handle,
                error=error,
            )
        except Exception:  # noqa: BLE001 记录轨迹失败不该影响工具调用
            pass
