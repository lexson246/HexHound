"""浏览器验证：区分「字符串反射」与「JavaScript 真的执行了」。

为什么必须有这一层（HANDOVER §1 与 §10 都写明了这个缺口）：

    XSS 只做到"字符串原样回显"级别，没有真实浏览器执行。

那意味着报告里所有 XSS 结论的强度都停在"payload 出现在响应里"——
而反射 ≠ 执行：内容可能落在 `<textarea>`、被 `Content-Type: text/plain` 当成纯文本、
被 CSP 挡住、或者虽然进了 DOM 但没有可执行的上下文。
把"反射"说成"确认的 XSS"是**最典型的误报**，而且恰好是安全报告里最不能犯的那类错。

对标机制来源（见 `docs/research-notes/strix-pentagi-refresh-2026.md` §C7）：
Strix 通过 CDP 驱动 headless Chromium，能做 a11y 快照、截图、网络路由、
`eval`；PentAGI 只有一个 HTTP 客户端去调 `vxcontrol/scraper` sidecar
（`/markdown`、`/screenshot`），**不能执行 JS、也不捕获 console**，
因此它自己无法确认 XSS 执行。

本模块的判据是**分级**的，绝不把低级别的信号说成高级别的结论：

| 级别 | 判据 | 报告里的措辞 |
| --- | --- | --- |
| `reflected` | payload 出现在**原始 HTTP 响应体**里 | 反射（未确认执行） |
| `dom` | payload 出现在**渲染后的 DOM** 里 | 进入了 DOM（仍未确认执行） |
| `executed` | 执行标记被观测到（DOM 被脚本改写 / console / dialog / 全局变量） | **确认执行** |
| `blocked` | payload 在响应里但被 CSP 等拦下 | 被拦截 |
| `absent` | 响应与 DOM 里都没有 payload | 未反射 |

只有 `executed` 允许把结论写成"确认的 XSS"——这一点在工具返回值里有明确措辞，
并且 prompt/tool 描述里也写死，避免模型自行升级措辞。

**作用域**：浏览器只允许访问授权范围内的目标。校验发生在**打开页面之前**，
并且对**最终 URL**（含重定向后）再校验一次——一次重定向就能把浏览器带到别处。
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

#: 验证结论的级别（从弱到强）。
VERDICT_LEVELS = ("absent", "blocked", "reflected", "dom", "executed")

#: 只有这一级允许把结论写成"确认的 XSS"。
CONFIRMED_LEVEL = "executed"

#: 默认的**无破坏性**验证载荷。
#:
#: 刻意不用 `<script>alert(1)</script>` 当默认：
#: - `alert()` 在 headless 里会**阻塞页面**直到有人点掉，会把一次验证挂死；
#: - `<script>` 标签只在"直接注入到 HTML 解析流"时才执行，用来做判据会把
#:   "属性上下文里的注入"和"innerHTML 插入的脚本"都误判成不执行。
#: 这里用一个只改自己属性的 marker：无副作用、不阻塞、且能同时覆盖
#: 事件处理器（`onerror`/`onload`）与 `srcdoc` 上下文。
MARKER_ATTRIBUTE = "data-hexhound-xss"
EXECUTION_FLAG = "__hexhound_xss_executed__"

#: 载荷模板里的**标记值占位符**。每次验证都会换成一个随机 nonce（见 `build_payloads`）。
#:
#: 为什么非要每次不同（实测踩到的假阳）：原来三种载荷都写死标记值 `1`，
#: 于是"DOM 上存在这个属性"无法证明是**本次**注入造成的——
#: 上一次验证留下的属性、页面自己写的同名属性，都会被算成本次执行的证据。
#: 换成 nonce 之后，"标记值等于本次 nonce"才是证据，因果链闭合。
_MARKER_TOKEN = "__HEXHOUND_MARKER__"

#: 载荷模板（`_MARKER_TOKEN` 处填本次 nonce）。
PAYLOAD_TEMPLATES: tuple[str, ...] = (
    '<img src=x onerror="document.documentElement.setAttribute(\''
    + MARKER_ATTRIBUTE
    + "','"
    + _MARKER_TOKEN
    + "')\">",
    "'\"><svg onload=\"document.documentElement.setAttribute('"
    + MARKER_ATTRIBUTE
    + "','"
    + _MARKER_TOKEN
    + "')\">",
    "<script>document.documentElement.setAttribute(\""
    + MARKER_ATTRIBUTE
    + '","'
    + _MARKER_TOKEN
    + '")</script>',
)

#: 默认载荷（标记值为固定的 `1`，保持对外字符串稳定）。
DEFAULT_PAYLOADS: tuple[str, ...] = tuple(
    template.replace(_MARKER_TOKEN, "1") for template in PAYLOAD_TEMPLATES
)


def new_marker() -> str:
    """生成一次验证专用的标记值（随机、无副作用）。"""
    return "hh" + secrets.token_hex(8)


def build_payloads(marker: str) -> tuple[str, ...]:
    """用本次验证的标记值生成载荷。"""
    value = str(marker or "").strip() or "1"
    return tuple(template.replace(_MARKER_TOKEN, value) for template in PAYLOAD_TEMPLATES)


#: 判定"被 CSP 拦下"的迹象（console 里会有这些字样）。
_CSP_MARKERS = (
    "content security policy",
    "refused to execute inline",
    "refused to load",
    "csp",
)

#: 允许用于验证的协议（不允许 file:/data: —— 那会越过作用域）。
_ALLOWED_SCHEMES = ("http", "https")


class BrowserUnavailable(RuntimeError):
    """Playwright 未安装或浏览器缺失（调用方应转成可读提示，而不是崩）。"""


class ScopeRefused(RuntimeError):
    """浏览器被要求访问授权范围之外的地址。"""


@dataclass
class PageObservation:
    """一次浏览器页面访问的观测结果（全部来自真实浏览器）。"""

    url: str
    final_url: str = ""
    status: int = 0
    raw_body: str = ""
    rendered_html: str = ""
    screenshot: bytes = b""
    console: list[dict[str, Any]] = field(default_factory=list)
    dialogs: list[str] = field(default_factory=list)
    console_errors: list[str] = field(default_factory=list)
    requests: list[str] = field(default_factory=list)
    navigation: list[str] = field(default_factory=list)
    executed_flags: dict[str, Any] = field(default_factory=dict)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    #: 观察过程中的异常说明（页面加载失败等）。这些**必须**带出来：
    #: "页面打不开"和"页面打开但没有反射"是两件完全不同的事，
    #: 后者会被判成 absent（不是漏洞），前者若被静默吞掉就会得出错误结论。
    notes: list[str] = field(default_factory=list)

    def to_dict(self, *, include_body: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "console": self.console[:80],
            "console_errors": self.console_errors[:20],
            "dialogs": self.dialogs[:20],
            "requests": self.requests[:80],
            "navigation": self.navigation[:20],
            "executed_flags": self.executed_flags,
            "cookies": self.cookies[:20],
            "rendered_chars": len(self.rendered_html),
            "raw_chars": len(self.raw_body),
            "screenshot_bytes": len(self.screenshot),
            "notes": list(self.notes),
        }
        if include_body:
            data["rendered_html"] = self.rendered_html
            data["raw_body"] = self.raw_body
        return data


@dataclass
class XssVerdict:
    """一次 XSS 验证的结论。"""

    level: str
    payload: str
    url: str
    final_url: str = ""
    in_response: bool = False
    in_dom: bool = False
    executed: bool = False
    execution_signals: list[str] = field(default_factory=list)
    blocked_by: str = ""
    observation: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    #: 这次验证的截图字节（PNG）。**不进 `to_dict()`**：字典要进 trace 与报告，
    #: 塞进二进制会把它们撑爆。调用方按需取用并存成 `S` 编号证据。
    screenshot: bytes = b""

    @property
    def confirmed(self) -> bool:
        """**只有真的执行了**才允许写成"确认的 XSS"。"""
        return self.level == CONFIRMED_LEVEL

    def statement(self) -> str:
        """结论的**标准措辞**（工具返回值直接用这一句，避免模型自行升级）。"""
        return {
            "executed": f"确认执行：payload 在真实浏览器里执行了（{'; '.join(self.execution_signals)}）",
            "dom": "payload 进入了渲染后的 DOM，但**没有观测到执行**——不能报成确认的 XSS",
            "reflected": "payload 出现在原始响应里，但**没有进入 DOM、也没有执行**——"
                         "只能报成「反射」，不能报成 XSS",
            "blocked": f"payload 出现在响应里，但被拦截（{self.blocked_by}）——不可利用",
            "absent": "payload 既不在响应里也不在 DOM 里——未反射",
        }.get(self.level, f"未知结论：{self.level}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "confirmed": self.confirmed,
            "statement": self.statement(),
            "url": self.url,
            "final_url": self.final_url,
            "in_response": self.in_response,
            "in_dom": self.in_dom,
            "executed": self.executed,
            "execution_signals": list(self.execution_signals),
            "blocked_by": self.blocked_by,
            "notes": list(self.notes),
            "observation": self.observation,
        }


# ---------------------------------------------------------------------------
# 可用性探测
# ---------------------------------------------------------------------------


def playwright_available() -> tuple[bool, str]:
    """检查 Playwright 是否可用，返回 `(可用, 原因)`。

    未安装时给出**可操作**的安装指引——"XSS 未确认"与"浏览器没装"
    是两件完全不同的事，报告里不能混为一谈。
    """
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False, (
            "未安装 Playwright：浏览器执行验证不可用。\n"
            "安装：pip install playwright && python -m playwright install chromium\n"
            "（不装也能用内置 HTTP 探测，但 XSS 只能停在「字符串反射」级别，"
            "不能给出「确认执行」的结论。）"
        )
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError as exc:  # pragma: no cover - 极少见的不完整安装
        return False, f"Playwright 安装不完整：{exc}"
    return True, ""


def _validate_browser_url(url: str, allowed_hosts: frozenset[str]) -> str:
    """浏览器访问前的作用域校验；返回错误信息或空串。"""
    text = str(url or "").strip()
    if not text:
        return "URL 为空。"
    parsed = urlparse(text)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return (
            f"拒绝：浏览器验证只允许 http/https，收到 {parsed.scheme or '(无协议)'!r}。"
            "（file:// 与 data: 会越过作用域校验，一律不允许。）"
        )
    host = (parsed.hostname or "").lower()
    if not host:
        return f"无法从 URL 解析主机：{text}"
    if host not in allowed_hosts:
        allowed = ", ".join(sorted(allowed_hosts))
        return f"拒绝：主机 {host!r} 不在白名单（{allowed}）内，浏览器不会打开它。"
    return ""


#: 判定"这段文本里出现过 payload"时要看的表示形式。
#:
#: 为什么不能只做原样子串匹配（实测踩到的误判）：服务端转义时，payload 在响应与
#: DOM 里变成 `&lt;img ...&gt;`，原样匹配**什么都匹配不到**，于是判成 `absent`
#: （"未反射"）——那是在**低估**风险：页面确实把这个字符串放进了 DOM，
#: 只是当前上下文被转义了。读者看到"未反射"就不会再跟进这个参数，
#: 而真相是"这里是一个输出点，只是这一处转义了"，换个上下文就可能成立。
#:
#: 也不能靠"枚举几种转义写法"：实测 `page.content()` 返回的是**混合编码**
#: （`&lt;` 保持转义、`&#39;` 已被解成 `'`），枚举法永远会漏掉某种组合。
#: 因此改为**把待查文本解码后再匹配**——同一段语义只对应一种解码结果。
_TEXT_ENCODINGS = ("raw", "html", "url")


def _appears(payload: str, text: str) -> bool:
    """payload 是否以（原样 / HTML 转义 / URL 编码）任一形式出现在文本里。"""
    if not payload or not text:
        return False
    body = str(text)
    if payload in body:
        return True
    decoded = body
    try:
        import html as html_module

        decoded = html_module.unescape(body)
    except Exception:  # noqa: BLE001
        decoded = body
    if payload in decoded:
        return True
    # URL 编码形式（有些输出点会把 payload 放进链接/JSON 里）
    try:
        from urllib.parse import unquote

        if payload in unquote(decoded) or payload in unquote(body):
            return True
    except Exception:  # noqa: BLE001
        pass
    return False


def _flag_matches(value: Any, marker: str) -> bool:
    """执行标记是否属于**本次**验证。

    `marker` 为空 = 调用方没有提供 nonce（只做纯判据测试），此时任何真值都算数；
    给了 nonce 就必须**等于**它：不同 nonce 的标记只能说明"页面别处执行过别的载荷"，
    不能证明本次 payload 执行了。
    """
    if not value:
        return False
    if not marker:
        return True
    return str(value) == marker


def _dialog_shows_payload(message: str, payload: str, marker: str) -> bool:
    """对话框内容是否**可归因于本次载荷**。

    只有两种归因才算证据：内容里出现本次载荷原文，或出现本次 nonce。
    页面自己弹的 `alert('请输入用户名')` 与本次注入毫无关系——
    把它算成"执行了"就是确认级误报。

    注意 `payload` 必须用**实际使用的**载荷：早先这里写的是函数参数
    （默认为空串），而 `"" in 任何文本` 恒为真，于是每个普通弹窗都会被
    标注成"对话框内容包含 payload"。
    """
    text = str(message or "")
    if not text:
        return False
    if payload and payload in text:
        return True
    return bool(marker) and marker in text


def classify(
    *,
    payload: str,
    raw_body: str,
    rendered_html: str,
    executed_flags: dict[str, Any] | None = None,
    execution_signals: list[str] | None = None,
    console: list[dict[str, Any]] | None = None,
    blocked_by: str = "",
    marker_value: str = "",
) -> str:
    """把观测结果分级。**这是整个模块的核心判据**，单独测。

    顺序很重要：先看有没有执行，再看 DOM，最后才是原始响应。
    反过来写就会把"响应里有 payload"当成强信号。

    `dom` 与 `reflected` 的判据包含**转义与 URL 编码形式**（见 `_appears`）：
    被转义的输出点仍然是一个输出点，把它判成 `absent` 是低估风险，
    而低估风险比高估更危险——读者会因此不再跟进这个参数。

    `marker_value`（本次验证的 nonce）给出时，执行标记必须与它相符才算数；
    `execution_signals` 由调用方负责**只**放入已归因到本次载荷的信号。
    """
    flags = executed_flags or {}
    signals = list(execution_signals or [])
    if (
        _flag_matches(flags.get(MARKER_ATTRIBUTE), marker_value)
        or _flag_matches(flags.get(EXECUTION_FLAG), marker_value)
        or signals
    ):
        return "executed"
    if blocked_by:
        return "blocked"
    in_dom = _appears(payload, str(rendered_html or ""))
    in_raw = _appears(payload, str(raw_body or ""))
    if in_dom:
        return "dom"
    if in_raw:
        # 响应里有、DOM 里没有：可能是被 CSP 拦下，也可能纯粹是响应体没进 DOM
        joined = " ".join(
            str(item.get("text") or "") for item in (console or []) if isinstance(item, dict)
        ).lower()
        if any(marker in joined for marker in _CSP_MARKERS):
            return "blocked"
        return "reflected"
    return "absent"


# ---------------------------------------------------------------------------
# 浏览器驱动
# ---------------------------------------------------------------------------


class BrowserVerifier:
    """用真实浏览器验证 XSS（反射 / DOM / 执行）。

    每次调用**新建**一个浏览器上下文：验证之间不共享 Cookie 与存储，
    否则前一次注入的 payload 会影响后一次的判据。
    """

    #: 单次页面访问的等待时间上限（毫秒）。执行标记通常在解析时立刻产生，
    #: 但事件处理器（`onerror`）要等资源加载失败，所以留一点时间。
    DEFAULT_WAIT_MS = 1500

    def __init__(
        self,
        *,
        allowed_hosts: frozenset[str],
        timeout_ms: int = 20000,
        wait_ms: int = DEFAULT_WAIT_MS,
        channel: str = "",
        headless: bool = True,
        user_agent: str = "",
    ) -> None:
        self.allowed_hosts = frozenset(host.lower() for host in allowed_hosts if host)
        self.timeout_ms = max(1000, int(timeout_ms))
        self.wait_ms = max(0, int(wait_ms))
        self.channel = channel
        self.headless = bool(headless)
        self.user_agent = user_agent

    # ---------- 可用性 ----------

    def available(self) -> bool:
        return playwright_available()[0]

    # ---------- 观测 ----------

    def observe(self, url: str, *, wait_ms: int | None = None) -> PageObservation:
        """打开页面并收集**证据**：DOM、console、网络、截图、执行标记。

        作用域校验在**打开之前**做，并且对 `final_url`（可能被重定向改写）
        再校验一次——一次重定向就能把浏览器带到别处。
        """
        error = _validate_browser_url(url, self.allowed_hosts)
        if error:
            raise ScopeRefused(error)
        ready, reason = playwright_available()
        if not ready:
            raise BrowserUnavailable(reason)

        from playwright.sync_api import sync_playwright

        console: list[dict[str, Any]] = []
        dialogs: list[str] = []
        requests: list[str] = []
        navigation: list[str] = []
        observation = PageObservation(url=url)

        with sync_playwright() as playwright:
            launch_args: dict[str, Any] = {"headless": self.headless}
            if self.channel:
                launch_args["channel"] = self.channel
            try:
                browser = playwright.chromium.launch(**launch_args)
            except Exception as exc:  # noqa: BLE001 未装浏览器时给出可读原因
                raise BrowserUnavailable(
                    f"启动浏览器失败：{exc}\n"
                    "若提示缺少浏览器，运行 `python -m playwright install chromium`；"
                    "或系统装有 Edge/Chrome 时，构造时传 channel='msedge' / 'chrome'。"
                ) from exc
            context_args: dict[str, Any] = {}
            if self.user_agent:
                context_args["user_agent"] = self.user_agent
            context = browser.new_context(**context_args)
            page = context.new_page()

            page.on(
                "console",
                lambda message: console.append(
                    {"type": message.type, "text": str(message.text)[:500]}
                ),
            )
            page.on("dialog", lambda dialog: (dialogs.append(str(dialog.message)), dialog.dismiss()))
            page.on("request", lambda request: requests.append(str(request.url)[:300]))
            page.on(
                "framenavigated",
                lambda frame: navigation.append(str(frame.url)[:300])
                if frame == page.main_frame
                else None,
            )
            try:
                response = page.goto(
                    url, wait_until="domcontentloaded", timeout=self.timeout_ms
                )
                if response is not None:
                    observation.status = response.status
                    try:
                        observation.raw_body = response.text()
                    except Exception:  # noqa: BLE001 非文本响应体取不到就算了
                        observation.raw_body = ""
                page.wait_for_timeout(self.wait_ms if wait_ms is None else max(0, wait_ms))
            except Exception as exc:  # noqa: BLE001 页面异常不该让验证整体失败
                observation.notes = [f"页面加载异常：{type(exc).__name__}: {exc}"]
            observation.final_url = str(page.url)
            try:
                observation.rendered_html = page.content()
            except Exception:  # noqa: BLE001
                observation.rendered_html = ""
            # 执行标记：脚本改写 DOM 属性 / 显式设置全局变量。
            # 取的是**值**而不是"有没有"：值要和本次 nonce 对上才算本次执行的证据。
            try:
                observation.executed_flags = page.evaluate(
                    """() => {
                        const out = {};
                        const root = document.documentElement;
                        const attr = root && root.getAttribute('data-hexhound-xss');
                        if (attr) out['data-hexhound-xss'] = attr;
                        const anywhere = document.querySelector('[data-hexhound-xss]');
                        if (anywhere && !attr) out['data-hexhound-xss'] = anywhere.getAttribute('data-hexhound-xss');
                        const flag = window.__hexhound_xss_executed__;
                        if (flag) out['__hexhound_xss_executed__'] = (typeof flag === 'string' ? flag : true);
                        return out;
                    }"""
                ) or {}
            except Exception:  # noqa: BLE001
                observation.executed_flags = {}
            try:
                observation.screenshot = page.screenshot(type="png")
            except Exception:  # noqa: BLE001
                observation.screenshot = b""
            try:
                observation.cookies = [
                    {"name": item.get("name"), "domain": item.get("domain")}
                    for item in context.cookies()
                ]
            except Exception:  # noqa: BLE001
                observation.cookies = []
            context.close()
            browser.close()

        observation.console = console
        observation.dialogs = dialogs
        observation.requests = requests
        observation.navigation = navigation
        observation.console_errors = [
            str(item.get("text") or "")
            for item in console
            if str(item.get("type")) == "error"
        ]
        # 最终 URL 也要在范围内：重定向是绕过作用域的经典手法
        final_host = (urlparse(observation.final_url).hostname or "").lower()
        if final_host and final_host not in self.allowed_hosts:
            raise ScopeRefused(
                f"页面被重定向到白名单外的 {final_host!r}（{observation.final_url}）。"
                "已停止验证——浏览器只允许访问授权范围内的目标。"
            )
        return observation

    # ---------- XSS 验证 ----------

    def verify_xss(
        self,
        url: str,
        *,
        payload: str = "",
        param: str = "",
        method: str = "GET",
        baseline: bool = True,
        wait_ms: int | None = None,
    ) -> XssVerdict:
        """验证一个 URL 上的 XSS：反射 / DOM / 执行 **分级**判定。

        `param` 给了就走查询串注入（`?param=payload`），否则直接用给定的 url
        （调用方应把 payload 已经编码进 url）。

        `baseline=True` 时先取一次**不带 payload** 的页面：payload 在基线里
        就出现（页面自己就含这段文本）时判据失效，此时明确标注而不是给结论。

        **执行证据必须能归因到本次载荷**（两条独立要求，都是实测假阳驱动的）：

        1. 每次验证用**自己的随机标记值**（`new_marker`）。DOM 标记属性 / 全局变量
           的值必须等于本次 nonce——上一次验证残留、页面自己写的同名标记都不算。
        2. 对话框只在**内容与本次载荷相关**（含载荷原文或含本次 nonce）时才算执行证据。
           页面自己弹的 `alert('请输入用户名')` 与注入无关，早先却直接把结论推成
           `executed`（**确认级误报**：payload 明明躺在 `<textarea>` 里没执行）。
           基线里已有的弹窗同样被扣除。
        """
        method_value = method.upper()
        if method_value not in ("GET", "POST"):
            raise ValueError(f"浏览器 XSS 验证只支持 GET/POST，收到 {method!r}。")

        # 自定义载荷无法带我们的标记值，此时只能靠"载荷原文"归因。
        marker = "" if payload else new_marker()
        chosen = payload or build_payloads(marker)[0]
        target_url = url
        if param:
            from urllib.parse import quote

            separator = "&" if "?" in url else "?"
            target_url = f"{url}{separator}{param}={quote(chosen, safe='')}"

        notes: list[str] = []
        baseline_dialogs: list[str] = []
        if baseline:
            baseline_observation = self.observe(url, wait_ms=wait_ms)
            baseline_dialogs = list(baseline_observation.dialogs)
            if chosen in baseline_observation.raw_body or chosen in baseline_observation.rendered_html:
                notes.append(
                    "基线页面里**本来就含**这段 payload 文本，本次判据不可靠——"
                    "请换一个不会与页面内容重合的 payload 再验证。"
                )

        observation = self.observe(target_url, wait_ms=wait_ms)
        signals: list[str] = []
        if _flag_matches(observation.executed_flags.get(MARKER_ATTRIBUTE), marker):
            signals.append(
                f"DOM 上出现了执行标记属性 {MARKER_ATTRIBUTE}={marker}"
                if marker
                else "DOM 上出现了执行标记属性 " + MARKER_ATTRIBUTE
            )
        if _flag_matches(observation.executed_flags.get(EXECUTION_FLAG), marker):
            signals.append("页面设置了执行标记全局变量 " + EXECUTION_FLAG)

        # 只把"基线里没有的"弹窗纳入考虑，再只把"能归因到本次载荷的"当证据。
        fresh_dialogs = [d for d in observation.dialogs if d not in baseline_dialogs]
        correlated = [
            message for message in fresh_dialogs if _dialog_shows_payload(message, chosen, marker)
        ]
        if correlated:
            signals.append(f"页面弹出了与本次载荷相关的对话框（{len(correlated)} 个）")
        elif fresh_dialogs:
            notes.append(
                f"页面弹出了 {len(fresh_dialogs)} 个对话框，但内容与本次载荷无关"
                "（页面自身行为，如表单校验提示）——**不作为执行证据**。"
            )

        blocked_by = ""
        joined_console = " ".join(
            str(item.get("text") or "") for item in observation.console
        ).lower()
        if any(marker_text in joined_console for marker_text in _CSP_MARKERS):
            blocked_by = "CSP / 浏览器安全策略"

        level = classify(
            payload=chosen,
            raw_body=observation.raw_body,
            rendered_html=observation.rendered_html,
            executed_flags=observation.executed_flags,
            execution_signals=signals,
            console=observation.console,
            blocked_by=blocked_by,
            marker_value=marker,
        )
        verdict = XssVerdict(
            level=level,
            payload=chosen,
            url=target_url,
            final_url=observation.final_url,
            in_response=_appears(chosen, observation.raw_body or ""),
            in_dom=_appears(chosen, observation.rendered_html or ""),
            executed=level == "executed",
            execution_signals=signals,
            blocked_by=blocked_by,
            observation=observation.to_dict(),
            notes=notes + observation.notes,
            screenshot=observation.screenshot or b"",
        )
        if verdict.in_dom and not verdict.executed:
            verdict.notes.append(
                "payload 出现在渲染后的 DOM 里，但**没有观测到执行**"
                "（可能被服务端转义、落在不可执行的元素里，或缺少触发条件）——"
                "结论只能到「进了 DOM」，不能写成确认的 XSS。"
            )
        return verdict


def verification_payloads(limit: int = 0, marker: str = "") -> list[str]:
    """返回可用的无破坏性验证载荷（供工具描述与测试共用）。

    给了 `marker` 就返回**带该标记值**的载荷（真实验证走这条，见 `build_payloads`）；
    否则返回对外稳定的默认载荷。
    """
    payloads = list(build_payloads(marker) if marker else DEFAULT_PAYLOADS)
    return payloads[:limit] if limit else payloads


def summarize_verdict(verdict: XssVerdict) -> str:
    """把结论渲染成给模型看的一段文本（含**明确的措辞约束**）。"""
    lines = [
        f"判定：**{verdict.level}** —— {verdict.statement()}",
        f"目标：{verdict.url}"
        + (f"（最终 {verdict.final_url}）" if verdict.final_url and verdict.final_url != verdict.url else ""),
        f"载荷：{verdict.payload}",
        f"- 原始响应里出现载荷：{'是' if verdict.in_response else '否'}",
        f"- 渲染后 DOM 里出现载荷：{'是' if verdict.in_dom else '否'}",
        f"- 观测到执行：{'是' if verdict.executed else '否'}",
    ]
    if verdict.execution_signals:
        lines.append("- 执行信号：" + "；".join(verdict.execution_signals))
    if verdict.blocked_by:
        lines.append(f"- 被拦截：{verdict.blocked_by}")
    for note in verdict.notes:
        lines.append(f"- 注意：{note}")
    lines += [
        "",
        "**措辞约束（必须遵守）**：",
        "- 只有 `executed` 才能写「确认的 XSS」；",
        "- `dom` 只能写「payload 进入了 DOM，未确认执行」；",
        "- `reflected` 只能写「反射」，**不能**写 XSS；",
        "- `blocked` / `absent` 都不是漏洞。",
    ]
    return "\n".join(lines)


def report_screenshot(verdict: XssVerdict, observation: PageObservation | None = None) -> bytes:
    """取回这次验证的截图字节（调用方负责存成 `S` 编号证据）。

    `XssVerdict` 里存的是观测的**摘要**（不含二进制），因此截图要通过
    `observation` 传回来。没给就返回空——截图是"锦上添花的证据"，
    不该因为它缺失而让整个验证失败。
    """
    if observation is None:
        return b""
    return observation.screenshot or b""


__all__ = [
    "CONFIRMED_LEVEL",
    "DEFAULT_PAYLOADS",
    "EXECUTION_FLAG",
    "MARKER_ATTRIBUTE",
    "PAYLOAD_TEMPLATES",
    "VERDICT_LEVELS",
    "BrowserUnavailable",
    "BrowserVerifier",
    "PageObservation",
    "ScopeRefused",
    "XssVerdict",
    "build_payloads",
    "classify",
    "new_marker",
    "playwright_available",
    "summarize_verdict",
    "verification_payloads",
]
