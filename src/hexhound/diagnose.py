"""连通性诊断：把"模型调不通"从一句话变成可判定的结论。

为什么需要它（真实事故）：一次运行只记下 `APIConnectionError: Connection error.` ——
这是 OpenAI SDK 的**摘要**，底层原因（DNS 解析失败 / 连接被拒 / TLS 被拦 / 代理挂掉）
全被吞掉了。事后既无法判定是谁的问题，也无法给用户下一步建议。
`Connection error.` 这种信息量约等于零：它同时覆盖了"网线没插"和"代理端口写错"。

这里做两件事：

1. `describe_exception()`：把异常的**因果链**摊开（`__cause__` / `__context__`），
   于是 `APIConnectionError` 后面会跟着真正的 `httpx.ConnectError: [Errno 11001]
   getaddrinfo failed` 或 `[WinError 10061] 目标计算机积极拒绝`。
2. `probe_endpoint()`：对配置里的 base_url 做**不花额度**的分步探测
   （DNS → TCP → TLS → 未认证 HTTP），并把代理环境变量一并报出来。

刻意**不发带凭据的请求**：诊断的目的是判断"通不通"，不是"key 对不对"——
后者由设置面板的「测试连接」负责（那一步才会消耗几个 token）。
"""
from __future__ import annotations

import locale
import os
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

#: 常见代理环境变量（httpx/openai 默认 trust_env=True 会读它们）。
PROXY_ENV_KEYS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "all_proxy",
    "NO_PROXY", "no_proxy",
)


def exception_chain(exc: BaseException, limit: int = 6) -> list[str]:
    """异常的因果链，从最外层到最内层（去重）。"""
    chain: list[str] = []
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and len(chain) < limit and id(current) not in seen:
        seen.add(id(current))
        text = f"{type(current).__name__}: {current}".strip()
        # Windows 的 OSError 带 winerror；把它显式带出来，别只留 errno
        winerror = getattr(current, "winerror", None)
        if winerror and str(winerror) not in text:
            text += f" (winerror={winerror})"
        chain.append(text)
        current = current.__cause__ or current.__context__
    return chain


def describe_exception(exc: BaseException) -> str:
    """一行摘要 + 底层原因。用于报告与界面，替掉只有一句"Connection error."的现状。"""
    chain = exception_chain(exc)
    if not chain:
        return type(exc).__name__
    if len(chain) == 1:
        return chain[0]
    return chain[0] + " ← " + " ← ".join(chain[1:])


def proxy_environment() -> dict[str, str]:
    """当前进程能看到的代理相关环境变量（只回非空的）。"""
    return {key: os.getenv(key, "") for key in PROXY_ENV_KEYS if os.getenv(key, "").strip()}


def effective_proxy() -> dict[str, str]:
    """**httpx/openai 真正会用的**代理：环境变量 + Windows 系统代理（注册表）。

    为什么不能只看环境变量（真实事故）：一台机器上 `ProxyEnable=1`、
    `ProxyServer=127.0.0.1:7892`（Clash/V2Ray 那类"设置系统代理"），
    而代理客户端已经退出、端口没人监听。环境变量是空的，于是所有诊断都说"直连"，
    但 httpx 在 `trust_env=True` 时会调用 `urllib.request.getproxies()`，
    而后者在 Windows 上回落到注册表 —— 请求实际全打到那个死端口上，
    症状是"关掉 VPN 就再也连不上，且换任何网络都一样"（系统代理是用户级、
    机器级设置，**与当前连的是哪个网络无关**）。

    这里返回 httpx 会用的那份解析结果（含来源说明）。
    """
    resolved: dict[str, str] = {}
    try:
        import urllib.request

        for key, value in (urllib.request.getproxies() or {}).items():
            if value:
                resolved[str(key)] = str(value)
    except Exception:  # noqa: BLE001 拿不到就当没有
        pass
    return resolved


def registry_proxy_state() -> dict[str, object]:
    """Windows 系统代理的原始注册表状态（供诊断展示；非 Windows 返回空）。"""
    if os.name != "nt":
        return {}
    try:
        import winreg

        state: dict[str, object] = {}
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        ) as key:
            for name in ("ProxyEnable", "ProxyServer", "AutoConfigURL"):
                try:
                    state[name] = winreg.QueryValueEx(key, name)[0]
                except FileNotFoundError:
                    continue
        return state
    except OSError:
        return {}


def proxy_health(proxies: dict[str, str] | None = None, *, timeout: float = 1.5) -> tuple[bool, str]:
    """配置了代理但端口没人监听 → `(True, 说明)`；否则 `(False, "")`。

    这一条把"连不上"从玄学变成一句话：**代理端口是死的**。
    """
    proxies = effective_proxy() if proxies is None else proxies
    url = proxies.get("https") or proxies.get("http") or proxies.get("all") or ""
    if not url:
        return False, ""
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
    if not host:
        return False, ""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return False, f"代理 {url} 可连"
    except OSError as exc:
        return True, f"代理 {url} **连不上**（{type(exc).__name__}: {exc}）"
    finally:
        sock.close()


@dataclass
class ProbeStep:
    """一步探测的结果。"""

    name: str
    ok: bool
    detail: str
    elapsed_ms: int = 0


@dataclass
class EndpointProbe:
    """对 base_url 的完整探测结果。"""

    base_url: str
    host: str = ""
    port: int = 0
    steps: list[ProbeStep] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    proxy_env: dict[str, str] = field(default_factory=dict)

    @property
    def reachable(self) -> bool:
        """TCP（https 还要 TLS）**确实探测过且通过**才算链路可达。

        不能写成 `all(step.ok for step in steps if step.name in (...))`：
        早期探测就在 DNS 失败时返回、根本没有 TCP/TLS 步骤，
        对空序列求 all() 得到 True——"没测"被当成了"通过"。
        （这与 XSS 那边 `"" in 文本` 恒真是同一类错误：空集上的全称判断。）
        """
        by_name = {step.name: step for step in self.steps}
        tcp = by_name.get("TCP 连接")
        if tcp is None or not tcp.ok:
            return False
        tls = by_name.get("TLS 握手")
        return tls.ok if tls is not None else True

    def verdict(self) -> str:
        """给用户的一句话结论 + 下一步。"""
        failed = [step for step in self.steps if not step.ok]
        if not failed:
            return "链路可达：DNS/TCP/TLS 都正常。若模型调用仍失败，问题多半在 key、模型名或额度上。"
        first = failed[0]
        advice = {
            "解析主机名": "域名解析失败：检查网络、DNS，或 base_url 是否写错。",
            "TCP 连接": "连不上端口：可能是网络不通、被防火墙拦、或代理端口写错。",
            "TLS 握手": "TLS 失败：可能是证书被中间设备替换（公司代理/杀软），或系统根证书异常。",
        }.get(first.name, "按上面的失败步骤排查。")
        return f"{first.name} 失败：{first.detail}。{advice}"


def _resolve(host: str, timeout: float) -> tuple[list[str], str]:
    """解析主机名，返回 (地址列表, 错误说明)。"""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        return [], f"{type(exc).__name__}: {exc}"
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    return addresses, ""


def probe_endpoint(base_url: str, *, timeout: float = 8.0) -> EndpointProbe:
    """分步探测一个 base_url：DNS → TCP → TLS → 未认证 HTTP。**不发凭据、不花额度**。"""
    probe = EndpointProbe(base_url=str(base_url or ""), proxy_env=proxy_environment())
    parsed = urlparse(probe.base_url if "://" in probe.base_url else "//" + probe.base_url)
    host = (parsed.hostname or "").lower()
    probe.host = host
    probe.port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
    if not host:
        probe.steps.append(ProbeStep("解析主机名", False, f"base_url 无法解析出主机名：{base_url!r}"))
        return probe

    started = time.monotonic()
    addresses, error = _resolve(host, timeout)
    elapsed = int((time.monotonic() - started) * 1000)
    if addresses:
        probe.addresses = addresses
        probe.steps.append(ProbeStep("解析主机名", True, f"{host} → {', '.join(addresses[:4])}", elapsed))
    else:
        probe.steps.append(ProbeStep("解析主机名", False, error or "无解析结果", elapsed))
        return probe

    # TCP：对每个解析到的地址都试一次，报出**第一个能连上的**；全失败则汇总
    tcp_ok = False
    tcp_detail: list[str] = []
    started = time.monotonic()
    for address in addresses[:4]:
        sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((address, probe.port))
            tcp_ok = True
            tcp_detail.append(f"{address}:{probe.port} 可连")
            break
        except OSError as exc:
            tcp_detail.append(f"{address}:{probe.port} {type(exc).__name__}: {exc}")
        finally:
            sock.close()
    elapsed = int((time.monotonic() - started) * 1000)
    probe.steps.append(ProbeStep("TCP 连接", tcp_ok, "；".join(tcp_detail[:3]), elapsed))
    if not tcp_ok:
        return probe

    if parsed.scheme == "https":
        started = time.monotonic()
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, probe.port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert() or {}
                    subject = dict(item[0] for item in cert.get("subject", ()) if item)
                    issuer = dict(item[0] for item in cert.get("issuer", ()) if item)
                    detail = (
                        f"{tls.version()} · 证书 CN={subject.get('commonName', '?')} "
                        f"签发者={issuer.get('organizationName') or issuer.get('commonName', '?')}"
                    )
            probe.steps.append(ProbeStep("TLS 握手", True, detail, int((time.monotonic() - started) * 1000)))
        except (ssl.SSLError, OSError) as exc:
            probe.steps.append(
                ProbeStep("TLS 握手", False, f"{type(exc).__name__}: {exc}", int((time.monotonic() - started) * 1000))
            )
            return probe

    # 未认证 HTTP 探测：401/403/404 都说明"服务在、链路通"
    started = time.monotonic()
    status, detail = _unauthenticated_get(probe.base_url, timeout=timeout)
    elapsed = int((time.monotonic() - started) * 1000)
    if status:
        probe.steps.append(ProbeStep("HTTP 响应（未认证）", True, f"HTTP {status}", elapsed))
    else:
        probe.steps.append(ProbeStep("HTTP 响应（未认证）", False, detail, elapsed))
    return probe


def _is_loopback(host: str) -> bool:
    name = str(host or "").strip().strip("[]").lower()
    if name in ("localhost", "::1", "0.0.0.0"):
        return True
    return name.startswith("127.")


def diagnostic_client(base_url: str, *, timeout: float) -> Any:
    """构造诊断用的 httpx 客户端：**不读环境变量**，代理由我们自己决定。

    为什么要绕开 `trust_env`（真实故障，Round4 实测）：不少代理工具会把
    `NO_PROXY=localhost,127.0.0.1,::1,[::1]` 写进环境变量，而 httpx 解析
    `[::1]` 这个条目时会抛 `InvalidURL: Invalid port: ':1]'`——**请求还没发出去**
    诊断自己就先崩了，用户看到的是一句与网络状况毫无关系的 "InvalidURL"。

    规则：
    - 本机目标（127.0.0.1/localhost/::1）**直连**，绝不走代理——
      诊断本地服务却经过代理毫无意义，而且代理多半连不上回环地址；
    - 其它目标用 `effective_proxy()` 解析出来的代理（含 Windows 系统代理）。
    """
    import httpx

    kwargs: dict[str, Any] = {
        "timeout": timeout,
        "follow_redirects": True,
        # 关掉 env 解析：代理由上面的规则显式给出，坏掉的 NO_PROXY 不该拖垮诊断
        "trust_env": False,
    }
    host = urlparse(str(base_url or "")).hostname or ""
    if not _is_loopback(host):
        proxy = effective_proxy()
        chosen = proxy.get("all") or proxy.get("https") or proxy.get("http") or ""
        if chosen:
            kwargs["proxy"] = chosen
    return httpx.Client(**kwargs)


def _unauthenticated_get(base_url: str, *, timeout: float) -> tuple[int, str]:
    """发一个**不带凭据**的请求，只看服务是否响应。"""
    url = base_url.rstrip("/") + "/v1/models"
    try:
        with diagnostic_client(base_url, timeout=timeout) as client:
            response = client.get(url)
            return response.status_code, ""
    except Exception as exc:  # noqa: BLE001 探测失败就是失败，不必区分类型
        return 0, describe_exception(exc)


def list_models(base_url: str, api_key: str, *, timeout: float = 15.0) -> tuple[list[str], str]:
    """列出该 key 可用的模型名，返回 `(模型列表, 错误说明)`。

    **不计费**：`GET /v1/models` 不产生 token 用量，因此这是"核对模型名"
    最便宜的权威手段——比跑一次审计或反复猜名字都划算。
    模型名写错时提供商的报错常常只说"模型不存在"，而合法名字就在这个列表里。
    """
    if not str(api_key or "").strip():
        return [], "没有可用的 API key（此接口需要鉴权；key 不会被记录或打印）"
    url = str(base_url or "").rstrip("/") + "/v1/models"
    try:
        with diagnostic_client(base_url, timeout=timeout) as client:
            response = client.get(url, headers={"Authorization": f"Bearer {api_key}"})
    except Exception as exc:  # noqa: BLE001
        return [], describe_exception(exc)
    if response.status_code != 200:
        return [], f"HTTP {response.status_code}：{response.text[:200]}"
    try:
        payload = response.json()
    except ValueError as exc:
        return [], f"响应不是 JSON：{exc}"
    models = [
        str(item.get("id"))
        for item in (payload.get("data") or [])
        if isinstance(item, dict) and item.get("id")
    ]
    return models, ""


def format_probe(probe: EndpointProbe, *, title: str = "连通性诊断") -> list[str]:
    """把探测结果渲染成人类可读的多行文本（CLI 与界面共用）。"""
    lines = [f"== {title} ==", f"目标：{probe.base_url}（{probe.host}:{probe.port}）"]
    lines.extend(proxy_report())
    lines.extend(local_network_facts())
    for step in probe.steps:
        flag = "[ OK ]" if step.ok else "[FAIL]"
        lines.append(f"{flag} {step.name}（{step.elapsed_ms} ms）：{step.detail}")
    lines.append("")
    lines.append("结论：" + probe.verdict())
    return lines


def proxy_report() -> list[str]:
    """代理情况的两行报告：环境变量 + **系统代理（注册表）** + 端口是否活着。

    系统代理那一行是这次事故的关键：环境变量全空、但注册表里挂着
    `ProxyEnable=1 → 127.0.0.1:7892`，httpx 照样走它，于是"直连正常"的结论是错的。
    """
    lines: list[str] = []
    env = proxy_environment()
    lines.append(
        "代理环境变量：" + ("，".join(f"{k}={v}" for k, v in env.items()) if env else "（无）")
    )
    resolved = effective_proxy()
    if resolved:
        lines.append(
            "httpx 实际会用的代理：" + "，".join(f"{k}={v}" for k, v in resolved.items())
        )
        dead, detail = proxy_health(resolved)
        if dead:
            lines.append(f"  [!!] {detail} —— 请求会全部打到这个端口，"
                         "表现为「突然连不上、换任何网络都一样」。")
            lines.append("       处理：启动代理客户端，或用系统设置关掉「使用代理服务器」。")
        else:
            lines.append(f"  [i] {detail}（走代理；若代理本身不通，请先修代理）")
    else:
        lines.append("httpx 实际会用的代理：（无）—— 直连")
    state = registry_proxy_state()
    if state:
        lines.append(
            "Windows 系统代理：" + "，".join(f"{k}={v}" for k, v in state.items())
            + ("（ProxyEnable=0 → 未启用）" if not state.get("ProxyEnable") else "")
        )
    return lines


def probe_lines(base_url: str, *, timeout: float = 6.0, indent: str = "  ") -> list[str]:
    """给"模型调用失败"现场用的一小段探测输出（**不发凭据、不消耗额度**）。

    为什么在失败现场自动跑一次：真实事故里只留下 `APIConnectionError: Connection error.`，
    用户既不知道是谁的问题，也不知道下一步做什么。失败的那一刻恰恰是**唯一**
    能观察到现场的时刻（网络状态稍后就变了），所以必须当场取证。
    探测耗时几百毫秒，比"事后猜"便宜得多。
    """
    try:
        probe = probe_endpoint(base_url, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 诊断本身失败绝不能影响收尾
        return [f"{indent}（连通性探测未能完成：{type(exc).__name__}: {exc}）"]
    lines: list[str] = []
    for step in probe.steps:
        flag = "[OK]" if step.ok else "[!!]"
        lines.append(f"{indent}{flag} {step.name}：{step.detail}")
    if probe.proxy_env:
        lines.append(f"{indent}[!!] 检测到代理环境变量：{'，'.join(probe.proxy_env)}")
    lines.append(f"{indent}结论：{probe.verdict()}")
    return lines


def is_network_error(exc: BaseException) -> bool:
    """这个异常是否属于"连不上"（网络类）——决定要不要在失败现场做连通性探测。"""
    from .llm import classify_error

    try:
        category, _advice = classify_error(exc if isinstance(exc, Exception) else Exception(str(exc)))
    except Exception:  # noqa: BLE001 归类失败时保守处理：不探测
        return False
    return category == "network"


#: 名字里带这些词的适配器多半是隧道/虚拟网卡（VPN、WSL、虚拟机、代理的 TUN 模式）。
TUNNEL_HINTS = (
    "tun", "tap", "wireguard", "tailscale", "openvpn", "clash", "wintun",
    "v2ray", "singbox", "sing-box", "warp", "zerotier", "softether", "anyconnect",
)


def parse_default_routes(route_print: str) -> list[tuple[str, str]]:
    """从 `route print -4` / `ip route` 文本里取默认路由 `(网关, 接口)`。

    为什么关心这个：VPN 客户端崩溃/退出后常留下一条指向死隧道的默认路由，
    于是**换任何网络都不通**（流量被送进黑洞），而重新打开 VPN 又"好了"。
    这是"必须挂 VPN 才能上网/调模型"最常见的成因，值得单独报出来。
    """
    routes: list[tuple[str, str]] = []
    for line in str(route_print or "").splitlines():
        text = line.strip()
        if not text:
            continue
        # Windows: "0.0.0.0          0.0.0.0    10.134.173.147     10.134.173.106     25"
        parts = text.split()
        if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gateway = parts[2]
            interface = next(
                (item for item in parts[3:] if item.count(".") == 3 and item != "0.0.0.0"),
                "",
            )
            routes.append((gateway, interface))
        # Linux: "default via 192.168.1.1 dev wlan0 proto dhcp metric 600"
        elif parts[0] == "default":
            gateway = parts[parts.index("via") + 1] if "via" in parts else ""
            interface = parts[parts.index("dev") + 1] if "dev" in parts else ""
            routes.append((gateway, interface))
    return routes


def parse_adapter_names(ipconfig_text: str) -> list[str]:
    """从 `ipconfig /all`（或 `ip -br link`）里取出适配器名字。"""
    names: list[str] = []
    for line in str(ipconfig_text or "").splitlines():
        text = line.strip()
        if text.endswith(":") and "adapter" in text.lower():
            name = text.split("adapter", 1)[1].strip().rstrip(":").strip()
            if name:
                names.append(name)
        elif " " in text and text.split()[0].isdigit():
            # Linux `ip -br link`: "2: wlan0    UP   ..."
            names.append(text.split()[1].split("@")[0])
    return names


def _decode_console(raw: bytes | str) -> str:
    """控制台命令输出的解码：Windows 上 `route`/`ipconfig` 按**ANSI 代码页**输出。

    实测事故（中文 Windows + 本地 CI 执行器）：`subprocess.run(..., text=True)`
    会按 UTF-8 去解 GBK 字节，读取线程里抛 `UnicodeDecodeError`——输出被截断，
    而调用方只看到一条 `PytestUnhandledThreadExceptionWarning`，
    排查时完全看不出是"本机命令输出不是 UTF-8"。

    顺序：UTF-8 → 系统首选编码（中文 Windows 即 cp936）→ GBK → 兜底替换解码。
    传入已经是 `str` 时原样返回（调用方可能自己解过码）。
    """
    if isinstance(raw, str):
        return raw
    for name in ("utf-8", locale.getpreferredencoding(False), "gbk", "cp1252"):
        if not name:
            continue
        try:
            return raw.decode(name)
        except (UnicodeDecodeError, LookupError):
            continue
    from .sanitize import decode_output

    return decode_output(raw)


def _run_console(command: list[str], *, timeout: float = 10.0) -> str:
    """跑一条只读的本机命令并解码输出（绝不抛异常，失败返回空串）。"""
    import subprocess

    try:
        proc = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return _decode_console(proc.stdout or b"")


def local_network_facts() -> list[str]:
    """本机网络事实（默认路由 / 隧道适配器 / DNS）——用于解释"为什么只有挂 VPN 才行"。

    只读本机命令输出，不联网。任何一步失败都不影响结论（返回已获得的部分）。
    """
    facts: list[str] = []
    is_windows = os.name == "nt"
    route_out = _run_console(["route", "print", "-4"] if is_windows else ["ip", "route"])
    if route_out:
        routes = parse_default_routes(route_out)
        if routes:
            described = "；".join(f"网关 {gw}" + (f"（接口 {iface}）" if iface else "") for gw, iface in routes)
            facts.append(f"默认路由 {len(routes)} 条：{described}")
            if len(routes) > 1:
                facts.append(
                    "  [!!] 存在多条默认路由：VPN/虚拟网卡退出后残留的路由会把流量送进死隧道——"
                    "症状正是「换任何网络都不通，重新打开 VPN 又好了」。"
                )
        else:
            facts.append("默认路由：未解析到（可能全部走 VPN 隧道，或命令输出格式不同）")
    else:
        facts.append("默认路由：读取失败（命令不可用或超时）")

    cfg_out = _run_console(["ipconfig", "/all"] if is_windows else ["ip", "-br", "link"])
    if cfg_out:
        adapters = parse_adapter_names(cfg_out)
        tunnels = [name for name in adapters if any(h in name.lower() for h in TUNNEL_HINTS)]
        if tunnels:
            facts.append(f"隧道/虚拟适配器：{'，'.join(tunnels)}")
            facts.append(
                "  [i] 若这些适配器在 VPN 关闭后仍处于启用状态，先禁用/重启它们再试——"
                "半初始化状态（例如 Tailscale 报 starting）会拖慢或阻断解析。"
            )
    else:
        facts.append("适配器：读取失败（命令不可用或超时）")
    return facts
