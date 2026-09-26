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

import os
import socket
import ssl
import time
from dataclasses import dataclass, field
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


def _unauthenticated_get(base_url: str, *, timeout: float) -> tuple[int, str]:
    """发一个**不带凭据**的请求，只看服务是否响应。"""
    url = base_url.rstrip("/") + "/v1/models"
    try:
        import httpx

        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
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
        import httpx

        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
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
    if probe.proxy_env:
        lines.append("代理环境变量：" + "，".join(f"{k}={v}" for k, v in probe.proxy_env.items()))
        lines.append("  注意：httpx/openai 默认 trust_env=True，会**真的**走这些代理；端口写错会直接连不上。")
    else:
        lines.append("代理环境变量：（无）—— 直连；若本机需要代理才能出网，这里就是失败原因。")
    for step in probe.steps:
        flag = "[ OK ]" if step.ok else "[FAIL]"
        lines.append(f"{flag} {step.name}（{step.elapsed_ms} ms）：{step.detail}")
    lines.append("")
    lines.append("结论：" + probe.verdict())
    return lines
