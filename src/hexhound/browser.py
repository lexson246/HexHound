from __future__ import annotations

import json
import os
from http.cookies import CookieError, SimpleCookie
from typing import Any
from urllib.parse import urljoin, urlparse

from .config import scope_allows


def _origin(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    suffix = f":{port}" if port and port != {"http": 80, "https": 443}.get(parsed.scheme) else ""
    return f"{parsed.scheme.lower()}://{host.lower()}{suffix}"


def _redirect_target_allowed(
    request_url: str, location: str, *, allowed_hosts: frozenset[str], target_host: str,
) -> tuple[bool, str]:
    """重定向目标是否允许跟随（不允许时给出可读原因）。

    两条规则，都是**实测**得到的（Round4 浏览器隔离用例）：

    1. **越界**：目标主机不在授权范围内 → 绝不跟随（把浏览器带出授权范围）。
    2. **同主机跨源**：`http://host:A → http://host:B`。cookie 是按主机而不是按端口
       发送的，所以跟随这种重定向等于把登录态交给 A 之外的端口。

    不同主机的重定向（例如 `127.0.0.1 → localhost`、`www → api`）允许跟随，
    但认证头会被摘掉——那是调用方 `scoped_request()` 在做的事。
    """
    if not location:
        return True, ""
    target = urljoin(request_url, location)
    parsed = urlparse(target)
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"非 HTTP(S) 重定向目标（{target}）"
    host = (parsed.hostname or "").lower()
    if not scope_allows(allowed_hosts, host):
        return False, f"重定向到授权范围外的主机 {host!r}（{target}）"
    if host == target_host and _origin(target) != _origin(request_url):
        return False, (
            f"重定向到同一主机的另一个源（{target}）——cookie 按主机发送，"
            "跟随它会把登录态交给该主机的其它端口"
        )
    return True, ""


def browser_context(
    browser: Any,
    url: str,
    *,
    allowed_hosts: frozenset[str],
    auth_headers: dict[str, str] | None = None,
    cookies: list[dict[str, Any]] | None = None,
    storage_state: dict[str, Any] | None = None,
    session_storage: dict[str, str] | None = None,
    user_agent: str = "",
    blocked_redirects: list[str] | None = None,
) -> Any:
    """创建隔离上下文：认证仅属于当前目标，每个请求都先检查作用域。

    `blocked_redirects`：可选的可变列表，被拦下的重定向会写进这里
    （调用方据此在观察结果里说明"页面想带你去哪、为什么没让它去"）。
    """
    host = (urlparse(url).hostname or "").lower()
    origin = _origin(url)
    headers = {str(k): str(v) for k, v in (auth_headers or {}).items()}
    target_cookies = []
    state = storage_state or {}
    for item in [*(state.get("cookies") or []), *(cookies or [])]:
        domain = str(item.get("domain") or "").lower().lstrip(".")
        cookie_host = (urlparse(str(item.get("url") or "")).hostname or domain).lower()
        if cookie_host and host != cookie_host and not host.endswith("." + cookie_host):
            continue
        cookie = {k: v for k, v in item.items() if k != "url"}
        # 将父域 cookie 收窄到当前主机，避免共享白名单里的兄弟站点拿到登录态。
        cookie.update(domain=host, path=item.get("path") or "/")
        target_cookies.append(cookie)
    for name in list(headers):
        if name.lower() == "cookie":
            jar = SimpleCookie()
            cookie_header = headers.pop(name)
            try:
                jar.load(cookie_header)
            except CookieError as exc:
                raise ValueError("浏览器认证 Cookie 格式无效。") from exc
            if cookie_header.strip() and not jar:
                raise ValueError("浏览器认证 Cookie 格式无效。")
            for cookie in jar.values():
                target_cookies.append({"name": cookie.key, "value": cookie.value, "url": origin + "/"})
    context_args: dict[str, Any] = {"service_workers": "block"}
    if user_agent:
        context_args["user_agent"] = user_agent
    context_args["storage_state"] = {
        "cookies": [],
        "origins": [item for item in (state.get("origins") or []) if item.get("origin") == origin],
    }
    context = browser.new_context(**context_args)
    if target_cookies:
        context.add_cookies(target_cookies)
    if session_storage:
        context.add_init_script(
            "if (location.origin === " + json.dumps(origin) + ") {"
            "for (const [key, value] of Object.entries(" + json.dumps(session_storage) + "))"
            "sessionStorage.setItem(key, String(value));}"
        )
    sensitive = {name.lower() for name in headers} | {"authorization", "proxy-authorization", "x-api-key"}

    def scoped_request(route: Any) -> None:
        request_url = str(route.request.url)
        parsed = urlparse(request_url)
        request_host = (parsed.hostname or "").lower()
        if parsed.scheme not in ("http", "https") or not scope_allows(allowed_hosts, request_host):
            route.abort()
            return
        same_origin = _origin(request_url) == origin
        # Cookie 无法通过 Route.continue_ 覆盖；浏览器按主机（不按端口）发送 cookie。
        if target_cookies and request_host == host and not same_origin:
            route.abort()
            return
        request_headers = dict(route.request.headers)
        if same_origin:
            request_headers.update(headers)
        else:
            request_headers = {k: v for k, v in request_headers.items() if k.lower() not in sensitive}
        response = route.fetch(headers=request_headers, max_redirects=0)
        location = str(response.headers.get("location") or "")
        allowed, reason = _redirect_target_allowed(
            request_url, location, allowed_hosts=allowed_hosts, target_host=host,
        )
        if location and not allowed:
            # **必须在响应里摘掉 Location**：实测浏览器跟随重定向时不会再经过
            # 路由拦截器（route 回调只被调用一次），所以"等下一个请求再拦"是拦不住的——
            # 越界目标与同主机其它端口都已经收到过请求了。
            if blocked_redirects is not None:
                blocked_redirects.append(f"{reason}｜被拦截的地址：{urljoin(request_url, location)}")
            response_headers = {
                key: value for key, value in response.headers.items()
                if key.lower() != "location"
            }
            try:
                body = response.body()
            except Exception:  # noqa: BLE001 二进制/流式响应体取不到就不带体
                body = b""
            route.fulfill(status=response.status, headers=response_headers, body=body)
            return
        route.fulfill(response=response)

    context.route("**/*", scoped_request)
    return context


def dynamic_scan(
    url: str,
    wait_ms: int = 2500,
    timeout_ms: int = 20000,
    execute_js: str | None = None,
    *,
    allowed_hosts: frozenset[str] | None = None,
    auth_headers: dict[str, str] | None = None,
    cookies: list[dict[str, Any]] | None = None,
    storage_state: dict[str, Any] | None = None,
    session_storage: dict[str, str] | None = None,
) -> dict[str, Any]:
    """用系统 Edge 无头执行页面，返回渲染后 HTML、截图和网络请求。"""
    from .xssverify import ScopeRefused, _validate_browser_url

    hosts = allowed_hosts if allowed_hosts is not None else frozenset({urlparse(url).hostname or ""})
    error = _validate_browser_url(url, hosts)
    if error:
        raise ScopeRefused(error)
    from playwright.sync_api import sync_playwright

    requests: list[dict[str, str]] = []
    responses: list[dict[str, Any]] = []
    dialogs: list[str] = []

    with sync_playwright() as playwright:
        launch_args: dict[str, Any] = {"headless": True}
        channel = os.environ.get("HEXHOUND_BROWSER_CHANNEL", "msedge")
        if channel:
            launch_args["channel"] = channel
        browser = playwright.chromium.launch(**launch_args)
        context = browser_context(
            browser, url, allowed_hosts=hosts, auth_headers=auth_headers, cookies=cookies,
            storage_state=storage_state, session_storage=session_storage,
        )
        page = context.new_page()
        page.on(
            "request",
            lambda request: requests.append(
                {"method": request.method, "url": request.url}
            ),
        )
        page.on(
            "response",
            lambda response: responses.append(
                {
                    "status": response.status,
                    "url": response.url,
                    "content_type": response.headers.get("content-type", ""),
                }
            ),
        )
        page.on("dialog", lambda dialog: (dialogs.append(dialog.message), dialog.dismiss()))
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            page.wait_for_timeout(wait_ms)
            if execute_js:
                page.evaluate(execute_js)
                page.wait_for_timeout(500)
            html = page.content()
            screenshot = page.screenshot(type="png")
            api_urls = sorted(
                {
                    item["url"]
                    for item in responses
                    if "json" in item.get("content_type", "").lower()
                    or "/api/" in item["url"].lower()
                    or re_url_like(item["url"])
                }
            )
            return {
                "html": html,
                "screenshot": screenshot,
                "requests": requests,
                "responses": responses,
                "dialogs": dialogs,
                "api_urls": api_urls,
            }
        finally:
            browser.close()


def re_url_like(value: str) -> bool:
    import re

    return bool(
        re.search(
            r"/(api|rest|graphql|ajax|json|v[0-9]+)/",
            value,
            re.I,
        )
    )
