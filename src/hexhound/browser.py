from __future__ import annotations

from typing import Any


def dynamic_scan(
    url: str,
    wait_ms: int = 2500,
    timeout_ms: int = 20000,
    execute_js: str | None = None,
) -> dict[str, Any]:
    """用系统 Edge 无头执行页面，返回渲染后 HTML、截图和网络请求。"""
    from playwright.sync_api import sync_playwright

    requests: list[dict[str, str]] = []
    responses: list[dict[str, Any]] = []
    dialogs: list[str] = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="msedge", headless=True)
        page = browser.new_page()
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
        page.on("dialog", lambda dialog: dialogs.append(dialog.message))
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
