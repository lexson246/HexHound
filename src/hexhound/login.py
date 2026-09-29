from __future__ import annotations

import os
import time
from typing import Any


def capture_login_state(
    url: str,
    timeout_sec: int = 300,
) -> dict[str, Any]:
    """打开系统 Edge 登录窗口，等用户手动完成登录后抓取登录态。"""
    from playwright.sync_api import sync_playwright

    init_script = """
    (() => {
      if (window.__hexhoundLoginButtonInstalled) return;
      window.__hexhoundLoginButtonInstalled = true;
      const btn = document.createElement('button');
      btn.id = '__hexhound_login_done';
      btn.textContent = '登录完成，保存登录态';
      btn.style.cssText = [
        'position:fixed', 'top:12px', 'right:12px', 'z-index:2147483647',
        'background:#4f8cff', 'color:#fff', 'border:0', 'padding:10px 14px',
        'border-radius:6px', 'cursor:pointer', 'font-size:14px', 'font-weight:600'
      ].join(';');
      btn.addEventListener('click', () => {
        window.__hexhoundLoginDone = true;
      });
      (document.body || document.documentElement).appendChild(btn);
    })();
    """

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            channel=os.environ.get("HEXHOUND_BROWSER_CHANNEL", "msedge"), headless=False
        )
        context = browser.new_context()
        page = context.new_page()
        page.add_init_script(init_script)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            deadline = time.monotonic() + timeout_sec
            while time.monotonic() < deadline:
                if page.is_closed():
                    raise RuntimeError("登录窗口已关闭，未保存登录态。")
                try:
                    done = page.evaluate("window.__hexhoundLoginDone === true")
                except Exception:
                    done = False
                if done:
                    break
                time.sleep(1)
            else:
                raise RuntimeError(f"登录超时（{timeout_sec} 秒）。")

            cookies = context.cookies()
            local_storage = page.evaluate(
                "Object.fromEntries(Object.entries(window.localStorage || {}))"
            )
            session_storage = page.evaluate(
                "Object.fromEntries(Object.entries(window.sessionStorage || {}))"
            )
        finally:
            browser.close()

    cookie_header = "; ".join(
        f"{cookie.get('name', '')}={cookie.get('value', '')}" for cookie in cookies
    )
    auth_headers: dict[str, str] = {}
    if cookie_header:
        auth_headers["Cookie"] = cookie_header
    for key in ("access_token", "token", "Authorization", "authorization", "Bearer"):
        value = local_storage.get(key) or session_storage.get(key)
        if value:
            auth_headers["Authorization"] = (
                value if key.lower() in ("authorization", "bearer") else f"Bearer {value}"
            )
            break

    return {
        "auth_json": auth_headers,
        "cookies": cookies,
        "local_storage": local_storage,
        "session_storage": session_storage,
        "login_url": page.url,
    }
