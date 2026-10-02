from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

_BROWSER_CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Chromium\Application\chrome.exe",
]


def _find_browser() -> str | None:
    bundled = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if bundled:
        for candidate in Path(bundled).glob(
            "chromium_headless_shell-*/chrome-headless-shell-win64/chrome-headless-shell.exe"
        ):
            if candidate.is_file():
                return str(candidate)
    for name in ("msedge", "msedge.exe", "chrome", "chrome.exe", "chromium"):
        path = shutil.which(name)
        if path:
            return path
    for candidate in _BROWSER_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


def capture_url(
    url: str,
    width: int = 1440,
    height: int = 900,
    timeout: int = 30,
) -> bytes:
    """用本机 Edge/Chrome 的无头模式截取 URL，返回 PNG 字节。"""
    browser = _find_browser()
    if not browser:
        raise RuntimeError("未找到 Edge/Chrome 浏览器，无法截图。")

    with tempfile.TemporaryDirectory(prefix="hexhound-shot-") as tmp:
        output = Path(tmp) / "page.png"
        profile = Path(tmp) / "profile"
        command = [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            f"--user-data-dir={profile}",
            f"--window-size={width},{height}",
            f"--screenshot={output}",
            "--virtual-time-budget=5000",
            "--hide-scrollbars",
            url,
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            shell=False,
        )
        if not output.exists() or output.stat().st_size == 0:
            # 浏览器在中文 Windows 上按 ANSI 代码页输出错误信息：交给统一的
            # 控制台解码，**不能**用 `text=True`（会按 UTF-8 解 GBK 字节，
            # 在读取线程里抛 UnicodeDecodeError，连失败原因都拿不到）。
            from .sanitize import decode_console_output

            raw = result.stderr or result.stdout or b""
            detail = decode_console_output(raw).strip()
            if detail:
                detail = detail[-500:]
            raise RuntimeError(f"浏览器截图失败：{detail or '未生成图片'}")
        return output.read_bytes()
