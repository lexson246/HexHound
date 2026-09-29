from __future__ import annotations

import os
import socket
import sys
import threading
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _acquire_single_instance() -> int | None:
    """用 Windows 命名互斥锁防止重复启动；已有实例时返回 0，否则返回句柄。"""
    if sys.platform != "win32":
        return None
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_bool

    handle = kernel32.CreateMutexW(None, False, "HexHound.SingleInstance.LeXSon")
    if not handle:
        return 0
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        kernel32.CloseHandle(handle)
        return 0
    return int(handle)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_server(port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("本地 Web 服务启动超时。")


def main() -> None:
    browsers = Path(sys.executable).resolve().parent / "browsers"
    if getattr(sys, "frozen", False) and browsers.is_dir():
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers)
        os.environ["HEXHOUND_BROWSER_CHANNEL"] = "chromium"
    mutex = _acquire_single_instance()
    if mutex == 0:
        if sys.platform == "win32":
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                0, "HexHound 已经在运行，请勿重复启动。", "HexHound", 0x40
            )
        else:
            print("HexHound 已经在运行，请勿重复启动。")
        return
    try:
        try:
            import webview
        except ImportError as exc:
            raise RuntimeError(
                "桌面版依赖未安装，请先运行：pip install -e \".[desktop]\""
            ) from exc

        try:
            from dotenv import load_dotenv
        except ImportError:
            load_dotenv = None
        if load_dotenv is not None:
            env_candidates = [
                Path(sys.executable).resolve().parent / ".env",
                Path.home() / ".hexhound" / ".env",
            ]
            for env_path in env_candidates:
                if env_path.exists():
                    load_dotenv(env_path, override=False)

        from hexhound.gui import create_app

        app = create_app()
        port = _free_port()
        server_thread = threading.Thread(
            target=app.run,
            kwargs={
                "host": "127.0.0.1",
                "port": port,
                "debug": False,
                "use_reloader": False,
                "threaded": True,
            },
            daemon=True,
        )
        server_thread.start()
        _wait_for_server(port)

        webview.create_window(
            "HexHound",
            f"http://127.0.0.1:{port}",
            width=1320,
            height=880,
            min_size=(1024, 720),
        )
        webview.start(gui="edgechromium")
    finally:
        if mutex:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_bool
            kernel32.CloseHandle(ctypes.c_void_p(mutex))


if __name__ == "__main__":
    main()
