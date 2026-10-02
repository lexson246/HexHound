from __future__ import annotations

import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

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


#: 关窗口时最多等多久让运行中的审计把"不完整报告"写出来。
#: 环境变量 `HEXHOUND_CLOSE_GRACE` 可覆盖（秒）。
CLOSE_GRACE_SECONDS = 45.0


def close_grace_seconds() -> float:
    raw = os.getenv("HEXHOUND_CLOSE_GRACE", "").strip()
    if not raw:
        return CLOSE_GRACE_SECONDS
    try:
        return max(0.0, float(raw))
    except ValueError:
        return CLOSE_GRACE_SECONDS


def wait_for_run_end(state: Any, *, timeout: float, sleep: float = 0.25) -> bool:
    """等运行收尾（返回是否已结束）。

    单独成函数是为了**可测**：真实等待要 45 秒，测试里换成假时钟/假状态即可。
    """
    deadline = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < deadline:
        try:
            if not state.snapshot().get("running"):
                return True
        except Exception:  # noqa: BLE001 状态读不到就当作已结束，别把窗口卡住
            return True
        time.sleep(sleep)
    try:
        return not state.snapshot().get("running")
    except Exception:  # noqa: BLE001
        return True


def stop_running_audit(state: Any, *, timeout: float) -> str:
    """关窗口时先把成果落盘：请求停止 → 等它写完不完整报告。

    返回 `"idle"`（本来就没在跑）/ `"saved"`（已收尾，报告已写）/ `"timeout"`。

    为什么必须做（第四轮报告 §10 记的边界）：pywebview 的窗口一关，
    `webview.start()` 返回、进程退出，**daemon 线程被直接杀掉**——
    正在跑的审计连部分报告都没有。而按界面上的"停止"按钮走的是
    `STATE.stop_current()`，它会写出标注"不完整"的报告。同一个动作，
    两种关法结果完全不同，用户实际的观感就是"辛苦跑的东西没了"。
    """
    try:
        snapshot = state.snapshot()
    except Exception:  # noqa: BLE001
        return "idle"
    if not snapshot.get("running"):
        return "idle"
    try:
        state.stop_current()
    except Exception:  # noqa: BLE001 停止信号发不出去就只能等超时
        pass
    return "saved" if wait_for_run_end(state, timeout=timeout) else "timeout"


def _notify_saving(window: Any) -> None:
    """在页面上提示"正在保存不完整报告"（窗口此时还没销毁）。"""
    script = (
        "(() => { const box = document.querySelector('#runStatus') || document.body;"
        " if (box) { box.textContent = '正在保存不完整报告（最多 45 秒）…'; } })()"
    )
    try:
        window.evaluate_js(script)
    except Exception:  # noqa: BLE001 页面已经关了就算了
        pass


def install_close_guard(window: Any, state: Any, *, timeout: float | None = None) -> None:
    """拦截第一次关窗：先让运行收尾落盘，再自己销毁窗口。

    第二次关窗不再拦截（否则用户会觉得"关不掉"）。任何 API 差异都吞掉——
    真正的兜底在 `main()` 的 finally（`stop_running_audit`），不依赖事件能不能挂上。
    """
    grace = close_grace_seconds() if timeout is None else timeout
    state_box = {"close_requested": False}

    def on_closing() -> bool:
        if state_box["close_requested"]:
            return True
        try:
            running = bool(state.snapshot().get("running"))
        except Exception:  # noqa: BLE001
            running = False
        if not running:
            return True
        state_box["close_requested"] = True
        _notify_saving(window)

        def finish() -> None:
            stop_running_audit(state, timeout=grace)
            try:
                window.destroy()
            except Exception:  # noqa: BLE001 窗口可能已经被用户关掉
                pass

        threading.Thread(target=finish, name="hexhound-close-guard", daemon=True).start()
        return False  # 取消这次关闭，等收尾完成后再销毁

    try:
        window.events.closing += on_closing
    except Exception:  # noqa: BLE001 挂不上事件时退回 finally 里的等待
        pass


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

        window = webview.create_window(
            "HexHound",
            f"http://127.0.0.1:{port}",
            width=1320,
            height=880,
            min_size=(1024, 720),
        )
        if window is None:
            window = webview.active_window()
        # 关窗口也要把成果落盘：见 install_close_guard 的说明
        from hexhound import gui as gui_module

        if window is not None:
            install_close_guard(window, gui_module.STATE)
        try:
            webview.start(gui="edgechromium")
        finally:
            # 兜底（事件没挂上 / 用户用其它方式关掉窗口）：这里再等一次，
            # 让审计线程把标注"不完整"的报告写完。
            outcome = stop_running_audit(gui_module.STATE, timeout=close_grace_seconds())
            if outcome == "timeout":
                print(
                    "窗口已关闭；审计仍在收尾，未能等到报告写完"
                    f"（可调大 HEXHOUND_CLOSE_GRACE，当前 {close_grace_seconds():.0f} 秒）。",
                    file=sys.stderr,
                )
    finally:
        if mutex:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_bool
            kernel32.CloseHandle(ctypes.c_void_p(mutex))


if __name__ == "__main__":
    main()
