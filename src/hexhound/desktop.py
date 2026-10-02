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


def log_line(message: str) -> None:
    """把启动/关闭里程碑写进 `HEXHOUND_DESKTOP_LOG` 指定的文件（可选）。

    为什么需要：桌面版是 **windowed** 构建，没有控制台——一旦启动阶段出问题
    （例如单实例互斥、WebView2 缺失、某个 import 炸了），用户看到的只是
    "双击没反应"，排查时没有任何线索（实测踩过：验收脚本报"进程活着但没监听"，
    完全不知道卡在哪一步）。设了这个环境变量就能拿到逐行日志。

    只写里程碑，不写密钥；写失败静默忽略（日志不该影响主流程）。
    """
    path = os.getenv("HEXHOUND_DESKTOP_LOG", "").strip()
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%H:%M:%S')} pid={os.getpid()} {message}\n")
    except OSError:
        pass


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


def install_close_guard(window: Any, state: Any, *, timeout: float | None = None) -> None:
    """关窗时的收尾：**立刻请求停止并中断沙箱命令，然后放行关闭**。

    报告由 `main()` 的 finally（`stop_running_audit`）等出来——在那里等是**可行**的，
    而在关窗回调里"先取消关闭、收尾完再自己 destroy"是**不可行**的（真机验收推翻）：
    pywebview 的窗口方法必须由 GUI 主线程调用，工作线程里 `window.destroy()`
    既不生效也不报错（异常被吞），结果是窗口永远关不掉、进程一直活着。

    同样**不能**在回调里调 `evaluate_js`：`closing` 事件是同步回调
    （`Event(window, True)` → 在 UI 线程里直接执行），而 `evaluate_js` 会等 UI 线程，
    于是自锁——窗口关不掉、进程不退出，日志停在"关窗护栏已挂上"。
    这一条只有打包 exe 的专项验收能发现（单元测试的替身不会死锁）。

    现在的语义（简单且可靠）：

    1. 有运行在跑 → 置停止标志 + 中断正在执行的沙箱命令（几百秒的 sqlmap 会被杀掉）；
    2. **一律放行关闭**（用户想关就能关，不存在"关不掉"）；
    3. `main()` 的 finally 里等报告落盘（上限 `HEXHOUND_CLOSE_GRACE`），再退出进程。
    """
    grace = close_grace_seconds() if timeout is None else timeout
    state_box = {"close_requested": False, "grace": grace}

    def on_closing() -> bool:
        if state_box["close_requested"]:
            return True
        state_box["close_requested"] = True
        try:
            running = bool(state.snapshot().get("running"))
        except Exception:  # noqa: BLE001
            running = False
        if running:
            try:
                # 停止标志 + 中断沙箱命令（这是"报告能在宽限期内写完"的关键）
                state.stop_current()
            except Exception:  # noqa: BLE001 通知失败也要放行关闭
                pass
        return True

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
        log_line("已有实例在运行，退出")
        if sys.platform == "win32":
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                0, "HexHound 已经在运行，请勿重复启动。", "HexHound", 0x40
            )
        else:
            print("HexHound 已经在运行，请勿重复启动。")
        return
    log_line("单实例互斥已获取")
    try:
        try:
            import webview
        except ImportError as exc:
            raise RuntimeError(
                "桌面版依赖未安装，请先运行：pip install -e \".[desktop]\""
            ) from exc
        log_line("webview 已导入")

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
        log_line(f"app 已创建，准备在 127.0.0.1:{port} 监听")
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
        log_line(f"本地服务已就绪：http://127.0.0.1:{port}")

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
            log_line("关窗护栏已挂上")
        else:
            log_line("警告：拿不到窗口对象，关窗护栏未挂上")
        try:
            webview.start(gui="edgechromium")
            log_line("webview.start 返回（窗口已关闭）")
        finally:
            # 兜底（事件没挂上 / 用户用其它方式关掉窗口）：这里再等一次，
            # 让审计线程把标注"不完整"的报告写完。
            outcome = stop_running_audit(gui_module.STATE, timeout=close_grace_seconds())
            log_line(f"收尾等待结果：{outcome}")
            if outcome == "timeout":
                print(
                    "窗口已关闭；审计仍在收尾，未能等到报告写完"
                    f"（可调大 HEXHOUND_CLOSE_GRACE，当前 {close_grace_seconds():.0f} 秒）。",
                    file=sys.stderr,
                )
    finally:
        log_line("main() 退出")
        if mutex:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_bool
            kernel32.CloseHandle(ctypes.c_void_p(mutex))


if __name__ == "__main__":
    main()
