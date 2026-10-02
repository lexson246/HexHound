"""打包 exe 的「运行中关窗」专项验收（零模型额度）。

外部评审第 4 条：普通关窗保存链路通过了，但**遇到长时间运行的工具调用**时，
等超时后仍可能退出、报告没写完。这里在**真实打包 exe** 上验收：

1. 用隔离的 HOME 启动 `hexhound.exe`（不碰用户真实配置与历史）；
2. 用离线脚本 LLM（`provider=scripted`）+ **一个"只连不答"的本机服务**起一次审计
   ——每次工具调用都会卡到请求超时，于是审计会持续足够久；
3. 审计运行中，用 `taskkill`（不带 `/F`，等价于点右上角关闭）关窗口；
4. 断言：进程在宽限期内退出、**报告文件已写出**、报告里写明"本次运行被中断"、
   运行记录存在、退出码正常。

用法：
    python tools/verify_desktop_close_inflight.py            # 默认用根目录 hexhound.exe
    python tools/verify_desktop_close_inflight.py path.exe   # 指定 exe
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "hexhound.exe"
WORK = ROOT / ".tmp" / "desktop-close-inflight"
TOKEN_HEADER = "X-HexHound-Token"
GRACE_WAIT = 90.0

FAILURES: list[str] = []
HITS = {"count": 0}


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


class _HangHandler(BaseHTTPRequestHandler):
    """只接受连接、永不回响应：让工具调用一直挂到 httpx 超时。"""

    def _hang(self) -> None:
        HITS["count"] += 1
        time.sleep(30)

    do_GET = _hang  # type: ignore[assignment]
    do_POST = _hang  # type: ignore[assignment]

    def log_message(self, *args) -> None:  # noqa: D102
        return


def _env(home: Path) -> dict:
    """给被测 exe 的隔离环境：设置与运行产物都写在临时目录，不碰用户真实数据。"""
    env = dict(os.environ)
    env["HEXHOUND_SETTINGS_PATH"] = str(home / "settings.json")
    env["HEXHOUND_HOME"] = str(home / "hh-home")
    env["HEXHOUND_CLOSE_GRACE"] = "30"
    # 启动/关闭里程碑写文件：windowed 构建没有控制台，出问题必须能查到卡在哪一步
    env["HEXHOUND_DESKTOP_LOG"] = str(home.parent / "desktop.log")
    return env


def _http(url: str, *, method: str = "GET", payload: dict | None = None,
          headers: dict | None = None) -> tuple[int, str]:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _wait_server(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _listening_ports(pid: int) -> list[int]:
    """该进程正在监听的端口（用 netstat，避免依赖 psutil）。"""
    try:
        out = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"],
            capture_output=True, text=True, check=False,
            encoding="gbk" if os.name == "nt" else "utf-8", errors="replace",
        ).stdout
    except OSError:
        return []
    ports: list[int] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        if not parts[3].upper().startswith("LISTEN"):
            continue
        if parts[4] != str(pid):
            continue
        local = parts[1]
        if ":" in local:
            try:
                ports.append(int(local.rsplit(":", 1)[1]))
            except ValueError:
                continue
    return ports


def _wait_exe_port(timeout: float = 60.0) -> tuple[int, int]:
    """等任一 hexhound 进程监听端口，返回 `(pid, port)`；超时返回 `(0, 0)`。

    为什么不能只盯启动时拿到的 PID：PyInstaller onefile 打包是**父子两个进程**，
    父进程是引导器（不持有端口），真正跑 Flask 的是子进程。实测踩过——
    日志里明明写着"本地服务已就绪：http://127.0.0.1:53059"，按父进程 PID 去
    netstat 里找却是空的，于是脚本误报"启动失败"。
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        for pid in sorted(_all_hexhound_pids()):
            for candidate in _listening_ports(pid):
                if _wait_server(candidate, timeout=0.4):
                    return pid, candidate
        time.sleep(0.3)
    return 0, 0


def _all_hexhound_pids() -> set[int]:
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq hexhound.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, check=False,
            encoding="gbk" if os.name == "nt" else "utf-8", errors="replace",
        ).stdout
    except OSError:
        return set()
    pids: set[int] = set()
    for line in out.splitlines():
        parts = [item.strip('"') for item in line.split('","')]
        if len(parts) >= 2 and parts[0].lower().startswith("hexhound.exe"):
            try:
                pids.add(int(parts[1]))
            except ValueError:
                continue
    return pids


def _kill_all() -> None:
    """整树结束 hexhound（onefile 的父/子都要杀）。"""
    for pid in sorted(_all_hexhound_pids()):
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], capture_output=True, check=False)


def _existing_instances() -> list[int]:
    """已在运行的 hexhound.exe 进程（**不杀**，只用来拒绝验收）。"""
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq hexhound.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, check=False,
            encoding="gbk" if os.name == "nt" else "utf-8", errors="replace",
        ).stdout
    except OSError:
        return []
    pids: list[int] = []
    for line in out.splitlines():
        parts = [item.strip('"') for item in line.split('","')]
        if len(parts) >= 2 and parts[0].lower().startswith("hexhound.exe"):
            try:
                pids.append(int(parts[1]))
            except ValueError:
                continue
    return pids


def main() -> int:
    if not EXE.exists():
        print(f"找不到 exe：{EXE}（先跑 python -m PyInstaller --noconfirm --clean HexHound-desktop.spec）")
        return 2
    # 单实例互斥：已有实例在跑时，新进程只会弹"已在运行"而不起服务，
    # 验收结果会变成"启动失败"——那不是被测代码的问题，直接拒绝跑。
    running = _existing_instances()
    if running:
        print(
            f"已有 hexhound.exe 在运行（PID {running}）。本程序是**单实例**的，"
            "请先关闭它再跑这个验收（关窗口即可，或在界面里点停止）。"
        )
        return 2
    if WORK.exists():
        for item in sorted(WORK.rglob("*"), reverse=True):
            try:
                item.unlink() if item.is_file() else item.rmdir()
            except OSError:
                pass
    (WORK / "home").mkdir(parents=True, exist_ok=True)
    home = WORK / "home"

    hang = ThreadingHTTPServer(("127.0.0.1", 0), _HangHandler)
    threading.Thread(target=hang.serve_forever, daemon=True).start()
    hang_url = f"http://127.0.0.1:{hang.server_port}"
    print(f"挂起服务：{hang_url}（只连不答，用来制造长时间工具调用）")

    (home / "settings.json").write_text(
        json.dumps(
            {
                **{k: v for k, v in json.loads(json.dumps(_defaults())).items()},
                "provider": "scripted",
                "model": "scripted-policy",
                "base_url": "",
                # 目标指向挂起服务：每次 fuzz/http 调用都会挂到超时
                "target": f"{hang_url}/",
                "allowed_hosts": "127.0.0.1,localhost",
                "output": str(WORK / "report.md"),
                "task_steps": "8",
                "max_tasks": "3",
                "swarm": "1",
                "request_timeout": "20",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    subprocess.Popen(
        [str(EXE)],
        cwd=str(ROOT), env=_env(home),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        # 桌面入口自己挑端口（写进窗口 URL）；onefile 是父子进程，扫全部 hexhound
        window_pid, port = _wait_exe_port()
        check("exe 启动并监听端口", bool(port), f"pid={window_pid} port={port}")
        if not port:
            return 1
        status, body = _http(f"http://127.0.0.1:{port}/")
        match = re.search(r"const LOCAL_TOKEN = \"([^\"]+)\"", body)
        token = match.group(1) if match else ""
        check("拿到本机会话令牌", bool(token), (token[:8] + "…") if token else "未找到")
        headers = {TOKEN_HEADER: token}

        settings = json.loads((home / "settings.json").read_text(encoding="utf-8"))
        code, payload = _http(
            f"http://127.0.0.1:{port}/api/run", method="POST", payload=settings, headers=headers,
        )
        check("/api/run 启动成功", code == 200, f"{code} {payload[:120]}")

        running = False
        deadline = time.time() + 30
        while time.time() < deadline:
            _code, snapshot = _http(f"http://127.0.0.1:{port}/api/status", headers=headers)
            try:
                data = json.loads(snapshot)
            except json.JSONDecodeError:
                data = {}
            if data.get("running"):
                running = True
                break
            if data.get("status") in ("done", "failed", "cancelled"):
                break
            time.sleep(0.3)
        check("审计确实在运行（工具调用挂起中）", running, f"挂起服务收到 {HITS['count']} 次请求")

        # 关窗：对**持有端口**的那个进程发 WM_CLOSE（不带 /F）
        time.sleep(2.0)
        started = time.time()
        subprocess.run(["taskkill", "/PID", str(window_pid)], capture_output=True, check=False)
        gone = False
        while time.time() - started < GRACE_WAIT:
            if not _all_hexhound_pids():
                gone = True
                break
            time.sleep(0.5)
        check("关窗后进程在宽限期内退出", gone, f"{time.time() - started:.1f}s")

        report = WORK / "report.md"
        check("报告文件已写出", report.exists(), str(report))
        text = report.read_text(encoding="utf-8", errors="replace") if report.exists() else ""
        check("报告写明本次运行被中断", "本次运行被中断" in text)

        runs = sorted((home / "hh-home" / "runs").glob("*/run.json"))
        check("运行记录已落盘", bool(runs), f"{len(runs)} 份")
        if runs:
            data = json.loads(runs[-1].read_text(encoding="utf-8"))
            check("运行记录里有沙箱字段", "sandbox" in data)
            archived = runs[-1].parent / "report.md"
            check("运行目录里也有报告副本", archived.exists(), str(archived))
    finally:
        hang.shutdown()
        _kill_all()
        log_path = home.parent / "desktop.log"
        if log_path.exists():
            print("--- exe 启动/关闭日志 ---")
            print(log_path.read_text(encoding="utf-8", errors="replace").strip())

    print()
    if FAILURES:
        print(f"运行中关窗验收未通过：{len(FAILURES)} 项 —— " + "；".join(FAILURES))
        return 1
    print("运行中关窗验收通过：中断后报告与运行记录都已落盘。")
    return 0


def _defaults() -> dict:
    """GUI 的默认设置（从源码读，避免与界面漂移）。"""
    sys.path.insert(0, str(ROOT / "src"))
    from hexhound import gui

    return dict(gui.DEFAULTS)


if __name__ == "__main__":
    raise SystemExit(main())
