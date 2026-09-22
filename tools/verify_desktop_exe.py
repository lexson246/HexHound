"""桌面版 exe 的启动验收（本地、无外部目标、无模型调用）。

检查（对应"必须真正验证"的几条）：

1. 双击式启动（不带参数）能起来，进程存活并监听本地端口；
2. 是**内嵌 WebView2** 而不是外部浏览器：我们自己拉起了 msedgewebview2 子进程，
   且没有拉起 msedge.exe / chrome.exe（没有另开浏览器窗口）；
3. 本地控制台可访问：`/` 200、`/api/status` 为 idle、`/api/history` 可用；
4. 本机接口守卫在打包后依然生效：无令牌写操作 403，带令牌 200 且能落盘；
5. 窗口真的建出来，关闭窗口后进程全部退出、端口释放；
6. 重启后配置与历史仍可读（配置持久化 + 历史确实来自磁盘）。

**不碰用户真实配置与历史**：设置与运行产物都通过 `HEXHOUND_SETTINGS_PATH` /
`HEXHOUND_HOME` 指到 `.tmp/desktop-verify/`。

用法：python tools/verify_desktop_exe.py [exe 路径]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "hexhound.exe"
TOKEN_HEADER = "X-HexHound-Token"
#: 验收用的隔离目录：设置与运行产物都写在这里，**不碰用户真实配置与历史**
ISOLATED = ROOT / ".tmp" / "desktop-verify"


def _env() -> dict:
    env = dict(os.environ)
    ISOLATED.mkdir(parents=True, exist_ok=True)
    (ISOLATED / "home").mkdir(parents=True, exist_ok=True)
    env["HEXHOUND_SETTINGS_PATH"] = str(ISOLATED / "settings.json")
    env["HEXHOUND_HOME"] = str(ISOLATED / "home")
    return env


def _http(url: str, *, method: str = "GET", payload: dict | None = None,
          headers: dict | None = None) -> tuple[int, str]:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _process_table() -> list[tuple[int, int, str]]:
    """(pid, ppid, name) 全表——用 Windows API，不依赖 wmic/pwsh。"""
    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == -1:
        return []
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    rows: list[tuple[int, int, str]] = []
    try:
        ok = kernel32.Process32First(snapshot, ctypes.byref(entry))
        while ok:
            rows.append((
                int(entry.th32ProcessID),
                int(entry.th32ParentProcessID),
                entry.szExeFile.decode("mbcs", "replace").lower(),
            ))
            ok = kernel32.Process32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return rows


def _processes(names: tuple[str, ...]) -> set[int]:
    return {pid for pid, _ppid, name in _process_table() if name in names}


def _children_of(pids: set[int]) -> dict[str, int]:
    """统计父进程属于 `pids` 的子进程（按名字计数）——用来证明"是我们拉起来的"。"""
    counts: dict[str, int] = {}
    for _pid, ppid, name in _process_table():
        if ppid in pids:
            counts[name] = counts.get(name, 0) + 1
    return counts


def _listening_port(pid: int) -> int | None:
    """用 netstat 找该进程的监听端口（不依赖 pwsh，避免 PATH 差异）。"""
    out = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                         capture_output=True, text=True, check=False).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        if parts[3].upper() != "LISTENING" or parts[4] != str(pid):
            continue
        local = parts[1]
        if ":" in local:
            try:
                return int(local.rsplit(":", 1)[1])
            except ValueError:
                continue
    return None


def _hexhound_pids() -> set[int]:
    return _processes(("hexhound.exe",))


def _wait_port(timeout: float = 90.0) -> tuple[int, int] | None:
    """等任一 hexhound 进程监听端口。

    注意 onefile 打包是**父子两个进程**：父进程是引导器（不持有端口），
    真正跑 Flask 的是子进程。只盯启动时拿到的 PID 会误判成"没起来"。
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for pid in sorted(_hexhound_pids()):
            port = _listening_port(pid)
            if port:
                return pid, port
        time.sleep(0.5)
    return None


def _wait_exit(pid: int, timeout: float = 60.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        alive = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                               capture_output=True, text=True, check=False).stdout
        if str(pid) not in alive:
            return True
        time.sleep(0.5)
    return False


def _window_ready(timeout: float = 60.0) -> bool:
    """等窗口真的建出来（标题为 HexHound）。

    为什么必须等：`taskkill`（不带 /F）就是发 WM_CLOSE，**窗口还不存在时没人接收**，
    关窗口的动作会被丢掉。实测把关闭请求发在启动后 1~2 秒时就出现过这种"关不掉"，
    那是验收脚本的竞态，不是应用的问题——但脚本必须先等窗口就绪再关。
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        out = subprocess.run(
            ["tasklist", "/V", "/FI", "IMAGENAME eq hexhound.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, check=False,
        ).stdout
        if '"HexHound"' in out:
            return True
        time.sleep(1)
    return False


def _wait_all_gone(timeout: float = 120.0) -> bool:
    """等到没有任何 hexhound 进程（父子一体，避免只盯单个 PID 的竞态）。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _hexhound_pids():
            return True
        time.sleep(1)
    return not _hexhound_pids()


def _graceful_close(window_pid: int) -> bool:
    """等于点窗口右上角关闭：taskkill 不带 /F 就是发 WM_CLOSE。"""
    subprocess.run(["taskkill", "/PID", str(window_pid)], capture_output=True, text=True, check=False)
    gone = _wait_all_gone()
    if not gone:  # 兜底清理，免得留下进程影响后续检查
        for leftover in _hexhound_pids():
            subprocess.run(["taskkill", "/F", "/PID", str(leftover)], capture_output=True, check=False)
    return gone


def main() -> int:
    checks: list[tuple[str, bool, str]] = []
    exe = Path(sys.argv[1]) if len(sys.argv) > 1 else EXE
    if not exe.is_file():
        print(f"[FAIL] 找不到 {exe}")
        return 1

    before_webview = _processes(("msedgewebview2.exe",))
    before_browsers = _processes(("msedge.exe", "chrome.exe", "firefox.exe"))
    print(f"启动前：WebView2 进程 {len(before_webview)} 个，浏览器进程 {len(before_browsers)} 个")

    process = subprocess.Popen([str(exe)], cwd=str(EXE.parent), env=_env())
    launcher_pid = process.pid
    print(f"已启动：{exe}（引导进程 PID {launcher_pid}）")
    print(f"隔离目录：{ISOLATED}")
    found = _wait_port()
    checks.append(("双击式启动后进程存活并监听本地端口", found is not None,
                   f"监听 {found}" if found else "超时未监听"))
    if not found:
        for pid in _hexhound_pids():
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, check=False)
        for name, ok, detail in checks:
            print(f"{'[ OK ]' if ok else '[FAIL]'} {name} — {detail}")
        return 1
    pid, port = found

    time.sleep(6)  # 给 WebView2 一点时间把子进程拉起来
    our_pids = _hexhound_pids()
    children = _children_of(our_pids)
    checks.append((
        "内嵌 WebView2 渲染（我们自己拉起了 msedgewebview2 子进程）",
        children.get("msedgewebview2.exe", 0) > 0,
        f"子进程：{children}",
    ))
    checks.append((
        "没有另开外部浏览器进程",
        not (children.get("msedge.exe", 0) or children.get("chrome.exe", 0)
             or children.get("firefox.exe", 0)),
        f"浏览器子进程：{ {k: v for k, v in children.items() if 'msedge.exe' in k} }",
    ))

    root = f"http://127.0.0.1:{port}"
    status, html = _http(f"{root}/")
    checks.append(("控制台页面返回 200", status == 200, f"status={status}, {len(html)} 字节"))
    checks.append(("页面包含关键控件（导航/设置/历史/预算字段）",
                   all(marker in html for marker in
                       ('id="settingsBtn"', 'data-view="reports"', 'id="historyList"',
                        'name="max_tokens"', 'name="max_llm_calls"', 'name="max_seconds"')),
                   "控件齐全"))
    token = html.split("const LOCAL_TOKEN = ")[1].split(";")[0].strip().strip('"') if "const LOCAL_TOKEN = " in html else ""
    checks.append(("会话令牌已渲染进页面", bool(token), f"token 长度 {len(token)}"))

    status, body = _http(f"{root}/api/status")
    snapshot = json.loads(body) if status == 200 else {}
    checks.append(("状态接口为 idle", snapshot.get("status") == "idle", f"status={snapshot.get('status')}"))

    status, body = _http(f"{root}/api/history")
    runs = json.loads(body).get("runs") if status == 200 else None
    checks.append(("历史接口可用（读磁盘产物）", isinstance(runs, list),
                   f"status={status}, {len(runs or [])} 条历史"))

    status, _ = _http(f"{root}/api/save", method="POST", payload={"target": "http://127.0.0.1:5000"})
    checks.append(("无令牌写操作被拒（防 CSRF）", status == 403, f"status={status}"))

    marker = f"http://127.0.0.1:5000/?desktop-check={int(time.time())}"
    status, _ = _http(f"{root}/api/save", method="POST",
                      payload={"target": marker, "max_tokens": "12345"},
                      headers={TOKEN_HEADER: token})
    checks.append(("带令牌保存配置成功", status == 200, f"status={status}"))

    # 优雅关闭（等于点窗口右上角的关闭）
    ready = _window_ready()
    checks.append(("原生窗口已创建（标题 HexHound）", ready, "窗口就绪" if ready else "未见窗口"))
    closed = _graceful_close(pid)
    checks.append(("关闭窗口后进程全部退出", closed, "已退出" if closed else "仍在运行"))
    checks.append(("端口随之释放", _listening_port(pid) is None, "无监听"))

    # 重启：配置与历史必须还能读。先往隔离目录里放一条"上一次运行"的产物，
    # 这样"重启后历史仍可读"是**真的读到了磁盘上的东西**（而不是空列表也算过）。
    seeded = ISOLATED / "home" / "runs" / "127.0.0.1-20260101-010101"
    seeded.mkdir(parents=True, exist_ok=True)
    (seeded / "run.json").write_text(json.dumps({
        "target": "http://127.0.0.1:5000", "mode": "blackbox",
        "usage": {"total_tokens": 4321, "estimated_cost": 0.12},
        "stats": {"findings": 3, "endpoints": 9},
    }, ensure_ascii=False), encoding="utf-8")
    (seeded / "report.md").write_text("## 打包后历史报告\n\n证据留档。\n", encoding="utf-8")
    (seeded / "snapshot.json").write_text("{}", encoding="utf-8")

    subprocess.Popen([str(exe)], cwd=str(EXE.parent), env=_env())
    found2 = _wait_port()
    checks.append(("重启后能再次启动", found2 is not None, f"监听 {found2}" if found2 else "超时未监听"))
    if found2:
        pid2, port2 = found2
        root2 = f"http://127.0.0.1:{port2}"
        _status, html2 = _http(f"{root2}/")
        checks.append(("重启后配置仍可读（上次保存的目标回填）", marker in html2, marker))
        _status, body2 = _http(f"{root2}/api/history")
        runs2 = json.loads(body2).get("runs") if _status == 200 else []
        seeded_entry = next((item for item in (runs2 or []) if item["id"] == seeded.name), None)
        checks.append((
            "重启后能读到磁盘上的历史运行",
            seeded_entry is not None and seeded_entry["findings"] == 3
            and seeded_entry["status"] == "done",
            f"{seeded_entry}",
        ))
        _status, detail = _http(f"{root2}/api/history/{seeded.name}")
        detail_json = json.loads(detail) if _status == 200 else {}
        checks.append((
            "能查看历史运行的报告原文",
            detail_json.get("markdown_source") == "report"
            and "打包后历史报告" in (detail_json.get("markdown") or ""),
            f"status={_status} source={detail_json.get('markdown_source')}",
        ))
        ready2 = _window_ready()
        checks.append(("重启后窗口也正常创建", ready2, "窗口就绪" if ready2 else "未见窗口"))
        subprocess.run(["taskkill", "/PID", str(pid2)], capture_output=True, text=True, check=False)
        closed2 = _wait_all_gone()
        if not closed2:
            for leftover in _hexhound_pids():
                subprocess.run(["taskkill", "/F", "/PID", str(leftover)], capture_output=True, check=False)
        checks.append(("第二次关闭也干净退出", closed2,
                       "已优雅退出" if closed2 else "需要强制结束"))

    failed = [name for name, ok, _ in checks if not ok]
    print()
    for name, ok, detail in checks:
        print(f"{'[ OK ]' if ok else '[FAIL]'} {name} — {detail}")
    print()
    if failed:
        print(f"桌面验收失败：{len(failed)} 项 → {', '.join(failed)}")
        return 1
    print(f"桌面验收通过：{len(checks)} 项全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
