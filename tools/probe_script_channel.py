"""手动验证 sandbox_script 真能跑通（排查工具通道本身是否坏了）。

用法：python tools/probe_script_channel.py
"""
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from hexhound.sandbox import Sandbox, detect_runtime  # noqa: E402

runtime = detect_runtime()
print("runtime:", runtime.describe() if runtime else "（无）")
sandbox = Sandbox(allowed_hosts=frozenset({"127.0.0.1", "localhost"}), map_loopback=False)
probe = sandbox.probe()
print("probe ok:", probe.get("ok"), "| python3:", (probe.get("tools") or {}).get("python3"))

script = """
import threading, urllib.request, json
BASE = "http://127.0.0.1:5000"
print("hello from sandbox script")
print("getaddrinfo host check:", BASE)
"""
result = sandbox.run_script(script, timeout=60)
print("ok:", result.ok, "| exit:", result.exit_code, "| error:", result.error)
print("--- stdout ---")
print(result.stdout[:1500])

# 运行时护栏验证：域名用拼接方式构造，静态扫描看不出来，必须由进程内护栏拦下
bypass = """
import socket
host = "ev" + "il.com"
try:
    socket.create_connection((host, 80), timeout=3)
    print("LEAK: connected to", host)
except Exception as exc:
    print("blocked:", type(exc).__name__, exc)
"""
blocked = sandbox.run_script(bypass, timeout=30)
print("\n[护栏] ok:", blocked.ok, "| exit:", blocked.exit_code)
print("[护栏] stdout:", blocked.stdout.strip()[:300])
print("[护栏] stderr:", blocked.stderr.strip()[:200])

