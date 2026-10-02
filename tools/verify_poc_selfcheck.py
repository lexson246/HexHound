"""在 WSL 里跑生成的 PoC，验证"自校验"是否真的能判定漏洞成立/已修复。

背景：PoC 里的地址可能是地址映射后的宿主 IP（Windows 侧不可达），
所以要在 WSL（靶场所在网络命名空间）里执行才打得通。
"""
from __future__ import annotations

import json
import locale
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hexhound.memory import RunArtifacts  # noqa: E402

#: WSL/本机命令输出按系统代码页：显式声明编码，避免 UTF-8 解码在读取线程里抛异常
_CONSOLE_ENCODING = locale.getpreferredencoding(False) or "utf-8"

RUNS = sorted(Path.home().joinpath(".hexhound/runs").glob("http---127.0.0.1-5000-*"))


def pick_run() -> Path | None:
    """挑一个带 surface.json 且含 findings 的运行目录。"""
    for run in reversed(RUNS):
        surface = run / "surface.json"
        if not surface.is_file():
            continue
        data = json.loads(surface.read_text(encoding="utf-8"))
        if data.get("findings"):
            return run
    return None


def wsl_bash(script: str, timeout: int = 180) -> subprocess.CompletedProcess:
    """在 WSL 里执行脚本（用 base64 传，绕开 PowerShell 编码/引号问题）。"""
    import base64
    import tempfile

    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    with tempfile.NamedTemporaryFile("w", suffix=".b64", delete=False, encoding="ascii") as handle:
        handle.write(encoded)
        temp = Path(handle.name)
    resolved = str(temp.resolve())
    mount = "/mnt/" + resolved[0].lower() + resolved[2:].replace("\\", "/")
    try:
        return subprocess.run(
            ["wsl.exe", "-d", "Ubuntu-24.04", "-u", "root", "--", "bash", "-c",
             f"tr -d '\\r\\n' < {mount} | base64 -d | bash"],
            capture_output=True, text=True, timeout=timeout, check=False,
            # wsl.exe 里跑的是 Linux 侧命令，输出是 UTF-8，显式声明即可
            encoding="utf-8", errors="replace",
        )
    finally:
        temp.unlink(missing_ok=True)


def main() -> int:
    run = pick_run()
    if run is None:
        print("找不到带 findings 的运行目录")
        return 1
    print(f"运行目录：{run.name}")
    data = json.loads((run / "surface.json").read_text(encoding="utf-8"))
    findings = data.get("findings") or []
    artifacts = RunArtifacts("http://127.0.0.1:5000", enabled=True)

    # PoC 里的地址可能是宿主映射地址，替换回回环地址以便在 WSL 里跑
    for finding in findings[:3]:
        path = artifacts.write_poc(finding)
        if not path:
            continue
        script = Path(path).read_text(encoding="utf-8")
        # 把映射后的宿主地址换回 127.0.0.1（靶场在 WSL 本机）
        for host in ("192.168.160.1", "host.docker.internal"):
            script = script.replace(host, "127.0.0.1")
        wrapped = "export no_proxy='*'; export NO_PROXY='*'\n" + script
        result = wsl_bash(wrapped)
        print(f"\n=== {finding.get('id')} {str(finding.get('title'))[:52]} ===")
        for line in (result.stdout or "").splitlines():
            if any(token in line for token in ("[成立]", "[不成立]", "结论", ">>>", "步骤")):
                print("   " + line.strip()[:110])
        print(f"   退出码：{result.returncode}  "
              f"（0=仍可复现 / 1=已修复 / 2=打不通）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
