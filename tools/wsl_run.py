"""在 WSL 里跑 bash 的小工具：用 base64 传脚本，绕开 PowerShell 的编码/引号地狱。

用法（在仓库根目录）：
    python tools/wsl_run.py "nmap --version"
    python tools/wsl_run.py --file tools/probe.sh
    python tools/wsl_run.py --distro Ubuntu-24.04 "sqlmap --version"

为什么要 base64：PowerShell 把这里的 here-string 交给原生进程时会按当前代码页转码，
中文与 BOM 都会被破坏（实测出现过 `#!/usr/bin/env` 找不到、中文变乱码、管道里多出 \r）。
base64 只含 ASCII，怎么转都不会坏。
"""
from __future__ import annotations

import argparse
import base64
import subprocess
import sys
import tempfile
from pathlib import Path


def run(distro: str, script: str, user: str = "root") -> int:
    """把 script 送进 WSL 执行，返回退出码（输出直接透传到当前终端）。"""
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    # 写入 Windows 临时文件，让 WSL 通过 /mnt/c/... 读取（避免管道与换行问题）
    with tempfile.NamedTemporaryFile("w", suffix=".b64", delete=False, encoding="ascii") as handle:
        handle.write(encoded)
        temp_path = Path(handle.name)
    # C:\Users\x\AppData\Local\Temp\a.b64 -> /mnt/c/Users/x/AppData/Local/Temp/a.b64
    mount = "/mnt/" + str(temp_path).replace("\\", "/")[0].lower() + str(temp_path).replace("\\", "/")[2:]
    remote = f"tr -d '\\r\\n' < {mount} | base64 -d | bash"
    try:
        proc = subprocess.run(
            ["wsl.exe", "-d", distro, "-u", user, "--", "bash", "-c", remote],
            check=False,
        )
        return proc.returncode
    finally:
        temp_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="在 WSL 发行版里执行 bash 脚本")
    parser.add_argument("command", nargs="?", help="要执行的命令")
    parser.add_argument("--file", help="从文件读取脚本")
    parser.add_argument("--distro", default="Ubuntu-24.04", help="WSL 发行版名")
    parser.add_argument("--user", default="root", help="以哪个用户执行")
    args = parser.parse_args()

    if args.file:
        script = Path(args.file).read_text(encoding="utf-8")
    elif args.command:
        script = args.command
    else:
        parser.error("需要给出命令或 --file")
        return 2
    return run(args.distro, script, args.user)


if __name__ == "__main__":
    sys.exit(main())
