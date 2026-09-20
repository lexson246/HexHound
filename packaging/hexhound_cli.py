"""PyInstaller 打包入口（控制台版 CLI）。

为什么需要这个文件：直接用 `src/hexhound/cli.py` 当入口，PyInstaller 会把它当作
顶层脚本执行，里面的 `from .config import ...` 相对导入无处可依（报
"attempted relative import with no known parent package"）。这里用绝对导入，
并显式调用包内的 main()。
"""
from __future__ import annotations

import multiprocessing
import sys


def main() -> None:
    # 打包后若子进程再拉起自己，不加这个会无限 fork（PyInstaller 官方建议）。
    multiprocessing.freeze_support()
    from hexhound.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    sys.exit(main())
