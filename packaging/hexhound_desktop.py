"""PyInstaller 打包入口（桌面窗口版）。

与 `hexhound_cli.py` 同理：用绝对导入拉起包内的桌面入口，
避免相对导入在顶层脚本里失效。
"""
from __future__ import annotations

import multiprocessing
import sys


def main() -> None:
    multiprocessing.freeze_support()
    from hexhound.desktop import main as desktop_main

    desktop_main()


if __name__ == "__main__":
    sys.exit(main())
