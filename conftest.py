"""pytest 根目录引导：在测试包自己的 conftest 切换工作目录**之前**锚定收集路径。

为什么需要这一层：`tests/conftest.py` 会把进程工作目录切到临时目录，以免测试
意外覆盖开发机真实的 `.env`。但 pytest 是在切换之后才解析 `testpaths` 的，
于是相对路径 `tests` 解析不到、报 "No files were found in testpaths" 并退化成
从当前目录递归收集。这里在导入阶段就显式收集 `tests/` 并清掉相对配置项。
"""
from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent


def pytest_configure(config) -> None:
    """把收集路径固定为项目内的 tests/（绝对路径），并移除会失效的相对配置。"""
    tests_dir = _ROOT / "tests"
    if not tests_dir.is_dir():
        return
    config.inicfg.pop("testpaths", None)
    if not [arg for arg in config.args if str(arg).strip() not in ("", ".")]:
        config.args = [str(tests_dir)]
