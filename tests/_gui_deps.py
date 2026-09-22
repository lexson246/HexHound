"""把 flask 依赖检查写成一个共享小工具，避免三份拷贝各写各的。

为什么需要它（CI 抓到的真问题）：`tests/test_gui_state.py` 在缺 flask 时会把
**假替身**塞进 `sys.modules`（`Flask = object`）。于是别的测试文件里
`import flask` 会成功，接着 `Flask(__name__)` 抛
`TypeError: object() takes no arguments`——本该"跳过"的用例变成 12 个 ERROR。
所以检查必须同时看两件事：flask 能不能导入、它是真的还是替身。
"""
from __future__ import annotations

import os
import unittest


def flask_available() -> tuple[bool, str]:
    """返回 `(是否有可用的真 flask, 原因)`。"""
    try:
        import flask
    except ImportError as exc:
        return False, f"未安装 flask（桌面端控制台依赖，属于 [lab] extra）：{exc}"
    if getattr(flask, "__hexhound_flask_stub__", False):
        return False, (
            "flask 只是 tests/test_gui_state.py 里的替身模块（缺真 flask 时注入的），"
            "不能用来创建应用"
        )
    return True, ""


def require_flask_or_skip(reason_prefix: str = "") -> None:
    """缺真 flask 时跳过该测试类；`HEXHOUND_REQUIRE_GUI=1` 时**失败**。

    CI 的 `test` 作业只装 `[dev]`（刻意不装可选依赖）→ 这里跳过；
    `gui` 作业装了 `[lab]` 并设 `HEXHOUND_REQUIRE_GUI=1` → 缺依赖必须变红。
    """
    ok, reason = flask_available()
    if ok:
        return
    if os.environ.get("HEXHOUND_REQUIRE_GUI", "").strip():
        raise AssertionError(
            f"GUI 测试依赖缺失，但本环境要求必须运行：{reason_prefix}{reason}"
        )
    raise unittest.SkipTest(f"{reason_prefix}{reason}")
