"""控制台编码处理：让 Windows 的 GBK 控制台不再因非 ASCII 字符崩溃。

背景（实测踩到的坑）：中文 Windows 控制台默认代码页 936（GBK），
`hexhound providers` 打印 `✓` 时直接抛 `UnicodeEncodeError: 'gbk' codec can't
encode character '\u2713'`——打包成 exe 后尤其明显，因为 exe 常被双击运行，
没有 `PYTHONIOENCODING=utf-8` 兜底。

处理方式（三层，任一层成功即可）：
1. 把 Windows 控制台输出代码页切成 UTF-8（65001）；
2. 把 stdout/stderr 重新配置为 UTF-8；
3. 仍失败则退化为 `errors="replace"`——宁可显示成 `?`，也不能让程序崩。

另外 CLI 输出统一改用 ASCII 标记（`[OK]` / `[!!]` / `--`），
不依赖控制台字体是否有对应字形。
"""
from __future__ import annotations

import sys


def enable_utf8_console() -> bool:
    """尽力把标准输出切到 UTF-8。返回是否确认可写 UTF-8。"""
    ok = False
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            # 65001 = UTF-8。控制台不支持时返回 0，不抛异常。
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
            ok = True
        except Exception:  # noqa: BLE001 无控制台/权限受限时忽略
            ok = False
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
                ok = True
            except Exception:  # noqa: BLE001 流被重定向成不支持重配置的对象
                pass
    return ok


#: CLI 里使用的纯 ASCII 状态标记（不依赖字体，也不会触发编码问题）。
MARK_OK = "[OK]"
MARK_WARN = "[!!]"
MARK_FAIL = "[XX]"
MARK_SKIP = "[--]"
MARK_DOT = "--"
