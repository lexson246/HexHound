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

**终端文本清理**在 `console_text()` 里统一做：工具输出（sqlmap 的 `\\x1b[?1049h`、
whatweb 的 SGR 配色、进度行里的裸 `\\r`）会经事件回调流到终端，
不清理就会看到乱码。清理逻辑与报告、模型上下文共用 `sanitize` 模块，
保证"同一个工具输出在终端/报告/上下文里长得一样"。
"""
from __future__ import annotations

import sys

from .sanitize import sanitize_terminal_text


_UTF8_READY = False


def enable_utf8_console() -> bool:
    """尽力把标准输出切到 UTF-8。返回是否确认可写 UTF-8。

    幂等：包导入时会调一次（覆盖示例脚本等入口），`cli.main()` 会再调一次。
    重复调用没有副作用，但没必要重复探测。
    """
    global _UTF8_READY
    if _UTF8_READY:
        return True
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
    _UTF8_READY = ok
    return ok


def console_text(value: object) -> str:
    """把任意值转成**可以安全打进终端**的一行（多行也允许，只是会占多行）。

    - 剥掉 ANSI/OSC 与其它控制序列（否则终端上就是乱码）；
    - 归一 `\\r\\n` 与裸 `\\r`（进度行原地刷新会把它糊成一坨）；
    - 去除首尾空白。

    不截断：截断由调用方决定（每个地方的合理长度不同）。
    """
    return sanitize_terminal_text(str(value)).strip()


#: CLI 里使用的纯 ASCII 状态标记（不依赖字体，也不会触发编码问题）。
MARK_OK = "[OK]"
MARK_WARN = "[!!]"
MARK_FAIL = "[XX]"
MARK_SKIP = "[--]"
MARK_DOT = "--"
