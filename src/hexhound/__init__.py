"""HexHound: AI-driven vulnerability hunting agent.

LLM 当"决策大脑"、真实 HTTP 请求当"手脚"、自带靶场当"裁判"，
先审计源码定位可疑点，再用黑盒请求拿到真实证据，只有证据成立才记录漏洞。

导入本包时会做一次**尽力而为**的控制台 UTF-8 初始化（`enable_utf8_console`）：
中文 Windows 控制台默认 GBK，任何非 GBK 字符（`✓`、`¥`、emoji、以及被
GBK 误解码的 UTF-8 中文）都会让 `print` 直接抛 `UnicodeEncodeError`。
实测踩过：

- `hexhound providers` 打印 `✓` 直接崩；
- `examples/swarm_demo.py` 打印预算行 `¥0.0000` 时崩在 `print`，
  而那次运行的所有编排工作其实都已经做完了——只是最后一步打印炸了。

放在包级而不是只放在 `cli.py`：示例脚本、第三方调用方、GUI 入口都从这里进来，
一处覆盖好过每个入口各写一遍。失败时静默忽略（没有控制台、权限受限、
流被重定向成不支持重配置的对象都属正常情况）。
"""
from __future__ import annotations

__version__ = "0.1.0"

_console_ready = False


def _bootstrap_console() -> None:
    """尽力把 stdout/stderr 切到 UTF-8；任何失败都不影响导入。"""
    global _console_ready
    if _console_ready:
        return
    _console_ready = True
    try:
        from .console import enable_utf8_console

        enable_utf8_console()
    except Exception:  # noqa: BLE001 控制台不可用不该让 import 失败
        pass


_bootstrap_console()

__all__ = ["__version__"]
