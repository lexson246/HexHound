"""终端与控制序列清理：让真工具的输出「可读、可存、可进模型上下文」。

为什么单独成模块（对应 docs/optimization-plan 的已知缺陷）：真工具的输出不是
给机器读的，而是给**终端**读的。实测两类污染：

1. **ANSI / OSC 转义序列**：sqlmap 的输出里带 `\\x1b[?1049h`、`\\x1b[0m` 这类
   光标与配色控制码；报告里印出来是乱码，模型读到也会浪费 token 去"理解"它们。
2. **编码与换行**：WSL 子进程回的是字节流，按错的编码解码就成了乱码
   （实测 `whatweb` 的中文/重音字符变 mojibake）；部分工具混用 `\\r\\n`，
   进度行还用裸 `\\r` 原地刷新，直接进报告会把一行糊成一坨。

本模块只做**确定性文本处理**，不碰网络、不碰文件、不依赖任何第三方库，
因此可以放心地在「裁剪 → 写报告 → 送模型」三条路径上共用。

安全性说明：清理是**单向**的（只删除控制序列，不做任何解释或求值）。
被删掉的字节不会影响证据链——原始字节仍保存在工具证据的完整输出里
（见 `spill.py`），报告与上下文里呈现的是可读版本。
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# 正则表：一条一条对着真实工具输出写的
# ---------------------------------------------------------------------------

#: CSI 序列：`ESC [ 参数 中间字节 终止字节`。
#: 覆盖光标移动、擦除、SGR 配色（`\x1b[0m`）、私有模式（`\x1b[?1049h`）等。
#: 终止字节范围 @-~ 是 ECMA-48 规定的 final byte。
_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

#: OSC 序列：`ESC ] ... BEL` 或 `ESC ] ... ST`。
#: 终端标题、超链接（`\x1b]8;;http://…\x07`）都走这条，里面的 URL 也不是内容。
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?", re.S)

#: 其它两字节转义（`ESC (`、`ESC =`、`ESC M` 等字符集/模式切换）。
_ESC_TWO_RE = re.compile(r"\x1b[ -/]*[0-~]")

#: 单个裸 ESC（前面那些都没吃掉时的兜底）。
_LONE_ESC_RE = re.compile(r"\x1b")

#: 除 `\n` `\t` 之外的 C0 控制字符（`\r` 单独处理，见 `_normalize_newlines`）。
_C0_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

#: DEL 与 C1 控制字符（0x80-0x9f）。C1 常出现在被按 Latin-1 解码的 UTF-8 字节里。
_C1_RE = re.compile(r"[\x80-\x9f]")

#: 进度条 / 原地刷新的经典形态：私有区字符（Braille 进度点 U+2800-U+28FF、
#: 方块 U+2580-U+259F）连成长串。只在**成串出现**时清理，单个字符保留。
_PROGRESS_CHUNK_RE = re.compile(r"[⠀-⣿▀-▟]{4,}")

#: 退格擦除不能只删 `\b` 了事——那会把被擦掉的原字符留在原地
#: （`abc\b\b\b   \b\b\bxyz` 会变成 `abc   xyz`，看起来像内容其实是终端残留）。
#: 这里按**终端语义**逐字符重放一行：`\b` 回退一格并覆盖。
_BACKSPACE_CHAR = "\x08"

#: 连续 3 个以上空行压成 2 个（工具输出常带大段空白）。
_BLANK_RUN_RE = re.compile(r"\n{3,}")


def decode_output(data: bytes | str | None, *, encoding: str = "utf-8") -> str:
    """把子进程回传的字节流解码成文本，**非法字节安全替换**。

    关键要求是"永不抛异常"：解码失败不该让一次工具调用整体失败，
    也不该让 `UnicodeDecodeError` 冒到编排层。策略：

    1. 先按 `encoding` 严格解码；
    2. 失败（或有 NUL，见下）时，在「替换解码结果」与「UTF-16LE / UTF-16 解码结果」
       里挑**噪音最少**的那个。`wsl.exe -l -q` 在部分 WSL 版本下就是 UTF-16LE
       （实测把 `Ubuntu-24.04` 解成乱码，于是"找不到发行版"）。
       注意不能只看 U+FFFD：UTF-16LE 的字节流按带替换的解码器解出来常常一个
       U+FFFD 都没有（0x00 是合法的 UTF-8 空字符），只会满屏 NUL，
       所以"噪音"要把 NUL 也算进去。
    3. 任何情况下都返回字符串，绝不抛异常。
    """
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    raw = bytes(data)
    if not raw:
        return ""
    try:
        decoded = raw.decode(encoding)
    except LookupError:
        # 编码名本身不认识（例如调用方传了 "not-a-codec"）：按 UTF-8 处理。
        encoding = "utf-8"
        decoded = ""
    except UnicodeDecodeError:
        decoded = ""
    if decoded and "\x00" not in decoded:
        return decoded
    # 走到这里说明：严格解码失败，或者解出来带 NUL（典型的 UTF-16LE 误判特征）。
    return _best_effort_decode(raw, encoding)


def _best_effort_decode(raw: bytes, encoding: str) -> str:
    """在替换解码与 UTF-16 之间选噪音最少的；都失败时返回替换解码结果。"""
    fallback = raw.decode(encoding, errors="replace")
    best = fallback
    best_noise = _noise(fallback)
    for candidate in ("utf-16-le", "utf-16"):
        if candidate.lower() == encoding.lower():
            continue
        try:
            decoded = raw.decode(candidate)
        except (UnicodeDecodeError, LookupError):
            continue
        noise = _noise(decoded)
        if noise < best_noise:
            best, best_noise = decoded, noise
    return best


def _noise(text: str) -> int:
    """解码噪音计数：替换字符 + 空字符。越低说明解得越对。"""
    return text.count("\ufffd") + text.count("\x00")


def decode_console_output(raw: bytes | str | None) -> str:
    """本机控制台命令输出的解码：**先按系统代码页，再按 UTF-8/UTF-16**。

    为什么不能直接用 `subprocess.run(..., text=True)`（实测事故，中文 Windows）：
    `route` / `ipconfig` / `docker info` / Edge 截图这类命令按**ANSI 代码页**
    （中文 Windows = cp936/GBK）输出，而 `text=True` 按 UTF-8 解码，
    读取线程里抛 `UnicodeDecodeError`——输出被截断，调用方只看到一条
    `PytestUnhandledThreadExceptionWarning`，根本看不出是编码问题。

    顺序刻意是**严格 UTF-8 优先**，失败才按系统代码页：

    - `route` / `ipconfig` / `docker` 这类命令在中文 Windows 上是 GBK，
      而 GBK 字节几乎不可能同时是合法 UTF-8（`0xd2 0xbb` 就不是），
      所以 UTF-8 严格解码失败 → 落到 cp936，结果正确；
    - 反过来（先按 cp936 试）会**静默解错**：UTF-8 的 `接口列表` 按 GBK 解出来是
      `鎺ュ彛鍒楄〃`，而且一个替换字符都没有——按"噪音"根本判不出来。
      这是实测踩到的坑，所以顺序不能反。

    两边都失败时回落到 `decode_output`（UTF-8/UTF-16 择优 + 替换，永不抛）。

    传入已是 `str` 时原样返回（调用方可能自己解过码）。
    """
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    data = bytes(raw)
    if not data:
        return ""
    import locale

    preferred = locale.getpreferredencoding(False)
    candidates: list[str] = []
    for name in ("utf-8", preferred, "gbk", "cp1252"):
        if name and name.lower() not in {item.lower() for item in candidates}:
            candidates.append(name)
    for name in candidates:
        try:
            decoded = data.decode(name)
        except (UnicodeDecodeError, LookupError):
            continue
        if "\x00" not in decoded:
            return decoded
        # ASCII + NUL 的字节流通常是 **UTF-16LE**（`wsl.exe -l -q` 就是），
        # 而它是合法 UTF-8（NUL 是合法字符）——不能就这么用，交给
        # `decode_output` 按噪音（替换字符 + NUL）择优。
        break
    return decode_output(data)


def _replay_backspaces(text: str) -> str:
    """按终端语义重放退格：`abc\\b\\b\\b   \\b\\b\\bxyz` → `xyz`。

    只处理退格这一种控制字符（不实现完整终端仿真）：真工具里出现退格的场景
    基本只有"进度行原地刷新"和"交互提示符重画"，逐字符回退覆盖就足够了，
    而且它是**确定性**的——不像"整行丢弃"那样会把同一行里有效的信息一起扔掉。
    """
    if _BACKSPACE_CHAR not in text:
        return text
    out: list[str] = []
    for line in text.split("\n"):
        if _BACKSPACE_CHAR not in line:
            out.append(line)
            continue
        buffer: list[str] = []
        for char in line:
            if char == _BACKSPACE_CHAR:
                if buffer:
                    buffer.pop()
                continue
            buffer.append(char)
        out.append("".join(buffer))
    return "\n".join(out)


def strip_ansi(text: str) -> str:
    """删除 ANSI / OSC / 其它转义序列与控制字符。

    只删除，不解释：转义序列里出现的 URL、颜色名都不是内容，
    留着只会污染报告与模型上下文（并且可能被误当成证据）。
    """
    if not text:
        return ""
    # 退格必须**最先**重放：它后面那几条规则里有一条会删掉全部 C0 控制字符，
    # 而 `\b` 正是 C0——顺序反了 `\b` 会被当成噪音清掉，被覆盖的原字符就留下了。
    cleaned = _replay_backspaces(text)
    cleaned = _OSC_RE.sub("", cleaned)
    cleaned = _CSI_RE.sub("", cleaned)
    cleaned = _ESC_TWO_RE.sub("", cleaned)
    cleaned = _LONE_ESC_RE.sub("", cleaned)
    cleaned = _C0_RE.sub("", cleaned)
    cleaned = _C1_RE.sub("", cleaned)
    cleaned = _PROGRESS_CHUNK_RE.sub("", cleaned)
    return cleaned


def normalize_newlines(text: str) -> str:
    """统一换行：`\\r\\n` → `\\n`，裸 `\\r`（进度刷新）→ `\\n`，去掉行尾空白。

    裸 `\\r` 不能直接删：它是"另起一行重画"的语义，直接拼起来会把两条不同信息
    粘成一条（例如 sqlmap 的进度行 + 结果行）。转成换行再压掉重复空行，
    既保留信息又不产生成片的空行噪音。
    """
    if not text:
        return ""
    cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in cleaned.split("\n")]
    return _BLANK_RUN_RE.sub("\n\n", "\n".join(lines))


def sanitize_terminal_text(text: str, *, max_chars: int = 0, keep_tail: bool = False) -> str:
    """完整清理管线：转义序列 → 换行归一 → 可选定长裁剪。

    `max_chars <= 0` 表示不裁剪。裁剪时保留头部（`keep_tail=True` 时改为保留尾部，
    例如"最后 N 行才是结论"的场景），并显式标注省略了多少字符——
    **被裁掉的部分必须写出来**，否则读者会以为那就是全部输出。
    """
    cleaned = normalize_newlines(strip_ansi(str(text or "")))
    if max_chars and len(cleaned) > max_chars:
        if keep_tail:
            omitted = len(cleaned) - max_chars
            cleaned = f"…[已省略前面 {omitted} 字符]…\n" + cleaned[-max_chars:]
        else:
            omitted = len(cleaned) - max_chars
            cleaned = cleaned[:max_chars] + f"\n…[已省略后面 {omitted} 字符]…"
    return cleaned


def clip_head_tail(text: str, limit: int) -> tuple[str, bool]:
    """保留头尾的定长裁剪，返回 `(文本, 是否被裁剪)`。

    与 `sanitize_terminal_text` 的分工：那个是"清理 + 简单裁剪"，
    这个是给需要同时看到**开头**（工具 banner / 命令行回显）与
    **结尾**（结论 / 报错）的场景用的（sqlmap、nuclei 的结论都在尾部）。
    """
    if limit <= 0 or len(text) <= limit:
        return text, False
    head = limit * 2 // 3
    tail = limit - head
    body = (
        text[:head]
        + f"\n…[输出过长，共 {len(text)} 字符，中间省略 {len(text) - limit} 字符]…\n"
        + text[-tail:]
    )
    return body, True


def visible_length(text: str) -> int:
    """清理后的可见长度（判断"有没有内容"时用它，而不是原始长度）。

    一份全是转义序列的输出，原始长度很可观，清理后是空的——
    那种情况应当报"无输出"，而不是让报告里出现一段看不见的东西。
    """
    return len(sanitize_terminal_text(text).strip())


__all__ = [
    "clip_head_tail",
    "decode_output",
    "normalize_newlines",
    "sanitize_terminal_text",
    "strip_ansi",
    "visible_length",
]
