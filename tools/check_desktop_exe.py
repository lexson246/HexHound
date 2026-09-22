"""校验打包出来的桌面版 exe 是「窗口子系统」——双击不弹黑色控制台窗口。

为什么单独写一个脚本：这是"桌面版到底是不是桌面版"最容易搞错、又最难在
CI 里直接看出来的性质。`console=True` 的构建同样能跑、同样能开窗口，
只是会先弹一个黑框（用户会以为程序出错了）；而反过来，桌面版被误当成
CLI 版复制到项目根目录时，用户双击后**什么都看不到**。

判据来自 PE 头（不需要运行 exe，因此在无桌面会话的 CI 里也能查）：
`Subsystem` 字段 2 = WINDOWS_GUI（窗口），3 = WINDOWS_CUI（控制台）。

用法：
    python tools/check_desktop_exe.py hexhound.exe [--expect-console]
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

SUBSYSTEM_GUI = 2
SUBSYSTEM_CONSOLE = 3
SUBSYSTEM_NAMES = {2: "WINDOWS_GUI（窗口，双击不弹控制台）", 3: "WINDOWS_CUI（控制台）"}


def read_subsystem(path: Path) -> int:
    """读取 PE 可选头里的 Subsystem 字段。"""
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError("不是 PE 文件（缺少 MZ 头）。")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("不是 PE 文件（缺少 PE 签名）。")
    # COFF 头 20 字节，紧跟可选头；Subsystem 在可选头偏移 68（PE32 与 PE32+ 一致）
    optional_offset = pe_offset + 4 + 20
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError(f"未知的可选头格式：0x{magic:x}")
    return struct.unpack_from("<H", data, optional_offset + 68)[0]


def main(argv: list[str]) -> int:
    args = [item for item in argv[1:] if not item.startswith("--")]
    expect_console = "--expect-console" in argv
    if not args:
        print(__doc__)
        return 2
    path = Path(args[0])
    if not path.is_file():
        print(f"[FAIL] 找不到文件：{path}")
        return 1
    try:
        subsystem = read_subsystem(path)
    except (OSError, ValueError, struct.error) as exc:
        print(f"[FAIL] {path} 不是可用的 Windows 可执行文件：{exc}")
        return 1
    name = SUBSYSTEM_NAMES.get(subsystem, f"未知（{subsystem}）")
    size_mb = path.stat().st_size / 1024 / 1024
    wanted = SUBSYSTEM_CONSOLE if expect_console else SUBSYSTEM_GUI
    ok = subsystem == wanted
    print(f"{'[ OK ]' if ok else '[FAIL]'} {path} — 子系统 {subsystem}：{name}（{size_mb:.1f} MB）")
    if not ok:
        expected = SUBSYSTEM_NAMES[wanted]
        print(f"       期望：{expected}")
        print(
            "       桌面版要求 console=False（HexHound-desktop.spec）；"
            "CLI 版用 --expect-console 校验。"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
