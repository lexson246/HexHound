# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：把 HexHound 打成单个可执行文件（放项目根目录即可用）。

产物是**控制台版 CLI**（`hexhound.exe`）——审计过程会打印任务计划、子任务起止、
漏洞清单与预算，这些输出在 windowed 模式里看不到，所以这里必须是 console 版。
桌面窗口版见 `HexHound-desktop.spec`。

构建：`python -m PyInstaller --noconfirm --clean HexHound.spec`
"""
from PyInstaller.utils.hooks import collect_all

datas = []
binaries = []
hiddenimports = []

# 逐个收集运行时依赖（包括其数据文件与子模块）：
# - click / dotenv / openai / httpx：CLI 与 LLM 调用
# - flask：`hexhound gui` 与设置面板（不装 playwright 也能跑）
for package in ("click", "dotenv", "openai", "httpx", "flask", "jinja2", "werkzeug"):
    try:
        collected = collect_all(package)
    except Exception:  # noqa: BLE001 可选依赖缺失时跳过，不让打包整体失败
        continue
    datas += collected[0]
    binaries += collected[1]
    hiddenimports += collected[2]

# 可选依赖：装了就打进去，没装也不影响构建。
for optional in ("playwright", "greenlet", "pyee", "webview"):
    try:
        collected = collect_all(optional)
    except Exception:  # noqa: BLE001
        continue
    datas += collected[0]
    binaries += collected[1]
    hiddenimports += collected[2]

# 显式声明入口模块，避免动态导入被裁掉。
hiddenimports += ["hexhound.cli"]

a = Analysis(
    ["packaging/hexhound_cli.py"],
    pathex=["src", "packaging"],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "unittest", "pydoc", "tkinter"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="hexhound",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,           # 审计输出必须可见
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
