# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：桌面窗口版（pywebview 套壳本地 Web 控制台）。

与 `HexHound.spec` 的区别：入口是 `desktop.py`（起本地 Flask + 开原生窗口），
因此是 windowed 模式（不弹控制台）。需要先 `pip install -e ".[desktop]"`。

构建：`python -m PyInstaller --noconfirm --clean HexHound-desktop.spec`
"""
from PyInstaller.utils.hooks import collect_all

datas = []
binaries = []
hiddenimports = []
for package in ("webview", "flask", "jinja2", "werkzeug", "openai", "httpx", "click", "dotenv"):
    try:
        collected = collect_all(package)
    except Exception:  # noqa: BLE001 可选依赖缺失时跳过
        continue
    datas += collected[0]
    binaries += collected[1]
    hiddenimports += collected[2]

for optional in ("playwright", "greenlet", "pyee"):
    try:
        collected = collect_all(optional)
    except Exception:  # noqa: BLE001
        continue
    datas += collected[0]
    binaries += collected[1]
    hiddenimports += collected[2]

hiddenimports += ["hexhound.desktop", "hexhound.gui"]

a = Analysis(
    ["packaging/hexhound_desktop.py"],
    pathex=["src", "packaging"],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "unittest", "pydoc"],
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
    name="HexHound-desktop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
