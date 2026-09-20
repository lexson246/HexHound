"""pytest 全局引导：把测试与「开发机上的真实 .env / 运行产物」隔离开。

三件事必须在**任何 hexhound 模块被导入之前**做掉：

1. **不让 python-dotenv 读项目 .env**：`hexhound.config` 在导入时就会 `load_dotenv()`，
   于是开发机 .env 里的 `LLM_PROVIDER`/`LLM_BASE_URL`/`LLM_API_KEY` 会悄悄注入测试进程，
   把"设置隔离环境变量"的用例全部污染。
2. **把数据根指向临时目录**：`RunArtifacts` / `HostMemory` 默认写 `~/.hexhound`。
3. **把进程工作目录切到临时目录**：`hexhound setup` 与设置面板的「写入 .env」
   都写 `Path.cwd()/.env`——测试若在仓库根目录跑，会把**开发机真实的 .env 覆盖掉**
   （真实发生过：一次测试把 .env 写成了 qwen/max + 假 key）。切到临时目录后，
   任何"写 .env"的测试都只影响临时目录，仓库里的 .env 永远不会被动到。
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# 1) 关掉 dotenv 的项目 .env 加载（必须在 import hexhound.* 之前打桩）
import dotenv  # noqa: E402

dotenv.load_dotenv = lambda *args, **kwargs: False  # type: ignore[assignment]

# 2) 运行产物 + 工作目录都落到临时目录
_TEST_ROOT = Path(tempfile.mkdtemp(prefix="hexhound-tests-"))
os.environ.setdefault("HEXHOUND_HOME", str(_TEST_ROOT / "home"))
(_TEST_ROOT / "cwd").mkdir(parents=True, exist_ok=True)
os.chdir(_TEST_ROOT / "cwd")

# 3) 不预设任何提供商：用例自己按需要显式配置（HexHound 默认也不预设）
for _key in ("LLM_PROVIDER", "LLM_MODEL", "LLM_BASE_URL", "LLM_API_KEY"):
    os.environ.pop(_key, None)
