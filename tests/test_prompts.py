"""提示词与工具集的一致性测试（P2 回归）。

用户报的故障：桌面跑起来模型**反复**调用 `port_scan` / `web_fingerprint` /
`sandbox_script`，每次都拿回"未知工具"。根因不是模型乱编，而是两边不一致：

- 角色提示词是**静态文本**（"参数疑似注入时第一选择 sqlmap_scan"、
  "必须用 sandbox_script 主动打"）；
- 工具集是**按环境动态裁剪**的（沙箱不可用时这些名字根本不在注册表里）。

所以这里锁定一条不变量：**系统提示词的正文里，不允许出现本次没有下发的工具名**
（只允许出现在末尾那段"未下发的真工具"显式说明里）。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import Any

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.agent import _OPTIONAL_TOOLS  # noqa: E402
from hexhound.prompts import (  # noqa: E402
    MISSING_TOOLS_NOTE,
    ROLE_PROMPTS,
    adapt_prompt_to_tools,
    build_system_prompt,
)
from hexhound.surface import AttackSurface  # noqa: E402
from hexhound.tools import BROWSER_TOOLS, SANDBOX_TOOLS, ToolRegistry  # noqa: E402


class FakeSandbox:
    """沙箱替身：工具齐备（用来验证"可用时确实被广告"）。"""

    def __init__(self, tools: dict[str, bool] | None = None) -> None:
        self._tools = tools if tools is not None else {
            name: True for name in ("nmap", "sqlmap", "nuclei", "ffuf", "whatweb", "python3")
        }

    def available(self) -> bool:
        return True

    def tool_status(self) -> dict[str, bool]:
        return dict(self._tools)


def make_registry(role: str, sandbox: Any = None) -> ToolRegistry:
    return ToolRegistry(
        base_dir=Path("."),
        allowed_hosts=frozenset({"127.0.0.1"}),
        timeout=5,
        mode="blackbox",
        surface=AttackSurface(target="http://127.0.0.1:5000", mode="blackbox"),
        role=role,
        worker_id="W1",
        sandbox=sandbox,
    )


def assembled_prompt(registry: ToolRegistry, role: str) -> str:
    """复现 agent 里拼系统提示词的过程（角色正文 + 工具清单 → 可用性对齐）。"""
    system = build_system_prompt(registry.describe(), "blackbox", role)
    return adapt_prompt_to_tools(system, registry.tool_names(), _OPTIONAL_TOOLS)


def body_of(system: str) -> str:
    """正文 = 去掉末尾"未下发的真工具"说明段，只留角色指令。"""
    return system.split(MISSING_TOOLS_NOTE)[0]


class PromptToolConsistencyTests(unittest.TestCase):
    def test_optional_tools_cover_the_registry_gates(self) -> None:
        """提示词要摘的名字，必须覆盖注册表真正会摘的工具（否则漏一个就复发）。"""
        self.assertEqual(set(_OPTIONAL_TOOLS), set(SANDBOX_TOOLS) | set(BROWSER_TOOLS))

    def test_no_role_advertises_tools_it_does_not_have(self) -> None:
        """核心不变量：正文里出现的真工具名，必须是本次真的下发了的。"""
        roles = [*ROLE_PROMPTS, "blackbox", "source"]
        for role in roles:
            for sandbox in (None, FakeSandbox(), FakeSandbox({"sqlmap": True})):
                with self.subTest(role=role, sandbox=sandbox is not None):
                    registry = make_registry(role, sandbox)
                    available = set(registry.tool_names())
                    system = assembled_prompt(registry, role)
                    body = body_of(system)
                    for name in _OPTIONAL_TOOLS:
                        if name in available:
                            continue
                        self.assertNotIn(
                            name, body,
                            f"{role} 的提示词正文提到了没下发的工具 {name}",
                        )
                    self.assertNotIn("__SCRIPT_REQUIREMENT__", system)

    def test_available_real_tools_stay_advertised(self) -> None:
        """反向保护：摘除逻辑不能把**已经下发**的真工具也一起摘掉。"""
        registry = make_registry("injection", FakeSandbox())
        system = assembled_prompt(registry, "injection")
        available = set(registry.tool_names())
        self.assertIn("sqlmap_scan", available, "注入角色在沙箱可用时必须拿到 sqlmap_scan")
        for tool in ("sqlmap_scan", "sandbox_script"):
            self.assertIn(tool, system, f"沙箱可用时提示词必须仍然告诉模型 {tool} 能用")
        self.assertNotIn(MISSING_TOOLS_NOTE, system, "没有缺失工具时不该出现缺失说明")

    def test_missing_tools_are_named_explicitly(self) -> None:
        """缺失说明必须点名——只说"有些工具不可用"模型仍然会去试。"""
        registry = make_registry("injection", None)
        system = assembled_prompt(registry, "injection")
        note = system.split(MISSING_TOOLS_NOTE, 1)[1]
        self.assertIn("sqlmap_scan", note)
        self.assertIn("sandbox_script", note)
        self.assertIn("不可调用", note)

    def test_script_playbook_is_rewritten_without_a_script_channel(self) -> None:
        """没有脚本能力时，不能再说"必须用 sandbox_script 主动打"。"""
        text = ROLE_PROMPTS["injection"]
        without = adapt_prompt_to_tools(text, ["http_request"], ["sandbox_script"])
        self.assertIn("没有脚本能力", without)
        self.assertIn("未覆盖", without)
        with_script = adapt_prompt_to_tools(text, ["http_request", "sandbox_script"], ["sandbox_script"])
        self.assertIn("必须用 sandbox_script 主动打", with_script)

    def test_bullet_removal_drops_continuation_lines_too(self) -> None:
        """条目是折行的：只删第一行会留下悬空的续行，读起来像正常说明。"""
        text = (
            "<core>\n"
            "- **sqlmap_scan（真工具）**：第一行说明，\n"
            "  续行也在讲 sqlmap，必须一起消失；\n"
            "- fuzz_params：内置筛查。\n"
            "</core>\n"
        )
        out = adapt_prompt_to_tools(text, ["fuzz_params"], ["sqlmap_scan"])
        body = body_of(out)
        self.assertNotIn("sqlmap_scan", body)
        self.assertNotIn("续行也在讲", body)
        self.assertIn("fuzz_params", body)

    def test_unavailable_note_keeps_prompt_otherwise_intact(self) -> None:
        """只在有缺失时才追加说明（全可用时提示词必须逐字不变）。"""
        text = "- http_request：发请求。\n- sqlmap_scan：注入。\n"
        self.assertEqual(adapt_prompt_to_tools(text, ["http_request", "sqlmap_scan"], ["sqlmap_scan"]), text)


if __name__ == "__main__":
    unittest.main()
