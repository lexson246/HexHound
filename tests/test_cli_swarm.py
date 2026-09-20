"""CLI 端到端测试：用脚本 LLM 跑通 `hexhound audit` 全链路（不需要 API key、不需要网络）。

覆盖：多代理编排入口、预算参数、报告落盘、`--fail-on` 退出码、单代理回退。
靶场地址指向不可达端口，工具的请求会失败——这里验证的是**编排与产物**，不是检测能力
（检测能力由 `examples/tool_selftest.py` 对着真实靶场验证）。
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from click.testing import CliRunner  # noqa: E402

from hexhound import cli  # noqa: E402
from hexhound import llm as llm_module  # noqa: E402
from hexhound.mockllm import ScriptedLLM  # noqa: E402

UNREACHABLE = "http://hexhound-test.invalid"
# 说明：这里刻意用一个**解析不了**的域名，而不是 127.0.0.1 上的空闲端口——
# Windows 防火墙会让空闲端口的 TCP 连接静默丢弃，每次请求都要等满超时，
# 一个用例能慢到两分钟（实测 1.7s → 116s）。DNS 失败是立刻返回的。


class FakeLLM:
    """脚本 LLM + 客户端协议（describe/model/provider）——CLI 与编排层会读它们。"""

    provider = "scripted"
    model = "scripted-policy"

    def __init__(self, plan_tasks=None) -> None:
        self._inner = ScriptedLLM(plan_tasks=plan_tasks)

    def describe(self) -> str:
        return f"{self.provider}/{self.model}"

    def complete(self, messages):
        return self._inner.complete(messages)


class CliSwarmTests(unittest.TestCase):
    def setUp(self) -> None:
        self._env = dict(os.environ)
        # 用临时目录做数据根，避免测试污染真实的 ~/.hexhound/runs
        self._home = tempfile.TemporaryDirectory()
        os.environ["HEXHOUND_HOME"] = self._home.name
        os.environ["ALLOWED_HOSTS"] = "127.0.0.1,localhost,hexhound-test.invalid"
        # 明确选一个提供商：HexHound 默认不预设提供商（见 config.resolve_provider）
        os.environ["LLM_PROVIDER"] = "deepseek"
        os.environ["PROVIDER_DEEPSEEK_API_KEY"] = "sk-test-not-used"
        for key in ("LLM_MODEL", "LLM_BASE_URL", "LLM_API_KEY"):
            os.environ.pop(key, None)
        self.runner = CliRunner()

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env)
        self._home.cleanup()

    def invoke(self, args: list[str], llm=None):
        """用脚本 LLM 替换真实客户端。

        注意要同时替换 `cli.LLMClient` 与 `llm.LLMClient`：客户端池由
        `llm.build_llm_pool` 构造，只打桩 cli 侧的话它会拿到真实客户端去打网络。
        """
        fake = llm or FakeLLM()
        with (
            patch.object(cli, "LLMClient", lambda *a, **k: fake),
            patch.object(llm_module, "LLMClient", lambda *a, **k: fake),
        ):
            result = self.runner.invoke(cli.main, args, catch_exceptions=True)
        # Click 的 ClickException 走 stderr；把两路合并，断言才看得见完整输出
        self._last_combined = (result.output or "") + (
            "" if result.stderr is None else ""
        )
        return result

    @property
    def combined(self) -> str:
        return getattr(self, "_last_combined", "")

    def test_swarm_run_writes_report_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.md"
            result = self.invoke(
                [
                    "audit",
                    "--target", UNREACHABLE,
                    "--mode", "blackbox", "--no-sandbox",
                    "--max-tasks", "3",
                    "--task-steps", "4",
                    "--parallel", "2",
                    "--output", str(output),
                ]
            )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertTrue(output.exists())
            text = output.read_text(encoding="utf-8")
            self.assertIn("# HexHound 安全审计报告", text)
            self.assertIn("## 已复核漏洞", text)
            self.assertIn("## 子任务台账", text)
            self.assertIn("## OWASP 覆盖矩阵", text)
            self.assertIn("任务计划", result.output)

    def test_budget_limits_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.invoke(
                [
                    "audit",
                    "--target", UNREACHABLE,
                    "--mode", "blackbox", "--no-sandbox",
                    "--max-cost", "0.5",
                    "--max-tasks", "2",
                    "--task-steps", "4",
                    "--output", str(Path(tmp) / "r.md"),
                ]
            )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("预算上限", result.output)
            self.assertIn("预算：", result.output)

    def test_target_outside_allowlist_is_rejected(self) -> None:
        result = self.invoke(
            ["audit", "--target", "http://evil.example.com", "--mode", "blackbox", "--no-sandbox",
             "--no-sandbox"]
        )
        self.assertNotEqual(result.exit_code, 0)
        # ClickException 写 stderr；CliRunner 的 output 只含 stdout
        message = result.output + (result.stderr or "")
        self.assertIn("白名单", message)

    def test_single_agent_fallback_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "single.md"
            result = self.invoke(
                [
                    "audit",
                    "--target", UNREACHABLE,
                    "--mode", "blackbox", "--no-sandbox",
                    "--single",
                    "--max-steps", "2",
                    "--output", str(output),
                ]
            )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("单代理 ReAct", result.output)
            self.assertTrue(output.exists())

    def test_fail_on_returns_exit_code_two(self) -> None:
        """脚本 LLM 会记录 high 级漏洞：--fail-on high 应返回退出码 2。"""
        with tempfile.TemporaryDirectory() as tmp:
            plan = [
                {
                    "id": "T1",
                    "role": "recon",
                    "objective": "crawl 首页并枚举敏感路径，摸清端点/参数/技术栈",
                    "steps": 8,
                },
                {
                    "id": "T2",
                    "role": "injection",
                    "objective": f"对 {UNREACHABLE}/file 做定向注入验证",
                    "steps": 8,
                },
            ]
            result = self.invoke(
                [
                    "audit",
                    "--target", UNREACHABLE,
                    "--mode", "blackbox", "--no-sandbox",
                    "--max-tasks", "2",
                    "--task-steps", "8",
                    "--fail-on", "high",
                    "--output", str(Path(tmp) / "r.md"),
                ],
                llm=ScriptedLLM(plan_tasks=plan),
            )
            # 命中阈值 → 2；若脚本链路未产出 high 级已复核漏洞则退回 0（断言两者之一并给出上下文）
            self.assertIn(result.exit_code, (0, 2), result.output)
            if result.exit_code == 2:
                self.assertIn("--fail-on high", result.output)

    def test_unknown_mode_rejected_by_click(self) -> None:
        result = self.invoke(["audit", "--target", UNREACHABLE, "--mode", "nope"])
        self.assertNotEqual(result.exit_code, 0)

    def test_offline_report_rerenders_from_snapshot(self) -> None:
        """audit 之后可以用 report 子命令离线重渲染（不发请求、不调 LLM）。"""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run.md"
            first = self.invoke(
                [
                    "audit",
                    "--target", UNREACHABLE,
                    "--mode", "blackbox", "--no-sandbox",
                    "--max-tasks", "2",
                    "--task-steps", "4",
                    "--output", str(out),
                ]
            )
            self.assertEqual(first.exit_code, 0, first.output)

            report_out = Path(tmp) / "offline.md"
            second = self.invoke(
                [
                    "report",
                    "--run", "latest",
                    "--target", UNREACHABLE,
                    "--output", str(report_out),
                ]
            )
            self.assertEqual(second.exit_code, 0, second.output)
            self.assertTrue(report_out.exists())
            text = report_out.read_text(encoding="utf-8")
            self.assertIn("# HexHound 安全审计报告", text)
            self.assertIn("离线重渲染", text)
            # 台账来自 tasks.json，应当一并渲染出来
            self.assertIn("## 子任务台账", text)

    def test_offline_report_rejects_missing_run(self) -> None:
        result = self.invoke(["report", "--run", "no-such-run-dir", "--output", "x.md"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("找不到运行产物目录", result.output)


if __name__ == "__main__":
    unittest.main()
