"""GUI 运行状态（RunState）的单元测试。

注意：这里**只**打桩真正的外部依赖（flask 的渲染函数），不再打桩 hexhound 自己的
内部模块——之前那样做会让"内部模块改名/新增函数"在测试里静默通过，直到真实运行时
才炸（v0.2 重构时就踩到了：`agent.extract_json` 被移到别处，打桩版测试仍全绿）。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import Mock, patch

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))


#: 打桩模块上的标记：让**别的测试文件**能分辨"真 flask"与"这个假替身"。
#:
#: 为什么必须有这个标记（CI 抓到的真问题）：这里的替身会把假的 `flask` 塞进
#: `sys.modules`，于是同一次 pytest 进程里别的文件 `import flask` 也会成功——
#: 接着 `Flask(__name__)` 在 `Flask = object` 上炸出
#: `TypeError: object() takes no arguments`。缺 flask 时 `test_providers` 的
#: 界面用例本该"跳过"，却变成了 12 个 ERROR。
STUB_MARKER = "__hexhound_flask_stub__"


def _stub_flask() -> None:
    """只替换 flask 的模板渲染与响应对象，保留真实模块结构。"""
    try:
        import flask  # noqa: F401

        return
    except ImportError:
        pass
    flask = types.ModuleType("flask")
    flask.Flask = object
    flask.jsonify = lambda data, *a, **k: data
    flask.render_template_string = lambda *a, **k: ""
    flask.request = object
    flask.send_file = object
    setattr(flask, STUB_MARKER, True)
    sys.modules["flask"] = flask


_stub_flask()

from hexhound import gui  # noqa: E402


class _FakeResult:
    """最小审计结果替身：只提供 `RunState.finish()` 真正读取的字段。"""

    findings = [{"title": "已确认的问题"}]
    final_summary = "中断前已完成 1 个子任务"
    prompt_tokens = 10
    completion_tokens = 5
    cache_hit_tokens = 1
    cache_miss_tokens = 2
    estimated_cost = 0.01
    total_tokens = 15


class RunStateTests(unittest.TestCase):
    def test_start_returns_increasing_tokens(self) -> None:
        state = gui.RunState()
        first = state.start()
        second = state.start()
        self.assertGreater(second, first)
        self.assertFalse(state.is_stopped(second))
        self.assertTrue(state.is_stopped(first))

    def test_stop_current_is_transitional_not_terminal(self) -> None:
        """停止请求只把状态推进到 `stopping`，收尾完成后才是 `cancelled`。

        旧行为是 `stop_current()` 立刻把状态写回 `idle`：界面上"跑到一半停下"
        与"什么都没跑"长得一模一样，而且立刻又允许启动新任务，两个审计线程
        会同时写同一份攻面与产物目录。这里把正确的迁移链钉死。
        """
        state = gui.RunState()
        token = state.start()
        state.add_step({"step": 1}, token)
        state.stop_current()
        self.assertTrue(state.is_stopped(token))
        snapshot = state.snapshot()
        self.assertEqual(snapshot["status"], "stopping")
        self.assertEqual(snapshot["status_label"], "正在停止")
        self.assertTrue(snapshot["running"], "收尾期间仍算占用运行名额")
        # 收尾期间不允许再起一个任务
        self.assertFalse(state.try_begin())

    def test_finish_after_stop_records_partial_result(self) -> None:
        """中断收尾：状态转 `cancelled`，但成果（步骤/发现/报告路径）必须保留。"""
        state = gui.RunState()
        token = state.start()
        state.add_step({"step": 1}, token)
        state.stop_current()
        state.finish(_FakeResult(), "runs/x/report.md", token, partial=True)
        snapshot = state.snapshot()
        self.assertEqual(snapshot["status"], "cancelled")
        self.assertEqual(snapshot["status_label"], "已中断（部分结果已保存）")
        self.assertTrue(snapshot["partial"])
        self.assertFalse(snapshot["running"])
        self.assertEqual(snapshot["findings"], [{"title": "已确认的问题"}])
        self.assertEqual(snapshot["summary"], "中断前已完成 1 个子任务")
        self.assertEqual(snapshot["output_path"], "runs/x/report.md")
        self.assertEqual(snapshot["steps"], [{"step": 1}])
        # 真正结束后才重新开放名额
        self.assertTrue(state.try_begin())

    def test_try_begin_blocks_overlapping_runs(self) -> None:
        """运行期间（含 stopping 收尾期）拒绝重叠启动，结束后才放行。"""
        state = gui.RunState()
        self.assertTrue(state.try_begin())
        self.assertFalse(state.try_begin(), "占位期间不得重复启动")
        state.start()
        self.assertFalse(state.try_begin())
        state.stop_current()
        self.assertFalse(state.try_begin(), "收尾期间不得重复启动")
        state.finish(_FakeResult(), "", 1, partial=True)
        self.assertEqual(state.snapshot()["status"], "cancelled")
        self.assertTrue(state.try_begin(), "结束后必须能再启动")

    def test_abort_begin_releases_only_the_placeholder(self) -> None:
        """`try_begin` 成功后若保存设置等步骤失败，必须能回滚占位。"""
        state = gui.RunState()
        self.assertTrue(state.try_begin())
        state.abort_begin()
        self.assertTrue(state.try_begin(), "回滚占位后应重新可占用")

    def test_failure_is_a_terminal_state(self) -> None:
        state = gui.RunState()
        token = state.start()
        state.fail("模型不可用", token)
        snapshot = state.snapshot()
        self.assertEqual(snapshot["status"], "failed")
        self.assertEqual(snapshot["error"], "模型不可用")
        self.assertFalse(snapshot["running"])
        self.assertTrue(state.try_begin())

    def test_stale_token_cannot_mutate_new_state(self) -> None:
        state = gui.RunState()
        old_token = state.start()
        new_token = state.start()
        state.add_step({"step": "old"}, old_token)
        self.assertEqual(state.snapshot()["steps"], [])
        state.add_step({"step": "new"}, new_token)
        self.assertEqual(state.snapshot()["steps"], [{"step": "new"}])

    def test_events_render_as_phases(self) -> None:
        state = gui.RunState()
        token = state.start()
        state.add_event({"kind": "plan", "tasks": [{"id": "T1", "role": "recon", "objective": "爬首页"}]}, token)
        state.add_event({"kind": "wave", "wave": 1, "count": 1}, token)
        state.add_event(
            {"kind": "task_end", "task": {"id": "T1", "outcome": "done", "summary": "完成"}}, token
        )
        phases = state.snapshot()["phases"]
        self.assertTrue(any("计划" in line for line in phases))
        self.assertTrue(any("第 1 波" in line for line in phases))
        self.assertTrue(any("[OK] [T1]" in line for line in phases))

    def test_stale_token_events_ignored(self) -> None:
        state = gui.RunState()
        old = state.start()
        new = state.start()
        state.add_event({"kind": "wave", "wave": 9, "count": 9}, old)
        self.assertEqual(state.snapshot()["phases"], [])
        state.add_event({"kind": "wave", "wave": 1, "count": 1}, new)
        self.assertNotEqual(state.snapshot()["phases"], [])


class DesktopExecutionTests(unittest.TestCase):
    """驱动真实桌面入口，所有执行环境、模型请求和文件写入均用替身。"""

    def run_audit(self, setup, *, swarm: bool):
        from hexhound import cli
        from hexhound.memory import RunArtifacts

        settings = {
            **gui.DEFAULTS,
            "provider": "custom", "model": "fixture", "base_url": "https://fixture.invalid/v1",
            "target": "http://fixture.invalid", "allowed_hosts": "fixture.invalid",
            "swarm": "1" if swarm else "0", "max_steps": "27", "task_steps": "7",
        }
        state = gui.RunState()
        token = state.start()
        with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
            stack.enter_context(patch.object(gui, "STATE", state))
            # 环境准备走**共享**的 prepare_sandbox（CLI 与桌面同一条路径）：
            # 这里替换它，正是为了验证"探测结果有没有真的下发到执行侧"。
            prepare = stack.enter_context(
                patch.object(gui, "prepare_sandbox", return_value=setup)
            )
            stack.enter_context(patch.object(cli, "_build_llm_pool", return_value=(Mock(), {})))
            stack.enter_context(patch.object(gui, "_provider_keys", return_value={}))
            stack.enter_context(patch.object(gui, "RunArtifacts", side_effect=lambda target: RunArtifacts(target, home=Path(tmp), enabled=False)))
            stack.enter_context(patch.object(gui, "HostMemory", return_value=None))
            stack.enter_context(patch.object(gui, "write_report", return_value=Path(tmp) / "report.md"))
            stack.enter_context(patch.object(gui, "write_butian_package", return_value=None))
            stack.enter_context(patch.object(gui, "_archive_report"))
            orchestrator = stack.enter_context(patch.object(gui, "Orchestrator"))
            orchestrator.return_value.run.return_value = _FakeResult()
            # 注册表用"真实构造 + 记录"的替身：既要能看传参，也要能拿到真对象
            # 去查它到底下发了哪些工具（P1 的判据就是工具集，不是传参）。
            created: list = []
            real_registry = gui.ToolRegistry

            def spy_registry(*args, **kwargs):
                obj = real_registry(*args, **kwargs)
                created.append(obj)
                return obj

            registry = stack.enter_context(
                patch.object(gui, "ToolRegistry", side_effect=spy_registry)
            )
            registry.created = created
            agent = stack.enter_context(patch.object(gui, "ReActAgent"))
            agent.return_value.run.return_value = _FakeResult()
            gui._run_audit(settings, token)
            snapshot = state.snapshot()
            self.assertEqual(snapshot["status"], "done", snapshot["error"])
            factory = orchestrator if swarm else registry
            return factory.call_args.kwargs, agent.call_args, snapshot, prepare.call_args, registry

    @staticmethod
    def ready_sandbox(kind: str = "wsl") -> Mock:
        sandbox = Mock()
        sandbox.runtime_kind = kind
        sandbox.probe.return_value = {"ok": True, "runtime": "fixture-tools"}
        sandbox.tool_status.return_value = {"sqlmap": True, "python3": True, "nuclei": True}
        sandbox.available.return_value = True
        sandbox.pick_image.return_value = "fixture-image"
        sandbox.images.return_value = ["fixture-image"]
        # `sandbox_report()` 会遍历它写进运行记录，替身必须提供真实类型，
        # 否则替身自身的不真实会伪装成产品代码的失败。
        sandbox.allowed_hosts = frozenset({"fixture.invalid"})
        sandbox.exec_log.return_value = []
        sandbox._host_map_notes = []
        sandbox._container = ""
        sandbox.host_gateway.return_value = ""
        return sandbox

    @staticmethod
    def ready_setup(kind: str = "wsl"):
        from hexhound.sandbox import SandboxSetup

        sandbox = DesktopExecutionTests.ready_sandbox(kind)
        return SandboxSetup(
            sandbox=sandbox, runtime="fixture-tools", tools=["nuclei", "python3", "sqlmap"]
        )

    def test_desktop_passes_available_sandbox_to_both_execution_paths(self) -> None:
        for swarm in (True, False):
            with self.subTest(swarm=swarm):
                setup = self.ready_setup()
                sandbox = setup.sandbox
                kwargs, agent_call, snapshot, prepare_call, _ = self.run_audit(setup, swarm=swarm)
                self.assertIs(kwargs["sandbox"], sandbox)
                self.assertEqual(kwargs["allowed_hosts"], frozenset({"fixture.invalid"}))
                if swarm:
                    self.assertEqual(kwargs["task_steps"], 7)
                    self.assertIn("各波次累计", "\n".join(snapshot["phases"]))
                else:
                    self.assertEqual(agent_call.kwargs["max_steps"], 27)
                sandbox.start.assert_not_called()
                sandbox.stop.assert_called_once_with()
                # 桌面端与 CLI 必须是同一份准备逻辑（只使用本地镜像，不自动下载）
                self.assertTrue(prepare_call.kwargs["local_image_only"])
                self.assertIn("sqlmap", "\n".join(snapshot["phases"]))

    def test_desktop_hands_real_tools_to_the_injection_role(self) -> None:
        """P1 回归：桌面跑出来的执行侧必须**真的有** sqlmap/nuclei/脚本工具。

        这条是用户报的原始故障（"桌面跑起来模型一直报未知工具"）的判据：
        只要探测成功却没把 sandbox 传进 ToolRegistry，注入角色就会静默退化成
        纯 HTTP 探测——所以这里不看"传参了没有"，而是直接问注册表要工具。
        """
        setup = self.ready_setup()
        _, _, _, _, registry = self.run_audit(setup, swarm=False)
        self.assertIs(registry.call_args.kwargs["sandbox"], setup.sandbox)
        # 桌面路径真正构造出来的那个注册表
        built = registry.created[-1]
        for tool in ("sqlmap_scan", "template_scan", "sandbox_script"):
            self.assertTrue(built.has(tool), f"桌面路径下 {tool} 必须可用")

        # 注入角色（波次/补扫任务用的就是这个角色）同样必须拿到真工具
        from hexhound.tools import ToolRegistry

        injection = ToolRegistry(
            base_dir=Path.cwd(), allowed_hosts=frozenset({"fixture.invalid"}), timeout=5,
            mode="blackbox", role="injection", sandbox=setup.sandbox,
        )
        names = set(injection.tool_names())
        for tool in ("sqlmap_scan", "template_scan", "sandbox_script"):
            self.assertIn(tool, names, f"注入角色缺少 {tool}——正是「未知工具」故障的来源")

    def test_unavailable_sandbox_is_reported_and_builtin_audit_still_runs(self) -> None:
        from hexhound.sandbox import SandboxSetup

        setup = SandboxSetup(reason="fixture unavailable", hint="先准备工具环境")
        kwargs, _, snapshot, _, _ = self.run_audit(setup, swarm=True)
        self.assertIsNone(kwargs["sandbox"])
        phases = "\n".join(snapshot["phases"])
        self.assertIn("fixture unavailable", phases)
        self.assertIn("先准备工具环境", phases)
        # 原因必须随运行一起落到执行侧：否则事后只能看到一堆"未知工具 xxx"
        self.assertIs(kwargs["sandbox_note"], setup)

    def test_docker_sandbox_reaches_execution_without_pulling(self) -> None:
        """桌面端只使用本地镜像：准备阶段已保证不拉取，运行期不得再 start。"""
        setup = self.ready_setup("docker")
        kwargs, _, _, _, _ = self.run_audit(setup, swarm=True)
        self.assertIs(kwargs["sandbox"], setup.sandbox)
        setup.sandbox.start.assert_not_called()
        setup.sandbox.stop.assert_called_once_with()

    def test_reasoning_setting_preserves_explicit_default_and_validates_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = Path(tmp) / "settings.json"
            with patch.object(gui, "SETTINGS_PATH", settings), patch.dict(os.environ, {"LLM_REASONING_EFFORT": "max"}):
                self.assertEqual(gui._load_settings()["reasoning_effort"], "max")
                settings.write_text(json.dumps({"reasoning_effort": ""}), encoding="utf-8")
                self.assertEqual(gui._load_settings()["reasoning_effort"], "")
                gui._save_settings({"reasoning_effort": "high"})
                self.assertEqual(gui._load_settings()["reasoning_effort"], "high")
        with self.assertRaisesRegex(ValueError, "推理强度"):
            gui._validate_run_settings({**gui.DEFAULTS, "reasoning_effort": "unsupported"})

    def test_reasoning_setting_is_forwarded_in_connection_and_env_endpoints(self) -> None:
        if getattr(sys.modules["flask"], STUB_MARKER, False):
            self.skipTest("requires real Flask")
        app = gui.create_app()
        client = app.test_client()
        headers = {gui.TOKEN_HEADER: app.config["HEXHOUND_LOCAL_TOKEN"]}
        payload = {"provider": "custom", "model": "fixture", "base_url": "https://fixture.invalid/v1", "reasoning_effort": "max"}
        with patch.object(gui, "_load_settings", return_value={}), patch.object(gui, "_provider_keys", return_value={}):
            with patch.object(gui, "LLMClient") as model:
                model.return_value.test_connection.return_value.to_dict.return_value = {"ok": True}
                response = client.post("/api/provider_test", json=payload, headers=headers)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(model.call_args.kwargs["reasoning_effort"], "max")
            with patch.object(gui, "write_env_file", return_value=(Path("fixture.env"), [])) as write_env:
                response = client.post("/api/write_env", json=payload, headers=headers)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(write_env.call_args.args[0]["LLM_REASONING_EFFORT"], "max")
                response = client.post("/api/write_env", json={**payload, "reasoning_effort": "unsupported"}, headers=headers)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(write_env.call_count, 1)
            with patch.object(gui, "LLMClient", side_effect=ValueError("invalid effort")):
                response = client.post("/api/provider_test", json=payload, headers=headers)
                self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
