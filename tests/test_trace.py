"""可离线审计的运行轨迹（trace）与报告重建测试。

覆盖需求里的每一条：
- trace 记录模型步骤 / 工具调用 / 参数摘要 / 时间 / 状态 / 证据引用；
- 敏感字段脱敏；
- 报告能从持久化 snapshot **重新渲染**；
- 离线 report **不重新访问目标、不调用 LLM**；
- 旧格式 snapshot 兼容（或给出清晰迁移说明）。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound import cli as cli_module  # noqa: E402
from hexhound import llm as llm_module  # noqa: E402
from hexhound.agent import AgentResult  # noqa: E402
from hexhound.mockllm import ScriptedLLM  # noqa: E402
from hexhound.trace import (  # noqa: E402
    SNAPSHOT_SCHEMA_VERSION,
    TRACE_SCHEMA_VERSION,
    TraceRecorder,
    legacy_snapshot,
    load_snapshot,
    load_trace,
    mask_value,
    migrate_snapshot,
    redact,
    restore_run,
    summarize_trace,
    trace_schema_version,
    write_snapshot,
)

UNREACHABLE = "http://hexhound-test.invalid"


class RedactionTests(unittest.TestCase):
    """脱敏：trace 会长期保留、可能被贴进 issue，写入前必须掩码。"""

    def test_sensitive_keys_are_masked(self) -> None:
        payload = {
            "Authorization": "Bearer sk-abcdefghijklmnopqrstuvwxyz",
            "Cookie": "hh_session=user:tok-user-demo",
            "Set-Cookie": "hh_session=abc; HttpOnly",
            "X-Api-Key": "AKIAIOSFODNN7EXAMPLE",
            "password": "hunter2",
        }
        cleaned = redact(payload)
        for value in cleaned.values():
            self.assertIn("长度", value, f"未掩码：{value}")
        self.assertNotIn("hunter2", json.dumps(cleaned, ensure_ascii=False))
        self.assertNotIn("tok-user-demo", json.dumps(cleaned, ensure_ascii=False))

    def test_masking_keeps_key_name_and_length(self) -> None:
        """保留键名与长度是有意的：还能看出"当时带了这个头、大概多长"。"""
        value = "Bearer sk-0123456789abcdef"
        cleaned = redact({"Authorization": value})
        self.assertIn("Authorization", cleaned)
        self.assertIn(f"长度 {len(value)}", cleaned["Authorization"])
        self.assertTrue(cleaned["Authorization"].startswith("Bear"))

    def test_nested_structures_are_masked(self) -> None:
        payload = {
            "headers": {"Authorization": "Bearer secret-value-here"},
            "items": [{"token": "abc123def456"}, {"safe": "hello"}],
        }
        cleaned = redact(payload)
        self.assertIn("长度", cleaned["headers"]["Authorization"])
        self.assertIn("长度", cleaned["items"][0]["token"])
        self.assertEqual(cleaned["items"][1]["safe"], "hello")

    def test_key_values_looking_like_secrets_are_masked_even_under_safe_keys(self) -> None:
        """键名不敏感、但值长得像密钥 —— 也要掩码。"""
        cleaned = redact({"note": "found key sk-abcdefghijklmnopqrstuvwxyz in config"})
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz", cleaned["note"])
        self.assertIn("长度", cleaned["note"])

    def test_jwt_values_are_masked(self) -> None:
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ."
            "abcdefghijklmnopqrstuvwxyz123456"
        )
        cleaned = redact({"evidence": f"forged token {jwt}"})
        self.assertNotIn(jwt, cleaned["evidence"])

    def test_private_key_headers_are_masked(self) -> None:
        cleaned = redact({"body": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."})
        self.assertNotIn("BEGIN RSA PRIVATE KEY", cleaned["body"])

    def test_long_values_are_truncated_with_a_stated_length(self) -> None:
        cleaned = redact({"observation": "x" * 5000})
        self.assertLess(len(cleaned["observation"]), 2200)
        self.assertIn("共 5000 字符", cleaned["observation"])

    def test_scalars_and_none_survive(self) -> None:
        cleaned = redact({"count": 7, "ratio": 0.5, "flag": True, "nothing": None})
        self.assertEqual(cleaned, {"count": 7, "ratio": 0.5, "flag": True, "nothing": None})

    def test_deep_nesting_is_bounded(self) -> None:
        payload: dict = {}
        cursor = payload
        for _ in range(40):
            cursor["child"] = {}
            cursor = cursor["child"]
        redact(payload)  # 不抛异常即通过

    def test_mask_value_short_input(self) -> None:
        self.assertIn("长度 2", mask_value("ab"))
        self.assertEqual(mask_value(""), "")


class TraceRecorderTests(unittest.TestCase):
    def test_header_records_schema_version_and_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.jsonl"
            TraceRecorder(path, target="http://x.invalid", goal="g", mode="blackbox")
            events = load_trace(path)
            self.assertEqual(events[0]["kind"], "trace_header")
            self.assertEqual(events[0]["schema_version"], TRACE_SCHEMA_VERSION)
            self.assertEqual(events[0]["target"], "http://x.invalid")
            self.assertEqual(trace_schema_version(events), TRACE_SCHEMA_VERSION)

    def test_events_are_appended_and_flushed(self) -> None:
        """逐条 flush：运行被中断时"已经发生的事"必须已经落盘。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.jsonl"
            recorder = TraceRecorder(path)
            recorder.record("one")
            on_disk_after_first = len(load_trace(path))
            recorder.record("two")
            self.assertEqual(on_disk_after_first, 2)  # header + one
            self.assertEqual(len(load_trace(path)), 3)

    def test_step_event_captures_action_summary_and_evidence_refs(self) -> None:
        recorder = TraceRecorder(None)
        event = recorder.record_step(
            {
                "step": 3,
                "phase": "probe",
                "thought": "试一下这个参数",
                "action": "fuzz_params",
                "action_input": {"url": "http://x.invalid/a", "params": {"q": "1"}},
                "observation": "命中信号，证据 W1-R4 与 T2",
            },
            task="T1",
            role="injection",
        )
        self.assertEqual(event["kind"], "model_step")
        self.assertEqual(event["task"], "T1")
        self.assertEqual(event["data"]["action"], "fuzz_params")
        self.assertEqual(event["data"]["phase"], "probe")
        self.assertEqual(event["data"]["action_input"]["params"], {"q": "1"})
        # 证据引用要自动抽出来，方便按编号回查
        self.assertIn("W1-R4", event["data"]["evidence_refs"])
        self.assertIn("T2", event["data"]["evidence_refs"])

    def test_step_event_flags_tool_errors(self) -> None:
        recorder = TraceRecorder(None)
        event = recorder.record_step(
            {"step": 1, "action": "sqlmap_scan", "observation": "工具执行出错：Timeout"}
        )
        self.assertTrue(event["data"]["tool_error"])

    def test_tool_call_event_records_state_and_spill_handle(self) -> None:
        recorder = TraceRecorder(None)
        event = recorder.record_tool_call(
            task="T2",
            evidence_id="W2-T1",
            tool="sqlmap",
            command="sqlmap -u http://x.invalid/a --batch",
            ok=True,
            exit_code=0,
            duration=2.64,
            output_chars=5167,
            spill_handle="SO-" + "a" * 32,
        )
        # 事件的自定义字段统一放在 data 下（seq/kind/at/elapsed/task 在顶层）
        data = event["data"]
        self.assertEqual(event["kind"], "tool_call")
        self.assertEqual(event["task"], "T2")
        self.assertEqual(data["evidence_id"], "W2-T1")
        self.assertTrue(data["ok"])
        self.assertEqual(data["duration"], 2.64)
        self.assertEqual(data["output_chars"], 5167)
        self.assertEqual(data["spill_handle"], "SO-" + "a" * 32)

    def test_elapsed_and_timestamp_present(self) -> None:
        recorder = TraceRecorder(None)
        event = recorder.record("x")
        self.assertIn("at", event)
        self.assertIn("elapsed", event)
        self.assertGreaterEqual(event["elapsed"], 0.0)

    def test_sensitive_values_never_reach_the_file(self) -> None:
        """端到端：把带 Authorization 头的观察写进 trace，文件里不能有明文。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.jsonl"
            recorder = TraceRecorder(path)
            recorder.record_step(
                {
                    "step": 1,
                    "action": "http_request",
                    "action_input": {"headers": {"Authorization": "Bearer sk-supersecret1234567890"}},
                    "observation": "Cookie: hh_session=user:tok-user-demo",
                }
            )
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn("sk-supersecret1234567890", raw)
            self.assertNotIn("tok-user-demo", raw)
            self.assertIn("Authorization", raw)  # 键名保留，便于审计

    def test_disabled_recorder_keeps_events_in_memory(self) -> None:
        """不落盘时事件仍然保留在内存里（报告要用），header 也照写。"""
        recorder = TraceRecorder(None, enabled=False)
        recorder.record("x")
        events = recorder.events()
        self.assertEqual(len(events), 2)  # header + x
        self.assertEqual(events[0]["kind"], "trace_header")
        self.assertEqual(events[1]["kind"], "x")
        self.assertFalse(recorder.status()["enabled"])

    def test_digest_identifies_the_trace_content(self) -> None:
        """摘要用来回答"这份报告对应哪份 trace"，因此必须**只由内容决定**。

        header 里带真实时间戳，所以两个独立 recorder 的摘要天然不同——
        这里验证的是"同内容同摘要、不同内容不同摘要"这条性质：
        对同一份事件序列反复计算要稳定，改动内容要变。
        """
        recorder = TraceRecorder(None)
        recorder.record("a")
        baseline = recorder.digest()
        self.assertEqual(baseline, recorder.digest(), "同一份事件序列的摘要必须稳定")

        replaced = TraceRecorder(None)
        replaced._events = list(recorder.events())
        self.assertEqual(replaced.digest(), baseline, "同内容必须得到同摘要")

        changed = list(recorder.events()) + [{"kind": "x"}]
        other = TraceRecorder(None)
        other._events = changed
        self.assertNotEqual(other.digest(), baseline, "内容变了摘要必须变")

    def test_digest_is_a_sha256_hex_digest(self) -> None:
        recorder = TraceRecorder(None)
        recorder.record("a")
        digest = recorder.digest()
        self.assertEqual(len(digest), 64)
        self.assertTrue(all(ch in "0123456789abcdef" for ch in digest))

    def test_corrupt_lines_are_skipped_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.jsonl"
            path.write_text(
                '{"kind": "trace_header", "schema_version": 1}\n'
                "this is not json\n"
                '{"kind": "model_step"}\n',
                encoding="utf-8",
            )
            events = load_trace(path)
            self.assertEqual(len(events), 3)
            self.assertEqual(events[1]["kind"], "trace_corrupt_line")

    def test_missing_file_returns_empty(self) -> None:
        self.assertEqual(load_trace(Path("no-such-trace.jsonl")), [])

    def test_summarize_trace(self) -> None:
        recorder = TraceRecorder(None)
        recorder.record_step({"step": 1, "action": "crawl"}, task="T1")
        recorder.record_tool_call(task="T1", evidence_id="W1-T1", tool="sqlmap")
        recorder.record_tool_call(task="T2", evidence_id="W2-T1", tool="sqlmap")
        recorder.record_tool_call(task="T2", evidence_id="W2-T2", tool="nuclei")
        summary = summarize_trace(recorder.events())
        self.assertEqual(summary["events"], 5)  # header + 1 step + 3 tool calls
        self.assertEqual(summary["tasks"], ["T1", "T2"])
        self.assertEqual(summary["tools"], {"sqlmap": 2, "nuclei": 1})
        self.assertEqual(summary["schema_version"], TRACE_SCHEMA_VERSION)
        self.assertEqual(summary["kinds"]["tool_call"], 3)
        self.assertEqual(summary["kinds"]["model_step"], 1)
        self.assertEqual(summary["actions"], {"crawl": 1})

    def test_summarize_trace_reads_tools_from_event_data(self) -> None:
        """工具名在 data 里（`tool`），摘要必须从那里取——否则全变成 '?'。"""
        recorder = TraceRecorder(None)
        recorder.record_tool_call(task="T1", evidence_id="W1-T1", tool="whatweb")
        summary = summarize_trace(recorder.events())
        self.assertEqual(summary["tools"], {"whatweb": 1})
        self.assertNotIn("?", summary["tools"])


class SnapshotTests(unittest.TestCase):
    def make_result(self) -> AgentResult:
        return AgentResult(
            steps=[{"step": 1, "action": "crawl", "observation": "ok"}],
            findings=[{"id": "HH-001", "title": "测试", "severity": "high"}],
            final_summary="完成",
            finish_reason="finish",
            total_tokens=1234,
            estimated_cost=0.5,
            steps_used=1,
            tasks=[{"id": "T1", "role": "recon", "outcome": "done"}],
            tool_log=[{"id": "W1-T1", "tool": "sqlmap", "output": "x" * 10}],
            coverage_gate={"total": 3, "touched": 2},
            closing={"attempted": 1, "closed": True},
            usage={"total_tokens": 1234},
        )

    def test_round_trip_through_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_snapshot(
                Path(tmp), self.make_result(), goal="g", target="http://x.invalid", mode="blackbox"
            )
            self.assertIsNotNone(path)
            payload = load_snapshot(tmp)
            self.assertEqual(payload["schema_version"], SNAPSHOT_SCHEMA_VERSION)
            self.assertEqual(payload["goal"], "g")
            restored = AgentResult.from_snapshot(payload["result"])
            self.assertEqual(restored.final_summary, "完成")
            self.assertEqual(restored.total_tokens, 1234)
            self.assertEqual(restored.tool_log[0]["id"], "W1-T1")
            self.assertEqual(restored.closing["closed"], True)
            self.assertEqual(len(restored.findings), 1)

    def test_snapshot_excludes_surface_to_avoid_double_storage(self) -> None:
        """surface 数据在 surface.json 里，快照不重复存（否则体积翻倍）。"""
        with tempfile.TemporaryDirectory() as tmp:
            write_snapshot(Path(tmp), self.make_result())
            raw = (Path(tmp) / "snapshot.json").read_text(encoding="utf-8")
            self.assertNotIn('"surface"', raw)
            self.assertNotIn('"endpoints"', raw)

    def test_restore_prefers_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            write_snapshot(Path(tmp), self.make_result())
            outcome = restore_run(tmp)
            self.assertTrue(outcome.ok)
            self.assertEqual(outcome.source, "snapshot")

    def test_restore_reports_legacy_when_no_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            outcome = restore_run(tmp)
            self.assertFalse(outcome.ok)
            self.assertEqual(outcome.source, "legacy")
            self.assertTrue(any("snapshot.json" in warning for warning in outcome.warnings))

    def test_migration_from_v1(self) -> None:
        v1 = {
            "schema_version": 1,
            "goal": "old",
            "result": {"final_summary": "旧", "steps": []},
        }
        migrated, warnings = migrate_snapshot(v1)
        self.assertEqual(migrated["schema_version"], SNAPSHOT_SCHEMA_VERSION)
        self.assertTrue(any("迁移" in warning for warning in warnings))
        # 缺失的新字段补空值，而不是渲染出错误内容
        self.assertEqual(migrated["result"]["closing"], {})
        self.assertEqual(migrated["result"]["usage"], {})

    def test_migration_from_versionless_legacy(self) -> None:
        """最早的手写格式：结果字段直接平铺在顶层，没有 schema_version。"""
        legacy = {
            "generated_at": "2026-01-01 00:00:00 UTC",
            "final_summary": "平铺格式",
            "steps": [{"step": 1}],
            "findings": [],
        }
        migrated, warnings = migrate_snapshot(legacy)
        self.assertEqual(migrated["schema_version"], SNAPSHOT_SCHEMA_VERSION)
        self.assertTrue(any("没有 schema 版本" in warning for warning in warnings))
        self.assertEqual(migrated["result"]["final_summary"], "平铺格式")
        self.assertEqual(migrated["result"]["steps"], [{"step": 1}])

    def test_future_schema_warns_but_still_parses(self) -> None:
        """比本程序新的快照：警告 + 尽量解析，而不是直接失败。"""
        future = {
            "schema_version": SNAPSHOT_SCHEMA_VERSION + 5,
            "result": {"final_summary": "来自未来"},
        }
        migrated, warnings = migrate_snapshot(future)
        self.assertEqual(migrated["result"]["final_summary"], "来自未来")
        self.assertTrue(any("高于本程序支持" in warning for warning in warnings))

    def test_legacy_snapshot_builder_marks_itself(self) -> None:
        from hexhound.surface import AttackSurface

        surface = AttackSurface(target="http://x.invalid")
        payload = legacy_snapshot(surface=surface, tasks=[{"id": "T1"}], target="http://x.invalid")
        self.assertTrue(payload["legacy"])
        self.assertEqual(payload["result"]["tool_log"], [])
        self.assertIn("没有保存执行轨迹", payload["result"]["final_summary"])

    def test_corrupt_snapshot_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "snapshot.json").write_text("{ not json", encoding="utf-8")
            self.assertEqual(load_snapshot(tmp), {})
            self.assertFalse(restore_run(tmp).ok)

    def test_write_snapshot_failure_returns_none(self) -> None:
        """写快照失败不该让一次成功的审计报错。"""
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "a-file"
            bad.write_text("x", encoding="utf-8")
            # 把文件当目录用 → OSError
            self.assertIsNone(write_snapshot(bad, self.make_result()))


class OfflineReportIntegrationTests(unittest.TestCase):
    """端到端：audit → snapshot/trace 落盘 → report 离线重建。

    这里同时验证"离线"这件事本身：整个 report 调用过程里，
    HTTP 客户端与 LLM 客户端都被替换成**会抛异常**的替身，
    任何一次真实访问都会让用例失败。
    """

    def setUp(self) -> None:
        from click.testing import CliRunner

        self._env = dict(os.environ)
        self._home = tempfile.TemporaryDirectory()
        os.environ["HEXHOUND_HOME"] = self._home.name
        os.environ["ALLOWED_HOSTS"] = "127.0.0.1,localhost,hexhound-test.invalid"
        os.environ["LLM_PROVIDER"] = "deepseek"
        os.environ["PROVIDER_DEEPSEEK_API_KEY"] = "sk-test-not-used"
        for key in ("LLM_MODEL", "LLM_BASE_URL", "LLM_API_KEY"):
            os.environ.pop(key, None)
        self.runner = CliRunner()

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env)
        self._home.cleanup()

    def audit(self, output: Path, **extra: str):
        class FakeLLM:
            provider = "scripted"
            model = "scripted-policy"

            def __init__(self, *args, **kwargs) -> None:
                self._inner = ScriptedLLM()

            def describe(self) -> str:
                return "scripted/scripted-policy"

            def complete(self, messages):
                return self._inner.complete(messages)

        args = [
            "audit",
            "--target", UNREACHABLE,
            "--mode", "blackbox", "--no-sandbox",
            "--max-tasks", "2", "--task-steps", "4", "--parallel", "2",
            "--output", str(output),
        ]
        for key, value in extra.items():
            args += [f"--{key.replace('_', '-')}", value]
        with (
            patch.object(cli_module, "LLMClient", FakeLLM),
            patch.object(llm_module, "LLMClient", FakeLLM),
        ):
            return self.runner.invoke(cli_module.main, args, catch_exceptions=True)

    def run_dir(self) -> Path:
        runs = Path(self._home.name) / "runs"
        dirs = [item for item in runs.iterdir() if item.is_dir()]
        self.assertTrue(dirs, "没有产生运行产物目录")
        return max(dirs, key=lambda item: item.stat().st_mtime)

    def test_audit_writes_trace_and_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.audit(Path(tmp) / "r.md")
            self.assertEqual(result.exit_code, 0, result.output)
            run_dir = self.run_dir()
            self.assertTrue((run_dir / "trace.jsonl").is_file(), "缺少 trace.jsonl")
            self.assertTrue((run_dir / "snapshot.json").is_file(), "缺少 snapshot.json")

            events = load_trace(run_dir / "trace.jsonl")
            self.assertGreater(len(events), 3)
            self.assertEqual(trace_schema_version(events), TRACE_SCHEMA_VERSION)
            kinds = {event.get("kind") for event in events}
            # 编排层事件与模型步骤都要有——审计要能回答"为什么又开了一波"
            self.assertIn("orchestrator_wave", kinds)
            self.assertIn("model_step", kinds)
            # 每一步都带时间与状态
            for event in events[1:]:
                self.assertIn("at", event)
                self.assertIn("elapsed", event)
                self.assertIn("kind", event)

    def test_report_renders_trace_section_from_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.audit(Path(tmp) / "r.md")
            offline = Path(tmp) / "offline.md"
            second = self.runner.invoke(
                cli_module.main,
                ["report", "--run", "latest", "--target", UNREACHABLE, "--output", str(offline)],
                catch_exceptions=True,
            )
            self.assertEqual(second.exit_code, 0, second.output)
            text = offline.read_text(encoding="utf-8")
            self.assertIn("## 运行轨迹（可离线审计）", text)
            self.assertIn("trace.jsonl", text)
            self.assertIn("snapshot.json", text)

    def test_offline_report_survives_without_any_network_or_llm(self) -> None:
        """离线 report 期间任何真实 HTTP / LLM 调用都必须让用例失败。"""
        import httpx

        def explode(*args, **kwargs):
            raise AssertionError("离线 report 不得发起 HTTP 请求")

        class ExplodingLLM:
            def __init__(self, *args, **kwargs) -> None:
                raise AssertionError("离线 report 不得构造 LLM 客户端")

        with tempfile.TemporaryDirectory() as tmp:
            self.audit(Path(tmp) / "r.md")
            offline = Path(tmp) / "offline.md"
            with (
                patch.object(httpx, "request", explode),
                patch.object(cli_module, "LLMClient", ExplodingLLM),
                patch.object(llm_module, "LLMClient", ExplodingLLM),
            ):
                second = self.runner.invoke(
                    cli_module.main,
                    ["report", "--run", "latest", "--output", str(offline)],
                    catch_exceptions=True,
                )
            self.assertEqual(second.exit_code, 0, second.output)
            self.assertTrue(offline.exists())

    def test_offline_report_preserves_tool_evidence_from_snapshot(self) -> None:
        """回归：旧实现只从 surface+tasks 重建，工具证据附录整个丢失。"""
        with tempfile.TemporaryDirectory() as tmp:
            self.audit(Path(tmp) / "r.md")
            run_dir = self.run_dir()
            snapshot = load_snapshot(run_dir)
            # 注入一条工具证据（模拟真工具跑过），再离线重渲染
            snapshot["result"]["tool_log"] = [
                {
                    "id": "W1-T1",
                    "tool": "sqlmap",
                    "command": "sqlmap -u http://x.invalid/a --batch",
                    "output": "sqlmap identified the following injection point(s)",
                    "exit_code": 0,
                    "ok": True,
                    "duration": 1.5,
                    "note": "sqlmap",
                }
            ]
            (run_dir / "snapshot.json").write_text(
                json.dumps(snapshot, ensure_ascii=False), encoding="utf-8"
            )
            offline = Path(tmp) / "offline.md"
            second = self.runner.invoke(
                cli_module.main,
                ["report", "--run", str(run_dir), "--output", str(offline)],
                catch_exceptions=True,
            )
            self.assertEqual(second.exit_code, 0, second.output)
            text = offline.read_text(encoding="utf-8")
            self.assertIn("W1-T1", text)
            self.assertIn("sqlmap identified the following injection point", text)

    def test_offline_report_shows_spill_handle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.audit(Path(tmp) / "r.md")
            run_dir = self.run_dir()
            snapshot = load_snapshot(run_dir)
            snapshot["result"]["tool_log"] = [
                {
                    "id": "W1-T1",
                    "tool": "nuclei",
                    "command": "nuclei -u http://x.invalid",
                    "output": "truncated preview",
                    "exit_code": 0,
                    "ok": True,
                    "spill": {
                        "handle": "SO-" + "c" * 32,
                        "original_size": 120000,
                        "stored_size": 120000,
                        "total_chars": 120000,
                        "lines": 900,
                        "truncated": False,
                        "sha256": "d" * 64,
                    },
                }
            ]
            (run_dir / "snapshot.json").write_text(
                json.dumps(snapshot, ensure_ascii=False), encoding="utf-8"
            )
            offline = Path(tmp) / "offline.md"
            self.runner.invoke(
                cli_module.main,
                ["report", "--run", str(run_dir), "--output", str(offline)],
                catch_exceptions=True,
            )
            text = offline.read_text(encoding="utf-8")
            self.assertIn("完整输出已保存", text)
            self.assertIn("SO-" + "c" * 32, text)
            self.assertIn("120000", text)

    def test_trace_export_to_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.audit(Path(tmp) / "r.md")
            exported = Path(tmp) / "trace.json"
            second = self.runner.invoke(
                cli_module.main,
                [
                    "report", "--run", "latest", "--target", UNREACHABLE,
                    "--output", str(Path(tmp) / "o.md"),
                    "--trace", "--trace-out", str(exported),
                ],
                catch_exceptions=True,
            )
            self.assertEqual(second.exit_code, 0, second.output)
            self.assertTrue(exported.exists())
            events = json.loads(exported.read_text(encoding="utf-8"))
            self.assertIsInstance(events, list)
            self.assertTrue(events)
            self.assertIn("轨迹：", second.output)

    def test_legacy_run_dir_still_renders_with_a_clear_warning(self) -> None:
        """旧格式（只有 surface/tasks/run）必须还能出报告，并说明缺了什么。"""
        with tempfile.TemporaryDirectory() as tmp:
            self.audit(Path(tmp) / "r.md")
            run_dir = self.run_dir()
            # 模拟 v0.5 及以前的运行目录：删掉新格式的两个文件
            (run_dir / "snapshot.json").unlink()
            (run_dir / "trace.jsonl").unlink()
            offline = Path(tmp) / "legacy.md"
            second = self.runner.invoke(
                cli_module.main,
                ["report", "--run", str(run_dir), "--output", str(offline)],
                catch_exceptions=True,
            )
            self.assertEqual(second.exit_code, 0, second.output)
            self.assertTrue(offline.exists())
            self.assertIn("旧格式", second.output + (second.stderr or ""))
            text = offline.read_text(encoding="utf-8")
            self.assertIn("# HexHound 安全审计报告", text)

    def test_report_rejects_dir_with_nothing_to_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp) / "empty-run"
            empty.mkdir()
            result = self.runner.invoke(
                cli_module.main,
                ["report", "--run", str(empty), "--output", str(Path(tmp) / "x.md")],
                catch_exceptions=True,
            )
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("无法重建报告", result.output)


if __name__ == "__main__":
    unittest.main()
