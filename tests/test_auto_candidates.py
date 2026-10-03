"""实测信号不许凭空消失：没人下结论的端点自动登记为**候选**。

事实经过（第 6 轮 live 评测实测）：`/reflect` 记了 3 条 xss 信号
（"payload 原样回显（未转义）"）、`/file` 记了 1 条 path 信号
（响应 196 → 1451 字节，内容差异就是那个敏感文件），但两个端点都没有 finding/候选：
一个被模型"排除"了、一个连覆盖结论都没写。报告于是读起来像"这两个面没漏"。

设计要点：
* 只登记**候选**（`status=candidate`，标题带 `[自动]`，`confidence=unreviewed`）——
  候选说的是"有待复核的证据"，不是"确认有漏洞"，所以不会制造假结论；
* 已经落地成结论的（finding/候选/`reported` 覆盖行）不重复登记；
* 发现类尝试（enumerate）不算信号——否则每个扫出来的端点都会变成候选，噪音淹没报告；
* 排除理由（`dismissed`）一并写进候选描述：读者既看到排除，也看到原始证据。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.budget import Budget, BudgetLimits  # noqa: E402
from hexhound.mockllm import ScriptedLLM  # noqa: E402
from hexhound.orchestrator import Orchestrator  # noqa: E402

TARGET = "http://hexhound-test.invalid"
ALLOWED = frozenset({"127.0.0.1", "localhost", "hexhound-test.invalid"})


class AutoCandidateTests(unittest.TestCase):
    def make(self) -> Orchestrator:
        return Orchestrator(
            ScriptedLLM(),
            target=TARGET,
            goal="测试信号兜底",
            mode="blackbox",
            base_dir=Path("."),
            allowed_hosts=ALLOWED,
            timeout=1,
            max_tasks=1,
            task_steps=4,
            parallel=1,
            budget=Budget(BudgetLimits(max_tool_calls=200)),
        )

    def signalled(self, orchestrator: Orchestrator, path: str = "/reflect", **kwargs) -> None:
        orchestrator.surface.mark_attempt(
            TARGET + path,
            kwargs.pop("category", "xss"),
            param=kwargs.pop("param", "name"),
            payload=kwargs.pop("payload", "<script>alert(1)</script>"),
            outcome="signal",
            detail=kwargs.pop("detail", "payload 原样回显（未转义），疑似反射型 XSS"),
        )

    def test_signal_without_conclusion_becomes_a_candidate(self) -> None:
        orchestrator = self.make()
        self.signalled(orchestrator)
        ids = orchestrator._auto_register_signals()
        self.assertEqual(len(ids), 1)
        candidate = orchestrator.surface.candidates[ids[0]]
        self.assertEqual(candidate.status, "candidate")
        self.assertEqual(candidate.confidence, "unreviewed")
        self.assertTrue(candidate.title.startswith("[自动]"))
        self.assertIn("反射型XSS", candidate.vuln_type)
        self.assertIn("原样回显", candidate.evidence)
        # 覆盖表里也留一条：这块没结论
        row = next(
            entry for entry in orchestrator.surface.coverage.values()
            if "/reflect" in str(entry.get("target", ""))
        )
        self.assertEqual(row["status"], "not_tested")
        self.assertIn("待复核", str(row["detail"]))

    def test_discovery_hits_are_not_signals(self) -> None:
        """枚举的"路径存在"不是漏洞信号——否则每个扫出来的端点都会变成候选。"""
        orchestrator = self.make()
        orchestrator.surface.mark_attempt(
            TARGET + "/api/order", "enumerate", outcome="signal",
            detail="200  http://hexhound-test.invalid/api/order",
        )
        self.assertEqual(orchestrator._auto_register_signals(), [])

    def test_reported_coverage_settles_the_signal(self) -> None:
        orchestrator = self.make()
        self.signalled(orchestrator)
        orchestrator.surface.record_coverage(TARGET + "/reflect", "reported", detail="已报")
        self.assertEqual(orchestrator._auto_register_signals(), [])

    def test_existing_candidate_settles_the_signal(self) -> None:
        orchestrator = self.make()
        self.signalled(orchestrator)
        from hexhound.surface import Finding

        orchestrator.surface.add_candidate(Finding(
            id="", title="反射型 XSS（候选）", severity="medium", url=TARGET + "/reflect",
            param="name", status="candidate", dedupe_key="manual|reflect",
        ))
        self.assertEqual(orchestrator._auto_register_signals(), [])

    def test_dismissed_signal_is_still_registered_but_records_the_reason(self) -> None:
        """被"排除"的信号照样登记为候选——候选只代表"有证据待复核"；
        排除理由一并写进描述，读者两边都能看到（第 6 轮 `/reflect` 正是这种情形）。"""
        orchestrator = self.make()
        self.signalled(orchestrator)
        registry_coverage = orchestrator.surface
        registry_coverage.record_coverage(
            TARGET + "/reflect", "no_issue_found", detail="payload 落进响应体但未做浏览器验证",
            dismissed="无浏览器可用，未见可执行上下文",
        )
        ids = orchestrator._auto_register_signals()
        self.assertEqual(len(ids), 1)
        description = orchestrator.surface.candidates[ids[0]].description
        self.assertIn("无浏览器可用", description)

    def test_only_one_candidate_per_signal_fingerprint(self) -> None:
        """同一端点重复试出信号 → 只登记一条（候选是给人看的，不是日志）。"""
        orchestrator = self.make()
        for _ in range(3):
            self.signalled(orchestrator)
        ids = orchestrator._auto_register_signals()
        self.assertEqual(len(ids), 1)
        self.assertEqual(len(orchestrator.surface.candidates), 1)

    def test_signals_without_a_resolvable_endpoint_are_skipped(self) -> None:
        orchestrator = self.make()
        orchestrator.surface.mark_attempt(
            "（不是 URL）", "xss", param="name", outcome="signal", detail="回显",
        )
        self.assertEqual(orchestrator._auto_register_signals(), [])

    def test_finalise_coverage_runs_the_safety_net_and_logs_an_event(self) -> None:
        """收尾流程里真的调用它，并留下事件（离线审计能看出"这几条是自动登记的"）。"""
        orchestrator = self.make()
        self.signalled(orchestrator)
        orchestrator._finalise_coverage([], [])
        self.assertEqual(len(orchestrator.surface.candidates), 1)
        kinds = [event["kind"] for event in orchestrator.events]
        self.assertIn("auto_candidates", kinds)

    def test_findings_from_this_run_prevent_auto_registration(self) -> None:
        """本轮已报的端点不该再冒出一条自动候选。"""
        orchestrator = self.make()
        self.signalled(orchestrator)
        orchestrator._finalise_coverage(
            [{"url": TARGET + "/reflect", "param": "name", "title": "反射型 XSS",
              "vuln_type": "反射型XSS"}],
            [],
        )
        self.assertEqual(len(orchestrator.surface.candidates), 0)


if __name__ == "__main__":
    unittest.main()
