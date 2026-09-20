"""跨运行记忆的维护接口测试（查看 / 按编号删除 / 按时间删除 / 重置）。

存在理由：记忆是**只增不减**的累积文件，旧格式条目与脚本模型试跑留下的条目会在
每一次跨运行 diff 里以"状态未知"重复出现，把真正的回归结论淹没。清理入口是 diff
能用下去的前提，所以它自己也要有测试。
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.memory import HostMemory  # noqa: E402

TARGET = "http://hexhound-test.invalid"


def _finding(fid: str, at: str, title: str = "SQL 注入") -> dict:
    return {
        "id": fid,
        "title": f"{title} {fid}",
        "severity": "high",
        "vuln_type": "SQL注入",
        "url": f"{TARGET}/login",
        "status": "verified",
        "param": "username",
        "dedupe_key": f"sqli|/login|username|{fid}",
    }


class ForgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.memory = HostMemory(TARGET, home=Path(self._tmp.name))
        self.memory.record_run(findings=[_finding("HH-001", "")])
        self.memory.record_run(findings=[_finding("HH-002", "")])
        self.memory.record_run(findings=[_finding("HH-003", "")])
        # record_run 自己打时间戳；为按时间删除的用例补写固定时间
        for index, item in enumerate(self.memory.data["findings"], 1):
            item["at"] = f"2026-09-0{index} 10:00:00 UTC"
        self.memory.save()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_stats_reports_file_and_counts(self) -> None:
        info = self.memory.stats()
        self.assertEqual(info["findings"], 3)
        self.assertEqual(info["runs"], 3)
        self.assertTrue(info["path"].endswith(".json"))
        self.assertEqual(info["host"], TARGET)

    def test_forget_by_id_only_removes_that_entry(self) -> None:
        outcome = self.memory.forget(ids=["HH-002"])
        self.assertEqual(outcome, {"removed": 1, "kept": 2})
        ids = [item["id"] for item in self.memory.known_findings(10)]
        self.assertEqual(ids, ["HH-001", "HH-003"])

    def test_forget_before_cutoff_keeps_newer(self) -> None:
        """只删该时间点之前的条目；且**缺时间戳的条目不会被误删**。"""
        self.memory.data["findings"].append({"id": "HH-999", "title": "无时间", "at": ""})
        outcome = self.memory.forget(before="2026-09-02 00:00:00 UTC")
        self.assertEqual(outcome["removed"], 1)
        kept = {item["id"] for item in self.memory.known_findings(10)}
        self.assertEqual(kept, {"HH-002", "HH-003", "HH-999"})

    def test_reset_clears_entries_and_run_counter(self) -> None:
        outcome = self.memory.forget(reset=True)
        self.assertEqual(outcome["removed"], 3)
        self.assertEqual(outcome["kept"], 0)
        info = self.memory.stats()
        self.assertEqual(info["findings"], 0)
        self.assertEqual(info["runs"], 0)

    def test_changes_are_written_to_disk(self) -> None:
        self.memory.forget(ids=["HH-001", "HH-003"])
        raw = json.loads(Path(self.memory.path).read_text(encoding="utf-8"))
        self.assertEqual([item["id"] for item in raw["findings"]], ["HH-002"])

    def test_forget_keeps_lessons_and_notes(self) -> None:
        """清漏洞条目不等于清目标经验：tech / param_lessons / notes 必须留下。"""
        self.memory.record_run(
            tech={"server": "Werkzeug"},
            notes=["/admin 需要管理员"],
            attempts=[{"param": "uid", "category": "idor", "outcome": "signal"}],
        )
        self.memory.forget(reset=True)
        self.assertEqual(self.memory.data["tech"], {"server": "Werkzeug"})
        self.assertIn("/admin 需要管理员", self.memory.data["notes"])
        self.assertTrue(self.memory.top_param_lessons(5))


if __name__ == "__main__":
    unittest.main()
