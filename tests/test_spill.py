"""溢写存储测试：有界、按运行隔离、opaque 句柄、分页、搜索、配额、元数据。

对应需求里的每一条约束都至少一个用例：
有界正文 / 超长原文落盘 / 不可猜测的句柄 / 按 offset-limit 分页 /
字面量搜索 / 禁止任意路径读取 / 禁止跨运行读取 / 三级配额 /
original_size+stored_size+truncated+sha256 元数据 / 失败与超时输出同样保存。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.spill import (  # noqa: E402
    HANDLE_PREFIX,
    MAX_ENTRY_BYTES,
    MAX_READ_CHARS,
    SpillStore,
    is_handle,
    new_handle,
)
from hexhound.surface import AttackSurface  # noqa: E402
from hexhound.tools import (  # noqa: E402
    EVIDENCE_OUTPUT_CHARS,
    GOVERNOR_SMALL_LIMIT,
    ToolRegistry,
)


class HandleTests(unittest.TestCase):
    """句柄必须**不可猜测**，且不能变成路径。"""

    def test_handle_shape(self) -> None:
        handle = new_handle()
        self.assertTrue(handle.startswith(HANDLE_PREFIX))
        self.assertTrue(is_handle(handle))

    def test_handles_are_unique(self) -> None:
        handles = {new_handle() for _ in range(500)}
        self.assertEqual(len(handles), 500, "句柄必须唯一")

    def test_handle_contains_no_path_separators(self) -> None:
        """句柄里不能有路径分隔符或点号——否则它可能被当成路径用。"""
        for _ in range(50):
            handle = new_handle()
            for bad in ("/", "\\", "..", ":", "\x00"):
                self.assertNotIn(bad, handle)

    def test_counting_style_handles_are_rejected(self) -> None:
        """`SO-1`、`SO-2` 这种可枚举形式不是合法句柄（长度/字符集都不对）。"""
        for bad in ("SO-1", "SO-2", "SO-", "SO-xyz", "SO-" + "z" * 32):
            self.assertFalse(is_handle(bad), bad)

    def test_all_zero_handle_is_well_formed_but_unfindable(self) -> None:
        """`SO-000…0` 形式上合法（32 位十六进制），但**查不到任何东西**。

        这条是刻意写下来的边界：句柄校验只保证"形状对"，真正的安全性来自
        "128 位随机 + 只在本次运行的字典里查找"。所以一个形状合法的句柄
        猜中了也读不到内容——存储里没有它。
        """
        zeros = HANDLE_PREFIX + "0" * 32
        self.assertTrue(is_handle(zeros))
        self.assertFalse(SpillStore().read(zeros).ok)

    def test_is_handle_rejects_other_shapes(self) -> None:
        self.assertFalse(is_handle(""))
        self.assertFalse(is_handle("hello"))
        self.assertFalse(is_handle("W1-T3"))
        self.assertFalse(is_handle(HANDLE_PREFIX + "A" * 32))  # 大写不是我们的编码


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SpillStore(label="W1")

    def test_store_and_read_round_trip(self) -> None:
        entry = self.store.store("hello world", label="test")
        self.assertTrue(entry.stored_bytes > 0)
        result = self.store.read(entry.handle)
        self.assertTrue(result.ok)
        self.assertEqual(result.text, "hello world")

    def test_metadata_records_size_hash_and_lines(self) -> None:
        text = "line one\nline two\nline three"
        entry = self.store.store(text, label="cmd")
        self.assertEqual(entry.original_bytes, len(text.encode("utf-8")))
        self.assertEqual(entry.stored_bytes, len(text.encode("utf-8")))
        self.assertFalse(entry.truncated)
        self.assertEqual(entry.lines, 3)
        self.assertEqual(len(entry.sha256), 64)
        # sha256 必须是**原文**的（可以用来核对"拿到的就是当时那段"）
        import hashlib

        self.assertEqual(entry.sha256, hashlib.sha256(text.encode()).hexdigest())

    def test_metadata_dict_excludes_the_body(self) -> None:
        """元数据是进报告与证据的，不能把正文也塞进去（那就没省下空间）。"""
        entry = self.store.store("SECRET-BODY-MARKER" * 100)
        data = entry.to_dict()
        self.assertNotIn("SECRET-BODY-MARKER", str(data))
        self.assertIn("sha256", data)
        self.assertIn("original_size", data)
        self.assertIn("stored_size", data)
        self.assertIn("truncated", data)

    def test_oversized_entry_keeps_head_and_tail_and_says_so(self) -> None:
        """单条超上限：保留头尾，记录 truncated，并写明丢了多少。"""
        big = "HEAD-MARKER" + ("x" * (MAX_ENTRY_BYTES + 5000)) + "TAIL-MARKER"
        entry = self.store.store(big)
        self.assertTrue(entry.truncated)
        self.assertEqual(entry.original_bytes, len(big.encode()))
        self.assertLess(entry.stored_bytes, entry.original_bytes)
        total = self.store.read(entry.handle, limit=MAX_READ_CHARS).total_chars
        # 头部在第一页
        self.assertIn("HEAD-MARKER", self.store.read(entry.handle, limit=MAX_READ_CHARS).text)
        # 尾部在最后一页
        last = self.store.read(entry.handle, offset=max(0, total - 4000), limit=4000)
        self.assertIn("TAIL-MARKER", last.text)
        # 且**明确写出**中间有多少字节没保存（省略提示在头尾之间，用搜索定位）
        outcome = self.store.search(entry.handle, "未保存")
        self.assertTrue(outcome["hits"], "必须写明中间有多少字节没有保存")
        notice = outcome["hits"][0]["text"]
        self.assertIn("单条上限", notice)
        self.assertIn("字节", notice)


class PaginationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SpillStore()
        self.body = "".join(f"{index:05d}\n" for index in range(5000))  # 30000 字符
        self.entry = self.store.store(self.body)

    def test_offset_and_limit(self) -> None:
        result = self.store.read(self.entry.handle, offset=10, limit=20)
        self.assertTrue(result.ok)
        self.assertEqual(result.start, 10)
        self.assertEqual(result.end, 30)
        self.assertEqual(result.text, self.body[10:30])
        self.assertTrue(result.has_more)

    def test_paging_covers_the_whole_body_exactly_once(self) -> None:
        """分页拼起来必须等于原文——不能漏字也不能重复。"""
        collected: list[str] = []
        offset = 0
        for _ in range(100):
            result = self.store.read(self.entry.handle, offset=offset, limit=4000)
            self.assertTrue(result.ok)
            collected.append(result.text)
            if not result.has_more:
                break
            offset = result.end
        self.assertEqual("".join(collected), self.body)

    def test_last_page_reports_no_more(self) -> None:
        result = self.store.read(self.entry.handle, offset=len(self.body) - 5, limit=100)
        self.assertFalse(result.has_more)
        self.assertEqual(result.end, len(self.body))

    def test_offset_past_the_end_is_safe(self) -> None:
        result = self.store.read(self.entry.handle, offset=10**9, limit=100)
        self.assertTrue(result.ok)
        self.assertEqual(result.text, "")
        self.assertFalse(result.has_more)

    def test_limit_is_capped(self) -> None:
        """单次读取有上限——否则"分页"形同虚设，一次调用又能把上下文塞满。"""
        result = self.store.read(self.entry.handle, offset=0, limit=10**9)
        self.assertLessEqual(len(result.text), MAX_READ_CHARS)

    def test_negative_offset_clamped(self) -> None:
        result = self.store.read(self.entry.handle, offset=-50, limit=10)
        self.assertEqual(result.start, 0)

    def test_default_limit_returns_a_page(self) -> None:
        result = self.store.read(self.entry.handle)
        self.assertTrue(result.ok)
        self.assertTrue(result.text)
        self.assertLessEqual(len(result.text), MAX_READ_CHARS)


class SearchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SpillStore()
        self.body = (
            "starting scan\n"
            "target http://127.0.0.1:5000\n"
            "no injection found\n"
            "Parameter: username (POST)\n"
            "    Type: boolean-based blind\n"
            "the back-end DBMS is SQLite\n"
        )
        self.entry = self.store.store(self.body)

    def test_literal_search_finds_lines(self) -> None:
        outcome = self.store.search(self.entry.handle, "injection")
        self.assertTrue(outcome["ok"])
        self.assertEqual(len(outcome["hits"]), 1)
        hit = outcome["hits"][0]
        self.assertEqual(hit["line"], 3)
        self.assertIn("injection", hit["text"])

    def test_search_returns_all_occurrences(self) -> None:
        outcome = self.store.search(self.entry.handle, "e")
        self.assertGreater(len(outcome["hits"]), 3)

    def test_search_is_literal_not_regex(self) -> None:
        """刻意不做正则：模型给的正则容易 ReDoS，而真实用法是找已知字符串。"""
        outcome = self.store.search(self.entry.handle, "1.1.1.1|2.2.2.2")
        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["hits"], [], "正则元字符必须按字面量处理")

    def test_search_for_regex_metacharacters_is_safe(self) -> None:
        """病态正则当字面量处理 → 立刻返回而不是灾难性回溯。"""
        import time

        start = time.time()
        outcome = self.store.search(self.entry.handle, "(a+)+$")
        self.assertLess(time.time() - start, 1.0)
        self.assertTrue(outcome["ok"])

    def test_search_missing_needle(self) -> None:
        outcome = self.store.search(self.entry.handle, "definitely-not-present")
        self.assertEqual(outcome["hits"], [])

    def test_empty_needle_rejected(self) -> None:
        outcome = self.store.search(self.entry.handle, "")
        self.assertFalse(outcome["ok"])

    def test_hits_are_capped(self) -> None:
        entry = self.store.store("x\n" * 5000)
        outcome = self.store.search(entry.handle, "x", limit=1000)
        self.assertLessEqual(len(outcome["hits"]), 50)
        self.assertTrue(outcome["truncated"])


class IsolationTests(unittest.TestCase):
    """禁止任意路径读取、禁止跨运行读取。"""

    def test_unknown_handle_is_refused(self) -> None:
        store = SpillStore()
        result = store.read("SO-" + "a" * 32)
        self.assertFalse(result.ok)
        self.assertIn("未找到", result.error)

    def test_handles_do_not_resolve_across_stores(self) -> None:
        """两个存储（= 两次运行 / 两个任务）之间句柄不互通。"""
        first = SpillStore(label="run-1")
        second = SpillStore(label="run-2")
        entry = first.store("run one secret")
        # 第二个存储里查不到第一个的句柄
        self.assertFalse(second.read(entry.handle).ok)
        self.assertFalse(second.search(entry.handle, "secret")["ok"])
        # 第一个自己能读到
        self.assertTrue(first.read(entry.handle).ok)

    def test_store_exposes_no_path_api(self) -> None:
        """存储的公开接口里不能有"按路径读"的入口。"""
        public = {name for name in dir(SpillStore) if not name.startswith("_")}
        for forbidden in ("read_file", "read_path", "open", "load", "read_bytes"):
            self.assertNotIn(forbidden, public)

    def test_path_like_handle_is_not_opened(self) -> None:
        """把路径当句柄传进来只会"未找到"，不会被打开。"""
        store = SpillStore()
        for candidate in ("/etc/passwd", "../../secret.txt", "C:\\Windows\\win.ini"):
            result = store.read(candidate)
            self.assertFalse(result.ok)


class QuotaTests(unittest.TestCase):
    def test_run_quota_refuses_and_reports(self) -> None:
        """运行配额用尽 → 明确记录未保存，而不是假装存下了。"""
        store = SpillStore(max_run_bytes=100)
        first = store.store("x" * 80)
        self.assertEqual(first.stored_bytes, 80)
        second = store.store("y" * 80)
        self.assertEqual(second.stored_bytes, 0, "超配额时不能假装保存成功")
        self.assertIn("run_quota_exceeded", second.reasons)
        self.assertTrue(second.truncated)
        usage = store.usage()
        self.assertEqual(usage["rejected"], 1)
        self.assertIn("配额已用尽", usage["last_rejection"])

    def test_usage_reports_quota_state(self) -> None:
        store = SpillStore(max_run_bytes=1000)
        store.store("abc")
        usage = store.usage()
        self.assertEqual(usage["entries"], 1)
        self.assertEqual(usage["used_bytes"], 3)
        self.assertEqual(usage["run_quota_bytes"], 1000)
        self.assertEqual(usage["rejected"], 0)

    def test_global_budget_exhaustion_disables_spilling(self) -> None:
        """全局配额（跨运行累计）用尽时，新的存储进入"不再溢写"模式。"""
        from hexhound import spill as spill_module

        original = spill_module.GLOBAL_SPILL_BUDGET.used_bytes
        try:
            spill_module.GLOBAL_SPILL_BUDGET.used_bytes = spill_module.MAX_TOTAL_BYTES + 1
            store = spill_module.make_store(label="W9")
            entry = store.store("some output")
            # 存储仍然可用（工具不该因此报错），但明确不保存
            self.assertEqual(entry.stored_bytes, 0)
            self.assertIn("run_quota_exceeded", entry.reasons)
        finally:
            spill_module.GLOBAL_SPILL_BUDGET.used_bytes = original

    def test_quota_does_not_corrupt_existing_entries(self) -> None:
        store = SpillStore(max_run_bytes=100)
        first = store.store("A" * 80)
        store.store("B" * 80)  # 被拒绝
        self.assertEqual(store.read(first.handle).text, "A" * 80)


class GovernorSpillIntegrationTests(unittest.TestCase):
    """治理层与溢写层的接线：超限输出必须落进存储并给出句柄。"""

    def make_registry(self) -> ToolRegistry:
        return ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1"}),
            mode="blackbox",
            role="recon",
            surface=AttackSurface(target="http://127.0.0.1:5000"),
        )

    def test_small_output_is_not_spilled(self) -> None:
        from hexhound.tools import _govern

        registry = self.make_registry()
        text, _ = _govern("read_urls", "small output", registry)
        self.assertEqual(text, "small output")
        self.assertEqual(registry.spill_store().handles(), [])

    def test_large_output_is_spilled_and_handle_is_advertised(self) -> None:
        from hexhound.tools import _govern

        registry = self.make_registry()
        body = "START\n" + ("payload line\n" * 4000) + "THE-CONCLUSION\n"
        self.assertGreater(len(body), GOVERNOR_SMALL_LIMIT)
        text, _ = _govern("read_urls", body, registry)

        self.assertIn("完整输出已保存", text)
        self.assertIn(HANDLE_PREFIX, text)
        self.assertIn("spill_read", text)
        # 从提示里把句柄抠出来，确认真的能读回**完整**原文。
        # 用 find 而不是按空白切分：提示里的句柄被引号/全角括号包着，
        # 切分后再 strip 容易把尾部一起吃掉。
        import re

        match = re.search(r"SO-[0-9a-f]{32}", text)
        self.assertIsNotNone(match, f"提示里没有可用句柄：{text[:300]}")
        handle = match.group(0)
        result = registry.spill_store().read(handle, limit=MAX_READ_CHARS)
        self.assertTrue(result.ok)
        self.assertIn("START", result.text)
        self.assertIn("THE-CONCLUSION", registry.spill_store().read(
            handle, offset=max(0, result.total_chars - 500), limit=1000
        ).text)

    def test_spilled_spill_is_not_recursively_spilled(self) -> None:
        """`spill_read` 自己的输出不该再触发一次溢写（会无限套娃）。"""
        from hexhound.tools import _DESC_SPILL_READ  # noqa: F401
        from hexhound.tools import _govern

        registry = self.make_registry()
        entry = registry.spill("Z" * 40000)
        page = registry.spill_store().read(entry.handle, limit=MAX_READ_CHARS)
        text, _ = _govern("spill_read", page.text, registry)
        # 一页最多 MAX_READ_CHARS，不超过正文上限 → 不再溢写
        self.assertLessEqual(len(page.text), MAX_READ_CHARS)
        self.assertLessEqual(len(text), MAX_READ_CHARS + 200)


class ToolEvidenceSpillTests(unittest.TestCase):
    """工具证据：超长输出落进溢写，证据里带句柄/大小/sha256。"""

    def make_registry(self) -> ToolRegistry:
        return ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1"}),
            mode="blackbox",
            role="recon",
            surface=AttackSurface(target="http://127.0.0.1:5000"),
        )

    def test_evidence_records_spill_metadata(self) -> None:
        from hexhound.sandbox import ExecResult
        from hexhound.tools import _record_tool_evidence

        registry = self.make_registry()
        body = "BANNER\n" + ("result line\n" * 3000)
        result = ExecResult(ok=True, command="nuclei -u x", stdout=body, exit_code=0)
        evidence_id = _record_tool_evidence(registry, result, "nuclei")
        entry = registry.sandbox_log[-1]
        self.assertEqual(evidence_id, entry["id"])
        spill = entry["spill"]
        self.assertTrue(spill, "超长输出必须产生溢写记录")
        # 溢写的是**证据实际拿到的文本**（ExecResult.output 会合并 stdout/stderr
        # 并 strip 首尾空白），不是原始 stdout 字节数——口径要一致。
        self.assertEqual(spill["original_size"], len(result.output.encode("utf-8")))
        self.assertEqual(len(spill["sha256"]), 64)
        self.assertLessEqual(len(entry["output"]), EVIDENCE_OUTPUT_CHARS)
        self.assertTrue(entry["truncated"])

    def test_failed_and_partial_output_is_also_saved(self) -> None:
        """失败/超时/部分输出同样要保存——那是最需要回看的输出。"""
        from hexhound.sandbox import ExecResult
        from hexhound.tools import _record_tool_evidence

        registry = self.make_registry()
        long_error = "Traceback\n" + ("error detail\n" * 2000)
        result = ExecResult(
            ok=False, command="sqlmap -u x", stderr=long_error,
            exit_code=124, error="退出码 124",
        )
        _record_tool_evidence(registry, result, "sqlmap timeout")
        entry = registry.sandbox_log[-1]
        self.assertTrue(entry["spill"], "失败的输出也必须保存")
        self.assertEqual(entry["exit_code"], 124)
        self.assertIn("124", entry["error"])
        # 失败原因与完整输出都能读回
        handle = entry["spill"]["handle"]
        recovered = registry.spill_store().read(handle, limit=MAX_READ_CHARS)
        self.assertTrue(recovered.ok)
        self.assertIn("Traceback", recovered.text)

    def test_scope_refusal_is_recorded_as_evidence(self) -> None:
        """作用域拒绝也是证据：报告里要能看出"这次调用为什么没执行"。"""
        from hexhound.sandbox import ExecResult
        from hexhound.tools import _record_tool_evidence

        registry = self.make_registry()
        result = ExecResult(
            ok=False, command="nmap evil.com",
            error="命令里出现白名单外的主机，已拒绝执行：evil.com",
        )
        _record_tool_evidence(registry, result, "raw")
        entry = registry.sandbox_log[-1]
        self.assertFalse(entry["ok"])
        self.assertIn("evil.com", entry["error"])


class SpillReadToolTests(unittest.TestCase):
    """`spill_read` 工具本身的行为与错误提示。"""

    def make_registry(self) -> ToolRegistry:
        return ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1"}),
            mode="blackbox",
            role="recon",
            surface=AttackSurface(target="http://127.0.0.1:5000"),
        )

    def test_no_handle_and_nothing_stored(self) -> None:
        registry = self.make_registry()
        text = registry.execute("spill_read", {})
        self.assertIn("需要 handle", text)
        self.assertIn("还没有任何输出被压缩保存", text)

    def test_no_handle_lists_available_handles(self) -> None:
        registry = self.make_registry()
        entry = registry.spill("x" * 100)
        text = registry.execute("spill_read", {})
        self.assertIn(entry.handle, text)

    def test_search_mode(self) -> None:
        registry = self.make_registry()
        entry = registry.spill("alpha\nINJECTABLE\nbeta\n")
        text = registry.execute("spill_read", {"handle": entry.handle, "search": "INJECTABLE"})
        self.assertIn("命中 1 处", text)
        self.assertIn("line 2", text)
        self.assertIn("字面量", text)

    def test_search_no_hits_says_literal(self) -> None:
        registry = self.make_registry()
        entry = registry.spill("alpha\nbeta\n")
        text = registry.execute("spill_read", {"handle": entry.handle, "search": "gamma"})
        self.assertIn("没有匹配", text)
        self.assertIn("字面量", text)

    def test_paging_mode_reports_position_and_next_call(self) -> None:
        registry = self.make_registry()
        entry = registry.spill("A" * 30000)
        text = registry.execute("spill_read", {"handle": entry.handle, "offset": 0, "limit": 100})
        self.assertIn("本次返回字符 [0, 100)", text)
        self.assertIn("后面还有", text)
        self.assertIn("offset=100", text)

    def test_unknown_handle_error_is_actionable(self) -> None:
        registry = self.make_registry()
        text = registry.execute("spill_read", {"handle": "SO-" + "b" * 32})
        self.assertIn("未找到", text)
        self.assertIn("只在", text)

    def test_path_argument_cannot_be_used_to_read_files(self) -> None:
        """传路径只当句柄 → 查不到。这个工具没有路径参数。"""
        registry = self.make_registry()
        for candidate in ("/etc/passwd", "C:\\Windows\\win.ini", "../../../etc/shadow"):
            text = registry.execute("spill_read", {"handle": candidate})
            self.assertIn("未找到", text)

    def test_tool_is_available_to_every_role(self) -> None:
        """输出治理是共享基础设施：每个角色都可能产生大输出。"""
        from hexhound.tools import ROLE_TOOLS

        for role, tools in ROLE_TOOLS.items():
            self.assertIn("spill_read", tools, f"角色 {role} 缺少 spill_read")


if __name__ == "__main__":
    unittest.main()
