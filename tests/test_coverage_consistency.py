"""覆盖记录与实测信号的一致性闸门。

实测事故（`docs/EVAL.md` §4.1 第 1 条，第 2 轮 live 评测）：靶场 `/reflect` 的
xss 尝试在攻面里已记录 **3 条 `signal`**（"payload 原样回显（未转义）"），
而模型写的覆盖记录是 `no_issue_found`，它的 detail 里恰恰写着
"`<script>alert(1)</script>` 与 `<img src=x onerror=alert(1)>` 均原样落进响应体"。
报告于是同时说"测到反射"和"测过没问题"，而读者只会看到后者——
**一条自相矛盾的记录**把实测证据洗成了"无问题"。

闸门的设计：写 `no_issue_found`/`ruled_out` 时，如果该对象上已有 signal，
**拒绝记录**并给出两条出路（记成候选/finding，或带 `dismiss_signals` 说明为什么不算）。
从 target 里认不出端点时不拦——宁可漏拦，也不靠猜去否定模型的结论。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.surface import AttackSurface, target_paths  # noqa: E402
from hexhound.tools import ToolRegistry  # noqa: E402


def make_registry(surface: AttackSurface) -> ToolRegistry:
    return ToolRegistry(
        base_dir=Path("."),
        allowed_hosts=frozenset({"127.0.0.1", "localhost"}),
        timeout=5,
        mode="blackbox",
        surface=surface,
    )


class TargetPathsTests(unittest.TestCase):
    """自由文本 → 路径：抽不出来就返回空集，绝不猜。"""

    def test_extracts_paths_from_human_text(self) -> None:
        for text, expected in (
            ("http://127.0.0.1:5000/api/order（参数 order_id）", {"/api/order"}),
            ("POST /order/confirm", {"/order/confirm"}),
            ("/login 表单 username 参数", {"/login"}),
            ("http://127.0.0.1:5000/reflect?name=1", {"/reflect"}),
            ("/api/order、/api/users", {"/api/order", "/api/users"}),
        ):
            with self.subTest(text=text):
                self.assertEqual(target_paths(text), expected)

    def test_prose_without_paths_returns_empty(self) -> None:
        for text in ("认证与未授权访问", "子任务 T2（auth）", "", "测试过登录接口"):
            with self.subTest(text=text):
                self.assertEqual(target_paths(text), set())

    def test_numeric_segments_are_folded(self) -> None:
        """`/order/1001` 与 `/order/1002` 是同一条路径（与攻面归一化一致）。"""
        self.assertEqual(target_paths("/order/1001"), target_paths("/order/1002"))

    def test_full_width_colon_in_an_objective_does_not_crash(self) -> None:
        """真实事故：任务目标写成 `http://host：crawl 首页`（全角冒号进了 netloc），
        `urlparse` 直接抛 ValueError，`_finalise_coverage` 于是崩掉整轮运行。

        取值函数不该能炸掉一轮审计——现在砍掉"人话尾巴"后返回可用路径。
        """
        from hexhound.surface import normalize_path

        self.assertEqual(normalize_path("http://hexhound-test.invalid：crawl 首页"), "/")
        self.assertEqual(
            normalize_path("http://hexhound-test.invalid：crawl /api/order"), "/"
        )
        # 同一个字符串里的**另一个**真路径仍要被抽出来
        self.assertIn("/api/order", target_paths("侦察 http://host：crawl /api/order 的越权"))

    def test_looks_like_url_rejects_the_same_prose(self) -> None:
        from hexhound.surface import looks_like_url

        self.assertFalse(looks_like_url("http://hexhound-test.invalid：crawl"))


class CoverageSignalConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.surface = AttackSurface(target="http://127.0.0.1:5000", mode="blackbox")
        self.registry = make_registry(self.surface)
        self.surface.mark_attempt(
            "http://127.0.0.1:5000/reflect",
            "xss",
            param="name",
            payload="<script>alert(1)</script>",
            outcome="signal",
            detail="payload 原样回显（未转义），疑似反射型 XSS",
        )

    def test_no_issue_found_is_refused_while_a_signal_exists(self) -> None:
        out = self.registry.execute("record_coverage", {
            "target": "http://127.0.0.1:5000/reflect（参数 name）",
            "status": "no_issue_found",
            "detail": "payload 原样落进响应体 <h1>，未做 HTML 转义",
        })
        self.assertIn("实测信号", out)
        self.assertIn("dismiss_signals", out)
        # 关键：**没有**把这条自相矛盾的记录写进攻面
        self.assertEqual(self.surface.coverage_summary(), {})

    def test_ruled_out_is_refused_too(self) -> None:
        out = self.registry.execute("record_coverage", {
            "target": "/reflect", "status": "ruled_out", "detail": "只是回显",
        })
        self.assertIn("实测信号", out)
        self.assertEqual(self.surface.coverage_summary(), {})

    def test_explicit_dismissal_is_accepted_and_stored(self) -> None:
        out = self.registry.execute("record_coverage", {
            "target": "/reflect",
            "status": "no_issue_found",
            "detail": "回显进了 <textarea>，浏览器不会执行",
            "dismiss_signals": "仅字符串回显，CSP 禁止内联脚本，未验证可执行性",
        })
        self.assertIn("已记录覆盖", out)
        self.assertEqual(self.surface.coverage_summary().get("no_issue_found"), 1)
        entry = next(iter(self.surface.coverage.values()))
        self.assertIn("CSP", str(entry.get("dismissed")))
        # 排除理由要出现在报告用的覆盖行里，别只躺在 JSON 里
        self.assertIn("已复核信号后排除", " ".join(self.surface.coverage_lines()))

    def test_reported_finding_is_never_blocked(self) -> None:
        out = self.registry.execute("record_coverage", {
            "target": "/reflect", "status": "reported", "detail": "反射型 XSS",
        })
        self.assertIn("已记录覆盖", out)

    def test_other_endpoints_are_not_affected(self) -> None:
        out = self.registry.execute("record_coverage", {
            "target": "/login", "status": "no_issue_found", "detail": "注入未成立",
        })
        self.assertIn("已记录覆盖", out)

    def test_prose_target_cannot_be_guessed_so_it_is_not_blocked(self) -> None:
        """target 里没有路径（"认证与未授权访问"）时拦不住——如实记录，不靠猜。"""
        out = self.registry.execute("record_coverage", {
            "target": "认证与未授权访问", "status": "no_issue_found", "detail": "无问题",
        })
        self.assertIn("已记录覆盖", out)

    def test_no_signal_no_gate(self) -> None:
        surface = AttackSurface(target="http://127.0.0.1:5000", mode="blackbox")
        surface.mark_attempt(
            "http://127.0.0.1:5000/reflect", "xss", param="name", outcome="no_signal",
            detail="payload 被转义",
        )
        registry = make_registry(surface)
        out = registry.execute("record_coverage", {
            "target": "/reflect", "status": "no_issue_found", "detail": "转义了",
        })
        self.assertIn("已记录覆盖", out)

    def test_blocked_or_errored_attempts_do_not_gate(self) -> None:
        """被限流/请求失败不算"实测到信号"——否则限流反而会禁止写结论。"""
        surface = AttackSurface(target="http://127.0.0.1:5000", mode="blackbox")
        for outcome in ("blocked", "error"):
            surface.mark_attempt(
                "http://127.0.0.1:5000/reflect", "xss", param="name", outcome=outcome,
            )
        out = make_registry(surface).execute("record_coverage", {
            "target": "/reflect", "status": "no_issue_found", "detail": "没测成",
        })
        self.assertIn("已记录覆盖", out)


if __name__ == "__main__":
    unittest.main()
