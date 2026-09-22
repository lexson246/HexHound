"""侦察工具的数据卫生：**展示文本不得被当成数据**。

对应第三轮报告 §6 里记的那条未修项：报告里出现过
`/cart（受保护，值得进一步探测）` 这种带自然语言后缀的假端点。

根因不是"后缀没剥掉"，而是 `_enumerate_common` 把自己**给人看的命中文本**
（`f"{status}  {url}（受保护…）"`）用 `split("  ")[-1]` 反解回 URL——
带内容特征的命中更糟：`[-1]` 取到的是 `特征: <title>…` 整段文字。
展示与数据必须分开。

这里用一个本地临时 HTTP 服务真实跑一遍 `enumerate_common`
（只监听 127.0.0.1，不碰任何真实目标）。
"""
from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path

from werkzeug.serving import make_server

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.surface import AttackSurface, looks_like_url, normalize_endpoint  # noqa: E402
from hexhound.tools import ToolRegistry  # noqa: E402


class _LocalLab:
    """三种命中形态各一个端点 + SPA 式 catch-all（让基线走软 404 分支）。"""

    @classmethod
    def start(cls) -> tuple[object, str]:
        from flask import Flask

        app = Flask("hexhound-enumerate-hygiene")

        @app.route("/admin")
        def admin():
            return "forbidden", 403

        @app.route("/broken")
        def broken():
            return "boom", 500

        @app.route("/<path:anything>")
        def catch_all(anything: str):
            return f"<html><head><title>Page {anything}</title></head><body>spa</body></html>", 200

        server = make_server("127.0.0.1", 0, app)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, f"http://127.0.0.1:{server.server_port}"


class LooksLikeUrlTests(unittest.TestCase):
    """攻面入口的边界防线（根因在调用方已修，这里是第二道）。"""

    def test_rejects_display_suffixes_and_prose(self) -> None:
        for bad in (
            "http://127.0.0.1:5000/admin（受保护，值得进一步探测）",
            "http://127.0.0.1:5000/admin  特征: <title>后台</title>",
            "特征: <title>后台</title>",
            "403  http://127.0.0.1:5000/admin",
            "包含 空格 的路径",
            "",
        ):
            self.assertFalse(looks_like_url(bad), bad)

    def test_accepts_real_urls_and_paths(self) -> None:
        for good in (
            "http://127.0.0.1:5000/admin",
            "https://example.com/a/b?x=1",
            "/api/v1/users",
            "http://127.0.0.1:5000/%E4%B8%AD%E6%96%87",
        ):
            self.assertTrue(looks_like_url(good), good)

    def test_surface_refuses_polluted_endpoints_and_paths(self) -> None:
        surface = AttackSurface(target="http://127.0.0.1:5000", mode="blackbox")
        added = surface.add_endpoints(
            [
                "http://127.0.0.1:5000/admin（受保护，值得进一步探测）",
                "http://127.0.0.1:5000/admin",
            ],
            source="enumerate",
        )
        self.assertEqual(added, 1)
        self.assertEqual(list(surface.endpoints), ["http://127.0.0.1:5000/admin"])
        self.assertEqual(surface.add_extra_paths(["特征: <title>x</title>", "/real"]), 1)
        self.assertEqual(list(surface.extra_paths), ["/real"])

    def test_attempt_key_never_contains_prose(self) -> None:
        surface = AttackSurface(target="http://127.0.0.1:5000", mode="blackbox")
        surface.mark_attempt(
            "http://127.0.0.1:5000/admin（受保护，值得进一步探测）", "enumerate", outcome="signal"
        )
        for key in surface.attempts:
            self.assertEqual(key[0], "", f"非法端点不该产生归一化端点键：{key!r}")
        self.assertEqual(normalize_endpoint("http://127.0.0.1:5000/admin"), "http://127.0.0.1:5000/admin")


class EnumerateCommonHygieneTests(unittest.TestCase):
    """真实跑一遍 enumerate_common，确认端点表里只有真 URL。"""

    server: object = None
    base = ""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server, cls.base = _LocalLab.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()  # type: ignore[attr-defined]

    def run_enumerate(self) -> tuple[str, AttackSurface]:
        surface = AttackSurface(target=self.base, mode="blackbox")
        registry = ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1", "localhost"}),
            timeout=10,
            mode="blackbox",
            surface=surface,
        )
        output = registry.execute(
            "enumerate_common",
            {"base_url": self.base, "tiers": ["admin"], "limit_per_tier": 4},
        )
        return output, surface

    def test_display_text_still_readable(self) -> None:
        """人看的提示要保留（修的是数据，不是可读性）。"""
        output, _surface = self.run_enumerate()
        self.assertIn("受保护，值得进一步探测", output)
        self.assertIn("/admin", output)

    def test_registered_endpoints_are_clean_urls(self) -> None:
        _output, surface = self.run_enumerate()
        endpoints = list(surface.endpoints)
        self.assertTrue(endpoints, "至少应登记到 /admin")
        for endpoint in endpoints:
            self.assertTrue(looks_like_url(endpoint), endpoint)
            self.assertNotIn("（", endpoint)
            self.assertNotIn("受保护", endpoint)
            self.assertNotIn("特征", endpoint)

    def test_extra_paths_and_attempts_are_clean(self) -> None:
        _output, surface = self.run_enumerate()
        for path in surface.extra_paths:
            self.assertTrue(looks_like_url(path), path)
            self.assertNotIn("受保护", path)
        attempt_endpoints = {key[0] for key in surface.attempts}
        self.assertTrue(attempt_endpoints)
        for endpoint in attempt_endpoints:
            self.assertNotIn("受保护", endpoint)
            self.assertNotIn("）", endpoint)

    def test_coverage_table_has_no_prose_suffix(self) -> None:
        """覆盖率表里的 target 必须是真端点——它直接进报告。"""
        _output, surface = self.run_enumerate()
        for entry in surface.coverage_summary():
            target = str(entry.get("target") or "")
            self.assertTrue(looks_like_url(target), target)
            self.assertNotIn("受保护", target)


if __name__ == "__main__":
    unittest.main()
