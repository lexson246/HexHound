"""作用域两种模式：白名单（默认）与**不限制主机**（`ALLOWED_HOSTS=*`）。

为什么要有这个模式而不是把白名单删掉：
作用域校验在 10 处生效（工具、浏览器、截图、沙箱命令与脚本、CLI、GUI），
沙箱里还有一层**进程内 DNS/socket 拦截**（拼接域名也绕不过）。
删掉机制 = 同时失去"限制"与"能限制"的能力；留一个显式开关，既不用维护列表，
需要时又能一键收紧。

这些用例钉住两件事：
1. 白名单模式**行为不变**（这是原有的安全不变量，不能被这次改动削弱）；
2. 不限制模式下所有入口都放行——**一处漏掉就会出现"设了不限制、某个入口仍拒绝"**。
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(TESTS))

from hexhound.config import (  # noqa: E402
    ANY_HOST,
    _normalize_host,
    scope_allows,
    scope_unrestricted,
)
from hexhound.sandbox import _SCRIPT_GUARD  # noqa: E402
from hexhound.surface import AttackSurface  # noqa: E402
from hexhound.tools import validate_url_against  # noqa: E402

LIST = frozenset({"127.0.0.1", "localhost"})
OPEN = frozenset({ANY_HOST})


class ScopePredicateTests(unittest.TestCase):
    def test_sentinel_survives_host_normalization(self) -> None:
        """`*` 必须原样活下来：被 URL 解析吃掉就会静默退化成"什么都不允许"。"""
        self.assertEqual(_normalize_host("*"), ANY_HOST)
        self.assertEqual(_normalize_host(" * "), ANY_HOST)
        self.assertEqual(_normalize_host("any"), ANY_HOST)

    def test_list_mode_is_unchanged(self) -> None:
        self.assertTrue(scope_allows(LIST, "localhost"))
        self.assertTrue(scope_allows(LIST, "127.0.0.1"))
        self.assertFalse(scope_allows(LIST, "evil.example.com"))
        self.assertFalse(scope_unrestricted(LIST))

    def test_open_mode_allows_anything(self) -> None:
        for host in ("evil.example.com", "8.8.8.8", "169.254.169.254", "anything"):
            self.assertTrue(scope_allows(OPEN, host), host)
        self.assertTrue(scope_unrestricted(OPEN))

    def test_empty_scope_allows_nothing(self) -> None:
        """空集合 ≠ 不限制：没配置时必须仍然拒绝（默认安全方向）。"""
        self.assertFalse(scope_allows(frozenset(), "evil.example.com"))
        self.assertFalse(scope_unrestricted(frozenset()))


class ToolScopeTests(unittest.TestCase):
    """工具层是主入口：一处漏掉，模型就会看到"设了不限制但工具全拒"。"""

    def test_list_mode_refuses_outside_hosts(self) -> None:
        _parsed, error = validate_url_against("http://evil.example.com/", LIST)
        self.assertIsNotNone(error)
        self.assertIn("不在白名单", error or "")

    def test_open_mode_allows_outside_hosts(self) -> None:
        parsed, error = validate_url_against("http://evil.example.com/a?b=1", OPEN)
        self.assertIsNone(error)
        self.assertEqual(parsed.hostname, "evil.example.com")

    def test_open_mode_still_restricts_scheme(self) -> None:
        """不限制主机 ≠ 什么协议都行：file:/data: 仍然拒绝（沙箱边界不在白名单里）。"""
        for url in ("file:///etc/passwd", "data:text/html,<script>x</script>"):
            _parsed, error = validate_url_against(url, OPEN)
            self.assertIsNotNone(error, url)


class SandboxGuardTests(unittest.TestCase):
    """沙箱脚本的运行时护栏：把 `*` 当普通主机名传进去会拒绝一切。"""

    def _check(self, allow: list[str], host: str) -> bool:
        namespace: dict = {}
        exec(_SCRIPT_GUARD.format(allow=allow), namespace)  # noqa: S102 测的就是这段护栏
        try:
            namespace["_check"](host)
            return True
        except RuntimeError:
            return False

    def test_open_mode_guard_lets_everything_through(self) -> None:
        self.assertTrue(self._check(["*"], "evil.example.com"))
        self.assertTrue(self._check(["*"], "127.0.0.1"))

    def test_list_mode_guard_still_blocks(self) -> None:
        self.assertTrue(self._check(["127.0.0.1", "localhost"], "localhost"))
        self.assertFalse(self._check(["127.0.0.1", "localhost"], "evil.example.com"))


class SurfaceScopeRecordTests(unittest.TestCase):
    """范围要跟着攻面落盘：否则离线重渲染的报告会把"没限制"说成"限定过范围"。"""

    def test_scope_is_persisted_and_restored(self, tmp_path: Path | None = None) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "surface.json"
            surface = AttackSurface(target="https://x.test", allowed_hosts=OPEN)
            surface.save(path)
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["allowed_hosts"], ["*"])
            restored = AttackSurface.load(path, target="https://x.test")
            self.assertEqual(restored.allowed_hosts, ("*",))
            self.assertTrue(scope_unrestricted(restored.allowed_hosts))

    def test_legacy_surface_without_scope_keeps_caller_value(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "surface.json"
            path.write_text(json.dumps({"target": "https://x.test", "endpoints": []}), encoding="utf-8")
            restored = AttackSurface.load(path, target="https://x.test", allowed_hosts=LIST)
            self.assertEqual(set(restored.allowed_hosts), set(LIST))

    def test_report_states_the_scope(self) -> None:
        from hexhound.agent import AgentResult
        from hexhound.report import _scope_line

        open_result = AgentResult()
        open_result.surface = AttackSurface(target="https://x.test", allowed_hosts=OPEN)
        self.assertIn("不限制主机", _scope_line(open_result))
        self.assertIn("任何主机都可能被访问", _scope_line(open_result))

        list_result = AgentResult()
        list_result.surface = AttackSurface(target="https://x.test", allowed_hosts={"a.com"})
        self.assertIn("ALLOWED_HOSTS", _scope_line(list_result))
        self.assertNotIn("不限制", _scope_line(list_result))


if __name__ == "__main__":
    unittest.main()
