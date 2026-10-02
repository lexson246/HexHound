"""请求体与身份维度回归（用户点名的三项验收之一）。

原始故障（外部代码评审 P4/P3）：`fuzz_params` 只会拼 query / form，于是

- **JSON 接口完全测不到**：`{"username": "..."}` 这种请求体注入不了 payload，
  返回的"无信号"被当成"测过没问题"；
- **PUT / PATCH 被降级成 GET**：改了状态的接口反而没被测；
- **身份维度不进指纹**：匿名访问拿到 401 记成 no_signal 之后，
  换成登录态重测会被去重逻辑直接跳过（"这个参数已经试过了"）——
  用户看到的 `sqlmap` 误报与"登录后链条断"都是同一类问题的表亲。

这里用一个**本地回环 HTTP 服务**真实跑一遍（只监听 127.0.0.1，不碰真实目标），
逐条断言服务端**真的收到了**什么请求体/方法，而不是只看工具自己的文字说明。
"""
from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.surface import AttackSurface  # noqa: E402
from hexhound.tools import ToolRegistry  # noqa: E402

#: 服务端记录到的每一次请求：方法 / 路径 / Content-Type / 原始请求体
RECEIVED: list[dict[str, str]] = []


class _EchoHandler(BaseHTTPRequestHandler):
    """把收到的请求原样记下来，并对注入 payload 给出"可疑"响应。

    响应里带上 SQL 报错特征：fuzz 判定需要看到信号，否则用例只能验"发没发出去"，
    验不了"发出去之后有没有被认成信号"。
    """

    def _handle(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        RECEIVED.append({
            "method": method,
            "path": urlsplit(self.path).path,
            "query": urlsplit(self.path).query,
            "content_type": str(self.headers.get("Content-Type") or ""),
            "body": raw,
            "cookie": str(self.headers.get("Cookie") or ""),
        })
        path = urlsplit(self.path).path
        cookie = str(self.headers.get("Cookie") or "")
        if path.startswith("/protected") and not cookie:
            # 未登录：401（"被访问控制阻断"，不算测过）
            body, code = "login required", 401
        elif "'" in raw or "%27" in self.path or "'" in self.path or "1=1" in raw:
            body = "You have an error in your SQL syntax near '''"
            code = 500
        else:
            body, code = '{"ok":true}', 200
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 标准库回调名
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._handle("PUT")

    def do_PATCH(self) -> None:  # noqa: N802
        self._handle("PATCH")

    def log_message(self, *args) -> None:  # noqa: D102 静音
        return


class RequestBodyTests(unittest.TestCase):
    server: ThreadingHTTPServer
    base = ""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _EchoHandler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()

    def setUp(self) -> None:
        RECEIVED.clear()
        self.surface = AttackSurface(target=self.base, mode="blackbox")
        self.registry = ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1", "localhost"}),
            timeout=10,
            mode="blackbox",
            surface=self.surface,
        )

    def last(self, **match: str) -> dict[str, str]:
        for entry in reversed(RECEIVED):
            if all(entry.get(key) == value for key, value in match.items()):
                return entry
        self.fail(f"服务端没有收到匹配 {match} 的请求；实际收到：{RECEIVED}")

    # ---------- JSON 请求体 ----------

    def test_http_request_sends_a_real_json_body(self) -> None:
        self.registry.execute("http_request", {
            "method": "POST", "url": f"{self.base}/api/login",
            "json": {"username": "alice", "password": "pw"},
        })
        entry = self.last(method="POST", path="/api/login")
        self.assertIn("application/json", entry["content_type"])
        self.assertEqual(json.loads(entry["body"]), {"username": "alice", "password": "pw"})

    def test_fuzz_params_injects_into_a_json_body(self) -> None:
        """JSON 体里的参数必须真的被 payload 替换——不是只在 query 上加一个同名参数。"""
        output = self.registry.execute("fuzz_params", {
            "url": f"{self.base}/api/login", "method": "POST",
            "json": {"username": "alice"}, "location": "json",
            "params": {"username": "alice"}, "categories": ["sqli"],
            "per_category": 2,
        })
        self.assertFalse(output.startswith("错误"), output)
        bodies = [json.loads(item["body"]) for item in RECEIVED if item["path"] == "/api/login"]
        self.assertTrue(bodies, f"JSON 体没有被发出去：{RECEIVED}")
        self.assertTrue(
            any("'" in str(body.get("username", "")) or "1=1" in str(body.get("username", ""))
                for body in bodies),
            f"注入 payload 没有进入 JSON 请求体：{bodies}",
        )
        for item in RECEIVED:
            if item["path"] == "/api/login" and item["method"] == "POST":
                self.assertIn("application/json", item["content_type"])
                break
        else:
            self.fail("没有发生 JSON POST 请求")

    # ---------- PUT / PATCH ----------

    def test_fuzz_params_keeps_put_and_patch_methods(self) -> None:
        for method in ("PUT", "PATCH"):
            with self.subTest(method=method):
                RECEIVED.clear()
                output = self.registry.execute("fuzz_params", {
                    "url": f"{self.base}/api/user/1", "method": method,
                    "json": {"nickname": "alice"}, "location": "json",
                    "params": {"nickname": "alice"}, "categories": ["sqli"], "per_category": 2,
                })
                self.assertFalse(output.startswith("错误"), output)
                entry = self.last(method=method, path="/api/user/1")
                self.assertIn("nickname", entry["body"])

    # ---------- 身份维度 ----------

    def test_attempt_fingerprint_separates_identities_and_methods(self) -> None:
        """去重键必须带身份/方法/位置：否则"匿名 401"会吃掉"登录后重测"。"""
        anon = AttackSurface.attempt_key(f"{self.base}/p", "id", "sqli", "'", account="")
        authed = AttackSurface.attempt_key(f"{self.base}/p", "id", "sqli", "'", account="cookie-hash")
        self.assertNotEqual(anon, authed)
        get_key = AttackSurface.attempt_key(f"{self.base}/p", "id", "sqli", "'", method="GET")
        put_key = AttackSurface.attempt_key(f"{self.base}/p", "id", "sqli", "'", method="PUT")
        self.assertNotEqual(get_key, put_key)
        body_key = AttackSurface.attempt_key(f"{self.base}/p", "id", "sqli", "'", location="json")
        self.assertNotEqual(get_key, body_key)

    def test_anonymous_no_signal_does_not_block_an_authenticated_retest(self) -> None:
        """两种"未成功"的语义必须分开（这正是登录后链条断掉的根因）：

        - `no_signal`：真的测过了，同一身份不必重发 → 跳过；
        - `blocked`（401/403）：**根本没能测**，任何身份都必须允许重测。
        """
        target = f"{self.base}/protected/orders"
        self.surface.mark_attempt(
            target, "sqli", param="id", payload="'", outcome="no_signal", account="",
        )
        self.assertTrue(self.surface.is_tried(target, "sqli", "id", "'", account=""))
        self.assertFalse(
            self.surface.is_tried(target, "sqli", "id", "'", account="session-b"),
            "换了身份必须算没试过——否则登录后重测会被去重逻辑吞掉",
        )

        blocked_target = f"{self.base}/protected/profile"
        self.surface.mark_attempt(
            blocked_target, "sqli", param="id", payload="'", outcome="blocked", account="",
        )
        for account in ("", "session-b"):
            self.assertFalse(
                self.surface.is_tried(blocked_target, "sqli", "id", "'", account=account),
                "401/403 不算测过——登录后必须允许重测",
            )

    def test_fuzz_params_retests_with_a_session_after_an_anonymous_attempt(self) -> None:
        """端到端：匿名跑一遍（401）→ 带会话再跑一遍，第二次必须真的发出去。"""
        url = f"{self.base}/protected/orders"
        first = self.registry.execute("fuzz_params", {
            "url": url, "params": {"id": "1"}, "categories": ["sqli"], "per_category": 1,
        })
        # 被访问控制阻断：结论必须写"未完成"，不能写成"无信号"
        self.assertIn("阻断", first)
        self.assertIn("不能据此排除漏洞", first)
        anon_calls = [item for item in RECEIVED if item["path"] == "/protected/orders"]
        self.assertTrue(anon_calls, first)
        self.assertTrue(all(not item["cookie"] for item in anon_calls))

        second = self.registry.execute("fuzz_params", {
            "url": url, "params": {"id": "1"}, "categories": ["sqli"], "per_category": 1,
            "headers": {"Cookie": "session=alice"},
        })
        calls = [item for item in RECEIVED if item["path"] == "/protected/orders"]
        authed = [item for item in calls if item["cookie"]]
        self.assertTrue(authed, f"带会话的重测没有真的发出去：{second}\n{RECEIVED}")


if __name__ == "__main__":
    unittest.main()
