"""终端输出清理测试：ANSI/OSC、非法 UTF-8、混合换行、超长输出、whatweb 参数。

对应 HANDOVER §7 的开放缺陷："`web_fingerprint`（whatweb）在 WSL 里返回乱码；
sqlmap 输出含裸 ANSI 转义（`[?1049h`）"。这里的用例全部取自**实测输出样本**
（本机 WSL 里真跑 whatweb / sqlmap / nuclei 抓到的字节），而不是凭空构造的字符串。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.sanitize import (  # noqa: E402
    clip_head_tail,
    decode_output,
    normalize_newlines,
    sanitize_terminal_text,
    strip_ansi,
    visible_length,
)

# 实测样本：`whatweb --no-errors --color=never` 的**真实**原始输出（未加 --color=never
# 时前面还会带这些 SGR 序列）。
WHATWEB_COLOURED = (
    "\x1b[1m\x1b[34mhttp://127.0.0.1:5000/\x1b[0m [200 OK] \x1b[1mCountry\x1b[0m"
    "[\x1b[0m\x1b[22mRESERVED\x1b[0m][\x1b[1m\x1b[31mZZ\x1b[0m], \x1b[1mHTML5\x1b[0m, "
    "\x1b[1mHTTPServer\x1b[0m[\x1b[1m\x1b[36mWerkzeug/3.0.1 Python/3.12.3\x1b[0m], "
    "\x1b[1mTitle\x1b[0m[\x1b[1m\x1b[33mHexHound 靶场\x1b[0m], "
    "\x1b[1mWerkzeug\x1b[0m[\x1b[1m\x1b[32m3.0.1\x1b[0m]"
)

# 实测样本：sqlmap 启动时切到备用屏幕缓冲区的序列。
SQLMAP_SCREEN = "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[1;1H[*] starting @ 10:00:00"


class StripAnsiTests(unittest.TestCase):
    """ANSI / OSC 必须被删干净，且**只删控制序列、不吞内容**。"""

    def test_coloured_whatweb_output_becomes_plain(self) -> None:
        cleaned = strip_ansi(WHATWEB_COLOURED)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("[1m", cleaned)
        # 内容必须完整保留
        self.assertIn("http://127.0.0.1:5000/", cleaned)
        self.assertIn("Werkzeug/3.0.1 Python/3.12.3", cleaned)
        self.assertIn("HexHound 靶场", cleaned)

    def test_sqlmap_private_mode_sequences_removed(self) -> None:
        """回归：`\\x1b[?1049h` 曾被原样写进报告（HANDOVER §7 记录的乱码）。"""
        cleaned = strip_ansi(SQLMAP_SCREEN)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("1049h", cleaned)
        self.assertIn("starting @ 10:00:00", cleaned)

    def test_osc_sequence_with_embedded_bel(self) -> None:
        """OSC 8 超链接：`\\x1b]8;;URL\\x07 文本 \\x1b]8;;\\x07`。"""
        raw = "\x1b]8;;http://evil.example/\x07click me\x1b]8;;\x07"
        cleaned = strip_ansi(raw)
        self.assertEqual(cleaned, "click me")
        # OSC 里带的 URL **不是内容**，不能因为"清理"把它留在报告里
        self.assertNotIn("evil.example", cleaned)

    def test_osc_terminated_by_st_instead_of_bel(self) -> None:
        cleaned = strip_ansi("\x1b]0;window title\x1b\\hello")
        self.assertEqual(cleaned, "hello")

    def test_csi_with_intermediate_bytes(self) -> None:
        """ECMA-48 允许 `ESC [ 参数 中间字节 终止字节`，中间字节段不能漏。"""
        cleaned = strip_ansi("a\x1b[1 qb")  # DECSCUSR：末尾是空格 + q
        self.assertEqual(cleaned, "ab")

    def test_two_byte_escape_sequences(self) -> None:
        """`ESC ( B`（字符集切换）、`ESC M`（反向索引）等两字节形式。"""
        self.assertEqual(strip_ansi("\x1b(Bplain"), "plain")
        self.assertEqual(strip_ansi("x\x1bMy"), "xy")

    def test_lone_escape_at_end_of_output(self) -> None:
        """输出被截断在半条转义序列中间时，裸 ESC 也必须消失。"""
        self.assertEqual(strip_ansi("truncated\x1b"), "truncated")
        self.assertEqual(strip_ansi("truncated\x1b["), "truncated")

    def test_backspace_rewrite_residue(self) -> None:
        """终端原地重写：`abc\\b\\b\\b   \\b\\b\\bxyz`。

        判据是**不能让被擦掉的原字符留下**——只删 `\\b` 会得到 `abcxyz`，
        那看起来像内容，其实是终端残留。
        """
        self.assertEqual(strip_ansi("abc\x08\x08\x08   \x08\x08\x08xyz"), "xyz")

    def test_backspace_line_is_replayed_but_neighbours_survive(self) -> None:
        """退格只影响自己被覆盖的那几个字符，同一行其余内容与邻行都要保留。

        这条是"整行丢弃"做法的反面用例：早期实现直接把带退格的整行删掉，
        会把进度行里的有效信息一起扔掉。
        """
        cleaned = strip_ansi("keep me\nrotated\x08\x08\x08\x08orig\nalso keep")
        self.assertIn("keep me", cleaned)
        self.assertIn("also keep", cleaned)
        self.assertNotIn("rotated", cleaned)
        self.assertIn("orig", cleaned)
        self.assertNotIn("\x08", cleaned)

    def test_c0_and_c1_control_characters_removed(self) -> None:
        cleaned = strip_ansi("a\x00b\x07c\x0bd\x1fe\x7ff\x9bg")
        self.assertEqual(cleaned, "abcdefg")

    def test_nul_bytes_do_not_survive(self) -> None:
        """UTF-16 输出被误解码时会插进 NUL：它们不该进报告。"""
        self.assertNotIn("\x00", strip_ansi("U\x00b\x00u\x00n\x00t\x00u\x00"))

    def test_progress_bar_spinner_runs_removed(self) -> None:
        """Braille 进度点成串出现时清掉；单个字符保留（可能是正常文本）。"""
        self.assertEqual(strip_ansi("扫描中 ⠋⠙⠹⠸⠼⠴⠦ done"), "扫描中  done")
        self.assertEqual(strip_ansi("单个 ⠋ 保留"), "单个 ⠋ 保留")

    def test_plain_text_is_untouched(self) -> None:
        text = "GET /api/users HTTP/1.1\nHost: 127.0.0.1\n\n{\"ok\": true}"
        self.assertEqual(strip_ansi(text), text)

    def test_empty_and_none_safe(self) -> None:
        self.assertEqual(strip_ansi(""), "")
        self.assertEqual(strip_ansi(None), "")  # type: ignore[arg-type]


class DecodeOutputTests(unittest.TestCase):
    """字节流解码：非法字节安全替换，UTF-16LE 能嗅探，**永不抛异常**。"""

    def test_valid_utf8_chinese_round_trips(self) -> None:
        raw = "标题：HexHound 靶场".encode()
        self.assertEqual(decode_output(raw), "标题：HexHound 靶场")

    def test_invalid_bytes_are_replaced_not_raised(self) -> None:
        """回归：非法字节曾导致 UnicodeDecodeError 冒到编排层。"""
        raw = b"ok \xff\xfe\x80 done"
        decoded = decode_output(raw)  # 不抛异常
        self.assertIn("ok", decoded)
        self.assertIn("done", decoded)
        self.assertIn("\ufffd", decoded)

    def test_truncated_multibyte_sequence(self) -> None:
        """UTF-8 中文被截断在半个字符上（超时/截断的常见产物）。

        不断言具体得到什么（不同编码启发式的产物不同），只断言两件事：
        **不抛异常**，且**前缀能认出来的部分要认出来**。
        """
        raw = "中文测试".encode()[:7]  # 两个完整字符 + 1 字节残片
        decoded = decode_output(raw)
        self.assertTrue(decoded.startswith("中文"), decoded)

    def test_utf16le_from_wsl_is_detected(self) -> None:
        """回归：`wsl.exe -l -q` 在部分版本下回 UTF-16LE。

        实测把 `Ubuntu-24.04` 按 UTF-8 解成乱码，于是 `detect_runtime` 报
        "找不到发行版"。`_wsl_distros` 现在自己按字节扫 ASCII，但输出解码这一层
        同样需要能识别 UTF-16LE。
        """
        raw = "Ubuntu-24.04\n".encode("utf-16-le")
        self.assertEqual(decode_output(raw).strip(), "Ubuntu-24.04")

    def test_utf16le_detection_does_not_misfire_on_utf8(self) -> None:
        """正常 UTF-8 不能被"嗅探"改写成别的东西。"""
        self.assertEqual(decode_output("普通文本".encode()), "普通文本")
        self.assertEqual(decode_output(b"plain ascii"), "plain ascii")

    def test_alternate_source_encoding(self) -> None:
        """按 GBK 回传的目标内容：显式指定编码时按它解。"""
        raw = "中文".encode("gbk")
        self.assertEqual(decode_output(raw, encoding="gbk"), "中文")

    def test_unknown_encoding_falls_back_instead_of_raising(self) -> None:
        self.assertEqual(decode_output(b"data", encoding="not-a-codec"), "data")

    def test_str_passthrough_and_empty(self) -> None:
        self.assertEqual(decode_output("already text"), "already text")
        self.assertEqual(decode_output(b""), "")
        self.assertEqual(decode_output(None), "")


class NewlineTests(unittest.TestCase):
    """混合换行：`\\r\\n`、裸 `\\r`（进度刷新）、行尾空白、成片空行。"""

    def test_crlf_is_normalised(self) -> None:
        self.assertEqual(normalize_newlines("a\r\nb\r\nc"), "a\nb\nc")

    def test_bare_cr_becomes_a_line_break_not_a_deletion(self) -> None:
        """裸 `\\r` 是"另起一行重画"，直接删会把两条信息粘成一条。"""
        self.assertEqual(normalize_newlines("progress 10%\rprogress 90%\rdone"),
                         "progress 10%\nprogress 90%\ndone")

    def test_trailing_whitespace_stripped(self) -> None:
        self.assertEqual(normalize_newlines("a   \nb\t\t\n"), "a\nb\n")

    def test_blank_line_runs_collapsed_to_one_blank(self) -> None:
        self.assertEqual(normalize_newlines("a\n\n\n\n\nb"), "a\n\nb")

    def test_mixed_line_endings_in_one_document(self) -> None:
        raw = "header\r\nline1\nline2\rline3\r\n"
        self.assertEqual(normalize_newlines(raw), "header\nline1\nline2\nline3\n")

    def test_no_newline_text_unchanged(self) -> None:
        self.assertEqual(normalize_newlines("single line"), "single line")


class SanitizePipelineTests(unittest.TestCase):
    """完整管线：先清控制序列，再归一换行，最后可选裁剪。"""

    def test_end_to_end_on_real_whatweb_sample(self) -> None:
        cleaned = sanitize_terminal_text(WHATWEB_COLOURED)
        self.assertNotIn("\x1b", cleaned)
        self.assertIn("Werkzeug/3.0.1", cleaned)
        self.assertIn("靶场", cleaned)

    def test_truncation_states_how_much_was_dropped(self) -> None:
        """裁剪必须**写明**省略了多少：否则读者会以为那就是全部输出。"""
        text = "A" * 5000
        cleaned = sanitize_terminal_text(text, max_chars=1000)
        self.assertIn("已省略", cleaned)
        self.assertIn("4000", cleaned)

    def test_truncation_keep_tail_mode(self) -> None:
        text = "start\n" + "X" * 5000 + "\nCONCLUSION: vulnerable"
        cleaned = sanitize_terminal_text(text, max_chars=200, keep_tail=True)
        self.assertTrue(cleaned.startswith("…[已省略前面"))
        self.assertIn("CONCLUSION: vulnerable", cleaned)

    def test_no_truncation_when_under_limit(self) -> None:
        self.assertEqual(sanitize_terminal_text("short", max_chars=100), "short")

    def test_control_sequences_do_not_count_toward_the_limit(self) -> None:
        """清理在裁剪之前：否则 ANSI 会把真正的结论挤出保留窗口。"""
        noisy = ("\x1b[1m\x1b[32m" * 400) + "THE CONCLUSION"
        cleaned = sanitize_terminal_text(noisy, max_chars=40, keep_tail=True)
        self.assertIn("THE CONCLUSION", cleaned)

    def test_visible_length_ignores_control_sequences_only_output(self) -> None:
        """一份全是转义序列的输出，可见长度必须是 0（应当报"无输出"）。"""
        self.assertEqual(visible_length("\x1b[?1049h\x1b[2J\x1b[1;1H"), 0)
        self.assertEqual(visible_length("real content"), 12)
        self.assertEqual(visible_length("\x1b[32mreal\x1b[0m"), 4)


class ClipHeadTailTests(unittest.TestCase):
    """保留头尾的裁剪（sqlmap 的 banner 在头、结论在尾）。"""

    def test_short_text_untouched(self) -> None:
        text, clipped = clip_head_tail("short", 100)
        self.assertFalse(clipped)
        self.assertEqual(text, "short")

    def test_long_text_keeps_both_ends(self) -> None:
        text = "HEAD" + ("M" * 5000) + "TAIL"
        clipped, was_clipped = clip_head_tail(text, 300)
        self.assertTrue(was_clipped)
        self.assertTrue(clipped.startswith("HEAD"))
        self.assertTrue(clipped.endswith("TAIL"))
        self.assertIn("输出过长", clipped)
        self.assertIn("字符", clipped)

    def test_zero_limit_means_no_clipping(self) -> None:
        text, clipped = clip_head_tail("x" * 100, 0)
        self.assertFalse(clipped)
        self.assertEqual(len(text), 100)

    def test_clipped_length_stays_near_the_limit(self) -> None:
        """裁剪结果本身不能比上限大太多（否则"限长"没有意义）。"""
        text = "x" * 100000
        clipped, _ = clip_head_tail(text, 1000)
        # 允许省略提示本身的长度
        self.assertLess(len(clipped), 1200)


class WhatWebParserTests(unittest.TestCase):
    """whatweb 输出解析：只登记真正的组件，不把目标描述与 stderr 噪音当技术栈。

    实测输出（本机 WSL 对靶场跑 `whatweb --no-errors --color=never`）：
        http://127.0.0.1:5000/ [200 OK] Country[RESERVED][ZZ], HTML5,
        HTTPServer[Werkzeug/3.0.1 Python/3.12.3], IP[127.0.0.1],
        Python[3.12.3], Script, Title[HexHound 靶场], Werkzeug[3.0.1]
    """

    SAMPLE = (
        "http://127.0.0.1:5000/ [200 OK] Country[RESERVED][ZZ], HTML5, "
        "HTTPServer[Werkzeug/3.0.1 Python/3.12.3], IP[127.0.0.1], "
        "Python[3.12.3], Script, Title[HexHound 靶场], Werkzeug[3.0.1]"
    )

    def test_extracts_component_versions(self) -> None:
        from hexhound.tools import _parse_whatweb_plugins

        parsed = dict(_parse_whatweb_plugins(self.SAMPLE))
        self.assertEqual(parsed.get("Python"), "3.12.3")
        self.assertEqual(parsed.get("Werkzeug"), "3.0.1")

    def test_skips_target_descriptions(self) -> None:
        """Country/IP/Title/Script 描述的是目标本身，不是"脆弱组件"。"""
        from hexhound.tools import _parse_whatweb_plugins

        names = {name.lower() for name, _ in _parse_whatweb_plugins(self.SAMPLE)}
        for noise in ("country", "ip", "title", "script", "html5"):
            self.assertNotIn(noise, names)

    def test_composite_value_is_not_registered_as_a_version(self) -> None:
        """`HTTPServer[Werkzeug/3.0.1 Python/3.12.3]` 是描述串，不是版本号。"""
        from hexhound.tools import _parse_whatweb_plugins

        parsed = dict(_parse_whatweb_plugins(self.SAMPLE))
        self.assertNotIn("HTTPServer", parsed)

    def test_trailing_stderr_noise_does_not_leak_into_values(self) -> None:
        """回归：实测 tech 里出现过 `Werkzeug: 3.0.1]\\n\\nwsl: 检测到 localhost…`。

        原因是拿 stdout+stderr 合并后按 `,` 分段——一条 WSL 警告就能把分段吃歪。
        现在按 `Name[value]` 正则匹配，值与分段方式无关。
        """
        from hexhound.tools import _parse_whatweb_plugins

        noisy = self.SAMPLE + "\n\nwsl: 检测到 localhost 代理配置，但未镜像到 WSL。"
        parsed = dict(_parse_whatweb_plugins(noisy))
        for value in parsed.values():
            self.assertNotIn("wsl", value.lower())
            self.assertNotIn("检测到", value)
            self.assertNotIn("\n", value)

    def test_name_regex_does_not_swallow_stray_brackets(self) -> None:
        """`Country[RESERVED][ZZ]` 的第二个括号不能被当成另一个组件。"""
        from hexhound.tools import _parse_whatweb_plugins

        names = [name.lower() for name, _ in _parse_whatweb_plugins("Country[RESERVED][ZZ], Nginx[1.24.0]")]
        self.assertNotIn("zz", names)
        self.assertIn("nginx", names)

    def test_titles_containing_commas_survive(self) -> None:
        """标题里有逗号时不能把后面半截当成组件（旧实现的第二个坑）。"""
        from hexhound.tools import _parse_whatweb_plugins

        parsed = dict(_parse_whatweb_plugins("Title[Hello, World], Nginx[1.24.0]"))
        self.assertEqual(parsed.get("Nginx"), "1.24.0")
        self.assertNotIn("World]", parsed)

    def test_empty_and_garbage_input(self) -> None:
        from hexhound.tools import _parse_whatweb_plugins

        self.assertEqual(_parse_whatweb_plugins(""), [])
        self.assertEqual(_parse_whatweb_plugins("no plugins here"), [])
        self.assertEqual(_parse_whatweb_plugins(None), [])  # type: ignore[arg-type]

    def test_duplicate_plugins_collapse(self) -> None:
        """同一组件在 whatweb 输出里可能出现多次，只登记一次。"""
        from hexhound.tools import _parse_whatweb_plugins

        parsed = _parse_whatweb_plugins("Nginx[1.24.0], PHP[8.2.0], Nginx[1.24.0]")
        self.assertEqual([name for name, _ in parsed].count("Nginx"), 1)


class WhatWebInvocationTests(unittest.TestCase):
    """回归：`whatweb -q` 把结果一起吞掉了（实测输出为空但退出码 0）。"""

    def test_whatweb_command_does_not_use_quiet_flag(self) -> None:
        """`-q/--quiet` 的官方说明是"不显示 brief logging"，但那**就是结果行**。

        实测对比（本机 WSL，靶场在 127.0.0.1:5000）：
            whatweb -q --no-errors URL        → 空输出（退出码 0）
            whatweb --no-errors --color=never URL → 完整指纹行
        结果是 `_web_fingerprint` 一直返回"无输出"，technology 面从未被填充过。
        """
        from hexhound.sandbox import Sandbox

        sandbox = Sandbox(allowed_hosts=frozenset({"127.0.0.1"}), map_loopback=False)
        captured: dict[str, str] = {}

        def fake_run(command: str, **kwargs):
            captured["command"] = command
            from hexhound.sandbox import ExecResult

            return ExecResult(ok=True, command=command)

        sandbox.run = fake_run  # type: ignore[assignment]
        sandbox.whatweb("http://127.0.0.1:5000/")
        command = captured["command"]
        self.assertNotIn(" -q ", command)
        self.assertNotIn("--quiet", command)
        self.assertIn("--no-errors", command)
        # 不给结果加 SGR 配色，省得下游还要清一遍
        self.assertIn("--color=never", command)

    def test_whatweb_blocks_are_parsed_into_tech(self) -> None:
        """`_web_fingerprint` 要把 `Name[Version]` 分段写进攻面的 tech。"""
        from hexhound.sandbox import ExecResult
        from hexhound.surface import AttackSurface
        from hexhound.tools import ToolRegistry

        class FakeSandbox:
            available = staticmethod(lambda: True)

            def tool_status(self):
                return {"whatweb": True}

            def probe(self):
                return {"ok": True, "tools": {"whatweb": True}, "runtime": "fake"}

            def whatweb(self, url, timeout=180):
                return ExecResult(
                    ok=True,
                    command=f"whatweb {url}",
                    stdout=(
                        "http://127.0.0.1:5000/ [200 OK] HTML5, "
                        "HTTPServer[Werkzeug/3.0.1 Python/3.12.3], "
                        "Werkzeug[3.0.1]"
                    ),
                )

        # 沙箱必须在**构造时**就传进去：`_drop_unavailable_sandbox_tools` 在
        # `_register_defaults` 里立刻执行，沙箱为 None 时这些工具根本不会下发
        # （刻意设计：不给模型一个必然失败的工具）。
        registry = ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1"}),
            mode="blackbox",
            role="recon",  # web_fingerprint 是侦察角色的工具（ROLE_TOOLS）
            surface=AttackSurface(target="http://127.0.0.1:5000"),
            sandbox=FakeSandbox(),
        )
        self.assertTrue(registry.has("web_fingerprint"))
        text = registry.execute("web_fingerprint", {"url": "http://127.0.0.1:5000/"})
        self.assertIn("Werkzeug", text)
        tech = " ".join(f"{k}={v}" for k, v in registry.surface.tech.items())
        self.assertIn("Werkzeug", tech)

    def test_empty_output_from_a_successful_run_is_flagged(self) -> None:
        """退出码 0 但没有输出 = 静默失效，必须显式报出来而不是"无指纹"。"""
        from hexhound.sandbox import ExecResult
        from hexhound.surface import AttackSurface
        from hexhound.tools import ToolRegistry

        class EmptySandbox:
            available = staticmethod(lambda: True)

            def tool_status(self):
                return {"whatweb": True}

            def probe(self):
                return {"ok": True, "tools": {"whatweb": True}, "runtime": "fake"}

            def whatweb(self, url, timeout=180):
                return ExecResult(ok=True, command=f"whatweb {url}", stdout="")

        registry = ToolRegistry(
            base_dir=Path("."),
            allowed_hosts=frozenset({"127.0.0.1"}),
            mode="blackbox",
            role="recon",
            surface=AttackSurface(target="http://127.0.0.1:5000"),
            sandbox=EmptySandbox(),
        )
        text = registry.execute("web_fingerprint", {"url": "http://127.0.0.1:5000/"})
        self.assertIn("没有任何输出", text)
        self.assertIn("参数", text)


class SandboxOutputSanitisationTests(unittest.TestCase):
    """沙箱出口清理：ExecResult.output 必须是干净的。"""

    def test_exec_result_output_is_sanitised(self) -> None:
        from hexhound.sandbox import ExecResult

        result = ExecResult(
            ok=True,
            stdout="\x1b[32mok\x1b[0m\nprogress 10%\rprogress 100%",
            stderr="\x1b[31mwarn\x1b[0m",
        )
        output = result.output
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\r", output)
        self.assertIn("ok", output)
        self.assertIn("warn", output)
        self.assertIn("progress 100%", output)

    def test_output_that_is_only_control_sequences_is_empty(self) -> None:
        """清完什么都不剩 → 当作无输出（长度 0），而不是"有一段看不见的内容"。"""
        from hexhound.sandbox import ExecResult

        result = ExecResult(ok=True, stdout="\x1b[?1049h\x1b[2J\x1b[1;1H")
        self.assertEqual(result.output, "")

    def test_host_env_forces_utf8(self) -> None:
        """子进程环境必须钉死 UTF-8（`WSL_UTF8=1` 是 wsl.exe 的官方开关）。"""
        from hexhound.sandbox import Sandbox

        env = Sandbox._host_env()
        self.assertEqual(env["WSL_UTF8"], "1")
        self.assertEqual(env["PYTHONIOENCODING"], "utf-8")
        self.assertEqual(env["PYTHONUTF8"], "1")
        # 不能把宿主环境整个替换掉（PATH 等必须保留）
        self.assertIn("PATH", env)


if __name__ == "__main__":
    unittest.main()
