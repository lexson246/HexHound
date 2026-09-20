"""无 API key 的假 LLM 演示：验证 ReAct 循环与工具链路。

按脚本顺序吐出 JSON，走完 list_files -> read_file -> search_code ->
http_request -> record_finding -> finish 全流程，不需要任何 LLM key。

运行：
    python examples/mock_demo.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from hexhound.agent import ReActAgent
from hexhound.tools import ToolRegistry

VULNLAB_DIR = Path(__file__).resolve().parent.parent / "vulnlab"

# 脚本化的 LLM 输出：每一步都是合法 JSON。
SCRIPT: list[dict] = [
    {
        "thought": "先看看靶场目录里有什么文件。",
        "action": "list_files",
        "action_input": {"path": "."},
    },
    {
        "thought": "读取 app.py 源码，定位可疑点。",
        "action": "read_file",
        "action_input": {"path": "app.py", "start": 1, "end": 120},
    },
    {
        "thought": "用正则搜索 SQL 拼接等可疑模式。",
        "action": "search_code",
        "action_input": {"pattern": r"execute\s*\(|SELECT.*f\"|username\s*="},
    },
    {
        "thought": "用真实请求验证错误型 SQL 注入：单引号触发报错回显。",
        "action": "http_request",
        "action_input": {
            "method": "POST",
            "url": "http://127.0.0.1:5000/login",
            "data": {"username": "'", "password": "x"},
        },
    },
    {
        "thought": "证据成立，记录漏洞。",
        "action": "record_finding",
        "action_input": {
            "title": "/login 错误型 SQL 注入",
            "severity": "high",
            "confidence": "high",
            "evidence": "POST /login username=' 使 SQLite 报错并把错误与完整查询回显（若未启动靶场，该步为连接失败，仅作链路演示）。",
            "description": "用户名/密码直接字符串拼接进 SQL 语句，未参数化，导致错误型 SQL 注入。",
            "remediation": "使用参数化查询（? 占位符）或 ORM，并对输入做校验。",
        },
    },
    {
        "thought": "审计完成，给出总结。",
        "action": "finish",
        "action_input": {
            "summary": "在 vulnlab 靶场中定位并验证了 /login 的错误型 SQL 注入漏洞，已记录 1 个 finding。"
        },
    },
]


def _force_utf8_stdout() -> None:
    """尽量把 stdout/stderr 切成 UTF-8，避免 Windows GBK 控制台因 emoji 崩溃。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except OSError:
                pass


class FakeLLM:
    """按 SCRIPT 顺序吐出 JSON 的假 LLM，complete 接口与 LLMClient 一致。"""

    def __init__(self) -> None:
        self._index = 0

    def complete(self, messages: list[dict]) -> tuple[str, int]:
        if self._index >= len(SCRIPT):
            return (
                json.dumps(
                    {"thought": "脚本已结束", "action": "finish", "action_input": {"summary": "演示结束。"}},
                    ensure_ascii=False,
                ),
                0,
            )
        message = SCRIPT[self._index]
        self._index += 1
        return json.dumps(message, ensure_ascii=False), 0


def main() -> None:
    _force_utf8_stdout()
    if not (VULNLAB_DIR / "app.py").exists():
        print("未找到 vulnlab/app.py，请在项目根目录运行。", file=sys.stderr)
        sys.exit(1)

    registry = ToolRegistry(
        base_dir=VULNLAB_DIR,
        allowed_hosts=frozenset({"127.0.0.1", "localhost"}),
        timeout=5,
    )
    agent = ReActAgent(FakeLLM(), registry, max_steps=20, verbose=True)
    result = agent.run("演示：审计 vulnlab 靶场源码并用黑盒请求验证漏洞。")

    print("\n" + "=" * 48)
    print(f"步数：{len(result.steps)}")
    print(f"漏洞数：{len(result.findings)}")
    for finding in result.findings:
        print(f"  - [{finding['severity']}] {finding['title']}")
    print(f"总结：{result.final_summary}")

    if result.findings:
        print("\n[OK] 演示成功：ReAct 循环与工具链路正常。")
    else:
        print("\n[FAIL] 未记录到漏洞，请检查工具链路。")
        sys.exit(1)


if __name__ == "__main__":
    main()
