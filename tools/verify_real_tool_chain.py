"""真工具链路端到端验证（零模型额度）：桌面/CLI 的下发路径真的能用真工具。

用法（在仓库根目录）：
    python tools/verify_real_tool_chain.py
前置：WSL 靶场已启动 —— wsl -d Ubuntu-24.04 -- bash tools/start_lab_in_wsl.sh 5000

用户在真实运行里看到的是"模型一直报未知工具"。单元测试证明的是"参数传下去了"，
这里再往前一步：用**真沙箱**（WSL）构建注入角色的注册表，跑真工具，
断言 (1) 工具集里确实有真工具、(2) 调用真的执行成功、(3) 失败统计里没有
"未下发的工具"、(4) 提示词里没有缺失工具清单。

靶场跑在 WSL 里（127.0.0.1:5000），沙箱也在 WSL 里执行，所以 map_loopback=False。
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hexhound.prompts import (  # noqa: E402 路径先注入 sys.path（见上）
    MISSING_TOOLS_NOTE,
    adapt_prompt_to_tools,
    build_system_prompt,
)
from hexhound.sandbox import prepare_sandbox, sandbox_report  # noqa: E402
from hexhound.surface import AttackSurface  # noqa: E402
from hexhound.tools import BROWSER_TOOLS, SANDBOX_TOOLS, ToolRegistry  # noqa: E402

TARGET = "http://127.0.0.1:5000"
FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


def main() -> int:
    setup = prepare_sandbox(["127.0.0.1", "localhost"], map_loopback=False)
    check("prepare_sandbox 判定可用", setup.ok, setup.message())
    if not setup.ok:
        return 1
    print("     工具：", ", ".join(setup.tools))

    surface = AttackSurface(target=TARGET, mode="blackbox", path=Path(".tmp/e2e-surface.json"))
    registry = ToolRegistry(
        base_dir=Path("."),
        allowed_hosts=frozenset({"127.0.0.1", "localhost"}),
        timeout=15,
        mode="blackbox",
        surface=surface,
        role="injection",
        worker_id="E2E",
        sandbox=setup.sandbox,
        artifacts=None,
    )
    names = set(registry.tool_names())
    for tool in ("sqlmap_scan", "template_scan", "sandbox_script", "raw_command"):
        check(f"注入角色持有 {tool}", tool in names)

    # ---- 真工具调用 1：sqlmap（靶场 /login 是错误型 SQL 注入）----
    out = registry.execute("sqlmap_scan", {
        "url": f"{TARGET}/login?username=admin&password=x", "timeout": 240,
    })
    check("sqlmap_scan 真的跑起来了", "sqlmap 结果" in out or "sqlmap" in out.lower(), out.splitlines()[0][:120])
    check("sqlmap_scan 未报未知工具", "未知工具" not in out)
    check("sqlmap_scan 给出证据编号", "[E2E-T" in out, out.strip().splitlines()[0][:80])

    # ---- 真工具调用 2：自定义脚本（竞态/多步只能靠它）----
    out = registry.execute("sandbox_script", {
        "purpose": "自定义脚本：确认沙箱内真的能发 HTTP 请求",
        "script": (
            "import urllib.request\n"
            "with urllib.request.urlopen('http://127.0.0.1:5000/', timeout=5) as r:\n"
            "    print('status', r.status)\n"
        ),
        "timeout": 90,
    })
    check("sandbox_script 执行成功", "status 200" in out, out.strip().splitlines()[0][:120])
    check("sandbox_script 未报未知工具", "未知工具" not in out)

    # ---- 真工具调用 3：原始命令（nmap 快速扫本机端口）----
    out = registry.execute("raw_command", {
        "command": "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:5000/", "timeout": 60,
    })
    check("raw_command 未报未知工具", "未知工具" not in out, out.strip()[:80])

    stats = registry.tool_failure_stats()
    check("失败统计里没有'未下发的工具'", not stats.get("unknown"), str(stats))
    check("失败统计里没有'工具内部异常'", not stats.get("crashed"), str(stats))
    print("     统计：", stats)

    # ---- 提示词里不应出现缺失工具清单（工具齐备时）----
    system = adapt_prompt_to_tools(
        build_system_prompt(registry.describe(), "blackbox", "injection"),
        registry.tool_names(), (*SANDBOX_TOOLS, *BROWSER_TOOLS),
    )
    check("提示词无缺失工具清单", MISSING_TOOLS_NOTE not in system)
    check("提示词广告了 sqlmap_scan", "sqlmap_scan" in system)

    # ---- 降级路径：原因必须具体 ----
    report = sandbox_report(None, reason=setup.reason or "环境探测失败（模拟）", hint="hexhound sandbox install")
    check("未启用时记录具体原因", "本次运行未启用容器沙箱" != report["reason"], report["reason"])

    print()
    if FAILURES:
        print(f"端到端验证未通过：{len(FAILURES)} 项 —— " + "；".join(FAILURES))
        return 1
    print("端到端验证通过：真工具链路可用，无未知工具、无工具异常。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
