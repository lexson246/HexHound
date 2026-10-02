"""多代理编排 + 真工具端到端验证（零模型额度）。

用法（在仓库根目录；靶场需先启动）：
    wsl -d Ubuntu-24.04 -- bash tools/start_lab_in_wsl.sh 5000
    python tools/verify_swarm_with_real_tools.py

与 `tools/verify_real_tool_chain.py` 的分工：那个只验证"注册表能不能跑真工具"，
这个再往上一层——**走真实编排**（规划 → 并发子代理 → 波次 → 复核 → 报告），
并让脚本 LLM 的注入角色**主动调用真工具**，于是能回答：

1. 运行记录里沙箱是不是真的启用了（不再是那句"本次运行未启用容器沙箱"）；
2. 波次/补扫任务（role=injection）**真的执行了** sqlmap 这类真工具；
3. 全程有没有"未下发的工具"或工具异常（`tool_failures`）；
4. 报告里"真工具沙箱"这一行是否如实写成已启用。

产物写到 `.tmp/swarm-verify-home`（`HEXHOUND_HOME`），不污染真实运行历史。
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hexhound.budget import Budget, BudgetLimits  # noqa: E402
from hexhound.memory import HostMemory, RunArtifacts  # noqa: E402
from hexhound.mockllm import ScriptedLLM  # noqa: E402
from hexhound.orchestrator import Orchestrator, SwarmCallbacks  # noqa: E402
from hexhound.report import to_markdown  # noqa: E402
from hexhound.sandbox import prepare_sandbox  # noqa: E402
from hexhound.surface import AttackSurface  # noqa: E402

TARGET = os.getenv("VERIFY_TARGET", "http://127.0.0.1:5000")
GOAL = f"对 {TARGET} 做黑盒安全评估（仅限授权 scope），只记录有真实请求证据的漏洞。"
HOME = ROOT / ".tmp" / "swarm-verify-home"
FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"[{'OK' if ok else 'FAIL'}] {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


class RealToolLLM(ScriptedLLM):
    """脚本 LLM + 真工具剧本：注入角色第一件事就是上 sqlmap。

    为什么不能用默认剧本验证这件事：`ScriptedLLM` 只会调内置 HTTP 工具，
    真工具调用是否被正确下发（P1）在编排层面就验证不到。
    """

    def _injection_next(self, messages: list[dict[str, Any]]) -> str:  # noqa: F821
        last = self._last_observation(messages)
        task_url = self._task_url(messages)
        if not last:
            url = task_url or f"{TARGET}/login?username=admin&password=x"
            return self._emit(
                "参数疑似注入，直接上真工具 sqlmap 确认",
                "sqlmap_scan",
                {"url": url, "timeout": 240},
            )
        if "sqlmap" in last:
            if "注入成立" in last:
                refs = __import__("re").findall(r"\[(\S+-T\d+)\]", last)
                return self._emit(
                    "sqlmap 已确认注入，登记为已复核漏洞",
                    "record_finding",
                    {
                        "title": "SQL 注入（sqlmap 工具级证据）",
                        "severity": "high",
                        "confidence": "high",
                        "confidence_rationale": "sqlmap 给出可复现 payload 与后端 DBMS 版本。",
                        "evidence": last[-400:],
                        "description": "参数未做参数化处理，注入 payload 可复现。",
                        "remediation": "使用参数化查询 / 预编译语句。",
                        "vuln_type": "SQL注入",
                        "url": task_url or f"{TARGET}/login",
                        "evidence_ref": refs[:1],
                        "verified": True,
                        "verification": "用 sqlmap 复跑并保留工具输出。",
                    },
                )
            return self._emit(
                "sqlmap 未确认，记录覆盖结论后收尾",
                "record_coverage",
                {"target": f"sqlmap：{task_url or TARGET}/login", "status": "ruled_out",
                 "detail": "sqlmap 未确认注入（否定结论，不是「无信号」）", "owasp": "A03"},
            )
        if "record_finding" in last or "record_coverage" in last:
            return self._emit("注入任务收尾", "finish_task", {"summary": "真工具验证完成。"})
        return self._emit("收尾", "finish_task", {"summary": "无可测项。"})

    def _recon_next(self, messages: list[dict[str, Any]]) -> str:
        last = self._last_observation(messages)
        if not last:
            return self._emit("先用真工具识别技术栈", "web_fingerprint", {"url": TARGET + "/"})
        if "web_fingerprint" in last or "whatweb" in last.lower():
            return super()._recon_next(messages)
        return super()._recon_next(messages)


def main() -> int:
    os.environ["HEXHOUND_HOME"] = str(HOME)
    allowed = frozenset({"127.0.0.1", "localhost"})

    setup = prepare_sandbox(allowed, map_loopback=False)
    check("沙箱准备成功", setup.ok, setup.message())
    if not setup.ok:
        return 1

    artifacts = RunArtifacts(TARGET)
    surface = AttackSurface(target=TARGET, mode="blackbox", path=artifacts.surface_path, allowed_hosts=allowed)
    budget = Budget(BudgetLimits(max_tool_calls=80, max_seconds=600))
    events: list[dict] = []

    def on_event(event: dict) -> None:
        events.append(event)
        if event.get("kind") in ("plan", "wave", "notice"):
            message = str(event.get("message") or "")
            print(f"  [{event.get('kind')}] {message or event.get('count') or ''}")

    llm = RealToolLLM()
    orchestrator = Orchestrator(
        llm,
        target=TARGET,
        goal=GOAL,
        mode="blackbox",
        base_dir=ROOT,
        allowed_hosts=allowed,
        timeout=15,
        max_tasks=3,
        task_steps=6,
        parallel=2,
        budget=budget,
        artifacts=artifacts,
        surface=surface,
        verbose=False,
        callbacks=SwarmCallbacks(on_event=on_event),
        memory=HostMemory(TARGET),
        sandbox=setup.sandbox,
        sandbox_note=setup,
        coverage_sweep=False,
    )
    print("=== 开始编排（脚本 LLM，零额度）===")
    result = orchestrator.run()

    # ---- 1. 运行记录里的沙箱状态 ----
    summary_path = Path(artifacts.dir) / "run.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
    sandbox_record = summary.get("sandbox") or {}
    check("run.json 记录沙箱已启用", bool(sandbox_record.get("enabled")), str(sandbox_record)[:160])
    check("run.json 记录了运行时", "WSL" in str(sandbox_record.get("runtime", "")),
          str(sandbox_record.get("runtime", "")))
    check("run.json 不再出现万能原因", sandbox_record.get("reason") != "本次运行未启用容器沙箱",
          str(sandbox_record.get("reason", "")))

    # ---- 2. 真工具是否真的在任务里执行了 ----
    commands = [str(item.get("command") or "") for item in (result.tool_log or [])]
    check("工具日志里有真工具执行", bool(commands), f"{len(commands)} 条")
    check("sqlmap 真的被执行", any("sqlmap" in cmd for cmd in commands),
          next((cmd for cmd in commands if "sqlmap" in cmd), "")[:120])
    has_t_id = any(str(item.get("id", "")).startswith(("E", "W", "T")) or "-T" in str(item.get("id", ""))
                   for item in (result.tool_log or []))
    check("真工具证据带编号", has_t_id)

    # ---- 3. 失败统计 ----
    failures = result.tool_failures or {}
    check("没有'未下发的工具'", not failures.get("unknown"), str(failures))
    check("没有工具内部异常", not failures.get("crashed"), str(failures))
    print(f"     工具失败统计：{failures or '{}（无失败）'}")

    # ---- 4. 报告如实记录 ----
    markdown = to_markdown(result, GOAL)
    check("报告写明沙箱已启用", "真工具沙箱：**已启用**" in markdown,
          next((line for line in markdown.splitlines() if "真工具沙箱" in line), "")[:140])
    check("报告含真工具证据附录", "sqlmap" in markdown)

    waves = [event for event in events if event.get("kind") == "wave"]
    print(f"     波次：{[(w.get('wave'), w.get('count')) for w in waves]}")
    print(f"     发现：{len(result.findings)} 条（去重 {result.deduped}）｜用量：{budget.describe()}")
    print(f"     产物：{artifacts.dir}")

    print()
    if FAILURES:
        print(f"编排验证未通过：{len(FAILURES)} 项 —— " + "；".join(FAILURES))
        return 1
    print("编排验证通过：真工具在真实编排里被下发并执行，记录与报告一致。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
