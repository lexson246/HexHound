"""端到端演练：真实 LLM + 靶场，验证「规划 → 并发子代理 → 复核 → 报告」闭环。

用法：
    python vulnlab/app.py                 # 另开终端启动靶场
    python examples/swarm_demo.py         # 默认打 http://127.0.0.1:5000

参数（环境变量）：
    SWARM_MAX_TASKS   最多几个子任务（默认 4）
    SWARM_TASK_STEPS  每个子任务步数（默认 8）
    SWARM_MAX_COST    费用上限（人民币，默认 0.6）
    SWARM_MAX_STEPS   工具调用总上限（默认 200）
    SWARM_MOCK=1      用脚本 LLM（不需要 API key，验证编排链路）

用法补充：没配 LLM key 时可直接 `SWARM_MOCK=1 python examples/swarm_demo.py`，
它会用 `hexhound.mockllm.ScriptedLLM` 驱动同一套编排/工具/复核链路。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound.budget import Budget, BudgetLimits  # noqa: E402
from hexhound.config import Config  # noqa: E402
from hexhound.llm import LLMClient  # noqa: E402
from hexhound.memory import HostMemory, RunArtifacts  # noqa: E402
from hexhound.mockllm import ScriptedLLM  # noqa: E402
from hexhound.orchestrator import Orchestrator, SwarmCallbacks, summarise_events  # noqa: E402
from hexhound.report import write_report  # noqa: E402
from hexhound.surface import AttackSurface  # noqa: E402

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
GOAL = f"对 {TARGET} 做黑盒安全评估（仅限授权 scope），按 OWASP Top 10 覆盖，只记录有真实请求证据的漏洞。"
LOCAL_HOSTS = {"127.0.0.1", "localhost"}


def build_llm():
    """返回 (llm, allowed_hosts, 说明)。MOCK 模式不需要 key，也不受白名单限制。"""
    if os.getenv("SWARM_MOCK"):
        return ScriptedLLM(), frozenset(LOCAL_HOSTS | {TARGET.split("//")[-1].split("/")[0].split(":")[0]}), "脚本 LLM（mock）"
    config = Config.from_env()
    allowed = set(config.allowed_hosts) | LOCAL_HOSTS
    return LLMClient(config.api_key, config.base_url, config.model), frozenset(allowed), config.model


def main() -> int:
    llm, allowed, label = build_llm()
    target_host = TARGET.split("//")[-1].split("/")[0].split(":")[0]
    if target_host not in allowed:
        print(f"目标主机 {target_host} 不在白名单内，请在 .env 的 ALLOWED_HOSTS 中追加。")
        return 2
    timeout = int(os.getenv("REQUEST_TIMEOUT", "10"))
    print(f"模型：{label}｜目标：{TARGET}｜白名单：{', '.join(sorted(allowed))}\n")
    budget = Budget(
        BudgetLimits(
            max_cost=float(os.getenv("SWARM_MAX_COST", "0.6")),
            max_tool_calls=int(os.getenv("SWARM_MAX_STEPS", "200")),
        )
    )
    artifacts = RunArtifacts(TARGET)
    surface = AttackSurface(target=TARGET, mode="blackbox", path=artifacts.surface_path)

    def on_step(step: dict) -> None:
        worker = step.get("worker", "?")
        action = step.get("action", "?")
        observation = str(step.get("observation") or "").replace("\n", " ")[:110]
        print(f"  [{worker}] {action}: {observation}")

    def on_event(event: dict) -> None:
        kind = event.get("kind")
        if kind == "plan":
            print("\n=== 计划 ===")
            for task in event.get("tasks") or []:
                print(f"  [{task['id']}] {task['role']}: {task['objective'][:90]}")
        elif kind == "wave":
            print(f"\n=== 第 {event.get('wave')} 波：{event.get('count')} 个任务 ===")
        elif kind == "task_start":
            task = event["task"]
            print(f"\n>>> [{task['id']}] {task['role']}: {task['objective'][:80]}")
        elif kind == "task_end":
            task = event["task"]
            print(f"<<< [{task['id']}] {task['outcome']}: {str(task.get('summary') or task.get('error'))[:150]}")
        elif kind == "notice":
            print(f"  ! [{event.get('task')}] {event.get('level')}: {event.get('message')}")

    callbacks = SwarmCallbacks(on_step=on_step, on_event=on_event)
    orchestrator = Orchestrator(
        llm,
        target=TARGET,
        goal=GOAL,
        mode="blackbox",
        base_dir=Path("."),
        allowed_hosts=allowed,
        timeout=timeout,
        max_tasks=int(os.getenv("SWARM_MAX_TASKS", "4")),
        task_steps=int(os.getenv("SWARM_TASK_STEPS", "8")),
        parallel=int(os.getenv("SWARM_PARALLEL", "3")),
        budget=budget,
        artifacts=artifacts,
        surface=surface,
        verbose=False,
        callbacks=callbacks,
        memory=HostMemory(TARGET),
    )
    result = orchestrator.run()

    print("\n=== 编排事件 ===")
    print(summarise_events(orchestrator.events))
    print("\n=== 任务台账 ===")
    for line in orchestrator.ledger.summary_lines():
        print("  " + line)
    print("\n=== 攻面统计 ===")
    print("  " + str(surface.stats()))
    print("  覆盖：" + str(surface.coverage_summary()))
    print("\n=== 预算 ===")
    print("  " + budget.describe())

    output = write_report(result, GOAL, Path("reports/swarm-demo.md"))
    print(f"\n=== 漏洞（{len(result.findings)} 条，去重合并 {result.deduped} 条）===")
    for finding in result.findings:
        print(
            f"  [{finding.get('status')}] {finding.get('id')} "
            f"({finding.get('severity')}) {finding.get('title')} -> {finding.get('url', '')}"
        )
    print(f"\n报告：{output}")
    print(f"产物目录：{artifacts.dir}")
    print(f"总结：\n{result.final_summary[:800]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
