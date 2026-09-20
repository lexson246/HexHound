"""手写 ReAct 循环：LLM 决策 -> 解析 JSON -> 执行工具 -> 观察 -> 继续。

v0.2 相比 v0.1 的变化（对标 Strix / PentAGI）：

1. **预算感知**：每一步先问 `budget.can_spend()`；到 70%/85%/95% 时把收尾指令
   插进对话（Strix 的 wrap-up directive 做法），越线则优雅收尾而不是被硬掐断。
2. **共享攻面 + 角色**：提示词里带攻击面简报，工具集按角色裁剪（见 tools.ROLE_TOOLS）。
3. **收尾动作纪律**：`finish_task` / `finish` 都算正常收尾；走到步数上限会被
   自动追问一次"给出结论"，避免白跑。
4. **更省的上下文压缩**：分层保留——系统提示与任务目标永不动，中期历史压成
   结构化摘要（已做动作/命中/结论），最近若干轮原样保留。
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .budget import Budget
from .llm import LLMClient, estimate_cost
from .prompts import build_system_prompt, build_task_prompt, finish_instruction
from .surface import AttackSurface
from .tools import ToolRegistry


def _summarize_steps(steps: list[dict[str, Any]], limit: int = 6000) -> str:
    """把已完成步骤压缩成一段简短记忆，避免上下文无限增长。

    分层压缩：命中/记录类动作优先保留（信息密度最高），普通探测压缩成一行。
    """
    key_lines: list[str] = []
    other_lines: list[str] = []
    for record in steps:
        action = str(record.get("action") or "?")
        thought = str(record.get("thought") or "").strip().replace("\n", " ")
        observation = str(record.get("observation") or "").strip().replace("\n", " ")
        action_input = record.get("action_input") or {}
        if not isinstance(action_input, dict):
            action_input = {}
        if action in ("record_finding", "record_coverage", "leave_note"):
            key_lines.append(
                f"Step {record.get('step', '?')} {action}({action_input.get('title') or action_input.get('target') or action_input.get('text', '')[:60]}): "
                f"{observation[:160]}"
            )
            continue
        if action == "fuzz_params" and "疑似信号" in observation:
            key_lines.append(
                f"Step {record.get('step', '?')} fuzz 命中：{observation[:200]}"
            )
            continue
        parts = [p for p in (thought[:120], observation[:150]) if p]
        other_lines.append(f"Step {record.get('step', '?')} {action}: {' / '.join(parts)}")
    body = "\n".join(key_lines + other_lines)
    if len(body) > limit:
        body = body[:limit] + "\n...(记忆已截断)"
    return body or "(暂无已完成步骤)"


def _compress_history(
    messages: list[dict[str, str]],
    steps: list[dict[str, Any]],
    max_context_chars: int,
    keep_recent_messages: int,
) -> list[dict[str, str]]:
    """保留系统提示、任务目标与最近几轮，压缩中间历史为确定性摘要。"""
    if len(messages) <= 2:
        return messages
    total_chars = sum(len(message.get("content", "")) for message in messages)
    if len(messages) <= keep_recent_messages and total_chars <= max_context_chars:
        return messages

    keep_recent_messages = max(4, keep_recent_messages)
    head = messages[:2]
    tail = messages[-keep_recent_messages:] if len(messages) > keep_recent_messages else messages[2:]
    summary = "[压缩历史]\n" + _summarize_steps(steps)
    return head + [{"role": "user", "content": summary}] + tail


def extract_json(text: str) -> dict[str, Any]:
    """从 LLM 输出中提取 JSON 对象，容忍 markdown 代码围栏与多余文字。

    失败时抛 ValueError。
    """
    text = (text or "").strip()
    # 1) 剥掉 ```json ... ``` 之类的围栏。
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    # 2) 尝试直接解析。
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        # 3) 找第一个 { 到与之配对的 }，容忍前后多余文字。
        parsed = _extract_balanced_object(text)
    if not isinstance(parsed, dict):
        raise ValueError("解析结果不是 JSON 对象")
    return parsed


def _extract_balanced_object(text: str) -> Any:
    """扫描第一个 { 起配对括号，返回解析后的对象。"""
    start = text.find("{")
    if start == -1:
        raise ValueError("未找到 JSON 对象（缺少 {）")
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : i + 1])
    raise ValueError("JSON 对象未闭合")


@dataclass
class AgentResult:
    """一次审计运行的完整结果。"""

    steps: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    final_summary: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cache_hit_tokens: int = 0
    cache_miss_tokens: int = 0
    estimated_cost: float = 0.0
    total_tokens: int = 0
    steps_used: int = 0
    finish_reason: str = ""
    surface: AttackSurface | None = None
    tasks: list[dict[str, Any]] = field(default_factory=list)
    artifacts_dir: str = ""
    poc_paths: dict[str, str] = field(default_factory=dict)
    deduped: int = 0
    #: 各角色实际使用的 提供商/模型（便于复现一次运行）。
    models: dict[str, str] = field(default_factory=dict)
    #: 真工具沙箱状态（报告里必须能看出"这次用了真工具还是只做了 HTTP 探测"）。
    sandbox: dict[str, Any] = field(default_factory=dict)
    #: 真工具执行记录（命令 + 输出），作为报告的证据附录。
    tool_log: list[dict[str, Any]] = field(default_factory=list)
    #: 覆盖率闸门结果：{total, touched, untouched, ratio, untouched_sample}
    coverage_gate: dict[str, Any] = field(default_factory=dict)
    #: 上次运行报告的漏洞（来自跨运行记忆），用于生成 diff
    previous_findings: list[dict[str, Any]] = field(default_factory=list)
    previous_run_at: str = ""
    #: 强制收尾回合的实际情况：{attempted, used, closed, tools_used, summary}
    #: 用来回答"这个子任务到底是自己收的尾，还是被系统收的尾"。
    closing: dict[str, Any] = field(default_factory=dict)
    #: 本任务**本地**用量（并发下由任务自己累计，不用全局前后差值）。
    usage: dict[str, Any] = field(default_factory=dict)
    #: 可审计轨迹的统计摘要（{events, kinds, tasks, tools, schema_version}）。
    #: 只在报告渲染"这次运行发生了什么"时用到，因此不参与 `to_snapshot`
    #: （轨迹本体在 trace.jsonl 里，快照只记摘要，避免重复存储）。
    trace_summary: dict[str, Any] = field(default_factory=dict)
    #: 快照来源标记：snapshot / legacy / ""（本次运行）。
    restored_from: str = ""

    # ---------- 离线重建（见 trace.py）----------

    def to_snapshot(self) -> dict[str, Any]:
        """展平成可 JSON 化的字典，供 `snapshot.json` 与离线报告重建使用。

        **不包含 surface**：findings/attempts/coverage 已经在 `surface.json` 里，
        重复存会让运行目录体积翻倍。报告重建时由调用方把 surface 装回去。
        """
        return {
            "steps": list(self.steps),
            "findings": list(self.findings),
            "final_summary": self.final_summary,
            "finish_reason": self.finish_reason,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cache_hit_tokens": self.cache_hit_tokens,
            "cache_miss_tokens": self.cache_miss_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost": self.estimated_cost,
            "steps_used": self.steps_used,
            "tasks": list(self.tasks),
            "artifacts_dir": self.artifacts_dir,
            "poc_paths": dict(self.poc_paths),
            "models": dict(self.models),
            "sandbox": dict(self.sandbox),
            "tool_log": list(self.tool_log),
            "coverage_gate": dict(self.coverage_gate),
            "deduped": self.deduped,
            "previous_findings": list(self.previous_findings),
            "previous_run_at": self.previous_run_at,
            "closing": dict(self.closing),
            "usage": dict(self.usage),
        }

    @classmethod
    def from_snapshot(cls, data: dict[str, Any], *, surface: AttackSurface | None = None) -> AgentResult:
        """从快照字典重建 `AgentResult`（离线重渲染用）。

        缺失字段一律取 dataclass 默认值——**旧快照不该因为少一个字段就渲染失败**，
        缺什么由报告层标注"未记录"。
        """
        payload = data if isinstance(data, dict) else {}
        return cls(
            steps=list(payload.get("steps") or []),
            findings=list(payload.get("findings") or []),
            final_summary=str(payload.get("final_summary") or ""),
            prompt_tokens=int(payload.get("prompt_tokens") or 0),
            completion_tokens=int(payload.get("completion_tokens") or 0),
            cache_hit_tokens=int(payload.get("cache_hit_tokens") or 0),
            cache_miss_tokens=int(payload.get("cache_miss_tokens") or 0),
            estimated_cost=float(payload.get("estimated_cost") or 0.0),
            total_tokens=int(payload.get("total_tokens") or 0),
            steps_used=int(payload.get("steps_used") or len(payload.get("steps") or [])),
            finish_reason=str(payload.get("finish_reason") or ""),
            surface=surface,
            tasks=list(payload.get("tasks") or []),
            artifacts_dir=str(payload.get("artifacts_dir") or ""),
            poc_paths=dict(payload.get("poc_paths") or {}),
            deduped=int(payload.get("deduped") or 0),
            models=dict(payload.get("models") or {}),
            sandbox=dict(payload.get("sandbox") or {}),
            tool_log=list(payload.get("tool_log") or []),
            coverage_gate=dict(payload.get("coverage_gate") or {}),
            previous_findings=list(payload.get("previous_findings") or []),
            previous_run_at=str(payload.get("previous_run_at") or ""),
            closing=dict(payload.get("closing") or {}),
            usage=dict(payload.get("usage") or {}),
        )


#: 收尾阶段允许调用的工具。**白名单，不是黑名单**——
#: 目的是"把已经查到的东西写下来"，而不是继续探测。
#: 任何扫描、HTTP 请求、shell/脚本命令都不在其中。
CLOSING_TOOLS: frozenset[str] = frozenset({
    "record_finding",
    "record_coverage",
    "leave_note",
    "finish_task",
})

#: 允许的最大收尾回合数（硬上限，配置不了——这是"给两次机会"，不是"再跑一轮"）。
MAX_CLOSING_ROUNDS = 2

#: 收尾结果的原因码：模型没主动 finish_task，但东西已经落库。
CLOSE_REASON_SYNTHESIZED = "closing_no_finish"

#: 收尾阶段都不肯收尾（或收尾回合被预算掐断）。
CLOSE_REASON_UNCLOSED = "closing_failed"


def harvest_findings(registry: Any) -> list[dict[str, Any]]:
    """从注册表收集已记录的发现；注册表不可用时返回空列表。

    为什么要有这个"安全版"：`AgentResult` 现在在**异常路径**上也会被构造
    （provider 报错、监督器中止）。异常路径上再抛一个异常就等于把已经拿到的
    发现全丢了——那正是最需要保住产出的时候。所以这里吞掉异常并返回 `[]`，
    由调用方在 `final_summary` 里说明"产出未能读取"。
    """
    getter = getattr(registry, "findings", None)
    if getter is None:
        return []
    try:
        return list(getter)
    except Exception:  # noqa: BLE001 异常路径上不能再抛
        return []


class ReActAgent:
    """手写 ReAct 循环，不依赖任何重框架。"""

    def __init__(
        self,
        llm: LLMClient,
        tools: ToolRegistry,
        max_steps: int = 30,
        verbose: bool = False,
        max_context_chars: int = 32000,
        keep_recent_messages: int = 8,
        *,
        role: str = "agent",
        budget: Budget | None = None,
        brief: str = "",
        target: str = "",
        on_notice: Callable[[str, str], None] | None = None,
        conversation: dict[str, list[dict[str, str]]] | None = None,
    ) -> None:
        self.llm = llm
        self.tools = tools
        self.max_steps = max_steps
        self.verbose = verbose
        self.max_context_chars = max_context_chars
        self.keep_recent_messages = keep_recent_messages
        self.role = role
        self.budget = budget if budget is not None else getattr(tools, "budget", None) or Budget()
        self.brief = brief
        self.target = target
        self.on_notice = on_notice
        # 供监督器往对话里插话（重复动作告警）：外部持有同一个 list 引用。
        self._conversation = conversation

    # ---------- 内部 ----------

    def _accumulate(
        self, usage: Any, totals: dict[str, float]
    ) -> tuple[int, int, int, int, int, float]:
        """把一次 LLM 用量累加进 totals，返回本步 (prompt, completion, total, hit, miss, cost)。"""
        if isinstance(usage, int):
            totals["total_tokens"] += usage
            return 0, usage, usage, 0, 0, 0.0
        prompt = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion = int(getattr(usage, "completion_tokens", 0) or 0)
        total = int(getattr(usage, "total_tokens", prompt + completion) or 0)
        hit = int(getattr(usage, "cache_hit_tokens", 0) or 0)
        miss = int(getattr(usage, "cache_miss_tokens", 0) or 0)
        if hit + miss == 0:
            miss = prompt
        cost = estimate_cost(usage)
        totals["prompt_tokens"] += prompt
        totals["completion_tokens"] += completion
        totals["total_tokens"] += total
        totals["cache_hit_tokens"] += hit
        totals["cache_miss_tokens"] += miss
        totals["estimated_cost"] += cost
        return prompt, completion, total, hit, miss, cost

    # ---------- 主循环 ----------

    def run(
        self,
        goal: str,
        on_step: Callable[[dict[str, Any]], None] | None = None,
        on_usage: Callable[[dict[str, int]], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
        task_usage: Any = None,
    ) -> AgentResult:
        mode = getattr(self.tools, "mode", "source")
        role = self.role if self.role in ("recon", "injection", "auth", "verify", "source") else (
            "blackbox" if mode == "blackbox" else "source"
        )
        system = build_system_prompt(self.tools.describe(), mode, role)
        # 把"本次真工具能力"贴进系统提示词——模型不会自己发现有 sqlmap 可用
        briefing = ""
        getter = getattr(self.tools, "sandbox_briefing", None)
        if callable(getter):
            try:
                briefing = str(getter() or "")
            except Exception:  # noqa: BLE001 说明取不到不影响主流程
                briefing = ""
        if briefing:
            system = f"{system}\n\n{briefing}"
        messages: list[dict[str, str]] = [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": build_task_prompt(
                    goal,
                    mode,
                    role,
                    brief=self.brief,
                    step_budget=self.max_steps,
                    target=self.target,
                ),
            },
        ]
        steps: list[dict[str, Any]] = []
        if self._conversation is not None:
            # 把消息列表交给外部（监督器需要能往对话里插话）。
            self._conversation["messages"] = messages
        totals: dict[str, float] = {
            "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
            "cache_hit_tokens": 0, "cache_miss_tokens": 0, "estimated_cost": 0.0,
        }
        final_summary = ""
        finish_reason = ""

        def emit(record: dict[str, Any]) -> None:
            steps.append(record)
            if on_step is not None:
                on_step(dict(record))

        def publish_usage() -> None:
            if on_usage is not None:
                on_usage(
                    {
                        "prompt_tokens": int(totals["prompt_tokens"]),
                        "completion_tokens": int(totals["completion_tokens"]),
                        "cache_hit_tokens": int(totals["cache_hit_tokens"]),
                        "cache_miss_tokens": int(totals["cache_miss_tokens"]),
                        "estimated_cost": float(totals["estimated_cost"]),
                        "total_tokens": int(totals["total_tokens"]),
                    }
                )

        # 收尾回合记账。**这是本函数最重要的状态**：它决定 `finish_reason` 是
        # "模型自己收的尾"还是"系统替它收的尾"，两者在报告里的含义不同。
        closing = _ClosingState()

        # 总请求预算 = 正常步数 + 收尾回合数。收尾回合在正常步数用尽后才开始，
        # 且只有 CLOSING_TOOLS 可用——所以"多出来的两轮"不可能变成新一轮扫描。
        total_budget = self.max_steps + MAX_CLOSING_ROUNDS
        step_no = 0
        while step_no < total_budget:
            step_no += 1
            phase = closing.phase(step_no, self.max_steps)

            if should_stop is not None and should_stop():
                finish_reason = "stopped"
                final_summary = "任务已终止（页面刷新或用户停止）。"
                break
            # 预算硬闸：越线立刻收尾（不再发 LLM 请求）。
            # 收尾回合也受这条约束——预算用尽时不该再花两次调用去"写总结"。
            if not self.budget.can_spend():
                finish_reason = "budget"
                final_summary = "预算用尽，已停止：" + "；".join(self.budget.stop_reasons())
                emit({"step": step_no, "action": "budget_stop", "observation": final_summary})
                break

            if phase == "closing":
                if closing.begin_round(step_no):
                    directive = closing_instruction(
                        role, self.max_steps, closing.rounds_started
                    )
                    messages.append({"role": "user", "content": directive})
                    closing.tools_used["_directive"] = closing.rounds_started
            else:
                # 预算预警带：把收尾指令插进对话。
                notice = self.budget.pending_notice()
                if notice is not None:
                    level, directive = notice
                    messages.append(
                        {"role": "user", "content": finish_instruction(role, f"{level}: {directive}")}
                    )
                    if self.on_notice is not None:
                        self.on_notice(level, directive)

            messages = _compress_history(
                messages, steps, self.max_context_chars, self.keep_recent_messages
            )
            # 发请求**之前**原子预留一次 LLM 名额：先查后记是两步，
            # 并发 worker 能一起越过 max_llm_calls（见 Budget.reserve_llm_call）。
            ok, blocked = self.budget.reserve_llm_call()
            if not ok:
                finish_reason = "budget"
                final_summary = "预算用尽，已停止：" + blocked
                emit({"step": step_no, "action": "budget_stop", "observation": final_summary})
                break
            try:
                content, usage = self.llm.complete(messages)
            except Exception as exc:  # noqa: BLE001 provider 故障必须形成明确终态
                # 以前这里会把异常抛到 TaskWorker，结果是"整个子任务的产出丢失"。
                # 现在转成一个明确的终态 + 保留已有产出（steps/findings/coverage）。
                finish_reason = "provider_error"
                final_summary = (
                    f"模型调用失败（{type(exc).__name__}: {exc}）。"
                    "已保留中断前的全部产出（步骤、发现、覆盖记录）。"
                )
                emit({"step": step_no, "action": "provider_error", "observation": final_summary})
                break
            self.budget.add_usage(usage, task=task_usage)
            self._accumulate(usage, totals)
            publish_usage()
            messages.append({"role": "assistant", "content": content})
            if self.verbose:
                print(f"\n===== Step {step_no} ({phase}) =====")
                print(content)

            try:
                parsed = extract_json(content)
                closing.parse_failures = 0
            except ValueError as exc:
                closing.parse_failures += 1
                observation = (
                    f"输出解析失败：{exc}。请严格只输出一个 JSON 对象，"
                    "不要包含代码围栏或多余文字，且必须包含 thought/action/action_input 三个键。"
                )
                messages.append({"role": "user", "content": observation})
                emit({"step": step_no, "action": "parse_error", "observation": observation,
                      "phase": phase})
                if closing.parse_failures >= 2:
                    finish_reason = (
                        CLOSE_REASON_UNCLOSED if phase == "closing" else "parse_error"
                    )
                    final_summary = "连续两次输出无法解析为 JSON，已停止以避免继续消耗预算。"
                    break
                continue

            if should_stop is not None and should_stop():
                finish_reason = "stopped"
                final_summary = "任务已终止（页面刷新或用户停止）。"
                break

            thought = parsed.get("thought", "")
            action = parsed.get("action", "")
            action_input = parsed.get("action_input", {})
            if not isinstance(action_input, dict):
                action_input = {"value": action_input}
            record = {
                "step": step_no,
                "thought": thought,
                "action": action,
                "action_input": action_input,
                "phase": phase,
            }

            if action in ("finish", "finish_task"):
                summary = str(action_input.get("summary") or parsed.get("summary") or "")
                final_summary = summary
                record["observation"] = "任务结束。"
                emit(record)
                finish_reason = "finish"
                if closing.rounds_started:
                    closing.closed = True
                break

            if not str(action).strip():
                # 模型偶尔会输出缺 action 的 JSON（或 action 为空串）。直接喂回错误提示，
                # 而不是让它变成"未知工具 ''"这种看不出问题的报错，从而浪费一步。
                observation = (
                    "输出里 action 为空。请输出一个真实可用的工具名，或 action=\"finish_task\" 结束任务。"
                    f"当前可用工具：{', '.join(self.tools.tool_names())}。"
                )
                record["action"] = "(空)"
                record["observation"] = observation
                emit(record)
                messages.append({"role": "user", "content": observation + "\n\n请继续，输出下一轮的 JSON。"})
                continue

            if phase == "closing" and str(action) not in CLOSING_TOOLS:
                # 收尾阶段拒绝一切探测类动作。**不执行**，只回一条说明——
                # 模型在收尾阶段要求扫端口/发请求是常见行为，执行一次就等于
                # 收尾回合变成了普通回合，"两轮封顶"的约束也就失效了。
                observation = closing.rejection(str(action))
                record["observation"] = observation
                closing.rejected += 1
                emit(record)
                messages.append({"role": "user", "content": observation})
                continue

            observation = self.tools.execute(str(action), action_input)
            record["observation"] = observation
            emit(record)
            if phase == "closing":
                closing.note_tool(str(action))
            messages.append(
                {
                    "role": "user",
                    "content": f"观察结果：\n{observation}\n\n请继续，输出下一轮的 JSON。",
                }
            )
            if self.verbose:
                print(f"[观察] {observation[:400]}")
        else:
            # while 正常走完（没有 break）：正常步数与收尾回合全部耗尽。
            # 用 CLOSE_REASON_UNCLOSED 标记，下面统一翻译成"系统代写总结"的终态。
            finish_reason = CLOSE_REASON_UNCLOSED
            final_summary = (
                f"正常步数（{self.max_steps} 步）用尽，且 {MAX_CLOSING_ROUNDS} 个收尾回合"
                "内未调用 finish_task。已保留全部产出。"
            )

        # ---- 终态收口 ----------------------------------------------------
        # 规则只有一条：**只要进过收尾回合且没收到 finish_task，就不算正常收尾**。
        # 此时区分两种原因（都保留全部产出，报告里如实标注）：
        #   closing_no_finish —— 收尾机会用完了，模型始终没交总结；
        #   其它（budget / stopped / provider_error）—— 收尾被外部原因打断。
        #
        # 总结一定不能是空的：收尾回合存在的意义就是"即使模型不总结，
        # 已完成的步骤、用量、覆盖与有效证据也要留下来"。系统代写的总结
        # 只陈述可核对的事实（记了几条 finding、几条覆盖、动作分布），
        # 不做任何推断——推断出来的东西没有证据支撑。
        if closing.rounds_started and not closing.closed:
            if finish_reason == CLOSE_REASON_UNCLOSED:
                finish_reason = CLOSE_REASON_SYNTHESIZED
            synthesized = _synthesized_summary(self.tools, steps)
            if synthesized:
                # 上面的循环收尾文案（"…未调用 finish_task"）是**状态说明**，
                # 不是任务总结；有事实可写时用它替换，状态说明则保留在
                # `finish_reason`（报告里以 outcome 文案呈现）。
                if not final_summary or "未调用 finish_task" in final_summary:
                    final_summary = synthesized

        return AgentResult(
            steps=steps,
            findings=harvest_findings(self.tools),
            final_summary=final_summary,
            prompt_tokens=int(totals["prompt_tokens"]),
            completion_tokens=int(totals["completion_tokens"]),
            cache_hit_tokens=int(totals["cache_hit_tokens"]),
            cache_miss_tokens=int(totals["cache_miss_tokens"]),
            estimated_cost=float(totals["estimated_cost"]),
            total_tokens=int(totals["total_tokens"]),
            steps_used=len(steps),
            finish_reason=finish_reason,
            surface=self.tools.surface,
            poc_paths=dict(getattr(self.tools, "poc_paths", {}) or {}),
            closing=closing.to_dict(),
            usage=task_usage.to_dict() if task_usage is not None else {},
        )


class _ClosingState:
    """收尾回合的状态机（正常步数用尽 → 最多 N 轮受限收尾）。

    单独成类是为了让"收尾"这件事**可测**：给定步号就能判定当前处于哪个阶段，
    不需要真的把一个 ReAct 循环跑到上限。
    """

    def __init__(self) -> None:
        self.rounds_started = 0
        self.closed = False
        self.rejected = 0
        self.parse_failures = 0
        self.tools_used: dict[str, int] = {}

    def phase(self, step_no: int, max_steps: int) -> str:
        """当前是 `probe`（正常步）还是 `closing`（受限收尾回合）。"""
        return "closing" if step_no > max_steps else "probe"

    def begin_round(self, step_no: int) -> bool:
        """进入一个新收尾回合；返回是否需要下发收尾指令。

        同一回合内可能因为"输出无法解析"而多走一步（`continue` 不推进回合计数），
        所以这里用"回合数是否变化"判断，而不是每步都下发一遍指令。
        """
        round_index = self.rounds_started + 1
        if round_index > MAX_CLOSING_ROUNDS:
            return False
        self.rounds_started = round_index
        return True

    def note_tool(self, action: str) -> None:
        self.tools_used[action] = self.tools_used.get(action, 0) + 1

    def rejection(self, action: str) -> str:
        """收尾阶段拒绝一个探测动作时回给模型的话。"""
        allowed = "、".join(sorted(CLOSING_TOOLS))
        return (
            f"收尾阶段不接受 {action}（第 {self.rounds_started}/{MAX_CLOSING_ROUNDS} 个收尾回合）："
            "正常步数已经用尽，现在**只允许收尾动作**，用来把已经查到的东西写下来。\n"
            f"可用动作：{allowed}。\n"
            "请立刻：把已确认的问题用 record_finding 记下（带 evidence_ref），"
            "把「测过但没问题」的位置用 record_coverage 记清，然后 finish_task 交回总结。"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempted": self.rounds_started,
            "used": self.rounds_started,
            "closed": self.closed,
            "rejected": self.rejected,
            "tools_used": dict(self.tools_used),
            "max_rounds": MAX_CLOSING_ROUNDS,
        }


def closing_instruction(role: str, max_steps: int, round_index: int) -> str:
    """收尾回合的指令：明确"能做什么、不能做什么"。"""
    allowed = "、".join(sorted(CLOSING_TOOLS))
    return (
        f"<closing_round index=\"{round_index}\" of=\"{MAX_CLOSING_ROUNDS}\">\n"
        f"你的正常步数（{max_steps} 步）已经用尽，现在是**收尾回合**。\n"
        "从现在起**只允许**以下动作（任何扫描、HTTP 请求、shell 或脚本调用都会被拒绝，"
        "而且不会被执行）：\n"
        f"  {allowed}\n"
        "本轮唯一目标：把**已经查到的东西**固化下来，别再探测。请按顺序做：\n"
        "1) 已经确认（有证据编号）的问题 → record_finding（evidence_ref 填真实编号）；\n"
        "2) 试过但没问题的位置（端点/参数）→ record_coverage"
        "（status=no_issue_found 或 ruled_out，写清试过什么）；\n"
        "3) 没做完、留给下一轮的部分 → leave_note；\n"
        "4) 然后 **finish_task**，summary 里写清：确认了什么、覆盖到哪、还有什么没做。\n"
        "如果已经无可记录，直接 finish_task。\n"
        "</closing_round>"
    )


def _synthesized_summary(tools: Any, steps: list[dict[str, Any]]) -> str:
    """模型没主动 finish_task 时，由系统按**已落库的事实**补一份总结。

    关键约束：这份总结只能陈述"可核对的事实"——记了几条 finding、几条覆盖、
    走了多少步、被拒了几次探测。**不推断漏洞、不补充结论**，
    因为推断出来的东西没有证据支撑（HANDOVER 的第 9 条不变量）。
    """
    findings: list[dict[str, Any]] = []
    try:
        findings = list(tools.findings)
    except Exception:  # noqa: BLE001 这里出异常就等于连总结都写不出来
        findings = []
    coverage: list[Any] = []
    surface = getattr(tools, "surface", None)
    if surface is not None:
        try:
            coverage = list(surface.coverage_lines(50))
        except Exception:  # noqa: BLE001
            coverage = []
    actions = [str(step.get("action") or "") for step in steps]
    counts: dict[str, int] = {}
    for action in actions:
        counts[action] = counts.get(action, 0) + 1
    top = "、".join(f"{name}×{count}" for name, count in sorted(
        counts.items(), key=lambda item: (-item[1], item[0])
    )[:8])
    verified = [item for item in findings if str(item.get("status")) != "candidate"]
    candidates = [item for item in findings if str(item.get("status")) == "candidate"]
    lines = [
        "[系统代写总结] 模型在收尾回合内没有调用 finish_task；"
        "以下内容全部来自**已经落库的记录**，未经额外推断：",
        f"- 执行步数：{len(steps)}；动作分布：{top or '（无）'}",
        f"- 已记录问题：{len(verified)} 条已复核 / {len(candidates)} 条候选",
    ]
    for item in findings[:8]:
        lines.append(f"    · [{item.get('severity', '')}] {item.get('title', '')}"
                     f" -> {item.get('url', '')}")
    lines.append(f"- 覆盖记录：{len(coverage)} 条")
    for line in coverage[:8]:
        lines.append(f"    · {line}")
    lines.append(
        "注意：本任务未正常收尾，报告里该子任务标记为 `closing_no_finish`——"
        "「没做完」这件事必须如实呈现，其产出仍然有效。"
    )
    return "\n".join(lines)
