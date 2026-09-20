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
from dataclasses import dataclass, field
from typing import Any, Callable

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
        parse_failures = 0

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

        for step_no in range(1, self.max_steps + 1):
            if should_stop is not None and should_stop():
                final_summary = "任务已终止（页面刷新或用户停止）。"
                finish_reason = "stopped"
                break
            # 预算硬闸：越线立刻收尾（不再发 LLM 请求）。
            if not self.budget.can_spend():
                finish_reason = "budget"
                final_summary = "预算用尽，已停止：" + "；".join(self.budget.stop_reasons())
                emit({"step": step_no, "action": "budget_stop", "observation": final_summary})
                break
            # 预算预警带：把收尾指令插进对话。
            notice = self.budget.pending_notice()
            if notice is not None:
                level, directive = notice
                messages.append({"role": "user", "content": finish_instruction(role, f"{level}: {directive}")})
                if self.on_notice is not None:
                    self.on_notice(level, directive)

            messages = _compress_history(
                messages, steps, self.max_context_chars, self.keep_recent_messages
            )
            content, usage = self.llm.complete(messages)
            self.budget.add_usage(usage)
            self._accumulate(usage, totals)
            publish_usage()
            messages.append({"role": "assistant", "content": content})
            if self.verbose:
                print(f"\n===== Step {step_no} =====")
                print(content)

            try:
                parsed = extract_json(content)
                parse_failures = 0
            except ValueError as exc:
                parse_failures += 1
                observation = (
                    f"输出解析失败：{exc}。请严格只输出一个 JSON 对象，"
                    "不要包含代码围栏或多余文字，且必须包含 thought/action/action_input 三个键。"
                )
                messages.append({"role": "user", "content": observation})
                emit({"step": step_no, "action": "parse_error", "observation": observation})
                if parse_failures >= 2:
                    final_summary = "连续两次输出无法解析为 JSON，已停止以避免继续消耗预算。"
                    finish_reason = "parse_error"
                    break
                continue

            if should_stop is not None and should_stop():
                final_summary = "任务已终止（页面刷新或用户停止）。"
                finish_reason = "stopped"
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
            }

            if action in ("finish", "finish_task"):
                summary = str(action_input.get("summary") or parsed.get("summary") or "")
                final_summary = summary
                record["observation"] = "任务结束。"
                emit(record)
                finish_reason = "finish"
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

            observation = self.tools.execute(str(action), action_input)
            record["observation"] = observation
            emit(record)
            messages.append(
                {
                    "role": "user",
                    "content": f"观察结果：\n{observation}\n\n请继续，输出下一轮的 JSON。",
                }
            )
            if self.verbose:
                print(f"[观察] {observation[:400]}")
        else:
            finish_reason = "max_steps"
            final_summary = f"达到最大步数 {self.max_steps} 仍未收尾，已停止。"

        return AgentResult(
            steps=steps,
            findings=list(self.tools.findings),
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
            poc_paths=dict(self.tools.poc_paths),
        )
