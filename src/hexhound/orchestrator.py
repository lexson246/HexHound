"""子代理（worker）与分层编排（orchestrator）。

对标两个参考项目的**结构**（不是照搬基建）：

- Strix：root 负责拆解与协调，worker 负责执行；worker 的工具集与提示词不同，
  结束时必须交回一份结构化报告（`agent_finish` 的 summary）。
- PentAGI：`flow → task → subtask`，主代理**没有手脚**（delegation-only），
  专家各有自己的执行器与结束工具；任务有工具调用上限；重复调用会被拦截
  （同一工具 3 次告警、7 次中止）。

HexHound 的落地方式：一个进程内的**分波并行**模型——
第 1 波侦察（recon）摸清攻面 → 第 2 波按攻面并行做 injection / auth →
第 3 波 verify 复核候选池 → 合并去重出报告。
每波内用线程池并发，共享同一个 `AttackSurface` 与 `Budget`。
"""
from __future__ import annotations

import json
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from .agent import AgentResult, ReActAgent, extract_json, harvest_findings
from .budget import Budget, TaskUsage
from .dedupe import dedupe_findings
from .llm import LLMClient
from .memory import HostMemory, RunArtifacts, TaskLedger
from .prompts import ROLE_PROMPTS
from .replan import (
    MAX_NEW_TASKS_PER_PATCH,
    PlanEntry,
    ReplanError,
    ReplanPolicy,
    apply_patch,
    parse_patch,
)
from .sandbox import sandbox_report
from .supervisor import Supervisor
from .surface import AttackSurface, normalize_endpoint, sort_urls
from .tools import ToolRegistry
from .trace import TraceRecorder, summarize_trace, write_snapshot

VALID_ROLES = ("recon", "injection", "auth", "verify", "source")

#: 单个任务默认步数上限（PentAGI 的 MAX_LIMITED_AGENT_TOOL_CALLS=20 同类约束）。
DEFAULT_TASK_STEPS = 10
#: 一次运行最多几个任务（PentAGI 的 TasksNumberLimit = 15，这里按单机预算收紧）。
MAX_TASKS = 6
#: 并发子代理数上限（避免把目标与 LLM 配额一起打爆）。
MAX_PARALLEL = 3

#: 每个波次开始前至少要剩余的墙钟时间（秒）。低于这个值就不再开新波。
#:
#: 为什么需要（HANDOVER §10 第 4 条：**"运行时长无界"**）：覆盖率补扫最多两轮，
#: 每轮还会跑端点补扫 + 参数补扫两波，实测一次运行能拖到 20 分钟。
#: `MAX_SECONDS` 只在"工具调用之间"生效，管不住"要不要再开一波"。
#: 这里在**每个波次边界**检查剩余时间，不够就不开新波——
#: 已经开跑的波次不会被腰斩，但不会再有下一波。
SWEEP_MIN_SECONDS = 45.0

#: 子任务结束状态的展示文案。注意 "done" 只表示**正常收尾**：
OUTCOME_LABEL: dict[str, str] = {
    "pending": "待执行",
    "done": "已收尾",
    "max_steps": "未收尾（达到步数上限）",
    "closing_no_finish": "已收尾（收尾回合内用受限动作固化产出）",
    "closing_failed": "未收尾（收尾回合也未交总结）",
    "budget": "未收尾（预算用尽）",
    "supervisor_abort": "未收尾（重复动作被中止）",
    "stopped": "已中断（用户停止）",
    "parse_error": "未收尾（输出无法解析）",
    "provider_error": "未收尾（模型调用失败）",
    "failed": "执行失败",
    "skipped": "跳过（预算/用户停止）",
}

#: 这些终态表示"子任务确实把活收口了"，产出可以当完整结论用。
#: 其余状态一律按"未收尾"对待（产出仍有效，但报告要标注没做完）。
CLOSED_OUTCOMES: frozenset[str] = frozenset({"done", "closing_no_finish"})

#: 这些终态表示"子任务被外部原因打断"，要在覆盖记录里标 blocked。
ABORTED_OUTCOMES: frozenset[str] = frozenset({"failed", "skipped"})

#: 这些终态表示"步数/预算/模型原因没跑完"，覆盖记录里标 not_tested。
INCOMPLETE_OUTCOMES: frozenset[str] = frozenset({
    "max_steps", "closing_failed", "budget", "supervisor_abort",
    "parse_error", "provider_error", "stopped",
})


@dataclass
class WorkerTask:
    """一个子任务（PentAGI 的 subtask / Strix 的 worker assignment）。"""

    id: str
    role: str
    objective: str
    url: str = ""
    steps: int = DEFAULT_TASK_STEPS
    wave: int = 1
    result: AgentResult | None = None
    error: str = ""
    outcome: str = "pending"  # pending / done / failed / skipped

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "role": self.role,
            "objective": self.objective,
            "url": self.url,
            "steps": self.steps,
            "wave": self.wave,
            "outcome": self.outcome,
            "outcome_label": OUTCOME_LABEL.get(self.outcome, self.outcome),
            "error": self.error,
            "summary": (self.result.final_summary if self.result else ""),
            # 收尾情况与本地用量：报告里要能回答"这个子任务是模型自己收的尾，
            # 还是系统给了收尾回合才收的尾"，以及"它自己花了多少"。
            "closing": (self.result.closing if self.result else {}),
            "usage": (self.result.usage if self.result else {}),
        }


@dataclass
class SwarmCallbacks:
    """编排过程对外的事件回调（CLI/GUI 用）。"""

    on_step: Callable[[dict[str, Any]], None] | None = None
    on_usage: Callable[[dict[str, Any]], None] | None = None
    on_event: Callable[[dict[str, Any]], None] | None = None
    should_stop: Callable[[], bool] | None = None

    def emit(self, **payload: Any) -> None:
        if self.on_event is not None:
            try:
                self.on_event(payload)
            except Exception:  # noqa: BLE001 事件回调失败不影响审计
                pass


class TaskWorker:
    """执行单个子任务：受限工具集 + 独立步数 + 重复动作监督。"""

    #: 同一 (工具, 参数) 连续重复到该次数即告警（对齐 PentAGI 的 3 次）。
    REPEAT_WARN = 3
    #: 重复到该次数直接中止子任务（对齐 PentAGI 的 7 次，这里收紧到 5）。
    REPEAT_ABORT = 5
    #: 剩余步数低于该值时提醒收尾（对齐 Strix/PentAGI 的"提前 3 轮开始 graceful termination"）。
    STEP_NOTICE_RESERVE = 2

    def __init__(
        self,
        llm: LLMClient,
        *,
        task: WorkerTask,
        base_dir: Any,
        allowed_hosts: frozenset[str],
        timeout: int,
        surface: AttackSurface,
        budget: Budget,
        artifacts: RunArtifacts,
        auth_profiles: dict[str, dict[str, str]],
        rate_limit: float = 0.0,
        verbose: bool = False,
        callbacks: SwarmCallbacks | None = None,
        worker_id: str = "",
        sandbox: Any = None,
        trace: Any = None,
    ) -> None:
        self.llm = llm
        self.task = task
        self.base_dir = base_dir
        self.allowed_hosts = allowed_hosts
        self.timeout = timeout
        self.surface = surface
        self.budget = budget
        self.artifacts = artifacts
        self.auth_profiles = auth_profiles
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.callbacks = callbacks or SwarmCallbacks()
        self.worker_id = worker_id or task.id
        self.sandbox = sandbox
        #: 运行级 trace（由编排器持有并注入；None = 走单代理/离线，不需要）。
        self.trace = trace
        #: 本任务自己的用量账本（并发下唯一正确的"这个任务花了多少"）。
        self.task_usage = TaskUsage(label=task.id)
        #: 停滞/重复/失败循环监督（判定逻辑见 supervisor.py）。
        self.supervisor = Supervisor()
        self._step_notices: set[str] = set()

    def _signature(self, action: str, action_input: dict[str, Any]) -> str:
        try:
            payload = json.dumps(action_input, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            payload = str(action_input)
        return f"{action}:{payload[:400]}"

    def _step_notice(self, step: dict[str, Any], messages: list[dict[str, str]]) -> None:
        """接近步数上限时提醒收尾（每个档位只提醒一次）。

        没有这层提醒，子代理会一路探测到硬上限，然后带着一堆未整理的观察结果
        被掐断——侦察结果留在对话里但没写进 finish_task，报告就少了结论。
        """
        try:
            step_no = int(step.get("step") or 0)
        except (TypeError, ValueError):
            return
        if step_no <= 0 or self.task.steps <= 0:
            return
        left = self.task.steps - step_no
        notice = ""
        if left <= 0:
            key = "end"
            notice = (
                "已到步数上限：本轮之后不会再执行工具了。请立即用 finish_task 交回总结"
                "（把已确认的结论、已验证的端点/参数、还没做完的部分写清楚）。"
            )
        elif left <= self.STEP_NOTICE_RESERVE:
            key = "reserve"
            notice = (
                f"只剩 {left} 步：请立刻收口——把已确认的漏洞用 record_finding 记录、"
                "结论用 record_coverage 写清，然后 finish_task，不要再开新的探测方向。"
            )
        elif left == 3:
            key = "warn3"
            notice = (
                f"只剩 {left} 步：开始收敛，优先把已命中的疑似信号复核成结论，"
                "未测完的部分写进 finish_task 的总结。"
            )
        if notice and key not in self._step_notices:
            self._step_notices.add(key)
            messages.append({"role": "user", "content": notice})
            self.callbacks.emit(
                kind="notice", task=self.task.id, level="STEPS", message=notice
            )

    def _supervise(self, step: dict[str, Any], messages: list[dict[str, str]]) -> None:
        """步数收尾提醒 + 停滞/重复/失败循环监督。

        监督判定委托给 `supervisor.Supervisor`（可脱离编排器单独测试）。
        这里只负责把判定结果变成**动作**：加一条提示，或者抛 `StepAbort`。

        v0.6 起多出来两类判据（原来只有"同工具同参数重复"）：
        - **长期无进展**：连续多步没有任何新证据/新结论；
        - **相同失败循环**：同一个失败连续出现多次。
        实测里这两种比"完全相同的调用"更常见——模型会稍微换个参数继续撞同一堵墙，
        签名不同所以旧判据抓不到，但预算照样烧光。
        """
        self._step_notice(step, messages)
        verdict = self.supervisor.observe(step)
        if self.trace is not None and verdict.level != "ok":
            # `Verdict.to_dict()` 里带一个 `kind` 键（repeat/stall/failure_loop），
            # 而 `TraceRecorder.record(kind=...)` 的第一个关键字参数**也叫 kind**。
            # 直接 `**verdict.to_dict()` 会 TypeError（"got multiple values for
            # argument 'kind'"）——实测把两个子任务打成"未预期错误中断"。
            # 所以这里显式改名，把判定类别放进 data 里。
            verdict_data = verdict.to_dict()
            verdict_data["verdict_kind"] = verdict_data.pop("kind", "")
            self.trace.record(
                "supervisor",
                task=self.task.id,
                role=self.task.role,
                **verdict_data,
            )
        if verdict.abort:
            raise StepAbort(f"{verdict.reason}；{verdict.directive}")
        if verdict.warn:
            messages.append({"role": "user", "content": "注意：" + verdict.directive})
            self.callbacks.emit(
                kind="notice", task=self.task.id, level="SUPERVISOR",
                message=verdict.reason,
            )

    def run(self) -> AgentResult:
        registry = ToolRegistry(
            base_dir=self.base_dir,
            allowed_hosts=self.allowed_hosts,
            timeout=self.timeout,
            mode="blackbox" if self.task.role != "source" else "source",
            auth_profiles=self.auth_profiles,
            surface=self.surface,
            budget=self.budget,
            worker_id=self.worker_id,
            role=self.task.role,
            artifacts=self.artifacts,
            rate_limit=self.rate_limit,
            sandbox=self.sandbox,
            task_usage=self.task_usage,
            trace=self.trace,
        )
        prior_exhausted = self.budget.exhausted_reason()
        # 监督器需要往对话里插话：用可变容器承接 ReActAgent 的消息列表引用。
        conversation: dict[str, list[dict[str, str]]] = {"messages": []}
        agent = ReActAgent(
            self.llm,
            registry,
            max_steps=self.task.steps,
            verbose=self.verbose,
            role=self.task.role,
            budget=self.budget,
            brief=self.surface.to_llm_summary(),
            target=self.task.url or self.surface.target,
            conversation=conversation,
            on_notice=lambda level, directive: self.callbacks.emit(
                kind="notice", task=self.task.id, level=level, message=directive
            ),
        )

        def on_step(record: dict[str, Any]) -> None:
            enriched = dict(record)
            enriched["worker"] = self.task.id
            enriched["role"] = self.task.role
            if self.callbacks.on_step is not None:
                self.callbacks.on_step(enriched)
            self._supervise(enriched, conversation["messages"])
            if self.trace is not None:
                self.trace.record_step(enriched, task=self.task.id, role=self.task.role)

        try:
            result = agent.run(
                self.task.objective,
                on_step=on_step,
                on_usage=self.callbacks.on_usage,
                should_stop=self.callbacks.should_stop,
                task_usage=self.task_usage,
            )
        except StepAbort as exc:
            result = AgentResult(
                steps=[],
                findings=harvest_findings(registry),
                final_summary=str(exc),
                finish_reason="supervisor_abort",
                surface=self.surface,
                poc_paths=dict(registry.poc_paths),
                usage=self.task_usage.to_dict(),
            )
        except Exception as exc:  # noqa: BLE001 最后一层兜底：任何未预期异常也要留下产出
            # ReActAgent 内部已经把 provider 故障转成终态；走到这里说明是别的东西坏了
            # （工具注册表构造、监督器回调…）。**仍然要保住已记录的证据**：
            # 一份"任务失败但有 N 条发现"的报告，比一句"子任务失败"有用得多。
            result = AgentResult(
                findings=harvest_findings(registry),
                final_summary=(
                    f"子任务因未预期错误中断（{type(exc).__name__}: {exc}）。"
                    "已保留中断前记录的证据与发现。"
                ),
                finish_reason="failed",
                surface=self.surface,
                poc_paths=dict(registry.poc_paths),
                usage=self.task_usage.to_dict(),
            )
        # 把本子任务的 **T 编号证据** 带上：报告附录必须能按 finding 里引用的编号查到命令，
        # 否则"证据可复核"就是一句空话（早先附录用的是沙箱内部 X 编号，两边对不上）。
        result.tool_log = list(registry.sandbox_log)
        if self.trace is not None:
            self._trace_tool_calls(result.tool_log)
            for finding in result.findings:
                self.trace.record_finding(finding, task=self.task.id)
        current = self.budget.exhausted_reason()
        if current and current != prior_exhausted:
            result.finish_reason = "budget"
        return result

    def _trace_tool_calls(self, tool_log: list[dict[str, Any]]) -> None:
        """把真工具调用写进 trace（参数摘要 + 状态 + 证据编号 + 溢写句柄）。"""
        if self.trace is None:
            return
        for entry in tool_log:
            spill = entry.get("spill") or {}
            self.trace.record_tool_call(
                task=self.task.id,
                evidence_id=str(entry.get("id") or ""),
                tool=str(entry.get("tool") or ""),
                command=str(entry.get("command") or ""),
                ok=bool(entry.get("ok")),
                exit_code=entry.get("exit_code"),
                duration=float(entry.get("duration") or 0.0),
                output_chars=len(str(entry.get("output") or "")),
                spill_handle=str(spill.get("handle") or ""),
                error=str(entry.get("error") or ""),
            )


class StepAbort(RuntimeError):
    """子任务被监督器中止（重复动作过多）。"""


def _outcome_for(result: AgentResult) -> str:
    """把 `AgentResult.finish_reason` 映射成台账/报告里的终态。

    `finish` 是模型自己交的总结；`closing_no_finish` 是"正常步数用尽，
    但在受限收尾回合里把产出固化下来了"。两者都算**已收尾**——
    区别只在报告里显示的文案（见 `OUTCOME_LABEL`），因为
    "模型自己收的尾"和"系统给了两轮机会才收的尾"对读者是不同信息。
    """
    reason = str(result.finish_reason or "failed")
    if reason == "finish":
        return "done"
    if reason == "closing_no_finish":
        return "closing_no_finish"
    return reason


def _parse_plan(text: str, target: str, surface: AttackSurface, max_tasks: int) -> list[WorkerTask]:
    """解析编排者的计划 JSON；失败则返回确定性兜底计划。"""
    tasks: list[WorkerTask] = []
    try:
        data = extract_json(text)
    except ValueError:
        data = {}
    raw_tasks = data.get("tasks") if isinstance(data, dict) else None
    if isinstance(raw_tasks, list):
        for index, item in enumerate(raw_tasks[:max_tasks], 1):
            if not isinstance(item, dict):
                continue
            role = str(item.get("role") or "").strip().lower()
            if role not in VALID_ROLES:
                continue
            objective = str(item.get("objective") or "").strip()
            if not objective:
                continue
            try:
                steps = int(item.get("steps") or DEFAULT_TASK_STEPS)
            except (TypeError, ValueError):
                steps = DEFAULT_TASK_STEPS
            tasks.append(
                WorkerTask(
                    id=f"T{index}",
                    role=role,
                    objective=objective[:400],
                    url=str(item.get("url") or target or "").strip(),
                    steps=max(4, min(steps, 20)),
                )
            )
    return tasks or _fallback_plan(target, surface, max_tasks)


def _fallback_plan(target: str, surface: AttackSurface, max_tasks: int) -> list[WorkerTask]:
    """编排器不可用时的确定性计划（也是重建计划的模板）。"""
    tasks: list[WorkerTask] = [
        WorkerTask(
            id="T1",
            role="recon",
            objective=(
                f"侦察 {target}：crawl 首页拿链接/表单/参数与技术栈，"
                "enumerate_common 探测 core+leak+admin+framework 档位，"
                "read_urls 读同域 JS 找接口与硬编码密钥，把可疑点用 leave_note 留给注入角色。"
            ),
            url=target,
            steps=DEFAULT_TASK_STEPS + 2,
        )
    ]
    interesting = _interesting_endpoints(surface, limit=3)
    for offset, url in enumerate(interesting, start=len(tasks) + 1):
        if len(tasks) >= max_tasks:
            break
        tasks.append(
            WorkerTask(
                id=f"T{offset}",
                role="injection",
                objective=(
                    f"对 {url} 做定向注入验证：先用 fuzz_params（按参数语义自动选类别），"
                    "命中的用 compare_responses 确认差异，证据成立才 record_finding。"
                ),
                url=url,
                steps=DEFAULT_TASK_STEPS,
            )
        )
    if len(tasks) < max_tasks and _looks_like_auth(surface):
        tasks.append(
            WorkerTask(
                id=f"T{len(tasks) + 1}",
                role="auth",
                objective=(
                    "认证与越权测试：check_default_creds 试默认凭据，"
                    "对返回敏感数据的接口测未授权访问（account=\"\"），"
                    "对带 id/uid/order_id 的接口测 IDOR（切 A/B 身份对比）。"
                ),
                url=target,
                steps=DEFAULT_TASK_STEPS,
            )
        )
    return tasks[:max_tasks]


def _interesting_endpoints(surface: AttackSurface, limit: int = 3) -> list[str]:
    """挑出最值得注入测试的端点：优先未测过且带参数、路径含动词的。"""
    candidates: list[str] = []
    for endpoint in surface.endpoints.values():
        if endpoint.params:
            candidates.append(endpoint.url)
    if not candidates:
        candidates = [url for url in surface.endpoints if not surface.is_tried(url, "fuzz")]
    return sort_urls(candidates, limit)


def _looks_like_auth(surface: AttackSurface) -> bool:
    tokens = ("login", "auth", "signin", "token", "session", "user", "admin", "account")
    for url in surface.endpoints:
        if any(token in url.lower() for token in tokens):
            return True
    for url in surface.forms:
        if any(token in url.lower() for token in tokens):
            return True
    return "/api/" in " ".join(surface.endpoints)


#: 参数名里出现这些片段时，说明"值得上 sqlmap"（数据库查询语义）。
_INJECTABLE_PARAM_HINTS = (
    "id", "uid", "q", "search", "keyword", "query", "name", "user", "pass",
    "order", "sort", "filter", "where", "select", "page", "cat", "type", "item",
    "product", "news", "article", "code", "no", "num", "key", "token", "email",
)


def _injectable_endpoints(surface: AttackSurface, limit: int = 3) -> list[str]:
    """挑出"最可能进数据库查询"的带参端点（用于优先安排 sqlmap 任务）。

    判据：端点有参数，且参数名或路径命中数据库查询类语义；登录/搜索类优先。
    """
    scored: list[tuple[int, str]] = []
    for endpoint in surface.endpoints.values():
        if not endpoint.params:
            continue
        low_url = endpoint.url.lower()
        low_params = " ".join(endpoint.params).lower()
        score = 0
        if any(token in low_url for token in ("login", "search", "query", "list", "item", "detail")):
            score += 3
        if any(hint in low_params for hint in _INJECTABLE_PARAM_HINTS):
            score += 2
        if any(token in low_params for token in ("id", "uid", "order", "no", "num")):
            score += 1
        if score:
            scored.append((score, endpoint.url))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [url for _score, url in scored[:limit]]


def _sqlmap_task_exists(tasks: list[WorkerTask]) -> bool:
    """计划里是否已经有会用到 sqlmap 的任务。"""
    for task in tasks:
        if task.role in ("injection", "auth", "verify"):
            lowered = task.objective.lower()
            if any(token in lowered for token in ("sql", "注入", "injection", "sqlmap")):
                return True
    return False


#: 状态变更语义提示词——竞态与业务逻辑问题**只可能**出现在这类面上
#: （优惠券、余额、积分、下单、退款、名额、一次性令牌…）。命中即派并发任务。
STATE_CHANGE_HINTS: tuple[str, ...] = (
    "coupon", "redeem", "voucher", "wallet", "balance", "points", "credit",
    "transfer", "pay", "payment", "order", "checkout", "cart", "claim",
    "apply", "invite", "reset", "verify", "confirm", "vote", "withdraw",
    "refund", "subscribe", "quota", "limit", "stock", "inventory", "seat",
)

#: 受保护接口的路径提示词（伪造凭据的利用目标）
PROTECTED_HINTS: tuple[str, ...] = ("admin", "manage", "internal", "console", "dashboard")

#: 可能泄露密钥/令牌结构的端点提示词
SECRET_HINTS: tuple[str, ...] = (
    "actuator", "/env", "config", ".js", ".json", "swagger", "openapi",
    "debug", "secret", "backup", ".git", "phpinfo", "metrics",
)


class Orchestrator:
    """分层编排：规划 → 分波执行 → 复核 → 合并。"""

    def __init__(
        self,
        llm: LLMClient,
        *,
        target: str,
        goal: str,
        mode: str = "blackbox",
        base_dir: Any = ".",
        allowed_hosts: frozenset[str] = frozenset({"127.0.0.1", "localhost"}),
        timeout: int = 10,
        max_tasks: int = MAX_TASKS,
        task_steps: int = DEFAULT_TASK_STEPS,
        parallel: int = MAX_PARALLEL,
        budget: Budget | None = None,
        artifacts: RunArtifacts | None = None,
        surface: AttackSurface | None = None,
        auth_profiles: dict[str, dict[str, str]] | None = None,
        rate_limit: float = 0.0,
        verbose: bool = False,
        callbacks: SwarmCallbacks | None = None,
        memory: HostMemory | None = None,
        verify: bool = True,
        llm_pool: dict[str, LLMClient] | None = None,
        sandbox: Any = None,
        coverage_sweep: bool = True,
    ) -> None:
        self.llm = llm
        #: 按角色分配的模型客户端（planner/recon/injection/auth/verify）。
        #: 缺哪个就用默认 llm，因此"不配角色覆盖"完全等同于 v0.2 的行为。
        self.llm_pool: dict[str, LLMClient] = dict(llm_pool or {})
        #: 真工具执行环境（None = 只有内置 HTTP 探测）
        self.sandbox = sandbox
        #: 是否在收尾前对"从未被碰过"的端点做强制补扫（覆盖率闸门）
        self.coverage_sweep = bool(coverage_sweep)
        self.target = target
        self.goal = goal
        self.mode = mode
        self.base_dir = base_dir
        self.allowed_hosts = allowed_hosts
        self.timeout = timeout
        self.max_tasks = max(1, min(max_tasks, MAX_TASKS * 2))
        self.task_steps = max(4, task_steps)
        self.parallel = max(1, min(parallel, 6))
        self.budget = budget or Budget()
        self.artifacts = artifacts or RunArtifacts(target, enabled=False)
        self.surface = surface or AttackSurface(target=target, mode=mode, path=self.artifacts.surface_path)
        self.auth_profiles = auth_profiles or {}
        self.rate_limit = rate_limit
        self.verbose = verbose
        self.callbacks = callbacks or SwarmCallbacks()
        self.memory = memory
        self.verify = verify
        self.ledger = TaskLedger()
        self.events: list[dict[str, Any]] = []
        #: 可离线审计的运行轨迹（trace.jsonl）。落在运行产物目录里，
        #: 追加写、逐条 flush——运行被中断时"已经发生的事"仍然读得到。
        trace_path = (
            (self.artifacts.dir / "trace.jsonl") if self.artifacts.enabled else None
        )
        self.trace = TraceRecorder(
            trace_path,
            enabled=self.artifacts.enabled,
            target=target,
            goal=goal,
            mode=mode,
        )
        #: 有界动态重规划的轮数政策（上限见 replan.MAX_REPLAN_ROUNDS）。
        self.replan_policy = ReplanPolicy()
        #: 本次运行开始前，跨运行记忆里已有的 findings（用于跨运行 diff）
        self.previous_findings: list[dict[str, Any]] = []
        self.previous_run_at: str = ""
        if memory is not None:
            self.previous_findings = list(memory.known_findings(200))
            self.previous_run_at = str(memory.data.get("updated_at") or "")
        self._lock = threading.Lock()
        self._counter = 0

    # ---------- 内部工具 ----------

    def _llm_for(self, role: str) -> LLMClient:
        """取该角色应使用的模型客户端（没配就用默认）。"""
        return self.llm_pool.get(role) or self.llm

    def _llm_label(self, role: str) -> str:
        """该角色所用模型的展示名。

        容错：任何"客户端没有 describe()"的替身（测试用的脚本 LLM、第三方包装）
        都不该让一个子任务直接失败——模型名只是日志信息。
        """
        client = self._llm_for(role)
        describe = getattr(client, "describe", None)
        if callable(describe):
            try:
                return str(describe())
            except Exception:  # noqa: BLE001 展示信息取不到就算了
                pass
        model = getattr(client, "model", "") or getattr(client, "_model", "")
        provider = getattr(client, "provider", "")
        return f"{provider}/{model}" if provider and model else str(model or "unknown")

    def describe_models(self) -> dict[str, str]:
        """各角色实际使用的模型（写进日志/报告，便于复现一次运行）。"""
        roles = set(self.llm_pool) | {"planner"}
        return {role: self._llm_label(role) for role in sorted(roles)}

    def _next_worker_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"W{self._counter}"

    def _event(self, **payload: Any) -> None:
        with self._lock:
            self.events.append({"at": len(self.events), **payload})
        self.callbacks.emit(**payload)
        # 编排层事件（计划/波次/任务起止/补扫/时间闸门）同样进 trace：
        # 离线审计要回答的不只是"调了什么工具"，还有"为什么后来又开了一波"。
        if self.trace is not None:
            kind = str(payload.get("kind") or "event")
            task = (
                str((payload.get("task") or {}).get("id") or "")
                if isinstance(payload.get("task"), dict)
                else ""
            )
            # 同理：payload 里也有 `kind`，与 `record(kind=...)` 撞名，必须改名。
            data = {
                ("event_kind" if key == "kind" else key): value
                for key, value in payload.items()
                if key != "task"
            }
            self.trace.record(f"orchestrator_{kind}", task=task, **data)

    def _stopped(self) -> bool:
        if self.callbacks.should_stop is not None and self.callbacks.should_stop():
            return True
        return not self.budget.can_spend()

    def _time_left(self) -> float | None:
        """剩余墙钟时间（秒）；未设 `MAX_SECONDS` 时返回 None。"""
        return self.budget.remaining_seconds()

    def _may_start_wave(self, stage: str, *, need: float = SWEEP_MIN_SECONDS) -> bool:
        """波次边界闸门：时间不够就别开新的一波。

        只在**波次之间**判断，不打断已启动的波次——半途掐断会让子代理
        来不及写结论，比"这一波根本没开始"更糟（产出全丢）。

        每次拒绝都写进事件流，报告里能看出"为什么后面几波没跑"。
        """
        if self._stopped():
            return False
        left = self._time_left()
        if left is None or left >= need:
            return True
        self._event(
            kind="time_budget_stop",
            stage=stage,
            remaining=round(left, 1),
            needed=need,
            message=(
                f"剩余时间 {left:.0f}s 不足以再开一波（{stage} 至少需要 {need:.0f}s），"
                "已跳过该波次。报告里会如实标注哪些补扫没有执行。"
            ),
        )
        return False

    # ---------- 规划 ----------

    def plan(self) -> list[WorkerTask]:
        """让编排者产出任务计划；解析失败则用确定性兜底计划。

        规划发生在**侦察之前**，所以编排者看不到本次将要发现的东西。这里做两件事补偿：
        1. 把「历史上命中过的参数」和「沙箱里有哪些真工具」写进规划提示词；
        2. 计划出来后做一次确定性偏置——有带参端点却没有注入类任务时补一个，
           并强制走 sqlmap（否则模型会一直用内置 payload，跑不出工具级证据）。
        """
        if self.mode == "source" and not self.surface.endpoints:
            return [
                WorkerTask(
                    id="T1",
                    role="source",
                    objective=(
                        f"审计源码目录并对 {self.target} 做黑盒验证："
                        "list_files/read_file/search_code 定位可疑点，再 http_request 复现，"
                        "证据成立才 record_finding。"
                    ),
                    url=self.target,
                    steps=self.task_steps + 4,
                )
            ]
        brief = self.surface.to_llm_summary()
        memory_brief = self.memory.briefing(6) if self.memory else ""
        sandbox_brief = self._sandbox_brief_for_planner()
        history_brief = self._history_brief_for_planner()
        api_brief = self._api_spec_brief_for_planner()
        user = (
            f"<engagement>\n目标：{self.target}\n模式：{self.mode}（黑盒）\n任务总目标：{self.goal}\n</engagement>\n\n"
            f"<known_attack_surface>\n{brief}\n</known_attack_surface>\n\n"
            + (f"<long_term_memory>\n{memory_brief}\n</long_term_memory>\n\n" if memory_brief else "")
            + (api_brief + "\n\n" if api_brief else "")
            + (history_brief + "\n\n" if history_brief else "")
            + (sandbox_brief + "\n\n" if sandbox_brief else "")
            + f"<constraints>\n最多 {self.max_tasks} 个任务；每个任务 4–20 步；"
            "第一波必须能并行执行（不要有互相依赖的任务）。\n</constraints>\n\n"
            "请输出任务计划 JSON。"
        )
        messages = [
            {"role": "system", "content": ROLE_PROMPTS["orchestrator"]},
            {"role": "user", "content": user},
        ]
        if not self.budget.can_spend():
            return self._refine_plan(_fallback_plan(self.target, self.surface, self.max_tasks))
        try:
            content, usage = self._llm_for("planner").complete(messages)
            self.budget.add_usage(usage)
            if self.callbacks.on_usage is not None and hasattr(usage, "prompt_tokens"):
                self.callbacks.on_usage(
                    {
                        "prompt_tokens": int(getattr(usage, "prompt_tokens", 0) or 0),
                        "completion_tokens": int(getattr(usage, "completion_tokens", 0) or 0),
                        "cache_hit_tokens": int(getattr(usage, "cache_hit_tokens", 0) or 0),
                        "cache_miss_tokens": int(getattr(usage, "cache_miss_tokens", 0) or 0),
                        "estimated_cost": 0.0,
                        "total_tokens": int(getattr(usage, "total_tokens", 0) or 0),
                    }
                )
        except Exception as exc:  # noqa: BLE001 规划失败不该让整次运行失败
            self._event(kind="plan_error", message=f"规划阶段失败，改用默认计划：{exc}")
            return self._refine_plan(_fallback_plan(self.target, self.surface, self.max_tasks))
        tasks = self._refine_plan(
            _parse_plan(content, self.target, self.surface, self.max_tasks)
        )
        self._event(
            kind="plan",
            tasks=[task.to_dict() for task in tasks],
            reason=str(_plan_reason(content))[:300],
        )
        return tasks

    def _history_brief_for_planner(self) -> str:
        """把上次运行报过的漏洞喂给规划者，要求安排**回归复核**。

        为什么必须有：跨运行 diff 只有在"本次确实重测了上次的端点"时才敢说
        「疑似已修复」，否则全部落入 unknown。若规划者不知道历史问题存在，
        就永远不会去重测——diff 功能等于空转。
        """
        previous = self.previous_findings
        if not previous:
            return ""
        lines = [
            "<previous_findings>",
            f"上次运行（{self.previous_run_at or '时间未知'}）报过 {len(previous)} 条问题，"
            "本次必须安排回归复核（这是回归测试，不是重复劳动）：",
        ]
        for item in previous[:8]:
            lines.append(
                f"- {item.get('id', '')} [{item.get('severity', '')}] "
                f"{str(item.get('title') or '')[:60]} -> {item.get('url', '')}"
            )
        lines += [
            "</previous_findings>",
            "规划要求：至少安排 1 个任务专门重测上述端点（沿用上次的参数与方法，"
            "如 sqlmap_scan / http_request），并在结论里明确写「仍可复现」或「已不可复现」。"
            "没测到的端点会被报告标为「状态未知」——不要用推测代替复测。",
        ]
        return "\n".join(lines)

    def _sandbox_brief_for_planner(self) -> str:
        """告诉编排者本次挂了哪些真工具，以便它把工具用进任务目标里。"""
        if self.sandbox is None:
            return ""
        try:
            probe = self.sandbox.probe()
        except Exception:  # noqa: BLE001
            return ""
        if not probe.get("ok"):
            return ""
        tools = sorted(name for name, ok in (probe.get("tools") or {}).items() if ok)
        if not tools:
            return ""
        return (
            "<real_tools_available>\n"
            f"本次运行挂了真渗透工具沙箱（{probe.get('runtime', '?')}），可用工具：{', '.join(tools)}。\n"
            "规划时请**把工具写进任务目标**：\n"
            "- 有带参端点（尤其 login/search/list/detail 或参数名含 id、q、name 等）→ "
            "安排一个注入验证任务，并要求「用 sqlmap_scan 确认并留证」；\n"
            "- 首次接触目标做端口/服务发现 → 要求「用 port_scan」；\n"
            "- 需要技术栈版本 → 要求「用 web_fingerprint」；\n"
            "- 需要找隐藏路径 → 要求「用 dir_bruteforce」；\n"
            "- 需要扫已知问题 → 要求「用 template_scan」；\n"
            "- **看到会改状态的接口**（优惠券/兑换/余额/积分/库存/限额/下单/一次性令牌/重置密码）→ "
            "单独安排一个任务，要求「用 sandbox_script 写并发脚本验证能否重复消费（串行 1 次成功、"
            "并发 N 次是否成功多次）」，这类问题单发请求测不出来；\n"
            "- **看到配置/前端 JS 里泄露 secret、jwt、sign 关键字，或有 /admin 这类 403 接口** → "
            "安排一个认证任务，要求「用 sandbox_script 拿泄露密钥/可预测令牌自己造一个凭据，"
            "再访问受保护接口」；\n"
            "任务目标里写明工具名，执行者才会真的用它。\n"
            "</real_tools_available>"
        )

    def _api_spec_brief_for_planner(self) -> str:
        """把导入的 API 合约清单喂给规划者。

        为什么要单独一段（而不是靠攻面简报）：攻面简报是"已发现的东西"的长列表，
        API 规范给的是**权威的接口清单**——方法、参数、认证要求都写在里面。
        规划者看不到这段，就不会为"规范里那 40 个没碰过的接口"安排任务，
        导入也就白导了。
        """
        summary = getattr(self.surface, "api_spec_summary", None)
        if not callable(summary):
            return ""
        info = summary()
        imports = info.get("imports") or []
        if not imports:
            return ""
        lines = ["<api_contract>"]
        for entry in imports:
            lines.append(
                f"已导入 API 规范：{entry.get('spec_label') or '未知格式'}"
                f"（来源 {entry.get('source')}）"
                f"，标题《{entry.get('title') or '未命名'}》"
                f"，共 {entry.get('operations')} 个接口。"
            )
            if entry.get("declared_servers"):
                lines.append(
                    "  规范里声明的 servers/host 已被**忽略**："
                    "所有接口都锚定到本次的 target，规范不能扩大授权范围。"
                )
            if entry.get("security_schemes"):
                lines.append(
                    "  规范声明的认证方案：" + "、".join(entry["security_schemes"][:8])
                )
            if entry.get("skipped"):
                lines.append(
                    f"  ⚠ 有 {len(entry['skipped'])} 条没能导入（解析/安全策略拒绝），"
                    "报告里会列出原因。"
                )
        lines.append(
            f"这些接口已进入共享攻面（{info.get('endpoints', 0)} 个端点 / "
            f"{info.get('params', 0)} 个已声明参数），**全部算覆盖率闸门的待测目标**："
            "每个接口最终必须有结论（record_finding 或 record_coverage）。"
        )
        lines.append(
            "规划要求：把**规范里声明了参数的接口**安排给 injection（参数级测试），"
            "把声明了认证要求的接口安排给 auth（越权/未授权），"
            "不要只依赖爬虫发现的端点——规范给出的接口列表比爬取结果更完整。"
        )
        sample = info.get("endpoint_sample") or []
        if sample:
            lines.append("接口样例：")
            lines += [f"  - {url}" for url in sample[:15]]
        lines.append("</api_contract>")
        return "\n".join(lines)

    def _refine_plan(self, tasks: list[WorkerTask]) -> list[WorkerTask]:
        """对计划做确定性偏置：有带参端点却没安排注入任务时补一个（并指定 sqlmap）。

        为什么必须做：规划在侦察之前，编排者看不到"有 /login?username= 这种端点"，
        于是经常只安排侦察和越权任务——真工具永远没机会上场（实测复现过）。
        """
        injectable = _injectable_endpoints(self.surface, limit=3)
        if not injectable or _sqlmap_task_exists(tasks):
            return tasks
        already = {task.url for task in tasks if task.role == "injection"}
        target_url = next((url for url in injectable if url not in already), injectable[0])
        if len(tasks) >= self.max_tasks:
            # 名额满了：把最不具体的一个 injection 任务改写掉，而不是硬塞
            for task in tasks:
                if task.role == "injection" and "sqlmap" not in task.objective.lower():
                    task.objective = (
                        f"对 {task.url or target_url} 做注入验证：**先用 sqlmap_scan**"
                        "（--data 传表单或 url 带 query）确认是否存在 SQL 注入并留证，"
                        "证据成立后 record_finding（evidence_ref 用 T 编号）。"
                    )
                    task.url = task.url or target_url
                    break
            return tasks
        tasks.append(
            WorkerTask(
                id=f"T{len(tasks) + 1}",
                role="injection",
                objective=(
                    f"对 {target_url} 做注入验证：**用 sqlmap_scan** 确认该端点是否存在 SQL 注入"
                    "（带参端点，表单用 data 参数），拿到 payload/注入类型/DBMS 版本作为证据；"
                    "若确认成立，record_finding 时 evidence_ref 引用工具证据编号（T 开头），"
                    "verification 写明重跑命令。"
                ),
                url=target_url,
                steps=self.task_steps,
            )
        )
        self._event(
            kind="plan_refine",
            message=f"计划缺少注入任务，已自动补上 sqlmap 任务：{target_url}",
        )
        return tasks

    # ---------- 执行 ----------

    def _run_task(self, task: WorkerTask) -> WorkerTask:
        if self._stopped():
            task.outcome = "skipped"
            task.error = "预算/用户停止"
            return task
        self.ledger.add(task.id, task.role, task.objective, model=self._llm_label(task.role))
        self.ledger.start(task.id)
        self._event(
            kind="task_start",
            task=task.to_dict(),
            model=self._llm_label(task.role),
        )
        if self.verbose:
            print(f"\n>>> [{task.id}] {task.role} ({self._llm_label(task.role)}): {task.objective}")
        role_llm = self._llm_for(task.role)
        worker = TaskWorker(
            role_llm,
            task=task,
            base_dir=self.base_dir,
            allowed_hosts=self.allowed_hosts,
            timeout=self.timeout,
            surface=self.surface,
            budget=self.budget,
            artifacts=self.artifacts,
            auth_profiles=self.auth_profiles,
            rate_limit=self.rate_limit,
            verbose=self.verbose,
            callbacks=self.callbacks,
            worker_id=self._next_worker_id(),
            sandbox=self.sandbox,
            trace=self.trace,
        )
        try:
            task.result = worker.run()
            # 子任务"跑完"不等于"跑好了"：被预算掐断、被监督器中止、
            # 或撞到步数上限仍未收尾的，都要如实标出来，否则调用方（CLI/GUI/报告）
            # 会把"达到最大步数仍未收尾"当成成功完成。
            task.outcome = _outcome_for(task.result)
        except Exception as exc:  # noqa: BLE001 单个子任务失败不影响整次运行
            task.outcome = "failed"
            task.error = f"{type(exc).__name__}: {exc}"
        # 用量取自**任务自己的账本**，而不是"全局快照前后差值"：
        # 并发时差值会把邻居的消耗算进来（实测一个 0 步任务的台账里出现过几万 token）。
        usage = worker.task_usage
        self.ledger.update_usage(
            task.id,
            steps=task.result.steps_used if task.result else 0,
            llm_calls=usage.llm_calls,
            tool_calls=usage.tool_calls,
            total_tokens=usage.total_tokens,
            estimated_cost=usage.estimated_cost,
        )
        self.ledger.finish(
            task.id,
            status="done" if task.outcome in CLOSED_OUTCOMES else "failed",
            summary=task.result.final_summary if task.result else "",
            error=task.error,
        )
        self._event(kind="task_end", task=task.to_dict())
        return task

    def run_wave(self, tasks: list[WorkerTask], wave: int = 1) -> list[WorkerTask]:
        """并发执行一波任务（最多 self.parallel 个同时跑）。"""
        for task in tasks:
            task.wave = wave
        if not tasks:
            return []
        if len(tasks) == 1 or self.parallel == 1:
            return [self._run_task(task) for task in tasks]
        results: list[WorkerTask] = []
        with ThreadPoolExecutor(max_workers=min(self.parallel, len(tasks))) as pool:
            futures = {pool.submit(self._run_task, task): task for task in tasks}
            for future in as_completed(futures):
                task = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001 兜底
                    task.outcome = "failed"
                    task.error = f"{type(exc).__name__}: {exc}"
                    results.append(task)
        order = {task.id: index for index, task in enumerate(tasks)}
        results.sort(key=lambda item: order.get(item.id, 99))
        return results

    # ---------- 复核 ----------

    def verification_tasks(self) -> list[WorkerTask]:
        """为候选池生成复核任务（按候选数量决定是否分片）。"""
        candidates = self.surface.pending_candidates()
        if not candidates:
            return []
        if len(candidates) <= 3:
            chunks = [candidates]
        else:
            size = max(2, (len(candidates) + 1) // 2)
            chunks = [candidates[index : index + size] for index in range(0, len(candidates), size)]
        tasks: list[WorkerTask] = []
        for index, chunk in enumerate(chunks[:2], start=1):
            listing = "；".join(f"{item.id}={item.title}" for item in chunk)
            tasks.append(
                WorkerTask(
                    id=f"V{index}",
                    role="verify",
                    objective=(
                        "复核以下候选，逐条重放证据请求确认是否仍可复现："
                        + listing
                        + "。可复现的用 record_finding(verified=true, evidence_ref=[...], verification=\"...\") 提升；"
                        "不可复现的不要提升，在 finish_task 的 summary 里说明判否理由。"
                    ),
                    url=self.target,
                    steps=max(6, min(4 + 2 * len(chunk), 16)),
                )
            )
        return tasks

    # ---------- 覆盖率强制 ----------

    def _touched_endpoints(self) -> set[str]:
        """收集"确实被碰过"的端点集合（实现在 `Surface.touched_endpoints`）。

        放在 Surface 上是因为有三个消费者：覆盖率闸门、覆盖补扫、跨运行 diff——
        diff 判 fixed 必须和闸门用**同一份**覆盖判据，否则会出现"报告说覆盖了、
        diff 说没覆盖"的自相矛盾。
        """
        return self.surface.touched_endpoints()

    def untested_targets(self) -> list[str]:
        """找出"登记了但从未被碰过"的端点。

        判据是**确定性**的（不看模型说了什么）：端点不在 `_touched_endpoints()` 里。
        用于收尾前的强制补扫与报告里的盲区清单。
        """
        touched = self._touched_endpoints()
        with self.surface._lock:  # noqa: SLF001
            endpoints = list(self.surface.endpoints.values())
        untouched: list[str] = []
        for endpoint in endpoints:
            if endpoint.url in touched:
                continue
            # 同路径不同 query 形态也算碰过（例如 endpoint 是 /api/user，实测打了 /api/user?uid=1）
            if any(url.split("?", 1)[0] == endpoint.url for url in touched):
                continue
            untouched.append(endpoint.url)
        return sort_urls(untouched)

    def coverage_ratio(self) -> tuple[int, int]:
        """(已触达端点数, 端点总数)。"""
        with self.surface._lock:  # noqa: SLF001
            total = len(self.surface.endpoints)
        touched = self._touched_endpoints()
        hit = 0
        for url in self.surface.endpoints:
            if url in touched or any(t.split("?", 1)[0] == url for t in touched):
                hit += 1
        return hit, total

    def coverage_sweep_tasks(
        self, max_tasks: int = 2, per_task: int = 4, round_index: int = 0
    ) -> list[WorkerTask]:
        """为未测端点生成补扫任务——**不依赖模型自觉**。

        为什么必须做：实测一次运行里 12 个端点只碰了 3 个（25%），剩下 9 个只是
        在报告里"列出来"。报告看着完整、实际漏一半，这比不报更危险
        （读者会以为"扫过了没问题"）。
        """
        pending = self.untested_targets()
        if not pending:
            return []
        # 优先补有参数的端点：它们才可能有注入/越权类问题
        with self.surface._lock:  # noqa: SLF001
            with_params = [url for url in pending if self.surface.endpoints[url].params]
        ordered = with_params + [url for url in pending if url not in with_params]
        if not ordered:
            return []
        tasks: list[WorkerTask] = []
        for index in range(max_tasks):
            chunk = ordered[index * per_task : (index + 1) * per_task]
            if not chunk:
                break
            listing = "\n".join(f"  - {url}" for url in chunk)
            tasks.append(
                WorkerTask(
                    id=f"C{round_index * max_tasks + index + 1}",
                    role="recon",
                    objective=(
                        "对以下**尚未被任何子代理碰过**的端点做覆盖性排查：\n"
                        f"{listing}\n"
                        "做法：逐个用 http_request 取一次响应，判断是否值得深挖"
                        "（带参数的端点用 fuzz_params 或 sqlmap_scan、看是否返回敏感数据、"
                        "是否泄露报错/版本）。\n"
                        "**必须对每个端点给出结论**：发现问题就 record_finding（带证据）；"
                        "没问题就用 record_coverage(status=\"no_issue_found\" 或 \"ruled_out\") 记清楚。\n"
                        "这是为了消除报告里「列出来了但没测」的盲区，别跳过任何一条。"
                    ),
                    url=self.target,
                    steps=max(6, min(3 * len(chunk) + 4, 18)),
                )
            )
        return tasks

    def unattacked_params(self, limit: int | None = None) -> list[tuple[str, str]]:
        """`(端点, 参数)` —— 参数登记了但从未被攻击过（参数级盲区，见 Surface 的说明）。"""
        return self.surface.unattacked_params(limit)

    def param_sweep_tasks(
        self, max_tasks: int = 2, per_task: int = 4, round_index: int = 0
    ) -> list[WorkerTask]:
        """为"从未被攻击过的参数"生成注入任务——端点级覆盖之外的第二道闸门。

        为什么需要：端点被 GET 过一次就算"已覆盖"，但**参数从未被试过**。
        实测一次运行显示 100% 覆盖，而 `/ping?ip=`（命令注入）与 `/ssti?name=`（模板注入）
        这两个侦察阶段就已发现的候选面根本没被打过——报告因此"看着完整"。
        """
        pending = self.unattacked_params()
        if not pending:
            return []
        tasks: list[WorkerTask] = []
        for index in range(max_tasks):
            chunk = pending[index * per_task : (index + 1) * per_task]
            if not chunk:
                break
            listing = "\n".join(f"  - {url} 参数[{param}]" for url, param in chunk)
            tasks.append(
                WorkerTask(
                    # 编号带轮次：补扫可能跑两轮，同 id 会在台账/事件里撞车
                    id=f"P{round_index * max_tasks + index + 1}",
                    role="injection",
                    objective=(
                        "以下端点的参数**从未被真正攻击过**（只被读过一次），逐个做注入排查：\n"
                        f"{listing}\n"
                        "做法：先 http_request 取基线响应留证，再用 fuzz_params 逐个试"
                        "（SQL/命令注入/模板注入/路径穿越/XSS 都要试），带参端点优先用 "
                        "sqlmap_scan 或 compare_responses 留工具级证据。\n"
                        "**每个参数都必须有结论**：命中就 record_finding（带 evidence_ref）；"
                        "试过没问题就用 record_coverage(status=\"no_issue_found\") "
                        "把「哪个参数、试过哪些类别」写清楚——这是消除参数级盲区的唯一凭据。"
                    ),
                    url=self.target,
                    steps=max(6, min(3 * len(chunk) + 6, 18)),
                )
            )
        return tasks

    # ---------- 特殊类别：竞态 / 业务逻辑 / 认证实现 ----------
    #
    # 为什么要**确定性**地生成这些任务：v0.4 首跑实测——侦察角色明明发现了 /wallet、
    # 在 leave_note 里写下"可用泄露的 jwt secret 伪造 HS256 管理员令牌"，但没有任何
    # 角色去执行，整轮 0 条竞态/伪造类结论。这和当初"真工具从不被调用"是同一类失效：
    # 提示词给了能力，但没人负责用。所以这里按攻面特征直接派任务。

    def _sandbox_script_ready(self) -> bool:
        """脚本通道是否真的可用（沙箱 + python3）。不可用就别派任务浪费步数。"""
        if self.sandbox is None:
            return False
        try:
            if not self.sandbox.available():
                return False
            return bool(self.sandbox.tool_status().get("python3", False))
        except Exception:  # noqa: BLE001 探测失败当作不可用
            return False

    def _race_targets(self, limit: int = 4) -> list[str]:
        """挑出"会改状态"的端点：竞态与业务逻辑问题只可能出现在这类面上。"""
        with self.surface._lock:  # noqa: SLF001
            items = list(self.surface.endpoints.values())
        hits: list[str] = []
        for item in items:
            text = f"{item.url} {','.join(item.params)}".lower()
            if any(hint in text for hint in STATE_CHANGE_HINTS):
                hits.append(item.url)
        return sort_urls(hits, limit)

    def _protected_endpoints(self, limit: int = 3) -> list[str]:
        """受保护接口（401/403 或路径带 admin/manage）：伪造凭据的利用目标。"""
        with self.surface._lock:  # noqa: SLF001
            items = list(self.surface.endpoints.values())
        hits: list[str] = []
        for item in items:
            if item.status in (401, 403) or any(
                hint in item.url.lower() for hint in PROTECTED_HINTS
            ):
                hits.append(item.url)
        return sort_urls(hits, limit)

    def _leak_sources(self, limit: int = 3) -> list[str]:
        """可能泄露密钥的端点（配置/actuator/前端 JS/接口文档）。"""
        with self.surface._lock:  # noqa: SLF001
            items = list(self.surface.endpoints.values())
        hits = [
            item.url
            for item in items
            if any(hint in item.url.lower() for hint in SECRET_HINTS)
        ]
        return sort_urls(hits, limit)

    # ---------- 业务逻辑（价格 / 数量 / 步骤 / 幂等）----------

    def _commerce_surface(self) -> dict[str, list[str]]:
        """按语义挑出"电商/订单"这一类面。

        为什么单独找：业务逻辑漏洞**不吃 payload**，它吃的是"服务端少了一道校验"。
        要测它，必须先认出"这是一条下单链路"——加购 → 确认 → 查订单。
        只靠通用词表找不出这层关系，因此这里按路径语义分组。
        """
        with self.surface._lock:  # noqa: SLF001
            items = list(self.surface.endpoints.values())
        groups: dict[str, list[str]] = {
            "cart": [], "confirm": [], "prepare": [], "detail": [],
        }
        for item in items:
            url = item.url.lower()
            if any(hint in url for hint in ("/cart", "basket", "shopping")):
                groups["cart"].append(item.url)
            is_confirm = any(
                hint in url for hint in ("confirm", "checkout", "submit_order", "place_order")
            )
            is_prepare = any(
                hint in url for hint in ("prepare", "pre_order", "order/init", "step")
            )
            if is_confirm:
                groups["confirm"].append(item.url)
            if is_prepare:
                groups["prepare"].append(item.url)
            # 查询单个订单的端点：**排除**确认/前置步骤类，
            # 否则 `/order/confirm` 会同时落进 confirm 与 detail 两组，
            # 派任务时把"下单接口"当成"查订单接口"用。
            if (
                any(hint in url for hint in ("/order/", "/orders/"))
                and not is_confirm
                and not is_prepare
            ):
                groups["detail"].append(item.url)
        return {
            key: sort_urls(value)
            for key, value in groups.items()
        }

    def business_logic_tasks(self, limit: int = 1) -> list[WorkerTask]:
        """生成**确定性**的业务逻辑测试任务（价格篡改 / 负数数量 / 跳过步骤 / 重复提交）。

        与竞态任务（S1）同样的理由：实测里"提示词给了能力但没人负责用"必然发生。
        这一类更严重——业务逻辑不触发任何 payload 类信号，模型除非**专门去想**
        "这个金额能不能由客户端说了算"，否则永远不会去试。
        所以这里按攻面特征机械派发。

        前提：必须能认出"这是一条下单链路"（至少有购物车/确认类端点之一）。
        认不出来就不派——瞎猜业务规则比不测更糟（会产出无证据的结论）。
        """
        groups = self._commerce_surface()
        cart = groups["cart"]
        confirm = groups["confirm"]
        if not cart and not confirm:
            return []
        endpoints = cart + [url for url in confirm if url not in cart]
        listing = "\n".join(f"  - {url}" for url in endpoints[:6])
        steps = max(8, min(3 * len(endpoints) + 8, 18))
        return [
            WorkerTask(
                id="B1",
                role="injection",
                objective=(
                    "**业务逻辑测试**：下面是一条下单链路，逐条验证服务端是否真的在校验"
                    "（这类问题不触发任何 payload 信号，必须主动想「钱和数量能不能由客户端说了算」）：\n"
                    f"{listing}\n"
                    "先侦察再判定：用 http_request 读一次（GET）拿清了字段名与正常流程，"
                    "然后逐项验证下面 4 种典型缺陷。**每一项都要给出可核对的证据**"
                    "（请求 + 响应关键字段 + 前后状态对比），成立就 record_finding，"
                    "不成立也要 record_coverage 写清试过什么。\n"
                    "1) **价格篡改**：加购/下单时把客户端提交的 `price` 改成一个极低价"
                    "（如 0.01），或干脆不传 price。看服务端是**按自己目录里的单价重算**，"
                    "还是接受客户端价格。判据：同一商品用低价提交后，"
                    "合计/订单金额是否变成你提交的价（而不是服务端单价）。\n"
                    "2) **负数或异常数量**：qty 传 -1 / -5 / 0 / 极大值。"
                    "判据：服务端是否拒绝；不拒绝就会让合计或订单金额变成负数。\n"
                    "3) **跳过步骤**：**只**调确认类接口（不先加购物车、不调其它前置步骤），"
                    "请求体里直接给 sku/qty/price。判据：是否照样下单成功。\n"
                    "4) **重复提交 / 无幂等**：同一份购物车连续确认 2~3 次（不要并发，"
                    "串行即可——这一条测的是缺幂等键，不是竞态）。"
                    "判据：是否产生**多张**订单、是否重复扣库存。\n"
                    "证据要求（缺一不可）：每条结论都要有 request 响应原文（evidence_ref 用 R 编号）"
                    "与**前后状态对比**（金额/订单号/库存数量）。"
                    "只凭「没报错」不算证据——要说清「钱少了多少」或「多出了几张订单」。"
                ),
                url=endpoints[0],
                steps=steps,
            )
        ]

    def special_class_tasks(self, limit: int = 2) -> list[WorkerTask]:
        """生成竞态/业务逻辑与认证实现两类**确定性**任务（不依赖模型自觉）。

        两类各最多一个任务；`limit` 控制总数，方便预算紧时只派一个。
        """
        if not self._sandbox_script_ready():
            return []
        tasks: list[WorkerTask] = []
        raced = self._race_targets()
        if raced:
            listing = "\n".join(f"  - {url}" for url in raced)
            tasks.append(
                WorkerTask(
                    id="S1",
                    role="injection",
                    objective=(
                        "对以下**会改状态**的端点做并发竞态测试（单发请求测不出来，"
                        "必须用 sandbox_script 写并发脚本）：\n"
                        f"{listing}\n"
                        "做法：\n"
                        "0) 先找一个**可用的输入**（有效券码/令牌/订单号）——这类值常出现在"
                        "首页文案、前端 JS、接口文档、上一轮的响应里；拿不到就先读这些位置，"
                        "不要拿猜的值直接下「无问题」的结论；\n"
                        "1) **串行基线与并发突发必须用两份不同的输入**（两张券，或两个账号）。"
                        "单次券被串行那次消费掉之后再并发打同一张券，只会全部被拒，"
                        "看起来像「没有竞态」——那是**测试设计错误**，不是结论。顺序：\n"
                        "   a. 券 A 串行 1 次：确认正常流程成功，记录成功后的状态；\n"
                        "   b. 券 B（或全新账号）**只做并发**：threading.Barrier 对齐起跑线，"
                        "同时发 N=5~10 个相同请求（带会话 cookie）；\n"
                        "   c. 数成功次数，并**再查一次状态**（余额/计数/发放记录）。\n"
                        "判据（缺一不可）：串行只成功 1 次、并发成功 >1 次、状态持久变化。\n"
                        "成立就 record_finding（evidence_ref 用脚本执行的 T 编号，evidence 里写"
                        "串行/并发的成功次数与前后状态）；不成立也要 record_coverage 写清"
                        "「并发 N=10 无重复生效」这类可核对的结论。"
                    ),
                    url=raced[0],
                    steps=max(8, min(4 * len(raced) + 6, 18)),
                )
            )
        protected = self._protected_endpoints()
        leaks = self._leak_sources()
        if protected and leaks and len(tasks) < limit:
            tasks.append(
                WorkerTask(
                    id="K1",
                    role="auth",
                    objective=(
                        "认证实现排查：以下接口**受保护**（返回 401/403）：\n"
                        + "\n".join(f"  - {url}" for url in protected)
                        + "\n这些位置可能泄露密钥或令牌结构：\n"
                        + "\n".join(f"  - {url}" for url in leaks)
                        + "\n做法（用 sandbox_script，不要只用单发请求）：\n"
                        "1) 先读泄露源，找 secret / jwt / sign / token / api_key 等关键值；\n"
                        "2) 拿到密钥就**自己签一个**管理员令牌（HS256，payload 里 role=admin），"
                        "或试 alg=none 去签名、试可预测的会话令牌（形如 user:tok-user-demo）；\n"
                        "3) 用伪造凭据请求受保护接口，**看到 200 + 受保护数据**才算成立。\n"
                        "成立就 record_finding（evidence_ref 用脚本执行的 T 编号，evidence 里写清"
                        "密钥来源、伪造过程、成功响应）；不成立用 record_coverage 记 ruled_out"
                        "并说明试过哪些伪造方式。"
                    ),
                    url=protected[0],
                    steps=max(8, min(4 * (len(protected) + len(leaks)) + 6, 18)),
                )
            )
        return tasks[:limit]

    def coverage_gate(self) -> dict[str, Any]:
        """覆盖率闸门：收尾前判断"还有多少端点/参数没被碰过"。

        返回 {total, touched, untouched, ratio, untouched_sample,
              params_total, params_attempted, params_unattacked, unattacked_sample}。
        两层判据缺一不可：端点级看"有没有请求过"，参数级看"参数有没有被试过"。
        """
        touched, total = self.coverage_ratio()
        untouched = self.untested_targets()
        unattacked = self.unattacked_params()
        params_tried, params_total = self.surface.param_coverage()
        return {
            "total": total,
            "touched": touched,
            "untouched": len(untouched),
            "ratio": round(touched / total, 3) if total else 1.0,
            "untouched_sample": untouched[:10],
            "params_total": params_total,
            "params_attempted": params_tried,
            "params_unattacked": len(unattacked),
            "params_ratio": round(params_tried / params_total, 3) if params_total else 1.0,
            "unattacked_sample": [f"{url} 参数[{param}]" for url, param in unattacked[:10]],
        }

    # ---------- 汇总 ----------

    def _aggregate(self, tasks: list[WorkerTask]) -> AgentResult:
        """把各子任务结果合并成一次运行的最终结果（含去重）。"""
        findings = self.surface.finding_dicts()
        deduped, merged = dedupe_findings(findings)
        if merged:
            self._event(kind="dedupe", merged=merged)
        self._finalise_coverage(deduped, tasks)
        steps: list[dict[str, Any]] = []
        prompt = completion = total = hit = miss = 0
        cost = 0.0
        stop_reasons: list[str] = []
        for task in tasks:
            result = task.result
            if result is None:
                continue
            for step in result.steps:
                step = dict(step)
                step["task"] = task.id
                step["role"] = task.role
                steps.append(step)
            prompt += result.prompt_tokens
            completion += result.completion_tokens
            total += result.total_tokens
            hit += result.cache_hit_tokens
            miss += result.cache_miss_tokens
            cost += result.estimated_cost
            if result.finish_reason in ("budget", "supervisor_abort", "provider_error"):
                stop_reasons.append(f"{task.id}: {result.final_summary[:80]}")
        summaries = [
            f"[{task.id}/{task.role}] {task.result.final_summary}" if task.result and task.result.final_summary
            else f"[{task.id}/{task.role}] （无总结，状态 {task.outcome}）"
            for task in tasks
        ]
        budget_reasons = self.budget.stop_reasons()
        if budget_reasons:
            stop_reasons.extend(budget_reasons)
        final = "\n".join(summaries)
        if stop_reasons:
            final += "\n\n停止原因：" + "；".join(dict.fromkeys(stop_reasons))
        # 报告附录用 **T 编号证据**（各子任务的 registry.sandbox_log 合并去重）：
        # finding 里引用的是 T 编号，附录必须能按同一个编号查到那条命令。
        # 只有内部运维操作（安装/探测，X 编号）时才退回落盘日志，保证附录不为空。
        evidence: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for task in tasks:
            for entry in getattr(task.result, "tool_log", None) or []:
                key = str(entry.get("id") or "")
                if key and key in seen_ids:
                    continue
                seen_ids.add(key)
                evidence.append(entry)
        if not evidence and self.sandbox is not None:
            evidence = list(getattr(self.sandbox, "_exec_log", []) or [])
        return AgentResult(
            steps=steps,
            findings=deduped,
            final_summary=final,
            prompt_tokens=prompt,
            completion_tokens=completion,
            cache_hit_tokens=hit,
            cache_miss_tokens=miss,
            estimated_cost=cost,
            total_tokens=total,
            steps_used=len(steps),
            finish_reason="budget" if budget_reasons else "finish",
            surface=self.surface,
            tasks=[task.to_dict() for task in tasks],
            artifacts_dir=str(self.artifacts.dir) if self.artifacts.enabled else "",
            poc_paths={str(item.get("id")): str(item.get("poc_path") or "") for item in deduped},
            deduped=merged,
            models=self.describe_models(),
            sandbox=sandbox_report(self.sandbox),
            tool_log=evidence,
            coverage_gate=self.coverage_gate(),
            previous_findings=self.previous_findings,
            previous_run_at=self.previous_run_at,
            trace_summary=(
                summarize_trace(self.trace.events()) if self.trace is not None else {}
            ),
        )

    def _finalise_coverage(self, findings: list[dict[str, Any]], tasks: list[WorkerTask]) -> None:
        """收尾时补齐覆盖面记录（对标 Strix 的 coverage 收口）。

        子代理经常忘记写 coverage，导致报告只能说"发现了什么"、说不出"覆盖到哪"。
        这里做一次确定性收口：
        - 每个已复核漏洞对应的端点 → `reported`；
        - 攻面里登记过、有参数、但始终没有尝试记录的端点 → `not_tested`；
        - 失败/被跳过的子任务 → `blocked`（写明原因）。
        """
        for finding in findings:
            url = str(finding.get("url") or "").strip()
            if not url:
                continue
            label = url + (f"（参数 {finding['param']}）" if finding.get("param") else "")
            self.surface.record_coverage(
                label, "reported",
                detail=str(finding.get("title") or "")[:120],
                owasp=str(finding.get("owasp") or ""),
            )
        reported = {
            normalize_endpoint(str(item.get("url") or ""))
            for item in findings
            if str(item.get("url") or "")
        }
        attempted = {key[0] for key in self.surface.attempts}
        for endpoint in self.surface.endpoints.values():
            if endpoint.url in reported or endpoint.url in attempted:
                continue
            if not endpoint.params:
                continue  # 无参数、也没测过的静态页面不值得占报告篇幅
            self.surface.record_coverage(
                endpoint.url,
                "not_tested",
                detail=f"未形成结论（{'+'.join(endpoint.methods) or 'GET'}，"
                f"含参数 {','.join(endpoint.params[:4])}）",
            )
        for task in tasks:
            if task.outcome in ABORTED_OUTCOMES:
                self.surface.record_coverage(
                    f"子任务 {task.id}（{task.role}）",
                    "blocked",
                    detail=(task.error or "预算/用户停止")[:150],
                )
            elif task.outcome in INCOMPLETE_OUTCOMES:
                # 未收尾 ≠ 没产出：把"活没干完"如实记进覆盖，而不是当成完成。
                # 收尾回合也没交出总结的（closing_failed）与撞步数上限同样处理。
                detail = {
                    "max_steps": "达到步数上限仍未收尾，可能仍有未覆盖的目标",
                    "closing_failed": (
                        "达到步数上限，且受限收尾回合内未交出总结，可能仍有未覆盖的目标"
                    ),
                    "provider_error": "模型调用中断，未跑完",
                    "parse_error": "模型输出无法解析，未跑完",
                    "budget": "预算用尽，未跑完",
                    "supervisor_abort": "重复动作被中止，未跑完",
                    "stopped": "用户中断，未跑完",
                }.get(task.outcome, "未跑完，可能仍有未覆盖的目标")
                self.surface.record_coverage(
                    f"子任务 {task.id}（{task.role}）",
                    "not_tested",
                    detail=detail,
                )

    def run(self) -> AgentResult:
        """完整流程：规划 → 第一波 → 补扫 → 复核波 → 汇总 → 落盘记忆。

        波次顺序有讲究：
        1. 计划里的任务（侦察 / 注入 / 认证）
        2. 侦察后的跟进波（新端点交给注入/认证角色）
        3. **端点级覆盖补扫**：把"登记了但没人碰过"的端点补齐
        4. **参数级覆盖补扫**：把"端点读过、参数没试过"的参数补上注入尝试
        5. 复核候选
        6. 汇总 + 覆盖闸门（把覆盖数字与未测清单写进报告）

        3/4 最多各跑两轮，且只在盲区确实缩小时继续。
        """
        tasks = self.plan()
        self._event(kind="wave", wave=1, count=len(tasks))
        done = self.run_wave(tasks, wave=1)
        # 侦察后再补一波：把侦察新发现的端点交给注入/认证角色。
        if self._may_start_wave("第 2 波（侦察后跟进）") and self.verify is not False:
            follow_up = self._follow_up_tasks(done)
            if follow_up:
                self._event(kind="wave", wave=2, count=len(follow_up))
                done.extend(self.run_wave(follow_up, wave=2))
        # 特殊类别（竞态/业务逻辑、认证实现）：按攻面特征**确定性**派任务。
        # 放在补扫之前：这两类更依赖"看懂业务"，越晚派越容易被步数上限挤掉。
        # 注意：不受 `coverage_sweep` 开关控制——那个开关管的是"补扫没碰过的端点/参数"，
        # 与"这两类问题必须有人去打"是两回事（早先耦合在一起，关掉补扫就把它们一起关了）。
        if self._may_start_wave("特殊类别任务波"):
            special = self.special_class_tasks()
            if special:
                self._event(
                    kind="special_tasks",
                    message=(
                        "按攻面特征派发特殊类别任务："
                        + "、".join(f"{t.id}({t.role})" for t in special)
                        + "（竞态/业务逻辑与认证实现，需要自定义脚本）"
                    ),
                )
                done.extend(self.run_wave(special, wave=2))
        # 业务逻辑（价格篡改 / 负数数量 / 跳过步骤 / 重复提交）：同样**确定性**派发。
        # 不放进 special_class_tasks 是因为那个函数以"脚本通道可用"为前提
        # （竞态必须写并发脚本），而业务逻辑用 http_request 串行就能测——
        # 没有沙箱时也不该漏掉这一类。
        if self._may_start_wave("业务逻辑任务波"):
            business = self.business_logic_tasks()
            if business:
                self._event(
                    kind="business_logic_tasks",
                    message=(
                        "按攻面特征派发业务逻辑任务："
                        + "、".join(f"{t.id}({t.role})" for t in business)
                        + "（价格篡改/负数数量/跳过步骤/重复提交）"
                    ),
                )
                done.extend(self.run_wave(business, wave=2))
        # 覆盖率补扫：未测端点/未攻击参数强制补上（这是报告可信度的前提）。
        # 最多两轮，且**只在确实缩小了盲区时**才继续——否则就是一个收敛不了的烧钱循环。
        # 每一波**开始之前**都要过 `_may_start_wave`：允许的时长不是"开始后无限跑"，
        # 而是"每一阶段都有资格入场的一次判定"。
        if not self._stopped() and self.coverage_sweep:
            for round_index in range(2):
                if not self._may_start_wave(f"覆盖率补扫第 {round_index + 1} 轮"):
                    break
                sweep = self.coverage_sweep_tasks(round_index=round_index)
                param_sweep = self.param_sweep_tasks(round_index=round_index)
                if not sweep and not param_sweep:
                    break
                before = self.coverage_gate()
                if sweep:
                    if not self._may_start_wave("端点补扫"):
                        break
                    self._event(
                        kind="coverage_sweep",
                        message=(
                            f"发现 {before['untouched']} 个端点从未被触碰"
                            f"（覆盖 {before['touched']}/{before['total']}），"
                            f"已安排 {len(sweep)} 个补扫任务"
                        ),
                    )
                    done.extend(self.run_wave(sweep, wave=3))
                if param_sweep:
                    if not self._may_start_wave("参数补扫"):
                        break
                    self._event(
                        kind="param_sweep",
                        message=(
                            f"发现 {before['params_unattacked']} 个参数从未被攻击过"
                            f"（参数覆盖 {before['params_attempted']}/{before['params_total']}），"
                            f"已安排 {len(param_sweep)} 个注入任务"
                        ),
                    )
                    done.extend(self.run_wave(param_sweep, wave=4))
                after = self.coverage_gate()
                progressed = (
                    after["untouched"] < before["untouched"]
                    or after["params_unattacked"] < before["params_unattacked"]
                )
                # ---- 波次边界：有界动态重规划 ----
                # 位置就在"一轮补扫跑完、下一轮开始之前"——这正是**唯一**允许
                # 改计划的时刻（波次内部不动计划：正在执行的目标被改掉，
                # 产出就与目标不对应了）。
                #
                # 触发条件：还有重规划额度，且**出现/变多了新盲区**。
                # `progressed` 说明补扫有效，那就不需要重规划；反之说明
                # 原计划没有覆盖到这些面，值得让规划者按现状调整一次。
                if not progressed or round_index == 0:
                    replanned = self._run_replan_round(after, done, tasks)
                    if replanned and self._may_start_wave("重规划新增任务波"):
                        self._event(kind="wave", wave=6, count=len(replanned))
                        done.extend(self.run_wave(replanned, wave=6))
                # 有盲区但一点没缩小 → 再跑一轮只会重复烧钱，如实留在报告里
                if not progressed or self._stopped():
                    break
        if self.verify and self._may_start_wave("复核波"):
            verify_tasks = self.verification_tasks()
            if verify_tasks:
                self._event(kind="wave", wave=5, count=len(verify_tasks))
                done.extend(self.run_wave(verify_tasks, wave=5))
        result = self._aggregate(done)
        self.artifacts.save_surface(self.surface)
        self.artifacts.save_ledger(self.ledger)
        # 覆盖率收口事件进 trace：离线审计要能看出"最后关闸时还剩多少盲区"。
        if self.trace is not None:
            self.trace.record_coverage("__run__", "finished", detail=str(result.coverage_gate))
            self.trace.record_budget(self.budget.snapshot())
        self.artifacts.save_summary(
            {
                "target": self.target,
                "goal": self.goal,
                "mode": self.mode,
                "tasks": result.tasks,
                "models": result.models,
                "sandbox": sandbox_report(self.sandbox),
                "stats": self.surface.stats(),
                "coverage": self.surface.coverage_summary(),
                "usage": self.budget.snapshot(),
                "deduped": result.deduped,
                # 离线审计：报告重建快照 + trace 摘要（对象引用同一个 trace 文件）
                "trace": {
                    **self.trace.status(),
                    "digest": self.trace.digest(),
                    "summary": summarize_trace(self.trace.events()),
                },
            }
        )
        # 报告重建快照：`hexhound report --run <dir>` 以后从这里恢复，
        # 而不是只拿 surface.json + tasks.json 拼一个缺了大半字段的 AgentResult。
        snapshot_path = write_snapshot(
            self.artifacts.dir,
            result,
            goal=self.goal,
            target=self.target,
            mode=self.mode,
            budget=self.budget.snapshot(),
            trace_digest=self.trace.digest(),
            trace_events=len(self.trace.events()),
            run_dir_name=self.artifacts.dir.name,
        )
        if snapshot_path is not None:
            result.artifacts_dir = str(self.artifacts.dir)
        if self.memory is not None:
            self.memory.record_run(
                tech=dict(self.surface.tech),
                notes=self.surface.notes,
                attempts=[vars(item) for item in self.surface.attempts.values()],
                findings=result.findings,
                endpoints=len(self.surface.endpoints),
            )
        return result

    # ---------- 有界动态重规划（只在波次边界）----------
    #
    # 对标 PentAGI 的 Refiner `subtask_patch`，但加了三道 HexHound 自己的约束：
    # 只在波次边界改计划、只能改白名单字段、有硬上限（见 replan.py）。
    # **重规划不能扩大授权范围**：新任务的 URL 主机必须与本次目标一致。

    def _replan_brief(self, gate: dict[str, Any], done: list[WorkerTask]) -> str:
        """给重规划者的现状简报（它只做增量决策，不重写整份计划）。"""
        pending = self.untested_targets()[:15]
        unattacked = [f"{url} 参数[{param}]" for url, param in self.unattacked_params()[:15]]
        finished = [task for task in done if task.outcome in CLOSED_OUTCOMES]
        unfinished = [task for task in done if task.outcome not in CLOSED_OUTCOMES]
        # 用 `OUTCOME_LABEL.get(task.outcome)` 而不是 `task.outcome_label`：
        # `WorkerTask` 只有 `to_dict()` 里的派生字段 `outcome_label`，
        # 直接当属性读会 AttributeError——实测把整次 audit 打挂了
        # （异常发生在波次边界的重规划里，一路冒到 CLI）。
        unfinished_text = (
            "（"
            + "、".join(
                f"{t.id}({OUTCOME_LABEL.get(t.outcome, t.outcome)})" for t in unfinished[:6]
            )
            + "）"
            if unfinished
            else ""
        )
        lines = [
            "<current_state>",
            f"已完成子任务：{len(finished)} 个；未收尾：{len(unfinished)} 个{unfinished_text}",
            f"端点覆盖：{gate.get('touched')}/{gate.get('total')}"
            f"；参数覆盖：{gate.get('params_attempted')}/{gate.get('params_total')}",
        ]
        if pending:
            lines.append("从未被触碰的端点：")
            lines += [f"  - {url}" for url in pending]
        if unattacked:
            lines.append("从未被攻击过的参数：")
            lines += [f"  - {item}" for item in unattacked]
        lines.append(
            "已记录的结论："
            f"{len([f for f in self.surface.finding_dicts() if f.get('status') != 'candidate'])} 条已复核 / "
            f"{len(self.surface.pending_candidates())} 条待复核"
        )
        lines.append("</current_state>")
        return "\n".join(lines)

    def _run_replan_round(
        self, gate: dict[str, Any], done: list[WorkerTask], plan: list[WorkerTask]
    ) -> list[WorkerTask]:
        """执行一轮重规划，返回新增的任务（不修改入参）。

        **整轮包在 try 里**：重规划是"锦上添花"的可选阶段，它的任何缺陷都
        不该让一次已经跑出结论的审计崩掉。实测教训：`_replan_brief` 里的一个
        AttributeError 一路冒到 CLI，把整次 audit 变成 exit 1——
        而那次运行其实已经发现了路径穿越与 SSRF 两条 critical。
        失败时记 `replan_error` 事件并返回空列表，主流程按原计划继续。
        """
        try:
            return self._replan_round_inner(gate, done, plan)
        except Exception as exc:  # noqa: BLE001 重规划不得影响主流程
            self._event(
                kind="replan_error",
                message=(
                    f"重规划阶段出错，已跳过（按原计划继续）：{type(exc).__name__}: {exc}"
                ),
            )
            if self.trace is not None:
                self.trace.record_error(
                    f"重规划阶段出错：{type(exc).__name__}: {exc}", kind="replan_error"
                )
            return []

    def _replan_round_inner(
        self, gate: dict[str, Any], done: list[WorkerTask], plan: list[WorkerTask]
    ) -> list[WorkerTask]:
        policy: ReplanPolicy = self.replan_policy
        if not policy.can_replan():
            return []
        prompt = self._replan_prompt(gate, done)
        if not prompt:
            return []
        if not self.budget.can_spend():
            return []
        try:
            content, usage = self._llm_for("planner").complete(prompt)
            self.budget.add_usage(usage)
        except Exception as exc:  # noqa: BLE001 重规划失败不该影响主流程
            self._event(
                kind="replan_error",
                message=f"重规划调用失败，按原计划继续：{type(exc).__name__}: {exc}",
            )
            return []
        if self.trace is not None:
            self.trace.record("replan_request", role="planner", gate=gate)
        try:
            ops = parse_patch(extract_json(content))
        except (ReplanError, ValueError) as exc:
            self._event(kind="replan_rejected", message=f"重规划输出无法解析，已忽略：{exc}")
            if self.trace is not None:
                self.trace.record("replan_rejected", reason=str(exc))
            return []

        entries = [self._entry_from_task(task) for task in plan]
        new_plan, result = apply_patch(
            entries,
            ops,
            allowed_hosts=self.allowed_hosts,
            target_host=self._target_host(),
            total_tasks=len(done) + len(plan),
            salt=self.target,
        )
        policy.take()
        if self.trace is not None:
            self.trace.record(
                "replan_applied",
                rounds=policy.rounds_used,
                applied=result.applied,
                rejected=result.rejected,
                ok=result.ok,
                reason=result.reason,
            )
        self._event(
            kind="replan",
            message=(
                f"第 {policy.rounds_used}/{policy.max_rounds} 轮重规划："
                f"应用 {len(result.applied)} 条、拒绝 {len(result.rejected)} 条"
            ),
        )
        for item in result.rejected:
            self._event(
                kind="replan_rejected",
                message=f"重规划请求被拒（{item.get('op')} {item.get('id') or ''}）：{item.get('reason')}",
            )
        # 只把**新增**的任务交给下一波；update/remove 影响的是尚未派发的任务，
        # 已经跑过的任务不动（改了目标，它的产出就与目标不对应了）。
        new_ids = {item["id"] for item in result.applied if item["op"] == "add"}
        added: list[WorkerTask] = []
        for entry in new_plan:
            if entry.id not in new_ids:
                continue
            added.append(
                WorkerTask(
                    id=entry.id,
                    role=entry.role,
                    objective=entry.objective,
                    url=entry.url or self.target,
                    steps=entry.steps,
                )
            )
        return added[: MAX_NEW_TASKS_PER_PATCH * policy.max_rounds]

    def _replan_prompt(self, gate: dict[str, Any], done: list[WorkerTask]) -> list[dict[str, str]]:
        """重规划提示词：要求输出**结构化 patch**，并明确硬约束。"""
        state = self._replan_brief(gate, done)
        if not state:
            return []
        instruction = (
            "你在做一次**运行中的计划调整**（不是重写整份计划）。\n"
            f"{state}\n\n"
            "只输出一个 JSON 对象：\n"
            '{"thought": "为什么这样调整", "ops": [\n'
            '  {"op": "add", "role": "recon|injection|auth|verify", '
            '"objective": "任务目标", "url": "完整 URL（必须与本次目标同主机）", '
            '"steps": 6, "depends_on": []},\n'
            '  {"op": "update", "id": "T2", "changes": {"objective": "…", "steps": 8}},\n'
            '  {"op": "remove", "id": "T3"}\n'
            "]}\n\n"
            "<constraints>\n"
            f"- 最多新增 {MAX_NEW_TASKS_PER_PATCH} 个任务；\n"
            "- 只能修改 objective / steps / depends_on / priority（改不了 id/role/url）；\n"
            "- **不允许把任务指向本次授权目标之外的主机**，哪怕它在白名单里；\n"
            "- 只在确实有新盲区时才新增任务；没有值得做的调整就输出 {\"ops\": []}。\n"
            "</constraints>"
        )
        return [
            {"role": "system", "content": ROLE_PROMPTS["orchestrator"]},
            {"role": "user", "content": instruction},
        ]

    @staticmethod
    def _entry_from_task(task: WorkerTask) -> PlanEntry:
        return PlanEntry(
            id=task.id,
            role=task.role,
            objective=task.objective,
            url=task.url,
            steps=task.steps,
            source="initial",
        )

    def _target_host(self) -> str:
        from urllib.parse import urlparse

        return (urlparse(self.target).hostname or "").lower()

    def _follow_up_tasks(self, done: list[WorkerTask]) -> list[WorkerTask]:
        """侦察完成后，把新发现的高价值端点补成第二波任务。

        注意：未收尾的子任务（`closing_failed` / `budget` / `supervisor_abort` …）
        其**产出仍然有效**——只是没来得及说"我做完了"。
        因此这里只看"哪些端点还没被注入/认证角色碰过"，不看子任务是否漂亮收尾。
        """
        already = {
            (task.role, task.url) for task in done if task.role in ("injection", "auth")
        }
        remaining = max(0, self.max_tasks - len(done))
        if remaining <= 0:
            return []
        tasks: list[WorkerTask] = []
        for url in _interesting_endpoints(self.surface, limit=remaining):
            if ("injection", url) in already:
                continue
            tasks.append(
                WorkerTask(
                    id=f"T{len(done) + len(tasks) + 1}",
                    role="injection",
                    objective=(
                        f"对 {url} 做定向注入验证：fuzz_params 按参数语义选类别，"
                        "命中用 compare_responses 确认差异，证据成立才 record_finding。"
                    ),
                    url=url,
                    steps=self.task_steps,
                )
            )
            if len(tasks) >= remaining:
                break
        if not tasks and not any(task.role == "auth" for task in done) and _looks_like_auth(self.surface):
            tasks.append(
                WorkerTask(
                    id=f"T{len(done) + 1}",
                    role="auth",
                    objective=(
                        "认证与越权测试：check_default_creds 试默认凭据；"
                        "对返回敏感数据的接口测未授权访问（account=\"\"）；"
                        "对带 id/uid/order_id 的接口测 IDOR（A/B 身份对比）。"
                    ),
                    url=self.target,
                    steps=self.task_steps,
                )
            )
        return tasks


def _plan_reason(content: str) -> str:
    """从计划 JSON 里取 thought 作为事件说明。"""
    try:
        data = extract_json(content)
    except ValueError:
        return ""
    return str(data.get("thought") or "") if isinstance(data, dict) else ""


def summarise_events(events: list[dict[str, Any]]) -> str:
    """把编排事件渲染成一段可读文本（CLI 输出用）。"""
    lines: list[str] = []
    for event in events:
        kind = event.get("kind")
        if kind == "plan":
            lines.append(f"计划（{len(event.get('tasks') or [])} 个任务）：{event.get('reason', '')}")
            for task in event.get("tasks") or []:
                lines.append(f"  [{task['id']}] {task['role']}: {task['objective'][:90]}")
        elif kind == "wave":
            lines.append(f"— 第 {event.get('wave')} 波：{event.get('count')} 个任务 —")
        elif kind == "task_start":
            task = event.get("task") or {}
            lines.append(f"  >> [{task.get('id')}] {task.get('role')}: {str(task.get('objective'))[:70]}")
        elif kind == "task_end":
            task = event.get("task") or {}
            flag = "[OK]" if task.get("outcome") == "done" else "[!!]"
            lines.append(
                f"  {flag} [{task.get('id')}] "
                f"{str(task.get('summary') or task.get('error') or '')[:100]}"
            )
        elif kind == "notice":
            lines.append(f"  ! [{event.get('task')}] {event.get('level')}: {event.get('message')}")
        elif kind == "dedupe":
            lines.append(f"  去重合并了 {event.get('merged')} 条重复上报")
        elif kind == "plan_error":
            lines.append(f"  规划回退：{event.get('message')}")
        elif kind == "plan_refine":
            lines.append(f"  计划修正：{event.get('message')}")
        elif kind == "coverage_sweep":
            lines.append(f"  覆盖补扫：{event.get('message')}")
    return "\n".join(lines)


__all__ = [
    "DEFAULT_TASK_STEPS",
    "MAX_PARALLEL",
    "MAX_TASKS",
    "Orchestrator",
    "StepAbort",
    "SwarmCallbacks",
    "TaskWorker",
    "WorkerTask",
    "summarise_events",
]
