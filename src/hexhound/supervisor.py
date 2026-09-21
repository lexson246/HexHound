"""监督器：检测"卡住"的迹象，先干预、再优雅收尾，避免死循环烧预算。

对标机制来源（`docs/research-notes/strix-pentagi-refresh-2026.md` §C3）：
- Strix：`_INTERACTIVE_TOOL_RECOVERY_LIMIT=3`（生命周期恢复次数）、
  `LLM_MAX_TOOL_CALLS_PER_TURN=32`、三档 NOTICE/URGENT/CRITICAL 收尾指令；
- PentAGI：`maxAgentShutdownIterations=3` 的强制 reflector 窗口、
  `maxReflectorCallsPerChain=3`、重复工具调用达到阈值 +4 即中止。

两家的做法是互补的：Strix 强在**收尾指令的梯度**，PentAGI 强在
**"重复即中止"的硬阈值**。HexHound 把两者合到一处，并且要求
**每一次干预都留下记录**（trace 事件 + 报告里的说明）——
"为什么这个子任务被中止"必须能回答，否则读者只看到一条缺失的结论。

本模块只做**判定**，不做执行：它输出一个 `Verdict`，由调用方决定
（加提示 / 中止）。这样判定逻辑可以脱离编排器单独测。
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

#: 同一 (工具, 参数) 重复到这个次数 → 告警（对齐 PentAGI 的 3 次）。
REPEAT_WARN = 3

#: 重复到这个次数 → 中止子任务（PentAGI 是 7 次，这里收紧到 5）。
REPEAT_ABORT = 5

#: 连续这么多步没有产生任何"进展"（新证据/新结论/新端点）→ 干预。
STALL_WARN_STEPS = 4

#: 停滞到这么多步 → 判定为卡死，交给调用方终止。
STALL_ABORT_STEPS = 8

#: 同一类失败连续出现这么多次 → 干预（"相同失败循环"）。
FAILURE_WARN = 3

#: 同一类失败连续出现这么多次 → 终止。
FAILURE_ABORT = 5

#: 视为"产生了进展"的动作与观察特征。
_PROGRESS_ACTIONS = frozenset({
    "record_finding", "record_coverage", "leave_note",
})
_PROGRESS_MARKERS = (
    "新增端点", "已记录", "已登记", "命中信号", "发现", "[OK]",
    "已写入", "已保存",
)
#: 会**改变服务端状态**的 HTTP 方法：多步业务逻辑测试靠它们推进。
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
#: 观察文本达到这个长度就认为"取回了实质内容"（大响应体 = 有新信息）。
_SUBSTANTIAL_OBSERVATION_CHARS = 400
#: 视为"失败"的观察特征（用于相同失败循环判定）。
_FAILURE_MARKERS = (
    "工具执行出错", "请求失败", "拒绝：", "已拒绝执行", "错误：",
    "执行失败", "超时", "Traceback",
)


@dataclass
class Verdict:
    """一次监督判定。"""

    level: str = "ok"  # ok / warn / abort
    reason: str = ""
    directive: str = ""
    kind: str = ""  # repeat / stall / failure_loop

    @property
    def abort(self) -> bool:
        return self.level == "abort"

    @property
    def warn(self) -> bool:
        return self.level == "warn"

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "kind": self.kind,
            "reason": self.reason,
            "directive": self.directive,
        }


def _signature(action: str, action_input: Any) -> str:
    """(工具, 参数) 的稳定签名：同样的调用必须得到同样的字符串。"""
    try:
        payload = json.dumps(action_input, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        payload = str(action_input)
    return f"{action}:{payload[:400]}"


def _looks_like_progress(step: dict[str, Any]) -> bool:
    """这一步是否推进了工作（新证据、新结论、新端点、或取回了实质内容）。

    判据要**既不误杀也要能抓真停滞**。早先只看"记录类动作 + 少数中文进展词"，
    结果误杀了一次业务逻辑任务（实测）：

        步骤 1-4  GET 探路 / POST /login 拿会话 / POST /cart 加购
        步骤 5    GET /catalog  → 观察 1602 字符（真的取回了商品目录）
        步骤 6-7  继续 POST 下单
        → 被判"连续 8 步无进展"**直接中止**

    那 7 步每一步都在推进，只是观察文本里既没有"新增端点"这类中文标记，
    也不是 record_* 动作。**该收尾的被中止、该中止的没被中止是同一类失效**：
    判据错了的时候，越自动化越危险。所以补两条与领域无关的信号：

    - 请求方法会改变服务端状态（POST/PUT/PATCH/DELETE）——多步业务逻辑
      正是靠这些请求推进，它们不产生"命中信号"，但必须算进展；
    - 观察文本足够长（>= `_SUBSTANTIAL_OBSERVATION_CHARS`）——说明取回了实质内容。
    """
    action = str(step.get("action") or "")
    if action in _PROGRESS_ACTIONS:
        return True
    observation = str(step.get("observation") or "")
    if any(marker in observation for marker in _PROGRESS_MARKERS):
        return True
    if len(observation) >= _SUBSTANTIAL_OBSERVATION_CHARS:
        return True
    action_input = step.get("action_input")
    if isinstance(action_input, dict):
        method = str(action_input.get("method") or "").upper()
        if method in _STATE_CHANGING_METHODS:
            return True
        # 没写 method 但带了请求体 → 按提交处理（http_request 默认 GET，
        # 但带 data/json 时客户端的实际语义是提交）
        if action_input.get("data") or action_input.get("json"):
            return True
    return False


def _failure_signature(step: dict[str, Any]) -> str:
    """失败签名：动作 + 失败特征。相同签名连续出现即"相同失败循环"。"""
    action = str(step.get("action") or "")
    observation = str(step.get("observation") or "")
    for marker in _FAILURE_MARKERS:
        if marker in observation:
            # 只取特征本身，不取整段文本——否则每次的错误细节不同就判不出来
            return f"{action}:{marker}"
    return ""


class Supervisor:
    """按步观察一个子任务，判定是否需要干预。"""

    def __init__(
        self,
        *,
        repeat_warn: int = REPEAT_WARN,
        repeat_abort: int = REPEAT_ABORT,
        stall_warn: int = STALL_WARN_STEPS,
        stall_abort: int = STALL_ABORT_STEPS,
        failure_warn: int = FAILURE_WARN,
        failure_abort: int = FAILURE_ABORT,
    ) -> None:
        self.repeat_warn = repeat_warn
        self.repeat_abort = repeat_abort
        self.stall_warn = stall_warn
        self.stall_abort = stall_abort
        self.failure_warn = failure_warn
        self.failure_abort = failure_abort
        self.calls: list[str] = []
        self.failures: list[str] = []
        self.stall_steps = 0
        self.interventions: list[dict[str, Any]] = []
        self._warned: set[str] = set()

    # ---------- 观察 ----------

    def observe(self, step: dict[str, Any]) -> Verdict:
        """观察一步并给出判定。"""
        action = str(step.get("action") or "")
        if action in ("finish", "finish_task", "parse_error", "budget_stop"):
            return Verdict()

        signature = _signature(action, step.get("action_input"))
        self.calls.append(signature)
        del self.calls[:-60]
        repeats = self.calls.count(signature)

        failure = _failure_signature(step)
        if failure:
            self.failures.append(failure)
        else:
            self.failures.clear()
        self.failures = self.failures[-20:]

        if _looks_like_progress(step):
            self.stall_steps = 0
        else:
            self.stall_steps += 1

        # 判定顺序：中止类优先于告警类（同一层次里最严重的原因先报）。
        if repeats >= self.repeat_abort:
            return self._verdict(
                "abort", "repeat",
                f"同一工具以完全相同的参数调用了 {repeats} 次",
                "立即停止重复调用：同样参数不会有新信息。"
                "请换参数/换端点，或直接用 finish_task 交回已有结论。",
            )
        if self.stall_steps >= self.stall_abort:
            return self._verdict(
                "abort", "stall",
                f"连续 {self.stall_steps} 步没有任何新证据或新结论",
                "本子任务判定为陷入停滞：立即用 record_finding / record_coverage "
                "固化已有产出，然后 finish_task。不要再开新的探测方向。",
            )
        if len(self.failures) >= self.failure_abort:
            same = self.failures[-1]
            return self._verdict(
                "abort", "failure_loop",
                f"同一个失败连续出现 {len(self.failures)} 次（{same}）",
                "这类调用一直在失败，继续重试不会成功。"
                "请换一种做法（换工具/换参数/换端点），或直接 finish_task。",
            )
        if repeats == self.repeat_warn:
            return self._verdict(
                "warn", "repeat",
                f"同一工具以完全相同的参数调用了 {repeats} 次",
                "同样的调用不会产生新信息——请换参数、换端点，或进入复核/收尾。",
            )
        if self.stall_steps == self.stall_warn:
            return self._verdict(
                "warn", "stall",
                f"连续 {self.stall_steps} 步没有新证据或新结论",
                "看起来在原地打转：优先把已命中的疑似信号复核成结论，"
                "或换一个更有价值的目标面。",
            )
        if len(self.failures) == self.failure_warn:
            return self._verdict(
                "warn", "failure_loop",
                f"同一个失败连续出现 {len(self.failures)} 次（{self.failures[-1]}）",
                "重复同一个失败调用没有意义：请换一种做法，或说明为什么这条路走不通。",
            )
        return Verdict()

    def _verdict(self, level: str, kind: str, reason: str, directive: str) -> Verdict:
        verdict = Verdict(level=level, kind=kind, reason=reason, directive=directive)
        # 同一种干预只记一次（多次触发会让 trace 与报告噪音化）
        key = f"{level}:{kind}"
        if key not in self._warned or level == "abort":
            self._warned.add(key)
            self.interventions.append(verdict.to_dict())
        return verdict

    # ---------- 汇总 ----------

    def summary(self) -> dict[str, Any]:
        return {
            "interventions": list(self.interventions),
            "stall_steps": self.stall_steps,
            "recent_calls": len(self.calls),
            "repeat_thresholds": {
                "warn": self.repeat_warn,
                "abort": self.repeat_abort,
            },
            "stall_thresholds": {"warn": self.stall_warn, "abort": self.stall_abort},
            "failure_thresholds": {
                "warn": self.failure_warn,
                "abort": self.failure_abort,
            },
        }


__all__ = [
    "FAILURE_ABORT",
    "FAILURE_WARN",
    "REPEAT_ABORT",
    "REPEAT_WARN",
    "STALL_ABORT_STEPS",
    "STALL_WARN_STEPS",
    "Supervisor",
    "Verdict",
]
