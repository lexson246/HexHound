"""预算控制：token / 费用 / 请求数与墙钟时间上限。

对标 PentAGI 的按 agent 计量与 Strix 的成本痛点：HexHound 之前只能事后
统计花费，跑飞了才发现（历史运行：100 步 / 79 万 token / 仅 1 条 finding）。
这里把「预算」变成一等公民——每个子代理、每个工具调用都先问一次
`can_spend()`，越线即优雅收尾并写进报告。

线程安全：并发子代理共享同一个 Budget 实例。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .llm import estimate_cost


@dataclass
class Usage:
    """累计用量（可序列化，直接进报告）。"""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    cache_hit_tokens: int = 0
    cache_miss_tokens: int = 0
    total_tokens: int = 0
    estimated_cost: float = 0.0
    llm_calls: int = 0
    tool_calls: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cache_hit_tokens": self.cache_hit_tokens,
            "cache_miss_tokens": self.cache_miss_tokens,
            "total_tokens": self.total_tokens,
            "estimated_cost": round(self.estimated_cost, 6),
            "llm_calls": self.llm_calls,
            "tool_calls": self.tool_calls,
        }


@dataclass
class BudgetLimits:
    """预算上限；0 或 None 表示不限制该项。"""

    max_cost: float = 0.0        # 人民币
    max_tokens: int = 0          # 总 token
    max_llm_calls: int = 0       # LLM 调用次数
    max_tool_calls: int = 0      # 工具调用次数
    max_seconds: float = 0.0     # 墙钟时间（秒）


class Budget:
    """共享预算账本：记账 + 越线判定 + 可读状态。"""

    def __init__(self, limits: BudgetLimits | None = None, verbose: bool = False) -> None:
        self.limits = limits or BudgetLimits()
        self.verbose = verbose
        self.usage = Usage()
        self.started_at = time.time()
        self._lock = threading.Lock()
        self._reasons: list[str] = []
        self._listeners: list[Any] = []
        self._issued_bands: set[str] = set()

    # ---------- 记账 ----------

    def add_usage(self, llm_usage: Any) -> None:
        """累计一次 LLM 调用的用量（接受 LLMUsage 或 int）。"""
        if llm_usage is None:
            return
        prompt = int(getattr(llm_usage, "prompt_tokens", 0) or 0)
        completion = int(getattr(llm_usage, "completion_tokens", 0) or 0)
        total = int(getattr(llm_usage, "total_tokens", prompt + completion) or 0)
        cost = estimate_cost(llm_usage) if hasattr(llm_usage, "prompt_tokens") else 0.0
        with self._lock:
            self.usage.prompt_tokens += prompt
            self.usage.completion_tokens += completion
            self.usage.total_tokens += total
            self.usage.cache_hit_tokens += int(getattr(llm_usage, "cache_hit_tokens", 0) or 0)
            self.usage.cache_miss_tokens += int(getattr(llm_usage, "cache_miss_tokens", 0) or 0)
            self.usage.estimated_cost += cost
            self.usage.llm_calls += 1
        self._notify()

    def add_tool_call(self, count: int = 1) -> None:
        with self._lock:
            self.usage.tool_calls += count
        self._notify()

    def set_verbose(self, verbose: bool) -> None:
        """设置是否打印每一步（供 CLI 中途切换）。"""
        self.verbose = verbose

    def child(self) -> "Budget":
        """子代理视图：共享同一账本与限制（避免各自重复计数）。"""
        return self

    def on_change(self, callback: Any) -> None:
        """注册用量变化回调（GUI 刷新 token 面板用）。"""
        with self._lock:
            self._listeners.append(callback)

    def _notify(self) -> None:
        with self._lock:
            listeners = list(self._listeners)
            snapshot = self.usage.to_dict()
        for callback in listeners:
            try:
                callback(snapshot)
            except Exception:  # noqa: BLE001 回调失败不影响主流程
                pass

    # ---------- 判定 ----------

    def exhausted_reason(self) -> str:
        """返回第一条越线的原因（未越线返回空串）。"""
        with self._lock:
            limits = self.limits
            usage = self.usage
            elapsed = time.time() - self.started_at
            if limits.max_cost and usage.estimated_cost >= limits.max_cost:
                return f"费用预算用尽（¥{usage.estimated_cost:.4f} ≥ ¥{limits.max_cost:.4f}）"
            if limits.max_tokens and usage.total_tokens >= limits.max_tokens:
                return f"token 预算用尽（{usage.total_tokens} ≥ {limits.max_tokens}）"
            if limits.max_llm_calls and usage.llm_calls >= limits.max_llm_calls:
                return f"LLM 调用次数用尽（{usage.llm_calls} ≥ {limits.max_llm_calls}）"
            if limits.max_tool_calls and usage.tool_calls >= limits.max_tool_calls:
                return f"工具调用次数用尽（{usage.tool_calls} ≥ {limits.max_tool_calls}）"
            if limits.max_seconds and elapsed >= limits.max_seconds:
                return f"时间预算用尽（{elapsed:.0f}s ≥ {limits.max_seconds:.0f}s）"
        return ""

    def can_spend(self) -> bool:
        """是否还能继续花钱/花时间。"""
        if self.exhausted_reason():
            self.stop()
            return False
        return True

    # ---------- 预算预警带（对标 Strix 的 0.70/0.85/0.95 提示）----------

    #: 用量占比 → (级别, 收尾指令)。到达该占比时把指令插进对话，让模型主动收尾，
    #: 而不是跑到硬阈值被直接掐断（那时往往连结论都来不及写）。
    WARN_BANDS: tuple[tuple[float, str, str], ...] = (
        (0.95, "CRITICAL", "预算即将耗尽：立即停止新探测，把已确认的漏洞用 record_finding 记录完整，然后 finish。"),
        (0.85, "URGENT", "预算已用 85%：只做「复核已有候选」这一类动作，不要再开拓新攻击面。"),
        (0.70, "NOTICE", "预算已用 70%：开始收敛，优先把已命中的疑似信号复核成结论。"),
    )

    def usage_ratio(self) -> float:
        """当前用量占最紧的那条预算的比例（没有任何限额时返回 0）。"""
        with self._lock:
            limits = self.limits
            usage = self.usage
            elapsed = time.time() - self.started_at
            ratios = []
            if limits.max_cost:
                ratios.append(usage.estimated_cost / limits.max_cost)
            if limits.max_tokens:
                ratios.append(usage.total_tokens / limits.max_tokens)
            if limits.max_llm_calls:
                ratios.append(usage.llm_calls / limits.max_llm_calls)
            if limits.max_tool_calls:
                ratios.append(usage.tool_calls / limits.max_tool_calls)
            if limits.max_seconds:
                ratios.append(elapsed / limits.max_seconds)
        return max(ratios) if ratios else 0.0

    def pending_notice(self) -> tuple[str, str] | None:
        """返回尚未下发过的最高级别预警（(级别, 指令)），没有则 None。"""
        ratio = self.usage_ratio()
        with self._lock:
            for threshold, level, directive in self.WARN_BANDS:
                if ratio >= threshold and level not in self._issued_bands:
                    self._issued_bands.add(level)
                    return level, directive
        return None

    def stop(self) -> None:
        """记录停止状态（幂等，重复调用只记一次原因）。"""
        reason = self.exhausted_reason()
        if not reason:
            return
        with self._lock:
            if reason not in self._reasons:
                self._reasons.append(reason)

    def stop_reasons(self) -> list[str]:
        with self._lock:
            return list(self._reasons)

    def exhausted(self) -> bool:
        return bool(self.exhausted_reason())

    # ---------- 展示 ----------

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            data = self.usage.to_dict()
            data["elapsed_seconds"] = round(time.time() - self.started_at, 1)
            data["limits"] = {
                "max_cost": self.limits.max_cost,
                "max_tokens": self.limits.max_tokens,
                "max_llm_calls": self.limits.max_llm_calls,
                "max_tool_calls": self.limits.max_tool_calls,
                "max_seconds": self.limits.max_seconds,
            }
            data["stop_reasons"] = list(self._reasons)
            return data

    def describe(self) -> str:
        """一行状态文本（CLI/日志用）。"""
        data = self.snapshot()
        parts = [
            f"{data['total_tokens']} tokens",
            f"¥{data['estimated_cost']:.4f}",
            f"{data['llm_calls']} LLM / {data['tool_calls']} 工具调用",
            f"{data['elapsed_seconds']:.0f}s",
        ]
        text = " · ".join(parts)
        reasons = self.stop_reasons()
        return f"{text}（已停止：{'; '.join(reasons)}）" if reasons else text


@dataclass
class SubBudget:
    """单个层级的限额（用于「每次运行最多 N 个任务」这类结构性限制）。"""

    max_items: int = 0
    used: int = 0
    label: str = ""

    def take(self) -> bool:
        """占用一个名额；已满返回 False。"""
        if self.max_items and self.used >= self.max_items:
            return False
        self.used += 1
        return True

    def left(self) -> int:
        return max(0, self.max_items - self.used) if self.max_items else 10**9


def limits_from_config(config: Any) -> BudgetLimits:
    """从 Config 读取预算上限（缺省 0 = 不限制）。"""
    return BudgetLimits(
        max_cost=float(getattr(config, "max_cost", 0) or 0),
        max_tokens=int(getattr(config, "max_tokens", 0) or 0),
        max_llm_calls=int(getattr(config, "max_llm_calls", 0) or 0),
        max_tool_calls=int(getattr(config, "max_tool_calls", 0) or 0),
        max_seconds=float(getattr(config, "max_seconds", 0) or 0),
    )
