"""审计参数与预算上限的**单一来源**（桌面端与 CLI 共用）。

为什么需要这个模块：桌面端原先在自己的视图函数里又拼了一套 `Config` 与 `Budget`，
于是 CLI 支持的五个预算上限里只有两个在桌面上生效——
`max_tokens` / `max_llm_calls` / `max_seconds` 被静默丢弃，界面上也没有对应输入框。
用户以为设了护栏，其实没有。这里把"字段定义 → 解析 → 校验 → Config/Budget"
收成一条路径，两边都走它。

字段语义（**必须明确，否则护栏形同虚设**）：

* 预算类字段（`max_cost` / `max_tokens` / `max_llm_calls` / `max_tool_calls` /
  `max_seconds`）填 `0` 或留空 = **不限制**；
* 其余字段（步数 / 并发 / 超时…）留空 = 用默认值，填 `0` 或负数 = **报错**
  （这些字段的 0 没有合理含义，静默改成默认值只会让用户以为设置生效了）；
* 非法数字 / 超出范围 = 报错，并且**一次报出全部问题**（表单一次改完，
  而不是改一个报一个）。
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from .budget import BudgetLimits, limits_from_config
from .config import Config


@dataclass(frozen=True)
class NumberField:
    """一个数值型审计参数：标签 + 单位 + 范围 + 默认值。"""

    key: str
    label: str
    unit: str
    kind: str  # "int" | "float"
    default: float
    minimum: float = 0.0
    maximum: float = 0.0  # 0 = 不设上限
    unlimited_at_zero: bool = False
    hint: str = ""

    def describe_range(self) -> str:
        """给用户看的取值范围说明。"""
        if self.unlimited_at_zero and self.minimum == 0:
            return f"{self._num(self.minimum)} 以上（0 = 不限制）"
        if self.maximum:
            return f"{self._num(self.minimum)} ~ {self._num(self.maximum)}"
        return f"{self._num(self.minimum)} 以上"

    def _num(self, value: float) -> str:
        return str(int(value)) if self.kind == "int" else f"{value:g}"

    def unit_suffix(self) -> str:
        return f"（单位：{self.unit}）" if self.unit else ""


#: 全部数值字段。界面据此渲染输入框，后端据此解析/校验——**只有这一份定义**。
FIELDS: tuple[NumberField, ...] = (
    # --- 预算护栏（0 = 不限制）---
    NumberField("max_cost", "费用上限", "元", "float", 0.0, unlimited_at_zero=True),
    NumberField("max_tokens", "Token 上限", "token", "int", 0, unlimited_at_zero=True),
    NumberField("max_llm_calls", "模型调用上限", "次", "int", 0, unlimited_at_zero=True),
    NumberField("max_tool_calls", "工具调用上限", "次", "int", 0, unlimited_at_zero=True),
    NumberField("max_seconds", "总时长上限", "秒", "float", 0.0, unlimited_at_zero=True),
    NumberField("soft_seconds", "运行软上限", "秒", "float", 1800.0, unlimited_at_zero=True,
                hint="只拦「要不要再开一波」，不打断进行中的波次；0 = 不限制"),
    # --- 执行规模 ---
    NumberField("max_steps", "单代理最大步数", "步", "int", 30, minimum=1,
                hint="仅单代理模式；多代理使用子任务最大步数"),
    NumberField("max_tasks", "子任务上限", "个", "int", 6, minimum=1, maximum=12),
    NumberField("task_steps", "子任务最大步数", "步", "int", 10, minimum=4, maximum=30,
                hint="每个子任务的探测上限；另有至多两轮受限收尾，各波次步数累计"),
    NumberField("parallel", "并发子任务数", "个", "int", 3, minimum=1, maximum=6),
    NumberField("request_timeout", "单请求超时", "秒", "int", 10, minimum=1),
    NumberField("rate_limit", "请求最小间隔", "秒", "float", 0.0, minimum=0.0),
    NumberField("temperature", "采样温度", "", "float", 0.2, minimum=0.0, maximum=2.0),
)

BY_KEY: dict[str, NumberField] = {field.key: field for field in FIELDS}

#: 预算类字段（这些字段的 0 = 不限制）
LIMIT_KEYS: tuple[str, ...] = tuple(
    field.key for field in FIELDS if field.unlimited_at_zero
)


def numeric_defaults() -> dict[str, str]:
    """字段默认值的**字符串**形式（与设置文件里的存储形式一致）。"""
    out: dict[str, str] = {}
    for field in FIELDS:
        out[field.key] = (
            str(int(field.default)) if field.kind == "int" else f"{field.default:g}"
        )
    return out


def field_specs() -> list[dict[str, Any]]:
    """给模板用的字段描述（界面与后端共用同一份标签/单位/范围）。"""
    return [
        {
            "key": field.key,
            "label": field.label,
            "unit": field.unit,
            "kind": field.kind,
            "default": numeric_defaults()[field.key],
            "min": field.minimum,
            "max": field.maximum,
            "range": field.describe_range(),
            "hint": field.hint,
            "unlimited_at_zero": field.unlimited_at_zero,
        }
        for field in FIELDS
    ]


def parse_number(raw: Any, field: NumberField) -> float | int:
    """把界面/配置里的一个值解析成数字；不合法就抛 `ValueError`。

    `ValueError` 的文本直接给用户看，因此必须带**标签与单位**：
    "填写有误"这种话对用户没有任何帮助。
    """
    text = "" if raw is None else str(raw).strip()
    if not text:
        return int(field.default) if field.kind == "int" else float(field.default)
    try:
        value = float(text)
    except (TypeError, ValueError):
        raise ValueError(
            f"{field.label} 必须是数字{field.unit_suffix()}，当前填的是 {text!r}。"
            f"取值范围：{field.describe_range()}。"
        ) from None
    if not math.isfinite(value):
        raise ValueError(
            f"{field.label} 必须是有限数字{field.unit_suffix()}，当前填的是 {text!r}。"
        )
    if field.kind == "int":
        if value != int(value):
            raise ValueError(
                f"{field.label} 必须是整数{field.unit_suffix()}，当前填的是 {text!r}。"
            )
        number: float | int = int(value)
    else:
        number = value
    if number < field.minimum:
        # 预算类字段的 0 是"不限制"，负数则一定是填错了
        raise ValueError(
            f"{field.label} 不能小于 {field._num(field.minimum)}{field.unit_suffix()}，"
            f"当前填的是 {text!r}。取值范围：{field.describe_range()}。"
        )
    if field.maximum and number > field.maximum:
        raise ValueError(
            f"{field.label} 不能大于 {field._num(field.maximum)}{field.unit_suffix()}，"
            f"当前填的是 {text!r}。取值范围：{field.describe_range()}。"
        )
    return number


def parse_fields(settings: dict[str, Any]) -> dict[str, float | int]:
    """解析全部数值字段；**一次报出所有问题**（不是遇到第一个就返回）。"""
    parsed: dict[str, float | int] = {}
    problems: list[str] = []
    for field in FIELDS:
        try:
            parsed[field.key] = parse_number(settings.get(field.key), field)
        except ValueError as exc:
            problems.append(str(exc))
    if problems:
        raise ValueError("；".join(problems))
    return parsed


def limits_from_settings(settings: dict[str, Any]) -> BudgetLimits:
    """从设置构造预算上限（与 CLI 的 `budget.limits_from_config` 同源同义）。

    这里刻意**不**自己拼 `BudgetLimits`：先把值写进 `Config`，
    再让 `budget.limits_from_config` 产出上限——保证桌面端与 CLI
    的预算构造只有一条路径（否则加一个新上限时，总有一边忘掉）。
    """
    parsed = parse_fields(settings)
    config = Config(api_key="", **{key: parsed[key] for key in LIMIT_KEYS})
    return limits_from_config(config)


def config_from_settings(
    settings: dict[str, Any],
    *,
    api_key: str = "",
    base_url: str = "",
    model: str = "",
    provider: str = "",
    role_models: dict[str, str] | None = None,
    allowed_hosts: frozenset[str] | None = None,
) -> Config:
    """把界面设置变成 `Config`（桌面端与 CLI 的字段含义由此统一）。"""
    parsed = parse_fields(settings)
    config = Config(
        api_key=str(api_key or ""),
        base_url=str(base_url or ""),
        model=str(model or ""),
        provider=str(provider or ""),
        role_models=dict(role_models or {}),
        reasoning_effort=str(settings.get("reasoning_effort") or "").strip().lower(),
        allowed_hosts=frozenset(allowed_hosts or ()),
        **{key: parsed[key] for key in parsed},
    )
    config.validate()
    return config
