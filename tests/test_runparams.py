"""审计参数与预算上限的解析/校验测试（桌面端与 CLI 共用的那份定义）。

这些用例盯住的是**护栏是否真的生效**：桌面端曾经只把 `max_cost` 与
`max_tool_calls` 传给 `Budget`，token / 模型调用数 / 总时长三个上限被静默丢弃——
用户以为设了限制，其实没有。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from hexhound import runparams  # noqa: E402


def test_zero_means_unlimited_for_budget_fields() -> None:
    """预算类字段的 0 = 不限制（这是界面与文档都写明的语义）。"""
    for key in runparams.LIMIT_KEYS:
        parsed = runparams.parse_fields({key: "0"})
        assert parsed[key] == 0, key


def test_empty_uses_the_documented_default() -> None:
    parsed = runparams.parse_fields({})
    assert parsed["max_steps"] == 30
    assert parsed["max_tasks"] == 6
    assert parsed["parallel"] == 3
    assert parsed["request_timeout"] == 10
    assert parsed["temperature"] == pytest.approx(0.2)


def test_budget_limits_cover_all_five_dimensions() -> None:
    """五个预算维度都要能设上（曾经的缺口就在这里）。"""
    limits = runparams.limits_from_settings(
        {
            "max_cost": "1.5",
            "max_tokens": "120000",
            "max_llm_calls": "40",
            "max_tool_calls": "25",
            "max_seconds": "600",
        }
    )
    assert limits.max_cost == pytest.approx(1.5)
    assert limits.max_tokens == 120000
    assert limits.max_llm_calls == 40
    assert limits.max_tool_calls == 25
    assert limits.max_seconds == pytest.approx(600)


def test_limits_go_through_the_same_path_as_the_cli() -> None:
    """桌面端的上限构造必须与 CLI 同源，否则新增上限时总有一边漏掉。"""
    from hexhound.budget import limits_from_config
    from hexhound.config import Config

    settings = {"max_cost": "2", "max_tokens": "999", "max_seconds": "30"}
    from_settings = runparams.limits_from_settings(settings)
    from_config = limits_from_config(
        Config(api_key="", max_cost=2.0, max_tokens=999, max_seconds=30.0)
    )
    assert from_settings == from_config


@pytest.mark.parametrize(
    "settings,expected",
    [
        ({"max_cost": "-1"}, "费用上限 不能小于 0"),
        ({"max_tokens": "-100"}, "Token 上限 不能小于 0"),
        ({"max_tool_calls": "-1"}, "工具调用上限 不能小于 0"),
        ({"max_seconds": "-5"}, "总时长上限 不能小于 0"),
        ({"max_steps": "0"}, "单代理最大步数 不能小于 1"),
        ({"max_tasks": "0"}, "子任务上限 不能小于 1"),
        ({"parallel": "0"}, "并发子任务数 不能小于 1"),
    ],
)
def test_negative_or_zero_where_meaningless_is_an_error(settings: dict, expected: str) -> None:
    """0 只在预算类字段里表示"不限制"；其它字段填 0 是配置错误，必须报错。"""
    with pytest.raises(ValueError) as excinfo:
        runparams.parse_fields(settings)
    assert expected in str(excinfo.value)


def test_non_numeric_is_rejected_with_label_and_unit() -> None:
    with pytest.raises(ValueError) as excinfo:
        runparams.parse_fields({"max_cost": "abc"})
    message = str(excinfo.value)
    assert "费用上限" in message
    assert "元" in message
    assert "abc" in message


def test_non_finite_is_rejected() -> None:
    for raw in ("inf", "-inf", "nan"):
        with pytest.raises(ValueError):
            runparams.parse_fields({"max_seconds": raw})


def test_out_of_range_is_rejected() -> None:
    with pytest.raises(ValueError) as excinfo:
        runparams.parse_fields({"max_tasks": "99"})
    assert "不能大于 12" in str(excinfo.value)
    with pytest.raises(ValueError):
        runparams.parse_fields({"temperature": "9"})


def test_all_problems_are_reported_at_once() -> None:
    """表单一次报出全部问题，而不是改一个报一个。"""
    with pytest.raises(ValueError) as excinfo:
        runparams.parse_fields({"max_cost": "-1", "max_tasks": "99", "max_steps": "x"})
    message = str(excinfo.value)
    assert "费用上限" in message
    assert "子任务上限" in message
    assert "单代理最大步数" in message


def test_integer_fields_reject_fractions() -> None:
    with pytest.raises(ValueError) as excinfo:
        runparams.parse_fields({"max_tokens": "1.5"})
    assert "整数" in str(excinfo.value)


def test_config_from_settings_fills_every_field() -> None:
    config = runparams.config_from_settings(
        {"max_tokens": "500", "max_llm_calls": "7", "max_seconds": "60", "max_steps": "12"},
        api_key="sk-fake-0001",
        base_url="https://api.deepseek.com/v1",
        model="deepseek-chat",
        provider="deepseek",
        allowed_hosts=frozenset({"127.0.0.1"}),
    )
    assert config.max_tokens == 500
    assert config.max_llm_calls == 7
    assert config.max_seconds == pytest.approx(60)
    assert config.max_steps == 12


def test_field_specs_expose_labels_and_units_for_the_ui() -> None:
    specs = {spec["key"]: spec for spec in runparams.field_specs()}
    assert specs["max_cost"]["label"] == "费用上限"
    assert specs["max_cost"]["unit"] == "元"
    assert specs["max_tokens"]["unit"] == "token"
    assert specs["max_seconds"]["unit"] == "秒"
    assert "不限制" in specs["max_cost"]["range"]
    # 每个字段都必须有标签与取值范围说明（界面直接显示）
    for spec in runparams.field_specs():
        assert spec["label"]
        assert spec["range"]
        assert spec["default"] != ""
