"""模型请求参数及响应验收回归；只用 SDK 桩，不访问模型或目标。"""
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hexhound.agent import ReActAgent
from hexhound.config import Config
from hexhound.llm import LLMClient, build_llm_pool
from hexhound.runparams import config_from_settings
from hexhound.tools import ToolRegistry
from hexhound.trace import TraceRecorder

ACTION = '{"action":"finish_task","action_input":{"summary":"可用"}}'


def response(content=ACTION, finish="stop"):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content), finish_reason=finish)],
        usage=SimpleNamespace(
            prompt_tokens=20, completion_tokens=30, total_tokens=50,
            completion_tokens_details=SimpleNamespace(reasoning_tokens=18),
        ),
    )


@pytest.fixture
def sdk():
    client = Mock()
    client.chat.completions.create.return_value = response()
    with patch("hexhound.llm.OpenAI", return_value=client), patch("hexhound.llm._dead_proxy_detail", return_value=(False, "")):
        yield client


@pytest.mark.parametrize("provider,effort,expected", [
    ("deepseek", "max", "max"), ("deepseek", "low", "low"),
    ("deepseek", "", ""), ("custom", "max", ""),
])
def test_actual_request_effort_and_usage(sdk, provider, effort, expected):
    llm = LLMClient("fake", "http://model.invalid", "deepseek-flash", provider=provider, reasoning_effort=effort)
    content, usage = llm.complete([])
    args = sdk.chat.completions.create.call_args.kwargs
    assert args.get("reasoning_effort", "") == expected
    assert args.get("extra_body") == ({"thinking": {"type": "enabled"}} if expected else None)
    assert llm.request_config()["reasoning_effort"] == (expected or "server_default")
    assert content == ACTION and usage.reasoning_tokens == 18 and usage.finish_reason == "stop"


@pytest.mark.parametrize("content,finish,ok", [
    (None, "length", False), ("", "stop", False), ("可用", "stop", False),
    (ACTION, "length", False), (ACTION, "content_filter", False), (ACTION, "stop", True),
])
def test_connection_requires_complete_action_json(sdk, content, finish, ok):
    sdk.chat.completions.create.return_value = response(content, finish)
    llm = LLMClient("fake", "http://model.invalid", "deepseek-flash", provider="deepseek", reasoning_effort="high")
    check = llm.test_connection()
    assert check.ok is ok
    assert check.category == ("ok" if ok else "response")
    assert check.usage["total_tokens"] == 50
    assert sdk.chat.completions.create.call_args.kwargs["reasoning_effort"] == "high"


def test_effort_flows_from_settings_env_and_role_pool(sdk, monkeypatch):
    config = config_from_settings({"reasoning_effort": "max"}, api_key="fake",
        provider="deepseek", model="deepseek-flash", base_url="http://model.invalid",
        role_models={"verify": "deepseek-v4-pro"}, allowed_hosts=frozenset({"target.invalid"}))
    default, pool = build_llm_pool(config)
    assert default.reasoning_effort == pool["verify"].reasoning_effort == "max"
    monkeypatch.setenv("LLM_PROVIDER", "deepseek")
    monkeypatch.setenv("LLM_API_KEY", "fake")
    monkeypatch.setenv("LLM_REASONING_EFFORT", "high")
    assert Config.from_env().reasoning_effort == "high"
    monkeypatch.setenv("LLM_REASONING_EFFORT", "typo")
    with pytest.raises(ValueError, match="推理强度"):
        Config.from_env()


@pytest.mark.parametrize("content,finish", [(None, "stop"), (ACTION, "length")])
def test_agent_preserves_usage_and_rejects_unfinished_action(sdk, tmp_path, content, finish):
    sdk.chat.completions.create.return_value = response(content, finish)
    llm = LLMClient("fake", "http://model.invalid", "deepseek-flash", provider="deepseek", reasoning_effort="max")
    trace = TraceRecorder(None)
    tools = ToolRegistry(tmp_path, frozenset({"target.invalid"}), mode="blackbox", trace=trace)
    result = ReActAgent(llm, tools, max_steps=1).run("仅离线检查")
    assert result.finish_reason == "provider_error"
    assert result.total_tokens == 50 and tools.finish_summary == ""
    config = next(event["data"] for event in trace.events() if event["kind"] == "llm_config")
    assert config["reasoning_effort"] == "max" and "api_key" not in config
    event = next(event["data"] for event in trace.events() if event["kind"] == "llm_response")
    assert event["finish_reason"] == finish and event["reasoning_tokens"] == 18
