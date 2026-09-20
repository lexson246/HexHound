"""模型提供商预设与解析。

设计目标：让"换个模型"变成**改一个名字**，而不是翻文档抄 base_url。
所有预设都走 OpenAI 兼容接口（HexHound 只依赖这一种协议），因此这里存的是
「base_url + 默认模型 + 可用模型 + 环境变量名」这类纯数据。

三层解析优先级（见 `Config.resolve_provider`）：
1. `--role-<角色>` / `.env` 的 `LLM_<角色>_MODEL`（按角色指定模型，最细粒度）
2. `--provider` / `.env` 的 `LLM_PROVIDER`（本次运行的提供商）
3. 旧键 `LLM_BASE_URL` + `LLM_MODEL`（向后兼容 v0.1 的 .env）

API key 同理：优先 `PROVIDER_<KEY>_API_KEY`，回退到共享的 `LLM_API_KEY`。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProviderPreset:
    """一个 OpenAI 兼容提供商的预设。"""

    key: str
    label: str
    base_url: str
    default_model: str
    models: tuple[str, ...] = ()
    key_style: str = "sk-"          # 仅用于界面上提示 key 长什么样
    api_key_url: str = ""           # 去哪拿 key
    note: str = ""
    aliases: tuple[str, ...] = ()   # 允许用户输入的别名
    #: 计价（人民币 / 每百万 token）：(缓存命中输入, 缓存未命中输入, 输出)。
    #: 只用于**估算**费用与预算护栏；实际以账单为准，可用 PRICE_* 环境变量覆盖。
    pricing: tuple[float, float, float] = (0.0, 0.0, 0.0)

    def model_list(self) -> list[str]:
        """返回可选模型列表（去重，默认模型排第一）。"""
        ordered = [self.default_model, *self.models]
        seen: list[str] = []
        for item in ordered:
            if item and item not in seen:
                seen.append(item)
        return seen


# ---------------------------------------------------------------------------
# 内置预设
# ---------------------------------------------------------------------------

PRESETS: tuple[ProviderPreset, ...] = (
    ProviderPreset(
        key="deepseek",
        label="DeepSeek（默认，性价比高）",
        base_url="https://api.deepseek.com",
        default_model="deepseek-v4-flash",
        models=("deepseek-v4-pro", "deepseek-flash", "deepseek-chat", "deepseek-reasoner"),
        api_key_url="https://platform.deepseek.com/api_keys",
        note="国内直连稳定；flash 便宜适合并发子代理，pro 适合编排/复核。",
        pricing=(0.02, 1.0, 2.0),
    ),
    ProviderPreset(
        key="openai",
        label="OpenAI",
        base_url="https://api.openai.com/v1",
        default_model="gpt-4o-mini",
        models=("gpt-4o", "gpt-4.1", "gpt-4.1-mini", "o4-mini"),
        api_key_url="https://platform.openai.com/api-keys",
        note="需要能直连 api.openai.com（国内通常要自备代理/中转）。",
        pricing=(0.08, 1.1, 4.4),
    ),
    ProviderPreset(
        key="anthropic",
        label="Anthropic Claude（OpenAI 兼容层）",
        base_url="https://api.anthropic.com/v1",
        default_model="claude-sonnet-4-20250514",
        models=("claude-opus-4-20250514",),
        key_style="sk-ant-",
        api_key_url="https://console.anthropic.com/settings/keys",
        note="Anthropic 的 OpenAI 兼容端点模型名与官方略有差异，建议先用「测试连接」确认。",
        pricing=(0.2, 2.2, 11.0),
    ),
    ProviderPreset(
        key="gemini",
        label="Google Gemini（OpenAI 兼容层）",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        default_model="gemini-2.5-flash",
        models=("gemini-2.5-pro", "gemini-2.0-flash"),
        key_style="AIza",
        api_key_url="https://aistudio.google.com/apikey",
        note="使用 Google 的 OpenAI 兼容端点，无需额外 SDK。",
        pricing=(0.05, 0.7, 2.9),
    ),
    ProviderPreset(
        key="qwen",
        label="阿里云百炼 / 通义千问",
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        default_model="qwen-plus",
        models=("qwen-max", "qwen-turbo", "qwen3-max", "qwen2.5-72b-instruct"),
        api_key_url="https://bailian.console.aliyun.com/",
        note="与识图面板（VISION_MODEL）同一家，key 可以复用。",
        pricing=(0.1, 0.8, 2.0),
    ),
    ProviderPreset(
        key="moonshot",
        label="月之暗面 Kimi",
        base_url="https://api.moonshot.cn/v1",
        default_model="kimi-k2-0905-preview",
        models=("moonshot-v1-128k", "moonshot-v1-32k", "moonshot-v1-8k"),
        api_key_url="https://platform.moonshot.cn/console/api-keys",
        note="长上下文友好，适合把大段 JS/HTML 交给模型判断。",
        pricing=(0.1, 4.0, 16.0),
    ),
    ProviderPreset(
        key="zhipu",
        label="智谱 GLM",
        base_url="https://open.bigmodel.cn/api/paas/v4",
        default_model="glm-4.5",
        models=("glm-4.5-air", "glm-4-plus", "glm-4-flash"),
        api_key_url="https://open.bigmodel.cn/usercenter/apikeys",
        pricing=(0.1, 0.8, 2.0),
    ),
    ProviderPreset(
        key="siliconflow",
        label="硅基流动 SiliconFlow",
        base_url="https://api.siliconflow.cn/v1",
        default_model="deepseek-ai/DeepSeek-V3",
        models=(
            "Qwen/Qwen2.5-72B-Instruct",
            "Qwen/Qwen3-235B-A22B-Instruct-2507",
            "moonshotai/Kimi-K2-Instruct",
        ),
        api_key_url="https://cloud.siliconflow.cn/account/ak",
        note="一个 key 调多家开源模型，适合对比不同模型在同一目标上的表现。",
        pricing=(0.1, 1.0, 2.0),
    ),
    ProviderPreset(
        key="openrouter",
        label="OpenRouter（聚合多家）",
        base_url="https://openrouter.ai/api/v1",
        default_model="deepseek/deepseek-chat-v3.1",
        models=(
            "anthropic/claude-sonnet-4",
            "openai/gpt-4o-mini",
            "google/gemini-2.5-flash",
            "qwen/qwen3-235b-a22b",
        ),
        api_key_url="https://openrouter.ai/keys",
        note="国内访问稳定性一般；好处是一个 key 切换所有模型。",
        pricing=(0.1, 1.0, 3.0),
    ),
    ProviderPreset(
        key="ollama",
        label="本地 Ollama（无 key）",
        base_url="http://127.0.0.1:11434/v1",
        default_model="qwen3:8b",
        models=("qwen2.5:14b", "llama3.1:8b", "deepseek-r1:8b"),
        key_style="ollama",
        api_key_url="https://ollama.com/download",
        note="本地推理不花钱、不出网；8B 级别模型在多代理编排下容易不按 JSON 输出，建议单代理模式。",
        pricing=(0.0, 0.0, 0.0),
    ),
    ProviderPreset(
        key="vllm",
        label="本地 vLLM / LM Studio / 其他兼容服务",
        base_url="http://127.0.0.1:8000/v1",
        default_model="",
        key_style="EMPTY",
        note="自建推理服务：填好 base_url 与模型名即可；不校验 key（可留空）。",
        pricing=(0.0, 0.0, 0.0),
    ),
    ProviderPreset(
        key="custom",
        label="自定义（自己填 base_url 与模型名）",
        base_url="",
        default_model="",
        note="任何 OpenAI 兼容端点：中转站、公司网关、私有部署都走这个。",
        pricing=(0.0, 0.0, 0.0),
    ),
)

_BY_KEY: dict[str, ProviderPreset] = {}
for _preset in PRESETS:
    _BY_KEY[_preset.key] = _preset
    for _alias in _preset.aliases:
        _BY_KEY[_alias.lower()] = _preset

#: 需要 API key 的预设（本地/自定义不强制）。
OPTIONAL_KEY_PROVIDERS = {"ollama", "vllm", "custom"}


def provider_keys() -> list[str]:
    """返回全部预设 key（供 CLI/GUI 做选项）。"""
    return [preset.key for preset in PRESETS]


def get_preset(name: str) -> ProviderPreset | None:
    """按 key/别名取预设（大小写不敏感）。"""
    if not name:
        return None
    return _BY_KEY.get(str(name).strip().lower())


def env_key_name(provider_key: str) -> str:
    """该提供商的 API key 环境变量名，如 `PROVIDER_DEEPSEEK_API_KEY`。"""
    return f"PROVIDER_{str(provider_key).upper().replace('-', '_')}_API_KEY"


def guess_preset(base_url: str) -> ProviderPreset | None:
    """按 base_url 反查预设（导入旧 .env 时用它把 URL 映射回提供商）。"""
    target = str(base_url or "").strip().rstrip("/").lower()
    if not target:
        return None
    for preset in PRESETS:
        if preset.base_url and preset.base_url.rstrip("/").lower() == target:
            return preset
    for preset in PRESETS:
        host = preset.base_url.split("//")[-1].split("/")[0].lower() if preset.base_url else ""
        if host and host in target:
            return preset
    return None


def describe_presets() -> list[dict[str, Any]]:
    """给前端用的预设清单（含默认值与备注）。"""
    return [
        {
            "key": preset.key,
            "label": preset.label,
            "base_url": preset.base_url,
            "default_model": preset.default_model,
            "models": preset.model_list(),
            "key_style": preset.key_style,
            "api_key_url": preset.api_key_url,
            "note": preset.note,
            "env_key": env_key_name(preset.key),
            "key_required": preset.key not in OPTIONAL_KEY_PROVIDERS,
            "pricing": {
                "cache_hit": preset.pricing[0],
                "cache_miss": preset.pricing[1],
                "output": preset.pricing[2],
            },
        }
        for preset in PRESETS
    ]


def pricing_for(provider: str) -> dict[str, float]:
    """返回该提供商的计价（人民币/百万 token），可用 `PRICE_*` 环境变量覆盖。

    计价只用于**估算**费用与预算护栏；不同供应商、不同档位差异很大，
    所以界面会明确写"预估"，并且允许用户自己覆盖。
    """
    preset = get_preset(provider)
    cache_hit, cache_miss, output = preset.pricing if preset else (0.0, 0.0, 0.0)
    return {
        "input_cache_hit_per_million": float(
            os.getenv("PRICE_CACHE_HIT", "") or cache_hit
        ),
        "input_cache_miss_per_million": float(
            os.getenv("PRICE_INPUT", "") or cache_miss
        ),
        "output_per_million": float(os.getenv("PRICE_OUTPUT", "") or output),
        "provider": preset.key if preset else "custom",
        "currency": "CNY",
    }


def pricing_known(provider: str) -> bool:
    """该提供商是否有可用计价（都没有的话费用只能显示为 0，界面要提示）。"""
    if os.getenv("PRICE_INPUT") or os.getenv("PRICE_OUTPUT"):
        return True
    preset = get_preset(provider)
    return bool(preset and any(value > 0 for value in preset.pricing))


# ---------------------------------------------------------------------------
# 按角色的模型覆盖
# ---------------------------------------------------------------------------

#: 编排里的角色 → 环境变量后缀。顺序即界面展示顺序。
ROLE_ENV_SUFFIX: dict[str, str] = {
    "planner": "PLANNER",
    "recon": "RECON",
    "injection": "INJECTION",
    "auth": "AUTH",
    "verify": "VERIFY",
}

ROLE_LABEL: dict[str, str] = {
    "planner": "编排者（拆任务，建议用最强模型）",
    "recon": "侦察（crawl/枚举，建议用便宜快的模型）",
    "injection": "注入验证（要按格式输出 JSON）",
    "auth": "认证与越权",
    "verify": "复核（决定是否上报，建议用最强的模型）",
}


def role_env_key(role: str) -> str:
    """该角色的模型覆盖环境变量名，如 `LLM_VERIFY_MODEL`。"""
    return f"LLM_{ROLE_ENV_SUFFIX.get(role, role.upper())}_MODEL"


@dataclass
class RoleModel:
    """一个角色最终用哪个提供商/模型（解析结果）。"""

    role: str
    provider: str
    model: str
    base_url: str
    api_key: str
    api_key_source: str = ""      # 说明 key 从哪来（界面/日志用）
    overridden: bool = False      # 是否被角色级设置覆盖
    extra: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        mark = "（角色覆盖）" if self.overridden else ""
        return f"{self.role}: {self.provider}/{self.model}{mark}"


def mask_key(key: str) -> str:
    """把 key 变成 `sk-1234…abcd` 形式，用于界面回显（绝不回传完整 key）。"""
    key = str(key or "")
    if not key:
        return ""
    if len(key) <= 10:
        return key[:2] + "…"
    return f"{key[:6]}…{key[-4:]}"


def any_provider_key_configured() -> bool:
    """环境变量里是否已经配过任意提供商的 key（用于首次运行提示）。"""
    if os.getenv("LLM_API_KEY", "").strip():
        return True
    return any(os.getenv(env_key_name(preset.key), "").strip() for preset in PRESETS)
