"""OpenAI 兼容 LLM 客户端封装（支持按提供商计价与连通性自检）。"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from openai import OpenAI

from .providers import get_preset, pricing_for

Message = dict[str, Any]

#: 兜底计价（没有任何预设信息时用），单位：人民币 / 每百万 token。
DEFAULT_PRICING = {
    "input_cache_hit_per_million": 0.02,
    "input_cache_miss_per_million": 1.0,
    "output_per_million": 2.0,
}


@dataclass(frozen=True)
class LLMUsage:
    """一次 LLM 调用的 token 用量。"""

    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cache_hit_tokens: int = 0
    cache_miss_tokens: int = 0


def estimate_cost(usage: LLMUsage, pricing: dict[str, float] | None = None) -> float:
    """按人民币估算一次 LLM 调用成本，价格为每 100 万 token 的单价。

    pricing 缺省用 DeepSeek 档位；调用方传入 `providers.pricing_for(provider)`
    即可按当前提供商计价（未收录的提供商会退化为 0，界面会提示"费用不可估"）。
    """
    price = pricing or DEFAULT_PRICING
    cache_hit = int(getattr(usage, "cache_hit_tokens", 0))
    cache_miss = int(getattr(usage, "cache_miss_tokens", 0))
    prompt = int(getattr(usage, "prompt_tokens", 0))
    completion = int(getattr(usage, "completion_tokens", 0))
    if cache_hit + cache_miss == 0:
        cache_miss = prompt
    return (
        cache_hit / 1_000_000 * float(price.get("input_cache_hit_per_million", 0.0))
        + cache_miss / 1_000_000 * float(price.get("input_cache_miss_per_million", 0.0))
        + completion / 1_000_000 * float(price.get("output_per_million", 0.0))
    )


@dataclass
class ConnectionCheck:
    """一次连通性自检的结果。"""

    ok: bool
    provider: str = ""
    model: str = ""
    base_url: str = ""
    latency_ms: int = 0
    message: str = ""
    sample: str = ""
    usage: dict[str, Any] | None = None
    category: str = ""  # auth / network / model / unknown / ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "latency_ms": self.latency_ms,
            "message": self.message,
            "sample": self.sample,
            "usage": self.usage,
            "category": self.category,
        }


def classify_error(exc: Exception) -> tuple[str, str]:
    """把 SDK 异常归成 (类别, 可读建议)，供界面给出下一步提示。"""
    text = f"{type(exc).__name__}: {exc}"
    low = text.lower()
    if any(token in low for token in ("supported api model names", "supported model", "available models")):
        # 有些提供商在 400 里直接列出合法模型名——把原文带出来，比泛泛提示有用得多
        return "model", f"模型名不被接受，提供商的合法模型见下；或改用下拉里列出的名称。\n{text[:400]}"
    if "401" in low or "authentication" in low or "invalid api key" in low or "unauthorized" in low:
        return "auth", "API key 无效或未授权：检查 key 是否填对、是否属于该提供商。"
    if "403" in low or "permission" in low:
        return "auth", "key 有效但无权限：确认该 key 已开通此模型（部分平台需先实名/开通）。"
    if (
        "model_not_found" in low
        or "does not exist" in low
        or ("404" in low and "model" in low)
        or ("400" in low and "model" in low)
    ):
        return "model", "模型名不存在：用界面里的模型下拉选一个，或核对提供商文档里的确切名称。"
    if "429" in low or "rate limit" in low or "quota" in low or "insufficient" in low:
        return "quota", "限流或余额不足：稍后重试，或换一个提供商/降低并发（PARALLEL）。"
    if any(token in low for token in ("timeout", "timed out", "connection", "ssl", "proxy", "getaddrinfo", "unreachable")):
        return "network", "网络不可达：检查 base_url 是否正确、是否需要代理（国内直连 OpenAI/Anthropic 常失败）。"
    return "unknown", "未知错误：把完整报错贴出来，或用 --verbose 看请求细节。"


def build_llm_pool(
    config: Any, *, verbose: bool = False, echo: Any = None
) -> tuple["LLMClient", dict[str, "LLMClient"]]:
    """按配置构建「默认客户端 + 按角色的客户端池」。

    只有被显式覆盖的角色才新建客户端；未覆盖的角色直接复用默认客户端，
    因此不配角色模型时行为与单模型完全一致（不多付任何代价）。

    `echo` 可传一个 callable（如 click.echo / print）用于打印角色覆盖信息——
    放在这里是为了让 CLI 与 GUI 共用同一套解析逻辑，避免两边行为漂移。
    """
    default = LLMClient(
        config.api_key,
        config.base_url,
        config.model,
        temperature=getattr(config, "temperature", 0.2),
        provider=config.provider,
        pricing=pricing_for(config.provider),
        label=f"{config.provider}/{config.model}",
    )
    pool: dict[str, LLMClient] = {"planner": default}
    resolver = getattr(config, "role_models_resolved", None)
    if resolver is None:
        return default, pool
    for role, resolved in resolver().items():
        if not resolved.overridden:
            pool[role] = default
            continue
        client = LLMClient(
            resolved.api_key,
            resolved.base_url,
            resolved.model,
            temperature=getattr(config, "temperature", 0.2),
            provider=resolved.provider,
            pricing=pricing_for(resolved.provider),
            label=f"{resolved.provider}/{resolved.model}",
        )
        pool[role] = client
        if verbose and echo is not None:
            echo(
                f"  角色覆盖：{role} → {resolved.provider}/{resolved.model}"
                f"（key 来源 {resolved.api_key_source or '未配置'}）"
            )
    return default, pool


class LLMClient:
    """对 openai.OpenAI 的薄封装，返回补全内容与 token 用量。"""

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        temperature: float = 0.2,
        *,
        provider: str = "custom",
        label: str = "",
        timeout: float = 180.0,
        pricing: dict[str, float] | None = None,
    ) -> None:
        self._model = model
        self._temperature = temperature
        self.provider = provider or "custom"
        self.label = label or self.provider
        self.base_url = base_url or ""
        # 本地服务/自定义端点常常不需要 key；SDK 只是要求非空字符串。
        self._client = OpenAI(
            api_key=api_key or "EMPTY",
            base_url=base_url or None,
            timeout=timeout,
        )
        #: 计价表（按提供商预设，或调用方显式传入）。
        self.pricing = pricing or (pricing_for(self.provider) if get_preset(self.provider) else DEFAULT_PRICING)

    # ---------- 属性 ----------

    @property
    def model(self) -> str:
        return self._model

    def describe(self) -> str:
        return f"{self.provider}/{self._model}"

    # ---------- 调用 ----------

    def complete(self, messages: list[Message]) -> tuple[str, LLMUsage]:
        """发起一次补全，返回 (content, LLMUsage)。"""
        response = self._client.chat.completions.create(
            model=self._model,
            messages=messages,
            temperature=self._temperature,
        )
        content = response.choices[0].message.content or ""
        usage_obj = response.usage
        prompt_tokens = usage_obj.prompt_tokens if usage_obj else 0
        completion_tokens = usage_obj.completion_tokens if usage_obj else 0
        total_tokens = usage_obj.total_tokens if usage_obj else 0
        cache_hit_tokens = getattr(usage_obj, "prompt_cache_hit_tokens", 0) if usage_obj else 0
        cache_miss_tokens = getattr(usage_obj, "prompt_cache_miss_tokens", 0) if usage_obj else 0
        if not cache_hit_tokens and not cache_miss_tokens and usage_obj:
            details = getattr(usage_obj, "prompt_tokens_details", None)
            if details is not None:
                cache_hit_tokens = int(getattr(details, "cached_tokens", 0) or 0)
                cache_miss_tokens = max(0, prompt_tokens - cache_hit_tokens)
        if cache_hit_tokens and not cache_miss_tokens:
            cache_miss_tokens = max(0, prompt_tokens - cache_hit_tokens)
        elif cache_miss_tokens and not cache_hit_tokens:
            cache_hit_tokens = max(0, prompt_tokens - cache_miss_tokens)
        if not cache_hit_tokens and not cache_miss_tokens:
            cache_miss_tokens = prompt_tokens
        return content, LLMUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            cache_hit_tokens=int(cache_hit_tokens or 0),
            cache_miss_tokens=int(cache_miss_tokens or 0),
        )

    def test_connection(self, timeout: float = 30.0) -> ConnectionCheck:
        """发一次最小请求验证 key / base_url / 模型名是否可用。

        这是"设置面板"最关键的一步：换提供商最容易错的就是模型名与 base_url，
        与其跑一次完整审计才发现 404，不如先花一次几百 token 的调用验一下。
        """
        started = time.time()
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": '只回复两个字：可用'}],
                max_tokens=16,
                temperature=0,
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001 这里就是要把各种 SDK 异常转成可读结论
            category, advice = classify_error(exc)
            return ConnectionCheck(
                ok=False,
                provider=self.provider,
                model=self._model,
                base_url=self.base_url,
                latency_ms=int((time.time() - started) * 1000),
                message=f"{advice}\n原始错误：{type(exc).__name__}: {exc}",
                category=category,
            )
        latency = int((time.time() - started) * 1000)
        content = ""
        usage: dict[str, Any] = {}
        try:
            content = (response.choices[0].message.content or "").strip()
        except (AttributeError, IndexError):
            content = ""
        if response.usage is not None:
            usage = {
                "prompt_tokens": int(response.usage.prompt_tokens or 0),
                "completion_tokens": int(response.usage.completion_tokens or 0),
                "total_tokens": int(response.usage.total_tokens or 0),
            }
        return ConnectionCheck(
            ok=True,
            provider=self.provider,
            model=self._model,
            base_url=self.base_url,
            latency_ms=latency,
            message=f"连接正常（{latency} ms）",
            sample=content[:80],
            usage=usage,
            category="ok",
        )
