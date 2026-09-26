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
    """把 SDK 异常归成 (类别, 可读建议)，供界面给出下一步提示。

    **必须带上因果链**：SDK 的顶层摘要常常是 `Connection error.` 这种零信息量的话，
    真正的判据（`getaddrinfo failed` / `连接被积极拒绝` / 证书错误）在 `__cause__` 里。
    只用顶层摘要归类，会把"DNS 解析失败"和"代理端口写错"混成同一条建议。
    """
    from .diagnose import describe_exception

    chain_text = describe_exception(exc)
    # 归类与实际展示都用链条文本：底层 errno/域名才是可操作的信息
    low = chain_text.lower()
    if any(token in low for token in ("supported api model names", "supported model", "available models")):
        # 有些提供商在 400 里直接列出合法模型名——把原文带出来，比泛泛提示有用得多
        return "model", f"模型名不被接受，提供商的合法模型见下；或改用下拉里列出的名称。\n{chain_text[:400]}"
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
    if "getaddrinfo" in low or "name or service not known" in low or "nodename nor servname" in low:
        return "network", (
            f"域名解析失败（不是 key 的问题）：检查 DNS/网络，或 base_url 是否写错。\n{chain_text[:400]}\n"
            "可用 `hexhound doctor` 看分步探测结果。"
        )
    if "refused" in low or "10061" in low:
        return "network", (
            f"连接被拒（对方端口没开，或代理端口写错）：若配了代理，先确认代理在运行。\n{chain_text[:400]}\n"
            "可用 `hexhound doctor` 看分步探测结果。"
        )
    if any(token in low for token in ("timeout", "timed out")):
        return "network", f"请求超时：网络慢或被拦。\n{chain_text[:400]}\n可用 `hexhound doctor` 看分步探测结果。"
    if any(token in low for token in ("certificate", "ssl", "tls")):
        return "network", (
            f"TLS/证书失败：可能是中间设备替换了证书（公司代理、杀软）或根证书异常。\n{chain_text[:400]}\n"
            "可用 `hexhound doctor` 看证书签发者。"
        )
    if any(token in low for token in ("connection", "proxy", "unreachable", "eof", "reset")):
        return "network", (
            "网络不可达：检查 base_url 是否正确、是否需要代理"
            "（国内直连 OpenAI/Anthropic 常失败）。"
            f"\n{chain_text[:400]}\n可用 `hexhound doctor` 看分步探测结果。"
        )
    return "unknown", f"未知错误：把完整报错贴出来，或用 --verbose 看请求细节。\n{chain_text[:400]}"


def build_llm_pool(
    config: Any, *, verbose: bool = False, echo: Any = None
) -> tuple[LLMClient, dict[str, LLMClient]]:
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
    # 网络侧的重要提醒（例如"绕过了已死的系统代理"）必须让人看见，
    # 否则"流量实际走了哪条路"就成了隐式行为。
    if echo is not None and getattr(default, "network_note", ""):
        echo(f"注意：{default.network_note}")
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


def _dead_proxy_detail() -> tuple[bool, str]:
    """代理配置存在但端口连不上时返回 `(True, 说明)`。"""
    from .diagnose import effective_proxy, proxy_health

    try:
        dead, detail = proxy_health()
        if dead:
            resolved = effective_proxy()
            url = resolved.get("https") or resolved.get("http") or ""
            return True, url or detail
    except Exception:  # noqa: BLE001 诊断失败就当没有代理问题
        return False, ""
    return False, ""


def _http_client_for_timeout(timeout: float):
    """需要绕过"已死的代理"时返回一个 `trust_env=False` 的 httpx 客户端，否则 None。

    为什么必须处理（真实事故，已受控复现）：Windows 上"系统代理"是用户级、机器级设置，
    代理客户端退出时**未必把它复位**。于是 `ProxyEnable=1 → 127.0.0.1:7892` 而端口没人监听：
    httpx 在 `trust_env=True` 时经 `urllib.request.getproxies()` 读到它，
    把每个请求都打到死端口 → SDK 重试 3 次 → 约 7.3 秒后 `APIConnectionError`、0 token。
    用户的观感是"关掉 VPN 就再也连不上，而且换任何网络都一样"（系统代理与网络无关）。

    这里的处理很克制：**只在代理端口确实连不上时**才绕开（那种情况下走代理必然失败，
    直连是唯一可能成功的路径），并在 `network_note` 里写明发生了什么，
    绝不静默改变流量走向。
    """
    from .diagnose import proxy_health

    try:
        dead, detail = proxy_health()
    except Exception:  # noqa: BLE001 诊断失败时保持 SDK 默认行为
        return None
    if not dead:
        return None
    try:
        import httpx

        return httpx.Client(timeout=timeout, trust_env=False)
    except Exception:  # noqa: BLE001
        return None


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
        #: 建客户端时的网络侧说明（例如"绕过了已死的系统代理"），供界面/CLI 展示。
        self.network_note = ""
        dead_proxy, proxy_url = _dead_proxy_detail()
        if dead_proxy:
            self.network_note = (
                f"检测到系统/环境代理 {proxy_url} 当前不可用，本次已改为直连。"
                "若你需要走代理出网，请先启动代理客户端；否则请在系统设置里关掉代理。"
            )
        http_client = _http_client_for_timeout(timeout) if dead_proxy else None
        # 本地服务/自定义端点常常不需要 key；SDK 只是要求非空字符串。
        self._client = OpenAI(
            api_key=api_key or "EMPTY",
            base_url=base_url or None,
            timeout=timeout,
            **({"http_client": http_client} if http_client is not None else {}),
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
