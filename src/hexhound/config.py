"""不可变配置：从环境变量读取（dotenv 加载后校验）。

v0.3 起支持**模型提供商预设**：不再硬编码 base_url，而是用 `LLM_PROVIDER`
（或 `--provider`）从 `providers.py` 的预设里取；也可以按角色分别指定模型
（`LLM_PLANNER_MODEL` / `LLM_VERIFY_MODEL` …），实现"编排与复核用强模型、
批量侦察用便宜模型"。

解析优先级（每个角色各自解析一次，见 `resolve_role_models`）：
1. 角色级：`LLM_<ROLE>_MODEL`（配合 `LLM_<ROLE>_PROVIDER` 覆盖提供商）
2. 运行级：`LLM_PROVIDER` + `LLM_MODEL`
3. 兼容级：旧键 `LLM_BASE_URL`（能反查回预设就反查，否则当作自定义提供商）

API key：`PROVIDER_<KEY>_API_KEY` 优先，回退共享的 `LLM_API_KEY`。
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

from .providers import (
    OPTIONAL_KEY_PROVIDERS,
    ROLE_ENV_SUFFIX,
    RoleModel,
    env_key_name,
    get_preset,
    guess_preset,
    provider_keys,
    role_env_key,
)

# 在导入时加载 .env（当前工作目录 / exe 目录 / 包目录，见 env_file_candidates）。
load_dotenv()


def env_file_candidates() -> list[Path]:
    """按优先级返回会尝试加载的 `.env` 路径。

    打包成 exe 后，exe 放在项目根目录而用户可能从任何地方调用它，
    因此除了「当前工作目录」，还要看「exe 所在目录」——这样双击运行、
    或在别的目录里调 `C:\\path\\hexhound.exe` 都能读到同一份 .env。
    """
    candidates: list[Path] = [Path.cwd() / ".env"]
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / ".env")
    candidates.append(Path(__file__).resolve().parent / ".env")
    seen: list[Path] = []
    for path in candidates:
        if path not in seen:
            seen.append(path)
    return seen


def load_env_file() -> Path | None:
    """依次尝试加载 .env（已存在的环境变量不被覆盖），返回实际加载到的那份。"""
    for path in env_file_candidates():
        if path.is_file():
            load_dotenv(path, override=False)
            return path
    return None


# 冻结（exe）场景下 cwd 往往是别处，必须再显式找一次 exe 同目录的 .env。
if getattr(sys, "frozen", False):
    load_env_file()


def write_env_file(updates: dict[str, str], path: Path | None = None) -> tuple[Path, list[str]]:
    """把若干键写进 .env（已存在的键就地替换，缺失的追加），写前备份。

    保留注释与未知键——用户常在里面放自己的东西。
    返回 (写入的文件, 实际更新的键名列表)。
    """
    target = Path(path) if path else (env_file_candidates()[0])
    lines: list[str] = []
    if target.exists():
        try:
            lines = target.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        try:
            target.with_suffix(target.suffix + ".bak").write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )
        except OSError:
            pass  # 备份失败不阻塞写入
    remaining = dict(updates)
    changed: list[str] = []
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            out.append(line)
            continue
        key = stripped.split("=", 1)[0].strip()
        if key in remaining:
            out.append(f"{key}={remaining.pop(key)}")
            changed.append(key)
        else:
            out.append(line)
    if remaining:
        if out and out[-1].strip():
            out.append("")
        out.append("# ---- written by HexHound ----")
        for key, value in remaining.items():
            out.append(f"{key}={value}")
            changed.append(key)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(out) + "\n", encoding="utf-8")
    return target, changed

#: 默认**不预设**提供商与模型：谁来用、用哪家、用哪个模型，由使用者显式选择。
#: 这样不会出现"没注意就按某个付费提供商跑起来"的情况，也避免内置模型名过期
#: （各家模型名几个月就换一轮）。`hexhound providers` / `hexhound setup` / GUI 面板
#: 都会引导选择；`--provider` / `--model` 也可以一次性指定。
DEFAULT_PROVIDER = ""
DEFAULT_BASE_URL = ""
DEFAULT_MODEL = ""
DEFAULT_MAX_STEPS = 30
DEFAULT_REQUEST_TIMEOUT = 10
DEFAULT_ALLOWED_HOSTS = "127.0.0.1,localhost"
# 多代理编排相关默认值（与 orchestrator.py 的常量保持一致）。
DEFAULT_MAX_TASKS = 6
DEFAULT_TASK_STEPS = 10
DEFAULT_PARALLEL = 3

#: 允许按角色覆盖模型的角色名（与 providers.ROLE_ENV_SUFFIX 对齐）。
ROLES = tuple(ROLE_ENV_SUFFIX)


def _parse_int(name: str, default: int) -> int:
    """解析整型环境变量，失败时回退默认值。"""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _parse_float(name: str, default: float) -> float:
    """解析浮点环境变量，失败时回退默认值。"""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except ValueError:
        return default


def _normalize_host(raw: str) -> str:
    """把用户输入归一化成裸主机名（容忍带 scheme/端口/路径的 URL）。"""
    value = raw.strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = "//" + value
    return (urlparse(value).hostname or "").lower()


def normalize_base_url(raw: str) -> str:
    """规范化 base_url：补 scheme、去掉尾部斜杠。

    用户常写成 `api.deepseek.com` 或 `https://x/v1/`，这里统一成
    `https://api.deepseek.com` / `https://x/v1`，避免 OpenAI SDK 报奇怪的 URL 错误。
    """
    value = str(raw or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    return value.rstrip("/")


def resolve_provider(name: str = "") -> str:
    """把提供商名解析成合法预设 key；**没有配置就返回空串**（不猜默认值）。

    未显式指定时（`name` 为空且没有 `LLM_PROVIDER`），会尝试从 `LLM_BASE_URL`
    反推——这样 v0.1 的老 .env（只写了 base_url）切过来仍然认得自己的提供商，
    不会被当成别的家去发请求。都没有就返回空串，由 `Config.validate()` 给出
    "请选择提供商" 的可读提示。
    """
    candidate = str(name or os.getenv("LLM_PROVIDER", "") or "").strip().lower()
    if candidate:
        preset = get_preset(candidate)
        return preset.key if preset else "custom"
    legacy_url = normalize_base_url(os.getenv("LLM_BASE_URL", ""))
    if legacy_url:
        preset = guess_preset(legacy_url)
        return preset.key if preset else "custom"
    return ""


def _provider_key_from_env(provider: str) -> tuple[str, str]:
    """返回 (key, 来源说明)：优先 `PROVIDER_<KEY>_API_KEY`，回退 `LLM_API_KEY`。"""
    dedicated = os.getenv(env_key_name(provider), "").strip()
    if dedicated:
        return dedicated, env_key_name(provider)
    shared = os.getenv("LLM_API_KEY", "").strip()
    if shared:
        return shared, "LLM_API_KEY"
    return "", ""


def _legacy_or_preset_base_url(provider: str) -> str:
    """确定 base_url：显式 `LLM_BASE_URL` > 该提供商预设的地址 > 空串。

    注意顺序：用户手填的 URL 永远优先——允许"用 deepseek 这个预设名，
    但指向自己的中转地址"这种混搭。
    """
    preset = get_preset(provider)
    explicit = normalize_base_url(os.getenv("LLM_BASE_URL", ""))
    if explicit:
        return explicit
    if preset is not None:
        return normalize_base_url(preset.base_url)
    # 没有预设（provider 为空或未知）：只能从 URL 反推，反推不到就留空由校验报错。
    return normalize_base_url(os.getenv("LLM_BASE_URL", ""))


@dataclass(frozen=True)
class Config:
    """运行时配置，全部字段不可变。"""

    api_key: str
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    provider: str = DEFAULT_PROVIDER
    #: 按角色覆盖的提供商/模型（空表示跟随 provider/model）。
    role_models: dict[str, str] = field(default_factory=dict)
    role_providers: dict[str, str] = field(default_factory=dict)
    max_steps: int = DEFAULT_MAX_STEPS
    request_timeout: int = DEFAULT_REQUEST_TIMEOUT
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    # --- 编排 ---
    max_tasks: int = DEFAULT_MAX_TASKS
    task_steps: int = DEFAULT_TASK_STEPS
    parallel: int = DEFAULT_PARALLEL
    use_swarm: bool = True
    # --- 预算护栏（0 = 不限制）---
    rate_limit: float = 0.0
    max_cost: float = 0.0
    max_tokens: int = 0
    max_llm_calls: int = 0
    max_tool_calls: int = 0
    max_seconds: float = 0.0
    #: 采样温度（推理型模型建议保持默认）。
    temperature: float = 0.2

    # ---------- 构建 ----------

    @classmethod
    def from_env(cls) -> "Config":
        """从环境变量构建并校验配置。"""
        provider = resolve_provider()
        base_url = _legacy_or_preset_base_url(provider)
        preset = get_preset(provider)
        model = os.getenv("LLM_MODEL", "").strip() or (
            preset.default_model if preset else ""
        )
        api_key, source = _provider_key_from_env(provider)
        if not base_url and provider and provider != "custom":
            base_url = DEFAULT_BASE_URL

        role_models: dict[str, str] = {}
        role_providers: dict[str, str] = {}
        for role in ROLES:
            role_model = os.getenv(role_env_key(role), "").strip()
            if role_model:
                role_models[role] = role_model
            role_provider = os.getenv(
                f"LLM_{ROLE_ENV_SUFFIX[role]}_PROVIDER", ""
            ).strip()
            if role_provider:
                role_providers[role] = resolve_provider(role_provider) or "custom"

        max_steps = _parse_int("MAX_STEPS", DEFAULT_MAX_STEPS)
        request_timeout = _parse_int("REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT)
        allowed_hosts = frozenset(
            host
            for host in (
                _normalize_host(h)
                for h in os.getenv("ALLOWED_HOSTS", DEFAULT_ALLOWED_HOSTS).split(",")
            )
            if host
        )
        config = cls(
            api_key=api_key,
            # 注意：这里不能写 `base_url or DEFAULT_BASE_URL`——自定义提供商故意留空时，
            # 会被兜底成 DeepSeek 的地址，于是"没填 URL"这种配置错误被静默掩盖。
            base_url=base_url,
            model=model,
            provider=provider,
            role_models=role_models,
            role_providers=role_providers,
            max_steps=max(1, max_steps),
            request_timeout=max(1, request_timeout),
            allowed_hosts=allowed_hosts,
            max_tasks=max(1, min(_parse_int("MAX_TASKS", DEFAULT_MAX_TASKS), 12)),
            task_steps=max(4, min(_parse_int("TASK_STEPS", DEFAULT_TASK_STEPS), 30)),
            parallel=max(1, min(_parse_int("PARALLEL", DEFAULT_PARALLEL), 6)),
            use_swarm=(os.getenv("USE_SWARM", "1").strip().lower() not in ("0", "false", "no")),
            rate_limit=max(0.0, _parse_float("RATE_LIMIT", 0.0)),
            max_cost=max(0.0, _parse_float("MAX_COST", 0.0)),
            max_tokens=max(0, _parse_int("MAX_TOKENS", 0)),
            max_llm_calls=max(0, _parse_int("MAX_LLM_CALLS", 0)),
            max_tool_calls=max(0, _parse_int("MAX_TOOL_CALLS", 0)),
            max_seconds=max(0.0, _parse_float("MAX_SECONDS", 0.0)),
            temperature=min(2.0, max(0.0, _parse_float("TEMPERATURE", 0.2))),
        )
        config.validate()
        return config

    # ---------- 按角色解析模型 ----------

    def role_model(self, role: str) -> RoleModel:
        """解析某个角色最终使用的 (提供商, 模型, base_url, key)。

        角色级覆盖只在"该角色的模型或提供商被显式设置"时生效；
        否则完全跟随运行级 provider/model/base_url。
        """
        role = str(role or "").strip().lower()
        explicit_model = self.role_models.get(role, "")
        explicit_provider = self.role_providers.get(role, "")
        if not explicit_model and not explicit_provider:
            return RoleModel(
                role=role,
                provider=self.provider,
                model=self.model,
                base_url=self.base_url,
                api_key=self.api_key,
                api_key_source=self.api_key_source,
                overridden=False,
            )
        provider = explicit_provider or self.provider
        preset = get_preset(provider)
        model = explicit_model or (preset.default_model if preset else "") or self.model
        if provider == self.provider and not explicit_provider:
            # 只换模型不换提供商：沿用同一套 URL 与 key。
            base_url, api_key, source = self.base_url, self.api_key, self.api_key_source
        else:
            base_url = normalize_base_url(preset.base_url) if preset else self.base_url
            api_key, source = _provider_key_from_env(provider)
            if not api_key:
                # 该提供商没配 key → 退回运行级 key，避免角色覆盖直接跑不起来。
                # 注意 source 只取"原来是哪个变量"，不再二次拼接——否则会写出
                # "LLM_API_KEY（回退）（回退）"这种滑稽的来源说明。
                api_key, source = self.api_key, self.api_key_source
        return RoleModel(
            role=role,
            provider=provider,
            model=model,
            base_url=base_url,
            api_key=api_key,
            api_key_source=source,
            overridden=True,
        )

    def role_models_resolved(self) -> dict[str, RoleModel]:
        """所有角色（含 planner）的解析结果，供日志/界面展示。"""
        return {role: self.role_model(role) for role in ROLES}

    @property
    def api_key_source(self) -> str:
        """当前 key 来自哪个环境变量（界面回显用，不泄露内容）。"""
        _, source = _provider_key_from_env(self.provider)
        return source

    def describe(self) -> str:
        """一行摘要：提供商/模型 + 角色覆盖。"""
        parts = [f"{self.provider}/{self.model}"]
        overrides = [
            f"{role}={model}" for role, model in sorted(self.role_models.items()) if model
        ]
        if overrides:
            parts.append("角色覆盖 " + ", ".join(overrides))
        return "；".join(parts)

    # ---------- 校验 ----------

    def validate(self) -> None:
        """校验配置；缺 key / 缺提供商 / 缺 base_url 时抛出可读错误。"""
        if not self.provider:
            raise ValueError(
                "还没有选择模型提供商。任选一种方式：\n"
                "  1) hexhound setup                     交互式向导\n"
                "  2) hexhound providers                 看全部预设（含去哪拿 key）\n"
                "  3) .env 里写 LLM_PROVIDER=deepseek    并填 LLM_API_KEY\n"
                "  4) hexhound audit --provider qwen --target <URL>   一次性指定"
            )
        preset = get_preset(self.provider)
        key_optional = self.provider in OPTIONAL_KEY_PROVIDERS
        if not key_optional and not self.api_key:
            where = (
                f"请在 .env 里设置 {env_key_name(self.provider)}"
                f"（或共享的 LLM_API_KEY）"
            )
            hint = f"，key 可在 {preset.api_key_url} 获取" if preset and preset.api_key_url else ""
            raise ValueError(
                f"缺少 {self.provider} 的 API 密钥：{where}{hint}。"
                "也可以在 GUI 的「模型提供商」面板里选择预设并填入 key。"
            )
        if not self.base_url:
            raise ValueError(
                f"提供商 {self.provider!r} 没有 base_url：自定义提供商必须填 LLM_BASE_URL"
                "（例如 https://your-gateway/v1）。"
            )
        if not self.model:
            raise ValueError(
                f"提供商 {self.provider!r} 没有指定模型：请设置 LLM_MODEL"
                "（`hexhound providers` 会列出各家的常用模型名）。"
            )
        if not self.allowed_hosts:
            raise ValueError("ALLOWED_HOSTS 不能为空，至少需要一个可访问的白名单主机。")


def available_providers() -> list[str]:
    """已配置 key 的提供商（界面用：哪些预设可以直接用）。"""
    ready: list[str] = []
    for key in provider_keys():
        if get_preset(key) and key in OPTIONAL_KEY_PROVIDERS:
            ready.append(key)
            continue
        if os.getenv(env_key_name(key), "").strip() or os.getenv("LLM_API_KEY", "").strip():
            ready.append(key)
    return ready


def provider_from_base_url(base_url: str) -> str:
    """把 base_url 映射回预设 key（导入旧配置时用）。"""
    preset = guess_preset(base_url)
    return preset.key if preset else "custom"
