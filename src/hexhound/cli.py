"""click CLI：`hexhound audit`（多代理黑盒 / 源码审计）+ `hexhound setup` 向导。

v0.2 的 audit 默认走**多代理编排**（对标 Strix 的 manager+workers 与 PentAGI 的
flow→task 分层）：编排者拆任务 → 侦察/注入/认证并发 → 复核候选 → 合并去重。
`--single` 可退回 v0.1 的单代理 ReAct 循环。
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlparse

import click

from . import __version__
from .agent import ReActAgent
from .budget import Budget, limits_from_config
from .console import (
    MARK_FAIL,
    MARK_OK,
    MARK_SKIP,
    MARK_WARN,
    enable_utf8_console,
)
from .providers import (
    ROLE_ENV_SUFFIX,
    ROLE_LABEL,
    describe_presets,
    env_key_name,
    get_preset,
    provider_keys,
)
from .config import (
    DEFAULT_PROVIDER,
    ROLES,
    Config,
    normalize_base_url,
    resolve_provider,
    write_env_file,
)
from .llm import LLMClient, build_llm_pool
from .memory import HostMemory, RunArtifacts, data_home
from .orchestrator import (
    DEFAULT_TASK_STEPS,
    MAX_PARALLEL,
    MAX_TASKS,
    Orchestrator,
    SwarmCallbacks,
)
from .report import build_diff, write_report
from .sandbox import Sandbox, detect_runtime, sandbox_report
from .submission import write_butian_package
from .surface import SEVERITY_RANK, AttackSurface
from .tools import ToolRegistry


def _project_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / "HexHound"
    return Path(__file__).resolve().parents[2]


PROJECT_ROOT = _project_root()

_ENV_DEFAULTS = {
    "LLM_BASE_URL": "https://api.deepseek.com",
    "LLM_MODEL": "deepseek-v4-flash",
    "MAX_STEPS": "30",
    "REQUEST_TIMEOUT": "10",
    "ALLOWED_HOSTS": "127.0.0.1,localhost",
    "MAX_COST": "0",
    "MAX_TOOL_CALLS": "0",
}


@click.group()
@click.version_option(__version__, prog_name="hexhound")
def main() -> None:
    """HexHound：AI 驱动的漏洞挖掘 Agent（侦察 → 探测 → 复核 → 记录）。"""
    # 中文 Windows 控制台默认 GBK：不切 UTF-8 的话，输出任何非 GBK 字符都会崩。
    enable_utf8_console()


def _llm_label(client: Any) -> str:
    """取客户端的展示名（容错：没有 describe() 也要能显示，而不是崩掉）。"""
    describe = getattr(client, "describe", None)
    if callable(describe):
        try:
            return str(describe())
        except Exception:  # noqa: BLE001 展示信息取不到就算了
            pass
    model = getattr(client, "model", "") or getattr(client, "_model", "")
    provider = getattr(client, "provider", "")
    return f"{provider}/{model}" if provider and model else str(model or "unknown")


def _build_llm_pool(config: Config, verbose: bool = False) -> tuple[LLMClient, dict[str, LLMClient]]:
    """按配置构建「默认客户端 + 按角色的客户端池」（实现见 llm.build_llm_pool）。"""
    return build_llm_pool(config, verbose=verbose, echo=click.echo)


def _apply_model_overrides(
    config: Config,
    *,
    provider: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    role_models: tuple[str, ...] = (),
    temperature: float | None = None,
) -> Config:
    """把命令行传来的模型设置合并进配置（命令行 > .env）。

    换提供商会自动带上该预设的 base_url 与默认模型（除非命令行另行指定），
    这样 `--provider openai` 一条命令就能切换，不用手抄 URL。
    """
    changes: dict[str, object] = {}
    resolved_provider = config.provider
    if provider:
        resolved_provider = resolve_provider(provider)
        preset = get_preset(resolved_provider)
        changes["provider"] = resolved_provider
        if resolved_provider != config.provider:
            # 切到别的提供商：base_url 与默认模型跟随预设。
            # 下面的 `if base_url` / `if model` 会再用命令行显式值覆盖回来，
            # 因此 `--provider openai --model gpt-4o` 里的 --model 一定是最终值。
            if not base_url:
                changes["base_url"] = normalize_base_url(preset.base_url) if preset else config.base_url
            if not model:
                changes["model"] = (preset.default_model if preset else "") or config.model
            # key 也跟随该提供商的专用变量（没配就退回原 key，后面由校验提示）
            dedicated = os.getenv(env_key_name(resolved_provider), "").strip()
            if dedicated:
                changes["api_key"] = dedicated
    if base_url:
        changes["base_url"] = normalize_base_url(base_url)
        # 手填 URL 却没指定提供商 → 视为自定义端点
        if not provider and resolved_provider != "custom":
            changes.setdefault("provider", "custom")
    if model:
        changes["model"] = model.strip()
    if api_key:
        changes["api_key"] = api_key.strip()
    if temperature is not None:
        changes["temperature"] = min(2.0, max(0.0, temperature))

    parsed_roles: dict[str, str] = dict(config.role_models)
    for item in role_models:
        if "=" not in item:
            raise click.ClickException(
                f"--role-model 需要「角色=模型」格式，收到 {item!r}。"
                f"可用角色：{', '.join(ROLES)}"
            )
        role, _, value = item.partition("=")
        role = role.strip().lower()
        value = value.strip()
        if role not in ROLES:
            raise click.ClickException(
                f"未知角色 {role!r}（--role-model）。可用角色：{', '.join(ROLES)}"
            )
        if not value:
            raise click.ClickException(f"--role-model {role}= 的模型名为空。")
        parsed_roles[role] = value
    if parsed_roles != config.role_models:
        changes["role_models"] = parsed_roles

    updated = replace(config, **changes) if changes else config
    updated.validate()
    return updated


def _run_audit(
    path: str | None,
    target: str,
    mode: str,
    max_steps: int | None,
    output: str,
    verbose: bool,
    *,
    swarm: bool = True,
    max_tasks: int | None = None,
    task_steps: int | None = None,
    parallel: int | None = None,
    max_cost: float | None = None,
    rate_limit: float | None = None,
    fail_on: str = "",
    provider: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    role_models: tuple[str, ...] = (),
    temperature: float | None = None,
    use_sandbox: bool = True,
    map_loopback: bool = False,
    coverage_sweep: bool = True,
) -> int:
    """审计的公共入口，被 audit 命令与 setup 向导复用。返回退出码。"""
    try:
        config = Config.from_env()
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    config = _apply_model_overrides(
        config,
        provider=provider,
        model=model,
        base_url=base_url,
        api_key=api_key,
        role_models=role_models,
        temperature=temperature,
    )

    if max_steps is not None:
        config = replace(config, max_steps=max_steps)
    if max_cost is not None:
        config = replace(config, max_cost=max_cost)
    if rate_limit is not None:
        config = replace(config, rate_limit=rate_limit)

    # 目标主机必须在白名单内，否则 http_request 会被全部拒绝。
    target_host = (urlparse(target).hostname or "").lower()
    if target_host not in config.allowed_hosts:
        allowed = ", ".join(sorted(config.allowed_hosts))
        raise click.ClickException(
            f"目标主机 {target_host!r} 不在 ALLOWED_HOSTS 白名单（{allowed}）内，"
            "请在 .env 的 ALLOWED_HOSTS 中追加该主机后重试（或运行 hexhound setup）。"
        )

    if mode == "source":
        if not path:
            raise click.ClickException("source 模式需要提供源码目录 PATH。")
        if target_host not in ("127.0.0.1", "localhost", "::1"):
            click.echo(
                f"{MARK_WARN} 注意：source 模式审计的是【本地源码目录 {path}】，"
                f"而目标 {target_host} 是远程站点；若你没有它的源码，应改用 --mode blackbox。"
            )
        base_dir = Path(path)
        if not base_dir.is_dir():
            raise click.ClickException(f"源码目录不存在：{path}")
        goal = (
            f"审计源码目录 {path}，并对靶场 {target} 做黑盒验证，"
            "只记录有真实请求证据的漏洞。"
        )
    else:
        base_dir = Path.cwd()
        goal = (
            f"对目标 {target} 做黑盒安全评估（仅限授权 scope，主机白名单见配置），"
            "按 OWASP Top 10 覆盖，只记录有真实请求证据的漏洞。"
        )

    llm, llm_pool = _build_llm_pool(config, verbose)
    budget = Budget(limits_from_config(config))

    # 真工具沙箱：自动探测执行环境；不可用则如实降级（报告里会写明）
    sandbox = None
    if use_sandbox:
        sandbox = Sandbox(
            allowed_hosts=config.allowed_hosts,
            exec_timeout=max(120, config.request_timeout * 30),
            map_loopback=map_loopback,
            verbose=verbose,
        )
        probe = sandbox.probe()
        if probe.get("ok"):
            present = sorted(name for name, ok in (probe.get("tools") or {}).items() if ok)
            click.echo(f"真工具沙箱：{probe.get('runtime')}（可用工具：{', '.join(present)}）")
            if map_loopback:
                click.echo(f"  回环目标映射到：{sandbox.host_gateway()}")
        else:
            click.echo(f"{MARK_WARN} 真工具沙箱不可用，降级为内置 HTTP 探测：{probe.get('reason')}")
            if probe.get("hint"):
                click.echo(f"  {probe['hint']}")
            sandbox = None
    artifacts = RunArtifacts(target)
    surface = AttackSurface(target=target, mode=mode, path=artifacts.surface_path)
    workers = parallel or MAX_PARALLEL

    def on_event(event: dict) -> None:
        kind = event.get("kind")
        if kind == "plan":
            click.echo(f"\n=== 任务计划（{len(event.get('tasks') or [])} 个）===")
            for task in event.get("tasks") or []:
                click.echo(f"  [{task['id']}] {task['role']}: {str(task['objective'])[:90]}")
        elif kind == "wave":
            click.echo(
                f"\n=== 第 {event.get('wave')} 波：{event.get('count')} 个子任务（并发 {workers}）==="
            )
        elif kind == "task_start":
            task = event["task"]
            model = event.get("model") or ""
            click.echo(
                f"\n>>> [{task['id']}] {task['role']}"
                + (f" [{model}]" if model else "")
                + f": {str(task['objective'])[:80]}"
            )
        elif kind == "task_end":
            task = event["task"]
            # 未收尾/失败要一眼看出来：用 [!!] 而不是 [OK]。
            flag = MARK_OK if task.get("outcome") == "done" else MARK_WARN
            label = task.get("outcome_label") or task.get("outcome")
            click.echo(
                f"{flag} [{task['id']}] {label}："
                f"{str(task.get('summary') or task.get('error') or '')[:120]}"
            )
        elif kind == "notice":
            click.echo(f"  ! [{event.get('task')}] {event.get('level')}: {event.get('message')}")
        elif kind == "dedupe":
            click.echo(f"  去重：合并了 {event.get('merged')} 条重复上报")
        elif kind == "plan_error":
            click.echo(f"  ! 规划回退：{event.get('message')}")

    def on_step(step: dict) -> None:
        if not verbose:
            return
        observation = str(step.get("observation") or "").replace("\n", " ")[:160]
        click.echo(f"  [{step.get('worker', '?')}] {step.get('action')}: {observation}")

    callbacks = SwarmCallbacks(on_step=on_step, on_event=on_event)
    llm_label = _llm_label(llm)
    click.echo(
        f"开始审计：{target}（模式 {mode}，模型 {llm_label}，"
        f"{'多代理编排' if swarm else '单代理 ReAct'}）"
    )
    overrides = [
        f"{role}={_llm_label(client)}"
        for role, client in sorted(llm_pool.items())
        if client is not llm
    ]
    if overrides:
        click.echo("角色模型：" + "，".join(overrides))
    if config.max_cost:
        click.echo(f"预算上限：¥{config.max_cost:.2f}")
    if config.max_tool_calls:
        click.echo(f"请求上限：{config.max_tool_calls} 次工具调用")
    if config.rate_limit:
        click.echo(f"限速：每次请求间隔 ≥{config.rate_limit:.2f}s")

    if swarm and mode == "blackbox":
        orchestrator = Orchestrator(
            llm,
            target=target,
            goal=goal,
            mode=mode,
            base_dir=base_dir,
            allowed_hosts=config.allowed_hosts,
            timeout=config.request_timeout,
            max_tasks=max_tasks or MAX_TASKS,
            task_steps=task_steps or DEFAULT_TASK_STEPS,
            parallel=workers,
            budget=budget,
            artifacts=artifacts,
            surface=surface,
            rate_limit=config.rate_limit,
            verbose=verbose,
            callbacks=callbacks,
            memory=HostMemory(target),
            llm_pool=llm_pool,
            sandbox=sandbox,
            coverage_sweep=coverage_sweep,
        )
        result = orchestrator.run()
    else:
        registry = ToolRegistry(
            base_dir=base_dir,
            allowed_hosts=config.allowed_hosts,
            timeout=config.request_timeout,
            mode=mode,
            surface=surface,
            budget=budget,
            worker_id="W1",
            role="source" if mode == "source" else "blackbox",
            artifacts=artifacts,
            rate_limit=config.rate_limit,
            sandbox=sandbox,
        )
        agent = ReActAgent(
            llm,
            registry,
            max_steps=config.max_steps,
            verbose=verbose,
            budget=budget,
            target=target,
            role="source" if mode == "source" else "blackbox",
        )
        result = agent.run(goal, on_step=on_step)
        artifacts.save_surface(surface)

    output_path = Path(output)
    if not output_path.is_absolute():
        output_path = PROJECT_ROOT / output_path
    out_path = write_report(result, goal, output_path)
    package_path = write_butian_package(result, out_path)
    verified = [item for item in result.findings if item.get("status") != "candidate"]
    candidates = [item for item in result.findings if item.get("status") == "candidate"]
    click.echo("")
    click.echo(
        f"完成：{len(result.tasks) or 1} 个子任务 / {result.steps_used or len(result.steps)} 步，"
        f"已复核 {len(verified)} 条，待复核 {len(candidates)} 条。"
    )
    for finding in result.findings:
        mark = MARK_OK if finding.get("status") != "candidate" else "?"
        click.echo(f"  {mark} [{finding['severity']}] {finding['title']} -> {finding.get('url', '')}")

    # 跨运行对比：新增/仍存在/疑似已修复必须出现在终端结论里。
    # 报告章节容易被略过，而"这次比上次好了还是坏了"是复测场景最先要看的结论。
    run_diff = build_diff(result)
    if run_diff is not None and not run_diff.is_empty():
        counts = run_diff.counts()
        click.echo(
            f"与上次运行对比（{run_diff.previous_at}）："
            f"新增 {counts['new']} ｜仍存在 {counts['persisting']} ｜"
            f"疑似已修复 {counts['fixed']} ｜状态未知 {counts['unknown']}"
        )
        if counts["new"]:
            for item in run_diff.new[:5]:
                click.echo(f"  {MARK_WARN} 新增 [{item['severity']}] {item['title']} -> {item['url']}")
        if counts["unknown"]:
            untested = sum(
                1 for item in run_diff.unknown if "仍报出其他问题" not in item["reason"]
            )
            other = counts["unknown"] - untested
            detail = []
            if untested:
                detail.append(f"{untested} 条端点未覆盖")
            if other:
                detail.append(f"{other} 条该端点仍报出其他问题")
            click.echo(
                f"  {MARK_WARN} {counts['unknown']} 条上次报过的问题本次无法判定为已修复"
                f"（{'、'.join(detail) or '原因见报告'}）——不要当作已修复。"
            )

    click.echo(f"报告：{out_path}")
    if package_path:
        click.echo(f"补天提交包：{package_path}")
    if result.artifacts_dir:
        click.echo(f"运行产物（PoC/攻面/台账）：{result.artifacts_dir}")
    click.echo("预算：" + budget.describe())
    if result.final_summary:
        click.echo(f"总结：\n{result.final_summary}")

    # 非交互退出码（对标 Strix：命中阈值返回 2，便于 CI 判定）。
    if fail_on:
        threshold = SEVERITY_RANK.get(fail_on.lower(), 99)
        hit = [
            item for item in verified
            if SEVERITY_RANK.get(str(item.get("severity") or "info").lower(), 99) <= threshold
        ]
        if hit:
            click.echo(f"--fail-on {fail_on}：命中 {len(hit)} 条达到阈值的已复核漏洞。")
            return 2
    return 0


@main.command()
@click.argument("path", required=False, type=str, default=None)
@click.option("--target", required=True, help="目标 URL（如 http://127.0.0.1:5000）")
@click.option(
    "--mode",
    type=click.Choice(["source", "blackbox"], case_sensitive=False),
    default="source",
    show_default=True,
    help="source=源码审计（需提供 PATH）；blackbox=纯 URL 黑盒（无需 PATH）",
)
@click.option("--single", is_flag=True, help="用 v0.1 的单代理 ReAct 循环（默认是多代理编排）")
@click.option("--max-tasks", type=int, default=None, help=f"最多子任务数（默认 {MAX_TASKS}）")
@click.option("--task-steps", type=int, default=None, help=f"每个子任务步数（默认 {DEFAULT_TASK_STEPS}）")
@click.option("--parallel", type=int, default=None, help=f"并发子代理数（默认 {MAX_PARALLEL}）")
@click.option("--max-steps", type=int, default=None, help="单代理模式的最大步数（默认取 MAX_STEPS）")
@click.option("--max-cost", type=float, default=None, help="本次运行费用上限（人民币，如 0.5）")
@click.option("--rate-limit", type=float, default=None, help="每次请求的最小间隔秒数（默认 0=不限速）")
@click.option(
    "--provider",
    "provider",
    default=None,
    help="模型提供商预设（deepseek/openai/anthropic/gemini/qwen/moonshot/zhipu/siliconflow/openrouter/ollama/vllm/custom），"
    "用 `hexhound providers` 看全部",
)
@click.option("--model", "model", default=None, help="模型名（覆盖预设默认值）")
@click.option("--base-url", "base_url", default=None, help="自定义 base_url（用中转/私有网关时填）")
@click.option("--api-key", "api_key", default=None, help="API key（一般写在 .env，不建议写命令行）")
@click.option(
    "--role-model",
    "role_models",
    multiple=True,
    metavar="角色=模型",
    help="按角色指定模型（可重复），如 --role-model verify=deepseek-v4-pro --role-model recon=deepseek-v4-flash",
)
@click.option("--temperature", type=float, default=None, help="采样温度（默认 0.2）")
@click.option(
    "--sandbox/--no-sandbox",
    "use_sandbox",
    default=True,
    show_default=True,
    help="启用真工具沙箱（sqlmap/nmap/nuclei/ffuf…），自动探测 Docker/Podman/WSL",
)
@click.option(
    "--sandbox-map-loopback/--no-sandbox-map-loopback",
    "map_loopback",
    default=False,
    show_default=True,
    help="是否把 127.0.0.1 目标改写成宿主可达地址（目标跑在宿主上时开；目标在沙箱内则关）",
)
@click.option(
    "--coverage-sweep/--no-coverage-sweep",
    "coverage_sweep",
    default=True,
    show_default=True,
    help="收尾前对从未被触碰的端点做强制补扫（消除报告盲区；关掉更快但可能漏测）",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
    default=None,
    help="存在该等级及以上的已复核漏洞时返回退出码 2（CI 用）",
)
@click.option("--output", default="reports/report.md", show_default=True, help="报告输出路径")
@click.option("--verbose", is_flag=True, help="打印每一步的工具调用与观察结果")
def audit(
    path: str | None,
    target: str,
    mode: str,
    single: bool,
    max_tasks: int | None,
    task_steps: int | None,
    parallel: int | None,
    max_steps: int | None,
    max_cost: float | None,
    rate_limit: float | None,
    fail_on: str | None,
    provider: str | None,
    model: str | None,
    base_url: str | None,
    api_key: str | None,
    role_models: tuple[str, ...],
    temperature: float | None,
    use_sandbox: bool,
    map_loopback: bool,
    coverage_sweep: bool,
    output: str,
    verbose: bool,
) -> None:
    """审计源码目录（source）或对 URL 做黑盒评估（blackbox），生成证据成立的漏洞报告。"""
    code = _run_audit(
        path,
        target,
        mode,
        max_steps,
        output,
        verbose,
        swarm=not single,
        max_tasks=max_tasks,
        task_steps=task_steps,
        parallel=parallel,
        max_cost=max_cost,
        rate_limit=rate_limit,
        fail_on=fail_on or "",
        provider=provider,
        model=model,
        base_url=base_url,
        api_key=api_key,
        role_models=role_models,
        temperature=temperature,
        use_sandbox=use_sandbox,
        map_loopback=map_loopback,
        coverage_sweep=coverage_sweep,
    )
    if code:
        raise SystemExit(code)


def _load_env_file() -> dict[str, str]:
    """读取当前 .env（用于 setup 的默认值，避免覆盖已有配置）。"""
    env_path = Path(".env")
    if not env_path.exists():
        return {}
    result: dict[str, str] = {}
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        result[key.strip()] = value.strip()
    return result


@main.command("report")
@click.option(
    "--run",
    "run_dir",
    default="latest",
    show_default=True,
    help="运行产物目录（~/.hexhound/runs/<名>），或 latest 取同目标最近一次",
)
@click.option("--target", default="", help="目标 URL（配合 --run latest 定位最近一次运行）")
@click.option("--promote", multiple=True, help="把指定候选提升为已复核（可重复，如 --promote HH-003）")
@click.option("--exclude", multiple=True, help="从报告中剔除指定编号（可重复，如 --exclude HH-002）")
@click.option("--output", default="reports/report.md", show_default=True, help="报告输出路径")
@click.option("--json-out", default="", help="同时输出 JSON 报告（可选）")
def report_cmd(
    run_dir: str,
    target: str,
    promote: tuple[str, ...],
    exclude: tuple[str, ...],
    output: str,
    json_out: str,
) -> None:
    """离线重渲染报告：读取已保存的攻面快照，不发起任何请求、不调用 LLM。

    用途：人工复核候选后，把确认的候选提升（--promote）、把误报剔除（--exclude），
    再生成最终交付报告。
    """
    from .agent import AgentResult
    from .report import to_json  # 局部导入避免顶层循环依赖

    path = _resolve_run_dir(run_dir, target)
    if path is None:
        raise click.ClickException(
            "找不到运行产物目录。请用 --run 指定 ~/.hexhound/runs/<目录名>，"
            "或先跑一次 audit。"
        )
    surface_file = path / "surface.json"
    if not surface_file.exists():
        raise click.ClickException(f"{path} 里没有 surface.json（该次运行可能未落盘攻面）。")

    surface = AttackSurface.load(surface_file, target=target, mode="blackbox")
    promoted: list[str] = []
    for ref in promote:
        candidate = surface.claim_candidate(ref)
        if candidate is None:
            click.echo(f"{MARK_WARN} 候选 {ref} 不存在（用 run.json/surface.json 里的编号），已跳过。", err=True)
            continue
        surface.promote(candidate, "manual", "人工复核确认")
        promoted.append(candidate.id)

    findings = surface.finding_dicts()
    dropped: list[str] = []
    if exclude:
        wanted = {str(item).strip() for item in exclude if str(item).strip()}
        kept = []
        for finding in findings:
            if str(finding.get("id")) in wanted:
                dropped.append(str(finding.get("id")))
            else:
                kept.append(finding)
        findings = kept

    tasks: list[dict] = []
    ledger_file = path / "tasks.json"
    if ledger_file.exists():
        try:
            tasks = [
                {
                    "id": record.get("task_id"),
                    "role": record.get("role"),
                    "objective": record.get("objective"),
                    "outcome": record.get("status"),
                    "summary": record.get("summary"),
                    "error": record.get("error"),
                }
                for record in (json.loads(ledger_file.read_text(encoding="utf-8")).get("tasks") or [])
            ]
        except (OSError, json.JSONDecodeError):
            tasks = []

    goal = f"离线重渲染自 {path.name}"
    result = AgentResult(
        findings=findings,
        surface=surface,
        tasks=tasks,
        final_summary="（离线重渲染：未重新执行任何探测）",
        finish_reason="offline",
        artifacts_dir=str(path),
    )
    output_path = Path(output)
    if not output_path.is_absolute():
        output_path = PROJECT_ROOT / output_path
    out_path = write_report(result, goal, output_path)
    if json_out:
        json_path = Path(json_out)
        if not json_path.is_absolute():
            json_path = PROJECT_ROOT / json_path
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(
            json.dumps(to_json(result, goal), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        click.echo(f"JSON 报告：{json_path}")

    verified = [item for item in findings if item.get("status") != "candidate"]
    candidates = [item for item in findings if item.get("status") == "candidate"]
    click.echo(f"来源：{path}")
    if promoted:
        click.echo(f"已提升候选：{', '.join(promoted)}")
    if dropped:
        click.echo(f"已剔除编号：{', '.join(dropped)}")
    click.echo(f"已复核 {len(verified)} 条 / 待复核 {len(candidates)} 条")
    click.echo(f"报告：{out_path}")


def _resolve_run_dir(run_dir: str, target: str) -> Path | None:
    """把 --run 解析成实际目录：支持绝对/相对路径、latest。"""
    if run_dir and run_dir != "latest":
        candidate = Path(run_dir)
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        return candidate if candidate.is_dir() else None
    runs_root = data_home() / "runs"
    if not runs_root.is_dir():
        return None
    dirs = [item for item in runs_root.iterdir() if item.is_dir()]
    if target:
        from .memory import _safe_name  # 内部工具：与产物目录命名保持一致

        prefix = _safe_name(target)
        dirs = [item for item in dirs if item.name.startswith(prefix)]
    if not dirs:
        return None
    return max(dirs, key=lambda item: item.stat().st_mtime)


@main.command("memory")
@click.option("--target", required=True, help="目标 URL（与审计时填的完全一致，记忆按 host 分文件）")
@click.option("--list", "do_list", is_flag=True, help="列出全部历史漏洞条目（含上报时间与指纹）")
@click.option("--forget", "forget_ids", multiple=True, help="按编号删除条目（可重复，如 --forget HH-002）")
@click.option("--before", default=None, help="删除该时间点之前上报的条目（ISO 时间字符串，如 2026-09-18）")
@click.option("--reset", is_flag=True, help="清空该目标的全部历史漏洞条目（需同时给 --yes）")
@click.option("--yes", is_flag=True, help="确认执行 --reset")
def memory_cmd(
    target: str,
    do_list: bool,
    forget_ids: tuple[str, ...],
    before: str | None,
    reset: bool,
    yes: bool,
) -> None:
    """查看 / 清理某目标的跨运行记忆。

    记忆是只增不减的累积文件（`~/.hexhound/memory/<host>.json`），里面会混进旧格式条目、
    脚本模型试跑留下的条目。它们会在**每一次**跨运行 diff 里以"状态未知"重复出现，
    把真正的回归结论淹没——所以清理入口是 diff 能用下去的前提。
    """
    memory = HostMemory(target)
    info = memory.stats()
    click.echo(f"记忆文件：{info['path']}")
    click.echo(
        f"历史运行 {info['runs']} 次｜端点 {info['endpoints']} 个｜"
        f"漏洞条目 {info['findings']} 条｜技术栈 {info['tech']} 项"
        + (f"｜最后更新 {info['updated_at']}" if info["updated_at"] else "")
    )
    if do_list:
        findings = memory.known_findings(200)
        if not findings:
            click.echo(f"{MARK_SKIP} 没有历史漏洞条目。")
        for item in findings:
            click.echo(
                f"  {item.get('id', '')} [{item.get('severity', '')}] "
                f"{str(item.get('title') or '')[:60]} -> {item.get('url') or '（缺 URL）'}"
                f"｜上报 {str(item.get('at') or '?')[:19]}"
            )
    if not (forget_ids or before or reset):
        return
    if reset and not yes:
        raise click.ClickException("--reset 会清空该目标的全部历史漏洞条目，请加 --yes 确认。")
    outcome = memory.forget(ids=forget_ids, before=before or "", reset=reset)
    click.echo(
        f"{MARK_OK} 已删除 {outcome['removed']} 条，剩余 {outcome['kept']} 条"
        + ("（已整体重置）" if reset else "")
    )


@main.command("providers")
@click.option("--test", "do_test", is_flag=True, help="对每个已配置 key 的提供商发一次最小请求验证连通性")
@click.option("--provider", "only", default=None, help="只显示/测试指定提供商")
@click.option("--model", "model", default=None, help="测试时使用的模型（默认用预设默认值）")
def providers_cmd(do_test: bool, only: str | None, model: str | None) -> None:
    """列出模型提供商预设，并检查当前 .env 里配了哪些 key。

    换模型最容易错的是「模型名」和「base_url」——这个命令让你在不跑审计的前提下
    先确认能不能通（`--test` 会发一次十几个 token 的最小请求）。
    """
    shared_key = os.getenv("LLM_API_KEY", "").strip()
    current = resolve_provider()
    rows: list[tuple[str, str, str, str, str]] = []
    for preset in describe_presets():
        if only and preset["key"] != resolve_provider(only) and only != preset["key"]:
            continue
        dedicated = os.getenv(preset["env_key"], "").strip()
        if dedicated:
            key_state = MARK_OK + " 专用 key"
        elif shared_key and preset["key_required"]:
            # 共享 key 只对"就是这家"的情况确定有效——别让人误以为换 openai 就能通
            key_state = (MARK_OK + " 共用(需--test确认)") if preset["key"] == current else "~  共用LLM_API_KEY"
        elif not preset["key_required"]:
            key_state = MARK_SKIP + " 无需 key"
        else:
            key_state = MARK_FAIL + " 未配置"
        mark = "<< 当前" if preset["key"] == current else ""
        rows.append(
            (
                f"{preset['key']} {mark}".strip(),
                preset["default_model"] or "（需自填）",
                key_state,
                preset["base_url"] or "（需自填）",
                preset["env_key"],
            )
        )
    click.echo(f"当前提供商：{current}\n")
    click.echo(f"{'提供商':<26}{'默认模型':<30}{'密钥':<26}{'环境变量'}")
    click.echo("-" * 118)
    for key, default_model, key_state, _url, env_key in rows:
        click.echo(f"{key:<26}{default_model:<30}{key_state:<26}{env_key}")
    click.echo(
        "\n换提供商：`--provider <名>`，或在 .env 里写 LLM_PROVIDER=<名>；"
        "自定义端点用 `--provider custom --base-url https://your-gateway/v1 --model <模型名>`。"
    )
    click.echo("按角色分配模型：LLM_PLANNER_MODEL / LLM_VERIFY_MODEL …（见 `hexhound setup`）")

    if not do_test:
        return
    click.echo("\n=== 连通性测试 ===")
    tested = 0
    for preset in describe_presets():
        if only and preset["key"] != resolve_provider(only) and only != preset["key"]:
            continue
        dedicated = os.getenv(preset["env_key"], "").strip()
        key = dedicated or (shared_key if preset["key_required"] else "")
        if preset["key_required"] and not key:
            click.echo(f"  - {preset['key']}: 跳过（未配置 key）")
            continue
        target_model = model or preset["default_model"]
        if not target_model:
            click.echo(f"  - {preset['key']}: 跳过（没有默认模型，请用 --model 指定）")
            continue
        client = LLMClient(
            key,
            preset["base_url"],
            target_model,
            provider=preset["key"],
            timeout=30,
        )
        check = client.test_connection()
        tested += 1
        flag = MARK_OK if check.ok else MARK_FAIL
        click.echo(f"  {flag} {preset['key']}/{target_model}: {check.message.splitlines()[0]}")
        if not check.ok and len(check.message.splitlines()) > 1:
            for line in check.message.splitlines()[1:]:
                click.echo(f"      {line}")
    if not tested:
        click.echo("  没有可测试的提供商（先在 .env 里填一个 key）。")


@main.group("sandbox")
def sandbox_cmd() -> None:
    """真工具执行环境（Docker / Podman / WSL）：查看状态、安装工具链、构建镜像。

    HexHound 只用 OpenAI 兼容 HTTP 接口做探测时，能力上限是"疑似信号"；
    接上真工具（sqlmap / nmap / nuclei / ffuf …）之后才能拿到**证明级**证据——
    例如 sqlmap 给出的可复现 payload、注入类型、后端 DBMS 版本，甚至导出真实数据。
    """


@sandbox_cmd.command("status")
def sandbox_status() -> None:
    """探测当前机器上有哪些可用执行环境，以及装了哪些工具。"""
    from .sandbox import TOOL_ALLOWLIST, detect_runtime

    runtime = detect_runtime()
    if runtime is None:
        click.echo(f"{MARK_FAIL} 没有可用的执行环境（Docker / Podman / WSL 都没探测到）")
        click.echo("\n可选做法：")
        click.echo("  1) 启动 Docker Desktop（需要管理员权限）")
        click.echo("  2) 装一个 WSL 发行版（不需要管理员）：")
        click.echo("       wsl --install -d Ubuntu-24.04")
        click.echo("       hexhound sandbox install")
        return
    click.echo(f"{MARK_OK} 执行环境：{runtime.describe()}")
    sandbox = Sandbox(allowed_hosts=frozenset({"127.0.0.1"}), map_loopback=False)
    probe = sandbox.probe()
    if not probe.get("ok"):
        click.echo(f"{MARK_WARN} 不可用：{probe.get('reason', '未知')}")
        if probe.get("hint"):
            click.echo(f"  建议：{probe['hint']}")
        return
    tools = probe.get("tools") or {}
    click.echo("\n工具链：")
    for name in TOOL_ALLOWLIST:
        mark = MARK_OK if tools.get(name) else MARK_FAIL
        click.echo(f"  {mark} {name:10} {TOOL_ALLOWLIST[name]}")
    missing = [name for name in TOOL_ALLOWLIST if not tools.get(name)]
    if missing:
        click.echo(f"\n补装：hexhound sandbox install（缺 {len(missing)} 个）")


@sandbox_cmd.command("install")
@click.option("--distro", default="", help="WSL 发行版名（默认取第一个非 docker 的发行版）")
def sandbox_install(distro: str) -> None:
    """在 WSL 发行版/容器里安装工具链（nmap/sqlmap/ffuf/gobuster/nuclei/whatweb/nikto）。"""
    sandbox = Sandbox(map_loopback=False, wsl_distro=distro)
    runtime = sandbox.runtime
    if runtime is None:
        raise click.ClickException(
            "没有可用的执行环境。先装一个 WSL 发行版：wsl --install -d Ubuntu-24.04"
        )
    if runtime.kind != "wsl":
        click.echo(
            f"当前环境是 {runtime.describe()}。容器后端请直接构建自带工具的镜像：\n"
            "  hexhound sandbox build\n"
            "（镜像定义见 docker/Dockerfile，已包含全部工具）"
        )
        return
    click.echo(f"在 {runtime.describe()} 里安装工具链（可能需要几分钟）...")
    result = sandbox.install_tools()
    click.echo(result.output[-4000:] if result.output else "(无输出)")
    if not result.ok:
        raise click.ClickException(f"安装失败：{result.error}")
    probe = Sandbox(map_loopback=False, wsl_distro=distro).probe()
    present = sorted(name for name, ok in (probe.get("tools") or {}).items() if ok)
    click.echo(f"\n{MARK_OK} 安装完成，可用工具：{', '.join(present)}")


@sandbox_cmd.command("build")
@click.option("--tag", default="hexhound-sandbox:latest", show_default=True, help="镜像标签")
def sandbox_build(tag: str) -> None:
    """构建自带全部工具的沙箱镜像（需要 docker/podman）。"""
    sandbox = Sandbox(map_loopback=False)
    result = sandbox.build_image(tag=tag)
    click.echo(result.output[-4000:] if result.output else "(无输出)")
    if not result.ok:
        raise click.ClickException(f"构建失败：{result.error}")


@sandbox_cmd.command("templates")
@click.option("--source", "source_dir", default="", help="本地已解压的模板目录（默认在宿主侧下载官方包）")
@click.option("--distro", default="", help="WSL 发行版名")
def sandbox_templates(source_dir: str, distro: str) -> None:
    """安装 nuclei 模板库。

    为什么单独做成一条命令：Windows 上装了 Steam++/Watt Toolkit 这类加速器时，
    GitHub 只在**宿主（Windows）侧**可达——WSL 不读 Windows hosts，直连会被重置。
    所以这里的策略是"宿主下载 → 送进 WSL 解压安装"。
    """
    sandbox = Sandbox(map_loopback=False, wsl_distro=distro)
    runtime = sandbox.runtime
    if runtime is None:
        raise click.ClickException("没有可用的执行环境（需要 WSL 或容器）。")
    if runtime.kind != "wsl":
        click.echo(
            f"当前后端是 {runtime.describe()}：容器镜像请直接构建自带模板的镜像"
            "（见 docker/Dockerfile），或进容器手动装。"
        )
        return
    click.echo("正在准备 nuclei 模板库（宿主下载 → 传入 WSL）...")
    result = sandbox.install_nuclei_templates(source_dir or None)
    click.echo((result.output or result.error or "(无输出)")[-2000:])
    if not result.ok:
        raise click.ClickException(f"模板安装失败：{result.error}")
    templates = sandbox._nuclei_templates()
    click.echo(f"\n{MARK_OK} 模板库就绪：{templates or '（未探测到）'}")


@sandbox_cmd.command("lab")
@click.option("--port", type=int, default=5000, show_default=True, help="靶场端口")
@click.option("--distro", default="", help="WSL 发行版名")
def sandbox_lab(port: int, distro: str) -> None:
    """把靶场跑进 WSL 里（解决 WSL2 网络命名空间导致工具打不到宿主靶场的问题）。"""
    sandbox = Sandbox(map_loopback=False, wsl_distro=distro)
    runtime = sandbox.runtime
    if runtime is None or runtime.kind != "wsl":
        raise click.ClickException("这个命令需要 WSL 后端（Docker 后端请用 python vulnlab/app.py）。")
    script = PROJECT_ROOT / "tools" / "start_lab_in_wsl.sh"
    if not script.is_file():
        raise click.ClickException(f"找不到脚本：{script}")
    result = sandbox.run(f"bash {script} {port}", timeout=900, check_scope=False)
    click.echo(result.output or "(无输出)")


@main.command("gui")
@click.option("--host", default="127.0.0.1", show_default=True, help="监听地址")
@click.option("--port", type=int, default=5001, show_default=True, help="监听端口")
def gui(host: str, port: int) -> None:
    """启动图形化界面（需要 flask，pip install -e ".[lab]"）。"""
    try:
        from .gui import run_server
    except ImportError as exc:
        raise click.ClickException(
            '图形界面需要 flask，请先执行 pip install -e ".[lab]"'
        ) from exc
    run_server(host, port)


@main.command("setup")
def setup() -> None:
    """交互式初始化向导：逐个询问该填什么，并写入 .env。"""
    click.echo("HexHound 初始化向导")
    click.echo("依次询问配置项并写入当前目录的 .env；括号里是默认值，直接回车用默认。\n")
    existing = _load_env_file()

    click.echo("可选的模型提供商：")
    rows = describe_presets()
    click.echo("  " + "、".join(f"{row['key']}" for row in rows))
    provider = click.prompt(
        "LLM_PROVIDER  用哪个提供商（deepseek/openai/qwen/ollama/custom …）",
        default=existing.get("LLM_PROVIDER", "deepseek"),
        show_default=True,
    ).strip()
    resolved_provider = resolve_provider(provider)
    preset = get_preset(resolved_provider)
    if preset is None or resolved_provider == "custom":
        click.echo("  → 自定义提供商：需要自己填 base_url 与模型名。")
    elif preset.note:
        click.echo(f"  → {preset.note}")

    base_url = click.prompt(
        "LLM_BASE_URL  API 地址",
        default=existing.get("LLM_BASE_URL", (preset.base_url if preset else "") or ""),
    )
    model = click.prompt(
        "LLM_MODEL     模型名" + (f"（该提供商常用：{', '.join(preset.model_list()[:3])}）" if preset and preset.model_list() else ""),
        default=existing.get("LLM_MODEL", (preset.default_model if preset else "") or ""),
    )
    key_hint = f"（{preset.api_key_url}）" if preset and preset.api_key_url else ""
    api_key = click.prompt(
        f"LLM_API_KEY   你的 API 密钥{key_hint}"
        + ("（本地/自定义端点可留空）" if resolved_provider in ("ollama", "vllm", "custom") else ""),
        default=existing.get("LLM_API_KEY", ""),
        show_default=False,
    )

    click.echo(
        "\n按角色分配模型（可选，回车跳过 = 跟随上面的默认模型）。"
        "\n建议：编排/复核用强模型，批量侦察用便宜模型。"
    )
    role_models: dict[str, str] = {}
    for role, suffix in ROLE_ENV_SUFFIX.items():
        current = existing.get(f"LLM_{suffix}_MODEL", "")
        value = click.prompt(
            f"  LLM_{suffix}_MODEL  {ROLE_LABEL.get(role, role)}",
            default=current,
            show_default=bool(current),
        ).strip()
        if value:
            role_models[f"LLM_{suffix}_MODEL"] = value

    max_steps = click.prompt(
        "MAX_STEPS     单代理模式最大步数",
        default=existing.get("MAX_STEPS", _ENV_DEFAULTS["MAX_STEPS"]),
    )
    max_tasks = click.prompt(
        "MAX_TASKS     一次运行最多子任务数（多代理编排）",
        default=existing.get("MAX_TASKS", str(MAX_TASKS)),
    )
    task_steps = click.prompt(
        "TASK_STEPS    每个子任务步数",
        default=existing.get("TASK_STEPS", str(DEFAULT_TASK_STEPS)),
    )
    parallel = click.prompt(
        "PARALLEL      并发子代理数（1 = 串行更省额度）",
        default=existing.get("PARALLEL", str(MAX_PARALLEL)),
    )
    timeout = click.prompt(
        "REQUEST_TIMEOUT 请求超时(秒)",
        default=existing.get("REQUEST_TIMEOUT", _ENV_DEFAULTS["REQUEST_TIMEOUT"]),
    )
    rate_limit = click.prompt(
        "RATE_LIMIT    每次请求最小间隔秒数（0=不限速）",
        default=existing.get("RATE_LIMIT", "0"),
    )
    max_cost = click.prompt(
        "MAX_COST      费用上限（人民币，0=不限）",
        default=existing.get("MAX_COST", _ENV_DEFAULTS["MAX_COST"]),
    )
    max_tool_calls = click.prompt(
        "MAX_TOOL_CALLS 工具调用总上限（0=不限）",
        default=existing.get("MAX_TOOL_CALLS", _ENV_DEFAULTS["MAX_TOOL_CALLS"]),
    )
    hosts = click.prompt(
        "ALLOWED_HOSTS 允许访问的主机名（逗号分隔，只填域名/IP，不带 http:// 和路径；"
        "测授权目标就把它加进来）",
        default=existing.get("ALLOWED_HOSTS", _ENV_DEFAULTS["ALLOWED_HOSTS"]),
    )

    values = {
        "LLM_PROVIDER": resolved_provider,
        "LLM_API_KEY": api_key.strip(),
        "LLM_BASE_URL": base_url.strip(),
        "LLM_MODEL": model.strip(),
        **role_models,
        "MAX_STEPS": max_steps.strip(),
        "MAX_TASKS": max_tasks.strip(),
        "TASK_STEPS": task_steps.strip(),
        "PARALLEL": parallel.strip(),
        "REQUEST_TIMEOUT": timeout.strip(),
        "RATE_LIMIT": rate_limit.strip(),
        "MAX_COST": max_cost.strip(),
        "MAX_TOOL_CALLS": max_tool_calls.strip(),
        "ALLOWED_HOSTS": hosts.strip(),
    }
    env_path, _changed = write_env_file(values, Path.cwd() / ".env")
    lines = [f"{key}={value}" for key, value in values.items()]

    click.echo(f"\n已写入 {env_path}：")
    for line in lines:
        if line.startswith("LLM_API_KEY="):
            value = line.split("=", 1)[1]
            click.echo(f"  LLM_API_KEY={value[:4]}...{value[-4:]}" if value else "  LLM_API_KEY=（空）")
        else:
            click.echo(f"  {line}")
    if not api_key.strip():
        click.echo("\n" + MARK_WARN + " 未填写 LLM_API_KEY，审计时会报错。可稍后再次运行 hexhound setup 补填。")

    if click.confirm("\n是否现在就开始一次审计？", default=False):
        mode = click.prompt(
            "模式（source=源码审计 / blackbox=纯 URL 黑盒）",
            default="blackbox",
            type=click.Choice(["source", "blackbox"]),
        )
        target = click.prompt("目标 URL", default="http://127.0.0.1:5000")
        path = None
        if mode == "source":
            path = click.prompt("源码目录 PATH", default="vulnlab")
        output = click.prompt("报告输出路径", default="reports/report.md")
        try:
            _run_audit(path, target, mode, None, output, True)
        except click.ClickException as exc:
            click.echo(f"运行失败：{exc}", err=True)
    else:
        click.echo(
            "\n下次直接运行：hexhound audit <PATH> --target <URL> [--mode blackbox] [--verbose]"
        )


if __name__ == "__main__":
    main()
