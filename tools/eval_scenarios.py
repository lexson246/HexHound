"""带标准答案的多场景评测：检出率 / 误报率 / 耗时 / 成本。

为什么要有它（交接文档 §7 第 0 条）：在此之前只有"能跑通"的验收
（`tools/verify_*.py` 证明链路活着），没有"跑得准不准"的量化——
改了 payload 库或判定规则之后，没人能回答"这次是变好还是变坏"。

两个层级，刻意分开（否则指标会互相污染）：

* `--tier engine`（引擎层，**零额度**）：对每个场景直接调用对应的检测工具
  （`fuzz_params` / `http_request`），按攻面里记录的判定结果打分。
  衡量的是 **payload 库 + 信号判定规则**，与模型无关，可重复、可回归。
* `--tier agent`（Agent 层）：跑完整编排（`--llm scripted` 用确定性脚本模型，
  零额度；`--llm live` 用真实模型，**必须显式加 `--allow-live`**，会花额度），
  按最终 findings/candidates 打分。衡量的是"整条链子"。

指标定义（都写进产物里的 JSON，便于跨轮对比）：

* 检出率 = 命中场景 / 应命中场景（**分不开时不算命中**：`blocked`/`error` 计为
  "无结论"，单独列出，绝不折算成"未检出"）；
* 误报率 = 报了信号的"应当安静"场景 / 应当安静场景总数；
  `reflection_only` 类**不计入**误报——它在字符串层面确实是反射，
  只有浏览器层能分辨（Agent 把它记成 XSS 才算误报，见产物里的 note）；
* 耗时 = 墙钟秒数；成本 = 预算账本的 token 与估算费用（引擎层为 0）。

用法：
    python tools/eval_scenarios.py --tier engine               # 零额度，推荐先跑这个
    python tools/eval_scenarios.py --tier agent --llm scripted  # 零额度，跑完整链路
    python tools/eval_scenarios.py --tier agent --llm live --allow-live   # 花额度！
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from hexhound.surface import AttackSurface  # noqa: E402
from hexhound.tools import ToolRegistry  # noqa: E402

DEFAULT_SCENARIOS = ROOT / "evals" / "scenarios.json"
DEFAULT_OUT = ROOT / ".tmp" / "evals"

#: `vuln_type`/标题里出现这些词就认为匹配该标准答案（大小写不敏感）。
TYPE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "SQL注入": ("sql", "注入"),
    "反射型XSS": ("xss", "跨站"),
    "SSTI": ("ssti", "模板"),
    "命令注入": ("命令", "cmd", "rce"),
    "任意文件读取": ("文件读取", "遍历", "路径穿越", "lfi"),
    "SSRF": ("ssrf", "服务端请求"),
    "越权访问": ("越权", "idor", "水平"),
    "未授权访问": ("未授权", "unauth"),
}


@dataclass
class ScenarioResult:
    """一个场景的评分行（可 JSON 化，产物与报告都用它）。"""

    id: str
    name: str
    expected: str
    verdict: str
    detail: str = ""
    seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "expected": self.expected,
            "verdict": self.verdict, "detail": self.detail, "seconds": round(self.seconds, 2),
        }


def load_scenarios(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("scenarios"), list):
        raise ValueError(f"{path} 格式不对：需要 {{version, target, scenarios: [...]}}")
    return data


def endpoint_path(endpoint: str) -> str:
    """只留**路径**（去 scheme/host/query/尾斜杠），用于把 finding 的完整 URL
    与场景里的相对路径对齐——`http://127.0.0.1:5000/login?u=1` 必须等于 `/login`。
    """
    raw = str(endpoint or "").strip()
    parsed = urlparse(raw if "//" in raw else "http://placeholder" + raw)
    path = parsed.path or "/"
    return path.rstrip("/") or "/"


# ---------------------------------------------------------------------------
# 评分（纯函数，单独测）
# ---------------------------------------------------------------------------


def classify_engine_outcome(outcomes: list[str], expected: str) -> tuple[str, str]:
    """把"这次尝试记录到的判定结果"翻译成评测结论。

    返回 `(verdict, detail)`；verdict 取值：

    * `detected` —— 应命中且命中了；
    * `missed` —— 应命中但判定为无信号（真·漏报）；
    * `false_positive` —— 应当安静却报了信号；
    * `true_negative` —— 应当安静也确实安静；
    * `reflection_only_flagged` —— 期望"仅反射"且确实报了（**不算误报**，
      只有浏览器层能分辨是不是可执行）；
    * `inconclusive` —— 全是 blocked/error：没测成，**不算漏报也不算通过**。
    """
    signals = outcomes.count("signal")
    conclusive = [item for item in outcomes if item in ("signal", "no_signal")]
    if not conclusive:
        return "inconclusive", f"没有有效判定（记录：{outcomes or '无'}）"
    if expected == "signal":
        return ("detected", "命中") if signals else ("missed", "判定为无信号")
    if expected == "none":
        return ("false_positive", f"报了 {signals} 个信号") if signals else ("true_negative", "安静")
    if expected == "reflection_only":
        return (
            ("reflection_only_flagged", "报为反射（符合预期，需要浏览器层再判）")
            if signals
            else ("missed", "连反射都没报出来——payload 或判定规则可能有问题")
        )
    return "inconclusive", f"未知 expected={expected!r}"


def requested_types(scenario: dict[str, Any]) -> tuple[str, ...]:
    truth = str(scenario.get("ground_truth") or "")
    return TYPE_KEYWORDS.get(truth, (truth.lower(),) if truth else ("",))


def finding_matches(scenario: dict[str, Any], finding: Any) -> bool:
    """finding（或候选）是否命中该场景：**路径一致 + 类型关键词一致**。"""
    url = str(getattr(finding, "url", "") or (finding.get("url") if isinstance(finding, dict) else ""))
    if endpoint_path(url) != endpoint_path(str(scenario.get("endpoint") or "")):
        return False
    keywords = tuple(word for word in requested_types(scenario) if word)
    if not keywords:
        return True
    text = " ".join(
        str(getattr(finding, key, "") or (finding.get(key, "") if isinstance(finding, dict) else ""))
        for key in ("title", "vuln_type", "description")
    ).lower()
    return any(word.lower() in text for word in keywords)


def summarize(results: list[ScenarioResult]) -> dict[str, Any]:
    """汇总成四列指标。**分母都不含 inconclusive**（没测成不能算漏报）。"""
    buckets: dict[str, list[ScenarioResult]] = {}
    for item in results:
        buckets.setdefault(item.verdict, []).append(item)

    def ids(verdict: str) -> list[str]:
        return [item.id for item in buckets.get(verdict, [])]

    detected = len(buckets.get("detected", []))
    missed = len(buckets.get("missed", []))
    positive_total = detected + missed
    quiet_expected = len(buckets.get("true_negative", [])) + len(buckets.get("false_positive", []))
    false_positives = len(buckets.get("false_positive", []))
    return {
        "scenarios": len(results),
        "detected": detected,
        "missed": missed,
        "detection_rate": round(detected / positive_total, 4) if positive_total else None,
        "false_positives": false_positives,
        "quiet_expected": quiet_expected,
        "false_positive_rate": round(false_positives / quiet_expected, 4) if quiet_expected else None,
        "reflection_only_flagged": len(buckets.get("reflection_only_flagged", [])),
        "inconclusive": len(buckets.get("inconclusive", [])),
        "missed_ids": ids("missed"),
        "false_positive_ids": ids("false_positive"),
        "inconclusive_ids": ids("inconclusive"),
    }


# ---------------------------------------------------------------------------
# Tier A：引擎层（零额度）
# ---------------------------------------------------------------------------


def run_engine_scenario(scenario: dict[str, Any], target: str, *, per_category: int = 4) -> ScenarioResult:
    """直接调对应工具，按攻面里记录的判定结果打分。"""
    url = target.rstrip("/") + str(scenario.get("endpoint") or "/")
    method = str(scenario.get("method") or "GET").upper()
    location = str(scenario.get("location") or "query")
    category = str(scenario.get("category") or "")
    param = str(scenario.get("param") or "")
    sample = scenario.get("sample") if isinstance(scenario.get("sample"), dict) else {}

    surface = AttackSurface(target=target, mode="blackbox")
    registry = ToolRegistry(
        base_dir=ROOT, allowed_hosts=frozenset({"127.0.0.1", "localhost"}),
        timeout=15, mode="blackbox", surface=surface, role="injection", worker_id="EVAL",
    )
    started = time.time()
    if category == "auth":
        # 未授权/越权：判据是"匿名能读到数据"，用 http_request 直接看响应，
        # 再用 body 分析给出的情报决定是否算命中。
        registry.execute("http_request", {
            "url": url, "method": method, "params": sample or None,
            "note": f"评测：匿名访问 {scenario['id']}",
        })
        pii = [note for note in surface.notes if "响应含疑似" in note]
        outcomes = ["signal"] if pii else _exchange_outcomes(surface)
    else:
        registry.execute("fuzz_params", {
            "url": url, "method": method, "location": location,
            "params": {param: str(sample.get(param, "1"))} if param else (sample or {"x": "1"}),
            "categories": [category] if category else None,
            "per_category": per_category,
        })
        outcomes = _fuzz_outcomes(surface, url, param)
    verdict, detail = classify_engine_outcome(outcomes, str(scenario.get("expected") or "signal"))
    return ScenarioResult(
        id=str(scenario["id"]), name=str(scenario.get("name") or scenario["id"]),
        expected=str(scenario.get("expected") or "signal"), verdict=verdict, detail=detail,
        seconds=time.time() - started,
    )


def _fuzz_outcomes(surface: AttackSurface, url: str, param: str) -> list[str]:
    """该场景相关的尝试判定（按端点过滤；给了参数名就再按参数过滤）。"""
    path = endpoint_path(url)
    with surface._lock:  # noqa: SLF001 评测需要读原始记录
        attempts = list(surface.attempts.values())
    return [
        item.outcome for item in attempts
        if endpoint_path(item.endpoint) == path and (not param or item.param == param)
    ]


def _exchange_outcomes(surface: AttackSurface) -> list[str]:
    """http_request 路径没有 fuzz 的"信号"概念：看有没有拿到 2xx/3xx 响应。"""
    with surface._lock:  # noqa: SLF001
        attempts = list(surface.attempts.values())
    if any(item.outcome == "signal" for item in attempts):
        return ["signal"]
    if attempts:
        return ["no_signal"]
    return []


# ---------------------------------------------------------------------------
# Tier B：Agent 层
# ---------------------------------------------------------------------------


def run_agent_tier(data: dict[str, Any], *, llm_kind: str, allow_live: bool,
                   artifacts_home: Path, max_tasks: int, task_steps: int) -> tuple[list[ScenarioResult], dict[str, Any]]:
    """跑一次完整编排，然后按 findings/candidates 打分。"""
    from hexhound.budget import Budget, BudgetLimits
    from hexhound.config import Config
    from hexhound.llm import build_llm_pool
    from hexhound.memory import HostMemory, RunArtifacts
    from hexhound.orchestrator import Orchestrator, SwarmCallbacks

    target = str(data.get("target") or "")
    allowed = frozenset({"127.0.0.1", "localhost"})
    config = Config(
        api_key="sk-fake-eval" if llm_kind != "live" else _live_key(),
        base_url="" if llm_kind != "live" else "",
        model="scripted-policy", provider="scripted" if llm_kind != "live" else _live_provider(),
        allowed_hosts=allowed,
    )
    if llm_kind == "live":
        if not allow_live:
            raise SystemExit(
                "拒绝执行：--llm live 会调用真实模型并消耗额度。"
                "确认要跑就加 --allow-live（建议先用 --llm scripted 验证链路）。"
            )
        from dotenv import load_dotenv

        load_dotenv(ROOT / ".env", override=False)
        config = Config.from_env()
        config = Config(**{**config.__dict__, "allowed_hosts": allowed})
    llm, pool = build_llm_pool(config, echo=print)

    artifacts = RunArtifacts(target, home=artifacts_home)
    surface = AttackSurface(target=target, mode="blackbox", path=artifacts.surface_path,
                            allowed_hosts=allowed)
    budget = Budget(BudgetLimits(max_tool_calls=200, max_seconds=900))
    orchestrator = Orchestrator(
        llm, target=target, goal=f"对 {target} 做黑盒安全评估（评测场景集）", mode="blackbox",
        base_dir=ROOT, allowed_hosts=allowed, timeout=10, max_tasks=max_tasks,
        task_steps=task_steps, parallel=2, budget=budget, artifacts=artifacts, surface=surface,
        callbacks=SwarmCallbacks(), memory=HostMemory(target), llm_pool=pool,
    )
    started = time.time()
    result = orchestrator.run()
    seconds = time.time() - started

    reported = list(result.findings or [])
    scenarios = data["scenarios"]
    matched: set[str] = set()
    for scenario in scenarios:
        if str(scenario.get("expected")) != "signal":
            continue
        hit = any(finding_matches(scenario, item) for item in reported)
        matched.add(str(scenario["id"])) if hit else None

    results: list[ScenarioResult] = []
    for scenario in scenarios:
        expected = str(scenario.get("expected") or "signal")
        if expected == "signal":
            hit = str(scenario["id"]) in matched
            results.append(ScenarioResult(
                id=str(scenario["id"]), name=str(scenario.get("name") or ""), expected=expected,
                verdict="detected" if hit else "missed",
                detail="findings/candidates 命中" if hit else "报告里没有对应条目",
            ))
        else:
            # 应当安静的场景：报告里出现对应条目才算误报
            flagged = [item for item in reported if finding_matches(scenario, item)]
            verdict = "false_positive" if flagged and expected == "none" else (
                "reflection_only_flagged" if flagged else "true_negative"
            )
            results.append(ScenarioResult(
                id=str(scenario["id"]), name=str(scenario.get("name") or ""), expected=expected,
                verdict=verdict,
                detail=f"报告了 {len(flagged)} 条" if flagged else "报告里没有对应条目",
            ))

    usage = budget.snapshot()
    meta = {
        "tier": "agent", "llm": llm_kind, "target": target, "seconds": round(seconds, 1),
        "tokens": int(usage.get("total_tokens") or 0),
        "estimated_cost": round(float(usage.get("estimated_cost") or 0.0), 4),
        "findings": len([item for item in reported if getattr(item, "status", "") != "candidate"]),
        "candidates": len(surface.pending_candidates()),
        "finish_reason": result.finish_reason,
        "model": config.provider + "/" + config.model,
    }
    return results, meta


def _live_key() -> str:
    import os

    return os.getenv("LLM_API_KEY", "")


def _live_provider() -> str:
    import os

    return os.getenv("LLM_PROVIDER", "deepseek")


# ---------------------------------------------------------------------------
# 产物
# ---------------------------------------------------------------------------


def render_report(data: dict[str, Any], results: list[ScenarioResult], metrics: dict[str, Any],
                  meta: dict[str, Any]) -> str:
    lines = [
        "# 评测报告（带标准答案）",
        "",
        f"- 目标：`{data.get('target')}`｜场景：{metrics['scenarios']} 个",
        f"- 层级：`{meta.get('tier')}`｜模型：`{meta.get('model', '—')}`",
        f"- 耗时：{meta.get('seconds', 0)}s｜token：{meta.get('tokens', 0)}"
        f"｜估算费用：¥{meta.get('estimated_cost', 0)}",
        f"- **检出率：{_pct(metrics['detection_rate'])}**"
        f"（{metrics['detected']}/{metrics['detected'] + metrics['missed']}）"
        f"｜**误报率：{_pct(metrics['false_positive_rate'])}**"
        f"（{metrics['false_positives']}/{metrics['quiet_expected']}）"
        f"｜仅反射命中：{metrics['reflection_only_flagged']}"
        f"｜无结论：{metrics['inconclusive']}",
        "",
        "## 逐场景",
        "",
        "| 场景 | 期望 | 结论 | 说明 | 耗时 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in results:
        lines.append(
            f"| {item.id} | {item.expected} | {item.verdict} | {item.detail} | {item.seconds:.1f}s |"
        )
    if metrics["missed_ids"]:
        lines += ["", "## 漏报（应检出但没检出）", ""]
        lines += [f"- {item}" for item in metrics["missed_ids"]]
    if metrics["false_positive_ids"]:
        lines += ["", "## 误报（应当安静却报了）", ""]
        lines += [f"- {item}" for item in metrics["false_positive_ids"]]
    if metrics["inconclusive_ids"]:
        lines += ["", "## 无结论（被阻断/请求失败，**不算漏报**）", ""]
        lines += [f"- {item}" for item in metrics["inconclusive_ids"]]
    lines += [
        "",
        "> 口径说明：`reflection_only` 与 `none` 是两类不同的「应当安静」——"
        "前者字符串层面确实是反射（只有浏览器能判是否可执行），不计入误报；"
        "后者才是真正的误报判据。无结论（blocked/error）单独列出，绝不折算成漏报。",
    ]
    return "\n".join(lines) + "\n"


def _pct(value: Any) -> str:
    return "—" if value is None else f"{float(value) * 100:.1f}%"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="带标准答案的多场景评测")
    parser.add_argument("--scenarios", default=str(DEFAULT_SCENARIOS))
    parser.add_argument("--tier", choices=("engine", "agent"), default="engine")
    parser.add_argument("--llm", choices=("scripted", "live"), default="scripted")
    parser.add_argument("--allow-live", action="store_true", help="跑真实模型（会花额度）")
    parser.add_argument("--target", default="", help="覆盖场景文件里的目标")
    parser.add_argument("--out", default="", help="产物目录（默认 .tmp/evals/<时间戳>）")
    parser.add_argument("--max-tasks", type=int, default=6)
    parser.add_argument("--task-steps", type=int, default=10)
    parser.add_argument("--per-category", type=int, default=4, help="引擎层每个类别试几个 payload")
    args = parser.parse_args(argv)

    data = load_scenarios(Path(args.scenarios))
    if args.target:
        data["target"] = args.target
    target = str(data.get("target") or "")
    out_dir = Path(args.out) if args.out else DEFAULT_OUT / time.strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)

    meta: dict[str, Any]
    if args.tier == "engine":
        print(f"引擎层评测（零额度）：{len(data['scenarios'])} 个场景 @ {target}")
        results = []
        for scenario in data["scenarios"]:
            item = run_engine_scenario(scenario, target, per_category=args.per_category)
            results.append(item)
            print(f"  [{item.verdict:>22}] {item.id} — {item.detail}")
        meta = {"tier": "engine", "llm": "n/a", "target": target,
                "seconds": round(sum(item.seconds for item in results), 1),
                "tokens": 0, "estimated_cost": 0.0, "model": "n/a"}
    else:
        artifacts_home = out_dir / "home"
        results, meta = run_agent_tier(
            data, llm_kind=args.llm, allow_live=args.allow_live,
            artifacts_home=artifacts_home, max_tasks=args.max_tasks, task_steps=args.task_steps,
        )
        meta["tier"] = f"agent/{args.llm}"

    metrics = summarize(results)
    payload = {
        "target": target, "meta": meta, "metrics": metrics,
        "results": [item.to_dict() for item in results],
    }
    (out_dir / "results.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    report = render_report(data, results, metrics, meta)
    (out_dir / "report.md").write_text(report, encoding="utf-8")

    print()
    print(
        f"检出率 {_pct(metrics['detection_rate'])}"
        f"｜误报率 {_pct(metrics['false_positive_rate'])}"
        f"｜仅反射 {metrics['reflection_only_flagged']}"
        f"｜无结论 {metrics['inconclusive']}"
        f"｜耗时 {meta['seconds']}s｜token {meta['tokens']}"
    )
    print(f"产物：{out_dir / 'report.md'}")
    # 无结论不算失败：网络/限流导致的"没测成"由调用方判断要不要重跑
    return 1 if (metrics["missed"] or metrics["false_positives"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
