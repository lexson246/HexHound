"""查看 GitHub Actions 的运行结果（公共仓库只读，**不需要 token**）。

用法：
    python tools/ci_status.py                      # 最近一次运行
    python tools/ci_status.py --sha 439e02f        # 指定 commit
    python tools/ci_status.py --runs 5             # 最近 5 次

为什么需要它：Actions 的**原始日志需要认证**，公共仓库上只能读到 check run 的
`output.summary`。于是"CI 红了，但不知道为什么"曾经真实发生过（第四轮）。
配合 `tools/ci_rerun_report.py`（失败时把 pytest 尾部写进 `$GITHUB_STEP_SUMMARY`），
这个脚本负责"读"，那个负责"写"——两者合起来，失败的 CI 才有可读的解释。

只访问 GitHub 的公开 REST API，不读任何凭据，也不碰目标流量。
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

DEFAULT_REPO = os.getenv("HEXHOUND_CI_REPO", "lexson246/HexHound")


def _api(url: str) -> dict:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "hexhound-ci-status"},
    )
    with urllib.request.urlopen(request, timeout=25) as response:
        return json.load(response)


def describe_run(repo: str, run: dict, *, summaries: bool = False) -> int:
    """打印一次运行的作业状态；返回非绿作业数。

    `summaries=True` 时额外把非绿作业的 check-run `output.summary` 打出来——
    那正是 `tools/ci_rerun_report.py` 写进去的失败原因（Actions 原始日志要认证，
    公共仓库只能读到这一段）。
    """
    jobs = _api(f"https://api.github.com/repos/{repo}/actions/runs/{run['id']}/jobs").get("jobs", [])
    failed = [
        job for job in jobs
        if job.get("conclusion") not in (None, "success", "skipped")
    ]
    print(f"{run['head_sha'][:7]}  {run['status']}/{run.get('conclusion')}  {run['created_at']}")
    print(f"  {run['html_url']}")
    for job in jobs:
        detail = ""
        steps = [s for s in job.get("steps", []) if s.get("conclusion") not in (None, "success", "skipped")]
        if steps:
            detail = "｜失败步骤：" + ", ".join(f"{s['name']}（{s['conclusion']}）" for s in steps[:3])
        print(f"  {job['name'][:44]:46} {job['status']:11} {job.get('conclusion')}{detail}")
    if failed and summaries:
        print()
        for job in failed:
            check_url = str(job.get("check_run_url") or "")
            text = ""
            if check_url:
                try:
                    text = str((_api(check_url).get("output") or {}).get("summary") or "")
                except Exception:  # noqa: BLE001 摘要读不到就只报状态
                    text = ""
            print(f"===== {job['name']} 的公开摘要 =====")
            print(text.strip() or "（这个作业没有写摘要——对应步骤可能还没接上包装脚本）")
    if failed:
        print(
            "\n提示：失败原因看上面的公开摘要（由 tools/ci_rerun_report.py 写入 "
            "$GITHUB_STEP_SUMMARY）；原始日志需要 GitHub 认证。"
        )
    return len(failed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="查看 GitHub Actions 运行结果（只读，无需 token）")
    parser.add_argument("--repo", default=DEFAULT_REPO, help=f"owner/repo（默认 {DEFAULT_REPO}）")
    parser.add_argument("--sha", default="", help="只看这个 commit（前缀匹配）")
    parser.add_argument("--runs", type=int, default=1, help="列出最近几次运行（默认 1，最多 10）")
    parser.add_argument(
        "--summaries", action="store_true",
        help="非绿作业额外打印 check-run 公开摘要（失败原因，无需 token）",
    )
    args = parser.parse_args(argv)

    try:
        runs = _api(
            f"https://api.github.com/repos/{args.repo}/actions/runs?per_page={max(1, min(args.runs, 10))}"
        ).get("workflow_runs", [])
    except urllib.error.HTTPError as exc:
        print(f"读取 CI 状态失败：HTTP {exc.code} {exc.reason}（仓库名对吗？私有仓库需要 token）")
        return 2
    except Exception as exc:  # noqa: BLE001 网络问题不该伪装成"CI 通过"
        print(f"读取 CI 状态失败：{type(exc).__name__}: {exc}")
        return 2
    if not runs:
        print("这个仓库还没有任何 CI 运行记录。")
        return 1
    if args.sha:
        matched = [run for run in runs if run["head_sha"].startswith(args.sha)]
        if not matched:
            print(f"最近 {len(runs)} 次运行里没有 {args.sha}；可以加大 --runs。")
            return 1
        runs = matched

    failed_total = 0
    for index, run in enumerate(runs):
        if index:
            print()
        failed_total += describe_run(args.repo, run, summaries=args.summaries)
    return 1 if failed_total else 0


if __name__ == "__main__":
    raise SystemExit(main())
