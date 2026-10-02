#!/usr/bin/env python3
"""在本机按 `.github/workflows/ci.yml` 真正执行 CI 作业（不依赖 GitHub、不依赖 Docker）。

为什么需要它：仓库里配了 CI，但"它到底会不会绿"只能等 GitHub 跑一次才知道。
`tools/check_ci_workflow.py` 只能查引用写错；这个脚本把**作业里的每一步真的跑一遍**——
在**匹配的操作系统**上（Linux 作业在 WSL/本机 Linux 上跑，windows 作业在 Windows 上跑），
用与工作流一致的 env（包括把 key 清空那几条，防止测试偷偷用真实凭据）。

与 GitHub runner 的差异（别把本地结果当成 GitHub 结果）：
* `uses:` 步骤（checkout / setup-python）被跳过——本地已经在仓库里、Python 也已就位；
  脚本会把跳过的步骤打印出来，不藏起来；
* runner 镜像里的预装工具不在（本机有什么用什么，所以"缺依赖"会在这里暴露，
  这正是 CI 最该抓的一类问题）；
* 平台不匹配的作业**拒绝执行**（在 Windows 上跑 ubuntu 作业只会得到误导性结果）。

用法：
    python tools/run_ci_locally.py --list
    python tools/run_ci_locally.py --job lint
    python tools/run_ci_locally.py --job test --matrix python-version=3.12
    python tools/run_ci_locally.py --all          # 本平台能跑的全部作业
"""
from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

LINUX_LABELS = ("ubuntu-latest", "ubuntu-22.04", "ubuntu-20.04", "ubuntu-24.04")
WINDOWS_LABELS = ("windows-latest", "windows-2022", "windows-2019")


def _load_workflow(path: Path) -> dict:
    try:
        import yaml
    except ImportError:
        print("需要 PyYAML：pip install pyyaml")
        raise SystemExit(2) from None
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _host_kind() -> str:
    return "windows" if platform.system() == "Windows" else "linux"


def _job_target(job: dict, matrix: dict[str, str] | None = None) -> str:
    """作业的目标平台；`${{ matrix.os }}` 用传入的矩阵值解析。"""
    runs_on = str(job.get("runs-on") or "").strip()
    if matrix:
        for key, value in matrix.items():
            runs_on = runs_on.replace("${{ matrix." + key + " }}", value)
            runs_on = runs_on.replace("${{matrix." + key + "}}", value)
    if runs_on in WINDOWS_LABELS:
        return "windows"
    if runs_on in LINUX_LABELS:
        return "linux"
    return f"unknown({runs_on})"


def _checkout_ref() -> str:
    """当前 commit（报告里写明"跑的是哪个提交"，否则结论没有意义）。"""
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT, capture_output=True, text=True, check=False,
            # 显式声明编码：不写的话按 UTF-8 解本机命令输出，中文 Windows 上是
            # GBK 字节 → 读取线程抛 UnicodeDecodeError（实测同类事故见
            # src/hexhound/diagnose.py 的 _decode_console 注释）。
            encoding="utf-8", errors="replace",
        ).stdout.strip()
    except OSError:
        return ""


def _dirty() -> bool:
    out = subprocess.run(
        ["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True, check=False,
        encoding="utf-8", errors="replace",
    ).stdout.strip()
    return bool(out)


def _run_step(command: str, shell_hint: str, env: dict) -> int:
    kind = _host_kind()
    if kind == "windows":
        if shell_hint == "cmd":
            argv = ["cmd", "/c", command]
        elif shell_hint == "bash":
            argv = ["bash", "-e", "-o", "pipefail", "-c", command]
        else:
            argv = ["powershell", "-NoProfile", "-Command", command]
    else:
        argv = ["/bin/bash", "-e", "-o", "pipefail", "-c", command] if shell_hint != "sh" else [
            "/bin/sh", "-eu", "-c", command
        ]
    print(f"$ {command.strip().splitlines()[0][:120]}")
    result = subprocess.run(argv, cwd=ROOT, env=env, check=False)
    return result.returncode


def run_job(job_id: str, job: dict, workflow: dict, matrix: dict[str, str], force: bool) -> bool | None:
    target = _job_target(job, matrix)
    host = _host_kind()
    if target != host and not force:
        print(f"跳过作业 {job_id}：它跑在 {target}，本机是 {host}（用 --force 可强行执行，结果不可信）")
        # 三态：True 通过 / False 失败 / **None 未执行**。
        # 返回 True 会让汇总额把它印成 PASS——实测因此把"没跑 Linux 作业"
        # 误当成"Linux 也通过了"（CI 抓到的假绿）。
        return None
    print("=" * 78)
    print(f"作业 {job_id}（runs-on={job.get('runs-on')}）")
    if matrix:
        print(f"矩阵：{matrix}")
    print("=" * 78)

    env = dict(os.environ)
    env.update({str(k): str(v) for k, v in (workflow.get("env") or {}).items()})
    env.update({str(k): str(v) for k, v in (job.get("env") or {}).items()})
    for key, value in matrix.items():
        env[f"MATRIX_{key.replace('-', '_').upper()}"] = value

    failures: list[str] = []
    skipped: list[str] = []
    for index, step in enumerate(job.get("steps") or [], start=1):
        name = step.get("name") or step.get("uses") or f"step {index}"
        if "uses" in step:
            skipped.append(f"{name}（uses: {step['uses']}）")
            print(f"[skip] {name} —— 本地环境已提供（{step['uses']}）")
            continue
        command = step.get("run")
        if not command:
            continue
        step_env = dict(env)
        step_env.update({str(k): str(v) for k, v in (step.get("env") or {}).items()})
        print(f"\n--- [{index}] {name} ---")
        code = _run_step(str(command), str(step.get("shell") or "").lower(), step_env)
        advisory = bool(step.get("continue-on-error"))
        if code != 0:
            if advisory:
                print(f"[warn] {name} 失败（工作流里标了 continue-on-error，不算门禁）rc={code}")
            else:
                failures.append(f"{name} (rc={code})")
                print(f"[FAIL] {name} rc={code}")

    print()
    if skipped:
        print("本地跳过的 uses: 步骤：" + "；".join(skipped))
    if failures:
        print(f"作业 {job_id} 结果：失败 → {', '.join(failures)}")
        return False
    print(f"作业 {job_id} 结果：通过")
    return True


def _with_hidden_dotenv(enabled: bool):
    """把仓库根目录的 `.env` 临时藏起来，模拟"CI 上的干净 checkout"。

    为什么必须这样：工作流里刻意把 `LLM_API_KEY` / `LLM_PROVIDER` 清空，
    好让"不小心依赖真实凭据"立刻暴露。但本机仓库根目录**有** `.env`，
    于是 CLI 仍能从里面推出提供商（`LLM_BASE_URL` 反推），报错文案随之不同——
    `self-check` 里那句 `grep "还没有选择模型提供商"` 就会假失败。
    GitHub 上不存在这个文件（`.env` 是 gitignored），所以藏起来才是**更忠实**的模拟。

    返回一个上下文管理器；无论成败都会把文件恢复原状。
    """
    import contextlib

    @contextlib.contextmanager
    def _cm():
        path = ROOT / ".env"
        hidden = ROOT / ".env.hexhound-ci-hidden"
        moved = False
        if enabled and path.is_file() and not hidden.exists():
            try:
                path.rename(hidden)
                moved = True
                print("[note] 已临时移开 .env（模拟干净 checkout；结束后恢复）")
            except OSError as exc:
                print(f"[warn] 无法临时移开 .env：{exc}")
        try:
            yield
        finally:
            if moved and hidden.exists():
                try:
                    hidden.rename(path)
                    print("[note] 已恢复 .env")
                except OSError as exc:  # pragma: no cover - 极端情况
                    print(f"[FAIL] 恢复 .env 失败，请手动把 {hidden} 改回 .env：{exc}")

    return _cm()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="在本机执行 .github/workflows/ci.yml 的作业")
    parser.add_argument("--workflow", default=str(WORKFLOW))
    parser.add_argument("--list", action="store_true", help="列出作业及其目标平台")
    parser.add_argument("--job", help="要执行的作业 id")
    parser.add_argument("--all", action="store_true", help="执行本平台能跑的全部作业")
    parser.add_argument("--matrix", action="append", default=[], help="矩阵值，如 --matrix python-version=3.12")
    parser.add_argument("--force", action="store_true", help="平台不匹配也执行（结果不可信）")
    parser.add_argument(
        "--keep-dotenv", action="store_true",
        help="不要临时移开仓库根目录的 .env（默认会移开，模拟 CI 的干净 checkout）",
    )
    args = parser.parse_args(argv[1:])

    workflow = _load_workflow(Path(args.workflow))
    jobs: dict = workflow.get("jobs") or {}
    host = _host_kind()

    matrix: dict[str, str] = {}
    for item in args.matrix:
        if "=" in item:
            key, value = item.split("=", 1)
            matrix[key.strip()] = value.strip()

    if args.list or (not args.job and not args.all):
        print(f"工作流：{Path(args.workflow).name}    本机平台：{host}")
        for job_id, job in jobs.items():
            target = _job_target(job, matrix)
            mark = "可跑" if target == host else "跳过"
            print(f"  {job_id:<12} runs-on={str(job.get('runs-on')):<16} [{mark}]")
        print()
        print(f"本地执行：HEAD={_checkout_ref()}{'（工作树有未提交改动）' if _dirty() else ''}")
        if any(_job_target(job, {}) .startswith("unknown") for job in jobs.values()):
            print("提示：带矩阵的作业用 --matrix os=ubuntu-latest 之类的参数解析目标平台。")
        return 0

    matrix: dict[str, str] = {}
    for item in args.matrix:
        if "=" in item:
            key, value = item.split("=", 1)
            matrix[key.strip()] = value.strip()

    selected = list(jobs) if args.all else [args.job]
    results: dict[str, bool | None] = {}
    with _with_hidden_dotenv(not args.keep_dotenv):
        for job_id in selected:
            job = jobs.get(job_id)
            if job is None:
                print(f"[FAIL] 工作流里没有作业 {job_id}")
                return 2
            results[job_id] = run_job(job_id, job, workflow, matrix, args.force)

    print()
    print("=" * 78)
    print(f"本地 CI 汇总（HEAD={_checkout_ref()}{'（工作树有未提交改动）' if _dirty() else ''}）")
    for job_id, ok in results.items():
        mark = "PASS" if ok else ("SKIP" if ok is None else "FAIL")
        print(f"  {mark}  {job_id}")
    skipped_jobs = [job_id for job_id, ok in results.items() if ok is None]
    failed = [job_id for job_id, ok in results.items() if ok is False]
    if skipped_jobs:
        print(
            f"\n未执行的作业（平台不匹配）：{', '.join(skipped_jobs)}"
            "——**这些没有被验证**，别当成通过。"
        )
    if failed:
        print(f"\n失败的作业：{', '.join(failed)}")
        return 1
    if skipped_jobs:
        print(
            f"\n通过：{len(results) - len(skipped_jobs)}/{len(results)} 个作业真的在本机跑了；"
            f"{len(skipped_jobs)} 个因平台不匹配未执行（见上）。"
        )
    else:
        print("\n全部通过。注意：这仍**不等于** GitHub runner 上的结果——")
        print("runner 镜像的预装工具、权限与网络都不同；真正的判定要看 GitHub 上的这一次运行。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
