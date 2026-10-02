"""CI 里跑 pytest 的包装：失败原因要能被**公开读到**。

背景（真实痛点）：GitHub Actions 的**原始日志需要认证**，公共仓库上第三方
（包括下一个接手的 AI）只能读到 check run 的 `output.summary`。于是"某个可选
依赖悄悄缺失、一整层测试没跑"这类问题在 CI 上是**红点没有解释**的。

这个脚本做三件事：

1. 跑 pytest（默认 `-q -rs`，可用 `--pytest-args` 覆盖）；
2. 把输出完整打到 stdout（人看日志时和以前一样）；
3. 失败时把尾部摘要写进 `$GITHUB_STEP_SUMMARY`（公开可读），并原样返回退出码。

**两个步骤都要用它**：早先只包了"再跑一次看 skip 明细"那一步，结果第一次
`Run test suite` 红在 Ubuntu 上时依旧拿不到任何原因（实测踩过）。

刻意**不**用 `| tail`：那依赖 Git 自带的 coreutils（GitHub 的 windows runner
恰好有，别的 Windows 环境没有）——本地 CI 执行器第一次跑就因此报 rc=1。
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path

#: 写进摘要的尾部行数（够看清失败用例与 skip 明细，又不至于把摘要撑爆）。
TAIL_LINES = 120


def tail_lines(text: str, limit: int = TAIL_LINES) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-limit:]) if len(lines) > limit else text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="跑 pytest 并在失败时写公开摘要")
    parser.add_argument(
        "--pytest-args", default="-q -rs",
        help='pytest 参数（默认 "-q -rs"；传 "" 表示不带参数，对应 CI 的第一步）',
    )
    parser.add_argument("--label", default="", help="摘要标题里的说明（可选）")
    args = parser.parse_args(argv)

    command = [sys.executable, "-m", "pytest", *shlex.split(args.pytest_args or "")]
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    print(output, flush=True)
    if proc.returncode == 0:
        return 0
    title = args.label or f"pytest {' '.join(command[3:])}".strip()
    summary = (
        f"# 测试失败（{title}，退出码 {proc.returncode}）\n\n"
        "尾部输出（完整日志需 GitHub 认证；这里给出可公开阅读的失败原因）：\n\n"
        f"```\n{tail_lines(output)}\n```\n"
    )
    path = os.getenv("GITHUB_STEP_SUMMARY", "").strip()
    if path:
        try:
            Path(path).write_text(summary, encoding="utf-8")
        except OSError as exc:  # noqa: BLE001 摘要写不进去不影响判失败
            print(f"[note] 写 GITHUB_STEP_SUMMARY 失败：{exc}", file=sys.stderr)
    else:
        print("[note] 没有 GITHUB_STEP_SUMMARY（本地跑），失败摘要只在上面。", file=sys.stderr)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
