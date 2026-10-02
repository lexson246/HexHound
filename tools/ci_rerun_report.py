"""CI 里"再跑一次并打印 skip 明细"这一步：失败原因要能被**公开读到**。

背景（真实痛点）：GitHub Actions 的**原始日志需要认证**，公共仓库上第三方
（包括下一个接手的 AI）只能读到 check run 的 `output.summary`。于是"某个可选
依赖悄悄缺失、一整层测试没跑"这类问题在 CI 上是**红点没有解释**的。

这个脚本做三件事：

1. 跑 `pytest -q -rs`（和 workflow 里那一步完全一致）；
2. 把输出完整打到 stdout（人看日志时和以前一样）；
3. 失败时把尾部摘要写进 `$GITHUB_STEP_SUMMARY`（公开可读），并原样返回退出码。

刻意**不**用 `| tail`：那依赖 Git 自带的 coreutils（GitHub 的 windows runner
恰好有，别的 Windows 环境没有）——本地 CI 执行器第一次跑就因此报 rc=1。
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

#: 写进摘要的尾部行数（够看清失败用例与 skip 明细，又不至于把摘要撑爆）。
TAIL_LINES = 120


def tail_lines(text: str, limit: int = TAIL_LINES) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-limit:]) if len(lines) > limit else text


def main() -> int:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rs"],
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
    summary = (
        f"# 测试重跑失败（pytest 退出码 {proc.returncode}）\n\n"
        "`python -m pytest -q -rs` 的尾部输出（详细日志见该步骤的原始日志）：\n\n"
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
