"""CI 工作流的**静态一致性**校验：不联网、不跑 runner，也能查出常见的手滑。

为什么需要它：上一轮把 `gui` / `desktop` 两个作业写进 CI 后，只能"等 GitHub 上跑一次"
才知道对不对——而本机没有 runner。这个脚本把**能在本机确定检查**的部分固化成检查项，
把"编排写错了"从"要等 CI 变红"提前到本地一条命令：

1. 工作流能解析（YAML）且每个作业都有 `runs-on`；
2. 每个 `run:` 步骤里引用的**本仓库文件**（`tools/*.py`、`examples/*.py`、`tests/*.py`、
   `.spec` 文件）确实存在——改名/删文件时最容易漏掉这里；
3. `python -m pytest <路径>` 里的路径存在；
4. `pip install -e ".[...]"` 里的 extras 在 `pyproject.toml` 里真的有定义；
5. 工作流里出现的 `HEXHOUND_*` 环境变量，代码里确实有人读（拼错就是静默失效）；
6. `python -m PyInstaller <spec>` 引用的 spec 文件存在。

**它不能替代真跑一次 CI**（runner 环境、缓存、权限、平台差异都测不到），
这一条限制写在输出里，避免有人把它当成"CI 已经验过了"。

用法：python tools/check_ci_workflow.py [.github/workflows/ci.yml]
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

#: 步骤命令里出现的、属于本仓库的文件引用
_FILE_PATTERNS = (
    re.compile(r"\b(tools/[\w./-]+\.py)\b"),
    re.compile(r"\b(examples/[\w./-]+\.py)\b"),
    re.compile(r"\b(tests/[\w./-]+\.py)\b"),
    re.compile(r"\b([\w./-]+\.spec)\b"),
)
_EDITABLE = re.compile(r"pip install -e \"\.\[([^\]]*)\]\"")
_ENV_REF = re.compile(r"\b(HEXHOUND_[A-Z0-9_]+)\b")


def _load_yaml(path: Path) -> dict:
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML 是测试依赖
        print("[SKIP] 未安装 PyYAML，无法解析工作流（pip install pyyaml）")
        raise SystemExit(0) from None
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _iter_run_commands(workflow: dict):
    for job_name, job in (workflow.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            command = step.get("run")
            if command:
                yield job_name, step.get("name", ""), str(command)


def _collect_env_refs(workflow: dict) -> set[str]:
    text = str(workflow)
    return set(_ENV_REF.findall(text))


def _grep_env_usage(name: str) -> bool:
    """代码里是否有人读这个环境变量（拼错就会静默失效）。"""
    for path in list((ROOT / "src").rglob("*.py")) + list((ROOT / "tools").glob("*.py")):
        try:
            if name in path.read_text(encoding="utf-8"):
                return True
        except OSError:
            continue
    return False


def main(argv: list[str]) -> int:
    workflow_path = Path(argv[1]) if len(argv) > 1 else DEFAULT_WORKFLOW
    if not workflow_path.is_file():
        print(f"[FAIL] 找不到工作流文件：{workflow_path}")
        return 1
    problems: list[str] = []
    checked = 0

    try:
        workflow = _load_yaml(workflow_path)
    except Exception as exc:  # noqa: BLE001 解析失败直接算错
        print(f"[FAIL] 工作流不是合法 YAML：{exc}")
        return 1

    jobs = workflow.get("jobs") or {}
    if not jobs:
        problems.append("工作流里没有任何作业")
    for name, job in jobs.items():
        if not job.get("runs-on"):
            problems.append(f"作业 {name} 缺少 runs-on")

    extras_declared: set[str] = set()
    pyproject = ROOT / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            extras_declared = set(
                (data.get("project", {}).get("optional-dependencies") or {}).keys()
            )
        except (OSError, tomllib.TOMLDecodeError) as exc:
            problems.append(f"pyproject.toml 解析失败：{exc}")

    for job_name, step_name, command in _iter_run_commands(workflow):
        where = f"{job_name} / {step_name or '(未命名步骤)'}"
        for pattern in _FILE_PATTERNS:
            for match in pattern.findall(command):
                checked += 1
                if not (ROOT / match).exists():
                    problems.append(f"{where}：引用的文件不存在 → {match}")
        for match in _EDITABLE.findall(command):
            for extra in (item.strip() for item in match.split(",")):
                if not extra:
                    continue
                checked += 1
                if extras_declared and extra not in extras_declared:
                    problems.append(
                        f"{where}：pyproject 里没有 extras [{extra}]（有的是 {sorted(extras_declared)}）"
                    )
        if "python -m pytest" in command:
            for token in command.split():
                if token.startswith(("tests/", "tools/", "examples/")) and token.endswith(".py"):
                    checked += 1
                    if not (ROOT / token).exists():
                        problems.append(f"{where}：pytest 目标不存在 → {token}")

    for env_name in sorted(_collect_env_refs(workflow)):
        if env_name in ("HEXHOUND_REQUIRE_GUI", "HEXHOUND_BROWSER"):
            checked += 1
            if not _grep_env_usage(env_name):
                problems.append(f"工作流设置了 {env_name}，但代码里没人读它（拼错了？）")

    print(f"检查项：{checked}（工作流：{workflow_path.relative_to(ROOT)}，作业：{list(jobs)}）")
    if problems:
        for problem in problems:
            print(f"[FAIL] {problem}")
        print()
        print(f"静态一致性检查未通过：{len(problems)} 个问题。")
        return 1
    print("[ OK ] 引用文件、extras、环境变量、作业结构都一致。")
    print()
    print("注意：这**不能**替代真跑一次 CI——runner 环境、权限、平台差异都测不到。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
