# 在 Windows 上执行 CI 的 windows 两条腿（desktop + test 矩阵），各用独立 venv。
#
# 为什么用 venv：本机 3.11 是 uv 管理的解释器，带 EXTERNALLY-MANAGED 标记，
# 连 `pip install --upgrade pip` 都会拒绝；3.12 若直接用系统解释器会污染全局环境。
# runner 上 `actions/setup-python` 提供的也是"隔离解释器"，venv 是最接近的本地等价物。
#
# ⚠ 脚本里的解释器路径是**本机路径**（见下面的 $interpreters），换机器要改。
# 通用入口是 tools/run_ci_locally.py（跨平台、按平台自动跳过不匹配的作业）。
$ErrorActionPreference = 'Continue'
$repo = 'C:\Users\LeXSon\Documents\ChatGPT\HexHound 2'
$log = Join-Path $repo '.tmp\ci-windows.log'
Set-Location $repo
$env:PYTHONIOENCODING = 'utf-8'
$env:PIP_INDEX_URL = 'https://pypi.tuna.tsinghua.edu.cn/simple'
$env:PIP_DISABLE_PIP_VERSION_CHECK = '1'

$interpreters = @(
    @{ version = '3.12'; exe = 'C:\Users\LeXSon\AppData\Local\Programs\Python\Python312\python.exe' },
    @{ version = '3.11'; exe = 'C:\Users\LeXSon\AppData\Roaming\uv\python\cpython-3.11.15-windows-x86_64-none\python.exe' }
)

"HEAD: $(git rev-parse --short HEAD)" | Out-File -FilePath $log -Encoding utf8

# --- desktop 作业（用默认 python 即可）---
"############### --job desktop ###############" | Out-File -FilePath $log -Append -Encoding utf8
python tools/run_ci_locally.py --job desktop *>&1 | Out-File -FilePath $log -Append -Encoding utf8
"#### desktop rc=$LASTEXITCODE ####" | Out-File -FilePath $log -Append -Encoding utf8

# --- test 作业的两条 windows 腿，各用独立 venv ---
foreach ($item in $interpreters) {
    $version = $item.version
    $venv = Join-Path $repo ".tmp\venv-$version"
    "--- 准备 venv $version ：$venv ---" | Out-File -FilePath $log -Append -Encoding utf8
    if (-not (Test-Path "$venv\Scripts\python.exe")) {
        & $item.exe -m venv $venv *>&1 | Out-File -FilePath $log -Append -Encoding utf8
    }
    $env:PATH = "$venv\Scripts;$venv;$env:PATH"
    "python -> $((Get-Command python).Source) $((python -V 2>&1))" | Out-File -FilePath $log -Append -Encoding utf8
    # 本地执行器需要 PyYAML（工作流本身不装它）
    python -m pip install -q pyyaml *>&1 | Out-File -FilePath $log -Append -Encoding utf8
    python -c "import yaml; print('pyyaml', yaml.__version__)" *>&1 | Out-File -FilePath $log -Append -Encoding utf8

    "############### --job test (windows-latest / py$version) ###############" | Out-File -FilePath $log -Append -Encoding utf8
    python tools/run_ci_locally.py --job test --matrix os=windows-latest --matrix python-version=$version *>&1 |
        Out-File -FilePath $log -Append -Encoding utf8
    "#### test py$version rc=$LASTEXITCODE ####" | Out-File -FilePath $log -Append -Encoding utf8
}
"ALL-WINDOWS-JOBS-DONE" | Out-File -FilePath $log -Append -Encoding utf8
