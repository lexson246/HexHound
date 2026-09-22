# 只跑 CI 的 windows/py3.11 那条腿（uv 管理的解释器需要 --break-system-packages）
$ErrorActionPreference = 'Continue'
$repo = 'C:\Users\LeXSon\Documents\ChatGPT\HexHound 2'
$log = Join-Path $repo '.tmp\ci-win311.log'
Set-Location $repo
$env:PYTHONIOENCODING = 'utf-8'
$env:PIP_INDEX_URL = 'https://pypi.tuna.tsinghua.edu.cn/simple'
$py311 = 'C:\Users\LeXSon\AppData\Roaming\uv\python\cpython-3.11.15-windows-x86_64-none'

"HEAD: $(git rev-parse --short HEAD)" | Out-File -FilePath $log -Encoding utf8
& uv pip install --python "$py311\python.exe" --break-system-packages -q pyyaml *>&1 |
    Out-File -FilePath $log -Append -Encoding utf8
& "$py311\python.exe" -c "import yaml; print('pyyaml', yaml.__version__)" *>&1 |
    Out-File -FilePath $log -Append -Encoding utf8

$env:PATH = "$py311;$py311\Scripts;$env:PATH"
"python -> $((Get-Command python).Source) $((python -V 2>&1))" | Out-File -FilePath $log -Append -Encoding utf8
"############### --job test (windows-latest / py3.11) ###############" | Out-File -FilePath $log -Append -Encoding utf8
python tools/run_ci_locally.py --job test --matrix os=windows-latest --matrix python-version=3.11 *>&1 |
    Out-File -FilePath $log -Append -Encoding utf8
"#### test py3.11 rc=$LASTEXITCODE ####" | Out-File -FilePath $log -Append -Encoding utf8
"WIN311-DONE" | Out-File -FilePath $log -Append -Encoding utf8
