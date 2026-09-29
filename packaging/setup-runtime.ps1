param([switch]$SystemSetup, [switch]$CheckOnly, [switch]$Quiet)
$ErrorActionPreference = 'Stop'
$env:WSL_UTF8 = '1'
$distro = 'HexHound-Tools'
$logDir = Join-Path $env:LOCALAPPDATA 'HexHound'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
Start-Transcript -Path (Join-Path $logDir 'runtime-setup.log') -Append | Out-Null
$result = 0
try {
    if ($SystemSetup) {
        $admin = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Administrator rights are required to enable Windows components.'
        }
        $restart = $false
        foreach ($feature in @('Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform')) {
            $state = Get-WindowsOptionalFeature -Online -FeatureName $feature
            if ($state.State -ne 'Enabled') {
                $change = Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart
                $restart = $restart -or $change.RestartNeeded
            }
        }
        $msi = Join-Path $PSScriptRoot 'wsl-x64.msi'
        $signature = Get-AuthenticodeSignature -LiteralPath $msi
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
            throw 'WSL installer signature verification failed.'
        }
        $install = Start-Process msiexec.exe -ArgumentList @('/i', ('"' + $msi + '"'), '/qn', '/norestart') -Wait -PassThru -WindowStyle Hidden
        if ($install.ExitCode -notin @(0, 1638, 3010)) { throw "WSL MSI failed: $($install.ExitCode)" }
        if ($restart -or $install.ExitCode -eq 3010) { $result = 3010 }
    } else {
        if (-not $CheckOnly) {
            $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
            $ready = $false
            if ($wsl) {
                & wsl.exe --status 2>&1 | Out-Host
                $ready = $LASTEXITCODE -eq 0
            }
            if (-not $ready) {
                Write-Host 'Enabling Windows virtualization and installing bundled WSL...'
                $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -SystemSetup -Quiet'
                $system = Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -WindowStyle Hidden -Wait -PassThru
                if ($system.ExitCode -eq 3010) {
                    throw 'Restart Windows, then run "HexHound - Finish runtime setup" from the Start menu.'
                }
                if ($system.ExitCode -ne 0) { throw "Windows runtime setup failed: $($system.ExitCode)" }
            }
        }
        $names = @(& wsl.exe --list --quiet) | ForEach-Object { $_.Replace([string][char]0, '').Trim() }
        if ($LASTEXITCODE -ne 0) { throw 'WSL is unavailable. Enable CPU virtualization in BIOS/UEFI and restart Windows.' }
        if ($distro -notin $names) {
            if ($CheckOnly) { throw 'HexHound-Tools is not installed.' }
            $destination = Join-Path $logDir 'Tools'
            if (Test-Path -LiteralPath $destination) { throw "Refusing to overwrite existing directory: $destination" }
            & wsl.exe --import $distro $destination (Join-Path $PSScriptRoot 'hexhound-tools.tar') --version 2
            if ($LASTEXITCODE -ne 0) { throw 'Import failed. Check free disk space, virtualization and Windows restart status.' }
        }
        & wsl.exe -d $distro --exec sh -c 'for t in nmap sqlmap nikto whatweb gobuster ffuf nuclei curl python3; do command -v "$t" || exit 1; done; test -d /root/nuclei-templates/http'
        if ($LASTEXITCODE -ne 0) { throw 'The tools environment is incomplete. See runtime-setup.log.' }
        Write-Host 'HexHound runtime is ready.' -ForegroundColor Green
    }
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    $result = 1
} finally {
    Stop-Transcript | Out-Null
}
if (-not $Quiet -and -not $SystemSetup) { Read-Host 'Press Enter to close' | Out-Null }
exit $result
