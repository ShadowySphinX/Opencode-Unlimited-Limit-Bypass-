<#
.SYNOPSIS
    Opencode Unlimited Usage v2.4.0 — clean Windows uninstaller.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

$Brand = "opencode-unlimited"
$Dest = Join-Path $env:LOCALAPPDATA $Brand
$BinDest = Join-Path $Dest "bin"
$ScriptsDest = Join-Path $Dest "scripts"
$TaskKeeper = "OpencodeUnlimited-Keeper"
$TaskGuard = "OpencodeUnlimited-Guard"

function Ok([string]$Msg) { Write-Host "  [OK] $Msg" -ForegroundColor Green }
function Warn([string]$Msg) { Write-Host "  [!]  $Msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "  removing Opencode Unlimited (Windows)..."
Write-Host ""

# 1. Stop and remove Scheduled Tasks & HKCU Run entries
foreach ($tn in @($TaskGuard, $TaskKeeper)) {
    Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $tn -ErrorAction SilentlyContinue
}
Ok "background tasks removed"

# 2. Terminate active worker processes
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.ProcessId -ne $PID -and
    ($_.Name -ieq "python.exe" -or $_.Name -ieq "pythonw.exe") -and
    $_.CommandLine -and (
        $_.CommandLine -like "*$Brand*warp_keeper.py*" -or
        $_.CommandLine -like "*$Brand*zen_guard.py*" -or
        $_.CommandLine -like "*$Brand*zen_proxy.py*"
    )
} | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
Ok "background workers stopped"

# 2b. Unwire OpenCode background service proxy env vars
$OcCandidates = @(
    (Join-Path $env:LOCALAPPDATA "Programs\ai.opencode.desktop\resources\opencode-cli.exe"),
    (Join-Path $env:USERPROFILE ".opencode\bin\opencode.exe"),
    (Join-Path $env:LOCALAPPDATA "opencode\opencode.exe"),
    (Join-Path $env:USERPROFILE ".bun\bin\opencode.exe"),
    (Join-Path $env:APPDATA "npm\opencode.cmd")
)
$OcReal = $OcCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($OcReal) {
    foreach ($k in @("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy")) {
        & $OcReal service unset env $k *> $null
    }
    $svcStatus = (& $OcReal service status 2>&1 | Out-String)
    if ($svcStatus -match "http://127\.0\.0\.1") {
        & $OcReal service restart *> $null
    }
    Ok "OpenCode background service restored to direct egress"
}

# 3. Remove firewall rule if present
$FwShow = netsh advfirewall firewall show rule name=OUC_LEAKGUARD_CLI 2>&1
if ($LASTEXITCODE -eq 0 -and ($FwShow -match "OUC_LEAKGUARD_CLI")) {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        netsh advfirewall firewall delete rule name=OUC_LEAKGUARD_CLI | Out-Null
        Ok "firewall kill-switch removed"
    } else {
        Warn "OUC_LEAKGUARD_CLI firewall rule exists — re-run uninstall.bat as Administrator to remove it"
    }
}

# 4. Remove from User PATH
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath) {
    $Cleaned = ($UserPath -split ";" | Where-Object { $_ -and ($_.TrimEnd("\") -ine $BinDest.TrimEnd("\")) }) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $Cleaned, "User")
    Ok "removed $BinDest from User PATH"
}

# 5. Disconnect WARP
$WarpCandidates = @(
    "C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe",
    "C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe",
    (Join-Path $env:LOCALAPPDATA "Cloudflare\Cloudflare WARP\warp-cli.exe")
)
$WarpBin = $WarpCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($WarpBin) {
    & $WarpBin disconnect *> $null
    Ok "warp tunnel disconnected (package left installed)"
}

# 6. Delete local app data directory
if (Test-Path $Dest) {
    Remove-Item -Path $Dest -Recurse -Force -ErrorAction SilentlyContinue
    Ok "removed $Dest"
}

Write-Host ""
Ok "gone. OpenCode itself and your sessions are untouched."
Write-Host ""
