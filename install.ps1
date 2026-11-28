<#
.SYNOPSIS
    Opencode Unlimited Usage - native Windows installer.
#>
[CmdletBinding()]
param(
    [switch]$SkipWarmCheck
)

$ErrorActionPreference = "Stop"

$Brand = "opencode-unlimited"
$Dest = Join-Path $env:LOCALAPPDATA $Brand
$ScriptsDest = Join-Path $Dest "scripts"
$BinDest = Join-Path $Dest "bin"
$TaskKeeper = "OpencodeUnlimited-Keeper"
$TaskGuard = "OpencodeUnlimited-Guard"
$TaskWatchdog = "OpencodeUnlimited-Watchdog"
$RepoWinDir = Join-Path $PSScriptRoot "src"
if (-not (Test-Path (Join-Path $RepoWinDir "ouc_common.py"))) {
    $RepoWinDir = Join-Path $PSScriptRoot "windows"
}

function Say([string]$Msg) { Write-Host "  $Msg" }
function Ok([string]$Msg) { Write-Host "  [OK] $Msg" -ForegroundColor Green }
function Warn([string]$Msg) { Write-Host "  [!]  $Msg" -ForegroundColor Yellow }
function Die([string]$Msg) { Write-Host "  [X]  $Msg" -ForegroundColor Red; exit 1 }

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Host ""
Write-Host "  ==================================================="
Write-Host "  Opencode Unlimited (Windows v4.0)"
Write-Host "  Created & Maintained by Avatar (ShadowySphinX)"
Write-Host "  ==================================================="
Write-Host ""

if (-not (Test-Path (Join-Path $RepoWinDir "ouc_common.py"))) {
    Die "source folder (src\ or windows\) not found next to install.ps1"
}

# ---------------------------------------------------------------- Python 3
$PyExe = $null
foreach ($cmd in @("python.exe", "python")) {
    $found = Get-Command $cmd -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found -and $found.Source -notlike "*\WindowsApps\*") {
        $ver = & $found.Source -c "import sys; print(sys.version_info[:2] >= (3, 10))" 2>$null
        if ($ver -eq "True") { $PyExe = $found.Source; break }
    }
}
if (-not $PyExe) {
    $pyLauncher = Get-Command "py.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pyLauncher) {
        $resolved = & $pyLauncher.Source -3 -c "import sys; print(sys.executable if sys.version_info[:2] >= (3, 10) else '')" 2>$null
        if ($resolved -and (Test-Path $resolved)) { $PyExe = $resolved }
    }
}
if (-not $PyExe) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Say "Python 3.10+ not found - attempting install via winget..."
        winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements | Out-Null
        $env:PATH = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
        $found = Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found -and $found.Source -notlike "*\WindowsApps\*") {
            $ver = & $found.Source -c "import sys; print(sys.version_info[:2] >= (3, 10))" 2>$null
            if ($ver -eq "True") { $PyExe = $found.Source }
        }
    }
}
if (-not $PyExe) { Die "Python 3.10+ is required. Install from https://www.python.org/downloads/ and re-run." }

$PyDir = Split-Path $PyExe -Parent
$PywCandidate = Join-Path $PyDir "pythonw.exe"
$PywExe = if (Test-Path $PywCandidate) { $PywCandidate } else { $PyExe }
Ok "python: $PyExe"

# ---------------------------------------------------------------- OpenCode CLI
$OcCandidates = @(
    (Join-Path $env:LOCALAPPDATA "Programs\ai.opencode.desktop\resources\opencode-cli.exe"),
    (Join-Path $env:USERPROFILE ".opencode\bin\opencode.exe"),
    (Join-Path $env:LOCALAPPDATA "opencode\opencode.exe"),
    (Join-Path $env:USERPROFILE ".bun\bin\opencode.exe"),
    (Join-Path $env:APPDATA "npm\opencode.cmd")
)
$DesktopCliRoot = Join-Path $env:APPDATA "ai.opencode.desktop\cli"
if (Test-Path $DesktopCliRoot) {
    $DesktopCli = Get-ChildItem -Path $DesktopCliRoot -Recurse -Filter "opencode-cli.exe" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($DesktopCli) { $OcCandidates = @($DesktopCli.FullName) + $OcCandidates }
}
$OcReal = $OcCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $OcReal) {
    $onPath = Get-Command opencode -All -ErrorAction SilentlyContinue | Where-Object {
        $_.Source -notlike "*$Brand*" -and $_.Source -notlike "*opencode-infinite*"
    } | Select-Object -First 1
    if ($onPath) { $OcReal = $onPath.Source }
}
if (-not $OcReal) {
    Say "opencode CLI not found - running official Windows installer..."
    try {
        Invoke-Expression (Invoke-RestMethod -Uri "https://opencode.ai/install.ps1")
    } catch {
        Warn "official installer failed: $_"
    }
    $OcReal = $OcCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $OcReal) { Die "opencode CLI not found - install OpenCode first (https://opencode.ai)." }
Ok "opencode found: $OcReal"

# ---------------------------------------------------------------- warp-cli.exe
$WarpCandidates = @(
    "C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe",
    "C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe",
    (Join-Path $env:LOCALAPPDATA "Cloudflare\Cloudflare WARP\warp-cli.exe")
)
$WarpBin = $WarpCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $WarpBin) {
    $wCmd = Get-Command warp-cli.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($wCmd) { $WarpBin = $wCmd.Source }
}
if (-not $WarpBin) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Say "Cloudflare WARP not found - installing via winget..."
        winget install --id Cloudflare.Warp -e --silent --accept-package-agreements --accept-source-agreements | Out-Null
        Start-Sleep -Seconds 3
        $WarpBin = $WarpCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
}
if (-not $WarpBin) { Die "warp-cli.exe not found - install Cloudflare WARP from https://1.1.1.1/ and re-run." }
Ok "warp-cli found: $WarpBin"

# ---------------------------------------------------------------- Stop existing workers
Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
    $_.ProcessId -ne $PID -and
    ($_.Name -ieq "python.exe" -or $_.Name -ieq "pythonw.exe") -and
    $_.CommandLine -and (
        $_.CommandLine -like "*$Brand*warp_keeper.py*" -or
        $_.CommandLine -like "*$Brand*zen_guard.py*"
    )
} | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- Copy scripts & create wrappers
New-Item -ItemType Directory -Force -Path $ScriptsDest, $BinDest | Out-Null
Copy-Item -Path (Join-Path $RepoWinDir "*.py") -Destination $ScriptsDest -Force

$Wrappers = @{
    "opencode.cmd"                  = "@echo off`r`n`"$PyExe`" `"$ScriptsDest\zen_lane.py`" %*`r`nexit /b %ERRORLEVEL%`r`n"
    "opencode-desktop.cmd"          = "@echo off`r`nstart `"`" `"$PywExe`" `"$ScriptsDest\zen_lane.py`" --ouc-desktop %*`r`n"
    "opencode-unlimited-hop.cmd"    = "@echo off`r`n`"$PyExe`" `"$ScriptsDest\zen_hop.py`" %*`r`nexit /b %ERRORLEVEL%`r`n"
    "opencode-unlimited-doctor.cmd" = "@echo off`r`n`"$PyExe`" `"$ScriptsDest\doctor.py`" %*`r`nexit /b %ERRORLEVEL%`r`n"
    "opencode-unlimited-keeper.cmd" = "@echo off`r`n`"$PyExe`" `"$ScriptsDest\warp_keeper.py`" %*`r`nexit /b %ERRORLEVEL%`r`n"
    "opencode-unlimited-guard.cmd"  = "@echo off`r`n`"$PyExe`" `"$ScriptsDest\zen_guard.py`" %*`r`nexit /b %ERRORLEVEL%`r`n"
}
foreach ($kv in $Wrappers.GetEnumerator()) {
    $Body = $kv.Value
    $Shim = Join-Path $BinDest $kv.Key
    if ($Body -match '[^\x00-\x7F]' -and $Body -match '^@echo off') {
        # cmd.exe reads the batch file in the console code page; a non-ASCII
        # install path needs UTF-8 mode before the first command runs.
        $Body = $Body -replace '^@echo off\r\n', "@echo off`r`nchcp 65001 >nul`r`n"
    }
    [IO.File]::WriteAllText($Shim, $Body, (New-Object System.Text.UTF8Encoding($false)))
}
Ok "scripts & shims installed in $Dest"

# ---------------------------------------------------------------- Update User PATH (prepend so shim wins)
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$Parts = @()
if ($UserPath) {
    $Parts = $UserPath -split ";" | Where-Object { $_ -and ($_.TrimEnd("\") -ine $BinDest.TrimEnd("\")) }
}
$NewUserPath = (@($BinDest) + $Parts) -join ";"
[Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
$env:PATH = "$BinDest;" + (($env:PATH -split ";" | Where-Object { $_ -and ($_.TrimEnd("\") -ine $BinDest.TrimEnd("\")) }) -join ";")
try {
    Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition '[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);' -ErrorAction SilentlyContinue
    $res = [UIntPtr]::Zero
    [Win32.NativeMethods]::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, "Environment", 2, 2000, [ref]$res) | Out-Null
} catch {}
Ok "User PATH updated (prepended $BinDest)"

# ---------------------------------------------------------------- Optional Firewall Kill-Switch (when elevated)
if (Test-IsAdmin) {
    $fwOut = & $PyExe (Join-Path $ScriptsDest "ouc_firewall.py") install 2>&1
    if ($LASTEXITCODE -eq 0) {
        Ok "firewall kill-switch: $fwOut"
    } else {
        Warn "firewall kill-switch skipped: $fwOut"
    }
} else {
    Warn "not elevated - skipping optional Windows Firewall rule (zen-proxy still fails closed via WARP IPv6 bind)"
}

# ---------------------------------------------------------------- Connect WARP in the selected mode (before starting keeper so they never race)
function Invoke-Warp([string[]]$WarpArgs) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $out = & $WarpBin --accept-tos @WarpArgs 2>&1
        if ($LASTEXITCODE -eq 0) { return $out }
        $out = & $WarpBin @WarpArgs 2>&1
        return $out
    } finally {
        $ErrorActionPreference = $prev
    }
}

if (-not $SkipWarmCheck) {
    Say "checking Cloudflare WARP configuration..."

    # Keep a working registration. Creating a new one on every install
    # invalidates the existing device and drops the tunnel.
    $regOut = (Invoke-Warp @("registration", "show") | Out-String)
    if ($LASTEXITCODE -ne 0 -or $regOut -match "registration missing|not registered|no registration") {
        Say "no WARP registration found - creating one..."
        Invoke-Warp @("registration", "new") | Out-Null
    }

    # Keep the scope and egress mode the user selected in the dashboard.
    # A reinstall must not silently switch an App-Only setup to full TUN.
    $EgressCfg = Join-Path $env:LOCALAPPDATA "opencode-unlimited\lane\egress_mode.json"
    $WarpScope = "tun"
    $EgressMode = "warp"
    if (Test-Path $EgressCfg) {
        try {
            $ec = Get-Content -LiteralPath $EgressCfg -Raw | ConvertFrom-Json
            if ($ec.warp_scope) { $WarpScope = [string]$ec.warp_scope }
            if ($ec.mode) { $EgressMode = [string]$ec.mode }
        } catch {}
    }
    $DesiredOpMode = if ($WarpScope -eq "isolated" -or $EgressMode -in @("tor", "custom")) { "proxy" } else { "warp" }
    $DesiredProtocol = if ($DesiredOpMode -eq "proxy") { "masque" } else { "wireguard" }

    $settingsRaw = (Invoke-Warp @("-j", "settings") | Out-String)
    $protocol = ""
    $opMode = ""
    try {
        $settings = $settingsRaw | ConvertFrom-Json
        $protocol = [string]$settings.settings.warp_tunnel_protocol
        $opMode = [string]$settings.settings.operation_mode
    } catch {}

    # Proxy mode only accepts MASQUE; WireGuard there fails and leaves the
    # proxy port dead. The protocol must be set before switching the mode.
    if ($protocol -ne $DesiredProtocol) {
        # An unreadable mode is treated like proxy: dropping the tunnel is the
        # only way to be sure a serving proxy client accepts the change.
        if ($opMode -eq "proxy" -or [string]::IsNullOrEmpty($opMode)) {
            Invoke-Warp @("disconnect") | Out-Null
        }
        Say "switching WARP tunnel protocol to $DesiredProtocol..."
        Invoke-Warp @("tunnel", "protocol", "set", $DesiredProtocol) | Out-Null
    }

    if ($DesiredOpMode -eq "proxy") {
        Invoke-Warp @("proxy", "port", "40000") | Out-Null
    }
    if ($opMode -ne $DesiredOpMode) {
        Say "switching WARP operating mode to $DesiredOpMode..."
        Invoke-Warp @("mode", $DesiredOpMode) | Out-Null
    }

    $st = (Invoke-Warp @("status") | Select-Object -First 1 | Out-String)
    if ($st -match "Connected" -and $st -notmatch "Disconnected") {
        Ok "warp tunnel: already connected"
    } else {
        Invoke-Warp @("connect") | Out-Null
        $Connected = $false
        for ($i = 0; $i -lt 10; $i++) {
            Start-Sleep -Seconds 2
            $st = (Invoke-Warp @("status") | Select-Object -First 1 | Out-String)
            if ($st -match "Connected" -and $st -notmatch "Disconnected") {
                $Connected = $true
                break
            }
        }
        if ($Connected) {
            Ok "warp tunnel: connected"
        } else {
            Warn "warp tunnel still connecting - warp-keeper will keep retrying"
        }
    }
}

# ---------------------------------------------------------------- Background Tasks (Logon + Immediate)
function Register-BgTask([string]$TaskName, [string]$ScriptFile, [string]$Desc) {
    $ScriptPath = Join-Path $ScriptsDest $ScriptFile
    $Action = New-ScheduledTaskAction -Execute $PywExe -Argument "`"$ScriptPath`""
    $Trigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
    # A worker that is killed or exits mid-session must come back without a
    # logon or a dashboard click. The repetition starts it again every minute;
    # IgnoreNew makes that a no-op while the live process holds its mutex.
    $Watchdog = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 1) `
        -RepetitionDuration (New-TimeSpan -Days 3650)
    $Settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -MultipleInstances IgnoreNew

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger @($Trigger, $Watchdog) -Settings $Settings -Description $Desc -ErrorAction Stop | Out-Null
        Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        return $true
    } catch {
        Warn "ScheduledTask $TaskName registration failed ($_); falling back to Run key + direct spawn"
        $RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty -Path $RunKey -Name $TaskName -Value "`"$PywExe`" `"$ScriptPath`"" -ErrorAction SilentlyContinue
        Start-Process -FilePath $PywExe -ArgumentList "`"$ScriptPath`"" -WindowStyle Hidden
        return $false
    }
}

$tk1 = Register-BgTask -TaskName $TaskKeeper -ScriptFile "warp_keeper.py" -Desc "Opencode Unlimited - WARP keeper"
$tk2 = Register-BgTask -TaskName $TaskGuard  -ScriptFile "zen_guard.py"  -Desc "Opencode Unlimited - quota wall auto-rotator"
$tk3 = Register-BgTask -TaskName $TaskWatchdog -ScriptFile "ouc_watchdog.py" -Desc "Opencode Unlimited - restarts a dead keeper or guard"
if ($tk1 -and $tk2) {
    Ok "scheduled background tasks registered & started ($TaskKeeper, $TaskGuard)"
}

# ---------------------------------------------------------------- Wire OpenCode Desktop / background service
$ServiceProxyUrl = "http://127.0.0.1:41987"
$ProxyReady = $false
for ($i = 0; $i -lt 10; $i++) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect("127.0.0.1", 41987)
        $tcp.Close()
        $ProxyReady = $true
        break
    } catch {
        Start-Sleep -Milliseconds 500
    }
}
if ($ProxyReady) {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        # Merge proxy variables into service.json so the background service
        # keeps every other key (password, model, theme, etc.).
        $ServiceCfg = Join-Path $env:USERPROFILE ".config\opencode\service.json"
        $cfg = $null
        if (Test-Path $ServiceCfg) {
            try { $cfg = Get-Content -Raw -Path $ServiceCfg | ConvertFrom-Json } catch { $cfg = $null }
        }
        if (-not $cfg) { $cfg = [pscustomobject]@{} }
        if (-not $cfg.PSObject.Properties["env"]) {
            $cfg | Add-Member -NotePropertyName "env" -NotePropertyValue ([pscustomobject]@{})
        }
        $EnvValues = @(
            @("HTTPS_PROXY", $ServiceProxyUrl),
            @("HTTP_PROXY", $ServiceProxyUrl),
            @("https_proxy", $ServiceProxyUrl),
            @("http_proxy", $ServiceProxyUrl),
            @("NO_PROXY", "127.0.0.1,localhost,::1"),
            @("no_proxy", "127.0.0.1,localhost,::1")
        )
        foreach ($pair in $EnvValues) {
            $cfg.env | Add-Member -NotePropertyName $pair[0] -NotePropertyValue $pair[1] -Force
        }
        New-Item -ItemType Directory -Force -Path (Split-Path $ServiceCfg) | Out-Null
        [IO.File]::WriteAllText(
            $ServiceCfg,
            ($cfg | ConvertTo-Json -Depth 10),
            (New-Object System.Text.UTF8Encoding($false))
        )

        $svcStatus = (& $OcReal service status 2>&1 | Out-String)
        if ($svcStatus -match "http://127\.0\.0\.1") {
            & $OcReal service restart *> $null
        } else {
            & $OcReal service start *> $null
        }
        Ok "OpenCode Desktop & background service wired to WARP lane ($ServiceProxyUrl)"
    } catch {
        Warn "could not configure opencode background service: $_"
    } finally {
        $ErrorActionPreference = $prevEap
    }
} else {
    Warn "service proxy not yet listening on 127.0.0.1:41987 - CLI still works via per-launch zen-lane"
}

# ---------------------------------------------------------------- Run Doctor
& $PyExe (Join-Path $ScriptsDest "doctor.py")

Write-Host "  Open a NEW terminal window and run:  opencode"
Write-Host "  Manual rotate:  opencode-unlimited-hop    Health check:  opencode-unlimited-doctor"
Write-Host ""
