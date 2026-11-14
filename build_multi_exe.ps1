<#
.SYNOPSIS
    Builds OpencodeUnlimited-Multi.exe v2.4.0 (standalone multi-egress Windows GUI executable).
    Supports Cloudflare WARP /64, Tor Network (SOCKS5), Custom Proxies, and Clean Endpoints.
    Keeps OpencodeUnlimited-Avatar.exe completely untouched!
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
if (-not $Root) {
    if ($MyInvocation.MyCommand.Path) {
        $Root = Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        $Root = (Get-Location).Path
    }
}
$SrcDir = Join-Path $Root "src"
if (-not (Test-Path (Join-Path $SrcDir "avatar_ui.py"))) {
    $SrcDir = Join-Path $Root "windows"
}
$SpecWork = Join-Path $env:TEMP "ouc-multi-build"
$DistDir = $Root

if (Test-Path $SpecWork) { Remove-Item $SpecWork -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $SpecWork | Out-Null

$PyInstaller = Get-Command pyinstaller.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
if (-not $PyInstaller) {
    throw "pyinstaller.exe not found in PATH."
}

# Dynamically locate webview, pythonnet, and clr_loader packages
$WebviewDir = ((& python -c "import webview, os; print(os.path.dirname(webview.__file__))") | Select-Object -Last 1).Trim()
$PythonnetDir = ((& python -c "import pythonnet, os; print(os.path.dirname(pythonnet.__file__))") | Select-Object -Last 1).Trim()
$ClrLoaderDir = ((& python -c "import clr_loader, os; print(os.path.dirname(clr_loader.__file__))") | Select-Object -Last 1).Trim()

$WvHooks = Join-Path $WebviewDir "__pyinstaller"
$PnHooks = Join-Path $PythonnetDir "_pyinstaller"

$Excludes = @(
    "torch", "torchvision", "ultralytics", "cv2", "numpy", "pandas", "scipy",
    "matplotlib", "scikit-learn", "sklearn", "sympy", "pyarrow", "polars",
    "streamlit", "selenium", "frida", "PIL", "yfinance", "sqlalchemy",
    "uvicorn", "starlette", "Flask", "altair", "plotly", "networkx",
    "webview.platforms.android", "webview.platforms.gtk", "webview.platforms.qt", "webview.platforms.cocoa"
)

$IconPath = Join-Path $SrcDir "assets\avatar.ico"
if (-not (Test-Path $IconPath)) {
    $IconPath = Join-Path $Root "windows\assets\avatar.ico"
}

$ArgsList = @(
    "--noconfirm",
    "--clean",
    "--onefile",
    "--windowed",
    "--name", "OpencodeUnlimited-Multi",
    "--icon", $IconPath,
    "--distpath", $DistDir,
    "--workpath", (Join-Path $SpecWork "work"),
    "--specpath", $SpecWork,
    "--paths", $SrcDir,
    "--collect-all", "webview",
    "--collect-all", "pythonnet",
    "--collect-all", "clr_loader",
    "--add-data", ((Join-Path $SrcDir "ui\index.html") + ";src\ui"),
    "--add-data", ((Join-Path $SrcDir "ui\index.html") + ";windows\ui"),
    "--add-data", ((Join-Path $SrcDir "ui\index.html") + ";ui"),
    "--add-data", ((Join-Path $SrcDir "assets\avatar.ico") + ";src\assets"),
    "--add-data", ((Join-Path $SrcDir "assets\avatar.ico") + ";windows\assets"),
    "--add-data", ((Join-Path $SrcDir "assets\avatar.ico") + ";assets"),
    "--add-data", ((Join-Path $SrcDir "*.py") + ";src"),
    "--add-data", ((Join-Path $SrcDir "*.py") + ";windows"),
    "--add-data", ((Join-Path $WebviewDir "lib") + ";webview\lib"),
    "--add-data", ((Join-Path $WebviewDir "js") + ";webview\js"),
    "--add-data", ((Join-Path $WebviewDir "lib\runtimes") + ";runtimes"),
    "--add-data", ((Join-Path $WebviewDir "lib\Microsoft.Web.WebView2.Core.dll") + ";."),
    "--add-data", ((Join-Path $WebviewDir "lib\Microsoft.Web.WebView2.WinForms.dll") + ";."),
    "--add-data", ((Join-Path $WebviewDir "lib\WebBrowserInterop.x64.dll") + ";."),
    "--add-data", ((Join-Path $WebviewDir "lib\runtimes\win-x64\native\WebView2Loader.dll") + ";."),
    "--hidden-import", "webview",
    "--hidden-import", "webview.platforms.winforms",
    "--hidden-import", "webview.platforms.edgechromium",
    "--hidden-import", "clr",
    "--hidden-import", "pythonnet",
    "--hidden-import", "clr_loader",
    "--hidden-import", "bottle",
    "--hidden-import", "psutil",
    "--hidden-import", "ouc_common",
    "--hidden-import", "ouc_firewall",
    "--hidden-import", "zen_proxy",
    "--hidden-import", "zen_lane",
    "--hidden-import", "warp_keeper",
    "--hidden-import", "zen_guard",
    "--hidden-import", "zen_hop",
    "--hidden-import", "doctor",
    "--hidden-import", "tor_manager",
    "--hidden-import", "proxy_chain",
    "--hidden-import", "clean_endpoint"
)

if (Test-Path $WvHooks) {
    $ArgsList += @("--additional-hooks-dir", $WvHooks)
}
if (Test-Path $PnHooks) {
    $ArgsList += @("--additional-hooks-dir", $PnHooks)
}

foreach ($ex in $Excludes) {
    $ArgsList += @("--exclude-module", $ex)
}
$ArgsList += (Join-Path $SrcDir "avatar_ui.py")

Write-Host "Building OpencodeUnlimited-Multi.exe..." -ForegroundColor Cyan
& $PyInstaller @ArgsList
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller exited with code $LASTEXITCODE"
}

$OutExe = Join-Path $DistDir "OpencodeUnlimited-Multi.exe"
if (-not (Test-Path $OutExe)) {
    throw "Expected output executable missing: $OutExe"
}

Remove-Item $SpecWork -Recurse -Force -ErrorAction SilentlyContinue
$SizeMB = [math]::Round((Get-Item $OutExe).Length / 1MB, 2)
Write-Host "Successfully built: $OutExe ($SizeMB MB)" -ForegroundColor Green
