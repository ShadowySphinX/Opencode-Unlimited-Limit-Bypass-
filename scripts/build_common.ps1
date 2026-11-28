<#
.SYNOPSIS
    Shared helpers for building and publishing Opencode Unlimited executables.
#>

function New-OucVersionFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExeName,
        [string]$Description = "Opencode Unlimited",
        [string]$ProductName = "Opencode Unlimited",
        [string]$Company = "Avatar",
        [string]$Version = "4.0.2"
    )

    $parts = @($Version.Split(".") | ForEach-Object { [int]$_ })
    while ($parts.Count -lt 4) { $parts += 0 }
    $tuple = "(" + ($parts[0..3] -join ", ") + ")"
    $internal = [IO.Path]::GetFileNameWithoutExtension($ExeName)

    # PyInstaller reads this file with eval(), so it must be a VSVersionInfo
    # expression rather than .rc syntax.
    $lit = {
        param([string]$value)
        $value.Replace("\", "\\").Replace("'", "\'")
    }

    $content = @"
# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=$tuple,
    prodvers=$tuple,
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [StringStruct('CompanyName', '$(& $lit $Company)'),
         StringStruct('FileDescription', '$(& $lit $Description)'),
         StringStruct('FileVersion', '$(& $lit $Version)'),
         StringStruct('InternalName', '$(& $lit $internal)'),
         StringStruct('OriginalFilename', '$(& $lit $ExeName)'),
         StringStruct('ProductName', '$(& $lit $ProductName)'),
         StringStruct('ProductVersion', '$(& $lit $Version)')])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"@

    [IO.File]::WriteAllText(
        $Path,
        $content,
        (New-Object System.Text.UTF8Encoding($false))
    )
}

function Invoke-OucCodeSign {
    param([Parameter(Mandatory)][string]$Path)

    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty Source
    if (-not $signtool) {
        if ($env:OUC_SIGN_PFX -or $env:OUC_SIGN_THUMBPRINT) {
            Write-Warning "signtool.exe not found; skipping code signing."
        }
        return $false
    }

    if ($env:OUC_SIGN_PFX) {
        $signArgs = @("sign", "/fd", "SHA256", "/f", $env:OUC_SIGN_PFX)
        if ($env:OUC_SIGN_PASSWORD) {
            $signArgs += @("/p", $env:OUC_SIGN_PASSWORD)
        }
        $signArgs += @(
            "/tr", "http://timestamp.digicert.com", "/td", "SHA256", $Path
        )
    } elseif ($env:OUC_SIGN_THUMBPRINT) {
        $signArgs = @(
            "sign", "/fd", "SHA256",
            "/sha1", $env:OUC_SIGN_THUMBPRINT,
            "/tr", "http://timestamp.digicert.com",
            "/td", "SHA256",
            $Path
        )
    } else {
        Write-Host "Code signing skipped (set OUC_SIGN_PFX or OUC_SIGN_THUMBPRINT to sign)."
        return $false
    }

    & $signtool @signArgs
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed with exit code $LASTEXITCODE"
    }
    return $true
}

function Publish-OucExe {
    param(
        [Parameter(Mandatory)][string]$BuiltExe,
        [Parameter(Mandatory)][string]$TargetExe,
        [int]$Attempts = 60
    )

    if (-not (Test-Path $BuiltExe)) {
        throw "Built executable is missing: $BuiltExe"
    }

    $targetDir = Split-Path -Parent $TargetExe
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

    # Stage next to the target so the final swap stays on one volume.
    $staged = "$TargetExe.new"
    Copy-Item -Path $BuiltExe -Destination $staged -Force

    $lastError = ""
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            if (Test-Path $TargetExe) {
                # [NullString]::Value passes a real null backup path; a PowerShell
                # $null becomes "" and File.Replace rejects it as an illegal path.
                [IO.File]::Replace($staged, $TargetExe, [NullString]::Value)
            } else {
                [IO.File]::Move($staged, $TargetExe)
            }
            return
        } catch {
            $lastError = $_.Exception.Message
            if (-not (Test-Path $staged)) {
                throw "Publishing stopped because the staged executable disappeared. Build again."
            }
            if ($attempt -eq $Attempts) {
                Remove-Item $staged -Force -ErrorAction SilentlyContinue
                throw "Cannot replace ${TargetExe}: $lastError Close the running app and build again."
            }
            Start-Sleep -Milliseconds 750
        }
    }
}
