#Requires -Version 5.1
<#
.SYNOPSIS
    Wire the versioned .githooks/ directory into this repo's Git config.
.DESCRIPTION
    Uses core.hooksPath so hooks live under version control (no copying into
    .git/hooks). Initializes the repo if needed and marks the hook executable.
#>
[CmdletBinding()]
param()

. "$PSScriptRoot\lib\Common.ps1"
$root = Get-RepoRoot
Push-Location $root
try {
    if (-not (Test-Path (Join-Path $root '.git'))) {
        Write-Step "Initializing Git repository..."
        $init = Invoke-Git init
        if ($init.ExitCode -ne 0) { throw "git init failed: $($init.Output)" }
    }
    $cfg = Invoke-Git config core.hooksPath .githooks
    if ($cfg.ExitCode -ne 0) { throw "git config failed: $($cfg.Output)" }
    Write-Pass "core.hooksPath -> .githooks"

    # Best-effort exec bit (matters once the hook is committed / on WSL/Linux).
    Invoke-Git update-index --add --chmod=+x .githooks/pre-commit | Out-Null
    Invoke-Git update-index --add --chmod=+x .githooks/pre-push   | Out-Null

    Write-Pass "Git hooks installed. The pre-commit gate is now active."
} finally {
    Pop-Location
}
