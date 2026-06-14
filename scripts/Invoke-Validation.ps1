#Requires -Version 5.1
<#
.SYNOPSIS
    Master orchestrator: syntax (+ optional functional) validation and indexing.
.DESCRIPTION
    Default run (no switches): full syntax validation of all rules + index refresh.
    -PreCommit : validate ONLY staged rule files, refresh + re-stage the index,
                 and exit non-zero to BLOCK the commit on any failure (fast path:
                 syntax for changed rules + full YARA functional, which is cheap).
                 Network functional replay is left to -Functional / pre-push.
    -Functional: also run PCAP replay + YARA sample matching.
    -Full      : syntax + functional for everything.
.EXAMPLE
    .\scripts\Invoke-Validation.ps1                 # syntax all + index
.EXAMPLE
    .\scripts\Invoke-Validation.ps1 -Full           # syntax + functional
.EXAMPLE
    .\scripts\Invoke-Validation.ps1 -PreCommit      # used by the git hook
#>
[CmdletBinding()]
param(
    [switch]$PreCommit,
    [switch]$Functional,
    [switch]$Full,
    [ValidateSet('all','snort','suricata','yara')] [string]$Engine = 'all'
)

. "$PSScriptRoot\lib\Common.ps1"

$root      = Get-RepoRoot
$total     = 0
$ValidateSyntax = Join-Path $PSScriptRoot 'Validate-Syntax.ps1'
$TestFunctional = Join-Path $PSScriptRoot 'Test-Functional.ps1'
$UpdateIndex    = Join-Path $PSScriptRoot 'Update-RuleIndex.ps1'

if ($PreCommit) {
    Write-Step "detection-rules-lab pre-commit gate"
    $staged = Get-StagedRuleFiles
    if (-not $staged) {
        Write-Pass "No staged rule changes detected. Pass."
    } else {
        Write-Step ("Staged rule files: {0}" -f ($staged -join ', '))
        & $ValidateSyntax -Files $staged
        $total += $LASTEXITCODE

        # YARA functional is cheap (no PCAP) — run it if any YARA rule changed.
        if ($staged | Where-Object { $_ -match '\.(yar|yara)$' }) {
            & $TestFunctional -Engine yara
            $total += $LASTEXITCODE
        }
    }

    # Keep the catalog in lockstep with the rules and re-stage it.
    & $UpdateIndex | Out-Null
    Push-Location $root
    try { Invoke-Git add metadata/rules-index.csv | Out-Null } finally { Pop-Location }

    if ($total -gt 0) { Write-Fail "Commit BLOCKED: $total validation failure(s)."; exit 1 }
    Write-Pass "Pre-commit validation passed."
    exit 0
}

# -------- non-hook (manual / CI-local) flow --------------------------------
& $ValidateSyntax -Engine $Engine
$total += $LASTEXITCODE

if ($Functional -or $Full) {
    & $TestFunctional -Engine $Engine
    $total += $LASTEXITCODE
}

& $UpdateIndex | Out-Null

if ($total -gt 0) { Write-Fail "$total total failure(s)."; exit 1 }
Write-Pass "All validation passed."
exit 0
