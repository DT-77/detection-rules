#Requires -Version 5.1
# =============================================================================
# Common.ps1 — shared helpers for the detection-rules-lab validation framework.
# Dot-source from sibling scripts:  . "$PSScriptRoot\lib\Common.ps1"
# =============================================================================

$ErrorActionPreference = 'Stop'

# Repo root = two levels up from scripts/lib/
$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

# ---------------------------------------------------------------------------
# Central image manifest. All four are LOCAL tags built by Build-Images.ps1,
# decoupling the framework from upstream tag drift.
# ---------------------------------------------------------------------------
$script:Images = @{
    Snort    = 'drl/snort3:local'
    Suricata = 'drl/suricata:local'
    Yara     = 'drl/yara:local'
    PcapGen  = 'drl/pcapgen:local'
}

function Get-RepoRoot    { return $script:RepoRoot }
function Get-EngineImages { return $script:Images }

# ---------------------------------------------------------------------------
# Console logging
# ---------------------------------------------------------------------------
function Write-Step { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Pass { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Fail { param([string]$Message) Write-Host "[x] $Message" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# Docker plumbing
# ---------------------------------------------------------------------------
function Test-DockerReady {
    $null = & docker info --format '{{.ServerVersion}}' 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker daemon is not reachable. Start Docker Desktop (Linux engine) and retry."
    }
}

function Test-DockerImage {
    param([Parameter(Mandatory)][string]$Image)
    $null = & docker image inspect $Image 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Assert-EngineImage {
    param([Parameter(Mandatory)][string]$Image)
    if (-not (Test-DockerImage -Image $Image)) {
        throw "Required image '$Image' is missing. Build it first:  .\scripts\Build-Images.ps1"
    }
}

# Run a short-lived, network-isolated container.
#   $Mounts is @{ '<windows-host-path>' = '<container-path[:ro]>' }
# Returns @{ ExitCode; Output }. stderr is merged into Output.
function Invoke-EngineContainer {
    param(
        [Parameter(Mandatory)][string]$Image,
        [string]$Entrypoint,
        [hashtable]$Mounts = @{},
        [string[]]$Arguments = @(),
        [string]$Network = 'none',
        [string]$Workdir
    )
    $dockerArgs = @('run', '--rm', '--network', $Network)
    if ($Entrypoint) { $dockerArgs += @('--entrypoint', $Entrypoint) }
    foreach ($src in $Mounts.Keys) {
        $dockerArgs += @('-v', ('{0}:{1}' -f $src, $Mounts[$src]))
    }
    if ($Workdir) { $dockerArgs += @('-w', $Workdir) }
    $dockerArgs += $Image
    $dockerArgs += $Arguments

    Write-Verbose ("docker " + ($dockerArgs -join ' '))

    # In Windows PowerShell 5.1, 2>&1 on a native command can throw under
    # ErrorActionPreference='Stop'. Drop to Continue around the call only.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $raw = & docker @dockerArgs 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
    # Render stderr ErrorRecords as plain text (their .ToString() is the raw
    # message) so callers/the demo don't see PowerShell's NativeCommandError
    # annotation block. Out-String would re-wrap them with source line noise.
    $text = if ($null -eq $raw) { '' } else { (@($raw) | ForEach-Object { $_.ToString() }) -join "`n" }
    return [pscustomobject]@{
        ExitCode = $code
        Output   = $text
    }
}

# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------
# Run git with the same EAP guard as Docker: in PowerShell 5.1 a native command
# emitting stderr under ErrorActionPreference='Stop' throws. Returns @{ExitCode;Output}.
function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$GitArgs)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out  = & git @GitArgs 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $prev }
    $text = if ($null -eq $out) { '' } else { (@($out) | ForEach-Object { $_.ToString() }) -join "`n" }
    return [pscustomobject]@{ ExitCode = $code; Output = $text.Trim() }
}

# Repo-relative paths of staged rule files (Added/Copied/Modified).
function Get-StagedRuleFiles {
    Push-Location $script:RepoRoot
    try {
        $r = Invoke-Git diff --cached --name-only --diff-filter=ACM
        if ($r.ExitCode -ne 0 -or -not $r.Output) { return @() }
        return @($r.Output -split "`r?`n" | Where-Object { $_ -match '^rules/.+\.(rules|yar|yara)$' })
    } finally { Pop-Location }
}

# Map a repo-relative or absolute rule path to its engine.
function Resolve-EngineFromPath {
    param([Parameter(Mandatory)][string]$Path)
    $p = $Path.Replace('\', '/').ToLower()
    if ($p -match '/rules/snort/')    { return 'snort' }
    if ($p -match '/rules/suricata/') { return 'suricata' }
    if ($p -match '/rules/yara/')     { return 'yara' }
    # Fall back on extension
    if ($p -match '\.(yar|yara)$')    { return 'yara' }
    if ($p -match '\.rules$')         { return 'unknown' }  # ambiguous (snort vs suricata)
    return 'unknown'
}

function New-CleanDir {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Path $Path) { Remove-Item -Recurse -Force $Path }
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    return (Resolve-Path $Path).Path
}
