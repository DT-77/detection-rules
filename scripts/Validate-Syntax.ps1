#Requires -Version 5.1
<#
.SYNOPSIS
    Syntax / compilation validation for Snort 3, Suricata, and YARA rules.
.DESCRIPTION
    Each rule file is loaded by its engine in TEST mode inside a network-isolated
    container. A non-zero engine exit code (or compile error) fails the file.
        Snort 3 : snort -c snort.lua -R <file> -T            (config+rule dry run)
        Suricata: suricata -T -c suricata.yaml -S <file>     (engine test mode)
        YARA    : yarac <file> /tmp/out.yarc                 (compile check)
.PARAMETER Engine
    all | snort | suricata | yara   (default all). Ignored when -Files is used.
.PARAMETER Scope
    all | staging | production | disabled (default all). Ignored when -Files is used.
.PARAMETER Files
    Explicit repo-relative or absolute rule paths (e.g. from the pre-commit hook).
.OUTPUTS
    Exit code = number of files that FAILED validation (0 = all clean).
.EXAMPLE
    .\scripts\Validate-Syntax.ps1
.EXAMPLE
    .\scripts\Validate-Syntax.ps1 -Engine suricata -Scope staging
.EXAMPLE
    .\scripts\Validate-Syntax.ps1 -Files rules/yara/staging/selftest.yar
#>
[CmdletBinding()]
param(
    [ValidateSet('all','snort','suricata','yara')] [string]$Engine = 'all',
    [ValidateSet('all','staging','production','disabled')] [string]$Scope = 'all',
    [string[]]$Files
)

. "$PSScriptRoot\lib\Common.ps1"
Test-DockerReady

$root   = Get-RepoRoot
$images = Get-EngineImages
$failures = 0

# ---------------------------------------------------------------------------
# Per-engine validators. Each takes a FULL host path and returns $true (pass).
# ---------------------------------------------------------------------------
function Test-YaraFile {
    param([string]$FullPath)
    Assert-EngineImage -Image $images.Yara
    $dir  = Split-Path -Parent $FullPath
    $name = Split-Path -Leaf   $FullPath
    $r = Invoke-EngineContainer -Image $images.Yara -Entrypoint 'yarac' `
            -Mounts @{ $dir = '/rules:ro' } -Workdir '/rules' `
            -Arguments @($name, '/tmp/out.yarc')
    if ($r.ExitCode -ne 0) { Write-Fail "YARA compile FAILED: $name"; Write-Host $r.Output; return $false }
    Write-Pass "YARA OK: $name"
    return $true
}

function Test-SuricataFile {
    param([string]$FullPath)
    Assert-EngineImage -Image $images.Suricata
    $dir  = Split-Path -Parent $FullPath
    $name = Split-Path -Leaf   $FullPath
    $cfg  = Join-Path $root 'config\suricata'
    $r = Invoke-EngineContainer -Image $images.Suricata -Entrypoint 'suricata' `
            -Mounts @{ $dir = '/rules:ro'; $cfg = '/config:ro' } `
            -Arguments @('-T','-c','/config/suricata.yaml','-S',"/rules/$name",'-l','/tmp')
    # Suricata -T returns non-zero if any rule fails to load.
    if ($r.ExitCode -ne 0) { Write-Fail "Suricata FAILED: $name"; Write-Host $r.Output; return $false }
    # Defensive: surface load errors even if exit code was lenient.
    if ($r.Output -match '(?im)^\s*\S*\s*Error') { Write-Warn "Suricata reported errors in $name :"; Write-Host $r.Output }
    Write-Pass "Suricata OK: $name"
    return $true
}

function Test-SnortFile {
    param([string]$FullPath)
    Assert-EngineImage -Image $images.Snort
    $dir  = Split-Path -Parent $FullPath
    $name = Split-Path -Leaf   $FullPath
    $cfg  = Join-Path $root 'config\snort'
    # Workdir = shipped defaults dir so `include 'snort_defaults.lua'` resolves.
    $r = Invoke-EngineContainer -Image $images.Snort -Entrypoint 'snort' `
            -Mounts @{ $dir = '/rules:ro'; $cfg = '/config:ro' } `
            -Workdir '/home/snorty/snort3/etc/snort' `
            -Arguments @('-c','/config/snort.lua','-R',"/rules/$name",'-T')
    if ($r.ExitCode -ne 0) { Write-Fail "Snort FAILED: $name"; Write-Host $r.Output; return $false }
    Write-Pass "Snort OK: $name"
    return $true
}

# ---------------------------------------------------------------------------
# Build the work list
# ---------------------------------------------------------------------------
$work = @()   # array of @{ Engine; Path }

if ($Files) {
    foreach ($f in $Files) {
        $full = if ([System.IO.Path]::IsPathRooted($f)) { $f } else { Join-Path $root $f }
        if (-not (Test-Path $full)) { Write-Warn "Skipping missing file: $f"; continue }
        $eng = Resolve-EngineFromPath -Path $full
        # Fall back to an explicitly-supplied -Engine for out-of-tree files (e.g. fixtures).
        if ($eng -eq 'unknown' -and $Engine -ne 'all') { $eng = $Engine }
        if ($eng -eq 'unknown') { Write-Warn "Cannot determine engine for: $f (pass -Engine to force; skipping)"; continue }
        $work += @{ Engine = $eng; Path = (Resolve-Path $full).Path }
    }
} else {
    $engines = if ($Engine -eq 'all') { @('snort','suricata','yara') } else { @($Engine) }
    $scopes  = if ($Scope  -eq 'all') { @('staging','production','disabled') } else { @($Scope) }
    foreach ($e in $engines) {
        $ext = if ($e -eq 'yara') { @('*.yar','*.yara') } else { @('*.rules') }
        foreach ($s in $scopes) {
            $d = Join-Path $root "rules\$e\$s"
            if (-not (Test-Path $d)) { continue }
            foreach ($pattern in $ext) {
                Get-ChildItem -Path $d -Filter $pattern -File -ErrorAction SilentlyContinue | ForEach-Object {
                    $work += @{ Engine = $e; Path = $_.FullName }
                }
            }
        }
    }
}

if (-not $work) { Write-Warn "No rule files matched the selection. Nothing to validate."; exit 0 }

Write-Step ("Syntax-validating {0} rule file(s)..." -f $work.Count)
foreach ($item in $work) {
    $ok = switch ($item.Engine) {
        'yara'     { Test-YaraFile     -FullPath $item.Path }
        'suricata' { Test-SuricataFile -FullPath $item.Path }
        'snort'    { Test-SnortFile    -FullPath $item.Path }
        default    { Write-Warn "Unknown engine for $($item.Path)"; $true }
    }
    if (-not $ok) { $failures++ }
}

if ($failures -gt 0) { Write-Fail "$failures file(s) failed syntax validation." }
else                 { Write-Pass "All files passed syntax validation." }
exit $failures
