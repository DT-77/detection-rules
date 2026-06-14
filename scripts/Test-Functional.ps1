#Requires -Version 5.1
<#
.SYNOPSIS
    Functional verification: prove rules actually FIRE on target telemetry.
.DESCRIPTION
    Network engines: replay synthetic PCAP(s) and confirm the required SIDs alert.
        Suricata: suricata -c suricata.yaml -S <rules> -r <pcap> -l <out> --runmode single -k none
        Snort 3 : snort -c snort.lua -R <rules> -r <pcap> -A alert_fast -l <out>
    YARA: scan benign true-positive samples and confirm matches (and no FPs on
    the negative-control sample).
    Expectations come from tests/expected/expected.json.
.PARAMETER Engine
    all | snort | suricata | yara  (default all).
.PARAMETER Scope
    Which rule directories to load: production+staging by default.
.OUTPUTS
    Exit code = number of failed expectations (0 = all green).
#>
[CmdletBinding()]
param(
    [ValidateSet('all','snort','suricata','yara')] [string]$Engine = 'all',
    [string[]]$Scope = @('production','staging')
)

. "$PSScriptRoot\lib\Common.ps1"
Test-DockerReady

$root      = Get-RepoRoot
$images    = Get-EngineImages
$reports   = Join-Path $root 'reports'
$expected  = Get-Content (Join-Path $root 'tests\expected\expected.json') -Raw | ConvertFrom-Json
$failures  = 0
$engines   = if ($Engine -eq 'all') { @('snort','suricata','yara') } else { @($Engine) }

# --- helper: concatenate all rules of an engine/scope into one temp file -----
function Get-CombinedRuleFile {
    param([string]$Eng, [string]$Ext)
    $tmpDir = New-CleanDir (Join-Path $reports "tmp\$Eng")
    $out    = Join-Path $tmpDir "combined$Ext"
    $files  = foreach ($s in $Scope) {
        $d = Join-Path $root "rules\$Eng\$s"
        if (Test-Path $d) { Get-ChildItem $d -Filter "*$Ext" -File -ErrorAction SilentlyContinue }
    }
    if (-not $files) { return $null }
    $content = foreach ($f in $files) { Get-Content $f.FullName -Raw }
    # Force LF + ASCII so the container parser is happy.
    [System.IO.File]::WriteAllText($out, ($content -join "`n") + "`n", (New-Object System.Text.ASCIIEncoding))
    return $out
}

# --- helper: extract SIDs from a fast-log style alert file ------------------
function Get-AlertedSids {
    param([string]$LogFile)
    if (-not (Test-Path $LogFile)) { return @() }
    $sids = @()
    foreach ($line in Get-Content $LogFile) {
        if ($line -match '\[\*\*\]\s*\[\d+:(\d+):\d+\]') { $sids += [int]$Matches[1] }
    }
    return ($sids | Sort-Object -Unique)
}

# ===========================================================================
# SURICATA
# ===========================================================================
function Invoke-SuricataFunctional {
    Assert-EngineImage -Image $images.Suricata
    $rules = Get-CombinedRuleFile -Eng 'suricata' -Ext '.rules'
    if (-not $rules) { Write-Warn "No Suricata rules in scope; skipping."; return 0 }
    $rulesDir = Split-Path -Parent $rules
    $pcapDir  = Join-Path $root 'tests\pcaps'
    $cfg      = Join-Path $root 'config\suricata'
    $fail = 0
    foreach ($case in $expected.suricata) {
        $out = New-CleanDir (Join-Path $reports "suricata\$($case.pcap)")
        Write-Step "Suricata replay: $($case.pcap)"
        $r = Invoke-EngineContainer -Image $images.Suricata -Entrypoint 'suricata' `
                -Mounts @{ $rulesDir='/rules:ro'; $pcapDir='/pcaps:ro'; $cfg='/config:ro'; $out='/out' } `
                -Arguments @('-c','/config/suricata.yaml','-S','/rules/combined.rules',
                             '-r',"/pcaps/$($case.pcap)",'-l','/out','--runmode','single','-k','none')
        if ($r.ExitCode -ne 0) { Write-Fail "Suricata run errored on $($case.pcap)"; Write-Host $r.Output; $fail++; continue }
        $sids = Get-AlertedSids (Join-Path $out 'fast.log')
        foreach ($need in $case.required_sids) {
            if ($sids -contains [int]$need) { Write-Pass "  required SID $need fired" }
            else { Write-Fail "  required SID $need DID NOT fire (saw: $($sids -join ', '))"; $fail++ }
        }
        foreach ($bonus in $case.bonus_sids) {
            if ($sids -contains [int]$bonus) { Write-Pass "  bonus SID $bonus fired" }
            else { Write-Warn "  bonus SID $bonus did not fire (non-fatal)" }
        }
    }
    return $fail
}

# ===========================================================================
# SNORT 3
# ===========================================================================
function Invoke-SnortFunctional {
    Assert-EngineImage -Image $images.Snort
    $rules = Get-CombinedRuleFile -Eng 'snort' -Ext '.rules'
    if (-not $rules) { Write-Warn "No Snort rules in scope; skipping."; return 0 }
    $rulesDir = Split-Path -Parent $rules
    $pcapDir  = Join-Path $root 'tests\pcaps'
    $cfg      = Join-Path $root 'config\snort'
    $fail = 0
    foreach ($case in $expected.snort) {
        $out = New-CleanDir (Join-Path $reports "snort\$($case.pcap)")
        Write-Step "Snort replay: $($case.pcap)"
        $r = Invoke-EngineContainer -Image $images.Snort -Entrypoint 'snort' `
                -Mounts @{ $rulesDir='/rules:ro'; $pcapDir='/pcaps:ro'; $cfg='/config:ro'; $out='/out' } `
                -Workdir '/home/snorty/snort3/etc/snort' `
                -Arguments @('-c','/config/snort.lua','-R','/rules/combined.rules',
                             '-r',"/pcaps/$($case.pcap)",'-A','alert_fast','-l','/out','-q')
        if ($r.ExitCode -ne 0) { Write-Fail "Snort run errored on $($case.pcap)"; Write-Host $r.Output; $fail++; continue }
        $sids = Get-AlertedSids (Join-Path $out 'alert_fast.txt')
        foreach ($need in $case.required_sids) {
            if ($sids -contains [int]$need) { Write-Pass "  required SID $need fired" }
            else { Write-Fail "  required SID $need DID NOT fire (saw: $($sids -join ', '))"; $fail++ }
        }
        foreach ($bonus in $case.bonus_sids) {
            if ($sids -contains [int]$bonus) { Write-Pass "  bonus SID $bonus fired" }
            else { Write-Warn "  bonus SID $bonus did not fire (non-fatal)" }
        }
    }
    return $fail
}

# ===========================================================================
# YARA
# ===========================================================================
function Invoke-YaraFunctional {
    Assert-EngineImage -Image $images.Yara
    $rules = Get-CombinedRuleFile -Eng 'yara' -Ext '.yar'
    if (-not $rules) { Write-Warn "No YARA rules in scope; skipping."; return 0 }
    $rulesDir   = Split-Path -Parent $rules
    $samplesDir = Join-Path $root 'tests\samples\yara'
    $fail = 0
    Write-Step "YARA scan of $samplesDir"
    # -r recurses; output line format: "RULENAME /samples/<file>"
    $r = Invoke-EngineContainer -Image $images.Yara -Entrypoint 'yara' `
            -Mounts @{ $rulesDir='/rules:ro'; $samplesDir='/samples:ro' } `
            -Arguments @('-r','/rules/combined.yar','/samples')
    if ($r.ExitCode -ne 0) { Write-Fail "YARA scan errored"; Write-Host $r.Output; return 1 }
    $lines = $r.Output -split "`r?`n"
    foreach ($case in $expected.yara) {
        foreach ($mustFile in $case.must_match) {
            $hit = $lines | Where-Object { $_ -match [regex]::Escape($case.rule) -and $_ -match [regex]::Escape($mustFile) }
            if ($hit) { Write-Pass "  $($case.rule) matched $mustFile" }
            else { Write-Fail "  $($case.rule) DID NOT match $mustFile"; $fail++ }
        }
        foreach ($noFile in $case.must_not_match) {
            $hit = $lines | Where-Object { $_ -match [regex]::Escape($case.rule) -and $_ -match [regex]::Escape($noFile) }
            if ($hit) { Write-Fail "  FALSE POSITIVE: $($case.rule) matched $noFile"; $fail++ }
            else { Write-Pass "  $($case.rule) correctly ignored $noFile" }
        }
    }
    return $fail
}

# ===========================================================================
# Ensure synthetic PCAPs exist (generate offline if needed)
# ===========================================================================
function Confirm-Pcaps {
    $pcapDir = Join-Path $root 'tests\pcaps'
    $needGen = $false
    foreach ($case in @($expected.suricata + $expected.snort)) {
        if ($case -and -not (Test-Path (Join-Path $pcapDir $case.pcap))) { $needGen = $true }
    }
    if (-not $needGen) { return }
    Assert-EngineImage -Image $images.PcapGen
    Write-Step "Generating synthetic PCAP(s) offline via Scapy..."
    $genDir = Join-Path $root 'tests\generators'
    $r = Invoke-EngineContainer -Image $images.PcapGen -Entrypoint 'python' `
            -Mounts @{ $genDir='/gen:ro'; $pcapDir='/out' } -Arguments @('/gen/gen_pcaps.py')
    if ($r.ExitCode -ne 0) { throw "PCAP generation failed:`n$($r.Output)" }
    Write-Host $r.Output
}

# ===========================================================================
# Main
# ===========================================================================
if ($engines -contains 'snort' -or $engines -contains 'suricata') { Confirm-Pcaps }

if ($engines -contains 'suricata') { $failures += Invoke-SuricataFunctional }
if ($engines -contains 'snort')    { $failures += Invoke-SnortFunctional }
if ($engines -contains 'yara')     { $failures += Invoke-YaraFunctional }

if ($failures -gt 0) { Write-Fail "$failures functional expectation(s) failed." }
else                 { Write-Pass "All functional expectations met." }
exit $failures
