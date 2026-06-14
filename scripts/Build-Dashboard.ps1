#Requires -Version 5.1
<#
.SYNOPSIS
    Collect live system status and render a self-contained monitoring dashboard.
.DESCRIPTION
    Gathers, for each engine: image build state + size, engine version, syntax and
    functional pass/fail by invoking the existing validators, and the SIDs that
    fired in the last functional replay. Combines that with the rule inventory from
    metadata/rules-index.csv and writes:
        reports/status.json     - machine-readable snapshot
        dashboard/index.html    - self-contained UI (data inlined into dashboard/template.html)
    100% local: every engine call runs in a `--network none` container.
.PARAMETER NoValidate
    Skip re-running the validators; re-render the HTML from the existing status.json.
.PARAMETER Open
    Open the generated dashboard in the default browser when done.
.EXAMPLE
    .\scripts\Build-Dashboard.ps1
.EXAMPLE
    .\scripts\Build-Dashboard.ps1 -NoValidate -Open
#>
[CmdletBinding()]
param(
    [switch]$NoValidate,
    [switch]$Open
)

. "$PSScriptRoot\lib\Common.ps1"
$root         = Get-RepoRoot
$images       = Get-EngineImages
$reportsDir   = Join-Path $root 'reports'
$dashDir      = Join-Path $root 'dashboard'
$statusPath   = Join-Path $reportsDir 'status.json'
$templatePath = Join-Path $dashDir 'template.html'
$validate     = Join-Path $PSScriptRoot 'Validate-Syntax.ps1'
$functional   = Join-Path $PSScriptRoot 'Test-Functional.ps1'
$updateIndex  = Join-Path $PSScriptRoot 'Update-RuleIndex.ps1'
New-Item -ItemType Directory -Force $reportsDir | Out-Null
New-Item -ItemType Directory -Force $dashDir    | Out-Null

$engineMeta = @{
    snort    = @{ label = 'Snort 3';  key = 'Snort';    entry = 'snort';    ver = @('--version') }
    suricata = @{ label = 'Suricata'; key = 'Suricata'; entry = 'suricata'; ver = @('-V') }
    yara     = @{ label = 'YARA';     key = 'Yara';     entry = 'yara';     ver = @('--version') }
}

function Get-ImageMeta {
    param([string]$Image)
    $raw = & docker image inspect $Image --format '{{.Size}}' 2>$null
    if ($LASTEXITCODE -eq 0 -and $raw) {
        $bytes = [long]$raw
        $size  = if ($bytes -ge 1GB) { '{0:N2} GB' -f ($bytes / 1GB) } else { '{0:N0} MB' -f ($bytes / 1MB) }
        return @{ built = $true; size = $size }
    }
    return @{ built = $false; size = $null }
}

function Get-EngineVersion {
    param([string]$Engine, [string]$Image)
    $m = $engineMeta[$Engine]
    $r = Invoke-EngineContainer -Image $Image -Entrypoint $m.entry -Arguments $m.ver
    if ($r.Output -match '(\d+\.\d+(?:\.\d+){0,2})') { return $Matches[1] }
    return 'unknown'
}

function Get-FiredSids {
    param([string]$EngineDir)
    $sids = @()
    if (-not (Test-Path $EngineDir)) { return $sids }
    Get-ChildItem $EngineDir -Recurse -Include 'fast.log','alert_fast.txt' -File -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($line in Get-Content $_.FullName) {
            if ($line -match '\[\*\*\]\s*\[\d+:(\d+):\d+\]') { $sids += [int]$Matches[1] }
        }
    }
    return ($sids | Sort-Object -Unique)
}

# --------------------------------------------------------------------------
# 1. Status collection
# --------------------------------------------------------------------------
if ($NoValidate -and (Test-Path $statusPath)) {
    Write-Step "Reusing existing status.json (-NoValidate)"
    $status = Get-Content $statusPath -Raw | ConvertFrom-Json
} else {
    Test-DockerReady
    & $updateIndex | Out-Null

    $status = [ordered]@{
        generated_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        project       = 'detection-rules-lab'
        overall_ok    = $true
        engines       = [ordered]@{}
        support       = [ordered]@{}
        inventory     = [ordered]@{ total = 0; by_engine = [ordered]@{}; by_scope = [ordered]@{}; rules = @() }
        detections    = @()
    }

    foreach ($eng in @('snort','suricata','yara')) {
        $img  = $images[$engineMeta[$eng].key]
        $meta = Get-ImageMeta -Image $img
        $entry = [ordered]@{
            label = $engineMeta[$eng].label; image = $img; built = $meta.built; size = $meta.size
            version = 'n/a'; syntax_ok = $false; syntax_failures = $null
            functional_ok = $false; functional_failures = $null; fired_sids = @()
        }
        if (-not $meta.built) {
            Write-Warn "$($engineMeta[$eng].label): image not built - skipping checks."
            $status.overall_ok = $false
            $status.engines[$eng] = $entry
            continue
        }
        Write-Step "Collecting $($engineMeta[$eng].label) status..."
        $entry.version = Get-EngineVersion -Engine $eng -Image $img

        & $validate -Engine $eng | Out-Null
        $entry.syntax_failures = $LASTEXITCODE
        $entry.syntax_ok = ($LASTEXITCODE -eq 0)

        & $functional -Engine $eng | Out-Null
        $entry.functional_failures = $LASTEXITCODE
        $entry.functional_ok = ($LASTEXITCODE -eq 0)

        if ($eng -ne 'yara') { $entry.fired_sids = @(Get-FiredSids (Join-Path $reportsDir $eng)) }

        if (-not ($entry.syntax_ok -and $entry.functional_ok)) { $status.overall_ok = $false }
        $status.engines[$eng] = $entry
    }

    $pg = Get-ImageMeta -Image $images.PcapGen
    $status.support['pcapgen'] = [ordered]@{ label = 'PCAP Generator'; image = $images.PcapGen; built = $pg.built; size = $pg.size }
    if (-not $pg.built) { $status.overall_ok = $false }

    $indexCsv = Join-Path $root 'metadata\rules-index.csv'
    if (Test-Path $indexCsv) {
        $rows = @(Import-Csv $indexCsv)
        $status.inventory.total = $rows.Count
        foreach ($g in ($rows | Group-Object engine)) { $status.inventory.by_engine[$g.Name] = $g.Count }
        foreach ($g in ($rows | Group-Object scope))  { $status.inventory.by_scope[$g.Name]  = $g.Count }
        $status.inventory.rules = @($rows | ForEach-Object {
            [ordered]@{ engine = $_.engine; scope = $_.scope; id = $_.id; name = $_.name; classtype = $_.classtype }
        })
    }

    $det = @()
    foreach ($eng in @('snort','suricata')) {
        if ($status.engines[$eng] -and $status.engines[$eng].fired_sids) {
            foreach ($sid in $status.engines[$eng].fired_sids) {
                $name = ($status.inventory.rules | Where-Object { $_.engine -eq $eng -and "$($_.id)" -eq "$sid" } | Select-Object -First 1).name
                $det += [ordered]@{ engine = $eng; sid = $sid; name = $name }
            }
        }
    }
    $status.detections = @($det)

    $status | ConvertTo-Json -Depth 12 | Set-Content -Path $statusPath -Encoding UTF8
    Write-Pass "Wrote $statusPath"
}

# --------------------------------------------------------------------------
# 2. Render the self-contained dashboard from the template
# --------------------------------------------------------------------------
if (-not (Test-Path $templatePath)) { throw "Template not found: $templatePath" }
$json     = $status | ConvertTo-Json -Depth 12 -Compress
$template = [System.IO.File]::ReadAllText($templatePath)
$html     = $template.Replace('__DATA__', $json)
$outFile  = Join-Path $dashDir 'index.html'
[System.IO.File]::WriteAllText($outFile, $html, (New-Object System.Text.UTF8Encoding($false)))
Write-Pass "Dashboard written: $outFile"

if ($Open) { Invoke-Item $outFile }
