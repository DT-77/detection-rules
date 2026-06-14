#Requires -Version 5.1
<#
.SYNOPSIS
    (Re)generate metadata/rules-index.csv — a flat catalog of every rule.
.DESCRIPTION
    Parses Snort/Suricata .rules (msg, sid, rev, classtype, metadata) and YARA
    .yar (rule name + meta{}) across all scopes and writes a single CSV so the
    repository is self-documenting and greppable. No engine/container needed.
.OUTPUTS
    metadata/rules-index.csv
#>
[CmdletBinding()]
param()

. "$PSScriptRoot\lib\Common.ps1"
$root = Get-RepoRoot
$rows = New-Object System.Collections.Generic.List[object]

function Add-Row {
    param($Engine,$Scope,$File,$Id,$Name,$Class,$Extra)
    $rows.Add([pscustomobject]@{
        engine   = $Engine
        scope    = $Scope
        file     = $File
        id       = $Id
        name     = $Name
        classtype= $Class
        metadata = $Extra
    })
}

# --- Snort / Suricata ------------------------------------------------------
foreach ($eng in @('snort','suricata')) {
    foreach ($scope in @('staging','production','disabled')) {
        $dir = Join-Path $root "rules\$eng\$scope"
        if (-not (Test-Path $dir)) { continue }
        Get-ChildItem $dir -Filter *.rules -File -ErrorAction SilentlyContinue | ForEach-Object {
            $rel = $_.FullName.Substring($root.Length + 1).Replace('\','/')
            foreach ($line in Get-Content $_.FullName) {
                $t = $line.Trim()
                if ($t -eq '' -or $t.StartsWith('#')) { continue }
                if ($t -notmatch '\bsid\s*:\s*(\d+)') { continue }
                $sid   = $Matches[1]
                $msg   = if ($t -match 'msg\s*:\s*"([^"]*)"')       { $Matches[1] } else { '' }
                $class = if ($t -match 'classtype\s*:\s*([^;]+)')    { $Matches[1].Trim() } else { '' }
                $meta  = if ($t -match 'metadata\s*:\s*([^;]+)')     { $Matches[1].Trim() } else { '' }
                Add-Row -Engine $eng -Scope $scope -File $rel -Id $sid -Name $msg -Class $class -Extra $meta
            }
        }
    }
}

# --- YARA ------------------------------------------------------------------
foreach ($scope in @('staging','production','disabled')) {
    $dir = Join-Path $root "rules\yara\$scope"
    if (-not (Test-Path $dir)) { continue }
    Get-ChildItem $dir -Include *.yar,*.yara -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $rel  = $_.FullName.Substring($root.Length + 1).Replace('\','/')
        $text = Get-Content $_.FullName -Raw
        $ruleMatches = [regex]::Matches($text, '(?ms)^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_]\w*).*?\{(.*?)\bcondition\b')
        foreach ($m in $ruleMatches) {
            $rname = $m.Groups[1].Value
            $body  = $m.Groups[2].Value
            $desc  = if ($body -match 'description\s*=\s*"([^"]*)"') { $Matches[1] } else { '' }
            $sev   = if ($body -match 'severity\s*=\s*"([^"]*)"')    { $Matches[1] } else { '' }
            $auth  = if ($body -match 'author\s*=\s*"([^"]*)"')      { $Matches[1] } else { '' }
            Add-Row -Engine 'yara' -Scope $scope -File $rel -Id $rname -Name $desc -Class $sev -Extra "author=$auth"
        }
    }
}

$outFile = Join-Path $root 'metadata\rules-index.csv'
$rows | Sort-Object engine,scope,file,id | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
Write-Pass ("Wrote {0} rule(s) to metadata/rules-index.csv" -f $rows.Count)
