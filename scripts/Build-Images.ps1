#Requires -Version 5.1
<#
.SYNOPSIS
    Build the four local validator images (Snort 3, Suricata, YARA, pcapgen).
.DESCRIPTION
    100% local: pulls the upstream BASE layers once, then bakes pinned local
    tags (drl/*:local). No image is used at run time except these.
.PARAMETER SkipSnort
    Skip the (large) Snort 3 image build.
.EXAMPLE
    .\scripts\Build-Images.ps1
.EXAMPLE
    .\scripts\Build-Images.ps1 -SkipSnort
#>
[CmdletBinding()]
param(
    [switch]$SkipSnort
)

. "$PSScriptRoot\lib\Common.ps1"
Test-DockerReady

$root   = Get-RepoRoot
$images = Get-EngineImages

function Build-One {
    param([string]$Tag, [string]$Context)
    Write-Step "Building $Tag  (context: $Context)"
    & docker build -t $Tag $Context
    if ($LASTEXITCODE -ne 0) { throw "Build FAILED for $Tag" }
    Write-Pass "Built $Tag"
}

Build-One -Tag $images.Yara    -Context (Join-Path $root 'docker\yara')
Build-One -Tag $images.PcapGen -Context (Join-Path $root 'docker\pcapgen')
Build-One -Tag $images.Suricata -Context (Join-Path $root 'docker\suricata')

if ($SkipSnort) {
    Write-Warn "Skipping Snort 3 image (-SkipSnort). Snort validation will be unavailable."
} else {
    Build-One -Tag $images.Snort -Context (Join-Path $root 'docker\snort')
}

Write-Pass "All requested images are ready. Verify with:  docker images drl/*"
