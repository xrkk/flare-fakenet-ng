# Export only the stopped run's registered, complete artifacts. No network calls.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$VeloRepository,
    [Parameter(Mandatory=$true)][string]$PolicyPath,
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [Parameter(Mandatory=$true)][string]$ArtifactsRoot,
    [Parameter(Mandatory=$true)][string]$OverviewPath,
    [Parameter(Mandatory=$true)][string]$BatchId,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($BatchId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') { throw 'Invalid batch identity.' }
foreach ($path in @($VeloRepository,$PolicyPath,$OutputRoot,$ArtifactsRoot,$OverviewPath,$EvidenceDirectory)) {
    if (-not [IO.Path]::IsPathRooted($path)) { throw "Use explicit absolute paths: $path" }
}
$overview=Get-Content -LiteralPath $OverviewPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($overview.error -or $overview.consistent -isnot [bool] -or -not $overview.consistent -or $overview.partial -isnot [bool] -or $overview.partial -or
    $overview.service_status.state -cne 'stopped' -or $overview.service_status.health.process_alive -isnot [bool] -or $overview.service_status.health.process_alive -or
    $overview.artifacts_query.error -or $overview.artifacts_query.query.run_id -cne $overview.selected_run_id -or
    $overview.status_after_version -ne $overview.service_status.state_version) {
    throw 'A consistent, stopped FakeNet get_run_overview(run_id=...) is required.'
}
$run=[Guid]::Empty
if (-not [Guid]::TryParseExact($overview.selected_run_id,'D',[ref]$run) -or
    $run.ToString('D') -cne $overview.selected_run_id) { throw 'Invalid selected run identity.' }
$source=(Get-Item -LiteralPath $ArtifactsRoot).FullName.TrimEnd('\')
$anchor=$source+'\'+$overview.selected_run_id+'\'
$records=@(foreach($file in @($overview.artifacts_query.artifacts)) {
    # Unpublished rows are explicitly omitted, never relabeled complete.
    if ($file.complete -isnot [bool] -or -not $file.complete) { continue }
    $path=[IO.Path]::GetFullPath($file.path)
    if (-not $path.StartsWith($anchor,[StringComparison]::OrdinalIgnoreCase)) { throw 'Artifact is outside selected registered run.' }
    [ordered]@{path=$path; relative_path=$path.Substring($source.Length+1).Replace('\','/')
        size=$file.size; sha256=$file.sha256; complete=$true}
})
if ($records.Count -eq 0) { throw 'Selected run has no complete artifacts.' }
$null=New-Item -ItemType Directory -Path $EvidenceDirectory -Force
$manifestPath=Join-Path $EvidenceDirectory ($BatchId+'.export.json')
if (Test-Path -LiteralPath $manifestPath) { throw 'Export evidence exists; use a new batch identity.' }
$manifest=[ordered]@{schema='velo.artifact-export.v1'; producer='FakeNet-NG'; batch_id=$BatchId
    source_root=$source; producer_state='stopped'; run_id=$overview.selected_run_id
    producer_complete=$true; producer_quiescent=$true
    references=@(('FakeNet get_run_overview selected_run_id='+$overview.selected_run_id),
        ('state_version='+$overview.status_after_version),
        ('overview_sha256='+(Get-FileHash -LiteralPath $OverviewPath -Algorithm SHA256).Hash.ToLowerInvariant()))
    files=$records}
[IO.File]::WriteAllText($manifestPath,($manifest|ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
& (Join-Path $VeloRepository 'export_transfer_artifacts.ps1') -ManifestPath $manifestPath -PolicyPath $PolicyPath -OutputRoot $OutputRoot
