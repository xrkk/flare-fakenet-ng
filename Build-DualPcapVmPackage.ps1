[CmdletBinding()]
param(
    [string]$SourceCommit = 'HEAD',
    [string]$OutputDirectory = ''
)

$ErrorActionPreference = 'Stop'
$packageVersion = 'v1'
$packageName = "Windows双PCAP同步输出-$packageVersion"
$fixedTimestamp = [DateTimeOffset]::new(
    [DateTime]::SpecifyKind([DateTime]'2000-01-01T00:00:00',
        [DateTimeKind]::Utc))

function Invoke-GitCaptured {
    param([string[]]$Arguments)
    $output = @(& git @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ('git failed: ' + ($output -join [Environment]::NewLine))
    }
    return ($output -join [Environment]::NewLine).Trim()
}

function Assert-PowerShellSyntax {
    param([string]$Path)
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) {
        throw ('PowerShell syntax failure in {0}: {1}' -f $Path,
            (($errors | ForEach-Object Message) -join '; '))
    }
}

function New-DeterministicZip {
    param([string]$SourceRoot, [string]$Destination)
    Add-Type -AssemblyName System.IO.Compression
    if (Test-Path -LiteralPath $Destination) {
        throw ('Refusing to overwrite versioned package: ' + $Destination)
    }
    $stream = [IO.File]::Open(
        $Destination, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            $parent = Split-Path -Parent $SourceRoot
            foreach ($file in Get-ChildItem -LiteralPath $SourceRoot -File -Recurse |
                    Sort-Object FullName) {
                $relative = $file.FullName.Substring($parent.Length + 1).Replace('\', '/')
                $entry = $archive.CreateEntry(
                    $relative, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $fixedTimestamp
                $input = [IO.File]::OpenRead($file.FullName)
                $output = $entry.Open()
                try { $input.CopyTo($output) }
                finally { $output.Dispose(); $input.Dispose() }
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

$repoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$gitRoot = [IO.Path]::GetFullPath((Invoke-GitCaptured @(
    '-C', $repoRoot, 'rev-parse', '--show-toplevel')))
if ($gitRoot -ne $repoRoot) {
    throw 'Builder must run from the repository root.'
}
$resolvedCommit = Invoke-GitCaptured @(
    '-C', $repoRoot, 'rev-parse', ('{0}^{{commit}}' -f $SourceCommit))
if ($resolvedCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'SourceCommit did not resolve to one commit.'
}
$outputRoot = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    Join-Path $repoRoot 'dist'
} else {
    [IO.Path]::GetFullPath($OutputDirectory)
}
$zipPath = Join-Path $outputRoot ($packageName + '.zip')
if ($packageName -match '(?i)logs|日志') {
    throw 'Package name must not contain a log marker.'
}

$buildRoot = Join-Path $repoRoot (
    '.build-dual-pcap-' + [Guid]::NewGuid().ToString('N'))
$stage = Join-Path $buildRoot $packageName
$sourceArchive = Join-Path $buildRoot 'source.zip'
try {
    New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
    & git -C $repoRoot archive --format=zip --output=$sourceArchive $resolvedCommit
    if ($LASTEXITCODE -ne 0) { throw 'git archive failed.' }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Expand-Archive -LiteralPath $sourceArchive -DestinationPath $stage
    $archivedDist = Join-Path $stage 'dist'
    if (Test-Path -LiteralPath $archivedDist) {
        Remove-Item -LiteralPath $archivedDist -Recurse -Force
    }

    $required = @(
        'test\dual_pcap_vm\Run-Tests.cmd',
        'test\dual_pcap_vm\Run-DualPcapTests.ps1',
        'test\dual_pcap_vm\verify_dual_pcap.py',
        'test\dual_pcap_vm\fault_launcher.py',
        'test\dual_pcap_vm\README.md',
        'test\benchmark_dual_pcap.py',
        'test\test_dual_pcap_writer.py',
        'fakenet\diverters\pcapwriter.py',
        'requirements-domain-takeover-windows.lock',
        'PLAN\2026.08.05\2026.08.05-04-FakeNet-NG原始及以太网PCAP同步输出方案.md')
    foreach ($relative in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $stage $relative))) {
            throw ('Required package file is missing: ' + $relative)
        }
    }
    foreach ($script in Get-ChildItem -LiteralPath $stage -Filter '*.ps1' -Recurse) {
        Assert-PowerShellSyntax $script.FullName
    }
    $runnerText = Get-Content -LiteralPath (
        Join-Path $stage 'test\dual_pcap_vm\Run-DualPcapTests.ps1') -Raw
    foreach ($requiredMarker in @(
            'Test-IsVirtualMachine', '--no-index', '--require-hashes',
            'TreatControlCAsInput', 'raw-write', 'ethernet-write',
            'PerformanceGate', 'Test-NetworkRestored', 'Plain logs available')) {
        if (-not $runnerText.Contains($requiredMarker)) {
            throw ('VM runner contract is missing: ' + $requiredMarker)
        }
    }
    foreach ($forbidden in @(
            'Invoke-WebRequest', 'pip download', '8.8.8.8', '1.1.1.1',
            'Compress-Archive')) {
        if ($runnerText.Contains($forbidden)) {
            throw ('VM runner contains forbidden fallback: ' + $forbidden)
        }
    }

    $fileRows = @()
    foreach ($file in Get-ChildItem -LiteralPath $stage -File -Recurse |
            Sort-Object FullName) {
        $relative = $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
        if ($relative -eq 'dual-pcap-manifest.json') { continue }
        $fileRows += [ordered]@{
            path = $relative
            size = [uint64]$file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $manifest = [ordered]@{
        schema_version = 1
        package_version = $packageVersion
        plan_version = 'v2'
        source_commit = $resolvedCommit
        windows_build = '10.0.19045'
        python_version = '3.13.7'
        dpkt_version = '1.9.8'
        dump_outputs = @(
            '<prefix>_<timestamp>.pcap',
            '<prefix>_<timestamp>-converted.pcap')
        logs_plaintext = $true
        files = $fileRows
    }
    $manifestPath = Join-Path $stage 'dual-pcap-manifest.json'
    [IO.File]::WriteAllText(
        $manifestPath,
        (($manifest | ConvertTo-Json -Depth 6) + [Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))

    New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
    New-DeterministicZip $stage $zipPath
    Write-Host ('Package: ' + $zipPath)
    Write-Host ('Source commit: ' + $resolvedCommit)
    Write-Host 'No .sha256 sidecar was generated.'
} finally {
    if (Test-Path -LiteralPath $buildRoot) {
        $resolvedBuild = [IO.Path]::GetFullPath($buildRoot)
        $expectedPrefix = $repoRoot + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedBuild.StartsWith(
                $expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
                [IO.Path]::GetFileName($resolvedBuild) -notlike
                    '.build-dual-pcap-*') {
            throw 'Refusing to remove an unexpected build path.'
        }
        Remove-Item -LiteralPath $resolvedBuild -Recurse -Force
    }
}
