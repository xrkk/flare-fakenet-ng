[CmdletBinding()]
param(
    [string]$SourceCommit = 'HEAD',
    [string]$OutputDirectory = ''
)

$ErrorActionPreference = 'Stop'
$packageVersion = 'v1'
$packageName = "Linux双PCAP同步输出-$packageVersion"
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
                $relative = $file.FullName.Substring(
                    $parent.Length + 1).Replace('\', '/')
                $entry = $archive.CreateEntry(
                    $relative, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $fixedTimestamp
                if ($relative.EndsWith('.sh',
                        [StringComparison]::OrdinalIgnoreCase)) {
                    # 0100755 in the Unix high word; Linux unzip restores +x.
                    $entry.ExternalAttributes = -2115174400
                }
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
if ($gitRoot -ne $repoRoot) { throw 'Builder must run from repository root.' }
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
    '.build-dual-pcap-linux-' + [Guid]::NewGuid().ToString('N'))
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

    # git archive/Expand-Archive can apply the Windows checkout EOL policy.
    # Normalize shell entries before hashing and packaging so the executable
    # shebang remains valid when the ZIP is extracted on Linux.
    $utf8NoBom = [Text.UTF8Encoding]::new($false)
    foreach ($shellFile in Get-ChildItem -LiteralPath $stage -Filter '*.sh' `
            -File -Recurse) {
        $shellText = [IO.File]::ReadAllText($shellFile.FullName)
        $shellText = $shellText.Replace("`r`n", "`n").Replace("`r", "`n")
        [IO.File]::WriteAllText($shellFile.FullName, $shellText, $utf8NoBom)
    }

    $required = @(
        'test\dual_pcap_linux\Run-Tests.sh',
        'test\dual_pcap_linux\run_tests.py',
        'test\dual_pcap_linux\run_unit_tests.py',
        'test\dual_pcap_linux\fault_launcher.py',
        'test\dual_pcap_linux\verify_capture.py',
        'test\dual_pcap_linux\writer_contract.py',
        'test\dual_pcap_linux\README.md',
        'test\benchmark_dual_pcap.py',
        'test\test_linux_pcap_lifecycle.py',
        'test\test_dual_pcap_linux_acceptance.py',
        'fakenet\diverters\pcapwriter.py',
        'fakenet\diverters\linux.py',
        'PLAN\2026.08.05\2026.08.05-04-FakeNet-NG原始及以太网PCAP同步输出方案.md')
    foreach ($relative in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $stage $relative))) {
            throw ('Required package file is missing: ' + $relative)
        }
    }
    $runner = Get-Content -LiteralPath (
        Join-Path $stage 'test\dual_pcap_linux\run_tests.py') -Raw
    foreach ($marker in @(
            'systemd-detect-virt', 'iptables-save', 'ip6tables-save',
            'raw-write', 'ethernet-write', 'close', 'PerformanceGate',
            'PCAP_DUAL_CURRENT_PACKET_DROP', 'emergency_restore')) {
        if (-not $runner.Contains($marker)) {
            throw ('Linux runner contract is missing: ' + $marker)
        }
    }
    foreach ($forbidden in @(
            'pip install', 'apt install', 'Invoke-WebRequest',
            '8.8.8.8', '1.1.1.1', 'Compress-Archive')) {
        if ($runner.Contains($forbidden)) {
            throw ('Linux runner contains forbidden fallback: ' + $forbidden)
        }
    }

    $fileRows = @()
    foreach ($file in Get-ChildItem -LiteralPath $stage -File -Recurse |
            Sort-Object FullName) {
        $relative = $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
        if ($relative -eq 'dual-pcap-linux-manifest.json') { continue }
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
        plan_version = 'v4'
        source_commit = $resolvedCommit
        linux_baseline = 'Ubuntu 24.04.2 LTS'
        python_minimum = '3.10'
        dpkt_version = '1.9.8'
        dlt_raw = 12
        live_coverage = 'Linux NFQUEUE IPv4 original and mangled packet'
        ipv6_coverage = 'Linux file-level writer contract'
        logs_plaintext = $true
        files = $fileRows
    }
    $manifestPath = Join-Path $stage 'dual-pcap-linux-manifest.json'
    [IO.File]::WriteAllText(
        $manifestPath,
        (($manifest | ConvertTo-Json -Depth 6) + [Environment]::NewLine),
        $utf8NoBom)

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
                    '.build-dual-pcap-linux-*') {
            throw 'Refusing to remove an unexpected build path.'
        }
        Remove-Item -LiteralPath $resolvedBuild -Recurse -Force
    }
}
