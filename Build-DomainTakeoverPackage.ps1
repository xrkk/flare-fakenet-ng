[CmdletBinding()]
param(
    [string]$SourceCommit = 'HEAD',
    [string]$OutputDirectory = ''
)

$ErrorActionPreference = 'Stop'
$packageName = 'Windows域名私网接管-一键启动包-2026.08.04'
$planRelative = 'PLAN\2026.08.03\2026.08.03-03-FakeNet-NG域名固定解析到指定IP并放行流量方案.md'
$fixedTimestamp = [DateTimeOffset]::new(
    [DateTime]::SpecifyKind([DateTime]'2000-01-01T00:00:00',
        [DateTimeKind]::Utc))

function Invoke-GitCaptured {
    param([string[]]$Arguments)
    $output = @(& git @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ('git failed: {0}' -f ($output -join [Environment]::NewLine))
    }
    return ($output -join [Environment]::NewLine).Trim()
}

function Get-NormalizedText {
    param([string]$Path)
    return (Get-Content -LiteralPath $Path -Raw).Replace("`r`n", "`n")
}

function Assert-TakeoverConfiguration {
    param([string]$BasePath, [string]$TakeoverPath)
    $base = Get-NormalizedText $BasePath
    $takeover = Get-NormalizedText $TakeoverPath
    foreach ($line in @(
            'ExternalTakeoverIPv4: 192.168.204.1',
            'ExternalTakeoverDnsTTL: 60',
            'ExternalTakeoverProbeTCPPorts:',
            'ExternalTakeoverProbeTimeoutMs: 500')) {
        if (($takeover.Split("`n") | Where-Object { $_ -eq $line }).Count -ne 1) {
            throw "Takeover INI must contain exactly one reviewed line: $line"
        }
        $takeover = $takeover.Replace($line + "`n", '')
    }
    $sinkResponse = 'ResponseA: 192.168.204.1'
    if (($takeover.Split("`n") | Where-Object { $_ -eq $sinkResponse }).Count -ne 2) {
        throw 'Takeover INI must contain exactly two sink ResponseA values.'
    }
    $takeover = $takeover.Replace($sinkResponse, 'ResponseA: GetFirstNonLoopback')
    if ($takeover -ne $base) {
        throw 'Takeover INI differs from the reviewed allow-list base outside the whitelist.'
    }
}

function Get-LockRows {
    param([string]$LockPath)
    $rows = @()
    foreach ($line in Get-Content -LiteralPath $LockPath) {
        if ($line -match '^\s*(?:#.*)?$') { continue }
        if ($line -notmatch '^([^= ]+)==([^ ]+) --hash=sha256:([0-9a-f]{64})$') {
            throw "Invalid lock line: $line"
        }
        $rows += [PSCustomObject]@{
            Name = $matches[1]
            Version = $matches[2]
            Hash = $matches[3]
        }
    }
    return $rows
}

function Assert-Wheelhouse {
    param([string]$Root)
    $lockPath = Join-Path $Root 'requirements-domain-takeover-windows.lock'
    $wheelPath = Join-Path $Root 'wheelhouse'
    $rows = @(Get-LockRows $lockPath)
    $wheels = @(Get-ChildItem -LiteralPath $wheelPath -Filter '*.whl')
    $nonWheels = @(Get-ChildItem -LiteralPath $wheelPath -File |
        Where-Object Extension -notin @('.whl', '.md'))
    if ($nonWheels.Count -ne 0 -or $rows.Count -ne $wheels.Count) {
        throw 'Wheelhouse contains an unexpected file or lock/wheel count mismatch.'
    }
    foreach ($row in $rows) {
        $prefix = ('{0}_{1}_' -f
            $row.Name.ToLowerInvariant().Replace('-', '_'), $row.Version)
        $match = @($wheels | Where-Object {
            $_.Name.ToLowerInvariant().Replace('-', '_').StartsWith($prefix)
        })
        if ($match.Count -ne 1) {
            throw "Lock entry does not map to exactly one wheel: $($row.Name)"
        }
        if ($match[0].Name -notmatch
                '(cp313-cp313-win_amd64|cp3\d+-abi3-win_amd64|py3-none-any|py2\.py3-none-any)\.whl$') {
            throw "Wheel tag is incompatible with reviewed CPython 3.13 x64: $($match[0].Name)"
        }
        $actual = (Get-FileHash -LiteralPath $match[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $row.Hash) {
            throw "Wheel hash mismatch: $($match[0].Name)"
        }
    }
    $critical = @{
        'pyasynchat' = @('1.0.5',
            '35b7859515693e479e8d95ebe9f32cbf4d6312ab7599ced39fc24699e51de46f')
        'pyasyncore' = @('1.0.5',
            '269bbc5252671827387636822841a1fb721ec6e858b23a3e12cf92eb1f97da2a')
        'netifaces-plus' = @('0.12.5',
            'ee3287ddbf73221cd4310a7a087f22e4c8c134c4d22bec9d4a65aa75f970eb8f')
        'pydivert' = @('2.1.0',
            '382db488e3c37c03ec9ec94e061a0b24334d78dbaeebb7d4e4d32ce4355d9da1')
    }
    foreach ($name in $critical.Keys) {
        $row = @($rows | Where-Object Name -eq $name)
        if ($row.Count -ne 1 -or $row[0].Version -ne $critical[$name][0] -or
                $row[0].Hash -ne $critical[$name][1]) {
            throw "Reviewed critical dependency mismatch: $name"
        }
    }
    return $rows
}

function Assert-PowerShellSyntax {
    param([string]$Path)
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -ne 0) {
        throw ('PowerShell syntax failure in {0}: {1}' -f
            $Path, (($errors | ForEach-Object Message) -join '; '))
    }
}

function Assert-PythonNativeArgumentSafety {
    param([string]$Path)
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) {
        throw "Cannot inspect Python native arguments in invalid script: $Path"
    }

    $commands = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
            @($node.CommandElements | Where-Object {
                $_.Extent.Text -eq '-c'
            }).Count -gt 0
    }, $true))
    foreach ($command in $commands) {
        $elements = @($command.CommandElements)
        $index = -1
        for ($i = 0; $i -lt $elements.Count; $i++) {
            if ($elements[$i].Extent.Text -eq '-c') {
                $index = $i
                break
            }
        }
        if ($index -lt 0 -or $index + 1 -ge $elements.Count) {
            throw "Malformed Python -c command in $Path"
        }
        $payload = $elements[$index + 1]
        if ($payload -is
                [System.Management.Automation.Language.VariableExpressionAst]) {
            throw ("Dynamic Python source must use stdin, not -c, in {0}: {1}" -f
                $Path, $command.Extent.Text)
        }
        if ($payload -isnot
                [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $payload -isnot
                [System.Management.Automation.Language.ExpandableStringExpressionAst]) {
            throw ("Unreviewable Python -c payload in {0}: {1}" -f
                $Path, $command.Extent.Text)
        }
        if ([string]$payload.Value -match '"') {
            throw ("Python -c payload contains a PowerShell 5.1-unsafe double quote in {0}: {1}" -f
                $Path, $command.Extent.Text)
        }
    }

    $text = Get-Content -LiteralPath $Path -Raw
    $requiredStdin = if ([IO.Path]::GetFileName($Path) -eq
            'Start-DomainTakeover.ps1') {
        @('identityCommand', 'dependencyCommand')
    } else {
        @('identityCommand', 'dependencyCommand', 'dnsParityCommand')
    }
    foreach ($name in $requiredStdin) {
        $pattern = ('\${0}\s*\|\s*&\s*\$[A-Za-z][A-Za-z0-9]*\s+-\s*' -f
            [regex]::Escape($name))
        if ($text -notmatch $pattern) {
            throw "Dynamic Python source is not transported through stdin in ${Path}: `${name}"
        }
    }
}

function New-DeterministicZip {
    param([string]$SourceRoot, [string]$Destination)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Force
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
                try {
                    $input.CopyTo($output)
                } finally {
                    $output.Dispose()
                    $input.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

$repoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$gitRootText = Invoke-GitCaptured @('-C', $repoRoot, 'rev-parse', '--show-toplevel')
$gitRoot = [IO.Path]::GetFullPath($gitRootText)
if ($gitRoot -ne $repoRoot) {
    throw 'Build script must run from the repository root.'
}
$resolvedCommit = Invoke-GitCaptured @(
    '-C', $repoRoot, 'rev-parse', ('{0}^{{commit}}' -f $SourceCommit))
if ($resolvedCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'SourceCommit did not resolve to one commit.'
}

$buildName = '.build-domain-takeover-{0}' -f [Guid]::NewGuid().ToString('N')
$buildRoot = Join-Path $repoRoot $buildName
$stage = Join-Path $buildRoot $packageName
$archivePath = Join-Path $buildRoot 'source.zip'
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $outputRoot = Join-Path $repoRoot 'dist'
} else {
    $outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
}
$zipPath = Join-Path $outputRoot ($packageName + '.zip')
$sidecarPath = $zipPath + '.sha256'

try {
    New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
    & git -C $repoRoot archive --format=zip --output=$archivePath $resolvedCommit
    if ($LASTEXITCODE -ne 0) { throw 'git archive failed.' }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Expand-Archive -LiteralPath $archivePath -DestinationPath $stage
    $archivedDist = Join-Path $stage 'dist'
    if (Test-Path -LiteralPath $archivedDist) {
        Remove-Item -LiteralPath $archivedDist -Recurse -Force
    }

    $required = @(
        'Start-DomainTakeover.cmd',
        'Start-DomainTakeover.ps1',
        'Build-DomainTakeoverPackage.ps1',
        'requirements-domain-takeover-windows.lock',
        'wheelhouse\SOURCES.md',
        'fakenet\configs\domain_allowlist_windows.ini',
        'fakenet\configs\domain_takeover_windows.ini',
        'test\domain_takeover_vm\Run-Tests.cmd',
        'test\domain_takeover_vm\Run-DomainTakeoverTests.ps1',
        'test\domain_takeover_vm\Test-LauncherContracts.ps1',
        $planRelative)
    foreach ($relative in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $stage $relative))) {
            throw "Required archived file is missing: $relative"
        }
    }

    $baseConfig = Join-Path $stage 'fakenet\configs\domain_allowlist_windows.ini'
    $takeoverConfig = Join-Path $stage 'fakenet\configs\domain_takeover_windows.ini'
    Assert-TakeoverConfiguration $baseConfig $takeoverConfig
    $dependencyRows = @(Assert-Wheelhouse $stage)
    Assert-PowerShellSyntax (Join-Path $stage 'Start-DomainTakeover.ps1')
    Assert-PowerShellSyntax (Join-Path $stage 'Build-DomainTakeoverPackage.ps1')
    Assert-PowerShellSyntax (
        Join-Path $stage 'test\domain_takeover_vm\Run-DomainTakeoverTests.ps1')
    Assert-PowerShellSyntax (
        Join-Path $stage 'test\domain_takeover_vm\Test-LauncherContracts.ps1')
    Assert-PythonNativeArgumentSafety (Join-Path $stage 'Start-DomainTakeover.ps1')
    Assert-PythonNativeArgumentSafety (
        Join-Path $stage 'test\domain_takeover_vm\Run-DomainTakeoverTests.ps1')

    $launcherPath = Join-Path $stage 'Start-DomainTakeover.ps1'
    $launcherText = Get-Content -LiteralPath $launcherPath -Raw
    foreach ($forbidden in @('8.8.8.8', '1.1.1.1', 'Invoke-WebRequest',
            'pip download', 'pip install -U')) {
        if ($launcherText -match [regex]::Escape($forbidden)) {
            throw "Launcher contains forbidden fallback/download marker: $forbidden"
        }
    }
    foreach ($requiredMarker in @('--no-index', '--require-hashes',
            'TAKEOVER_ROUTE_OK', 'TAKEOVER_PROBE_RESULT',
            'DNS restoration check')) {
        if ($launcherText -notmatch [regex]::Escape($requiredMarker)) {
            throw "Launcher is missing required marker: $requiredMarker"
        }
    }
    $runnerPath = Join-Path $stage `
        'test\domain_takeover_vm\Run-DomainTakeoverTests.ps1'
    $identityScripts = [ordered]@{
        Launcher = $launcherText
        Runner = Get-Content -LiteralPath $runnerPath -Raw
    }
    foreach ($identityScript in $identityScripts.GetEnumerator()) {
        if ($identityScript.Value -notmatch
                [regex]::Escape("json.dumps({'version':") -or
                $identityScript.Value -notmatch
                [regex]::Escape('python-identity.log') -or
                $identityScript.Value -notmatch
                '\$identityCommand\s*\|\s*&\s*\$[A-Za-z][A-Za-z0-9]*\s+-') {
            throw ("{0} is missing the stdin-safe Python identity contract." -f
                $identityScript.Key)
        }
        if ($identityScript.Value -match [regex]::Escape('json.dumps({"version"')) {
            throw ("{0} contains the PowerShell 5.1-unsafe Python identity payload." -f
                $identityScript.Key)
        }
    }

    $configPath = Join-Path $stage 'fakenet\configs\domain_takeover_windows.ini'
    $planPath = Join-Path $stage $planRelative
    $fileRows = @()
    foreach ($file in Get-ChildItem -LiteralPath $stage -File -Recurse |
            Sort-Object FullName) {
        $relative = $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
        if ($relative -eq 'domain-takeover-manifest.json') { continue }
        $fileRows += [ordered]@{
            path = $relative
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            size = [uint64]$file.Length
        }
    }
    $configHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $planHash = (Get-FileHash -LiteralPath $planPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = [ordered]@{
        schema_version = 1
        policy_version = 'v5'
        source_commit = $resolvedCommit
        allowed_domain = 'api.deepseek.com'
        takeover_ipv4 = '192.168.204.1'
        takeover_dns_ttl = 60
        windows_build = '10.0.19045'
        python_version = '3.13.7'
        python_architecture = 'AMD64'
        config_sha256 = $configHash
        plan_sha256 = $planHash
        dependencies = @($dependencyRows | Sort-Object Name | ForEach-Object {
            [ordered]@{ name=$_.Name; version=$_.Version; sha256=$_.Hash }
        })
        files = $fileRows
    }
    $manifestPath = Join-Path $stage 'domain-takeover-manifest.json'
    $manifest | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $manifestPath -Encoding UTF8

    New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
    New-DeterministicZip -SourceRoot $stage -Destination $zipPath
    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    ('{0}  {1}' -f $zipHash, [IO.Path]::GetFileName($zipPath)) |
        Set-Content -LiteralPath $sidecarPath -Encoding ASCII
    Write-Host "Package: $zipPath"
    Write-Host "SHA-256: $zipHash"
    Write-Host "Source commit: $resolvedCommit"
} finally {
    if (Test-Path -LiteralPath $buildRoot) {
        $resolvedBuild = [IO.Path]::GetFullPath($buildRoot)
        $expectedPrefix = $repoRoot + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedBuild.StartsWith(
                $expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
                [IO.Path]::GetFileName($resolvedBuild) -notlike
                    '.build-domain-takeover-*') {
            throw 'Refusing to remove an unexpected build path.'
        }
        Remove-Item -LiteralPath $resolvedBuild -Recurse -Force
    }
}
