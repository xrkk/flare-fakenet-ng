[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OriginalIPv4,
    [Parameter(Mandatory = $true)][string]$TargetIPv4,
    [Parameter(Mandatory = $true)][ValidateRange(1,65535)][int]$SentinelPort,
    [string]$SourceCommit = 'HEAD',
    [string]$OutputDirectory = ''
)

$ErrorActionPreference = 'Stop'
$packageVersion = 'v23'
$packageName = "Windows按进程透明重定向-$packageVersion"
$fixedTimestamp = [DateTimeOffset]::new(
    [DateTime]::SpecifyKind([DateTime]'2000-01-01T00:00:00',
        [DateTimeKind]::Utc))

function Invoke-GitCaptured([string[]]$Arguments) {
    $output = @(& git @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw ('git failed: ' + ($output -join [Environment]::NewLine))
    }
    return ($output -join [Environment]::NewLine).Trim()
}

function Assert-ReviewedAddresses {
    $original = $null
    $target = $null
    if (-not [Net.IPAddress]::TryParse($OriginalIPv4,[ref]$original) -or
            $original.AddressFamily -ne 'InterNetwork' -or
            $OriginalIPv4 -ne [string]$original) {
        throw 'OriginalIPv4 must be one canonical IPv4 address.'
    }
    if (-not [Net.IPAddress]::TryParse($TargetIPv4,[ref]$target) -or
            $target.AddressFamily -ne 'InterNetwork' -or
            $TargetIPv4 -ne [string]$target) {
        throw 'TargetIPv4 must be one canonical IPv4 address.'
    }
    $originalBytes = $original.GetAddressBytes()
    $targetBytes = $target.GetAddressBytes()
    $targetPrivate = ($targetBytes[0] -eq 10) -or
        ($targetBytes[0] -eq 172 -and $targetBytes[1] -ge 16 -and
            $targetBytes[1] -le 31) -or
        ($targetBytes[0] -eq 192 -and $targetBytes[1] -eq 168)
    $originalSpecial = ($originalBytes[0] -in @(0,10,127)) -or
        ($originalBytes[0] -eq 169 -and $originalBytes[1] -eq 254) -or
        ($originalBytes[0] -eq 172 -and $originalBytes[1] -ge 16 -and
            $originalBytes[1] -le 31) -or
        ($originalBytes[0] -eq 192 -and $originalBytes[1] -eq 168) -or
        ($originalBytes[0] -ge 224)
    if ($originalSpecial) { throw 'OriginalIPv4 is not reviewed public unicast.' }
    if (-not $targetPrivate) { throw 'TargetIPv4 is not RFC1918.' }
}

function Assert-PowerShellSyntax([string]$Path) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $Path,[ref]$tokens,[ref]$errors)
    if ($errors.Count) {
        throw ('PowerShell syntax failure in {0}: {1}' -f $Path,
            (($errors | ForEach-Object Message) -join '; '))
    }
}

function Import-VcEnvironment {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} `
        'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw 'Visual Studio vswhere.exe is required; no compiler is downloaded.'
    }
    $installation = (& $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath).Trim()
    if (-not $installation) { throw 'Reviewed MSVC x64 compiler was not found.' }
    $vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
    $command = '"' + $vcvars + '" >nul && set'
    $environment = & cmd.exe /d /c $command
    if ($LASTEXITCODE -ne 0) { throw 'vcvars64.bat failed.' }
    foreach ($line in $environment) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) {
            $name = $line.Substring(0,$separator)
            $value = $line.Substring($separator+1)
            if ($name -ieq 'Path') { $env:Path = $value }
            else {
                [Environment]::SetEnvironmentVariable(
                    $name,$value,'Process')
            }
        }
    }
    $toolset = Get-ChildItem -LiteralPath (Join-Path $installation `
        'VC\Tools\MSVC') -Directory | Sort-Object Name -Descending |
        Select-Object -First 1
    $compiler = if ($toolset) {
        Join-Path $toolset.FullName 'bin\Hostx64\x64\cl.exe'
    } else { $null }
    if (-not $compiler -or -not (Test-Path -LiteralPath $compiler)) {
        throw 'MSVC x64 cl.exe was not found after vcvars initialization.'
    }
    return [PSCustomObject]@{ Installation=$installation; Compiler=$compiler }
}

function New-Client([string]$Compiler,[string]$Source,[string]$Output,
                    [string]$Object,[switch]$Target) {
    $arguments = @('/nologo','/O2','/MT','/W4','/WX','/Brepro',
        '/D_CRT_SECURE_NO_WARNINGS',
        ('/Fo' + $Object),('/Fe' + $Output),$Source)
    if ($Target) { $arguments += '/DTARGET_CLIENT=1' }
    $arguments += @('/link','/INCREMENTAL:NO','/OPT:REF','/OPT:ICF',
        '/DYNAMICBASE','/NXCOMPAT','/SUBSYSTEM:CONSOLE')
    & $Compiler @arguments
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Output)) {
        throw ('Native client compilation failed: ' + $Output)
    }
}

function New-DeterministicZip([string]$SourceRoot,[string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression
    if (Test-Path -LiteralPath $Destination) {
        throw ('Refusing to overwrite versioned package: ' + $Destination)
    }
    $stream = [IO.File]::Open($Destination,[IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream,[IO.Compression.ZipArchiveMode]::Create,$false)
        try {
            $parent = Split-Path -Parent $SourceRoot
            foreach ($file in Get-ChildItem -LiteralPath $SourceRoot -File -Recurse |
                    Where-Object { $_.FullName -notmatch '[\\/]Logs[\\/]' } |
                    Sort-Object FullName) {
                $relative = $file.FullName.Substring($parent.Length+1).Replace('\','/')
                $entry = $archive.CreateEntry(
                    $relative,[IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $fixedTimestamp
                $input = [IO.File]::OpenRead($file.FullName)
                $output = $entry.Open()
                try { $input.CopyTo($output) }
                finally { $output.Dispose(); $input.Dispose() }
            }
        } finally { $archive.Dispose() }
    } finally { $stream.Dispose() }
}

function Get-ZipEntrySha256([string]$Archive,[string]$EntryName) {
    Add-Type -AssemblyName System.IO.Compression
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        $matches = @($zip.Entries | Where-Object FullName -CEQ $EntryName)
        if ($matches.Count -ne 1) {
            throw ('Expected exactly one wheel entry: ' + $EntryName)
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $stream = $matches[0].Open()
            try { $digest = $sha.ComputeHash($stream) }
            finally { $stream.Dispose() }
        } finally { $sha.Dispose() }
        return ([BitConverter]::ToString($digest)).Replace(
            '-','').ToLowerInvariant()
    } finally { $zip.Dispose() }
}

Assert-ReviewedAddresses
$repoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$resolvedCommit = Invoke-GitCaptured @(
    '-C',$repoRoot,'rev-parse',("{0}^{{commit}}" -f $SourceCommit))
$outputRoot = if ($OutputDirectory) {
    [IO.Path]::GetFullPath($OutputDirectory)
} else { Join-Path $repoRoot 'dist' }
$zipPath = Join-Path $outputRoot ($packageName + '.zip')
if ($packageName -match '(?i)logs|日志') { throw 'Package name contains a log marker.' }
$buildRoot = Join-Path $repoRoot (
    '.build-process-redirect-' + [Guid]::NewGuid().ToString('N'))
$stage = Join-Path $buildRoot $packageName
$archivePath = Join-Path $buildRoot 'source.zip'
try {
    New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null
    & git -C $repoRoot archive --format=zip --output=$archivePath $resolvedCommit
    if ($LASTEXITCODE -ne 0) { throw 'git archive failed.' }
    Expand-Archive -LiteralPath $archivePath -DestinationPath $stage
    $archivedDist = Join-Path $stage 'dist'
    if (Test-Path -LiteralPath $archivedDist) {
        Remove-Item -LiteralPath $archivedDist -Recurse -Force
    }
    $bin = Join-Path $stage 'test\process_redirect_vm\bin'
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
    $compiler = Import-VcEnvironment
    $source = Join-Path $stage `
        'test\process_redirect_vm\client\process_redirect_client.c'
    New-Client $compiler.Compiler $source `
        (Join-Path $bin 'reviewed-target-client.exe') `
        (Join-Path $buildRoot 'target.obj') -Target
    New-Client $compiler.Compiler $source `
        (Join-Path $bin 'non-target-client.exe') `
        (Join-Path $buildRoot 'non-target.obj')
    $targetHash = (Get-FileHash -LiteralPath (
        Join-Path $bin 'reviewed-target-client.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    $negativeHash = (Get-FileHash -LiteralPath (
        Join-Path $bin 'non-target-client.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($targetHash -eq $negativeHash) { throw 'Target and negative PE identities are not distinct.' }

    $runnerPath = Join-Path $stage `
        'test\process_redirect_vm\Run-ProcessRedirectTests.ps1'
    $runner = Get-Content -LiteralPath $runnerPath -Raw
    $runner = $runner.Replace('__REVIEWED_PUBLIC_IPV4_A__',$OriginalIPv4).
        Replace('__REVIEWED_PRIVATE_IPV4_B__',$TargetIPv4).
        Replace('__REVIEWED_SENTINEL_PORT__',[string]$SentinelPort).
        Replace('__PACKAGE_VERSION__',$packageVersion)
    $buildMarkers = @(
        '__REVIEWED_PUBLIC_IPV4_A__',
        '__REVIEWED_PRIVATE_IPV4_B__',
        '__REVIEWED_SENTINEL_PORT__',
        '__PACKAGE_VERSION__')
    foreach ($marker in $buildMarkers) {
        if ($runner.Contains($marker)) {
            throw ('Runner contains unresolved build marker: ' + $marker)
        }
    }
    [IO.File]::WriteAllText($runnerPath,$runner,[Text.UTF8Encoding]::new($false))
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\ManifestTools.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\Test-ManifestEncoding.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\RouteTargetTools.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\Test-RouteTargetEncoding.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\RouteResultTools.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\Test-RouteResultShape.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\ProcessExitTools.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\Test-ProcessExitTracking.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\NativeCommandTools.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\Test-NativeCommandCapture.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\FakeNetLaunchTools.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\Test-FakeNetModuleLaunch.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\WinDivertVersionTools.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\Test-WinDivertVersion.ps1')
    Assert-PowerShellSyntax (Join-Path $stage `
        'test\process_redirect_vm\LongTaskConsoleTools.ps1')
    $longTaskConsoleTest = Join-Path $stage `
        'test\process_redirect_vm\Test-LongTaskConsole.ps1'
    Assert-PowerShellSyntax $longTaskConsoleTest
    & powershell.exe -NoLogo -NoProfile -NonInteractive `
        -ExecutionPolicy Bypass -File $longTaskConsoleTest
    if ($LASTEXITCODE -ne 0) {
        throw 'Long-task console visibility regression failed.'
    }
    $forwardContractTest = Join-Path $stage `
        'test\process_redirect_vm\Test-RunnerForwardContracts.ps1'
    Assert-PowerShellSyntax $forwardContractTest
    & powershell.exe -NoLogo -NoProfile -NonInteractive `
        -ExecutionPolicy Bypass -File $forwardContractTest
    if ($LASTEXITCODE -ne 0) {
        throw 'Runner forward-path contract regression failed.'
    }
    $runtimeMarkerTest = Join-Path $stage `
        'test\process_redirect_vm\Test-RuntimeConfigMarkers.ps1'
    Assert-PowerShellSyntax $runtimeMarkerTest
    & powershell.exe -NoLogo -NoProfile -NonInteractive `
        -ExecutionPolicy Bypass -File $runtimeMarkerTest
    if ($LASTEXITCODE -ne 0) {
        throw 'Runtime config marker separation regression failed.'
    }
    Assert-PowerShellSyntax $runnerPath
    python -m py_compile (Join-Path $stage `
        'test\process_redirect_vm\verify_process_redirect.py')
    if ($LASTEXITCODE -ne 0) { throw 'Acceptance verifier syntax failed.' }
    Get-ChildItem -LiteralPath $stage -Filter '__pycache__' -Directory -Recurse |
        Remove-Item -Recurse -Force

    $rows = @()
    foreach ($file in Get-ChildItem -LiteralPath $stage -File -Recurse |
            Where-Object { $_.Name -ne 'process-redirect-manifest.json' -and
                           $_.FullName -notmatch '[\\/]Logs[\\/]' } |
            Sort-Object FullName) {
        $rows += [ordered]@{
            path=$file.FullName.Substring($stage.Length+1).Replace('\','/')
            size=[uint64]$file.Length
            sha256=(Get-FileHash -LiteralPath $file.FullName `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $pydivertWheel = Join-Path $stage `
        'wheelhouse\pydivert-2.1.0-py2.py3-none-any.whl'
    $winDivertDllHash = Get-ZipEntrySha256 $pydivertWheel `
        'pydivert/windivert_dll/WinDivert64.dll'
    $winDivertSysHash = Get-ZipEntrySha256 $pydivertWheel `
        'pydivert/windivert_dll/WinDivert64.sys'
    $manifest = [ordered]@{
        schema_version=1
        package_version=$packageVersion
        plan_version='v2'
        source_commit=$resolvedCommit
        windows_build='10.0.19045'
        python_version='3.13.7'
        pydivert_version='2.1.0'
        expected_windivert_version='1.3.0'
        expected_windivert_service='WinDivert1.3'
        expected_windivert_x64_dll_sha256=$winDivertDllHash
        expected_windivert_x64_sys_sha256=$winDivertSysHash
        compiler_path=$compiler.Compiler
        compiler_installation=$compiler.Installation
        original_ipv4=$OriginalIPv4
        target_ipv4=$TargetIPv4
        sentinel_port=$SentinelPort
        sentinel_protocol='FNPR/1'
        target_client_sha256=$targetHash
        non_target_client_sha256=$negativeHash
        logs_plaintext=$true
        files=$rows
    }
    [IO.File]::WriteAllText(
        (Join-Path $stage 'process-redirect-manifest.json'),
        (($manifest | ConvertTo-Json -Depth 6)+[Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))
    New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
    New-DeterministicZip $stage $zipPath
    Write-Host ('Package: ' + $zipPath)
    Write-Host ('Source commit: ' + $resolvedCommit)
    Write-Host 'No Logs directory and no .sha256 sidecar were generated.'
} finally {
    if (Test-Path -LiteralPath $buildRoot) {
        $resolved = [IO.Path]::GetFullPath($buildRoot)
        if (-not $resolved.StartsWith(
                $repoRoot+[IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase) -or
                [IO.Path]::GetFileName($resolved) -notlike
                    '.build-process-redirect-*') {
            throw 'Refusing to remove unexpected build path.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
