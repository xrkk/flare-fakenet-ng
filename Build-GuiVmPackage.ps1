[CmdletBinding()]
param(
    [string]$SourceCommit = 'HEAD',
    [string]$OutputDirectory = ''
)

# One-click GUI VM acceptance package (plan 2026.08.14 §12.5).
#
# Layout inside the versioned ZIP:
#   <pkg>\fakenet.exe            - built from the staged source (A6-A8)
#   <pkg>\fakenet-GUI.exe     - built from the staged source (A9)
#   <pkg>\configs|defaultFiles|listeners\ssl_utils
#                               - flattened release layout beside the exes
#                                 (mirrors build.yaml) so double-clicking
#                                 fakenet.exe finds configs\default.ini and
#                                 the frozen GUI template menu is populated
#   <pkg>\test\gui_vm\...        - Run-Tests.cmd one-click acceptance
#   <pkg>\<full source tree>     - transparency + python fallback
#
# House style: deterministic ZIP (fixed 2000-01-01 timestamps), refuse
# overwrite of a versioned package, plaintext manifest with per-file
# SHA-256, no Logs directory, no .sha256 sidecar.

$ErrorActionPreference = 'Stop'
$packageVersion = 'v31'
$packageName = "Windows-GUI配置工具-VM验收-$packageVersion"
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

function Invoke-PyInstaller([string]$WorkingDirectory,[string]$Spec,
                            [string]$DistPath,[string]$WorkPath) {
    # PyInstaller logs INFO progress to stderr; under EAP=Stop PS 5.1 turns
    # the first stderr line into a terminating NativeCommandError.  Relax
    # EAP for the call and judge success by exit code only.
    $arguments = @('-m','PyInstaller',$Spec,'--distpath',$DistPath,
        '--workpath',$WorkPath,'--noconfirm')
    Push-Location -LiteralPath $WorkingDirectory
    try {
        $previousEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { $null = @(& python @arguments 2>&1) }
        finally { $ErrorActionPreference = $previousEap }
        if ($LASTEXITCODE -ne 0) {
            throw ('PyInstaller failed for ' + $Spec + ' (exit ' +
                $LASTEXITCODE + ')')
        }
    } finally { Pop-Location }
}

$repoRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$resolvedCommit = Invoke-GitCaptured @(
    '-C',$repoRoot,'rev-parse',("{0}^{{commit}}" -f $SourceCommit))
$outputRoot = if ($OutputDirectory) {
    [IO.Path]::GetFullPath($OutputDirectory)
} else { Join-Path $repoRoot 'dist' }
$zipPath = Join-Path $outputRoot ($packageName + '.zip')
if ($packageName -match '(?i)logs|日志') { throw 'Package name contains a log marker.' }
$buildRoot = Join-Path $repoRoot (
    '.build-gui-vm-' + [Guid]::NewGuid().ToString('N'))
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

    # Build both executables FROM THE STAGED TREE so packaged binaries
    # correspond to the packaged source (manifest binds both by hash).
    $pythonVersion = ((& python -c 'import platform;print(platform.python_version())') 2>&1).ToString().Trim()
    $pyinstallerVersion = ((& python -m PyInstaller --version) 2>&1).ToString().Trim()
    Invoke-PyInstaller $stage 'fakenet.spec' $stage (Join-Path $buildRoot 'work-fakenet')
    Invoke-PyInstaller $stage 'fakenet-GUI.spec' $stage (Join-Path $buildRoot 'work-gui')
    $fakenetExe = Join-Path $stage 'fakenet.exe'
    $guiExe = Join-Path $stage 'fakenet-GUI.exe'
    foreach ($binary in @($fakenetExe,$guiExe)) {
        if (-not (Test-Path -LiteralPath $binary)) {
            throw ('Expected build output missing: ' + $binary)
        }
    }
    # fakenet.spec's legacy COLLECT step also emits a redundant dir copy.
    $collectDir = Join-Path $stage 'fakenet-dat'
    if (Test-Path -LiteralPath $collectDir) {
        Remove-Item -LiteralPath $collectDir -Recurse -Force
    }

    # Flatten the official release layout next to the exes (mirrors
    # build.yaml) so double-clicking fakenet.exe finds configs\default.ini
    # exactly like the CI release zip, and the frozen GUI's template menu
    # (exe_dir\configs) is populated.
    foreach ($item in @('configs','defaultFiles')) {
        Copy-Item -LiteralPath (Join-Path $stage ('fakenet\'+$item)) `
            -Destination (Join-Path $stage $item) -Recurse
    }
    New-Item -ItemType Directory -Path (Join-Path $stage 'listeners') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $stage 'fakenet\listeners\ssl_utils') `
        -Destination (Join-Path $stage 'listeners\ssl_utils') -Recurse
    Get-ChildItem -LiteralPath (Join-Path $stage 'listeners') -Filter '__pycache__' `
        -Directory -Recurse | Remove-Item -Recurse -Force
    foreach ($probe in @(
            (Join-Path $stage 'configs\default.ini'),
            (Join-Path $stage 'defaultFiles'),
            (Join-Path $stage 'listeners\ssl_utils\privkey.pem'))) {
        if (-not (Test-Path -LiteralPath $probe)) {
            throw ('Release layout incomplete at: ' + $probe)
        }
    }

    # Syntax gates on the acceptance payload before it ships.
    python -m py_compile (Join-Path $stage 'test\gui_vm\run_gui_vm_acceptance.py')
    if ($LASTEXITCODE -ne 0) { throw 'Acceptance runner syntax failed.' }
    if (-not (Test-Path -LiteralPath (Join-Path $stage 'test\gui_vm\Run-Tests.cmd'))) {
        throw 'Run-Tests.cmd missing from staged tree.'
    }
    Get-ChildItem -LiteralPath $stage -Filter '__pycache__' -Directory -Recurse |
        Remove-Item -Recurse -Force

    $fakenetHash = (Get-FileHash -LiteralPath $fakenetExe `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $guiHash = (Get-FileHash -LiteralPath $guiExe `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $rows = @()
    foreach ($file in Get-ChildItem -LiteralPath $stage -File -Recurse |
            Where-Object { $_.Name -ne 'gui-vm-manifest.json' -and
                           $_.FullName -notmatch '[\\/]Logs[\\/]' } |
            Sort-Object FullName) {
        $rows += [ordered]@{
            path=$file.FullName.Substring($stage.Length+1).Replace('\','/')
            size=[uint64]$file.Length
            sha256=(Get-FileHash -LiteralPath $file.FullName `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $manifest = [ordered]@{
        schema_version=1
        package_version=$packageVersion
        plan_version='v1.32'
        source_commit=$resolvedCommit
        python_version=$pythonVersion
        pyinstaller_version=$pyinstallerVersion
        fakenet_exe_sha256=$fakenetHash
        fakenet_gui_exe_sha256=$guiHash
        acceptance_entry='test/gui_vm/Run-Tests.cmd'
        evidence_levels='results.tsv 标注 实测/等效'
        logs_plaintext=$true
        files=$rows
    }
    [IO.File]::WriteAllText(
        (Join-Path $stage 'gui-vm-manifest.json'),
        (($manifest | ConvertTo-Json -Depth 6)+[Environment]::NewLine),
        [Text.UTF8Encoding]::new($false))
    New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
    New-DeterministicZip $stage $zipPath
    Write-Host ('Package: ' + $zipPath)
    Write-Host ('Source commit: ' + $resolvedCommit)
    Write-Host ('fakenet.exe sha256: ' + $fakenetHash)
    Write-Host ('fakenet-GUI.exe sha256: ' + $guiHash)
    Write-Host 'No Logs directory and no .sha256 sidecar were generated.'
} finally {
    if (Test-Path -LiteralPath $buildRoot) {
        $resolved = [IO.Path]::GetFullPath($buildRoot)
        if (-not $resolved.StartsWith(
                $repoRoot+[IO.Path]::DirectorySeparatorChar,
                [StringComparison]::OrdinalIgnoreCase) -or
                [IO.Path]::GetFileName($resolved) -notlike '.build-gui-vm-*') {
            throw 'Refusing to remove unexpected build path.'
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
