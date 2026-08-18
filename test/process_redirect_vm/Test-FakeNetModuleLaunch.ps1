$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'FakeNetLaunchTools.ps1')

$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$runner = Get-Content -Raw -LiteralPath (
    Join-Path $PSScriptRoot 'Run-ProcessRedirectTests.ps1')
foreach ($required in @(
        "'-X','utf8','-u','-m','fakenet.fakenet'",
        '$env:PYTHONPATH = $root',
        'Test-AnyLogContainsMarker -Paths @($Path,$ErrorPath)',
        '--port $sentinelPort --log $fakeErr --target-client-log',
        'Read-TrackedProcessExitCode $script:FakeNet')) {
    if (-not $runner.Contains($required)) {
        throw ('FakeNet runner module-launch contract is missing: ' + $required)
    }
}

$empty = Join-Path ([IO.Path]::GetTempPath()) (
    'process-redirect-empty-' + [Guid]::NewGuid().ToString('N') + '.log')
try {
    [IO.File]::WriteAllText($empty,'',[Text.Encoding]::UTF8)
    if (Test-LogContainsMarker $empty 'PROCESS_REDIRECT_READY') {
        throw 'An empty FakeNet log was treated as READY.'
    }
    if ((Get-LogSummary $empty) -ne '<empty>') {
        throw 'An empty FakeNet stderr log was not summarized safely.'
    }
    $structured = $empty + '.structured'
    [IO.File]::WriteAllText($structured,
        'EGRESS_CONTROL_READY PROCESS_REDIRECT_READY',
        [Text.Encoding]::UTF8)
    if (-not (Test-AnyLogContainsMarker `
            @($empty,$structured) 'PROCESS_REDIRECT_READY')) {
        throw 'A READY marker in FakeNet stderr was not detected.'
    }
} finally {
    Remove-Item -LiteralPath $empty -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath ($empty + '.structured') `
        -Force -ErrorAction SilentlyContinue
}

$hadPythonPath = Test-Path Env:PYTHONPATH
$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = $root
    $json = & python.exe -c (
        "import importlib.util,json; s=importlib.util.find_spec('fakenet'); " +
        "print(json.dumps({'origin':s.origin,'locations':list(s.submodule_search_locations or [])}))")
    if ($LASTEXITCODE -ne 0) { throw 'Python package resolution probe failed.' }
} finally {
    if ($hadPythonPath) { $env:PYTHONPATH = $previousPythonPath }
    else { Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue }
}
$spec = $json | ConvertFrom-Json
if (-not ([string]$spec.origin).EndsWith('fakenet\__init__.py',
        [StringComparison]::OrdinalIgnoreCase) -or
        @($spec.locations).Count -ne 1) {
    throw ('fakenet does not resolve as the package directory: ' + $json)
}
Write-Host 'FakeNet module-launch and empty-log test passed.'
