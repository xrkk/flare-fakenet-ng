$ErrorActionPreference = 'Stop'

$runner = Get-Content -Raw -LiteralPath (
    Join-Path $PSScriptRoot 'Run-ProcessRedirectTests.ps1')
$client = Get-Content -Raw -LiteralPath (
    Join-Path $PSScriptRoot 'client\process_redirect_client.c')
$verifier = Get-Content -Raw -LiteralPath (
    Join-Path $PSScriptRoot 'verify_process_redirect.py')
$cmd = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'Run-Tests.cmd')

foreach ($required in @(
        '--capture --comp nics --pkt-size 0',
        'Register-ClientProcess',
        'Stop-TrackedClientProcesses',
        'TARGET_PROCESS_STILL_RUNNING',
        '--negative-client-log',
        '--owner-client-log',
        '--burst-client-log')) {
    if (-not $runner.Contains($required)) {
        throw ('Runner forward contract is missing: ' + $required)
    }
}
foreach ($required in @(
        "'OwnerGate10000'",
        "'16-22 minutes on the reviewed 4 GB VM'",
        "'OfflineEnvironmentSetup'",
        "'FakeNetStartup'",
        "'25 minutes'",
        '1500000',
        'Get-CompletedConnectionCount',
        'Write-LongTaskProgress',
        "'StopAndVerify'")) {
    if (-not $runner.Contains($required)) {
        throw ('Runner long-task visibility contract is missing: ' + $required)
    }
}
foreach ($required in @(
        '--minimum-start-interval-ms',
        'GetTickCount64()',
        'minimum_start_interval_ms > elapsed_ms',
        'failure_stage')) {
    if (-not $client.Contains($required)) {
        throw ('Native client pacing contract is missing: ' + $required)
    }
}
if ($client.Contains('if (delay_ms) Sleep(delay_ms);')) {
    throw 'Native client still sleeps a fixed delay after every connection.'
}
foreach ($required in @(
        "'PROCESS_REDIRECT_SUSPEND'",
        "'PROCESS_REDIRECT_RESUME'",
        "'reason=route_query_'",
        "'reason=route_snapshot_changed'",
        "'reason=policy_exception'",
        "'UnicodeDecodeError:'")) {
    if (-not $verifier.Contains($required)) {
        throw ('Verifier runtime-failure contract is missing: ' + $required)
    }
}
if (-not $cmd.Contains('%~dp0..\..\dist\Logs')) {
    throw 'CMD launcher still prints the wrong Logs directory.'
}
$negativeResult = $runner.IndexOf('Add-Result NonTargetIsolation PASS')
$pktmonStart = $runner.IndexOf('& pktmon.exe start --capture --comp nics')
if ($negativeResult -lt 0 -or $pktmonStart -le $negativeResult) {
    throw 'Pktmon target-only evidence starts before non-target isolation ends.'
}
$burstResult = $runner.IndexOf('Add-Result ConcurrentBurst64 PASS')
$clientStop = $runner.IndexOf('Stop-TrackedClientProcesses',$burstResult)
$fakeNetStop = $runner.IndexOf('Stop-FakeNet $root',$burstResult)
if ($burstResult -lt 0 -or $clientStop -le $burstResult -or
        $fakeNetStop -le $clientStop) {
    throw 'Target clients are not proven stopped before FakeNet/WinDivert.'
}

Write-Host 'Runner forward-path contracts passed.'
