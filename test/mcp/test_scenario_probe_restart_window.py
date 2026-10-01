"""Restart-window match-probe lifecycle contract (sst-041 option A, 2026-09-28).

A restart-window B3/match probe is released BEFORE the restart while the
engine is going down.  The client must hold its first connection until the
restarted engine publishes PROCESS_REDIRECT_RULE_READY (it stays alive as
the reviewed image the second start adopts), and the driver must stop run-01's
same-image probe before the restart so its gap SYN retries cannot leave live
A rows that the restart quiescence gate refuses.  These contracts are
extracted from the PRODUCTION sources, never a rewritten mirror.
"""

import re
from pathlib import Path

HERE = Path(__file__).parent
PROBES = (HERE / 'acceptance' / 'scenario_probes.ps1').read_text(encoding='utf-8')
SUITE = (HERE / 'acceptance' / 'scenario_suite.py').read_text(encoding='utf-8')


def client_source():
    match = re.search(r"\$clientSource = @'\r?\n(.*?)\r?\n'@", PROBES, re.S)
    assert match, 'client source block missing'
    return match.group(1)


def test_client_accepts_normal_or_identity_bound_engine_wait_arguments():
    assert 'if (a.Length != 6 && a.Length != 10) return 2;' in client_source()


def test_client_engine_wait_holds_first_connection_until_launcher_signal():
    source = client_source()
    assert 'a[6] == "engine-wait"' in source
    # The signal file is derived from the probe's own stop control.
    assert 'Path.Combine(Path.GetDirectoryName(a[2]), "probe.engine-ok")' in source
    # Both executable and launcher use the same QPC/owner-bound gate.
    assert 'ScenarioEngineGate.Evaluate(contract, signal, a[4], a[9]' in source
    assert 'Stopwatch.GetTimestamp(), Stopwatch.Frequency, cancelled)' in source
    assert 'owner.StartTime.ToUniversalTime().Ticks != Int64.Parse(a[8])' in source
    assert 'ENGINE_OK_MISSED|' in source and 'return 4;' in source
    assert 'ENGINE_WAIT|' in source and '\"ENGINE_OK|\" + engineOk' in source
    # Connection attempts get a fresh budget after the signal.
    assert re.search(
        r'ENGINE_OK\|" \+ engineOk.*?\s*'
        r'retryDeadline = DateTime\.UtcNow\.AddSeconds\(retrySeconds\);',
        source, re.S)
    # The managed run.log is deliberately NOT read: its writer refuses
    # concurrent readers until exit, which made the marker invisible for
    # the whole live window (sst-041 option A verification, 2026-09-29).
    assert 'PROCESS_REDIRECT_RULE_READY' not in source
    assert '\"run.log\"' not in source


def test_spawn_passes_engine_wait_only_for_second_restart_window_probe():
    assert re.search(
        r"\$clientArgs = @\(\$endpoint\.host, \$endpoint\.port, \$Stop, "
        r"\$Cadence, \$Token, \$StartupRetrySeconds\)\r?\n"
        r"\s*if \(\(\$Interleave -eq 'restart-window' -or \$Interleave -eq 'during-start' -or \$Interleave -eq 'after-healthy' -or \$Interleave -eq 'before-start'\) -and \$EngineWait\) \{ \$clientArgs \+= @\('engine-wait', \$PID, \[Diagnostics\.Process\]::GetCurrentProcess\(\)\.StartTime\.ToUniversalTime\(\)\.Ticks, \$CaptureRunId\) \}",
        PROBES)
    # The launcher-side log wait is skipped exactly for EngineWait probes:
    # the client holds its own first connection until the signal file.
    assert re.search(
        r"if \(\$Interleave -eq 'during-start' -and -not \$EngineWait\) \{\s*"
        r"Wait-EngineReadiness", PROBES)
    assert re.search(r"\[switch\]\$EngineWait", PROBES)
    # The legacy six-argument spawn form is gone.
    assert '-ArgumentList @($endpoint.host, $endpoint.port, $Stop, $Cadence, $Token, $StartupRetrySeconds) -RedirectStandardOutput' not in PROBES


def test_suite_marks_only_the_second_probe_engine_wait():
    matches = re.findall(
        r"if \(run_label == 'run-02' and profile\['bucket'\] in \('B3', 'B4'\) and\s*"
        r"profile\['interleave'\] in \('restart-window', 'during-start', 'after-healthy', 'before-start'\)\):\s*"
        r"#\s*Only this probe is released before the restart.*?\s*"
        r"params\['EngineWait'\] = True", SUITE, re.S)
    assert len(matches) == 2, 'expected EngineWait gating at both probe launch sites'


def test_client_build_reuse_requires_matching_source_hash():
    """A reused probe binary must come from the current client source.

    A stale reused binary keeps the old argv contract: the engine-wait
    client returned 2 on seven arguments with no output (sst-041 option A,
    2026-09-28), and the failure only surfaced as a missing probe close.
    """
    reuse = re.search(
        r"if \(Test-Path -LiteralPath \$ResultPath\) \{\s*"
        r"try \{\s*\$prior = Get-Content -LiteralPath \$ResultPath -Raw \| ConvertFrom-Json\s*"
        r"if \(\$prior -and \$prior\.path -and \$prior\.source_sha256 -eq \$sourceHash "
        r"-and \(Test-Path -LiteralPath \$prior\.path\)\) \{\s*return \$prior",
        PROBES)
    assert reuse, 'source-hash gated reuse missing from Ensure-ProbeClient'
    assert re.search(
        r"\$sourceHash = \[BitConverter\]::ToString\(\s*"
        r"\[Security\.Cryptography\.SHA256\]::Create\(\)\.ComputeHash\(\s*"
        r"\[Text\.Encoding\]::UTF8\.GetBytes\(\$clientSource\)\)\)",
        PROBES)
    assert re.search(
        r"private_ipv4 = '192\.168\.204\.1'; source_sha256 = \$sourceHash \}", PROBES)


def test_driver_stops_run01_probe_before_b3_match_restart():
    # The cooperative pre-restart stop exists and keeps the capture open (no
    # pktmon stop is passed).
    assert 'def _pre_restart_probe_stop' in SUITE
    body = re.search(
        r'def _pre_restart_probe_stop\(.*?\n(?=    def _arm_managed_exit_probe)', SUITE, re.S)
    assert body, 'pre-restart probe stop helper missing'
    assert "capture['stop']" in body.group(0)
    assert '_fail_closed_cooperative' in body.group(0)
    assert re.search(
        r'self\._probe_cooperative_cleanup_command\(\s*'
        r"capture\['pid'\], capture\.get\('probe_creation_ticks'\), capture\['stop'\],\s*"
        r'status_path, None, wait_seconds=30', body.group(0))
    # The restart chain invokes it only for the B3/match/restart-window
    # combination, after releasing the second probe and before the restart
    # call.
    call_site = re.search(
        r"second_release = None if interleave == 'stop-window' else.*?"
        r"_release_probe\(captures\[second_label\], 'restart-window'\)\n"
        r"(.*?)if interleave == 'stop-window':", SUITE, re.S)
    assert call_site, 'restart-chain call site not found'
    site = call_site.group(1)
    assert "_pre_restart_probe_stop(captures[first_label])" in site
    assert "runtime_profile.get('bucket') in ('B3', 'B4')" in site
    # Both match and nonmatch B3 probes leave live A rows through the gap
    # (sst-048); the mode gate is deliberately gone.
    assert "process_mode" not in site
    assert "interleave in ('restart-window', 'during-start', 'after-healthy')" in site


def test_driver_signals_engine_ok_after_a_healthy_restart():
    helper = re.search(
        r'def _signal_engine_ok\(.*?\n(?=    def _pre_restart_probe_stop)', SUITE, re.S)
    assert helper, 'engine-ok helper missing'
    body = helper.group(0)
    assert "with_name('probe.engine-ok')" in body and 'WriteAllText' in body
    call_site = re.search(
        r"engine_signal = self\._release_restart_engine\(\s*"
        r"restarted, runtime_profile, captures\[second_label\]\)", SUITE)
    assert call_site, 'engine-ok call site missing'
    # The signal is written only after the restart call converged.
    restart_pos = SUITE.index("restarted = call('restart', {}, mutation=True)")
    assert call_site.start() > restart_pos


def test_restart_window_probe_window_spans_the_restart_transition():
    """A restart-window probe's traffic window extends by the startup budget.

    The probe is released before the restart; the launcher releases the
    auxiliary cases only after the restart converged and the health checks
    completed -- with the plain connection window the probe expired before
    the cases file appeared (sst-058, 2026-09-30).
    """
    assert re.search(
        r"\$windowSeconds = if \(\$Interleave -eq 'restart-window'\) "
        r"\{ \$Seconds \+ \$StartupRetrySeconds \} else \{ \$Seconds \}",
        PROBES)


def test_engine_wait_precedes_udp_socket_creation():
    """The held second UDP socket must not pollute run-01 restoration.

    R02 sst-058 originals bind the extra listen port to run-02's native UDP
    source. The real WinPS loop verifies silence before engine-ok, emission
    afterwards, and cooperative close; this guard catches moving the wait
    back behind the UDP branch's unconditional return.
    """
    wait = PROBES.index("    if ($EngineWait -and -not ($Bucket -eq 'B3' -and $ProcessMode -eq 'match'))")
    udp = PROBES.index("    if ($endpoint.protocol -eq 'udp') {")
    assert wait < udp
