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


def test_client_accepts_six_or_seven_arguments():
    assert 'if (a.Length != 6 && a.Length != 7) return 2;' in client_source()


def test_client_engine_wait_holds_first_connection_until_rule_marker():
    source = client_source()
    assert 'a[6] == "engine-wait"' in source
    assert 'PROCESS_REDIRECT_RULE_READY' in source
    # The wait is bounded by the same startup budget and by the stop control.
    assert re.search(
        r'while \(DateTime\.UtcNow < retryDeadline && !File\.Exists\(a\[2\]\)\)', source)
    # An engine that never publishes the marker is a distinct failure.
    assert 'if (!markerSeen) return 4;' in source


def test_client_engine_wait_only_accepts_run_dirs_created_after_launch():
    source = client_source()
    assert 'Process.GetCurrentProcess().StartTime.ToUniversalTime()' in source
    assert 'Directory.GetCreationTimeUtc(d) > launchUtc' in source


def test_spawn_passes_engine_wait_only_for_restart_window():
    assert re.search(
        r"\$clientArgs = @\(\$endpoint\.host, \$endpoint\.port, \$Stop, "
        r"\$Cadence, \$Token, \$StartupRetrySeconds\)\r?\n"
        r"\s*if \(\$Interleave -eq 'restart-window'\) \{ \$clientArgs \+= @\('engine-wait'\) \}",
        PROBES)
    # The legacy six-argument spawn form is gone.
    assert '-ArgumentList @($endpoint.host, $endpoint.port, $Stop, $Cadence, $Token, $StartupRetrySeconds) -RedirectStandardOutput' not in PROBES


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
    assert "runtime_profile.get('bucket') == 'B3'" in site
    assert "runtime_profile['probe_target'].get('process_mode') == 'match'" in site
    assert "interleave == 'restart-window'" in site
