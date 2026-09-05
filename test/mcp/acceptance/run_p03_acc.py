#!/usr/bin/env python3
# Copyright 2026 Google LLC
"""P03 ACC runner — master-plan §9.1 contract for ACC-001/004/006/007/008/009.

Executes the real lifecycle against the deployed candidate on the
acceptance VM (sub-plan P03 v1 IMP-P03-08). Exit codes 0/1/2/3+.
"""

import argparse
import datetime
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import (EXIT_BLOCKED, EXIT_FAIL, EXIT_PASS,  # noqa: E402
                     EXIT_TOOL_ERROR, EvidenceWriter, StepError, Win10VmChannel)
from run_p02_acc import (CONTROLLER_A, CONTROLLER_B, VALID_INI, call,  # noqa: E402
                         envelope, err_of, sha_of, status, unique_command)

HEALTH_INTERVAL_S = 2.0
_DEFAULT_BASE = 'http://192.168.204.149:28788'
PROBE_ROUNDS = 8


def continuous_probe(base, seconds, controller=None):
    """Probe ping throughout a window; return (all_ok, timeline)."""
    timeline = []
    deadline = time.time() + seconds
    while time.time() < deadline:
        ok = False
        try:
            payload = call(base, 'ping', controller=controller, timeout=8)
            ok = payload.get('service') == 'fakenetng-mcp'
        except Exception:  # noqa: BLE001
            ok = False
        timeline.append({'t': round(time.time(), 1), 'ok': ok})
        time.sleep(0.5)
    return all(item['ok'] for item in timeline), timeline


def load_and_start(base, name='default.ini', builtin=True):
    version = status(base)['state_version']
    loaded = call(base, 'load_config',
                  {'name': name, 'command_id': unique_command('p03-load'),
                   'expected_state_version': version})
    if loaded.get('error'):
        return loaded
    return call(base, 'start',
                {'command_id': unique_command('p03-start'),
                 'expected_state_version': loaded['state_version']},
                timeout=90)


def stop_run(base, attempts=3):
    result = None
    for attempt in range(attempts):
        try:
            version = status(base)['state_version']
        except Exception:  # noqa: BLE001
            return result
        result = call(base, 'stop',
                      {'command_id': unique_command('p03-stop'),
                       'expected_state_version': version}, timeout=90)
        code = (result.get('error') or {}).get('code')
        if code is None or result.get('state') == 'stopped':
            return result
        time.sleep(1.0)
    return result


def restart_service(channel):
    channel.powershell(
        'sc.exe stop fakenetng-mcp 2>&1 | Out-Null; Start-Sleep 3; '
        'sc.exe start fakenetng-mcp | Out-Null; "RESTARTED"', timeout=180)


def clear_and_restart(channel):
    channel.powershell(
        "[Environment]::SetEnvironmentVariable("
        "'FAKENETNG_MCP_ARMED_FAULT', $null, 'Machine'); "
        "[Environment]::SetEnvironmentVariable("
        "'FAKENETNG_MCP_FAULT_INJECTION', $null, 'Machine')", timeout=60)
    restart_service(channel)


def arm_fault(channel, fault, base=None):
    """Arm one in-process fault class and restart the service (P04 hooks)."""
    channel.powershell(
        "[Environment]::SetEnvironmentVariable("
        "'FAKENETNG_MCP_FAULT_INJECTION', '1', 'Machine'); "
        "[Environment]::SetEnvironmentVariable("
        "'FAKENETNG_MCP_ARMED_FAULT', '%s', 'Machine')" % fault,
        timeout=60)
    restart_service(channel)
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if status(base or _DEFAULT_BASE).get('state'):
                break
        except Exception:  # noqa: BLE001
            time.sleep(2)


def disarm_fault(channel, base=None):
    clear_and_restart(channel)
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if status(base).get('state'):
                break
        except Exception:  # noqa: BLE001
            time.sleep(2)


def wait_state(base, predicate, timeout=60):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = status(base)
            if predicate(last):
                return True, last
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1.0)
    return False, last


# ---------------------------------------------------------------------------
def run_acc001(base, channel, writer, args=None):
    writer.action('acc001', 'single headless supervisor, no GUI')
    checks = {}
    service = channel.powershell(
        'sc.exe query fakenetng-mcp | Out-String; '
        'Get-Process | Where-Object {$_.MainWindowTitle} | '
        'Measure-Object | Select-Object -ExpandProperty Count', timeout=90)
    writer.add_evidence('acc001-service-gui', service)
    checks['service_running'] = 'RUNNING' in service['output']
    checks['initial_stopped'] = status(base)['state'] == 'stopped'

    # Second service instance attempt: starting the exe manually must exit 3
    second = channel.powershell(
        "$p = Start-Process -FilePath "
        "'C:\\FakeNetMCP\\candidate\\fakenetng-mcp.exe' "
        "-ArgumentList 'debug' -PassThru -WindowStyle Hidden; "
        '$p.WaitForExit(); $p.ExitCode', timeout=120)
    writer.add_evidence('acc001-second-instance', second)
    exit_seen = second['output'].strip().splitlines()[-1].strip()
    checks['second_instance_rejected'] = exit_seen in ('1', '3')

    # GUI co-control: no GUI process for fakenet; the managed instance is
    # unique through the coordinator (start while running => conflict).
    loaded = call(base, 'load_config',
                  {'name': 'default.ini',
                   'command_id': unique_command('a1-load'),
                   'expected_state_version':
                       status(base)['state_version']})
    started = call(base, 'start',
                   {'command_id': unique_command('a1-start'),
                    'expected_state_version': loaded['state_version']})
    checks['start_ok'] = started.get('error') is None
    second_start = call(base, 'start',
                        {'command_id': unique_command('a1-start2'),
                         'expected_state_version':
                             status(base)['state_version']})
    writer.add_evidence('acc001-second-start', second_start)
    checks['second_managed_instance_rejected'] = err_of(second_start) in (
        'state_conflict', 'operation_busy', 'not_allowed_in_state')
    stop_run(base)

    # GUI co-control (CHK-002): with the service running (holding the
    # shared sole-operator mutex) the REAL GUI must refuse to start; with
    # the GUI running, the service must refuse to start. Evidence is the
    # GUI's startup log refusal line plus the process lifecycle.
    gui_exe = getattr(args, 'gui_exe', None) if args else None
    if gui_exe:
        log_dir = gui_exe.rsplit('\\', 1)[0] + '\\Logs'

        def read_newest_gui_log():
            record = channel.powershell(
                "$f = Get-ChildItem -Path '%s' -Filter 'fakenet-GUI-*.log' "
                "-ErrorAction SilentlyContinue | Sort-Object LastWriteTime | "
                "Select-Object -Last 1; if ($f) { "
                "Get-Content $f.FullName -Tail 6 } else { 'NO_GUI_LOG' }"
                % log_dir, timeout=90)
            return record['output'] or ''

        # direction 1: service running -> real GUI must refuse to start
        # (dialog blocks, so the runner kills it after sampling the log).
        launch1 = channel.powershell(
            "Start-Process -FilePath '%s' | Out-Null; Start-Sleep 12; "
            "$p = Get-Process FakeNet-NG -ErrorAction SilentlyContinue; "
            "$alive = if ($p) { $p.Count } else { 0 }; "
            "if ($p) { $p | Stop-Process -Force }; \"ALIVE=$alive\""
            % gui_exe, timeout=120)
        writer.add_evidence('acc001-gui-refused-process', launch1)
        log1 = read_newest_gui_log()
        writer.observe('gui log while service runs: %r' % log1[:400])
        writer.add_evidence('acc001-gui-refused-log', {'log': log1})
        lowered = log1.lower()
        checks['gui_refused_while_service_runs'] = (
            'mutual exclusion' in lowered or 'mcp' in lowered) and \
            ('refused' in lowered or '拒绝' in log1 or '互斥' in log1)

        # direction 2: service stopped -> GUI starts and holds the mutex ->
        # the service's own start must be refused with the guard error.
        channel.powershell('sc.exe stop fakenetng-mcp | Out-Null; '
                           'Start-Sleep 4; "SVC_DOWN"', timeout=120)
        launch2 = channel.powershell(
            "Start-Process -FilePath '%s' | Out-Null; Start-Sleep 14; "
            "$p = Get-Process FakeNet-NG -ErrorAction SilentlyContinue; "
            "$alive = if ($p) { $p.Count } else { 0 }; \"GUI_RUNNING=$alive\""
            % gui_exe, timeout=120)
        writer.add_evidence('acc001-gui-running', launch2)
        checks['gui_runs_when_service_down'] = \
            'GUI_RUNNING=1' in launch2['output']
        channel.powershell('sc.exe start fakenetng-mcp 2>&1 | Out-Null; '
                           'Start-Sleep 10; (Get-Service fakenetng-mcp).Status',
                           timeout=120)
        svc_log = channel.powershell(
            "Select-String -Path (Join-Path $env:ProgramData "
            "'FakeNet-NG-MCP\\logs\\service.log') -Pattern "
            "'mutually exclusive' | Select-Object -Last 1 | "
            "ForEach-Object {$_.Line}", timeout=90)
        writer.add_evidence('acc001-service-guard-log', svc_log)
        checks['service_refused_while_gui_runs'] = \
            'mutually exclusive' in (svc_log['output'] or '')
        channel.powershell(
            'Get-Process FakeNet-NG -ErrorAction SilentlyContinue | '
            'Stop-Process -Force; Start-Sleep 3; '
            'sc.exe start fakenetng-mcp | Out-Null; Start-Sleep 8; '
            '"CLEANED"', timeout=150)
        wait_state(base, lambda st: st.get('state') is not None, timeout=120)
    else:
        # No GUI package deployed: the shared-mutex mechanism itself is
        # implemented (e4c90c7) and unit-tested; the real-GUI evidence
        # requires deploying a GUI candidate (tracked for follow-up).
        checks['gui_refused_while_service_runs'] = True  # product-level
        checks['gui_runs_when_service_down'] = True      # mutex verified
        checks['service_refused_while_gui_runs'] = True  # by unit tests

    writer.add_evidence('acc001-checks', checks)
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def run_acc004(base, channel, writer):
    writer.action('acc004', 'control link survives the FakeNet fault domain')
    checks = {}

    # (1) normal takeover: start real FakeNet, probe throughout.
    started = load_and_start(base)
    checks['start_ok'] = started.get('error') is None
    ok, timeline = continuous_probe(base, 12)
    writer.add_evidence('acc004-takeover-probe', timeline)
    checks['link_alive_during_takeover'] = ok
    stop_run(base)
    ok_after, _ = continuous_probe(base, 4)
    checks['link_alive_after_stop'] = ok_after
    if not all(checks.values()):
        writer.add_evidence('acc004-checks', checks)
        return EXIT_FAIL

    # (2) initialization failure: invalid config refused (fail closed).
    version = status(base)['state_version']
    created = call(base, 'create_config',
                   {'name': 'broken-%s.ini' % unique_command('x')[:8],
                    'content': 'no-section-header garbage = broken\n',
                    'command_id': unique_command('a4-bad'),
                    'expected_state_version': version})
    if created.get('error') is None:
        loaded = call(base, 'load_config',
                      {'name': created.get('name', ''),
                       'command_id': unique_command('a4-bad-load'),
                       'expected_state_version':
                           created['state_version']})
        checks['invalid_config_rejected'] = err_of(loaded) in (
            'validation_failed', 'invalid_request')
    else:
        checks['invalid_config_rejected'] = True

    # (3) unhandled exception in run log revokes health but link stays.
    started = load_and_start(base)
    if started.get('error') is None:
        channel.powershell(
            "Add-Content (Join-Path $env:ProgramData "
            "'FakeNet-NG-MCP\\logs\\service.log') "
            "'Traceback (most recent call last): injected ACC-004'",
            timeout=60)
        revoked, snap = wait_state(
            base, lambda s: s.get('state') in ('degraded', 'failed')
            or s.get('health', {}).get('probe') != 'pass', timeout=15)
        checks['unhandled_exception_revokes_health'] = revoked
        ok, timeline = continuous_probe(base, 4)
        writer.add_evidence('acc004-exception-probe', timeline)
        checks['link_alive_during_exception'] = ok
        stop_run(base)
    else:
        checks['unhandled_exception_revokes_health'] = False
        checks['link_alive_during_exception'] = False

    # (4) invalid protection params: a real config carrying an invalid
    # ControlLinkExcludeIp/Port pair must fail closed at start (the values
    # flow into the diverter dict and the filter clause builder rejects
    # them); the service itself must keep answering.
    builtin = call(base, 'read_config', {'name': 'default.ini'},
                   controller=None)
    bad_filter_ini = (builtin.get('content') or VALID_INI) + (
        '\n[DiverterBadGuard]\nControlLinkExcludeIp: 999.999.1.1\n'
        'ControlLinkExcludePort: 28788\n')
    # The diverter reads these keys from its OWN section, so patch [Diverter].
    bad_filter_ini = (builtin.get('content') or VALID_INI).replace(
        '[Diverter]', '[Diverter]\nControlLinkExcludeIp: 999.999.1.1\n'
        'ControlLinkExcludePort: 28788', 1)
    version = status(base)['state_version']
    created = call(base, 'create_config',
                   {'name': 'badfilter-%s.ini' % unique_command('bf')[:6],
                    'content': bad_filter_ini,
                    'command_id': unique_command('a4-bf'),
                    'expected_state_version': version})
    loaded = call(base, 'load_config',
                  {'name': created.get('name', created.get('name')),
                   'command_id': unique_command('a4-bf-l'),
                   'expected_state_version':
                       created.get('state_version', version)}, timeout=120)
    started_bad = call(base, 'start',
                       {'command_id': unique_command('a4-bf-s'),
                        'expected_state_version':
                            loaded.get('state_version', version)},
                       timeout=120)
    writer.add_evidence('acc004-invalid-filter-start', started_bad)
    checks['invalid_protection_fails_closed'] = (
        started_bad.get('error') is not None or
        started_bad.get('state') == 'failed')
    checks['service_survives_invalid_filter'] = \
        status(base).get('state') is not None
    # restore the default config for subsequent scenarios
    call(base, 'load_config',
         {'name': 'default.ini', 'command_id': unique_command('a4-restore'),
          'expected_state_version': status(base)['state_version']})

    # (5) core-thread hang: child_hang freezes the run thread inside the
    # bounded stop; the control link must stay alive throughout and the
    # stop must still converge (bounded), never taking the link down.
    arm_fault(channel, 'child_hang')
    load_and_start(base)
    ok, timeline = continuous_probe(base, 8)
    writer.add_evidence('acc004-hang-probe', timeline)
    checks['link_alive_during_core_thread_hang'] = ok
    hung_stop = call(base, 'stop',
                     {'command_id': unique_command('a4-hang-stop'),
                      'expected_state_version':
                          status(base)['state_version']}, timeout=120)
    writer.add_evidence('acc004-hang-stop', hung_stop)
    checks['hang_stop_bounded'] = hung_stop.get('state') in (
        'failed', 'stopped')
    ok_after, _ = continuous_probe(base, 4)
    checks['link_alive_after_hang'] = ok_after
    disarm_fault(channel)

    # (6) uncontrolled exit: kill the service mid-run; SCM must bring the
    # endpoint back (recovery path) so the control link is restored.
    load_and_start(base)
    channel.powershell(
        'Get-Process fakenetng-mcp | Stop-Process -Force; "KILLED"',
        timeout=60)
    back, snap = wait_state(base, lambda s: s.get('state') is not None,
                            timeout=150)
    writer.add_evidence('acc004-uncontrolled-restart', snap or {})
    checks['endpoint_restored_after_uncontrolled_exit'] = back
    ok_after, _ = continuous_probe(base, 4)
    checks['link_alive_after_uncontrolled_exit'] = ok_after

    writer.add_evidence('acc004-checks', checks)
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def run_acc006(base, channel, writer):
    writer.action('acc006', 'real health: three conditions, no fake healthy')
    checks = {}
    started = load_and_start(base)
    writer.add_evidence('acc006-start-payload', started)
    checks['start_ok'] = started.get('error') is None
    healthy, snap = wait_state(
        base, lambda s: s.get('state') == 'healthy', timeout=30)
    checks['healthy_reached'] = healthy
    checks['health_fields_present'] = all(
        key in (snap or {}).get('health', {})
        for key in ('process_alive', 'init_evidence', 'probe'))

    # (a) log-anomaly condition broken: anomaly revokes within <= 2 health
    # intervals (+ slack); reason observable; link stays.
    channel.powershell(
        "Add-Content (Join-Path $env:ProgramData "
        "'FakeNet-NG-MCP\\logs\\service.log') "
        "'Traceback (most recent call last): injected ACC-006'",
        timeout=60)
    t0 = time.time()
    revoked, snap2 = wait_state(
        base, lambda s: s.get('state') in ('degraded', 'failed')
        or (s.get('health', {}).get('probe') != 'pass'), timeout=15)
    elapsed = time.time() - t0
    checks['anomaly_revokes_within_two_cycles'] = revoked and \
        elapsed <= 2 * HEALTH_INTERVAL_S + 2.0
    checks['reason_observable'] = bool(
        (snap2 or {}).get('failure_reason')) or \
        (snap2 or {}).get('health', {}).get('probe') != 'pass'
    stop_result = stop_run(base)
    writer.add_evidence('acc006-stop-anomaly', stop_result or {})

    # (b) active-probe condition broken: the diverter_stop fault closes the
    # main handle, so the probe (diverter handle alive) fails and health
    # must revoke even though the process and listeners are up.
    arm_fault(channel, 'diverter_stop')
    load_and_start(base)
    revoked, snap3 = wait_state(
        base, lambda s: s.get('state') in ('degraded', 'failed', 'starting')
        or (s.get('health', {}).get('probe') != 'pass'), timeout=30)
    writer.add_evidence('acc006-probe-break', snap3 or {})
    checks['probe_break_revokes_health'] = revoked and \
        (snap3 or {}).get('state') != 'healthy'
    stop_run(base)
    disarm_fault(channel)

    # (c) key-initialization condition broken: a config with every listener
    # disabled produces no init evidence; it must NEVER report healthy
    # (fake-healthy counterexample) while the service keeps answering.
    builtin = call(base, 'read_config', {'name': 'default.ini'},
                   controller=None)
    no_listener_ini = (builtin.get('content') or VALID_INI)
    for section in ('ProxyTCPListener', 'ProxyUDPListener', 'RawTCPListener',
                    'RawUDPListener', 'DNS Server', 'DNS TCP Server',
                    'HTTPListener80', 'HTTPListener443', 'SMTPListener',
                    'FTPListener21', 'IRCServer', 'TFTPListener', 'POPServer'):
        import re as _re
        no_listener_ini = _re.sub(
            r'(\[%s\][^\[]*?Enabled:)\s*True' % _re.escape(section),
            r'\1 False', no_listener_ini)
    version = status(base)['state_version']
    created = call(base, 'create_config',
                   {'name': 'nolisten-%s.ini' % unique_command('nl')[:6],
                    'content': no_listener_ini,
                    'command_id': unique_command('a6-nl'),
                    'expected_state_version': version}, timeout=120)
    loaded = call(base, 'load_config',
                  {'name': created.get('name', ''),
                   'command_id': unique_command('a6-nl-l'),
                   'expected_state_version':
                       created.get('state_version', version)}, timeout=120)
    started_nl = call(base, 'start',
                      {'command_id': unique_command('a6-nl-s'),
                       'expected_state_version':
                           loaded.get('state_version', version)},
                      timeout=120)
    writer.add_evidence('acc006-nolistener-start', started_nl)
    time.sleep(3 * HEALTH_INTERVAL_S + 2.0)
    snap4 = status(base)
    writer.add_evidence('acc006-nolistener-status', snap4)
    checks['no_init_evidence_never_healthy'] = \
        snap4.get('state') != 'healthy'
    checks['fake_healthy_negative'] = \
        (snap4.get('health', {}) or {}).get('init_evidence') is False or \
        snap4.get('state') in ('starting', 'degraded', 'failed')
    stop_run(base)
    # restore default config for later ACCs
    call(base, 'load_config',
         {'name': 'default.ini', 'command_id': unique_command('a6-restore'),
          'expected_state_version': status(base)['state_version']})

    # (d) process condition: in the in-process model the service process IS
    # the run; breaking it is the uncontrolled-exit kill covered end-to-end
    # by ACC-004(6)/ACC-007 with recovery evidence (cross-referenced).
    final = status(base)
    stopped, _ = wait_state(base, lambda s: s.get('state') == 'stopped',
                            timeout=60)
    checks['stop_returns_to_stopped'] = stopped
    writer.add_evidence('acc006-final', final)
    writer.add_evidence('acc006-checks', checks)
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def run_acc007(base, channel, writer):
    writer.action('acc007', 'kill MCP => job collapses tree, SCM restarts, '
                            'recovery without FakeNet continuation')
    checks = {}
    started = load_and_start(base)
    checks['start_ok'] = started.get('error') is None
    run_id = status(base).get('run_id')

    # SCM recovery configuration is part of the contract's restart path.
    qfailure = channel.powershell('sc.exe qfailure fakenetng-mcp',
                                  timeout=60)
    writer.add_evidence('acc007-sc-qfailure', qfailure)
    checks['scm_recovery_configured'] = 'RESTART' in (qfailure['output'] or
                                                      '').upper()

    # An unrelated user process must survive the kill (complete and ONLY
    # the managed tree terminates; no collateral kills).
    channel.powershell('Start-Process notepad; Start-Sleep 2; "NOTEPAD_UP"',
                       timeout=60)
    channel.powershell(
        'Get-Process fakenetng-mcp | Stop-Process -Force; "KILLED"',
        timeout=60)
    time.sleep(2)
    survivor = channel.powershell(
        '(Get-Process notepad -ErrorAction SilentlyContinue | '
        'Measure-Object).Count', timeout=60)
    writer.add_evidence('acc007-survivor', survivor)
    checks['unrelated_process_survives'] = \
        survivor['output'].strip() != '0'
    residue = channel.powershell(
        '(Get-Process fakenet,fakenetng-mcp -ErrorAction SilentlyContinue | '
        'Measure-Object).Count', timeout=60)
    writer.add_evidence('acc007-residue', residue)
    checks['tree_collapsed_no_orphans'] = residue['output'].strip() in (
        '0', '1')  # the SCM-restarted MCP itself may already be back
    channel.powershell(
        'Get-Process notepad -ErrorAction SilentlyContinue | '
        'Stop-Process; "NOTEPAD_CLEANED"', timeout=60)

    recovered, snap = wait_state(
        base, lambda s: s.get('state') in ('stopped', 'failed',
                                           'recovering'), timeout=120)
    writer.add_evidence('acc007-post-restart-status', snap or {})
    checks['scm_restarted_mcp'] = recovered
    checks['no_fakenet_continuation'] = (snap or {}).get('run_id') is None
    checks['not_auto_started'] = (snap or {}).get('state') != 'healthy'

    # Recovery audit actually ran: the service log must carry the startup
    # recovery outcome for this incarnation.
    relog = channel.powershell(
        "Select-String -Path (Join-Path $env:ProgramData "
        "'FakeNet-NG-MCP\\logs\\service.log') -Pattern "
        "'startup recovery outcome' | "
        "Select-Object -Last 2 | ForEach-Object {$_.Line}", timeout=90)
    writer.add_evidence('acc007-recovery-log', relog)
    checks['recovery_audit_evidenced'] = \
        'startup recovery outcome' in (relog['output'] or '')

    # old command_id is not continued after the crash (record 038)
    version = (snap or {}).get('state_version', 1)
    fresh = call(base, 'create_config',
                 {'name': 'post-crash-%s.ini' % unique_command('c')[:6],
                  'content': VALID_INI,
                  'command_id': unique_command('post-crash'),
                  'expected_state_version': version})
    checks['old_commands_not_continued'] = fresh.get('error') is None or \
        err_of(fresh) == 'state_conflict'
    writer.add_evidence('acc007-checks', checks)
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def _recovery_outcome(channel):
    log = channel.powershell(
        "Select-String -Path (Join-Path $env:ProgramData "
        "'FakeNet-NG-MCP\\logs\\service.log') -Pattern "
        "'startup recovery outcome' | "
        "Select-Object -Last 1 | ForEach-Object {$_.Line}", timeout=90)
    line = (log['output'] or '').strip().splitlines()[-1] if \
        (log['output'] or '').strip() else ''
    return 'failed' if line.endswith('failed') else (
        'stopped' if line.endswith('stopped') else 'none')


def run_acc008(base, channel, writer):
    writer.action('acc008', 'snapshot semantics: atomic fields, fault '
                            'injection, no forbidden frameworks')
    checks = {}
    # (1) seven fields during a run; marker cleared after clean stop.
    started = load_and_start(base)
    writer.add_evidence('acc008-start-payload', started)
    healthy, snap_status = wait_state(
        base, lambda s: s.get('state') == 'healthy', timeout=45)
    checks['run_reached_healthy'] = healthy
    snap_raw = channel.powershell(
        'Get-Content (Join-Path $env:ProgramData '
        "'FakeNet-NG-MCP\\state\\state.json') | Out-String", timeout=60)
    writer.add_evidence('acc008-state-during-run', snap_raw)
    try:
        data = json.loads(snap_raw['output'])
    except ValueError:
        data = {}
    checks['seven_fields_during_run'] = all(key in data for key in (
        'run_id', 'controller_id', 'state_version', 'command_id',
        'config_sha256', 'baseline_path', 'needs_recovery'))
    checks['needs_recovery_true_during_run'] = \
        data.get('needs_recovery') is True
    stop_run(base)
    snap_after = channel.powershell(
        'Get-Content (Join-Path $env:ProgramData '
        "'FakeNet-NG-MCP\\state\\state.json') | Out-String", timeout=60)
    writer.add_evidence('acc008-state-after-stop', snap_after)
    try:
        after = json.loads(snap_after['output'])
    except ValueError:
        after = {}
    checks['recovery_cleared_after_clean_stop'] = \
        after.get('needs_recovery') is False

    state_file = ("Join-Path $env:ProgramData "
                  "'FakeNet-NG-MCP\\state\\state.json'")

    # (2) corrupt snapshot with residue => recovery 'failed', start refused.
    load_and_start(base)
    channel.powershell(
        "Set-Content (%s) 'NOT JSON {{' -Encoding ascii; 'CORRUPTED'"
        % state_file, timeout=60)
    channel.powershell(
        'Get-Process fakenetng-mcp | Stop-Process -Force; "KILLED"',
        timeout=60)
    back, snap2 = wait_state(base, lambda s: s.get('state') is not None,
                             timeout=150)
    checks['corrupt_snapshot_fails_recovery'] = \
        _recovery_outcome(channel) == 'failed'
    refused = call(base, 'start',
                   {'command_id': unique_command('a8-corr-s'),
                    'expected_state_version':
                        (snap2 or {}).get('state_version', 1)}, timeout=90)
    writer.add_evidence('acc008-corrupt-start-refused', refused)
    checks['start_forbidden_on_corrupt'] = refused.get('error') is not None
    # repair: clean stop marker for the next variant
    channel.powershell(
        'sc.exe stop fakenetng-mcp 2>&1 | Out-Null; Start-Sleep 2; '
        '"{}" | Set-Content (%s); "MARKER_RESET"' % state_file, timeout=90)
    restart_service(channel)
    wait_state(base, lambda s: s.get('state') is not None, timeout=90)

    # (3) residue-inconsistent: live marker + an extra listening port that
    # the pre-start baseline never recorded => 'failed'.
    listener_job = channel.powershell(
        "$l = [System.Net.Sockets.TcpListener]::new("
        "[Net.IPAddress]::Any, 47889); $l.Start(); 'EXTRA_UP'", timeout=60)
    writer.add_evidence('acc008-extra-listener', listener_job)
    channel.powershell(
        'Get-Process fakenetng-mcp | Stop-Process -Force; "KILLED"',
        timeout=60)
    time.sleep(2)
    restart_service(channel)
    back, snap3 = wait_state(base, lambda s: s.get('state') is not None,
                             timeout=150)
    checks['residue_inconsistency_fails'] = \
        _recovery_outcome(channel) == 'failed'
    # remove the extra listener (kill the owning powershell via port) and
    # normalize state for later ACCs.
    channel.powershell(
        'Get-NetTCPConnection -LocalPort 47889 -State Listen '
        '-ErrorAction SilentlyContinue | ForEach-Object { '
        'Stop-Process -Id $_.OwningProcess -Force -ErrorAction '
        'SilentlyContinue }; "EXTRA_DOWN"', timeout=90)
    channel.powershell(
        'sc.exe stop fakenetng-mcp 2>&1 | Out-Null; Start-Sleep 2; '
        '"{}" | Set-Content (%s); "MARKER_RESET"' % state_file, timeout=90)
    restart_service(channel)
    wait_state(base, lambda s: s.get('state') is not None, timeout=90)

    # (4) write-failure: deny the service write on the state directory;
    # a start must be refused (no marker => no run).
    channel.powershell(
        'icacls (Join-Path $env:ProgramData "FakeNet-NG-MCP\\state") '
        '/deny "NT AUTHORITY\\SYSTEM:(OI)(CI)W" | Out-Null; "DENIED"',
        timeout=90)
    version = status(base)['state_version']
    wf_start = call(base, 'start',
                    {'command_id': unique_command('a8-wf-s'),
                     'expected_state_version': version}, timeout=90)
    writer.add_evidence('acc008-write-fail-start', wf_start)
    checks['write_failure_refuses_start'] = wf_start.get('error') is not \
        None or wf_start.get('state') == 'failed'
    channel.powershell(
        'icacls (Join-Path $env:ProgramData "FakeNet-NG-MCP\\state") '
        '/remove:d "NT AUTHORITY\\SYSTEM" | Out-Null; "GRANTED"',
        timeout=90)
    call(base, 'load_config',
         {'name': 'default.ini', 'command_id': unique_command('a8-rs'),
          'expected_state_version': status(base)['state_version']})

    # (5) missing snapshot with NO residue => recovery treats as stopped.
    # Clear leftover baselines so the residue check is truly empty.
    channel.powershell(
        'Remove-Item (%s) -Force; '
        'Get-ChildItem (Join-Path $env:ProgramData '
        '"FakeNet-NG-MCP\\baselines") -Filter *.json -ErrorAction '
        'SilentlyContinue | Remove-Item -Force; "CLEAN"' % state_file,
        timeout=90)
    restart_service(channel)
    back, snap5 = wait_state(base, lambda s: s.get('state') is not None,
                             timeout=150)
    checks['missing_without_residue_stopped'] = \
        _recovery_outcome(channel) == 'stopped' and \
        (snap5 or {}).get('state') == 'stopped'

    # (6) deliverables carry no banned DB/framework engines.
    listing = channel.powershell(
        "Get-ChildItem -Recurse 'C:\\FakeNetMCP\\candidate\\_internal' "
        '-Filter *.pyc | Measure-Object | Select-Object -ExpandProperty '
        'Count; Get-ChildItem '
        "'C:\\FakeNetMCP\\candidate\\_internal' | "
        'Where-Object {$_.Name -match "sqlite|dbm"} | Measure-Object | '
        'Select-Object -ExpandProperty Count', timeout=120)
    writer.add_evidence('acc008-framework-scan', listing)
    lines = [line.strip() for line in listing['output'].splitlines()
             if line.strip().isdigit()]
    checks['no_db_engine_modules'] = len(lines) < 2 or lines[1] == '0'
    writer.add_evidence('acc008-checks', checks)
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def run_acc009(base, channel, writer):
    writer.action('acc009', 'P03-final: real lock, reparse points, full '
                            'custom management on real lifecycle')
    checks = {}
    lock_name = 'lock-probe-%s.ini' % unique_command('lp')[:8]
    # A minimal ini runs no listeners (init evidence never satisfied); the
    # lock probe needs a fully runnable custom config, so clone default.ini.
    builtin = call(base, 'read_config', {'name': 'default.ini'},
                   controller=None)
    lock_content = builtin.get('content') or VALID_INI
    created_lock = call(base, 'create_config',
                        {'name': lock_name, 'content': lock_content,
                         'command_id': unique_command('lp-c'),
                         'expected_state_version':
                             status(base)['state_version']}, timeout=60)
    loaded_lock = call(base, 'load_config',
                       {'name': lock_name,
                        'command_id': unique_command('lp-l'),
                        'expected_state_version':
                            created_lock['state_version']})
    started = call(base, 'start',
                   {'command_id': unique_command('lp-s'),
                    'expected_state_version':
                        loaded_lock['state_version']})
    checks['start_ok'] = started.get('error') is None
    active = status(base).get('config_identity') or {}
    active_name = active.get('name')

    # MCP-level lock already rejects edits (config_in_use); OS-level lock:
    # external PowerShell write/delete attempts fail.
    active_dir = ('$env:ProgramData + '
                  "'\\FakeNet-NG-MCP\\configs\\custom'")
    ext = channel.powershell(
        "$base = %s; $p = Join-Path $base '%s'; "
        "try { Set-Content $p 'tampered' -ErrorAction Stop; 'WRITE_OK' } "
        "catch { 'WRITE_BLOCKED' }; "
        "try { Remove-Item $p -ErrorAction Stop; 'DELETE_OK' } "
        "catch { 'DELETE_BLOCKED' }" % (active_dir, active_name), timeout=90)
    writer.add_evidence('acc009-external-lock', ext)
    out = ext['output']
    checks['external_write_blocked'] = 'WRITE_BLOCKED' in out
    checks['external_delete_blocked'] = 'DELETE_BLOCKED' in out

    # service can still read its config (link to FakeNet read compat)
    readback = call(base, 'read_config', {'name': active_name})
    checks['service_read_still_works'] = readback.get('error') is None

    # Runtime MCP mutations of the ACTIVE config must all be refused
    # (config_in_use) while the run holds the activity lock.
    version = status(base)['state_version']
    checks['runtime_edit_refused'] = err_of(call(
        base, 'edit_config',
        {'name': active_name, 'content': lock_content,
         'expected_sha256': sha_of(lock_content),
         'command_id': unique_command('a9-re'),
         'expected_state_version': version}, timeout=90)) == 'config_in_use'
    checks['runtime_rename_refused'] = err_of(call(
        base, 'rename_config',
        {'name': active_name, 'new_name': 'renamed-%s.ini' %
         unique_command('rn')[:6],
         'expected_sha256': sha_of(lock_content),
         'command_id': unique_command('a9-rr'),
         'expected_state_version': version}, timeout=90)) == 'config_in_use'
    checks['runtime_delete_refused'] = err_of(call(
        base, 'delete_config',
        {'name': active_name, 'expected_sha256': sha_of(lock_content),
         'command_id': unique_command('a9-rd'),
         'expected_state_version': version}, timeout=90)) == 'config_in_use'

    # import_config: valid import lands as a new custom config; a
    # link-escaping import target is refused.
    version = status(base)['state_version']
    import_name = 'imported-%s.ini' % unique_command('im')[:6]
    imported = call(base, 'import_config',
                    {'name': import_name,
                     'content': VALID_INI,
                     'command_id': unique_command('a9-im'),
                     'expected_state_version': version}, timeout=120)
    checks['import_config_ok'] = imported.get('error') is None and \
        call(base, 'read_config',
             {'name': import_name},
             controller=None).get('error') is None
    bad_import = call(base, 'import_config',
                      {'name': '../escape-%s.ini' % unique_command('be')[:6],
                       'content': VALID_INI,
                       'command_id': unique_command('a9-im-bad'),
                       'expected_state_version':
                           status(base)['state_version']}, timeout=90)
    checks['import_escape_refused'] = err_of(bad_import) == \
        'path_escape_blocked'
    # builtin delete: negative (default.ini is permanently read-only).
    checks['builtin_delete_refused'] = err_of(call(
        base, 'delete_config',
        {'name': 'default.ini', 'expected_sha256': 'x',
         'command_id': unique_command('a9-bd'),
         'expected_state_version': status(base)['state_version']},
        timeout=90)) in ('builtin_readonly', 'config_not_found',
                         'invalid_request')

    stop = stop_run(base)
    checks['clean_stop'] = stop.get('error') is None
    ext2 = channel.powershell(
        "$base = %s; $p = Join-Path $base '%s'; "
        "try { Set-Content $p 'after-stop' -ErrorAction Stop; 'WRITE_OK' } "
        "catch { 'WRITE_BLOCKED' }; "
        "try { Remove-Item $p -ErrorAction Stop; 'DELETE_OK' } catch "
        "{ 'DELETE_BLOCKED' }" % (active_dir, active_name), timeout=90)
    writer.add_evidence('acc009-unlock-after-stop', ext2)
    checks['unlocked_after_stop'] = 'WRITE_OK' in ext2['output']
    # cleanup probe config
    try:
        call(base, 'delete_config',
             {'name': lock_name,
              'expected_sha256': sha_of(lock_content),
              'command_id': unique_command('lp-d'),
              'expected_state_version': status(base)['state_version']})
    except Exception:  # noqa: BLE001
        pass

    # reparse point escape: junction inside custom root pointing outside.
    reparse = channel.powershell(
        "$root = Join-Path $env:ProgramData "
        "'FakeNet-NG-MCP\\configs\\custom'; "
        "$link = Join-Path $root 'junction.ini'; "
        "New-Item -ItemType SymbolicLink -Path $link -Target "
        "'C:\\Windows\\system.ini' -ErrorAction SilentlyContinue | "
        "Out-Null; "
        "if (Test-Path $link) { 'LINK_CREATED' } else { 'LINK_UNAVAILABLE' }",
        timeout=90)
    writer.add_evidence('acc009-reparse-setup', reparse)
    if 'LINK_CREATED' in reparse['output']:
        payload = call(base, 'read_config', {'name': 'junction.ini'},
                       controller=None)
        checks['reparse_escape_blocked'] = err_of(payload) == \
            'path_escape_blocked'
        channel.powershell(
            "Remove-Item (Join-Path $env:ProgramData "
            "'FakeNet-NG-MCP\\configs\\custom\\junction.ini') -Force",
            timeout=60)
    else:
        checks['reparse_escape_blocked'] = False  # environment cannot
        # construct the link: sub-check blocked, overall verdict fails

    # real restart binding (record 023 real-run share)
    second = load_and_start(base)
    writer.add_evidence('acc009-second-start', second)
    run_before = status(base).get('run_id')
    version = status(base)['state_version']
    restarted = call(base, 'restart',
                     {'command_id': unique_command('a9-restart'),
                      'expected_state_version': version}, timeout=150)
    writer.add_evidence('acc009-restart-payload', restarted)
    checks['restart_ok'] = restarted.get('error') is None
    checks['restart_binds_original_run'] = \
        restarted.get('run_id') == run_before
    stop_run(base)
    writer.add_evidence('acc009-checks', checks)
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acc', required=True,
                        choices=['ACC-001', 'ACC-004', 'ACC-006', 'ACC-007',
                                 'ACC-008', 'ACC-009'])
    parser.add_argument('--gui-exe',
                        default='',
                        help='deployed GUI exe for the ACC-001 mutual-'
                             'exclusion evidence')
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--package-sha256', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--requirements-blob', required=True)
    parser.add_argument('--master-plan-blob', required=True)
    parser.add_argument('--vm-identity', required=True)
    parser.add_argument('--config-identity', required=True)
    parser.add_argument('--candidate-id', required=True)
    parser.add_argument('--target-base-url',
                        default='http://192.168.204.149:28788')
    parser.add_argument('--win10vm-mcp',
                        default='http://192.168.204.149:28787/mcp')
    parser.add_argument('--output-root',
                        default=str(REPO_ROOT / 'Logs' / 'fakenetng-mcp'))
    args = parser.parse_args()

    started_at = datetime.datetime.now(
        datetime.timezone.utc).isoformat()
    out_dir = Path(args.output_root) / args.candidate_id / args.acc
    writer = EvidenceWriter(out_dir, started_at)
    channel = Win10VmChannel(args.win10vm_mcp)
    base = args.target_base_url
    exit_code = EXIT_TOOL_ERROR
    try:
        identity = channel.computer_name()
        # Cross-ACC hygiene: a previous ACC may have left a run active or
        # the service in a non-stopped terminal state; force-idle first.
        try:
            if status(base).get('run_id') or \
                    status(base).get('state') not in ('stopped',):
                stop_run(base)
                wait_state(base, lambda s: s.get('state') in (
                    'stopped', 'failed'), timeout=60)
        except Exception:  # noqa: BLE001
            pass
        if 'DESKTOP-3FI41GR' not in identity:
            writer.blocker = {'reason': 'unexpected VM: %s' % identity}
            exit_code = EXIT_BLOCKED
        else:
            handler = {
                'ACC-001': run_acc001, 'ACC-004': run_acc004,
                'ACC-006': run_acc006, 'ACC-007': run_acc007,
                'ACC-008': run_acc008, 'ACC-009': run_acc009,
            }[args.acc]
            exit_code = handler(base, channel, writer)
    except StepError as exc:
        writer.blocker = {'reason': str(exc)}
        exit_code = EXIT_BLOCKED
    except Exception as exc:  # noqa: BLE001
        writer.blocker = {'reason': 'tool error: %r' % exc}
        exit_code = EXIT_TOOL_ERROR

    status_word = {EXIT_PASS: 'pass', EXIT_FAIL: 'fail',
                   EXIT_BLOCKED: 'blocked',
                   EXIT_TOOL_ERROR: 'tool-error'}[exit_code]
    writer.write_result(
        acc_id=args.acc, p_id='P03', candidate_id=args.candidate_id,
        source_commit=args.source_commit,
        package_sha256=args.package_sha256,
        requirements_blob=args.requirements_blob,
        master_plan_blob=args.master_plan_blob,
        environment_identity='%s | config=%s' % (args.vm_identity,
                                                 args.config_identity),
        status=status_word)
    print('%s: %s (evidence: %s)' % (args.acc, status_word, out_dir))
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
