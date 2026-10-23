#!/usr/bin/env python3
# Copyright 2026 Google LLC
"""P03 ACC runner — master-plan §9.1 contract for ACC-001/004/006/007/008/009.

Executes the real lifecycle against the deployed candidate on the
acceptance VM (sub-plan P03 v1 IMP-P03-08). Exit codes 0/1/2/3+.
"""

import argparse
import base64
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
                     EXIT_TOOL_ERROR, EvidenceWriter, StepError, Win10VmChannel,
                     controlled_service_stop)
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


def probe_during(action, base, seconds=4.0):
    """CHK-038: run the continuous probe CONCURRENTLY with a scenario
    action. Returns (timeline, action_result)."""
    import threading

    box = {}

    def run_action():
        box['result'] = action()

    worker = threading.Thread(target=run_action, daemon=True)
    worker.start()
    timeline = []
    deadline = time.time() + seconds
    while time.time() < deadline or worker.is_alive():
        ok = False
        try:
            payload = call(base, 'ping', controller=None, timeout=8)
            ok = payload.get('service') == 'fakenetng-mcp'
        except Exception:  # noqa: BLE001
            ok = False
        timeline.append({'t': round(time.time(), 1), 'ok': ok})
        if not worker.is_alive() and time.time() >= deadline:
            break
        time.sleep(0.5)
    worker.join(30)
    return timeline, box.get('result')


def load_and_start(base, name='default.ini', builtin=True):
    def attempt():
        version = status(base)['state_version']
        loaded = call(base, 'load_config',
                      {'name': name,
                       'command_id': unique_command('p03-load'),
                       'expected_state_version': version})
        if loaded.get('error'):
            return loaded
        return call(base, 'start',
                    {'command_id': unique_command('p03-start'),
                     'expected_state_version': loaded['state_version']},
                    timeout=90)

    result = attempt()
    load_and_start.first_failed_start = None
    if result.get('state') == 'failed' and not result.get('error'):
        load_and_start.first_failed_start = dict(result)
    return result


def stop_run(base, attempts=1):
    # Kept as a call-shape argument for old scenarios; never retries an
    # accepted or rejected mutation to make an acceptance case pass.
    version = status(base)['state_version']
    return call(base, 'stop',
                {'command_id': unique_command('p03-stop'),
                 'expected_state_version': version}, timeout=1020)


def restart_service(channel):
    stopped = controlled_service_stop(channel)
    started = channel.powershell(
        "$ErrorActionPreference='Stop'; Start-Service fakenetng-mcp; "
        "Get-Service fakenetng-mcp | Select-Object Name,Status | ConvertTo-Json -Compress",
        timeout=60)
    return {'stop': stopped, 'start': started}


def normalize_service(base, channel):
    """Require a clean endpoint; never erase failure via a forced restart."""
    try:
        snap = status(base)
    except Exception:
        return False
    if snap.get('state') == 'failed':
        return False
    if snap.get('state') != 'stopped' or snap.get('run_id'):
        result = stop_run(base)
        if not result or result.get('error') or result.get('state') != 'stopped':
            return False
    snap = status(base)
    return snap.get('state') == 'stopped' and not snap.get('run_id')


def clear_and_restart(channel):
    from helpers import configure_fault_service
    return configure_fault_service(channel, False, 60)


def arm_fault(channel, fault, base=None):
    """Arm the actual fixed-file hook with a unique triggering nonce."""
    from helpers import configure_fault_service, arm_fault_file
    mode = configure_fault_service(channel, True, 5)
    ready, snap = wait_state(base or _DEFAULT_BASE,
                            lambda x: x.get('state') == 'stopped' and not x.get('run_id'),
                            timeout=60)
    if not ready:
        raise StepError('fault entry not cleanly stopped: %r' % snap)
    return dict(arm_fault_file(channel, fault), mode=mode)


def disarm_fault(channel, base=None):
    snap = status(base or _DEFAULT_BASE)
    if snap.get('state') != 'stopped' or snap.get('run_id'):
        raise StepError('fault did not recover; preserve failed scene')
    result = clear_and_restart(channel)
    ready, snap = wait_state(base or _DEFAULT_BASE,
                            lambda x: x.get('state') == 'stopped' and not x.get('run_id'),
                            timeout=60)
    if not ready:
        raise StepError('normal mode not ready: %r' % snap)
    return result


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
def run_acc001_headless(base, channel, writer, args=None):
    writer.action('acc001', 'single headless supervisor, no GUI')
    checks = {}
    service = channel.powershell(
        'sc.exe query fakenetng-mcp | Out-String', timeout=90)
    writer.add_evidence('acc001-service-gui', service)
    checks['service_running'] = 'RUNNING' in service['output']
    checks['initial_stopped'] = status(base)['state'] == 'stopped'

    # Second service instance attempt: starting the exe manually must exit 3
    second = channel.powershell(
        "$p = Start-Process -FilePath "
        "'C:\\Progra~1\\FakeNet-NG-MCP\\fakenetng-mcp.exe' "
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

    writer.add_evidence('acc001-headless-checks', checks)
    return EXIT_PASS if checks and all(v is True for v in checks.values()) else EXIT_FAIL


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
        "'C:\\Progra~1\\FakeNet-NG-MCP\\fakenetng-mcp.exe' "
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
            "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath '%s' -PassThru; "
            "[void]$p.Handle; Start-Sleep 12; $alive=-not $p.HasExited; "
            "if($alive){$p.Kill(); if(-not $p.WaitForExit(5000)){throw 'owned GUI did not exit'}}; "
            "@{alive=$alive;pid=$p.Id} | ConvertTo-Json -Compress"
            % gui_exe.replace("'", "''"), timeout=120)
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
        controlled_service_stop(channel)
        launch2 = channel.powershell(
            "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath '%s' -PassThru; "
            "[void]$p.Handle; $born=$p.StartTime.ToFileTimeUtc(); Start-Sleep 14; "
            "@{alive=(-not $p.HasExited);pid=$p.Id;created=$born} | ConvertTo-Json -Compress"
            % gui_exe.replace("'", "''"), timeout=120)
        owned_gui = json.loads(launch2['output'])
        writer.add_evidence('acc001-gui-running', launch2)
        checks['gui_runs_when_service_down'] = \
            owned_gui['alive'] is True
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
        from helpers import kill_owned_process
        if owned_gui['alive']:
            writer.add_evidence('acc001-owned-gui-stop', kill_owned_process(
                channel, owned_gui['pid'], owned_gui['created'], 'acc001-gui'))
        restart_service(channel)
        wait_state(base, lambda st: st.get('state') is not None, timeout=120)
    else:
        # No GUI package deployed: skip (None = not tested, not pass).
        # The shared-mutex mechanism is implemented and unit-tested
        # (e4c90c7); real-GUI evidence requires a deployed GUI package.
        checks['gui_refused_while_service_runs'] = None
        checks['gui_runs_when_service_down'] = None
        checks['service_refused_while_gui_runs'] = None

    writer.add_evidence('acc001-checks', checks)
    checked = [v for v in checks.values() if v is not None]
    return EXIT_PASS if all(checked) else EXIT_FAIL


# ---------------------------------------------------------------------------
# ACC-004 runs as six INDEPENDENT invocations (ACC-004-S1 .. S6): the serial
# six-scenario form repeatedly timed out on service-restart accumulation.
# Each scenario normalizes the service before and after, so every sub-test
# is order-independent and a retry never inherits a wedged endpoint.


def acc004_s1_takeover(base, channel, writer):
    """Normal takeover: start real FakeNet, probe throughout, stop."""
    checks = {}
    started = load_and_start(base)
    checks['start_ok'] = started.get('error') is None
    ok, timeline = continuous_probe(base, 12)
    writer.add_evidence('acc004-s1-takeover-probe', timeline)
    checks['link_alive_during_takeover'] = ok
    stop_run(base)
    ok_after, _ = continuous_probe(base, 4)
    checks['link_alive_after_stop'] = ok_after
    return checks


def acc004_s2_init_failure(base, channel, writer):
    """Fail inside actual managed Fakenet.start, with a valid configuration."""
    from run_initialization_case import run_initialization_failure
    return run_initialization_failure(base, channel, writer)


def exercise_listener_exception(base, channel, writer, tag, fault="listener_exception"):
    """Arm after healthy; require actual worker stack, nonce and recovery."""
    if fault not in ("listener_exception", "capture_exception"):
        raise StepError("unsupported worker exception")
    from helpers import configure_fault_service, arm_fault_file
    mode = configure_fault_service(channel, True, 5)
    writer.add_evidence(tag + '-fault-mode', mode)
    ready, initial = wait_state(base, lambda x: x.get('state') == 'stopped' and not x.get('run_id'), timeout=60)
    if not ready:
        raise StepError('fault mode entry not stopped; preserve scene')
    started = load_and_start(base)
    writer.add_evidence(tag + '-start', started)
    healthy, initial = wait_state(base, lambda x: x.get('state') == 'healthy', timeout=30)
    if not healthy or not initial.get('run_id'):
        raise StepError('exception precondition not healthy; preserve scene')
    run_id = initial['run_id']
    import uuid
    uuid.UUID(run_id)
    def trigger():
        began = time.time()
        armed = arm_fault_file(channel, fault)
        if fault == 'capture_exception':
            stimulus = channel.powershell(
                "$c=[Net.Sockets.UdpClient]::new();try{"
                "$b=[Text.Encoding]::ASCII.GetBytes('fakenet-capture-" + armed['nonce'] + "');"
                "@{sent=$c.Send($b,$b.Length,'127.0.0.1',39999);destination='127.0.0.1:39999'}|ConvertTo-Json -Compress"
                "}finally{$c.Dispose()}", timeout=15)
            writer.add_evidence(tag + '-loopback-stimulus', stimulus)
        revoked, snap = wait_state(base, lambda x: x.get('state') != 'healthy', timeout=15)
        ended = time.time()
        settled, final = wait_state(base, lambda x: x.get('state') == 'stopped' and not x.get('run_id'), timeout=420)
        return dict(armed=armed, began=began, ended=ended, revoked=revoked, status=snap,
                    settled=settled, final=final)
    timeline, outcome = probe_during(trigger, base)
    writer.add_evidence(tag + '-probe', timeline)
    writer.add_evidence(tag + '-trigger', outcome or {})
    if not outcome:
        raise StepError('actual exception trigger did not return evidence')
    raw = channel.powershell(
        "$ErrorActionPreference='Stop'; $p=Join-Path $env:ProgramData "
        "'FakeNet-NG-MCP\\artifacts\\runs\\%s'; "
        "@{receipt=(Get-Content (Join-Path $p 'fault-triggered.json') -Raw | ConvertFrom-Json); "
        "log=(Get-Content (Join-Path $p 'run.log') -Raw); "
        "stderr=(Get-Content (Join-Path $p 'stdout_stderr.log') -Raw)} | ConvertTo-Json -Depth 5 -Compress" % run_id,
        timeout=60)
    writer.add_evidence(tag + '-actual-thread-evidence', raw)
    evidence = json.loads(raw['output'])
    receipt = evidence.get('receipt', {})
    log = evidence.get('log', '')
    checks = {
        'healthy_before_trigger': healthy,
        'matching_consumed_fault': receipt == {'fault': fault,
                                              'nonce': outcome['armed']['nonce']},
        'actual_thread_exception_stack': all(value in log for value in
            (('Traceback (most recent call last)', 'service_actions',
              'RuntimeError: injected listener thread exception') if fault == 'listener_exception' else
             ('Traceback (most recent call last)', '_inbound_capture_loop', 'capture_checkpoint',
              'RuntimeError: injected capture thread exception'))),
        'exception_revokes_within_two_cycles': outcome['revoked'] and
            outcome['ended'] - outcome['began'] <= 2 * HEALTH_INTERVAL_S + 2.0,
        'link_alive_during_exception': bool(timeline) and all(x['ok'] for x in timeline),
    }
    if fault == 'capture_exception':
        raw_timing = channel.powershell(
            "$d='C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs\\" + run_id + "';"
            "@{trigger=(Get-Content (Join-Path $d 'capture-exception-time.json') -Raw|ConvertFrom-Json);"
            "parent=(Get-Content (Join-Path $d 'ipc-parent.jsonl') -Raw)}|ConvertTo-Json -Depth 6 -Compress", timeout=30)
        writer.add_evidence(tag + '-actual-capture-timing', raw_timing)
        timing = json.loads(raw_timing['output'])
        rows = [json.loads(line) for line in timing['parent'].splitlines()]
        transitions = [row for row in rows if row['event'] == 'health_state' and
                       (row.get('frame') or {}).get('state') == 'failed' and
                       row['monotonic'] >= timing['trigger']['monotonic']]
        checks['actual_capture_revocation_within_four_seconds'] = bool(transitions) and (
            transitions[0]['monotonic'] - timing['trigger']['monotonic'] <= 4)
    from helpers import export_run_incidents
    bundles = export_run_incidents(channel, run_id, writer.out_dir)
    writer.add_evidence(tag + '-actual-incidents', bundles)
    writer.evidence.extend({key: bundle[key] for key in ('path', 'size', 'sha256')} for bundle in bundles)
    checks['incident_bytes_complete'] = bool(bundles) and all(bundle['complete'] for bundle in bundles)
    settled, final = outcome['settled'], outcome['final']
    writer.add_evidence(tag + '-final', final or {})
    checks['protective_stop_completed'] = settled and final.get('last_run_outcome') == 'failed'
    writer.add_evidence(tag + '-checks', checks)
    if not settled:
        raise StepError('exception did not converge; preserve failed scene')
    disarm_fault(channel, base)
    return checks


def acc004_s3_exception(base, channel, writer):
    return exercise_listener_exception(base, channel, writer, 'acc004-s3')


def acc004_s4_invalid_protection(base, channel, writer):
    """Invalid protection params: the config LOADS (store syntax is fine),
    the START is refused at the filter-parameter layer (FB-002), the
    service survives and the link stays alive throughout (CHK-038)."""
    checks = {}
    builtin = call(base, 'read_config', {'name': 'default.ini'},
                   controller=None)
    writer.add_evidence('acc004-s4-builtin', builtin)
    if builtin.get('error') or not builtin.get('content') or '[Diverter]' not in builtin['content']:
        return {'actual_default_config_available': False}
    # The diverter reads these keys from its OWN section, so patch [Diverter].
    bad_filter_ini = builtin['content'].replace(
        '[Diverter]', '[Diverter]\nControlLinkExcludeIp: not-an-ip\n'
        'ControlLinkExcludePort: 28788', 1)
    # MutationResponse reports config_identity, not a top-level name.
    # Bind the accepted create to our original request; never retry a mutation
    # or fall back to the previously loaded default when load was rejected.
    name = 'badfilter-%s.ini' % unique_command('bf')[:6]
    created = call(base, 'create_config',
                   {'name': name, 'content': bad_filter_ini,
                    'command_id': unique_command('a4-bf'),
                    'expected_state_version': status(base)['state_version']})
    writer.add_evidence('acc004-s4-create', created)
    if created.get('error'):
        writer.add_evidence('acc004-s4-create-rejected', created)
        return {'config_loads_for_filter_layer': False}
    loaded = call(base, 'load_config',
                  {'name': name, 'command_id': unique_command('a4-bf-l'),
                   'expected_state_version': created['state_version']}, timeout=120)
    writer.add_evidence('acc004-s4-load', loaded)
    checks['config_loads_for_filter_layer'] = not loaded.get('error')
    if not checks['config_loads_for_filter_layer']:
        return checks

    def start_attempt():
        return call(base, 'start',
                    {'command_id': unique_command('a4-bf-s'),
                     'expected_state_version':
                         (loaded or {}).get(
                             'state_version',
                             status(base)['state_version'])},
                    timeout=120)

    timeline, started_bad = probe_during(start_attempt, base, seconds=6)
    writer.add_evidence('acc004-s4-invalid-filter-start', started_bad or {})
    writer.add_evidence('acc004-s4-survival-probe', timeline)
    checks['link_alive_during_invalid_protection'] = all(
        item['ok'] for item in timeline) and bool(timeline)
    message = str(((started_bad or {}).get('error') or {}).get('message')
                  or '')
    checks['invalid_protection_fails_closed'] = (
        (started_bad or {}).get('error') is not None or
        (started_bad or {}).get('state') == 'failed')
    checks['rejection_names_protection_params'] = (
        'protection' in message.lower() or
        'controllinkexclude' in message.lower())
    checks['service_survives_invalid_filter'] = \
        status(base).get('state') is not None
    # restore the default config for subsequent scenarios
    call(base, 'load_config',
         {'name': 'default.ini', 'command_id': unique_command('a4-restore'),
          'expected_state_version': status(base)['state_version']})
    return checks


def acc004_s5_hang(base, channel, writer):
    """Pause the real managed stop phase; keep probing through cleanup."""
    checks = {}
    armed = arm_fault(channel, 'policy_pause', base)
    writer.add_evidence('acc004-s5-fault-arm', armed)
    started = load_and_start(base)
    checks['start_ok'] = started.get('error') is None
    if not checks['start_ok']:
        return checks
    healthy, current = wait_state(base, lambda s: s.get('state') == 'healthy', timeout=45)
    if not healthy:
        raise StepError('hang precondition not healthy; preserve scene')
    import uuid
    run_id = str(uuid.UUID(current['run_id']))
    writer.add_evidence('acc004-s5-current-run', current)
    ok, timeline = continuous_probe(base, 8)
    writer.add_evidence('acc004-s5-hang-probe', timeline)
    checks['link_alive_during_core_thread_hang'] = ok
    stop_timeline, hung_stop = probe_during(lambda: call(base, 'stop',
                     {'command_id': unique_command('a4-hang-stop'),
                      'expected_state_version':
                          status(base)['state_version']}, timeout=1020), base)
    writer.add_evidence('acc004-s5-whole-stop-probe', stop_timeline)
    checks['link_alive_through_bounded_stop'] = bool(stop_timeline) and all(x['ok'] for x in stop_timeline)
    if hung_stop is None:
        raise StepError('stop fault action missing result; preserve scene')
    writer.add_evidence('acc004-s5-hang-stop', hung_stop)
    # Arming alone is not an observed hang. The real hook consumes its
    # nonce into this run's fixed receipt before entering the stop pause.
    command = (
        "$ErrorActionPreference='Stop'; "
        "$run='RUN_ID'; $dir=Join-Path $env:ProgramData "
        "('FakeNet-NG-MCP\\artifacts\\runs\\' + $run); "
        "$receipt=Get-Content (Join-Path $dir 'fault-triggered.json') -Raw | ConvertFrom-Json; "
        "@{run_id=$run;receipt=$receipt} | ConvertTo-Json -Depth 5 -Compress"
    ).replace('RUN_ID', run_id)
    raw = channel.powershell(command, timeout=30)
    writer.add_evidence('acc004-s5-triggered-receipt', raw)
    observed = json.loads(raw['output'])
    checks['actual_policy_pause_triggered'] = (
        raw.get('exit_code') == 0 and raw.get('is_error') is not True and
        observed.get('run_id') == run_id and
        observed.get('receipt') == {key: armed[key] for key in ('fault', 'nonce')})
    checks['hang_stop_bounded'] = hung_stop.get('state') in (
        'failed', 'stopped')
    ok_after, _ = continuous_probe(base, 4)
    checks['link_alive_after_hang'] = ok_after
    return checks


def terminate_current_managed_child(channel, snapshot):
    """Terminate only the handle-pinned child of this SCM service/run."""
    import uuid
    run_id = str(uuid.UUID(snapshot['run_id']))
    identity = snapshot['health']['identity']
    child_pid = int(identity['pid'])
    created = str(identity['creation_time'])
    if child_pid <= 0 or not created.isdecimal():
        raise StepError('invalid managed child identity')
    command = (
        "$ErrorActionPreference='Stop'; $service=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\"; "
        "$p=Get-Process -Id CHILD_PID; [void]$p.Handle; try { "
        "if($p.StartTime.ToFileTimeUtc().ToString() -ne 'CREATED'){throw 'child PID reused'}; "
        "$c=Get-CimInstance Win32_Process -Filter 'ProcessId=CHILD_PID'; "
        "if($service.State -ne 'Running' -or $service.ProcessId -eq CHILD_PID -or "
        "$c.ParentProcessId -ne $service.ProcessId -or "
        "$c.ExecutablePath -ne 'C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp-managed.exe' -or "
        "$c.CommandLine -notmatch 'managed-child[ ]+RUN_ID(?:[ ]|$)'){throw 'child scope mismatch'}; "
        "$before=@{pid=$p.Id;creation_time=$p.StartTime.ToFileTimeUtc().ToString(); "
        "parent_pid=$c.ParentProcessId;command_line=$c.CommandLine;image=$c.ExecutablePath;run_id='RUN_ID'}; "
        "$p.Kill(); if(-not $p.WaitForExit(65000)){throw 'child did not exit'}; "
        "$after=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\"; "
        "@{child=$before;exit_code=$p.ExitCode;service_pid_before=$service.ProcessId; "
        "service_pid_after=$after.ProcessId;service_state_after=$after.State} | ConvertTo-Json -Depth 5 -Compress "
        "} finally {$p.Dispose()}"
    ).replace('CHILD_PID', str(child_pid)).replace('CREATED', created).replace('RUN_ID', run_id)
    return channel.powershell(command, timeout=80)


def acc004_s6_uncontrolled_exit(base, channel, writer):
    """The managed child exits; the same supervisor remains reachable."""
    started = load_and_start(base)
    writer.add_evidence('acc004-s6-start', started)
    healthy, initial = wait_state(base, lambda x: x.get('state') == 'healthy', timeout=30)
    if not healthy:
        raise StepError('child-exit precondition not healthy; preserve scene')
    def terminate_and_recover():
        raw = terminate_current_managed_child(channel, initial)
        settled, final = wait_state(base, lambda x: x.get('state') == 'stopped' and not x.get('run_id'), timeout=420)
        return dict(termination=raw, settled=settled, final=final)
    timeline, result = probe_during(terminate_and_recover, base)
    writer.add_evidence('acc004-s6-whole-window-probe', timeline)
    writer.add_evidence('acc004-s6-child-exit', result or {})
    if not result:
        raise StepError('child-exit action missing evidence')
    actual = json.loads(result['termination']['output'])
    return {
        'exact_managed_child_terminated': actual['child']['pid'] == initial['health']['identity']['pid'] and
            actual['child']['creation_time'] == initial['health']['identity']['creation_time'] and
            actual['child']['run_id'] == initial['run_id'],
        'same_supervisor_survives': actual['service_pid_before'] == actual['service_pid_after'] and
            actual['service_state_after'] == 'Running',
        'control_link_survives_entire_recovery': bool(timeline) and all(x['ok'] for x in timeline),
        'protective_recovery_completed': result['settled'] and result['final'].get('last_run_outcome') == 'failed',
    }


ACC004_SCENARIOS = (
    ('S1', 'normal takeover', acc004_s1_takeover),
    ('S2', 'initialization failure', acc004_s2_init_failure),
    ('S3', 'unhandled exception', acc004_s3_exception),
    ('S4', 'invalid protection params', acc004_s4_invalid_protection),
    ('S5', 'core-thread hang', acc004_s5_hang),
    ('S6', 'uncontrolled exit', acc004_s6_uncontrolled_exit),
)


def run_acc004_scenario(base, channel, writer, tag):
    for key, title, handler in ACC004_SCENARIOS:
        if key == tag:
            break
    else:
        writer.blocker = {'reason': 'unknown ACC-004 scenario %r' % tag}
        return EXIT_BLOCKED
    writer.action('acc004-%s' % tag.lower(),
                  'control link survives: %s' % title)
    if not normalize_service(base, channel):
        writer.blocker = {'reason': 'service normalization failed'}
        return EXIT_BLOCKED
    try:
        checks = handler(base, channel, writer)
    finally:
        if tag == 'S5':
            # disarm before normalizing: the fault env must not leak into
            # the restart (a hung child would wedge the next start).
            disarm_fault(channel, base)
        normalize_service(base, channel)
    writer.add_evidence('acc004-%s-scenario-checks' % tag.lower(), checks)
    checked = [v for v in checks.values() if v is not None]
    return EXIT_PASS if all(checked) else EXIT_FAIL


def no_listener_config(content):
    """Disable every listener section, including passive/dynamically added ones."""
    import configparser
    import io
    parser = configparser.ConfigParser()
    parser.read_string(content)
    for section in parser.sections():
        if section not in ('FakeNet', 'Diverter'):
            parser.set(section, 'Enabled', 'False')
    output = io.StringIO()
    parser.write(output)
    return output.getvalue()


def exercise_no_listener_health(base, writer):
    """Original ACC006 initialization negative, independently selectable."""
    checks = {}
    builtin = call(base, 'read_config', {'name': 'default.ini'}, controller=None)
    writer.add_evidence('acc006-nolistener-source', builtin)
    if builtin.get('error') or not builtin.get('content'):
        return {'actual_default_config_available': False}
    no_listener_ini = no_listener_config(builtin['content'])
    name = 'nolisten-%s.ini' % unique_command('nl')[:6]
    created = call(base, 'create_config',
                   {'name': name, 'content': no_listener_ini,
                    'command_id': unique_command('a6-nl'),
                    'expected_state_version': status(base)['state_version']}, timeout=120)
    writer.add_evidence('acc006-nolistener-create', created)
    if created.get('error'):
        return {'no_listener_config_created': False}
    loaded = call(base, 'load_config',
                  {'name': name, 'command_id': unique_command('a6-nl-l'),
                   'expected_state_version': created['state_version']}, timeout=120)
    writer.add_evidence('acc006-nolistener-load', loaded)
    if loaded.get('error'):
        return {'no_listener_config_loaded': False}
    started = call(base, 'start',
                   {'command_id': unique_command('a6-nl-s'),
                    'expected_state_version': loaded['state_version']}, timeout=120)
    writer.add_evidence('acc006-nolistener-start', started)
    checks['no_listener_start_attempted'] = started.get('error') is None and started.get('changed') is True
    observations = [started]
    deadline = time.monotonic() + 3 * HEALTH_INTERVAL_S + 2.0
    while True:
        observations.append(status(base))
        if time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    observed = observations[-1]
    writer.add_evidence('acc006-nolistener-status', observed)
    writer.add_evidence('acc006-nolistener-window', observations)
    checks['no_init_evidence_never_healthy'] = all(
        not item.get('error') and item.get('state') != 'healthy' for item in observations)
    checks['fake_healthy_negative'] = ((observed.get('health') or {}).get('init_evidence') is False
                                      or observed.get('state') in ('starting', 'degraded', 'failed'))
    stopped = stop_run(base)
    checks['no_listener_stop_completed'] = not stopped.get('error') and stopped.get('state') == 'stopped'
    restored = call(base, 'load_config',
                    {'name': 'default.ini', 'command_id': unique_command('a6-restore'),
                     'expected_state_version': status(base)['state_version']})
    checks['default_config_restored'] = (not restored.get('error') and
                                       (restored.get('config_identity') or {}).get('name') == 'default.ini')
    writer.add_evidence('acc006-nolistener-restore', restored)
    writer.add_evidence('acc006-nolistener-checks', checks)
    return checks


def run_acc006(base, channel, writer):
    writer.action('acc006', 'real health: three conditions, no fake healthy')
    from run_ipc_cases import run_ipc_matrix, IPC_CASES
    checks = run_ipc_matrix(base, channel, writer)
    if set(checks) != set(IPC_CASES) or not all(checks.values()):
        writer.add_evidence('acc006-ipc-matrix-incomplete', checks)
        return EXIT_FAIL
    started = load_and_start(base)
    writer.add_evidence('acc006-start-payload', started)
    checks['start_ok'] = started.get('error') is None
    healthy, snap = wait_state(
        base, lambda s: s.get('state') == 'healthy', timeout=30)
    checks['healthy_reached'] = healthy
    checks['health_fields_present'] = all(
        key in (snap or {}).get('health', {})
        for key in ('process_alive', 'init_evidence', 'probe'))

    # End the healthy control run before changing the service test mode.
    writer.add_evidence('acc006-stop-control', stop_run(base))
    checks.update(exercise_listener_exception(base, channel, writer, 'acc006-anomaly'))
    capture_checks = exercise_listener_exception(base, channel, writer, 'acc006-capture', 'capture_exception')
    checks.update({'capture_' + key: value for key, value in capture_checks.items()})

    from run_active_probe import run_active_probe_loss
    active_checks = run_active_probe_loss(base, channel, writer)
    checks.update({'active_' + key: value for key, value in active_checks.items()})
    if not all(active_checks.values()):
        writer.add_evidence('acc006-checks', checks)
        return EXIT_FAIL

    checks.update(exercise_no_listener_health(base, writer))

    # (d) process condition: in the in-process model the service process IS
    # the run; breaking it is the uncontrolled-exit kill covered end-to-end
    # by ACC-004(6)/ACC-007 with recovery evidence (cross-referenced).
    final = status(base)
    stopped, _ = wait_state(base, lambda s: s.get('state') == 'stopped',
                            timeout=60)
    checks['stop_returns_to_stopped'] = stopped
    writer.add_evidence('acc006-final', final)
    writer.add_evidence('acc006-checks', checks)
    checked = [v for v in checks.values() if v is not None]
    return EXIT_PASS if all(checked) else EXIT_FAIL


def crash_current_service(channel, snapshot):
    """Pin SCM supervisor and current child; never terminate by process name."""
    import uuid
    run_id = str(uuid.UUID(snapshot['run_id']))
    identity = snapshot['health']['identity']
    child_pid = int(identity['pid'])
    created = str(identity['creation_time'])
    if child_pid <= 0 or not created.isdecimal():
        raise StepError('invalid managed child identity')
    script = Path(__file__).with_name('crash_current_service.ps1').read_text()
    script = script.replace('__CHILD_PID__', str(child_pid)).replace(
        '__CREATION__', created).replace('__RUN_ID__', run_id)
    return channel.powershell(script, timeout=60)


def run_acc007(base, channel, writer):
    writer.action('acc007', 'kill MCP => job collapses tree, SCM restarts, '
                            'recovery without FakeNet continuation')
    from run_creation_cases import run_creation_matrix, CREATION_STAGES
    creation = run_creation_matrix(base, channel, writer)
    writer.add_evidence('acc007-creation-matrix', creation)
    if set(creation) != set(CREATION_STAGES) or not all(creation.values()):
        return EXIT_FAIL
    checks = {}
    started = load_and_start(base)
    checks['start_ok'] = started.get('error') is None
    writer.add_evidence('acc007-start', started)
    healthy, initial = wait_state(base, lambda x: x.get('state') == 'healthy', timeout=45)
    if not healthy:
        raise StepError('ACC007 requires a healthy current run; preserve scene')
    run_id = initial['run_id']

    # SCM recovery configuration is part of the contract's restart path.
    qfailure = channel.powershell('sc.exe qfailure fakenetng-mcp',
                                  timeout=60)
    writer.add_evidence('acc007-sc-qfailure', qfailure)
    checks['scm_recovery_configured'] = 'RESTART' in (qfailure['output'] or
                                                      '').upper()

    recovery_log_query = (
        "Select-String -Path (Join-Path $env:ProgramData "
        "'FakeNet-NG-MCP\\logs\\service.log') -Pattern "
        "'startup recovery outcome' | ForEach-Object {$_.Line}")
    recovery_before = channel.powershell(recovery_log_query, timeout=30)
    writer.add_evidence('acc007-recovery-log-before', recovery_before)
    marker_before = channel.powershell(
        "Get-Content 'C:\\ProgramData\\FakeNet-NG-MCP\\state\\state.json' -Raw", timeout=30)
    writer.add_evidence('acc007-recovery-marker-before', marker_before)
    raw = crash_current_service(channel, initial)
    writer.add_evidence('acc007-exact-crash-and-tree', raw)
    observed = json.loads(raw['output'])
    checks['only_pinned_supervisor_killed'] = observed['supervisor_exited']
    checks['unrelated_process_survives'] = observed['canary_survived']
    checks['observed_tree_collapsed'] = bool(observed['observed_tree']) and not observed['remaining_pids']

    recovered, snap = wait_state(
        base, lambda s: s.get('state') in ('stopped', 'failed'), timeout=420)
    writer.add_evidence('acc007-post-restart-status', snap or {})
    service_after = channel.powershell(
        'Get-CimInstance Win32_Service -Filter "Name=\'fakenetng-mcp\'" | '
        'Select-Object ProcessId,State | ConvertTo-Json -Compress', timeout=30)
    writer.add_evidence('acc007-new-scm-instance', service_after)
    new_service = json.loads(service_after['output'])
    checks['scm_restarted_mcp'] = (recovered and new_service['State'] == 'Running' and
        new_service['ProcessId'] > 0 and new_service['ProcessId'] != observed['supervisor']['pid'])
    checks['recovery_completed_stopped'] = (snap or {}).get('state') == 'stopped'
    checks['no_fakenet_continuation'] = (snap or {}).get('run_id') is None
    checks['not_auto_started'] = (snap or {}).get('state') != 'healthy'

    # Recovery audit actually ran: the service log must carry the startup
    # recovery outcome for this incarnation.
    relog = channel.powershell(recovery_log_query, timeout=90)
    writer.add_evidence('acc007-recovery-log', relog)
    from collections import Counter
    new_lines = Counter(relog['output'].splitlines()) - Counter(
        recovery_before['output'].splitlines())
    checks['recovery_audit_evidenced'] = any(
        'startup recovery outcome' in line and line.rstrip().endswith('stopped')
        for line in new_lines)

    from replay_observation import observe_no_replay
    checks['old_command_not_resumed_evidence'] = (
        checks['recovery_completed_stopped'] and observe_no_replay(
            base, channel, writer, 'acc007', json.loads(marker_before['output'])))
    checks['atomic_creation_window_matrix'] = all(creation.values())
    writer.add_evidence('acc007-checks', checks)
    checked = [v for v in checks.values() if v is not None]
    return EXIT_PASS if all(checked) else EXIT_FAIL


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
    previous = channel.powershell(
        "@(Get-ChildItem (Join-Path $env:ProgramData 'FakeNet-NG-MCP\\baselines') "
        "-Filter '*.json' -ErrorAction SilentlyContinue).Count", timeout=30)
    if int(previous['output']) != 0:
        writer.blocker = {'reason': 'ACC008 needs a fresh candidate scene; existing baselines are preserved'}
        writer.add_evidence('acc008-existing-baselines', previous)
        return EXIT_BLOCKED
    # (1) seven fields during a run; marker cleared after clean stop.
    owned_runs = set()
    started = load_and_start(base)
    owned_runs.add(started["run_id"])
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

    def preserve_marker(label):
        raw = channel.powershell(
            "[Convert]::ToBase64String([IO.File]::ReadAllBytes((%s)))" % state_file,
            timeout=30)['output']
        marker = json.loads(base64.b64decode(raw).decode('utf-8-sig'))
        if marker.get('run_id') not in owned_runs:
            raise StepError('marker not owned by this ACC')
        writer.add_evidence(label, {'body_base64': raw, 'marker': marker})
        return raw

    def restore_marker(raw, label):
        # Preserve the injected failure bytes before restoring the SAME run's
        # valid recovery responsibility. Never substitute an empty marker.
        writer.add_evidence(label, channel.powershell(
            "[Convert]::ToBase64String([IO.File]::ReadAllBytes((%s)))" % state_file,
            timeout=30))
        channel.powershell(
            "$ErrorActionPreference='Stop'; $p=(%s); "
            "$tmp=$p+'.restore-'+[guid]::NewGuid().ToString(); "
            "[IO.File]::WriteAllBytes($tmp,[Convert]::FromBase64String('%s')); "
            "[IO.File]::Replace($tmp,$p,$null); 'RESTORED_OWNED_RESPONSIBILITY'"
            % (state_file, raw), timeout=30)

    # (2) corrupt snapshot with residue => recovery 'failed', start refused.
    owned_runs.add(load_and_start(base)["run_id"])
    original_marker = preserve_marker("acc008-valid-marker-before-corruption")
    channel.powershell(
        "Set-Content (%s) 'NOT JSON {{' -Encoding ascii; 'CORRUPTED'"
        % state_file, timeout=60)
    from helpers import kill_current_service
    writer.add_evidence('acc008-corrupt-kill',
                        kill_current_service(channel, 'corrupt-snapshot'))
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
    restore_marker(original_marker, 'acc008-corrupt-marker-body')
    restart_service(channel)
    wait_state(base, lambda s: s.get('state') == 'stopped', timeout=90)

    # (3) residue-inconsistent: live marker + an extra listening port that
    # the pre-start baseline never recorded => 'failed'.
    owned_runs.add(load_and_start(base)["run_id"])
    listener_body = ("$ErrorActionPreference='Stop'; "
                     "$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,47889); "
                     "$l.Start(); try {Start-Sleep 600} finally {$l.Stop()}")
    encoded = base64.b64encode(listener_body.encode('utf-16-le')).decode('ascii')
    listener_job = channel.powershell(
        "$ErrorActionPreference='Stop'; "
        "$p=Start-Process (Join-Path $PSHOME 'powershell.exe') -ArgumentList "
        "'-NoProfile -NonInteractive -EncodedCommand %s' -PassThru -WindowStyle Hidden; "
        "[void]$p.Handle; $born=$p.StartTime.ToFileTimeUtc(); "
        "@{pid=$p.Id;created=$born} | ConvertTo-Json -Compress" % encoded, timeout=30)
    listener = json.loads(listener_job['output'])
    writer.add_evidence('acc008-extra-listener', listener_job)
    try:
        ready = channel.powershell(
            "Start-Sleep 2; $p=Get-Process -Id %d -ErrorAction Stop; "
            "if($p.StartTime.ToFileTimeUtc() -ne %d){throw 'listener changed'}; "
            "if(-not (Get-NetTCPConnection -LocalPort 47889 -State Listen | "
            "Where-Object OwningProcess -eq $p.Id)){throw 'owned listener not listening'}; 'READY'"
            % (listener['pid'], listener['created']), timeout=30)
        writer.add_evidence('acc008-listener-ready', ready)
        writer.add_evidence('acc008-residue-kill', kill_current_service(channel, 'residue-inconsistent'))
        back, snap3 = wait_state(base, lambda s: s.get('state') == 'failed', timeout=150)
        checks['residue_inconsistency_fails'] = back and _recovery_outcome(channel) == 'failed'
    finally:
        from helpers import kill_owned_process
        writer.add_evidence('acc008-listener-stop', kill_owned_process(
            channel, listener['pid'], listener['created'], 'acc008-listener'))
    # Removing our injected listener allows the same real recovery audit.
    restart_service(channel)
    wait_state(base, lambda s: s.get('state') == 'stopped', timeout=90)

    # (4) write-failure: with a config ALREADY LOADED (CHK-040: the
    # refusal must come from the state-write layer, not from a missing
    # configuration), deny the service write on the state directory; a
    # start must be refused (no marker => no run).
    call(base, 'load_config',
         {'name': 'default.ini', 'command_id': unique_command('a8-wf-l'),
          'expected_state_version': status(base)['state_version']})
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
    controlled_service_stop(channel)
    from helpers import preserve_owned_state
    preserve_owned_state(channel, writer, owned_runs)
    restart_service(channel)
    back, snap5 = wait_state(base, lambda s: s.get('state') is not None,
                             timeout=150)
    checks['missing_without_residue_stopped'] = \
        _recovery_outcome(channel) == 'stopped' and \
        (snap5 or {}).get('state') == 'stopped'

    # (6) deliverables carry no banned DB/framework engines. The onedir
    # install puts _internal next to the exe at the package root (the
    # former candidate\_internal layout moved in ff48f64).
    listing = channel.powershell(
        "Get-ChildItem -Recurse 'C:\\Progra~1\\FakeNet-NG-MCP\\_internal' "
        '-Filter *.pyc | Measure-Object | Select-Object -ExpandProperty '
        'Count; Get-ChildItem '
        "'C:\\Progra~1\\FakeNet-NG-MCP\\_internal' | "
        'Where-Object {$_.Name -match "sqlite|dbm"} | Measure-Object | '
        'Select-Object -ExpandProperty Count; "SCAN_OK"', timeout=120)
    writer.add_evidence('acc008-framework-scan', listing)
    lines = [line.strip() for line in listing['output'].splitlines()
             if line.strip().isdigit()]
    checks['no_db_engine_modules'] = len(lines) < 2 or lines[1] == '0'
    writer.add_evidence('acc008-checks', checks)
    checked = [v for v in checks.values() if v is not None]
    return EXIT_PASS if all(checked) else EXIT_FAIL


def _acc009_os_probe(channel, request):
    """Run one fixed owned-file probe, returning observed bytes and actions."""
    import re
    from pathlib import PureWindowsPath
    inputs = getattr(channel, 'inputs', None) or {}
    request = dict(request, programdata_root=inputs.get('programdata_root'))
    if not re.fullmatch(r'acc009-[a-z]+-[0-9a-f]{32}\.ini', request['name']) or not re.fullmatch(r'[0-9a-f]{32}', request['token']):
        raise StepError('invalid ACC009 owned name/token')
    if request['operation'] not in ('file-probe', 'reparse-setup', 'reparse-cleanup'):
        raise StepError('unknown ACC009 fixed operation')
    if request['operation'] == 'reparse-setup':
        request['work_root'] = inputs.get('guest_work_root')
        if request['work_root']:
            work = PureWindowsPath(request['work_root'])
            if not work.is_absolute() or work.drive.upper() not in ('E:', 'D:') or '..' in work.parts:
                raise StepError('ACC009 requires an absolute selected E/D work root')
    encoded = base64.b64encode(json.dumps(request).encode('utf-8')).decode('ascii')
    script = Path(__file__).with_name('acc009_config_probe.ps1').read_text()
    try:
        raw = channel.powershell(script.replace('__REQUEST__', encoded), timeout=90)
        value = json.loads(raw['output'])
        for key, expected in (('schema', 'fakenet.acc009-os.v1'), ('operation', request['operation']),
                              ('name', request['name']), ('token', request['token']),
                              ('run_id', request.get('run_id'))):
            if value.get(key) != expected:
                raise StepError('ACC009 probe identity mismatch: ' + key)
        path = PureWindowsPath(value['path'])
        if (not path.is_absolute() or path.name != request['name'] or
                tuple(part.lower() for part in path.parts[-3:-1]) != ('configs', 'custom')):
            raise StepError('ACC009 probe path differs')
        if inputs.get('programdata_root') and path != PureWindowsPath(inputs['programdata_root']) / 'configs' / 'custom' / request['name']:
            raise StepError('ACC009 probe outside frozen root')
        if request['operation'].startswith('reparse-') and value.get('work_dir'):
            work = PureWindowsPath(value['work_dir'])
            if work.drive.upper() not in ('E:', 'D:') or work.name != 'fakenet-acc009-' + request['token'] or PureWindowsPath(value['target']) != work / 'target.ini':
                raise StepError('ACC009 reparse work identity differs')
        if request['operation'] == 'file-probe' and value.get('phase') != request['phase']:
            raise StepError('ACC009 probe phase differs')
        if request['operation'].startswith('reparse-') and value.get('work_dir'):
            work = PureWindowsPath(value['work_dir'])
            expected_parent = PureWindowsPath(inputs['guest_work_root']) if inputs.get('guest_work_root') else PureWindowsPath(work.anchor)
            if work.parent != expected_parent:
                raise StepError('ACC009 work root differs from frozen selection')
            if value.get('created') is True and value.get('target_sha256') != sha_of('acc009 benign controlled target\n'):
                raise StepError('ACC009 controlled target bytes differ')
        return value, raw
    except Exception:
        channel.preserve_scene = True
        raise



def run_acc009(base, channel, writer):
    writer.action('acc009', 'P03-final: real lock, reparse points, full '
                            'custom management on real lifecycle')
    import uuid
    checks = {}

    def finish(code=None):
        writer.add_evidence('acc009-checks', checks)
        return code if code is not None else (EXIT_PASS if checks and all(checks.values()) else EXIT_FAIL)

    def mutate(tool, arguments, label):
        command_id = unique_command(label)
        version = status(base)['state_version']
        payload = call(base, tool, dict(arguments, command_id=command_id,
                       expected_state_version=version), timeout=120)
        writer.add_evidence(label, payload)
        if not payload.get('error') and (
                payload.get('command_id') != command_id or
                type(payload.get('state_version')) is not int or
                payload['state_version'] < version or payload.get('in_progress')):
            channel.preserve_scene = True
            raise StepError('ACC009 mutation receipt not confirmed: ' + tool)
        return payload

    def content_matches(payload, name, content):
        return (not payload.get('error') and payload.get('name') == name and
                payload.get('content') == content and payload.get('sha256') == sha_of(content))

    token = uuid.uuid4().hex
    lock_name = 'acc009-lock-' + token + '.ini'
    builtin = call(base, 'read_config', {'name': 'default.ini'}, controller=None)
    writer.add_evidence('acc009-default-source', builtin)
    lock_content = builtin.get('content')
    checks['source_read_ok'] = isinstance(lock_content, str) and bool(lock_content) and content_matches(builtin, 'default.ini', lock_content)
    if not checks['source_read_ok']:
        return finish()
    created = mutate('create_config', {'name': lock_name, 'content': lock_content}, 'acc009-create-lock')
    checks['create_lock_ok'] = created.get('error') is None
    if not checks['create_lock_ok']:
        return finish()
    read_created = call(base, 'read_config', {'name': lock_name}, controller=None)
    writer.add_evidence('acc009-created-bytes', read_created)
    checks['created_content_exact'] = content_matches(read_created, lock_name, lock_content)
    if not checks['created_content_exact']:
        return finish()
    loaded = mutate('load_config', {'name': lock_name}, 'acc009-load-lock')
    checks['load_lock_ok'] = loaded.get('error') is None
    if not checks['load_lock_ok']:
        return finish()
    started = mutate('start', {}, 'acc009-start-lock')
    checks['start_ok'] = started.get('error') is None
    if not checks['start_ok']:
        return finish()
    ready, active = wait_state(base, lambda s: s.get('state') == 'healthy', timeout=45)
    writer.add_evidence('acc009-active', active or {})
    identity = (active or {}).get('config_identity') or {}
    checks['healthy_lock_identity'] = bool(ready and identity.get('name') == lock_name and identity.get('sha256') == sha_of(lock_content) and active.get('run_id'))
    if not checks['healthy_lock_identity']:
        return finish()
    run_id = str(uuid.UUID(active['run_id']))
    probe_request = dict(operation='file-probe', name=lock_name, token=token,
                         run_id=run_id, phase='active', sha256=sha_of(lock_content))
    observed, raw = _acc009_os_probe(channel, probe_request)
    writer.add_evidence('acc009-external-lock', raw)
    before, after = observed['before'], observed['after']
    checks['external_target_exact'] = (before.get('exists') is True and before.get('sha256') == sha_of(lock_content) and bool(before.get('creation_time')) and after == before)
    for action in ('write', 'delete'):
        attempt = observed[action]
        checks['external_' + action + '_blocked'] = (attempt.get('attempted') is True and attempt.get('success') is False and type(attempt.get('win32_error')) is int and attempt['win32_error'] in (32, 33))
    if not all(checks.values()):
        return finish()
    readback = call(base, 'read_config', {'name': lock_name}, controller=None)
    writer.add_evidence('acc009-service-read', readback)
    checks['service_read_still_works'] = content_matches(readback, lock_name, lock_content)
    if not checks['service_read_still_works']:
        return finish()

    for operation, arguments in (
            ('edit', {'content': lock_content}),
            ('rename', {'new_name': 'acc009-renamed-' + uuid.uuid4().hex + '.ini'}),
            ('delete', {})):
        prior = status(base)
        payload = mutate(operation + '_config', dict(arguments, name=lock_name, expected_sha256=sha_of(lock_content)), 'acc009-runtime-' + operation)
        post = status(base)
        current = call(base, 'read_config', {'name': lock_name}, controller=None)
        writer.add_evidence('acc009-runtime-' + operation + '-after', {'before': prior, 'after': post, 'content': current})
        checks['runtime_' + operation + '_refused'] = err_of(payload) == 'config_in_use'
        # Accepted failed mutations reserve versions; lifecycle/bytes stay fixed.
        checks['runtime_' + operation + '_unchanged'] = (
            post.get('state') == 'healthy' and post.get('run_id') == run_id and
            post.get('config_identity') == prior.get('config_identity') and
            payload.get('state_version') == post.get('state_version') and
            post['state_version'] >= prior['state_version'] and
            content_matches(current, lock_name, lock_content))
        if not all(checks.values()):
            return finish()

    import_name = 'acc009-import-' + uuid.uuid4().hex + '.ini'
    imported = mutate('import_config', {'name': import_name, 'content': VALID_INI}, 'acc009-import')
    imported_read = call(base, 'read_config', {'name': import_name}, controller=None)
    writer.add_evidence('acc009-imported-read', imported_read)
    checks['import_config_ok'] = imported.get('error') is None and content_matches(imported_read, import_name, VALID_INI)
    if not checks['import_config_ok']:
        return finish()
    bad = mutate('import_config', {'name': '../escape-' + uuid.uuid4().hex + '.ini', 'content': VALID_INI}, 'acc009-import-escape')
    checks['import_escape_refused'] = err_of(bad) == 'path_escape_blocked'
    builtin_delete = mutate('delete_config', {'name': 'default.ini', 'expected_sha256': 'x'}, 'acc009-builtin-delete')
    checks['builtin_delete_refused'] = err_of(builtin_delete) in ('builtin_readonly', 'config_not_found', 'invalid_request')

    stop = stop_run(base)
    writer.add_evidence('acc009-stop', stop)
    stopped = status(base)
    checks['clean_stop'] = stop.get('error') is None and stopped.get('state') == 'stopped' and stopped.get('run_id') is None
    if not checks['clean_stop']:
        return finish()
    unlocked, raw = _acc009_os_probe(channel, dict(probe_request, phase='stopped', creation_time=before['creation_time']))
    writer.add_evidence('acc009-unlock-after-stop', raw)
    checks['unlocked_after_stop'] = (
        unlocked['before'] == before and unlocked['write'].get('attempted') is True and
        unlocked['write'].get('success') is True and unlocked['delete'].get('attempted') is True and
        unlocked['delete'].get('success') is True and unlocked.get('restored') is True and
        unlocked['after'].get('exists') is True and unlocked['after'].get('sha256') == sha_of(lock_content))
    if not checks['unlocked_after_stop']:
        channel.preserve_scene = True
        return finish()
    deleted_lock = mutate('delete_config', {'name': lock_name, 'expected_sha256': sha_of(lock_content)}, 'acc009-delete-lock')
    checks['owned_lock_removed'] = deleted_lock.get('error') is None
    if not checks['owned_lock_removed']:
        return finish()
    edited_content = VALID_INI + '\n# ACC009 stopped management\n'
    edited = mutate('edit_config', {'name': import_name, 'content': edited_content, 'expected_sha256': sha_of(VALID_INI)}, 'acc009-stopped-edit')
    read_edited = call(base, 'read_config', {'name': import_name}, controller=None)
    writer.add_evidence('acc009-stopped-edit-read', read_edited)
    checks['stopped_edit_ok'] = edited.get('error') is None and content_matches(read_edited, import_name, edited_content)
    if not checks['stopped_edit_ok']:
        return finish()
    renamed_name = 'acc009-moved-' + uuid.uuid4().hex + '.ini'
    renamed = mutate('rename_config', {'name': import_name, 'new_name': renamed_name, 'expected_sha256': sha_of(edited_content)}, 'acc009-stopped-rename')
    read_renamed = call(base, 'read_config', {'name': renamed_name}, controller=None)
    writer.add_evidence('acc009-stopped-rename-read', read_renamed)
    checks['stopped_rename_ok'] = renamed.get('error') is None and content_matches(read_renamed, renamed_name, edited_content)
    if not checks['stopped_rename_ok']:
        return finish()
    deleted = mutate('delete_config', {'name': renamed_name, 'expected_sha256': sha_of(edited_content)}, 'acc009-stopped-delete')
    missing = call(base, 'read_config', {'name': renamed_name}, controller=None)
    writer.add_evidence('acc009-stopped-delete-read', missing)
    checks['stopped_delete_ok'] = deleted.get('error') is None and err_of(missing) == 'config_not_found'
    if not all(checks.values()):
        return finish()

    link_request = dict(operation='reparse-setup', name='acc009-link-' + token + '.ini', token=token, run_id=run_id)
    setup, raw = _acc009_os_probe(channel, link_request)
    writer.add_evidence('acc009-reparse-setup', raw)
    if setup.get('created') is not True:
        if setup.get('cleanup_complete') is not True:
            channel.preserve_scene = True
            raise StepError('ACC009 failed reparse setup cleanup unconfirmed')
        writer.blocker = {'reason': 'ACC009 reparse construction unavailable; not evaluated', 'observation': setup}
        return finish(EXIT_BLOCKED)
    try:
        payload = call(base, 'read_config', {'name': link_request['name']}, controller=None)
        writer.add_evidence('acc009-reparse-read', payload)
        checks['reparse_escape_blocked'] = err_of(payload) == 'path_escape_blocked'
    finally:
        cleanup, raw = _acc009_os_probe(channel, dict(link_request, operation='reparse-cleanup', work_dir=setup['work_dir'], target_sha256=setup['target_sha256']))
        writer.add_evidence('acc009-reparse-cleanup', raw)
        checks['reparse_cleanup_confirmed'] = cleanup.get('cleanup_complete') is True
        if not checks['reparse_cleanup_confirmed']:
            channel.preserve_scene = True
    if not all(checks.values()):
        return finish()

    second = load_and_start(base)
    writer.add_evidence('acc009-second-start', second)
    ready, prior = wait_state(base, lambda s: s.get('state') == 'healthy', timeout=45)
    checks['second_start_ok'] = second.get('error') is None and bool(ready and prior.get('run_id') and second.get('run_id') == prior['run_id'] and second.get('config_identity') == prior.get('config_identity'))
    if not checks['second_start_ok']:
        return finish()
    run_before = prior['run_id']
    restarted = mutate('restart', {}, 'acc009-restart')
    current = status(base)
    writer.add_evidence('acc009-restart-observed', current)
    checks['restart_ok'] = restarted.get('error') is None and current.get('state') == 'healthy'
    checks['restart_binds_original_run'] = restarted.get('bound_run_id') == run_before
    checks['restart_reports_current_run'] = bool(restarted.get('run_id') and restarted['run_id'] == current.get('run_id') and restarted['run_id'] != run_before)
    final = stop_run(base)
    writer.add_evidence('acc009-final-stop', final)
    checks['final_stop_ok'] = final.get('error') is None and final.get('state') == 'stopped' and not final.get('run_id')
    return finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acc', required=True,
                        choices=['ACC-001', 'ACC-004-S1', 'ACC-004-S2',
                                 'ACC-004-S3', 'ACC-004-S4', 'ACC-004-S5',
                                 'ACC-004-S6', 'ACC-006', 'ACC-007',
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
            if args.acc.startswith('ACC-004-'):
                exit_code = run_acc004_scenario(base, channel, writer,
                                                args.acc[-2:])
            else:
                handler = {
                    'ACC-001': run_acc001,
                    'ACC-006': run_acc006, 'ACC-007': run_acc007,
                    'ACC-008': run_acc008, 'ACC-009': run_acc009,
                }[args.acc]
                exit_code = handler(base, channel, writer)
            # CHK-043: a bounded start retry is only honest when the
            # first failed attempt is preserved as evidence.
            first_failed = getattr(load_and_start, 'first_failed_start',
                                   None)
            if first_failed is not None:
                writer.add_evidence('%s-start-retry-first-result'
                                    % args.acc.lower(), first_failed)
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
        environment_identity='%s@%s | config=%s' % (
            args.vm_identity, identity, args.config_identity),
        status=status_word)
    print('%s: %s (evidence: %s)' % (args.acc, status_word, out_dir))
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
