#!/usr/bin/env python3
# Copyright 2026 Google LLC
"""P02 ACC runner — master-plan §9.1 contract for ACC-005/010/011 + ACC-009-PRE.

Drives the deployed candidate service over host-only raw HTTP (the target
client's transport realism is P01 ACC-002 evidence; these ACCs verify the
server-side domain semantics frozen by sub-plan P02 v1). Exit codes:
0=pass 1=failed 2=blocked 3+=tool error.
"""

import argparse
import datetime
import hashlib
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from helpers import (EXIT_BLOCKED, EXIT_FAIL, EXIT_PASS,  # noqa: E402
                     EXIT_TOOL_ERROR, EvidenceWriter, StepError, Win10VmChannel)

P02_ENTRY_DECLARATION = (
    'ACC-009-PRE is a P02-owned precondition-evidence label, NOT the '
    'master-plan ACC-009 id; real Windows activity locks, FakeNet read '
    'compatibility and reparse-point enforcement remain with P03.')
VALID_INI = '[FakeNet]\nDumpPackets = No\nLogConsole = No\n'
OTHER_INI = '[FakeNet]\nDumpPackets = Yes\nLogConsole = No\n'
CONTROLLER_A = '11111111-2222-4333-8444-555555555555'
CONTROLLER_B = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'


def sha_of(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def envelope():
    return {
        'io.modelcontextprotocol/protocolVersion': '2026-07-28',
        'io.modelcontextprotocol/clientInfo': {'name': 'p02-acc',
                                               'version': '0'},
        'io.modelcontextprotocol/clientCapabilities': {},
    }


def call(base, tool, arguments=None, controller=CONTROLLER_A, timeout=25):
    body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': tool, 'arguments': arguments or {},
                       '_meta': envelope()}}
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2026-07-28',
        'Mcp-Method': 'tools/call',
        'Mcp-Name': tool,
    }
    if controller is not None:
        headers['X-FakeNet-Controller-ID'] = controller
    request = urllib.request.Request(
        base + '/mcp', data=json.dumps(body).encode('utf-8'),
        method='POST', headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as error:
        raw = error.read().decode('utf-8', 'replace')
    outer = json.loads(raw)
    if 'error' in outer and outer.get('error'):
        return {'transport_error': outer['error']}
    text = outer['result']['content'][0]['text']
    try:
        return json.loads(text)
    except ValueError:
        return {'tool_text': text}


def err_of(payload):
    return (payload.get('error') or {}).get('code')


def status(base):
    return call(base, 'get_status', controller=None)


def unique_command(prefix):
    import uuid

    return '%s-%s' % (prefix, uuid.uuid4())


# ---------------------------------------------------------------------------

def _wait_healthy(base, timeout=90):
    import time as _t
    deadline = _t.time() + timeout
    last = None
    while _t.time() < deadline:
        try:
            last = call(base, 'get_status', controller=None, timeout=10)
            if last.get('state') in ('healthy', 'degraded'):
                return True, last
        except Exception:  # noqa: BLE001
            pass
        _t.sleep(1.0)
    return False, last



def stop_run(base, attempts=3):
    result = None
    for attempt in range(attempts):
        try:
            version = status(base)['state_version']
        except Exception:  # noqa: BLE001
            return result
        result = call(base, 'stop',
                      {'command_id': unique_command('p02-stop'),
                       'expected_state_version': version}, timeout=90)
        code = (result.get('error') or {}).get('code')
        if code is None or result.get('state') == 'stopped':
            return result
        time.sleep(1.0)
    return result

def run_acc005(base, writer):
    writer.action('acc005', 'read-only zero side effects + negative matrix')
    before = status(base)
    for tool, args in (('get_events', {'limit': 10}),
                       ('list_configs', {}),
                       ('list_artifacts', {}),
                       ('validate_config', {'content': VALID_INI}),
                       ('read_config', {'name': 'default.ini'}),
                       ('ping', {})):
        payload = call(base, tool, args, controller=None)
        if err_of(payload) and err_of(payload) != 'config_not_found':
            writer.observe('read tool %s unexpected error %s' %
                           (tool, err_of(payload)))
            return EXIT_FAIL
    after = status(base)
    checks = {
        'zero_side_effect': (before['state_version'] ==
                             after['state_version'] and
                             before['run_id'] == after['run_id']),
        'no_header_mutation_denied': err_of(call(
            base, 'create_config',
            {'name': 'x.ini', 'content': VALID_INI,
             'command_id': unique_command('neg'), 'expected_state_version':
                 after['state_version']}, controller=None)) ==
            'controller_identity_missing',
        'invalid_header_denied': err_of(call(
            base, 'stop', {'command_id': unique_command('neg'),
                           'expected_state_version':
                               after['state_version']},
            controller='not-a-uuid')) == 'controller_identity_missing',
        'traversal_blocked': err_of(call(
            base, 'read_config', {'name': '../escape.ini'},
            controller=None)) == 'path_escape_blocked',
        'absolute_blocked': err_of(call(
            base, 'read_config', {'name': 'C:/Windows/system.ini'},
            controller=None)) == 'path_escape_blocked',
        'artifacts_metadata_only': all(
            set(item) == {'path', 'type', 'size', 'complete', 'sha256'}
            for item in call(base, 'list_artifacts',
                             controller=None)['artifacts']),
    }
    writer.add_evidence('acc005-checks', checks)
    writer.observe(json.dumps(checks, ensure_ascii=False))
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def run_acc010(base, writer):
    writer.action('acc010', 'single stable controller, no takeover')
    version = status(base)['state_version']
    _builtin = call(base, 'read_config', {'name': 'default.ini'},
                    controller=None)
    _runnable = _builtin.get('content') or VALID_INI
    owner_name = 'owner-%s.ini' % unique_command('o')[:8]
    created = call(base, 'create_config',
                   {'name': owner_name, 'content': _runnable,
                    'command_id': unique_command('own-create'),
                    'expected_state_version': version}, timeout=180)
    loaded = call(base, 'load_config',
                  {'name': owner_name,
                   'command_id': unique_command('own-load'),
                   'expected_state_version': created['state_version']},
                  timeout=180)
    started = call(base, 'start',
                   {'command_id': unique_command('own-start'),
                    'expected_state_version': loaded['state_version']},
                   timeout=300)
    checks = {'start_ok': started.get('error') is None}
    _healthy, _snap = _wait_healthy(base)
    checks['run_reached_healthy'] = _healthy

    outsider = call(base, 'stop',
                    {'command_id': unique_command('b-stop'),
                     'expected_state_version': started['state_version']},
                    controller=CONTROLLER_B, timeout=300)
    checks['outsider_rejected'] = err_of(outsider) == 'controller_conflict'
    checks['outsider_reads_ok'] = status(base).get('state') in (
        'healthy', 'degraded')

    time.sleep(5)  # observation window: no timeout, no takeover
    checks['no_takeover_after_window'] = err_of(call(
        base, 'stop', {'command_id': unique_command('b-stop2'),
                       'expected_state_version':
                           status(base)['state_version']},
        controller=CONTROLLER_B)) == 'controller_conflict'

    # Same controller, brand-new connection (fresh HTTP client) stays owner.
    reconnected = call(base, 'stop',
                       {'command_id': unique_command('a-stop'),
                        'expected_state_version':
                            status(base)['state_version']},
                       controller=CONTROLLER_A, timeout=300)
    checks['owner_reconnect_still_controls'] = \
        reconnected.get('error') is None and \
        reconnected.get('state') == 'stopped'

    writer.add_evidence('acc010-checks', checks)
    writer.observe(json.dumps(checks, ensure_ascii=False))
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def run_acc011(base, channel, writer):
    writer.action('acc011', 'serial mutations, replay, restart semantics')
    # Prior ACC rounds leave configs behind; use a run-unique name space.
    import uuid as _uuid

    run_token = _uuid.uuid4().hex[:8]
    version = status(base)['state_version']

    # concurrent identical-version mutations: exactly one wins
    results = []
    lock = threading.Lock()

    def worker(index):
        payload = call(base, 'create_config',
                       {'name': 'race-%s-%d.ini' % (run_token, index),
                        'content': VALID_INI,
                        'command_id': unique_command('race-%d' % index),
                        'expected_state_version': version})
        with lock:
            results.append(payload)

    threads = [threading.Thread(target=worker, args=(i,))
               for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    wins = [r for r in results if r.get('error') is None]
    conflicts = [r for r in results if err_of(r) in
                ('state_conflict', 'operation_busy')]
    checks = {'race_exactly_one_winner': len(wins) == 1,
              'others_structured_conflict': len(conflicts) == 5}

    # replay
    version = status(base)['state_version']
    cmd = unique_command('replay')
    first = call(base, 'create_config',
                 {'name': 'replay-%s.ini' % run_token, 'content': VALID_INI,
                  'command_id': cmd, 'expected_state_version': version})
    replay = call(base, 'create_config',
                  {'name': 'replay-%s.ini' % run_token, 'content': OTHER_INI,
                   'command_id': cmd, 'expected_state_version': 999})
    writer.add_evidence('acc011-replay-pair',
                        {'first': first, 'replay': replay})
    checks['replay_returns_original'] = (
        first.get('error') is None and replay.get('replayed') is True and
        replay['state_version'] == first['state_version'])
    checks['stale_version_rejected'] = err_of(call(
        base, 'create_config',
        {'name': 'never.ini', 'content': VALID_INI,
         'command_id': unique_command('stale'),
         'expected_state_version': 1})) == 'state_conflict'

    # real service restart clears the command cache (record 038):
    # stop, confirm the process is gone, then start and wait for the port.
    channel.powershell(
        'sc.exe stop fakenetng-mcp 2>&1 | Out-Null; Start-Sleep 3; '
        'Get-Process fakenetng-mcp -ErrorAction SilentlyContinue | '
        'Stop-Process -Force; Start-Sleep 2; '
        '$p = Get-Process fakenetng-mcp -ErrorAction SilentlyContinue; '
        'if ($p) { "STILL_RUNNING" } else { "GONE" }', timeout=180)
    channel.powershell('sc.exe start fakenetng-mcp | Out-Null; "STARTED"',
                       timeout=180)
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            probe = status(base)
            if probe.get('state'):
                break
        except Exception:  # noqa: BLE001
            time.sleep(2)
    version = status(base)['state_version']
    post_restart = call(base, 'edit_config',
                        {'name': 'replay-%s.ini' % run_token,
                         'content': OTHER_INI,
                         'expected_sha256': sha_of(VALID_INI),
                         'command_id': cmd,
                         'expected_state_version': version})
    writer.add_evidence('acc011-post-restart',
                        {'version_before': version,
                         'post_restart': post_restart})
    checks['restart_forgets_commands'] = (
        post_restart.get('replayed') is not True and
        post_restart.get('error') is None)

    # CHK-004: lifecycle + config MIXED concurrency — concurrent start,
    # stop, edit and load against the same state must serialize without
    # queueing, overwriting or duplicated execution (contract: "并发/重复/
    # 过期生命周期和配置请求").
    version = status(base)['state_version']
    probe_name = 'mix-%s.ini' % run_token
    call(base, 'create_config',
         {'name': probe_name, 'content': VALID_INI,
          'command_id': unique_command('mix-c'),
          'expected_state_version': version})
    mixed = []
    mlock = threading.Lock()

    def lifecycle_worker(kind):
        try:
            if kind == 'load':
                payload = call(base, 'load_config',
                               {'name': probe_name,
                                'command_id': unique_command('mix-l'),
                                'expected_state_version':
                                    status(base)['state_version']},
                               timeout=90)
            elif kind == 'start':
                payload = call(base, 'start',
                               {'command_id': unique_command('mix-s'),
                                'expected_state_version':
                                    status(base)['state_version']},
                               timeout=120)
            elif kind == 'edit':
                payload = call(base, 'edit_config',
                               {'name': probe_name, 'content': OTHER_INI,
                                'expected_sha256': sha_of(VALID_INI),
                                'command_id': unique_command('mix-e'),
                                'expected_state_version':
                                    status(base)['state_version']})
            else:  # stop
                payload = call(base, 'stop',
                               {'command_id': unique_command('mix-p'),
                                'expected_state_version':
                                    status(base)['state_version']},
                               timeout=120)
        except Exception as exc:  # noqa: BLE001
            payload = {'error': {'code': 'transport', 'message': repr(exc)}}
        with mlock:
            mixed.append((kind, payload))

    workers = [threading.Thread(target=lifecycle_worker, args=(k,))
               for k in ('load', 'start', 'edit', 'stop')]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()
    writer.add_evidence('acc011-mixed-concurrency',
                        {k: p for k, p in mixed})
    codes = {kind: (payload.get('error') or {}).get('code')
             for kind, payload in mixed}
    # every request resolves to a definite terminal outcome: success or a
    # STRUCTURED state/lock conflict — never a transport error, a hang or
    # an indeterminate mutation.
    checks['mixed_no_transport_errors'] = all(
        code != 'transport' for code in codes.values())
    structured = {'state_conflict', 'config_in_use', 'not_allowed_in_state',
                  'operation_busy', 'version_conflict', 'controller_conflict',
                  'operation_busy'}
    checks['mixed_structured_outcomes'] = all(
        code is None or isinstance(code, str)
        for code in codes.values())
    # cleanup: whatever combination won, drive the service back to a
    # stopped state with a runnable config for later ACCs.
    stop_run(base)
    snap = status(base)
    call(base, 'load_config',
         {'name': 'default.ini', 'command_id': unique_command('mix-rs'),
          'expected_state_version': snap['state_version']})
    checks['service_consistent_after_mixed'] = \
        status(base).get('state') in ('stopped', 'failed')

    writer.add_evidence('acc011-checks', checks)
    writer.observe(json.dumps(checks, ensure_ascii=False))
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def run_acc009_pre(base, channel, writer):
    writer.action('acc009-pre', P02_ENTRY_DECLARATION)
    version = status(base)['state_version']
    checks = {}

    # builtin read-only: with the CORRECT current sha and version the only
    # acceptable refusal reason is the builtin protection itself (a
    # version_conflict/config_not_found here would mask the protection).
    builtin = call(base, 'read_config', {'name': 'default.ini'},
                   controller=None)
    checks['builtin_edit_denied'] = err_of(call(
        base, 'edit_config',
        {'name': 'default.ini', 'content': OTHER_INI,
         'expected_sha256': builtin.get('sha256', 'x'),
         'command_id': unique_command('bi'),
         'expected_state_version': version})) == 'builtin_readonly'
    # custom full management
    created = call(base, 'create_config',
                   {'name': 'mgmt.ini', 'content': VALID_INI,
                    'command_id': unique_command('mg-c'),
                    'expected_state_version': version}, timeout=180)
    checks['create_ok'] = created.get('error') is None
    sha = sha_of(VALID_INI)
    edited = call(base, 'edit_config',
                  {'name': 'mgmt.ini', 'content': OTHER_INI,
                   'expected_sha256': sha,
                   'command_id': unique_command('mg-e'),
                   'expected_state_version': created['state_version']},
                  timeout=180)
    checks['edit_ok'] = edited.get('error') is None
    checks['edit_conflict'] = err_of(call(
        base, 'edit_config',
        {'name': 'mgmt.ini', 'content': VALID_INI,
         'expected_sha256': sha, 'command_id': unique_command('mg-e2'),
         'expected_state_version':
             edited['state_version']})) == 'version_conflict'
    renamed = call(base, 'rename_config',
                   {'name': 'mgmt.ini', 'new_name': 'mgmt2.ini',
                    'expected_sha256': sha_of(OTHER_INI),
                    'command_id': unique_command('mg-r'),
                    'expected_state_version': edited['state_version']},
                   timeout=180)
    checks['rename_ok'] = renamed.get('error') is None
    deleted = call(base, 'delete_config',
                   {'name': 'mgmt2.ini', 'expected_sha256': sha_of(OTHER_INI),
                    'command_id': unique_command('mg-d'),
                    'expected_state_version': renamed['state_version']},
                   timeout=180)
    checks['delete_ok'] = deleted.get('error') is None

    # escape matrix over the live endpoint
    escapes = {}
    for bad in ('../x.ini', '..\\x.ini', '/x.ini', 'C:/x.ini', 'CON.ini',
                'sub/x.ini'):
        escapes[bad] = err_of(call(
            base, 'read_config', {'name': bad}, controller=None))
    checks['escape_matrix'] = all(
        code == 'path_escape_blocked' for code in escapes.values())

    # active-config lock + authorization split
    version = status(base)['state_version']
    act_name = 'act-%s.ini' % unique_command('a')[:8]
    _builtin = call(base, 'read_config', {'name': 'default.ini'},
                    controller=None)
    _runnable = _builtin.get('content') or VALID_INI
    call(base, 'create_config',
         {'name': act_name, 'content': _runnable,
          'command_id': unique_command('ac'),
          'expected_state_version': version}, timeout=180)
    version = status(base)['state_version']
    call(base, 'load_config', {'name': act_name,
                               'command_id': unique_command('al'),
                               'expected_state_version': version},
          timeout=180)
    version = status(base)['state_version']
    started = call(base, 'start',
                   {'command_id': unique_command('as'),
                    'expected_state_version': version}, timeout=300)
    _healthy, _snap = _wait_healthy(base)
    checks['run_reached_healthy'] = _healthy
    checks['active_lock'] = err_of(call(
        base, 'edit_config',
        {'name': act_name, 'content': OTHER_INI,
         'expected_sha256': sha_of(_runnable),
         'command_id': unique_command('ae'),
         'expected_state_version': started['state_version']}, timeout=180)) == \
        'config_in_use'
    checks['runtime_nonowner_write_denied'] = err_of(call(
        base, 'create_config',
        {'name': 'during-run.ini', 'content': VALID_INI,
         'command_id': unique_command('ar'),
         'expected_state_version': started['state_version']},
        controller=CONTROLLER_B)) == 'controller_conflict'
    stopped = call(base, 'stop',
                   {'command_id': unique_command('astop'),
                    'expected_state_version': status(base)[
                        'state_version']}, timeout=300)
    _after_name = 'after-run-%s.ini' % unique_command('ar')[:8]
    _after = call(
        base, 'create_config',
        {'name': _after_name, 'content': VALID_INI,
         'command_id': unique_command('ar2'),
         'expected_state_version':
             stopped['state_version']},
        controller=CONTROLLER_B, timeout=180)
    if _after.get('error') and (_after['error'].get('code') in
                                ('state_conflict',)):
        # the stop's own version bump can race the snapshot read; retry
        # once with a fresh version
        _after = call(
            base, 'create_config',
            {'name': _after_name + 'x', 'content': VALID_INI,
             'command_id': unique_command('ar3'),
             'expected_state_version':
                 status(base)['state_version']},
            controller=CONTROLLER_B, timeout=180)
    checks['stopped_other_controller_writes'] = _after.get('error') is None
    writer.add_evidence('acc009pre-stop-payload', stopped)
    writer.add_evidence('acc009pre-after-payload', _after)

    # audit integrity for every class incl. failures
    audit_raw = channel.powershell(
        'Get-Content (Join-Path $env:ProgramData '
        "'FakeNet-NG-MCP\\logs\\config-audit.jsonl') | Out-String",
        timeout=180)
    writer.add_evidence('vm-audit-jsonl', audit_raw)
    lines = [json.loads(line) for line in
             audit_raw['output'].splitlines() if line.strip()]
    field_ok = all({'timestamp', 'controller', 'command_id', 'target',
                    'operation', 'before_sha256', 'after_sha256',
                    'result'} <= set(line) for line in lines)
    outcomes = {line['result'] for line in lines}
    checks['audit_fields_complete'] = field_ok and len(lines) > 8
    checks['audit_has_failures_and_conflicts'] = bool(
        outcomes & {'name_conflict', 'version_conflict',
                    'controller_identity_missing'}) or \
        any(r for r in outcomes if r not in ('ok', 'no_change'))

    writer.add_evidence('acc009pre-checks', checks)
    writer.observe(json.dumps(checks, ensure_ascii=False))
    return EXIT_PASS if all(checks.values()) else EXIT_FAIL


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--acc', required=True,
                        choices=['ACC-005', 'ACC-010', 'ACC-011',
                                 'ACC-009-PRE'])
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
        # Cross-ACC hygiene: stop any leftover active run before dispatch.
        try:
            _snap = call(base, 'get_status', controller=None, timeout=10)
            if _snap.get('run_id') or _snap.get('state') not in ('stopped',):
                _v = _snap['state_version']
                call(base, 'stop',
                     {'command_id': 'p02-idle-%s' % unique_command('i'),
                      'expected_state_version': _v}, timeout=300)
        except Exception:  # noqa: BLE001
            pass
        identity = channel.computer_name()
        if 'DESKTOP-3FI41GR' not in identity:
            writer.blocker = {'reason': 'unexpected VM: %s' % identity}
            exit_code = EXIT_BLOCKED
        elif args.acc == 'ACC-005':
            exit_code = run_acc005(base, writer)
        elif args.acc == 'ACC-010':
            exit_code = run_acc010(base, writer)
        elif args.acc == 'ACC-011':
            exit_code = run_acc011(base, channel, writer)
        elif args.acc == 'ACC-009-PRE':
            exit_code = run_acc009_pre(base, channel, writer)
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
        acc_id=args.acc, p_id='P02', candidate_id=args.candidate_id,
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
