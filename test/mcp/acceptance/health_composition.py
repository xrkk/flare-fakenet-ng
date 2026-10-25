"""ACC006's complete original health collection; no fixture-only shortcuts."""
import base64
import hashlib
import json
from pathlib import Path, PureWindowsPath
from helpers import StepError, EXIT_PASS, EXIT_FAIL
from process_recovery import identity, canonical_run, require_mutation
from fakenet.mcp.supervisor import evaluate_health_evidence
from run_ipc_cases import IPC_CASES

EXCEPTION_KEYS = ('healthy_before_trigger', 'matching_consumed_fault', 'actual_thread_exception_stack',
                  'exception_revokes_within_two_cycles', 'link_alive_during_exception',
                  'incident_bytes_complete', 'protective_stop_completed')
REQUIRED = {
    'ipc': tuple(IPC_CASES),
    'healthy-control': ('current_owned_healthy', 'confirmed_stop'),
    'listener': EXCEPTION_KEYS,
    'capture': EXCEPTION_KEYS + ('actual_capture_revocation_within_four_seconds',),
    'active-probe': ('healthy_before_arm', 'actual_consumed_nonce', 'fresh_response_probe_failed_with_listeners_alive',
                     'same_child_failed_within_four_seconds', 'whole_window_http_alive', 'incident_bytes_complete',
                     'protective_recovery_completed'),
    'no-listener': ('no_listener_start_attempted', 'no_init_evidence_never_healthy', 'fake_healthy_negative',
                    'no_listener_stop_completed', 'default_config_restored'),
    'process': ('exact_managed_child_terminated', 'same_supervisor_survives',
                'control_link_survives_entire_recovery', 'protective_recovery_completed', 'same_supervisor_birth'),
}


def config_identity(value, name, digest):
    return isinstance(value, dict) and value.get('name') == name and value.get('sha256') == digest


def healthy_origin(base, channel, writer, label, started, snapshot):
    from run_p03_acc import call
    run = canonical_run(started.get('run_id'))
    health = snapshot.get('health') or {}
    child = identity(health.get('identity'))
    if started.get('health', {}).get('identity') and started['health']['identity'] != child:
        raise StepError('ACC006 accepted start child identity changed')
    if (started.get('error') or snapshot.get('error') or snapshot.get('state') != 'healthy' or
            snapshot.get('run_id') != run or snapshot.get('config_identity') != started.get('config_identity') or
            evaluate_health_evidence(health, '')[0] is not True):
        raise StepError('ACC006 current run/config/three healthy conditions unconfirmed')
    expected = dict(run_id=run, child=child)
    script = Path(__file__).with_name('health_origin.ps1').read_text().replace(
        '__EXPECTED__', base64.b64encode(json.dumps(expected).encode()).decode())
    script = script.replace('__SCOPE_HELPERS__', Path(__file__).with_name('process_scope.ps1').read_text())
    raw = channel.powershell(script, timeout=45)
    writer.add_evidence(label + '-owned-healthy', raw)
    facts = json.loads(raw['output'])
    inputs = getattr(channel, 'inputs', None) or {}
    install = PureWindowsPath(inputs.get('installation_root', r'C:\Program Files\FakeNet-NG-MCP'))
    root = PureWindowsPath(inputs.get('programdata_root', r'C:\ProgramData\FakeNet-NG-MCP'))
    observed = facts.get('child') or {}
    service = facts.get('service') or {}
    identity(service)
    log = facts.get('log') or {}
    body = base64.b64decode(log['body'], validate=True)
    if (facts.get('run_id') != run or identity(observed) != child or
            observed.get('parent_pid') != service['pid'] or observed.get('run_id') != run or
            PureWindowsPath(observed.get('image', '')) != install / 'fakenetng-mcp-managed.exe' or
            PureWindowsPath(service.get('image', '')) != install / 'fakenetng-mcp.exe' or
            service.get('state') != 'Running' or
            PureWindowsPath(log.get('path', '')) != root / 'artifacts/runs' / run / 'run.log' or
            len(body) != log.get('size') or hashlib.sha256(body).hexdigest() != log.get('sha256')):
        raise StepError('ACC006 healthy child/SCM/log original differs')
    log_text = body.decode('utf-8', 'replace')
    final = call(base, 'get_status', controller=None)
    writer.add_evidence(label + '-confirmed-status', final)
    if (final.get('state') != 'healthy' or final.get('run_id') != run or
            final.get('config_identity') != started.get('config_identity') or
            (final.get('health') or {}).get('identity') != child or
            evaluate_health_evidence(health, log_text)[0] is not True or
            evaluate_health_evidence(final.get('health') or {}, log_text)[0] is not True):
        raise StepError('ACC006 health/log predicate or current identity changed')
    return facts


def verified_start(base, channel, writer, label, name='default.ini'):
    from run_p03_acc import call, status, unique_command, wait_state
    before = status(base)
    if before.get('state') != 'stopped' or before.get('run_id'):
        raise StepError('ACC006 dependent start requires clean stopped entry')
    config = call(base, 'read_config', {'name': name}, controller=None)
    writer.add_evidence(label + '-config-bytes', config)
    if config.get('error') or config.get('name') != name or not isinstance(config.get('content'), str) or hashlib.sha256(config['content'].encode()).hexdigest() != config.get('sha256'):
        raise StepError('ACC006 requested config bytes unconfirmed')
    command = unique_command('health-load')
    loaded = call(base, 'load_config', {'name': name, 'command_id': command, 'expected_state_version': before['state_version']})
    writer.add_evidence(label + '-accepted-load', loaded)
    require_mutation(loaded, command, before['state_version'])
    if not config_identity(loaded.get('config_identity'), name, config['sha256']):
        raise StepError('ACC006 load selected another configuration')
    command = unique_command('health-start')
    started = call(base, 'start', {'command_id': command, 'expected_state_version': loaded['state_version']}, timeout=90)
    writer.add_evidence(label + '-accepted-start', started)
    require_mutation(started, command, loaded['state_version'])
    if started.get('config_identity') != loaded['config_identity']:
        raise StepError('ACC006 start receipt config differs')
    ready, snapshot = wait_state(base, lambda s: s.get('state') in ('healthy', 'failed', 'stopped'), timeout=30)
    if not ready:
        raise StepError('ACC006 healthy publication unavailable')
    healthy_origin(base, channel, writer, label, started, snapshot)
    return started


def verified_stop(base, channel, writer, label, run_id, config, allow_stopped=False):
    from run_p03_acc import call, status, unique_command
    before = status(base)
    already_stopped = allow_stopped and before.get('state') == 'stopped' and not before.get('run_id') and not (before.get('health') or {}).get('process_alive')
    if (before.get('error') or before.get('config_identity') != config or
            (before.get('run_id') != run_id and not already_stopped)):
        raise StepError('ACC006 stop target identity/config changed')
    command = unique_command('health-stop')
    result = call(base, 'stop', {'command_id': command, 'expected_state_version': before['state_version']}, timeout=1020)
    writer.add_evidence(label + '-accepted-stop', result)
    require_mutation(result, command, before['state_version'])
    final = status(base)
    writer.add_evidence(label + '-stopped-status', final)
    if result.get('state') != 'stopped' or result.get('run_id') or final.get('error') or final.get('state') != 'stopped' or final.get('run_id') or (final.get('health') or {}).get('process_alive') or final.get('config_identity') != config:
        raise StepError('ACC006 stop/recovery not confirmed')
    return result


def run_complete_health(base, channel, writer):
    from run_p03_acc import (exercise_listener_exception, exercise_no_listener_health,
                            acc004_s6_uncontrolled_exit)
    from run_ipc_cases import run_ipc_matrix
    from run_active_probe import run_active_probe_loss
    writer.add_evidence('acc006-required-sections', {key: list(value) for key, value in REQUIRED.items()})
    sections = {}

    def record(name, checks):
        missing = set(REQUIRED[name]) - set(checks or {}) if isinstance(checks, dict) else set(REQUIRED[name])
        extra = set(checks) - set(REQUIRED[name]) if isinstance(checks, dict) else set()
        ok = isinstance(checks, dict) and not missing and not extra and all(v is True for v in checks.values())
        sections[name] = dict(checks=checks, missing=sorted(missing), extra=sorted(extra), passed=ok)
        writer.add_evidence('acc006-section-' + name, sections[name])
        return ok

    def finish():
        writer.add_evidence('acc006-complete-health', {'required': list(REQUIRED), 'sections': sections})
        return EXIT_PASS if set(sections) == set(REQUIRED) and all(v['passed'] for v in sections.values()) else EXIT_FAIL

    try:
        if not record('ipc', run_ipc_matrix(base, channel, writer, verify_lifecycle=True)):
            return finish()
        started = verified_start(base, channel, writer, 'acc006-control')
        verified_stop(base, channel, writer, 'acc006-control', started['run_id'], started['config_identity'])
        record('healthy-control', {'current_owned_healthy': True, 'confirmed_stop': True})
        if not record('listener', exercise_listener_exception(base, channel, writer, 'acc006-anomaly', verify_lifecycle=True)):
            return finish()
        if not record('capture', exercise_listener_exception(base, channel, writer, 'acc006-capture', 'capture_exception', verify_lifecycle=True)):
            return finish()
        if not record('active-probe', run_active_probe_loss(base, channel, writer, verify_lifecycle=True)):
            return finish()
        if not record('no-listener', exercise_no_listener_health(base, writer, channel=channel, verify_lifecycle=True)):
            return finish()
        record('process', acc004_s6_uncontrolled_exit(base, channel, writer, verify_lifecycle=True))
        return finish()
    except Exception:
        channel.preserve_scene = True
        raise
