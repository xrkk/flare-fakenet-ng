"""Offline P7 failure evidence and cleanup contracts."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace

import pytest


SUITE_PATH = Path(__file__).parent / 'acceptance' / 'scenario_suite.py'
SPEC = importlib.util.spec_from_file_location('scenario_p7_evidence_suite', SUITE_PATH)
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)
WRAPPER_PATH = SUITE_PATH.parent / 'p7_capture_wrapper.py'
WRAPPER_SPEC = importlib.util.spec_from_file_location('scenario_p7_capture_wrapper', WRAPPER_PATH)
wrapper = importlib.util.module_from_spec(WRAPPER_SPEC)
sys.modules[WRAPPER_SPEC.name] = wrapper
WRAPPER_SPEC.loader.exec_module(wrapper)


def runner(tmp_path, probe=None, vm_error=None, default_error=False, foreign_owner=False):
    subject = object.__new__(suite.Suite)
    subject.root = tmp_path
    subject.vm = object()
    state = {'state': 'stopped', 'run_id': None, 'controller': None,
             'config_identity': {'name': 'default.ini'}}
    calls = []

    def status():
        return dict(state)

    def mutate(_scenario, _attempt, _sequence, name, arguments):
        calls.append((name, arguments))
        if name == 'load_config' and arguments['name'] == 'default.ini' and default_error:
            raise suite.SuiteError('default load rejected')
        if name == 'load_config':
            state['config_identity'] = {'name': arguments['name']}
        elif name == 'start':
            state.update(state='healthy', run_id='current-run',
                         controller='foreign' if foreign_owner else 'ours')
        elif name == 'stop':
            state.update(state='stopped', run_id=None, controller=None)
        return dict(state, **({'run_id': 'current-run'} if name == 'start' else {}))

    subject._status = status
    subject._mutate = mutate
    subject.service = SimpleNamespace(controller_id='ours',
                                      tool=lambda name, args: {'sha256': 'config-sha'})
    if probe is not None:
        for stream in ('stdout', 'stderr'):
            data = probe.get(stream, '').encode()
            probe[stream + '_path'] = 'C:\\p7-' + stream + '.raw'
            probe[stream + '_size'] = len(data)
            probe[stream + '_sha256'] = hashlib.sha256(data).hexdigest()
        def transfer(guest, size, sha256, destination):
            stream = 'stdout' if 'stdout' in guest else 'stderr'
            raw = probe.get(stream, '').encode()
            assert len(raw) == size and hashlib.sha256(raw).hexdigest() == sha256
            destination.write_bytes(raw)
            return suite.file_record(destination, tmp_path)
        subject._transfer_guest_file = transfer
    if vm_error:
        def fail(_command, _timeout):
            raise vm_error
        subject._vm_json = fail
    else:
        subject._vm_json = lambda _command, _timeout: (probe, {'raw': 'complete wire',
                                                                'output': json.dumps(probe)})
    return subject, calls, state


def evidence(tmp_path):
    return suite.Evidence(tmp_path / 'preflight-evidence')


def test_nonzero_curl_keeps_full_diagnostics_and_blocks_after_cleanup(tmp_path):
    probe = {'exit_code': 1, 'actual_curl_exit': 28, 'http_code': '000',
             'stderr': 'curl: (28) SSL connection timeout', 'stdout': '000',
             'nonce': 'preflight-00000000-0000-0000-0000-000000000001',
             'url': 'https://api.deepseek.com/preflight-...'}
    subject, calls, state = runner(tmp_path, probe=probe)
    ledger = evidence(tmp_path)
    with pytest.raises(suite.SuiteError, match='B1 relay preflight failed'):
        subject._preflight_b1('content', 'preflight-b1', 1, ledger)
    wire = json.loads((ledger.root / 'p7-probe-wire.json').read_text())
    cleanup = json.loads((ledger.root / 'p7-cleanup.json').read_text())
    assert wire['run_id'] == 'current-run' and wire['probe']['actual_curl_exit'] == 28
    assert wire['probe']['stderr'].endswith('timeout') and wire['vm_record']['raw'] == 'complete wire'
    assert [name for name, _ in calls] == ['create_config', 'load_config', 'start',
                                           'stop', 'load_config', 'delete_config']
    assert cleanup['errors'] == [] and state['config_identity']['name'] == 'default.ini'
    assert {item['path'] for item in ledger.items} == {'p7-probe-wire.json', 'p7-cleanup.json',
                                                      'p7-curl.stdout.raw', 'p7-curl.stderr.raw'}


@pytest.mark.parametrize('http_code,actual', [('000', 0), ('401', 28)])
def test_http000_or_actual_native_failure_never_passes(tmp_path, http_code, actual):
    probe = {'exit_code': 0, 'actual_curl_exit': actual, 'http_code': http_code,
             'nonce': 'preflight-00000000-0000-0000-0000-000000000001',
             'url': 'https://api.deepseek.com/preflight-...'}
    subject, _calls, _state = runner(tmp_path, probe=probe)
    with pytest.raises(suite.SuiteError, match='B1 relay preflight failed'):
        subject._preflight_b1('content', 'preflight-b1', 1, evidence(tmp_path))


def test_success_retains_original_exit_and_cleanup_order(tmp_path):
    probe = {'exit_code': 0, 'actual_curl_exit': 0, 'http_code': '401',
             'nonce': 'preflight-00000000-0000-0000-0000-000000000001',
             'url': 'https://api.deepseek.com/preflight-...'}
    subject, calls, _state = runner(tmp_path, probe=probe)
    result = subject._preflight_b1('content', 'preflight-b1', 1, evidence(tmp_path))
    assert result['probe']['http_code'] == '401'
    assert [name for name, _ in calls][-3:] == ['stop', 'load_config', 'delete_config']
    assert result['cleanup']['errors'] == []


def test_optional_capture_ack_precedes_product_start_and_done_follows_cleanup(tmp_path,
                                                                              monkeypatch):
    control = tmp_path / 'control'
    control.mkdir()
    monkeypatch.setenv('SST_P7_CAPTURE_CONTROL_DIR', str(control))
    probe = {'exit_code': 0, 'actual_curl_exit': 0, 'http_code': '401',
             'nonce': 'preflight-00000000-0000-0000-0000-000000000001',
             'url': 'https://api.deepseek.com/preflight-...',
             'started_at': '2026-01-01T00:00:01Z', 'ended_at': '2026-01-01T00:00:02Z'}
    subject, calls, _state = runner(tmp_path, probe=probe)
    original_mutate = subject._mutate

    def guarded_mutate(scenario, attempt, sequence, name, arguments):
        if name == 'start':
            assert (control / 'request.json').is_file()
            assert json.loads((control / 'ack.json').read_text())['status'] == 'ready'
        return original_mutate(scenario, attempt, sequence, name, arguments)

    subject._mutate = guarded_mutate

    def acknowledge():
        deadline = time.monotonic() + 3
        while not (control / 'request.json').is_file() and time.monotonic() < deadline:
            time.sleep(0.01)
        suite.write_p7_control(control / 'ack.json', {
            'status': 'ready', 'owner': 'owned', 'etl': r'C:\p7.etl',
            'started': '2026-01-01T00:00:00Z'})

    helper = threading.Thread(target=acknowledge)
    helper.start()
    try:
        subject._preflight_b1('content', 'preflight-b1', 1, evidence(tmp_path))
    finally:
        helper.join(timeout=3)
    assert not helper.is_alive()
    assert json.loads((control / 'done.json').read_text())['run_id'] == 'current-run'
    assert [name for name, _ in calls][-3:] == ['stop', 'load_config', 'delete_config']


def test_native_start_or_stream_error_blocks_even_if_exit_zero(tmp_path):
    probe = {'exit_code': 0, 'actual_curl_exit': 0, 'http_code': '401',
             'native_error': 'stream drain failed',
             'nonce': 'preflight-00000000-0000-0000-0000-000000000001',
             'url': 'https://api.deepseek.com/preflight-...'}
    subject, _calls, _state = runner(tmp_path, probe=probe)
    with pytest.raises(suite.SuiteError, match='B1 relay preflight failed'):
        subject._preflight_b1('content', 'preflight-b1', 1, evidence(tmp_path))


def test_broken_vm_json_preserves_full_wire_and_cleanup(tmp_path):
    failure = suite.SuiteError('expected VM JSON')
    failure.vm_record = {'raw': 'prefix' + 'diagnostic-data' * 100,
                         'output': '{broken', 'exit_code': 0}
    subject, calls, _state = runner(tmp_path, vm_error=failure)
    with pytest.raises(suite.SuiteError, match='expected VM JSON'):
        subject._preflight_b1('content', 'preflight-b1', 1, evidence(tmp_path))
    wire = json.loads((tmp_path / 'preflight-evidence/p7-probe-wire.json').read_text())
    assert wire['vm_record']['raw'] == failure.vm_record['raw']
    assert [name for name, _ in calls][-3:] == ['stop', 'load_config', 'delete_config']


def test_default_restore_failure_is_visible_and_withholds_delete(tmp_path):
    probe = {'exit_code': 0, 'actual_curl_exit': 0, 'http_code': '401',
             'nonce': 'preflight-00000000-0000-0000-0000-000000000001',
             'url': 'https://api.deepseek.com/preflight-...'}
    subject, calls, state = runner(tmp_path, probe=probe, default_error=True)
    with pytest.raises(suite.SuiteError, match='B1 cleanup failed'):
        subject._preflight_b1('content', 'preflight-b1', 1, evidence(tmp_path))
    cleanup = json.loads((tmp_path / 'preflight-evidence/p7-cleanup.json').read_text())
    assert any('default load rejected' in item for item in cleanup['errors'])
    assert not any(name == 'delete_config' for name, _ in calls)
    assert state['config_identity']['name'] == 'sst-preflight-b1.ini'


def test_foreign_owner_is_never_stopped_or_deleted(tmp_path):
    failure = suite.SuiteError('VM failed')
    subject, calls, state = runner(tmp_path, vm_error=failure, foreign_owner=True)
    with pytest.raises(suite.SuiteError, match='B1 cleanup failed'):
        subject._preflight_b1('content', 'preflight-b1', 1, evidence(tmp_path))
    assert not any(name in ('stop', 'delete_config') for name, _ in calls)
    assert state['controller'] == 'foreign'


def test_vm_command_error_keeps_complete_response(monkeypatch):
    vm = suite.VmMcp('http://192.168.204.233:28787/mcp')
    responses = iter([({}, {'mcp-session-id': 'session'}), ({}, {}),
                      ({'result': {'content': [{'type': 'text', 'text':
                        'Response: ' + 'X' * 1200 + '\nStatus Code: 1'}]}}, {})])
    monkeypatch.setattr(vm, '_post', lambda *_args, **_kwargs: next(responses))
    with pytest.raises(suite.VmCommandError) as raised:
        vm.powershell('failing-command', 60)
    assert len(raised.value.record['raw']) > 1200
    assert raised.value.record['exit_code'] == 1


def test_vm_json_error_keeps_original_malformed_payload():
    subject = object.__new__(suite.Suite)
    wire = {'raw': 'Response: {malformed\nStatus Code: 0', 'output': '{malformed',
            'exit_code': 0}
    subject.vm = SimpleNamespace(powershell=lambda _command, _timeout: wire)
    with pytest.raises(suite.SuiteError, match='expected VM JSON') as raised:
        subject._vm_json('command', 60)
    assert raised.value.vm_record is wire


def test_guest_probe_invokes_curl_directly_and_preserves_native_diagnostics():
    ps = (SUITE_PATH.parent / 'scenario_probes.ps1').read_text()
    body = ps.split('function Invoke-PreflightB1', 1)[1].split('function New-ApplicationRequest', 1)[0]
    assert "@('--noproxy', '*', '-sS', '-o', 'NUL', '-w', '%{http_code}'" in body
    assert "'--connect-timeout', '10', '--max-time', '30', $url)" in body
    assert '[ScenarioNativeCapture]::Run' in body
    assert 'Start-Process' not in body and '2>$null' not in body
    assert '$global:LASTEXITCODE = 0' in body
    assert 'stderr_sha256' in body and 'actual_curl_exit' in body


def test_capture_wrapper_checks_ownership_and_bounds_pull(tmp_path):
    commands = []

    class FakeVm:
        def powershell(self, command, _timeout):
            commands.append(command)
            return {'output': json.dumps({'owner': 'owner', 'files': []})}

    vm = FakeVm()
    wrapper.start_capture(vm, 'owner', r'C:\diagnostics\unique')
    wrapper.stop_capture(vm, 'owner', r'C:\diagnostics\unique')
    assert "pktmon already active or unknown" in commands[0]
    assert commands[0].index('pktmon status') < commands[0].index('pktmon start')
    assert "ownership marker mismatch" in commands[1]
    assert commands[1].index('ReadAllText($marker)') < commands[1].index('pktmon stop')
    assert "active pktmon is not owned ETL" in commands[1]
    payload = b'bounded capture bytes'
    class FileVm:
        def powershell(self, _command, _timeout):
            return {'output': base64.b64encode(payload).decode()}
    info = {'path': r'C:\diagnostics\unique\p7.etl', 'size': len(payload),
            'sha256': __import__('hashlib').sha256(payload).hexdigest()}
    assert wrapper.pull_file(FileVm(), info, tmp_path / 'p7.etl')['size'] == len(payload)
    with pytest.raises(RuntimeError, match='64 MiB'):
        wrapper.pull_file(FileVm(), dict(info, size=wrapper.MAX_BYTES + 1),
                          tmp_path / 'too-large.etl')


def test_capture_wrapper_stops_owned_capture_when_child_fails(tmp_path, monkeypatch):
    actions = []
    monkeypatch.setattr(wrapper, 'start_capture', lambda *_: (actions.append('start') or
        {'owner': 'ours', 'etl': r'C:\diagnostics\unique\p7.etl',
         'started': '2026-01-01T00:00:00Z'}, {'output': '{}'}))
    monkeypatch.setattr(wrapper, 'stop_capture', lambda *_: (actions.append('stop') or
        {'ended': '2026-01-01T00:00:04Z'}, {'output': '{}'}))
    monkeypatch.setattr(wrapper, 'export_capture', lambda *_: (actions.append('export') or
        {'files': [{'path': r'C:\diagnostics\unique\p7.etl', 'size': 0, 'sha256':
                    hashlib.sha256(b'').hexdigest()}]}, {'output': '{}'}))
    monkeypatch.setattr(wrapper, 'pull_file', lambda _vm, _item, path:
                        (actions.append(('pull', path.name)) or {'path': str(path)}))
    class Child:
        def poll(self): return None
        def wait(self, timeout=None): return 3
    def launch(_command, **kwargs):
        control = Path(kwargs['env']['SST_P7_CAPTURE_CONTROL_DIR'])
        wrapper.save_control(control / 'request.json', {
            'suite_root': str(tmp_path / 'suite'), 'scenario_id': 'preflight-b1'})
        wrapper.save_control(control / 'done.json', {
            'run_id': 'run-1', 'probe_started_at': '2026-01-01T00:00:01Z',
            'probe_ended_at': '2026-01-01T00:00:03Z'})
        return Child()
    monkeypatch.setattr(wrapper.subprocess, 'Popen', launch)
    root = tmp_path / 'evidence'
    result = wrapper.run(object(), tmp_path / 'suite', root, ['fake-command'])
    assert actions == ['start', 'stop', 'export', ('pull', 'p7.etl')]
    assert result['process_exit'] == 3
    assert result['same_run_coverage'] is True
    assert json.loads((root / 'terminal.json').read_text())['capture_started'] is True


def test_capture_wrapper_does_not_stop_unowned_capture_on_start_error(tmp_path, monkeypatch):
    actions = []
    class Child:
        def poll(self): return None
        def wait(self, timeout=None): return 4
    def launch(_command, **kwargs):
        control = Path(kwargs['env']['SST_P7_CAPTURE_CONTROL_DIR'])
        wrapper.save_control(control / 'request.json', {'suite_root': str(tmp_path / 'suite')})
        return Child()
    monkeypatch.setattr(wrapper.subprocess, 'Popen', launch)
    def denied(*_):
        raise RuntimeError('pktmon already active or unknown')
    monkeypatch.setattr(wrapper, 'start_capture', denied)
    def ownership_guard(*_):
        actions.append('guarded')
        raise RuntimeError('pktmon ownership marker mismatch')
    monkeypatch.setattr(wrapper, 'stop_capture', ownership_guard)
    result = wrapper.run(object(), tmp_path / 'suite', tmp_path / 'evidence', ['fake-command'])
    assert actions == ['guarded'] and result['capture_started'] is False
    assert any('pktmon already active or unknown' in error for error in result['errors'])
    assert json.loads((tmp_path / 'evidence/control/ack.json').read_text())['status'] == 'error'


def test_uncertain_start_recovers_only_through_owned_stop_guard(tmp_path, monkeypatch):
    actions = []
    class Child:
        def poll(self): return None
        def wait(self, timeout=None): return 4
    def launch(_command, **kwargs):
        control = Path(kwargs['env']['SST_P7_CAPTURE_CONTROL_DIR'])
        wrapper.save_control(control / 'request.json', {'suite_root': str(tmp_path / 'suite')})
        return Child()
    monkeypatch.setattr(wrapper.subprocess, 'Popen', launch)
    def lost_response(*_):
        raise suite.VmCommandError('transport lost', {'raw': 'full start response'})
    monkeypatch.setattr(wrapper, 'start_capture', lost_response)
    monkeypatch.setattr(wrapper, 'stop_capture', lambda *_: (actions.append('owned-guard') or
        {'etl_exists': True, 'ended': '2026-01-01T00:00:04Z'}, {'raw': 'stop wire'}))
    result = wrapper.run(object(), tmp_path / 'suite', tmp_path / 'evidence', ['fake-command'])
    assert actions == ['owned-guard'] and result['capture_started'] is False
    assert json.loads((tmp_path / 'evidence/start-error-wire.json').read_text()) == {
        'raw': 'full start response'}
    assert result['same_run_coverage'] is False


def test_capture_deadline_stops_only_capture_and_waits_for_original_cleanup(tmp_path,
                                                                             monkeypatch):
    events = []
    suite_root = tmp_path / 'suite'
    control_path = tmp_path / 'evidence/control'

    class Child:
        pid = 7301
        waits = 0
        def poll(self): return None
        def wait(self, timeout=None):
            assert timeout == 30
            self.waits += 1
            if self.waits == 1:
                events.append('wait-long-cleanup')
                raise wrapper.subprocess.TimeoutExpired('scenario_suite', timeout)
            events.append('wait-cleanup-complete')
            suite_root.mkdir(exist_ok=True)
            (suite_root / 'preflight.json').write_text('{"passed":false}')
            wrapper.save_control(control_path / 'done.json', {
                'run_id': 'same-run', 'probe_started_at': '2026-01-01T00:00:01Z',
                'probe_ended_at': '2026-01-01T00:00:02Z',
                'cleanup': {'final': {'state': 'stopped',
                                      'config_identity': {'name': 'default.ini'}}}})
            return 4
        def terminate(self): raise AssertionError('must not terminate suite cleanup')
        def kill(self): raise AssertionError('must not kill suite cleanup')

    child = Child()
    def launch(_command, **kwargs):
        assert kwargs['start_new_session'] is True
        wrapper.save_control(control_path / 'request.json', {'suite_root': str(suite_root)})
        return child
    monkeypatch.setattr(wrapper.subprocess, 'Popen', launch)
    class FakeClock:
        now = 0.0
        def monotonic(self): return self.now
        def sleep(self, seconds): self.now += seconds
    clock = FakeClock()
    def bounded_wait(path, process, seconds):
        return wrapper.wait_for_original(path, process, seconds,
                                         clock=clock.monotonic, pause=clock.sleep)
    monkeypatch.setattr(wrapper, 'wait_for_original', wrapper.wait_for, raising=False)
    monkeypatch.setattr(wrapper, 'wait_for', bounded_wait)
    monkeypatch.setattr(wrapper, 'start_capture', lambda *_: (events.append('start-capture') or
        {'owner': 'ours', 'etl': r'C:\p7.etl', 'started': '2026-01-01T00:00:00Z'},
        {'raw': 'start'}))
    monkeypatch.setattr(wrapper, 'stop_capture', lambda *_: (events.append('stop-capture') or
        {'ended': '2026-01-01T00:00:03Z'}, {'raw': 'stop'}))
    monkeypatch.setattr(wrapper, 'export_capture', lambda *_: (events.append('export') or
        {'files': []}, {'raw': 'export'}))
    result = wrapper.run(object(), suite_root, tmp_path / 'evidence', ['suite-child'],
                         capture_seconds=0.1)
    assert events == ['start-capture', 'stop-capture', 'export',
                      'wait-long-cleanup', 'wait-cleanup-complete']
    assert result['capture_deadline_reached'] is True
    assert result['process_exit'] == 4 and result['same_run_coverage'] is False
    assert result['done_after_capture_stop'] is True
    assert result['done']['cleanup']['final']['config_identity']['name'] == 'default.ini'
    assert (tmp_path / 'evidence/recovery-pending.json').is_file()
    assert 'child-still-responsible' in (tmp_path / 'evidence/recovery-progress.jsonl').read_text()
    assert any('nonzero' in error for error in result['errors'])


def test_operator_interrupt_is_deferred_until_original_child_exits(tmp_path):
    class Child:
        pid = 7302
        calls = 0
        def poll(self): return None
        def wait(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise KeyboardInterrupt
            return 0
        def terminate(self): raise AssertionError('unexpected terminate')
        def kill(self): raise AssertionError('unexpected kill')
    child = Child()
    terminal = {'errors': [], 'capture_deadline_reached': True, 'stop': {'ended': 'done'}}
    wrapper.await_responsible_child(child, tmp_path, terminal)
    assert child.calls == 2 and terminal['process_exit'] == 0
    assert 'interrupt deferred' in terminal['errors'][0]
    assert 'interrupt-deferred' in (tmp_path / 'recovery-progress.jsonl').read_text()


def test_capture_stop_exception_keeps_child_cleanup_responsibility(tmp_path, monkeypatch):
    events = []
    suite_root = tmp_path / 'suite'

    class Child:
        pid = 7303
        def poll(self): return None
        def wait(self, timeout=None):
            events.append('child-exit-after-cleanup')
            return 4
        def terminate(self): raise AssertionError('unexpected terminate')
        def kill(self): raise AssertionError('unexpected kill')

    def launch(_command, **kwargs):
        control = Path(kwargs['env']['SST_P7_CAPTURE_CONTROL_DIR'])
        wrapper.save_control(control / 'request.json', {'suite_root': str(suite_root)})
        wrapper.save_control(control / 'done.json', {
            'run_id': 'same-run', 'probe_started_at': '2026-01-01T00:00:01Z',
            'probe_ended_at': '2026-01-01T00:00:02Z',
            'cleanup': {'final': {'state': 'stopped'}}})
        return Child()

    monkeypatch.setattr(wrapper.subprocess, 'Popen', launch)
    monkeypatch.setattr(wrapper, 'start_capture', lambda *_: (
        {'owner': 'ours', 'etl': r'C:\p7.etl', 'started': '2026-01-01T00:00:00Z'},
        {'raw': 'start'}))
    def stop_failed(*_):
        events.append('owned-stop-error')
        raise suite.VmCommandError('stop transport error', {'raw': 'complete stop wire'})
    monkeypatch.setattr(wrapper, 'stop_capture', stop_failed)
    result = wrapper.run(object(), suite_root, tmp_path / 'evidence', ['suite-child'])
    assert events == ['owned-stop-error', 'child-exit-after-cleanup']
    assert result['process_exit'] == 4 and result['same_run_coverage'] is False
    assert result['done']['cleanup']['final']['state'] == 'stopped'
    assert json.loads((tmp_path / 'evidence/stop-error-wire.json').read_text()) == {
        'raw': 'complete stop wire'}
