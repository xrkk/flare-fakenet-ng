"""Original SCM/preflight/P7/copy/Batch functions with environment-only seams.

Native packets and process records are controlled fixtures; real VM credit is 0.
"""
import base64
import hashlib
import json
import re
import signal
import subprocess
from pathlib import Path, PurePath, PureWindowsPath
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials
from test_formal_runtime_prepare import prepared
from test_formal_runtime_instance import full_preflight_environment
from test_formal_runtime_dns import pinned_probe, originals, SOURCE
from formal_runtime import coordinator, dns_capture, config_ownership, instance
from bounded_mcp import TransportUnknown
import scenario_suite as suite
import formal_batch_v3 as batch


@pytest.fixture
def environment(prepared, monkeypatch):
    _, r, store, state = full_preflight_environment(prepared, monkeypatch)
    repo, material, pin, data, plan = prepared
    context = pinned_probe((repo, material, pin, data))
    base = r.vm
    wire_pcap, log, native, probe, _, _ = originals(context.evidence_root / 'controlled-DNS-originals')
    raw_powershell = base.powershell
    model = {'pid': 2716, 'filetime': '134353511031206360', 'environment': [], 'grace': 60,
             'scm_calls': 0, 'unknown_SCM': False, 'bad_DNS': False, 'identity_drift': False}
    operations, processes = [], []

    def update_native():
        for path in list(base.bytes):
            if PureWindowsPath(path).name not in ('entry.json', 'owner-result.json', 'result.json'): continue
            value = json.loads(base.bytes[path]); target = value['target']
            target.update(supervisor_pid=model['pid'], supervisor_creation_time=model['filetime'])
            base.bytes[path] = json.dumps(value).encode()

    def boundary(command, timeout):
        operations.append(command)
        if 'Start-Service fakenetng-mcp' in command:
            model['scm_calls'] += 1
            enabled = '$answer=@{enabled=$true;' in command
            fault = 'config_bytes_restored=' in command or '$cfgObject.stop_grace_seconds=5' in command
            model.update(pid=model['pid'] + 1, filetime=str(int(model['filetime']) + 1000),
                         environment=['FAKENETNG_MCP_FAULT_INJECTION=1'] if fault or enabled else [],
                         grace=5 if fault and enabled else 60)
            update_native()
            if model['unknown_SCM']:
                raise TransportUnknown('controlled SCM response unknown', {'sent': 'possibly_sent'})
            return {'output': json.dumps({'enabled': enabled, 'backup': 'controlled-original-snapshot',
                        'state': 'Running', 'environment_restored': not enabled,
                        'config_bytes_restored': not enabled}), 'exit_code': 0}
        if "if(Test-Path $r){Get-Content $r -Raw}" in command:
            return {'output': json.dumps({'stage': 'start_intent', 'enabled': True})}
        if command == config_ownership.INVENTORY_COMMAND:
            rows = [dict(row, path=str(PureWindowsPath(config_ownership.BUILTIN if row['builtin']
                                  else config_ownership.CUSTOM) / row['name'])) for row in store.list()]
            return {'output': json.dumps({'schema': 'r48.config-inventory.v1', 'complete': True,
                'custom_root': config_ownership.CUSTOM, 'builtin_root': config_ownership.BUILTIN,
                'rows': rows, 'count': len(rows)})}
        if '@{pid=$p.Id;filetime=' in command and '$runs=@()' not in command:
            return {'output': json.dumps({'pid': model['pid'] + int(model['identity_drift']),
                                         'filetime': model['filetime']})}
        if command == coordinator.SCENE:
            manifest = json.loads(Path(plan['candidate_files']['manifest']['path']).read_bytes())
            return {'output': json.dumps({'computer': 'DESKTOP-3FI41GR',
                'uuid': 'D9FD4D56-3DC4-C64B-19F1-411EEBC1CA49', 'mac': ['00-0C-29-C1-CA-49'],
                'service': 'Running', 'source': context.candidate_identity['source'],
                'manifest_sha': context.candidate_identity['manifest_sha256'],
                'members': manifest['files'], 'pid': model['pid'] + int(model['identity_drift']),
                'filetime': model['filetime'], 'marker': {'needs_recovery': False}, 'workers': [],
                'fault': False, 'fault_gate': False, 'env': model['environment'],
                'env_present': bool(model['environment']), 'grace': model['grace'],
                'config_sha': 'c' * 64, 'space': [{'Name': 'C', 'Free': 5 * 2**30}, {'Name': 'E', 'Free': 12 * 2**30}]})}
        if 'Import-Clixml' in command:
            return {'output': json.dumps({'present': bool(model['environment']), 'values': model['environment']})}
        if "$fault='C:\\ProgramData" in command:
            return {'output': json.dumps({'fault': False, 'probe_count': 0, 'pktmon': 'PktMon is not running.'})}
        if 'route.exe print -4' in command:
            raise suite.VmCommandError('CONTROLLED FORMAL BASELINE REJECTED; no traffic run', {'exit_code': 7})
        if 'Add-Original' in command:
            run = re.search(r'run_id=\x27([a-f0-9-]+)\x27', command)[1]
            root = r'C:\ProgramData\FakeNet-NG-MCP\artifacts\runs' + '\\' + run
            rows = [{'root': root, 'path': path, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                     'sha256_after': hashlib.sha256(raw).hexdigest()}
                    for path, raw in base.bytes.items() if path.startswith(root + '\\')]
            return {'output': json.dumps({'run_id': run, 'files': rows, 'missing': []})}
        if '& $p -Action preflight-b1 -Nonce $n' in command:
            run = base.product_boundary.run_id
            root = r'C:\ProgramData\FakeNet-NG-MCP\artifacts\runs' + '\\' + run
            base.bytes[root + r'\run.log'] = log.read_bytes()
            base.bytes[root + r'\relay-native-events.jsonl'] = native.read_bytes()
            if model['bad_DNS']:
                base.bytes[root + r'\run.log'] = base.bytes[root + r'\run.log'].replace(b'ttl=30', b'ttl=31')
        raw = raw_powershell(command, timeout)
        if 'Win32_Service' in command or '$runs=@()' in command:
            value = json.loads(raw['output'])
            value.update(pid=model['pid'], filetime=model['filetime'])
            if 'environment' in value:
                value.update(environment=model['environment'], environment_present=bool(model['environment']),
                             config={'stop_grace_seconds': model['grace']})
            raw = dict(raw, output=json.dumps(value))
        return raw

    base.powershell = boundary
    r.args.command = 'run'
    r.vm = instance.ProtectedVm(base, context, state)
    r.service = instance.ProtectedService(r.service, context, state)
    instance.bind_namespace(r, context)
    config_ownership.prestart_gate(r, context)
    caps = dns_capture.Captures(r, context)
    co = coordinator.Coordinator(r, state, caps, context)
    original_popen, original_run, original_check_output = subprocess.Popen, subprocess.run, subprocess.check_output

    class Process:
        def __init__(self, argv):
            self.pid, self.argv, self.returncode = 73000 + len(processes), argv, None
            output = Path(argv[argv.index('-w') + 1]); output.write_bytes(wire_pcap.read_bytes())
            processes.append(self)
        def poll(self): return self.returncode
        def send_signal(self, value):
            assert value == signal.SIGINT
            self.returncode = 0
        def wait(self, timeout):
            assert self.returncode is not None
            return self.returncode
        def kill(self): self.returncode = -9

    def popen(argv, **kwargs):
        if argv[0] == 'dumpcap': return Process(argv)
        return original_popen(argv, **kwargs)
    def run(argv, **kwargs):
        if argv == ['dumpcap', '-D']: return subprocess.CompletedProcess(argv, 0, stdout=b'controlled interface', stderr=b'')
        return original_run(argv, **kwargs)
    def check_output(argv, **kwargs):
        if argv[:4] == ['ip', '-j', 'route', 'get']:
            assert argv[4] == SOURCE
            return json.dumps([{'prefsrc': '192.168.204.1', 'dev': 'vmnet8'}])
        return original_check_output(argv, **kwargs)
    monkeypatch.setattr(subprocess, 'Popen', popen)
    monkeypatch.setattr(subprocess, 'run', run)
    monkeypatch.setattr(subprocess, 'check_output', check_output)
    monkeypatch.setattr(coordinator.shutil, 'disk_usage', lambda _: SimpleNamespace(free=100 * 2**30))
    return context, r, store, state, caps, co, model, operations, processes


def test_actual_single_SCM_then_native_P1_P7_DNS_closed_export_and_restore(environment):
    context, r, store, state, caps, co, model, calls, processes = environment
    old_begin, old_end, old_reconcile = suite.p7_capture_begin, suite.p7_capture_end, suite.reconcile_timed_out_command
    with co.installed():
        enabled = r._ipc_evidence_mode(True)
        first = co.batch_gate(r, 'enabled', enabled)
        assert first['passed'] and state.admission_ready and len(co.admitted) == 1
        old_identity = dict(co.current)
        assert r._continuation_gate()['current_native_identity'] == old_identity
        disabled = r._ipc_evidence_mode(False)
        second = co.batch_gate(r, 'disabled', disabled)
        assert second['passed'] and co.current != old_identity and len(co.admitted) == 2
        assert all(value['passed'] for value in co.admitted)
    assert model['scm_calls'] == 2 and len(processes) == 2 and all(p.poll() == 0 for p in processes)
    assert not caps.owned
    assert not list(store.custom_root.glob('sst-*.ini')) and not r.service.owned
    assert suite.p7_capture_begin is old_begin and suite.p7_capture_end is old_end
    assert suite.reconcile_timed_out_command is old_reconcile and caps.runner is r and not state.admission_context
    bindings = list(context.evidence_root.glob('instances/*/P7-original-capture-*/runtime-DNS-lease-TLS-binding.json'))
    assert len(bindings) == 2 and all(json.loads(path.read_bytes())['passed'] for path in bindings)
    assert sum('Start-Service fakenetng-mcp' in command for command in calls) == 2


def test_original_Batch_and_original_run_one_stop_next_row_after_controlled_baseline_failure(environment):
    context, r, _, state, caps, co, model, _, processes = environment
    rows = [row for row in r.manifest()['scenarios'] if row['fault_class'] is None][:2]
    argv = Path(context.materials['suite_argv']['benign']['path'])
    args = batch.load_suite_args(argv)
    with co.installed():
        terminal = batch.run_batch(r, args, argv, 'offline-original-chain', rows, r.manifest(),
                                  {'passed': False, 'deferred_until_enabled_instance': True}, instance_gate=co.batch_gate)
    assert not terminal['passed'] and rows[1]['scenario_id'] in terminal['not_executed']
    assert model['scm_calls'] == 2 and len(co.admitted) == 2 and state.safe
    assert not r._result_path(rows[1]['scenario_id']).exists()
    assert not caps.owned and all(p.poll() == 0 for p in processes)


def test_unknown_original_SCM_never_replays_or_runs_native_business(environment):
    context, r, _, state, caps, co, model, _, processes = environment
    model['unknown_SCM'] = True
    with co.installed():
        with pytest.raises(TransportUnknown): r._ipc_evidence_mode(True)
        assert not r._ipc_restore_allowed()
        with pytest.raises(RuntimeError): r._ipc_evidence_mode(False)
    assert model['scm_calls'] == 1 and not state.safe and not state.admission_ready
    assert not co.admitted and not processes and not caps.owned
    ledger = json.loads((context.evidence_root / 'cycle-1-responsibility.json').read_bytes())
    assert not ledger['transaction_completed'] and ledger['admission_not_granted_by_transaction']


def test_DNS_lease_conflict_preserves_original_preflight_failure_and_revokes_hooks(environment):
    context, r, _, state, caps, co, model, _, processes = environment
    model['bad_DNS'] = True
    old_begin, old_end = suite.p7_capture_begin, suite.p7_capture_end
    with co.installed():
        with pytest.raises(suite.Blocked): r._ipc_evidence_mode(True)
    assert model['scm_calls'] == 1 and not state.admission_ready and not co.admitted
    assert not caps.owned and all(p.poll() == 0 for p in processes)
    assert suite.p7_capture_begin is old_begin and suite.p7_capture_end is old_end
    failures = list(context.evidence_root.glob('instances/*/P7-original-capture-*/P7-binding-failure.json'))
    assert len(failures) == 1 and json.loads(failures[0].read_bytes())['no_fake_lease_or_retry']


def test_fresh_low_capacity_refuses_every_VM_call_before_SCM(environment, monkeypatch):
    _, r, _, state, _, co, model, commands, _ = environment
    initial = len(commands)
    monkeypatch.setattr(coordinator.shutil, 'disk_usage', lambda _: SimpleNamespace(free=23 * 2**30))
    with co.installed():
        with pytest.raises(AssertionError): r._ipc_evidence_mode(True)
    assert len(commands) == initial and model['scm_calls'] == 0 and co.seq == 0 and not state.admission_ready


def test_actual_fault_instance_is_admitted_before_original_profile_freeze_and_restored_once(environment):
    context, r, _, state, caps, co, model, calls, processes = environment
    scenario = next(row for row in r.manifest()['scenarios'] if row['fault_class'])
    with co.installed():
        r._ipc_evidence_mode(True)
        result = r._run_one(scenario, 1)
        assert result['state'] != 'pass' and co.fault_restore_pending
        assert r._ipc_restore_allowed() and not co.fault_restore_pending
        r._ipc_evidence_mode(False)
    assert model['scm_calls'] == 4 and len(co.admitted) == 4 and state.safe
    assert model['environment'] == [] and model['grace'] == 60 and not caps.owned
    assert len(processes) == 4 and all(process.poll() == 0 for process in processes)
    note = json.loads((context.evidence_root / 'scenario-bindings' / (scenario['scenario_id'] + '-a1.json')).read_bytes())
    assert note['profile_freeze_after_fault_instance_admission'] and note['no_extra_SCM_enable']
    assert PurePath(note['selected_preflight']['path']).as_posix().count('/instances/cycle-02/') == 1
    assert sum('$cfgObject.stop_grace_seconds=5' in command for command in calls) == 1


def test_current_instance_drift_refuses_business_gate(environment):
    context, r, _, _, caps, co, model, _, processes = environment
    with co.installed():
        enabled = r._ipc_evidence_mode(True)
        model['identity_drift'] = True
        with pytest.raises(AssertionError): co.batch_gate(r, 'enabled', enabled)
        with pytest.raises(AssertionError): r._continuation_gate()
    assert model['scm_calls'] == 1 and not caps.owned and all(process.poll() == 0 for process in processes)


def test_P7_hook_scope_refuses_second_owner_and_restores_every_original(environment):
    _, r, _, _, caps, _, _, _, _ = environment
    other = dns_capture.Captures(r, caps.context)
    begin, end = suite.p7_capture_begin, suite.p7_capture_end
    with caps.probe_hooks():
        with pytest.raises(RuntimeError, match='context overlap'):
            with other.probe_hooks(): pytest.fail('second context must not install hooks')
        assert suite.p7_capture_begin == caps.begin and suite.p7_capture_end == caps.end
    assert suite.p7_capture_begin is begin and suite.p7_capture_end is end


def test_P7_failure_preserved_when_terminal_audit_write_fails(environment, monkeypatch):
    context, r, _, _, caps, _, model, _, _ = environment
    out = context.evidence_root / 'controlled-terminal-failure'
    out.mkdir()
    control = {'root': str(out), 'native_identity_command': '@{pid=$p.Id;filetime=',
               'native_identity': {'pid': model['pid'], 'filetime': model['filetime']}}
    original_open = Path.open

    def open_boundary(path, *args, **kwargs):
        if path == out / 'terminal.json':
            raise OSError('controlled local audit storage failure')
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'open', open_boundary)
    with pytest.raises(RuntimeError, match='did not reach original domain probe') as failure:
        caps.end(control, None, None, {})
    assert any('audit storage failure' in note for note in failure.value.__notes__)
    assert json.loads((out / 'P7-binding-failure.json').read_bytes())['original_failure_retained']
    assert caps.pending is None and r.vm.p7_binding is None and r.vm.p7_capture_start is None


def test_owned_host_process_unresolved_is_retained_after_close_failure(environment):
    context, _, _, _, caps, _, _, _, _ = environment
    out = context.evidence_root / 'controlled-unresolved-process'
    out.mkdir()
    stream = (out / 'stderr').open('x')

    class UnresolvedProcess:
        pid = 74001
        def poll(self): return None
        def send_signal(self, _): pass
        def wait(self, timeout): raise subprocess.TimeoutExpired('dumpcap', timeout)
        def kill(self): pass

    owned = (UnresolvedProcess(), stream, out / 'capture.pcap', ['dumpcap', 'controlled'])
    caps.owned.append(owned)
    with pytest.raises(RuntimeError, match='74001'): caps.close()
    assert caps.owned == [owned] and stream.closed
