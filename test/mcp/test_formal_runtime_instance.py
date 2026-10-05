"""Exercise original native adjudication and capture stop at RPC-only boundaries.

All native bytes here are controlled offline inputs, never Windows pass credit.
"""
import base64
import copy
import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_formal_runtime_context import materials, load
from test_formal_runtime_transport import ByteClient
from test_formal_runtime_prepare import prepared
from formal_runtime.context import load_context
from fakenet.mcp.configstore import ConfigStore
from fakenet.mcp import errors
from formal_runtime import instance
from formal_runtime.recovery import ExactRecoveryVm
from formal_runtime.source import transfer_limit
from bounded_mcp import TransportUnknown
import scenario_suite as suite


def subject(context):
    r = suite.Suite(suite.parse_args([
        'generate', '--suite-root', str(context.evidence_root),
        '--candidate-id', context.candidate_identity['candidate'],
        '--source-commit', context.candidate_identity['source'],
        '--package-sha256', context.candidate_identity['zip_sha256'],
        '--guest-work-root', suite.E_GUEST_WORK_ROOT, '--capture-contract', 'scenario-shared-v2']))
    r.generate()
    return r


class NativeService:
    controller_id = 'controlled-native-environment'

    def __init__(self, context):
        self.context = context
        self.calls = []
        self.state, self.run_id, self.version = 'stopped', None, 1

    def tool_outcome(self, name, args=None, timeout=120):
        self.calls.append((name, args))
        if name == 'start':
            self.state, self.run_id = 'healthy', 'controlled-run'
        if name == 'stop':
            self.state, self.run_id = 'stopped', None
        if name in instance.MUTATIONS:
            self.version += 1
        value = {'state': self.state, 'run_id': self.run_id, 'state_version': self.version,
                 'controller': self.controller_id if self.run_id else None,
                 'config_identity': {'sha256': self.context.candidate_identity['default_sha256']},
                 'service': 'fakenetng-mcp'}
        return {'ok': True, 'error': None, 'value': value}

    def tool(self, name, args=None, timeout=120):
        return self.tool_outcome(name, args, timeout)['value']


class NativeVm:
    def __init__(self, context, failure=None):
        self.context, self.failure, self.calls = context, failure, []
        target = {'pid': 42, 'supervisor_pid': 2716, 'supervisor_creation_time': '134353511031206360',
                  'budget_seconds': 60}
        dump = b'controlled native dump bytes'
        result = {'target': target, 'entered_monotonic': 100, 'completed_monotonic': 105,
                  'deadline_monotonic': 160, 'notification': {
                      'target_pid': 42, 'initiator_pid': 42, 'exit_status': 49158},
                  'dump': {'name': 'controlled.dmp', 'sha256': hashlib.sha256(dump).hexdigest(), 'size': len(dump)},
                  'target_handle_closed': True}
        if failure == 'native-deadline':
            result['completed_monotonic'] = 161
        if failure == 'native-supervisor':
            target['supervisor_creation_time'] = '134353511031106360'
        prefix = r'C:\ProgramData\FakeNet-NG-MCP\logs\exit-evidence\controlled-native'
        self.bytes = {prefix + '\\' + name: json.dumps(value).encode() for name, value in {
            'entry.json': {'target': target}, 'result.json': result,
            'owner-result.json': {'target': target, 'helper_ended': True, 'retained_target_handle_closed': True},
            'capability.json': {'passed': True, 'elapsed_seconds': 5}, 'native-error.json': {'error': None}}.items()}
        self.bytes[prefix + r'\controlled.dmp'] = dump

    def powershell(self, command, timeout):
        self.calls.append(command)
        if '$s=[IO.File]::OpenRead(' in command:
            path = re.search(r"OpenRead\('([^']+)'\)", command)[1]
            offset = int(re.search(r'\$s.Seek\((\d+),', command)[1])
            length = int(re.search(r'New-Object byte\[\] (\d+)', command)[1])
            return {'output': base64.b64encode(self.bytes[path][offset:offset + length]).decode()}
        if '$runs=@()' in command:
            value = {'pid': 2716, 'filetime': '134353511031206360', 'runs': [{
                'run_id': 'controlled-native', 'files': [{'path': path, 'size': len(raw),
                    'sha256': hashlib.sha256(raw).hexdigest()} for path, raw in self.bytes.items()]}]}
        elif 'Import-Clixml' in command:
            value = {'present': True, 'values': ['FAKENETNG_MCP_FAULT_INJECTION=1']}
        elif 'Win32_Service' in command:
            value = {'computer': 'DESKTOP-3FI41GR', 'uuid': 'D9FD4D56-3DC4-C64B-19F1-411EEBC1CA49',
                     'mac': ['00-0C-29-C1-CA-49'], 'service': 'Running', 'pid': 2716,
                     'filetime': '134353511031206360', 'marker': {'needs_recovery': False},
                     'fault': False, 'fault_gate': False, 'config': {'stop_grace_seconds': 60},
                     'source': self.context.candidate_identity['source'],
                     'manifest_sha': self.context.candidate_identity['manifest_sha256'],
                     'members': [{'expected': 'a' * 64, 'actual': 'a' * 64} for _ in range(199)],
                     'environment_present': True, 'environment': ['FAKENETNG_MCP_FAULT_INJECTION=1']}
            if self.failure == 'candidate':
                value['manifest_sha'] = '0' * 64
        elif '$mac=@(Get-NetAdapter' in command:
            # Execute the real Suite.preflight and its P1 rejection, not a fake gate verdict.
            value = {'computer': 'WRONG-ENVIRONMENT', 'mac': []}
        else:
            raise AssertionError('unrecognized native environment boundary')
        return {'output': json.dumps(value), 'exit_code': 0}


def native_subject(materials, failure=None):
    context = load(materials)
    r = subject(context)
    r.vm, r.service = NativeVm(context, failure), NativeService(context)
    r.bootstrap_environment = ['FAKENETNG_MCP_FAULT_INJECTION=1']
    r.bootstrap_grace, r.bootstrap_preflight = 60, False
    state = instance.Responsibility()
    gate = instance.FirstSpikeInstanceGate(context, state)
    return context, r, state, gate


def test_original_native_six_adjudication_transfers_and_checks_all_original_bytes(materials, monkeypatch):
    context, r, state, gate = native_subject(materials)
    monkeypatch.setattr(instance.time, 'sleep', lambda _: None)
    verdict = gate(r, 'disabled', {'backup': 'controlled-backup.xml'})
    assert verdict['passed'] and all(verdict['checks'].values())
    assert len(verdict['checks']) == 8 and len(verdict['identity']) == 2
    assert len(list((r.root / 'instance-gates/disabled/six-originals').iterdir())) == 6
    assert sum('OpenRead(' in command for command in r.vm.calls) == 6
    assert not state.admission_ready  # The coordinator must require fresh P1-P7 before granting business.
    assert (r.root / 'instance-gates/disabled/result.json').is_file()
    with pytest.raises(AssertionError):
        gate(r, 'same-instance', {'backup': 'controlled-backup.xml'})
    assert [name for name, _ in r.service.calls].count('start') == 1


@pytest.mark.parametrize('failure', ['native-deadline', 'native-supervisor', 'candidate'])
def test_original_native_failure_never_grants_instance_admission(materials, monkeypatch, failure):
    _, r, state, gate = native_subject(materials, failure)
    monkeypatch.setattr(instance.time, 'sleep', lambda _: None)
    with pytest.raises(AssertionError):
        gate(r, 'enabled', {'backup': 'controlled-backup.xml'})
    verdict = json.loads((r.root / 'instance-gates/enabled/result.json').read_bytes())
    assert not verdict['passed'] and not state.admission_ready
    if failure == 'candidate':
        assert all(name not in instance.MUTATIONS for name, _ in r.service.calls)


def test_original_P1_P7_preflight_failure_blocks_after_native_six(materials, monkeypatch):
    _, r, state, gate = native_subject(materials)
    r.bootstrap_preflight = True
    monkeypatch.setattr(instance.time, 'sleep', lambda _: None)
    with pytest.raises(suite.Blocked, match='preflight failed'):
        gate(r, 'enabled', {'backup': 'controlled-backup.xml'})
    preflight = json.loads(r.preflight_path.read_bytes())
    assert preflight['passed'] is False and preflight['checks'][0]['id'] == 'P1-vm-identity'
    assert not state.admission_ready
    assert (r.root / 'instance-gates/enabled/six-native-verdict.json').is_file()


def test_native_six_then_actual_original_P1_P7_preserves_probe_and_config_cleanup(prepared, monkeypatch):
    repo, material, pin, _, plan = prepared
    context = load_context(material, pin, repository_root=repo)
    r = subject(context)
    for field, name in [('package_manifest', 'manifest'), ('package_verification', 'verification'),
                        ('deployment_record', 'deployment')]:
        setattr(r.args, field, plan['candidate_files'][name]['path'])
    store = ConfigStore(custom_root=r.root / 'product-store/custom', builtin_root=r.root / 'product-store/builtin',
                        audit_path=r.root / 'product-store/audit.jsonl')
    store.builtin_root.mkdir(parents=True)
    (store.builtin_root / 'default.ini').write_bytes(b'[FakeNet]\n')

    class ProductBoundary(NativeService):
        selected = 'default.ini'

        def tool_outcome(self, name, args=None, timeout=120):
            args = args or {}
            if name in ('create_config', 'read_config', 'delete_config'):
                self.calls.append((name, args))
                if name == 'read_config':
                    value = store.read(args['name'])
                else:
                    fields = {key: value for key, value in args.items() if key in
                              ('name', 'content', 'expected_sha256', 'command_id')}
                    value = getattr(store, 'create' if name == 'create_config' else 'delete')(
                        controller=self.controller_id, **fields)
                    self.version += 1
                return {'ok': True, 'value': value, 'error': None}
            if name == 'load_config': self.selected = args['name']
            answer = super().tool_outcome(name, args, timeout)
            current = store.read(self.selected)
            answer['value']['config_identity'] = {key: current[key] for key in ('name', 'sha256', 'builtin')}
            return answer

    script = (Path(__file__).parent / 'acceptance/scenario_probes.ps1').read_bytes()

    class ControlledTransfer:
        """HTTP socket/guest boundary only; original stage function still runs."""
        url = 'http://192.168.204.1:1/scenario_probes.ps1'
        def __init__(self, source, name):
            assert source.read_bytes() == script and name == 'scenario_probes.ps1'
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def record(self):
            return {'requests': [{'method': 'GET', 'path': '/scenario_probes.ps1', 'status': 200, 'bytes': len(script)}]}

    class FullPreflightVm(NativeVm):
        def powershell(self, command, timeout):
            value = None
            if '$mac=@(Get-NetAdapter' in command:
                value = {'computer': 'DESKTOP-3FI41GR', 'mac': ['00-0C-29-C1-CA-49']}
            elif '$parts=@()' in command:
                value = {'computer': 'DESKTOP-3FI41GR', 'root': suite.E_GUEST_WORK_ROOT, 'existing': [],
                         'c_free': 5 * 2**30, 'e_free': 12 * 2**30, 'e_drive_type': 3}
            elif '[Environment]::OSVersion' in command:
                value = {'computer': 'DESKTOP-3FI41GR', 'version': 'controlled-offline-10'}
            elif 'Resolve-DnsName' in command:
                value = {'routes': [{'InterfaceAlias': 'controlled-default-route'}],
                         'external_dns_server': '8.8.8.8', 'api_ipv4': '1.1.1.1'}
            elif 'DownloadFile' in command:
                value = {'sha256': hashlib.sha256(script).hexdigest(), 'bytes': len(script),
                         'path': suite.E_GUEST_WORK_ROOT + r'\scenario-suite-20260912\scenario_probes.ps1'}
            elif 'Test-NetConnection' in command:
                value = {'computer': 'DESKTOP-3FI41GR', 'tcp': False, 'remote': '198.51.100.77'}
            elif '& $p -Action preflight-b1 -Nonce $n' in command:
                value = {'actual_curl_exit': 0, 'exit_code': 0, 'http_code': '401',
                         'nonce': 'preflight-controlled', 'url': 'https://api.deepseek.com/preflight-controlled'}
                for stream, body in [('stdout', b'401'), ('stderr', b'')]:
                    path = suite.E_GUEST_WORK_ROOT + '\\p7-' + stream + '.raw'
                    self.bytes[path] = body
                    value.update({stream + '_path': path, stream + '_size': len(body),
                                  stream + '_sha256': hashlib.sha256(body).hexdigest()})
            if value is None: return super().powershell(command, timeout)
            self.calls.append(command)
            return {'output': json.dumps(value), 'exit_code': 0}

    monkeypatch.setattr(suite, 'HostOnlyFileTransfer', ControlledTransfer)
    monkeypatch.setattr(instance.time, 'sleep', lambda _: None)
    r.vm, r.service = FullPreflightVm(context), ProductBoundary(context)
    r.bootstrap_environment = ['FAKENETNG_MCP_FAULT_INJECTION=1']
    r.bootstrap_grace, r.bootstrap_preflight = 60, True
    state = instance.Responsibility()
    verdict = instance.FirstSpikeInstanceGate(context, state)(r, 'enabled', {'backup': 'controlled.xml'})
    assert verdict['passed']
    preflight = r._require_preflight()
    assert preflight['passed']
    assert [row['id'] for row in preflight['checks']] == [
        'P1-vm-identity', 'P1-guest-work-root', 'P2-candidate-material', 'P2-service-candidate',
        'P3-win10vm-mcp', 'P4-route-dns', 'P5-probe-stage', 'P5-empty-cycle', 'P6-test-net', 'P7-deepseek-relay']
    assert not store.list()[1:] and not (store.custom_root / 'sst-preflight-b1.ini').exists()
    commands = r.vm.calls
    assert commands.index(next(c for c in commands if '$runs=@()' in c)) < commands.index(
        next(c for c in commands if '$mac=@(Get-NetAdapter' in c))
    assert sum('& $p -Action preflight-b1 -Nonce $n' in c for c in commands) == 1
    assert not any('--resolve' in c for c in commands)
    assert not state.admission_ready  # Only the full coordinator can bind/enable business.


def test_fresh_instance_and_unknown_mutation_cannot_dispatch_business(materials):
    context = load(materials)
    client, state = NativeService(context), instance.Responsibility()
    guarded = instance.ProtectedService(client, context, state)
    with pytest.raises(suite.Blocked):
        guarded.tool_outcome('start', {})
    assert not client.calls
    state.admission_context = True
    def unknown(*_args):
        raise TransportUnknown('controlled unknown RPC', {'sent': 'possibly-sent'})
    client.tool_outcome = unknown
    with pytest.raises(instance.MutationUnknown):
        guarded.tool_outcome('load_config', {'name': 'default.ini'})
    assert not state.safe
    with pytest.raises(RuntimeError, match='no replay'):
        guarded.tool_outcome('stop', {})


@pytest.mark.parametrize('phase', ['completed', 'partial', 'wrong-nonce'])
def test_original_single_SCM_command_reconciles_only_matching_completed_receipt(materials, phase):
    context = load(materials)
    state = instance.Responsibility()
    state.receipt = context.physical_namespace + r'\scenario-suite-20260912\cycle\receipt.json'
    state.expected_enabled = True
    commands = []

    class Client:
        def powershell(self, command, timeout):
            commands.append(command)
            if 'Start-Service' in command:
                raise TransportUnknown('SCM response unknown', {'sent': 'possibly-sent'})
            return {'output': json.dumps({'stage': 'completed' if phase != 'partial' else 'start_intent',
                'enabled': True, 'answer': {'enabled': True, 'state': 'Running'},
                'dispatch_nonce': '0' * 64 if phase == 'wrong-nonce' else hashlib.sha256(state.receipt.encode()).hexdigest()})}

    guarded = instance.ProtectedVm(Client(), context, state)
    command = "Start-Service fakenetng-mcp;@{enabled=$true;backup='owned'}|ConvertTo-Json -Compress"
    if phase == 'completed':
        value = guarded.powershell(command, 180)
        assert value['original_response_unknown'] and value['projection'] == 'completed receipt.answer'
        assert state.safe and state.cycle_applied and not state.admission_ready
    else:
        with pytest.raises(TransportUnknown):
            guarded.powershell(command, 180)
        assert not state.safe and not state.cycle_applied
        with pytest.raises(RuntimeError):
            guarded.powershell(command, 180)
    assert len(commands) == 2 and sum('Start-Service' in command for command in commands) == 1


PROFILE = {'bucket': 'default', 'tempo': 'steady', 'variant': 'main', 'interleave': 'none',
    'cadence_ms': 1000, 'connection_window_seconds': 70,
    'probe_target': {'host': '198.51.100.77', 'port': 1337, 'protocol': 'tcp', 'process_mode': 'match'},
    'negative_cases': [], 'probe_cases': [], 'startup_retry_seconds': 70}


class CaptureClient(ByteClient):
    def __init__(self, context, bad=None, success=False):
        super().__init__()
        self.context, self.bad, self.starts, self.success = context, bad, 0, success
        self.run = context.physical_namespace + r'\scenario-suite-20260912\sst-001-a1\run-01'
        self.native_commands = []

    def powershell(self, command, timeout):
        raw = super().powershell(command, timeout)
        if '$__r46b=' in command or '@{size=(Get-Item' in command:
            return raw
        command = self.executions[-1]
        self.native_commands.append(command)
        if 'logman start $s -ets' in command:
            value = {'session_name': 'SST-Kernel-controlled', 'guest': self.run,
                     'metadata': self.run + r'\kernel-network.metadata.json'}
        elif "$encoded='" in command:
            self.starts += 1
            if not self.success:
                raise TransportUnknown('controlled capture start unknown', {'sent': 'possibly-sent'})
            value = {'guest': self.run, 'run_label': 'run-01', 'pid': 7, 'probe_creation_ticks': 11,
                     'etl': self.run + r'\pktmon.etl', 'probe': self.run + r'\probe.jsonl',
                     'stop': self.run + r'\probe.stop', 'pktmon_nic': self.run + r'\pktmon-nic.json'}
        elif 'probe_ready=$ready' in command:
            native = {'supported': True, 'run_id': 'bound-nonce:run-01',
                      'candidate_id': self.context.candidate_identity['candidate']}
            ready = {'pid': 7, 'creation_ticks': 11, 'nonce': 'bound-nonce', 'native_identity': native}
            value = {'run_root': self.run, 'probe_ready': ready, 'etl_exists': True,
                     'pktmon_exit': 0, 'pktmon_status': (
                         'Collected data:\n    Packet capture\nCapture type:\n    All packets\n'
                         'Logging parameters:\n    Logger name: PktMon\n    Log file: ' + self.run +
                         '\\pktmon.etl\n    Maximum file size: 128 MB\n'),
                     'process': {'pid': 7, 'creation_ticks': 11}}
            if self.bad == 'pid': value['process']['pid'] = 8
            if self.bad == 'creation': value['process']['creation_ticks'] = 12
            if self.bad == 'nonce': ready['nonce'] = 'foreign'
            if self.bad == 'capture':
                value['pktmon_status'] = value['pktmon_status'].replace(self.run, r'E:\foreign')
        elif 'Invoke-Expression $c' in command:
            value = {'coop': {'cooperative_exit': 'exited', 'errors': []}}
        elif 'pktmon stop' in command:
            value = {'owner_id': 'bound-nonce:pktmon', 'exit': 0, 'status_exit': 0, 'status': 'Stopped', 'output': 'controlled original stop'}
        elif 'logman query $m.session_name' in command:
            value = {'files': []}
        elif 'pktmon etl2txt' in command:
            value = {'conversion': {'exit_code': 0}, 'status': 'Stopped'}
        elif '$files=@(' in command:
            value = {'files': []}
        else:
            raise AssertionError('unexpected capture environment boundary')
        return {'output': json.dumps(value), 'exit_code': 0}


@pytest.mark.parametrize('bad', [None, 'pid', 'creation', 'nonce', 'capture'])
def test_original_snapshot_and_stop_use_exact_recovery_without_general_replay(materials, monkeypatch, bad):
    context = load(materials)
    r = subject(context)
    state = instance.Responsibility()
    client = CaptureClient(context, bad)
    r.vm = instance.ProtectedVm(client, context, state)
    instance.bind_namespace(r, context)
    client.run = r._guest_scenario_root('sst-001', 1) + r'\run-01'
    monkeypatch.setattr(instance.time, 'sleep', lambda _: None)
    expected = suite.RecoveredCaptureStart if bad is None else suite.UnsettledCaptureStart
    with pytest.raises(expected):
        r._start_capture_and_probe(r._guest_scenario_root('sst-001', 1), PROFILE, 'bound-nonce', 'run-01')
    assert not state.safe and client.starts == 1 and isinstance(r.vm, instance.ProtectedVm)
    stops = [command for command in client.native_commands if '$output=(& pktmon stop' in command]
    assert len(stops) == (1 if bad is None else 0)
    if bad is None:
        assert any(client.run + r'\probe.stop' in command and '11' in command for command in client.native_commands)
        assert sum('logman query $m.session_name' in command for command in client.native_commands) == 1
        assert len(list((context.evidence_root / 'exact-recovery').rglob('*.json'))) == 5
    with pytest.raises(RuntimeError):
        r.vm.powershell('Start-Service fakenetng-mcp', 30)


def test_live_source_budget_binds_only_after_original_capture_response_not_path_generation(materials):
    context = load(materials)
    r = subject(context)
    client = CaptureClient(context, success=True)
    r.vm = instance.ProtectedVm(client, context, instance.Responsibility())
    instance.bind_namespace(r, context)
    guest = r._guest_scenario_root('sst-001', 1)
    client.run = guest + r'\run-01'
    destination = context.evidence_root / 'copied/run-01/pktmon.txt'
    assert not hasattr(r, 'physical_source_binding')
    assert transfer_limit(r, client.run + r'\pktmon.txt', destination) == suite.MAX_GUEST_TRANSFER
    value = r._start_capture_and_probe(guest, PROFILE, 'bound-nonce', 'run-01')
    assert 'physical_owner_id' not in value  # Preserve the actual original response shape.
    assert transfer_limit(r, client.run + r'\pktmon.txt', destination) == suite.MAX_SHARED_PKTMON_TEXT_TRANSFER
    from formal_runtime.source import SourceError
    with pytest.raises(SourceError, match='ownership differs'):
        transfer_limit(r, client.run.replace('sst-001', 'sst-002') + r'\pktmon.txt', destination)


def test_exact_recovery_refuses_force_kill_foreign_stop_and_replay_from_new_adapter(materials):
    context = load(materials)
    client, state = ByteClient(), instance.Responsibility()
    protected = instance.ProtectedVm(client, context, state)
    root = context.physical_namespace + r'\scenario-suite-20260912\owned\run-01'
    cap = {'guest': root, 'run_label': 'run-01', 'pid': 7, 'probe_creation_ticks': 11,
           'nonce': 'owned-nonce', 'physical_owner_id': 'owned-nonce:pktmon',
           'probe': root + r'\probe.jsonl', 'stop': root + r'\probe.stop',
           'etl': root + r'\pktmon.etl', 'pktmon_nic': root + r'\pktmon-nic.json',
           'kernel_capture': {'guest': root, 'metadata': root + r'\kernel-network.metadata.json',
                              'session_name': 'SST-Kernel-owned'}}
    recovery = ExactRecoveryVm(protected, cap, context)
    for command in ['Stop-Process -Id 7', 'Stop-Service fakenetng-mcp', 'pktmon start',
                    'pktmon stop', 'logman stop foreign', "WriteAllText('E:\\foreign','stop')"]:
        with pytest.raises(RuntimeError): recovery.powershell(command, 30)
    assert not client.calls
    command = "$output=(& pktmon stop|Out-String);@{owner_id='owned-nonce:pktmon'}|ConvertTo-Json -Compress"
    recovery.powershell(command, 30)
    second = ExactRecoveryVm(protected, cap, context)
    with pytest.raises(RuntimeError, match='never replay'):
        second.powershell(command, 30)
    assert len(client.calls) == 1
