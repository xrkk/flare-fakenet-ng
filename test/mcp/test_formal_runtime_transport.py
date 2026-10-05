"""Exercise real staging with an exact-byte client at the environment boundary."""

import base64
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials, load
from formal_runtime import command_transport as transport
from formal_runtime.context import MaterialError
from bounded_mcp import TransportUnknown
import scenario_suite as suite


LONG_COMMAND = "Write-Output '🧪原字节';\n#" + 'x' * 12500


class Responsibility:
    def __init__(self):
        self.safe = True

    def refuse(self):
        if not self.safe:
            raise RuntimeError('unknown responsibility')

    def unknown(self, error):
        self.safe = False


class ByteClient:
    def __init__(self, failure=None):
        self.failure = failure
        self.calls = []
        self.files = {}
        self.executions = []
        self.response = {'output': '原始 stdout\n', 'exit_code': 0, 'raw': 'unaltered', 'is_error': False}

    def powershell(self, command, timeout):
        self.calls.append((command, timeout, getattr(self, '_absolute_deadline', None)))
        if '$__r46b=' in command:
            path = re.search(r"\$__r46p='([^']+)'", command)[1]
            block = base64.b64decode(re.search(r"FromBase64String\('([^']+)'\)", command)[1])
            offset = int(re.search(r'Length -ne (\d+)', command)[1])
            if self.failure == 'stage-unknown':
                raise TransportUnknown('possibly sent', {})
            if self.failure == 'collision':
                raise suite.VmCommandError('stage collision', {'exit_code': 1})
            if '::CreateNew' in command:
                assert path not in self.files
                self.files[path] = b''
            assert len(self.files[path]) == offset
            prefix = re.search(r"-cne '([a-f0-9]{64})'", command)[1]
            assert transport.digest(self.files[path]) == prefix
            assert len(block) <= transport.CHUNK
            self.files[path] += block
            return {'output': json.dumps({'size': len(self.files[path]),
                                         'sha256': '0' * 64 if self.failure == 'sha' else transport.digest(self.files[path])})}
        if '@{size=(Get-Item' in command:
            path = re.search(r"\$p='([^']+)'", command)[1]
            return {'output': json.dumps({'size': len(self.files[path]),
                                         'sha256': '0' * 64 if self.failure == 'full-sha' else transport.digest(self.files[path])})}
        if '$__r46StageFile=' in command:
            path = re.search(r"\$__r46StageFile='([^']+)'", command)[1]
            assert transport.digest(self.files[path]) == re.search(r"-cne '([a-f0-9]{64})'", command)[1]
            assert '. $__r46StageFile' in command and 'Start-Process' not in command
            self.executions.append(self.files[path].decode('utf-8-sig'))
        else:
            self.executions.append(command)
        if self.failure == 'execute-unknown':
            raise TransportUnknown('possibly executed', {})
        if self.failure == 'execute-error':
            raise suite.VmCommandError('original failure', {'exit_code': 7, 'output': 'original error'})
        return self.response


def adapter(materials, client=None, responsibility=None):
    return transport.StageFileVm(client or ByteClient(), load(materials), responsibility or Responsibility())


def test_short_command_uses_original_client_and_response_without_staging(materials):
    client = ByteClient()
    vm = adapter(materials, client)
    assert vm.powershell('Get-Content owned', 37) is client.response
    assert client.calls == [('Get-Content owned', 37, None)]
    assert not vm.context.evidence_root.exists()


def test_long_command_stages_exact_bytes_and_preserves_original_result(materials):
    client = ByteClient()
    vm = adapter(materials, client)
    result = vm.powershell(LONG_COMMAND, 120)
    assert transport.wire_units(LONG_COMMAND) > transport.LIMIT
    assert list(client.files.values()) == [transport.script_bytes(LONG_COMMAND)]
    assert client.executions == [LONG_COMMAND]
    for key, value in client.response.items():
        assert result[key] == value
    assert all(transport.wire_units(c) <= transport.LIMIT and 0 < t <= 120 for c, t, _ in client.calls)
    assert len({deadline for _, _, deadline in client.calls}) == 1
    assert client._absolute_deadline == float('inf')
    receipt = json.loads(Path(result['file_transport']['stage_receipt']).read_text())
    assert receipt['passed'] and receipt['execution_started'] and receipt['local_writers_ended']
    assert not receipt['unknown']
    assert result['file_transport']['guest_path'].startswith(vm.context.physical_namespace + '\\transport-stage\\')


@pytest.mark.parametrize('failure', ['sha', 'full-sha', 'collision'])
def test_bad_stage_refuses_original_execution(materials, failure):
    client = ByteClient(failure)
    vm = adapter(materials, client)
    with pytest.raises((transport.CommandTransportError, suite.VmCommandError)):
        vm.powershell(LONG_COMMAND)
    assert not client.executions
    terminal = next(vm.context.evidence_root.glob('file-transport/*/terminal.json'))
    assert not json.loads(terminal.read_text())['passed']


@pytest.mark.parametrize('failure,command', [('stage-unknown', LONG_COMMAND),
                                            ('execute-unknown', LONG_COMMAND),
                                            ('execute-unknown', 'Get-Content owned')])
def test_unknown_request_never_reissued_even_by_new_adapter(materials, failure, command):
    client = ByteClient(failure)
    vm = adapter(materials, client)
    with pytest.raises(TransportUnknown):
        vm.powershell(command)
    assert not vm.responsibility.safe
    before = len(client.calls)
    for target in (vm, adapter(materials, client)):
        with pytest.raises(transport.CommandTransportError, match='never reissue'):
            target.powershell(command)
    assert len(client.calls) == before


def test_known_remote_failure_preserves_original_exception_and_exit(materials):
    vm = adapter(materials, ByteClient('execute-error'))
    with pytest.raises(suite.VmCommandError) as failure:
        vm.powershell(LONG_COMMAND)
    assert failure.value.record['exit_code'] == 7
    assert failure.value.record['output'] == 'original error'
    assert vm.responsibility.safe


def test_original_deadline_is_not_reset_between_chunks(materials, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(transport, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    client = ByteClient()
    original = client.powershell

    def slow(command, timeout):
        raw = original(command, timeout)
        clock[0] += 0.28
        return raw

    client.powershell = slow
    vm = adapter(materials, client)
    with pytest.raises(transport.CommandTransportError, match='deadline exhausted'):
        vm.powershell(LONG_COMMAND, 3)
    assert client.calls and not client.executions
    assert len({deadline for _, _, deadline in client.calls}) == 1
    assert 1000 < clock[0] < 1003


def test_late_response_is_unknown_not_success(materials, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(transport, 'time', SimpleNamespace(monotonic=lambda: clock[0]))
    client = ByteClient()
    original = client.powershell

    def late(command, timeout):
        raw = original(command, timeout)
        clock[0] += 3
        return raw

    client.powershell = late
    vm = adapter(materials, client)
    with pytest.raises(TransportUnknown, match='deadline exhausted during parsing'):
        vm.powershell(LONG_COMMAND, 3)
    assert not vm.responsibility.safe and not client.executions


@pytest.mark.parametrize('variable', ['PSScriptRoot', 'pscommandpath', 'MyInvocation'])
def test_file_location_semantics_refused_before_staging(materials, variable):
    vm = adapter(materials)
    with pytest.raises(transport.CommandTransportError, match='automatic variable'):
        vm.powershell(LONG_COMMAND + ';$' + variable)
    assert not vm.client.calls and not vm.context.evidence_root.exists()


def test_unknown_responsibility_refuses_long_read_staging(materials):
    state = Responsibility()
    state.safe = False
    vm = adapter(materials, responsibility=state)
    with pytest.raises(RuntimeError, match='unknown responsibility'):
        vm.powershell('Get-Content owned;#' + 'x' * 12500)
    assert not vm.client.calls and not vm.context.evidence_root.exists()


def test_oversize_script_and_changed_material_refused_before_client(materials):
    vm = adapter(materials)
    with pytest.raises(transport.CommandTransportError, match='script bound'):
        vm.powershell('x' * transport.MAX_SCRIPT)
    assert not vm.client.calls and not vm.context.evidence_root.exists()
    materials[1].write_text('changed')
    with pytest.raises(MaterialError, match='independent materials SHA256 mismatch'):
        vm.powershell('Get-Content owned')
    assert not vm.client.calls


def test_utf16_count_and_encoded_namespace_preserve_non_bmp_and_other_text():
    assert transport.units('🧪') == 2
    child = "Write-Output '🧪';Get-Content 'E:\\old\\input'"
    token = base64.b64encode(child.encode('utf-16-le')).decode('ascii')
    original = "$encoded='" + token + "';$timeout=37;Get-Content 'E:\\old\\outside'"
    mapped = transport.map_command(original, ((r'E:\old', r'E:\bound'),))
    decoded = base64.b64decode(re.search(r"\$encoded='([^']+)'", mapped)[1]).decode('utf-16-le')
    assert decoded == child.replace(r'E:\old', r'E:\bound')
    assert ";$timeout=37;Get-Content 'E:\\bound\\outside'" in mapped
    assert transport.map_command(original, ((r'E:\unused', r'E:\bound'),)) == original


@pytest.mark.parametrize('shared', [False, True])
def test_original_suite_launch_command_reaches_real_stage_adapter(materials, shared):
    class LaunchClient(ByteClient):
        def powershell(self, command, timeout):
            raw = super().powershell(command, timeout)
            if self.executions and '$__r46b=' not in command and '@{size=(Get-Item' not in command:
                original = self.executions[-1]
                if "$encoded='" in original:
                    label = 'run-02' if shared else 'run-01'
                    run = guest + '\\' + label
                    return {'output': json.dumps({
                        'guest': run, 'run_label': label, 'pid': 7, 'probe_creation_ticks': 11,
                        'physical_owner_id': 'bound-nonce:pktmon', 'nonce': 'bound-nonce',
                        'capture_run_id': 'bound-nonce:' + label,
                        'etl': guest + r'\run-01\pktmon.etl', 'probe': run + r'\probe.jsonl',
                        'start': run + r'\probe.start', 'case': run + r'\probe.cases',
                        'stop': run + r'\probe.stop', 'pktmon_nic': guest + r'\run-01\pktmon-nic.json'})}
                if 'logman start $s -ets' in original:
                    return {'output': json.dumps({'session_name': 'SST-Kernel-fixture',
                                                   'metadata': 'owned.metadata.json', 'guest': 'owned-run'})}
            return raw

    context = load(materials)
    instance = suite.Suite(suite.parse_args([
        'generate', '--candidate-id', context.candidate_identity['candidate'],
        '--source-commit', context.candidate_identity['source'], '--package-sha256', 'p',
        '--suite-root', str(context.evidence_root)]))
    instance.guest_work_root = context.physical_namespace
    instance.capture_contract = 'scenario-shared-v2'
    client = LaunchClient()
    staged = adapter(materials, client)

    # A length-only comment exercises the original Suite parent script without
    # modifying its probe parameters, encoded child, or lifecycle decisions.
    instance.vm = SimpleNamespace(powershell=lambda command, timeout=120:
                                  staged.powershell(command + '\n#' + 'L' * 12500, timeout))
    guest = context.physical_namespace + r'\scenario-suite-20260912\owned-sst-001-a1'
    profile = {'bucket': 'default', 'tempo': 'steady', 'variant': 'main', 'interleave': 'none',
               'cadence_ms': 1000, 'connection_window_seconds': 70,
               'probe_target': {'host': '198.51.100.77', 'port': 1337, 'protocol': 'tcp',
                                'process_mode': 'match', 'tls_server_name': '', 'fnpr_role': ''},
               'negative_cases': [], 'probe_cases': [], 'startup_retry_seconds': 70}
    if shared:
        value = instance._start_probe_on_shared_capture(guest, profile, 'bound-nonce', 'run-02', {
            'run_label': 'run-01', 'etl': guest + r'\run-01\pktmon.etl',
            'pktmon_nic': guest + r'\run-01\pktmon-nic.json', 'physical_owner_id': 'bound-nonce:pktmon'})
    else:
        value = instance._start_capture_and_probe(guest, profile, 'bound-nonce', 'run-01')
    assert value['pid'] == 7 and value['probe_creation_ticks'] == 11
    parents = [command for command in client.executions if "$encoded='" in command]
    assert len(parents) == 1
    child = base64.b64decode(re.search(r"\$encoded='([^']+)'", parents[0])[1]).decode('utf-16-le')
    assert context.physical_namespace in child and 'bound-nonce' in child
    assert "TargetHost='198.51.100.77'" in child and '--resolve' not in child
    assert transport.script_bytes(parents[0]) in client.files.values()
    assert all(transport.wire_units(command) <= transport.LIMIT for command, _, _ in client.calls)
