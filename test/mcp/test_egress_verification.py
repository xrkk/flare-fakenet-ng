"""Guest egress subset, coordinator idempotency and tool-level behavior."""
import copy
import json
import os
from pathlib import Path
import socket
import sys

import pytest

from fakenet.mcp import egress_contract, egress_verification, schemas, tools
from fakenet.mcp.coordination import Coordinator


CONTROLLER = '11111111-2222-4333-8444-555555555555'
RUN_ID = '22222222-3333-4444-8555-666666666666'
VERIFICATION_ID = '33333333-4444-4555-8666-777777777777'


class FakeRunner:
    def __init__(self):
        self.verification = None

    def health_detail(self, state):
        return {'process_alive': True, 'init_evidence': True, 'probe': True}

    def verify_egress(self, coordinator, controller, request, command_id):
        if self.verification is None:
            self.verification = guest_result(request, command_id)
        return {'changed': False, 'verification': copy.deepcopy(
            self.verification)}


class FakeContext:
    def __init__(self, coordinator, runner):
        self.coordinator = coordinator
        self.runner = runner

    def controller_identity(self):
        return CONTROLLER, 'valid_uuid'

    def error_response(self, exc):
        snap = self.coordinator.snapshot()
        return {'state': snap['state'], 'state_version': snap['state_version'],
                'run_id': snap['run_id'], 'changed': False,
                'error': exc.to_dict(), 'command_id': None}


class FakeServer:
    def __init__(self):
        self.tools = {}

    def tool(self, **_kwargs):
        def decorate(fn):
            self.tools[fn.__name__] = fn
            return fn
        return decorate


def request_dict(**overrides):
    value = {
        'schema_version': egress_contract.SCHEMA_VERSION,
        'verification_id': VERIFICATION_ID,
        'run_id': RUN_ID,
        'vm_epoch': 'epoch',
        'policy_identity': 'policy',
        'execution_context_identity': 'context',
        'probe_nonce': 'nonce',
        'required_control_ports': [28787, 28788, 28790],
        'matrix_version': 'v1',
        'random_tcp_port': 50001,
        'random_udp_port': 50002,
        'host_evidence_sha256': '',
        'budget': {'guest_ms': 1000},
        'controller': CONTROLLER,
    }
    value.update(overrides)
    return value


def health_dict(**overrides):
    value = {
        'process_alive': True,
        'init_evidence': True,
        'probe': True,
        'capture_threads_alive': True,
        'capture_error': None,
        'final_filter': ('(ip.DstAddr != 192.168.204.1 or '
                         '(tcp.SrcPort != 28787 and tcp.SrcPort != 28788 '
                         'and tcp.SrcPort != 28790))'),
        'inbound_capture_filter': 'inbound and ip',
        'inbound_capture_flags': 'SNIFF',
        'inbound_capture_active': True,
        'capture_mode': 'sniff',
    }
    value.update(overrides)
    return value


def child_dict(**overrides):
    value = {
        'firewall': {'available': True, 'profiles': [
            {'name': 'Domain', 'enabled': False},
            {'name': 'Private', 'enabled': False},
            {'name': 'Public', 'enabled': False},
        ]},
        'route4': {'available': True, 'stdout': 'route'},
        'route6': {'available': True, 'stdout': 'route6'},
        'adapters': {'available': True, 'stdout': 'adapter'},
        'netstat': {'available': True, 'stdout': 'netstat'},
        'local_echo': {'available': True, 'sent': 24,
                       'received': 'MALTRACE-EGRESS-nonce',
                       'nonce_match': True, 'error': None},
        'evidence': {'path': '/tmp/guest-subset.json',
                     'sha256': 'a' * 64, 'size': 1},
    }
    value.update(overrides)
    return value


def snapshot_dict(**overrides):
    value = {'state': 'healthy', 'run_id': RUN_ID,
             'controller': CONTROLLER,
             'config_identity': {'name': 'cfg', 'sha256': 'b' * 64,
                                 'builtin': False}}
    value.update(overrides)
    return value


def guest_result(request=None, command_id='cmd'):
    req = request or request_dict()
    return egress_verification.build_guest_result(
        command_id=command_id, request=req, snapshot=snapshot_dict(),
        health=health_dict(), child=child_dict(),
        live_evidence={'path': '/tmp/live-health.json',
                       'sha256': 'c' * 64, 'size': 1})


def coordinator(runner):
    coord = Coordinator(runner)
    coord._state = 'healthy'
    coord._run_id = RUN_ID
    coord._controller = CONTROLLER
    coord._state_version = 1
    return coord


def test_guest_result_is_underdetermined_and_never_host_pass():
    result = guest_result()
    assert result['verdict'] == 'unknown'
    assert result['conclusion']['status'] == 'underdetermined'
    assert 'running_egress_contained' in result['conclusion']['unknown_checks']
    assert 'sample_path_equivalent' in result['conclusion']['unknown_checks']
    assert result['authorized'] is False
    assert len(result['steps']) == 10
    schemas.VerificationResult.model_validate(result)


def test_guest_filter_missing_port_fails():
    health = health_dict(final_filter='(tcp.SrcPort != 28787 and tcp.SrcPort != 28788)')
    result = egress_verification.build_guest_result(
        command_id='cmd', request=request_dict(), snapshot=snapshot_dict(),
        health=health, child=child_dict())
    assert result['checks']['mcp_control_exclusions_effective']['value'] is False
    assert 'mcp_control_exclusions_effective' in result['conclusion']['failed_checks']


def test_guest_filter_disjunction_is_not_control_proof():
    health = health_dict(
        final_filter='tcp.SrcPort != 28787 or tcp.SrcPort != 28788 '
                     'or tcp.SrcPort != 28790')
    result = egress_verification.build_guest_result(
        command_id='cmd', request=request_dict(), snapshot=snapshot_dict(),
        health=health, child=child_dict())
    assert result['checks']['mcp_control_exclusions_effective']['value'] is False
    assert 'mcp_control_exclusions_effective' in result['conclusion']['failed_checks']


def test_guest_firewall_enabled_fails():
    child = child_dict(firewall={'available': True, 'profiles': [
        {'name': 'Domain', 'enabled': True},
        {'name': 'Private', 'enabled': False},
        {'name': 'Public', 'enabled': False}]})
    result = egress_verification.build_guest_result(
        command_id='cmd', request=request_dict(), snapshot=snapshot_dict(),
        health=health_dict(), child=child)
    assert result['checks']['firewall_disabled']['value'] is False
    assert 'firewall_disabled' in result['conclusion']['failed_checks']


def test_guest_echo_nonce_mismatch_does_not_pass():
    child = child_dict(local_echo={'available': True, 'sent': 24,
                                   'received': 'other', 'nonce_match': False,
                                   'error': None})
    result = egress_verification.build_guest_result(
        command_id='cmd', request=request_dict(), snapshot=snapshot_dict(),
        health=health_dict(), child=child)
    assert result['checks']['local_interception_observed']['value'] is None
    echo_step = next(step for step in result['steps']
                     if step['id'] == 'guest_local_echo')
    assert echo_step['outcome'] == 'fail'


def test_guest_subset_writes_bounded_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv('FAKENETNG_MCP_PROGRAMDATA', str(tmp_path))
    payload = {'run_id': RUN_ID, 'verification_id': VERIFICATION_ID,
               'probe_nonce': 'nonce', 'required_control_ports': [28787],
               'guest_echo_allowed': True}

    def execute(argv, timeout):
        if 'Get-NetFirewallProfile' in ' '.join(argv):
            return {'available': True, 'returncode': 0,
                    'stdout': json.dumps([
                        {'Name': 'Domain', 'Enabled': False},
                        {'Name': 'Private', 'Enabled': False},
                        {'Name': 'Public', 'Enabled': False}]),
                    'stderr': ''}
        return {'available': True, 'returncode': 0,
                'stdout': 'ok', 'stderr': ''}

    def probe(nonce, timeout):
        return {'available': True, 'sent': 24,
                'received': 'MALTRACE-EGRESS-' + nonce,
                'nonce_match': True, 'error': None}

    child = egress_verification.collect_guest_subset(
        payload, None, execute=execute, probe=probe)
    evidence = Path(child['evidence']['path'])
    assert evidence.is_file()
    assert evidence.parent.name == VERIFICATION_ID
    assert egress_verification.sha256_file(evidence) == \
        child['evidence']['sha256']
    assert child['local_echo']['nonce_match'] is True


def test_tool_idempotency_cross_kind_and_deep_copy():
    runner = FakeRunner()
    coord = coordinator(runner)
    ctx = FakeContext(coord, runner)
    server = FakeServer()
    tools.register_tools(server, ctx)
    tool = server.tools['verify_egress_isolation']
    request = schemas.VerificationRequest(**request_dict())
    first = tool('cmd-1', 1, request)
    assert first['error'] is None
    assert first['changed'] is False
    assert first['verification']['verification_id'] == VERIFICATION_ID
    assert first['state_version'] == 2
    replay = tool('cmd-1', 1, request)
    assert replay['replayed'] is True
    assert replay['verification']['verification_id'] == VERIFICATION_ID
    replay['verification']['steps'][0]['outcome'] = 'poisoned'
    status = coord.command_status(command_id='cmd-1', controller=CONTROLLER,
                                  controller_valid=True)
    assert status['response']['verification']['steps'][0]['outcome'] != 'poisoned'
    different = schemas.VerificationRequest(**request_dict(
        verification_id='44444444-5555-4666-8777-888888888888',
        probe_nonce='other'))
    rejected = tool('cmd-1', 2, different)
    assert rejected['error']['code'] == 'invalid_request'
    runner.verification = None
    cross = tool('cmd-old', 2, request)
    assert cross['error'] is None
    # A lifecycle command with the same id is a different kind and must not replay.
    coord.submit(command_id='cmd-cross', expected_version=3,
                 controller=CONTROLLER, controller_valid=True,
                 kind='start', describe={}, execute=lambda c: {'changed': False})
    cross_kind = tool('cmd-cross', 4, request)
    assert cross_kind['error']['code'] == 'invalid_request'


def test_coordinator_rejects_empty_verification_identity():
    coord = coordinator(FakeRunner())
    with pytest.raises(Exception) as excinfo:
        coord.submit(command_id='cmd-empty', expected_version=1,
                     controller=CONTROLLER, controller_valid=True,
                     kind='verify_egress', describe={},
                     execute=lambda c: {'changed': False},
                     request_identity='')
    assert excinfo.value.code == 'invalid_request'


@pytest.mark.parametrize('mismatch', [None, 'source', 'source_port', 'protocol'])
def test_supervisor_preserves_full_producer_tuple(tmp_path, monkeypatch, mismatch):
    """Exercise the real supervisor dispatch, not a fake guest shortcut."""
    from types import SimpleNamespace
    from fakenet.mcp.supervisor import RealSupervisor

    artifacts = tmp_path / 'artifacts'
    run_dir = artifacts / 'runs' / RUN_ID
    run_dir.mkdir(parents=True)
    log = run_dir / 'run.log'
    log.write_text(
        'DIVERT_FAKE_PROBE pid=1234 creation=100 probe_nonce=nonce '
        'src=192.0.2.10 sport=40000 dst=198.51.100.77 dport=1337 '
        'proto=TCP epoch=1792465201\n')
    monkeypatch.setattr(egress_verification.paths, 'data_directories',
                        lambda: {'artifacts': str(artifacts)})
    request = request_dict(
        host_probe_pid=1234, host_probe_creation=100,
        host_probe_started='2026-10-20T03:00:00+00:00',
        host_probe_ended='2026-10-20T03:00:02+00:00',
        host_probe_source='192.0.2.10', host_probe_source_port=40000,
        host_probe_protocol='TCP', host_probe_destination='198.51.100.77',
        host_probe_port=1337, unrelated_option='not-forwarded')
    if mismatch == 'source':
        request['host_probe_source'] = '192.0.2.11'
    elif mismatch == 'source_port':
        request['host_probe_source_port'] = 40001
    elif mismatch == 'protocol':
        request['host_probe_protocol'] = 'UDP'
    request = schemas.VerificationRequest(**request).model_dump(mode='json')
    captured = {}

    class AtDiagnostic(Exception):
        pass

    def diagnostic(operation, payload, deadline):
        assert operation == 'verify-egress-isolation'
        captured.update(payload)
        producer = egress_verification._producer_match(RUN_ID, payload)
        raise AtDiagnostic(producer)

    supervisor = RealSupervisor.__new__(RealSupervisor)
    supervisor._fakenet = SimpleNamespace(
        request=lambda *a, **kw: health_dict(), alive=lambda: True,
        identity={'pid': 1})
    supervisor._artifacts_root = artifacts
    supervisor._run_dir = run_dir
    supervisor._diagnostic_call = diagnostic
    coordinator = SimpleNamespace(snapshot=lambda: {
        'state': 'healthy', 'run_id': RUN_ID, 'controller': CONTROLLER})
    with pytest.raises(AtDiagnostic) as event:
        supervisor.verify_egress(coordinator, CONTROLLER, request, 'command')
    for key in ('host_probe_source', 'host_probe_source_port',
                'host_probe_protocol', 'host_probe_pid', 'host_probe_creation',
                'host_probe_started', 'host_probe_ended'):
        assert captured.get(key) == request[key], key
    assert 'unrelated_option' not in captured
    assert event.value.args[0]['value'] is (mismatch is None)
