"""Qualification gate: matrix not_run/unknown must never pass."""
import copy

from fakenet.mcp import host_merge, host_probe

REQUEST = {
    'schema_version': 'fakenetng.egress-verification.v1',
    'verification_id': '00000000-0000-4000-8000-000000000001',
    'run_id': 'run-1',
    'vm_epoch': 'epoch',
    'policy_identity': 'policy',
    'execution_context_identity': 'context',
    'probe_nonce': 'nonce',
    'required_control_ports': [28787, 28788, 28790],
    'matrix_version': 'v1',
    'random_tcp_port': 50001,
    'random_udp_port': 50002,
}
IDENTITY = {'pid': 1, 'creation_ticks': 2, 'account': 'LAB\\analyst',
            'sid': 'S-1-5-21-1', 'session': 1,
            'token_integrity_level': 'S-1-16-12288',
            'policy_scope': 'applocker:fixture',
            'protocol_class': 'mixed-v1',
            'image_path': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'image_sha256': 'a' * 64, 'vm_uuid': 'v', 'boot_id': 'b'}
SAMPLE = {'account': 'LAB\\analyst', 'sid': 'S-1-5-21-1', 'session': 1,
          'token_integrity_level': 'S-1-16-12288',
          'launcher_path': 'E:\\sample.exe',
          'launcher_sha256': 'f' * 64,
          'policy_scope': 'applocker:fixture',
          'protocol_class': 'mixed-v1'}


def guest_result():
    checks = {key: {'value': value, 'evidence_refs': ['guest#1']}
              for key, value in {
                  'firewall_disabled': True,
                  'fakenet_running_healthy': True,
                  'mcp_control_exclusions_effective': True,
                  'blocked_before_interception': False,
                  'control_channels_reachable': True,
                  'local_interception_observed': True,
                  'running_egress_contained': True,
                  'sample_path_equivalent': True}.items()}
    return {
        'checks': checks, 'producer_match': True,
        'bindings': {'effective_control_exclusion_ports':
                     [28787, 28788, 28790]},
        'manifest': {'entries': [{'path': '/guest', 'sha256': 'g' * 64}]},
        'steps': [],
    }


def host_snapshot():
    return {
        'vmx': {'available': True, 'uuid': 'v', 'sha256': 'h' * 64},
        'networking': {'available': True, 'nat': False},
        'nat': {'available': True},
        'route_to_guest': {'returncode': 0, 'stdout': 'dev vmnet1'},
        'forwarding': {'ipv4': 0, 'ipv6_all': 0},
        'firewall': {'known': True},
        'boundary': {'value': True, 'reason': 'fixture'},
    }


def strict_row(expected, step):
    base = {
        'id': step['id'], 'outcome': 'response', 'sent': 12,
        'received': 'MALTRACE-EGRESS-nonce', 'error': None,
        'response_type': 'udp_nonce', 'status': None,
        'nonce_match': True,
        'address_family': 'InterNetwork' if step['family'] == 'ipv4'
        else 'InterNetworkV6',
        'remote_endpoint': '%s:%s' % (step['destination'], step['port']),
        'local_endpoint': '192.0.2.10:50000', 'elapsed_ms': 2,
        'started': 'now', 'ended': 'now',
    }
    if expected == 'blocked':
        base.update(outcome='no_response', received='', sent=1,
                    response_type='', nonce_match=False)
        return base
    if step.get('probe_kind') == 'tcp_raw':
        base.update(response_type='tcp_nonce', status=None,
                    received='MALTRACE-EGRESS-nonce')
    elif step['kind'] == 'tcp':
        base.update(response_type='http', status=200,
                    received='HTTP/1.1 200 OK\r\n\r\nnonce')
    elif step['kind'] == 'dns':
        base.update(response_type='dns', transaction_id=step['dns_txid'],
                    question=step.get('question', 'MALTRACE-nonce.invalid'),
                    qtype=1, qclass=1, qr=True, rcode=0)
    elif step['kind'] == 'icmp':
        base.update(response_type='icmp_echo',
                    responder=step['destination'])
    return base


def probe_result(expected_map, matrix_run=True, final=True):
    steps = []
    for step_id, expected in expected_map.items():
        steps.append(strict_row(expected['expected'], expected))
    return {
        'identity': IDENTITY,
        'positive': {'id': host_probe.POSITIVE_ID, 'nonce_match': True,
                     'started': 'now', 'ended': 'now'},
        'matrix_run': matrix_run, 'steps': steps, 'firewall': [
            {'name': 'Domain', 'enabled': False},
            {'name': 'Private', 'enabled': False},
            {'name': 'Public', 'enabled': False}],
        'firewall_error': None,
        'final_consistency': final, 'final_consistency_observed': {},
        'completed_at': 'now',
    }


def build(probe, expected_map):
    return host_merge.build_host_result(
        command_id='00000000-0000-4000-8000-000000000002',
        request=REQUEST, guest_result=guest_result(),
        host_snapshot=host_snapshot(), probe_result=probe,
        expected_map=expected_map,
        config={'sample_context': SAMPLE},
        channels={'windows_mcp': True, 'fakenet_mcp': True,
                  'velo_mcp': True},
        host_evidence={'path': '/host', 'sha256': 'h' * 64},
        probe_evidence={'path': '/probe', 'sha256': 'p' * 64})


def test_matrix_not_run_cannot_pass_and_still_lists_planned_rows():
    expected = host_probe.expected_steps(
        random_tcp_port=50001, random_udp_port=50002, nonce='nonce')
    probe = probe_result(expected, matrix_run=False)
    probe['steps'] = []
    result = build(probe, expected)
    assert result['verdict'] != 'pass'
    assert result['conclusion']['status'] == 'underdetermined'
    assert result['conclusion']['sample_path_qualified'] is False
    assert result['coverage']['matrix_planned'] == 30
    assert result['coverage']['matrix_not_run']
    matrix_rows = [row for row in result['steps']
                   if row['id'] in expected]
    assert len(matrix_rows) == 30
    assert all(row['outcome'] == 'not_run' for row in matrix_rows)


def test_unknown_row_or_missing_final_cannot_pass():
    expected = host_probe.expected_steps(
        random_tcp_port=50001, random_udp_port=50002, nonce='nonce')
    probe = probe_result(expected)
    for row in probe['steps']:
        if row['id'] == 'ipv4_tcp_80':
            row.update(outcome='unknown', received='', sent=1)
    result = build(probe, expected)
    assert result['verdict'] != 'pass'
    assert result['conclusion']['status'] == 'underdetermined'
    assert 'matrix_completeness' in result['conclusion']['unknown_checks']


def test_complete_matrix_positive_and_final_without_observation_cannot_pass():
    expected = host_probe.expected_steps(
        random_tcp_port=50001, random_udp_port=50002, nonce='nonce')
    probe = probe_result(expected)
    result = build(probe, expected)
    assert result['verdict'] == 'unknown', result['conclusion']
    assert 'running_egress_contained' in result['conclusion']['unknown_checks']
    assert result['conclusion']['status'] == 'underdetermined'
    assert result['conclusion']['sample_path_qualified'] is False
    assert result['conclusion']['matrix_completeness']['complete'] is False
    for name, check in result['checks'].items():
        if check['value'] is not None:
            assert check['evidence_refs'], name
    matrix = [step for step in result['steps']
              if step['id'] in expected]
    assert all(step['evidence_refs'] for step in matrix)


def test_no_nonce_or_producer_cannot_pass():
    expected = host_probe.expected_steps(
        random_tcp_port=50001, random_udp_port=50002, nonce='nonce')
    probe = probe_result(expected)
    probe['positive']['nonce_match'] = False
    result = build(probe, expected)
    assert result['verdict'] != 'pass'
    assert result['conclusion']['status'] == 'invalid_environment'


def test_sample_launcher_image_hash_is_not_required_to_equal_probe_binary():
    expected = host_probe.expected_steps(
        random_tcp_port=50001, random_udp_port=50002, nonce='nonce')
    probe = probe_result(expected)
    sample = dict(SAMPLE, image_path='E:\\sample.exe',
                  image_sha256='z' * 64)
    result = host_merge.build_host_result(
        command_id='00000000-0000-4000-8000-000000000002',
        request=REQUEST, guest_result=guest_result(),
        host_snapshot=host_snapshot(), probe_result=probe,
        expected_map=expected, config={'sample_context': sample},
        channels={'windows_mcp': True, 'fakenet_mcp': True,
                  'velo_mcp': True},
        host_evidence={'path': '/host', 'sha256': 'h' * 64},
        probe_evidence={'path': '/probe', 'sha256': 'p' * 64})
    assert result['checks']['sample_path_equivalent']['value'] is True
    assert result['verdict'] == 'unknown'
    assert result['checks']['sample_path_equivalent']['value'] is True
