"""Matrix, fixed PowerShell probe and strict bounded parsing."""
import json

from fakenet.mcp import host_probe


def probe_fixture():
    matrix = host_probe.matrix_steps(50001, 50002, 'fixture')
    steps = [{'id': row['id'], 'outcome': 'no_response', 'sent': 1,
              'received': '', 'error': 'fixture'} for row in matrix]
    return {
        'schema': host_probe.PROBE_SCHEMA,
        'nonce': 'fixture',
        'instance': {'pid': 1, 'creation_ticks': 2,
                     'nonce': 'fixture', 'script_hash': 'fixture-hash'},
        'identity': {'pid': 1, 'computer': 'DESKTOP'},
        'firewall': [{'name': 'Domain', 'enabled': False},
                     {'name': 'Private', 'enabled': False},
                     {'name': 'Public', 'enabled': False}],
        'firewall_error': None,
        'matrix_run': True,
        'positive': {'id': host_probe.POSITIVE_ID, 'nonce_match': True},
        'steps': steps,
    }


def strict_response(row, **overrides):
    value = {
        'id': row.get('id', 'step'), 'outcome': 'response', 'sent': 12,
        'received': 'MALTRACE-EGRESS-nonce', 'error': None,
        'response_type': 'udp_nonce', 'status': None,
        'nonce_match': True, 'address_family': 'InterNetwork',
        'remote_endpoint': '%s:%s' % (row['destination'], row['port']),
        'local_endpoint': '192.0.2.10:50000', 'elapsed_ms': 4,
    }
    value.update(overrides)
    return value


def test_matrix_is_thirty_and_positive_is_separate():
    matrix = host_probe.matrix_steps(50001, 50002)
    assert len(matrix) == 30
    assert len({row['id'] for row in matrix}) == 30
    assert not any(row['id'] == host_probe.POSITIVE_ID for row in matrix)


def test_probe_script_is_fixed_and_contains_no_shell_launcher():
    script = host_probe.probe_script(
        'nonce', host_probe.matrix_steps(1, 2, 'nonce'))
    assert 'MALTRACE_JSON:' in script
    assert '__PAYLOAD__' not in script
    assert '__TIMEOUT__' not in script
    assert 'Start-Process' not in script
    assert 'cmd.exe' not in script
    assert host_probe.script_sha256(script) == host_probe.script_sha256(
        host_probe.probe_script('nonce',
                                host_probe.matrix_steps(1, 2, 'nonce')))


def test_expected_map_and_timeout_is_not_block_proof():
    expected = host_probe.expected_steps(
        bypass_tcp=[139], bypass_udp=[443], mapped_ports=[1337],
        redirect_all=True, random_tcp_port=50001, random_udp_port=50002,
        nonce='nonce')
    assert len(expected) == 30
    assert expected['ipv4_tcp_139']['expected'] == 'blocked'
    assert expected['ipv4_udp_443']['expected'] == 'blocked'
    assert expected['ipv4_tcp_80']['expected'] == 'local_fake'
    outcome, reason = host_probe.classify_step(
        {'kind': 'tcp', 'family': 'ipv4', 'port': 80,
         'destination': '198.51.100.77'},
        {'received': '', 'error': 'timeout'}, 'blocked')
    assert outcome == 'unknown'
    assert reason == 'running_observation_unconfirmed'
    outcome, reason = host_probe.classify_step(
        {'kind': 'tcp', 'family': 'ipv4', 'port': 80,
         'destination': '198.51.100.77'},
        {'received': '', 'error': 'timeout'}, 'blocked')
    assert outcome == 'unknown'
    assert reason == 'running_observation_unconfirmed'


def test_unreachable_text_cannot_be_local_fake_pass():
    row = {'kind': 'icmp', 'family': 'ipv6', 'port': None,
           'destination': '2001:db8::77'}
    outcome, reason = host_probe.classify_step(
        row, {'received': 'DestinationUnreachable', 'sent': 32,
              'response_type': 'icmp_echo', 'nonce_match': True,
              'address_family': 'InterNetworkV6',
              'remote_endpoint': '2001:db8::77:0',
              'local_endpoint': '2001:db8::1:0', 'elapsed_ms': 2},
        'local_fake')
    assert outcome != 'pass'
    assert reason in ('icmp_nonce_mismatch', 'icmp_responder_mismatch', 'response_not_verified')


def test_strict_local_response_but_extra_boundary_does_not_qualify():
    row = {'kind': 'udp', 'family': 'ipv4', 'port': 53,
           'destination': '198.51.100.77'}
    outcome, reason = host_probe.classify_step(
        row, strict_response(row), 'local_fake')
    assert (outcome, reason) == ('pass', 'strict_udp_nonce_response')
    outcome, reason = host_probe.classify_step(
        row, {'received': '', 'sent': 12, 'outcome': 'no_response'},
        'blocked', boundary_verified=True)
    assert (outcome, reason) == (
        'unknown', 'running_observation_unconfirmed')
    outcome, reason = host_probe.classify_step(
        row, {'received': '', 'sent': 12, 'outcome': 'no_response'},
        'blocked', boundary_verified=None)
    assert (outcome, reason) == ('unknown', 'running_observation_unconfirmed')


def test_validate_probe_result_requires_instance_nonce_and_all_rows():
    value = probe_fixture()
    ids = [row['id'] for row in host_probe.matrix_steps(50001, 50002)]
    host_probe.validate_probe_result(value, ids, nonce='fixture')
    broken = json.loads(json.dumps(value))
    broken['steps'] = broken['steps'][:-1]
    try:
        host_probe.validate_probe_result(broken, ids, nonce='fixture')
    except ValueError as exc:
        assert 'coverage' in str(exc)
    else:
        raise AssertionError('missing row accepted')
    broken = json.loads(json.dumps(value))
    broken['instance']['nonce'] = 'other'
    try:
        host_probe.validate_probe_result(broken, ids, nonce='fixture')
    except ValueError as exc:
        assert 'nonce' in str(exc)
    else:
        raise AssertionError('instance nonce mismatch accepted')


def test_validate_probe_result_allows_positive_gate_skip():
    value = probe_fixture()
    value['matrix_run'] = False
    value['steps'] = []
    host_probe.validate_probe_result(
        value, [row['id'] for row in host_probe.matrix_steps(1, 2)],
        nonce='fixture')


def test_extract_marker_requires_exactly_one_marker():
    assert host_probe.extract_marker('x\nMALTRACE_JSON:{"a":1}\n') == {'a': 1}
    try:
        host_probe.extract_marker('x\n')
    except ValueError as exc:
        assert 'marker' in str(exc)
    else:
        raise AssertionError('missing marker accepted')
