"""Single-author egress contract behavior and matrix coverage."""
import copy
import runpy
from pathlib import Path

import pytest

from fakenet.mcp import egress_contract as contract


@pytest.mark.parametrize('case', contract.CONTRACT_CASES,
                         ids=lambda case: case['name'])
def test_contract_cases(case):
    plan = copy.deepcopy(case['plan'])
    observation = copy.deepcopy(case['observation'])
    if 'expected_error' in case:
        with pytest.raises(contract.EgressContractError) as excinfo:
            contract.evaluate_interception_qualification(plan, observation)
        assert str(excinfo.value) == case['expected_error']
        return
    result = contract.evaluate_interception_qualification(plan, observation)
    for key, value in case['expected'].items():
        assert result[key] == value, (case['name'], key, result)
    assert result['authorized'] is False


def test_matrix_is_exactly_two_families_of_fifteen():
    rows = contract.matrix_definition(50001, 50002)
    assert len(rows) == 30
    assert [row['id'] for row in rows[:15]][0].startswith('ipv4_')
    assert [row['id'] for row in rows[15:]][0].startswith('ipv6_')
    for row in rows:
        assert row['destination'] in ('198.51.100.77', '2001:db8::77')
        assert row['kind'] in ('tcp', 'udp', 'icmp', 'dns')
    assert {row['id'] for row in rows if row['kind'] == 'dns'} == {
        'ipv4_dns_nonce_invalid', 'ipv6_dns_nonce_invalid'}
    assert {row['id'] for row in rows if row['kind'] == 'icmp'} == {
        'ipv4_icmp', 'ipv6_icmp'}


def test_request_validation_and_fingerprint_are_stable():
    request = {
        'schema_version': contract.SCHEMA_VERSION,
        'verification_id': '00000000-0000-4000-8000-000000000001',
        'run_id': '00000000-0000-4000-8000-000000000002',
        'vm_epoch': 'epoch',
        'policy_identity': 'policy',
        'execution_context_identity': 'context',
        'probe_nonce': 'nonce',
        'required_control_ports': [28787, 28788, 28790],
        'matrix_version': contract.MATRIX_VERSION,
        'host_evidence_sha256': '0' * 64,
        'random_tcp_port': 50001,
        'random_udp_port': 50002,
        'budget': {'total_ms': 50000},
    }
    assert contract.validate_verification_request(request) == request
    first = contract.request_fingerprint(request)
    second = contract.request_fingerprint(dict(request))
    assert first == second
    changed = dict(request, probe_nonce='other')
    assert contract.request_fingerprint(changed) != first


def test_generated_export_roundtrip_and_existing_copy_match(tmp_path):
    # Immutable Windows builds contain only this repository. Exercise the
    # actual exporter there too, rather than skipping a cross-repo assertion.
    repo = Path(__file__).resolve().parents[2]
    exporter = runpy.run_path(str(repo / 'tools/export_egress_contract.py'))
    export = exporter['main']
    output = tmp_path / 'generated_egress_contract.py'
    args = ['--repo', str(repo), '--output', str(output)]
    assert export(args) == 0
    assert export(args + ['--check']) == 0
    namespace = runpy.run_path(str(output))
    assert namespace['CONTRACT_VERSION'] == contract.CONTRACT_VERSION
    assert namespace['CONTRACT_CASES'] == contract.CONTRACT_CASES
    # Preserve the source identity header while changing the body: checking
    # only a hash string in that header must not accept a drifted contract.
    output.write_bytes(output.read_bytes() + b'\n# body drift\n')
    assert export(args + ['--check']) == 1
    generated = Path('/home/adminn/projects/MalTrace/AI辅助逆向/'
                     'skills/evidence-lifecycle/_generated_egress_contract.py')
    if generated.is_file():
        assert export(['--repo', str(repo), '--output', str(generated),
                       '--check']) == 0


def test_completeness_gate_requires_every_row_positive_producer_and_final():
    ids = contract.matrix_step_ids(50001, 50002)
    rows = [{'id': step_id, 'outcome': 'pass'} for step_id in ids]
    positive = {'nonce_match': True}
    complete = contract.evaluate_verification_completeness(
        ids, rows, positive, True, True)
    assert complete['complete'] is True
    assert complete['status'] == 'complete'
    missing = contract.evaluate_verification_completeness(
        ids, rows[:-1], positive, True, True)
    assert missing['complete'] is False
    assert missing['status'] == 'underdetermined'
    unknown_rows = [dict(row) for row in rows]
    unknown_rows[ids.index(contract.IPV4_REQUIRED_IDS[0])]['outcome'] = 'unknown'
    unknown = contract.evaluate_verification_completeness(
        ids, unknown_rows, positive, True, True)
    assert unknown['complete'] is False
    failed = contract.evaluate_verification_completeness(
        ids, rows[:-1] + [{'id': ids[-1], 'outcome': 'fail'}],
        positive, True, True)
    assert failed['status'] == 'invalid_environment'
    no_positive = contract.evaluate_verification_completeness(
        ids, rows, {'nonce_match': False}, True, True)
    assert no_positive['status'] == 'invalid_environment'
    no_producer = contract.evaluate_verification_completeness(
        ids, rows, positive, None, True)
    assert no_producer['status'] == 'underdetermined'
    no_final = contract.evaluate_verification_completeness(
        ids, rows, positive, True, None)
    assert no_final['status'] == 'underdetermined'


def _loopback_exposure():
    return {
        'schema': 'fakenetng.ipv6-exposure.v1', 'complete': True,
        'interfaces': [{'index': 1, 'forwarding': 'Disabled',
                                'connection_state': 'Up'}],
        'addresses': [{'interface_index': 1, 'address': '::1',
                       'prefix_length': 128, 'state': 'Preferred'}],
        'routes': [{'interface_index': 1, 'prefix': '::1/128',
                    'next_hop': '::'},
                   {'interface_index': 1, 'prefix': 'ff00::/8',
                    'next_hop': '::'}],
        'os_map': [{'index': 1, 'type': 'Loopback'}], 'errors': [],
        'collection_started': '2026-10-21T00:00:00Z',
        'collection_ended': '2026-10-21T00:00:01Z',
    }


def test_strict_ipv6_scope_guard_only_loopback_and_ll_is_unknown():
    guard = contract.normalize_ipv6_exposure(_loopback_exposure())
    assert guard['value'] is True
    assert guard['fingerprint']
    link_local = _loopback_exposure()
    link_local['interfaces'] = [{'index': 11, 'forwarding': 'Disabled'}]
    link_local['addresses'] = [{'interface_index': 11,
                                'address': 'fe80::1', 'prefix_length': 64}]
    link_local['routes'] = [{'interface_index': 11, 'prefix': 'fe80::/64',
                             'next_hop': '::'},
                            {'interface_index': 11, 'prefix': 'ff00::/8',
                             'next_hop': '::'}]
    link_local['os_map'] = [{'index': 11, 'type': 'Ethernet'}]
    assert contract.normalize_ipv6_exposure(link_local)['value'] is None
    # Same local list, hypothetical peers do not change the conservative fact.
    guarded = contract.normalize_ipv6_exposure(link_local)
    assert guarded['value'] is None
    duplicate = _loopback_exposure()
    duplicate['interfaces'].append(dict(duplicate['interfaces'][0]))
    assert contract.normalize_ipv6_exposure(duplicate)['value'] is None
    empty = dict(_loopback_exposure(), interfaces=[], addresses=[], routes=[],
                 os_map=[])
    assert contract.normalize_ipv6_exposure(empty)['value'] is None


def test_contract3_profile_and_scope_guard_are_required():
    ids = contract.matrix_step_ids(50001, 50002)
    rows = [{'id': step, 'outcome': 'pass'} for step in ids]
    positive = {'nonce_match': True}
    complete = contract.evaluate_verification_completeness(
        ids, rows, positive, True, True,
        required_ids=contract.IPV4_REQUIRED_IDS,
        diagnostic_ids=contract.IPV6_DIAGNOSTIC_IDS)
    assert complete['complete'] is True
    assert complete['required_ids'] == list(contract.IPV4_REQUIRED_IDS)
    plan, observation = contract._base_material()
    observation['qualification_profile'] = 'ipv4-v1'
    observation['scope_guard'] = contract.normalize_ipv6_exposure(
        _loopback_exposure())
    assert contract.evaluate_interception_qualification(
        plan, observation)['status'] == 'qualified_in_scope'
    observation.pop('scope_guard')
    result = contract.evaluate_interception_qualification(plan, observation)
    assert result['status'] == 'underdetermined'
    assert 'scope_guard' in result['unknown_checks']
    observation['scope_guard'] = contract.normalize_ipv6_exposure(
        _loopback_exposure())
    plan.pop('required_matrix_ids')
    result = contract.evaluate_interception_qualification(plan, observation)
    assert result['status'] == 'underdetermined'
    assert 'matrix_profile_scope' in result['unknown_checks']
