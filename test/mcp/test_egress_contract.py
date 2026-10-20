"""Single-author egress contract behavior and matrix coverage."""
import copy
import hashlib
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


def test_generated_copy_matches_source_when_present():
    generated = Path('/home/adminn/projects/MalTrace/AI辅助逆向/'
                     'skills/evidence-lifecycle/_generated_egress_contract.py')
    if not generated.is_file():
        pytest.skip('MalTrace generated contract copy is not present')
    source = Path(__file__).resolve().parents[2] / 'fakenet/mcp/egress_contract.py'
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    text = generated.read_text(encoding='utf-8')
    assert ('# Source-SHA256: ' + source_sha) in text
    assert 'GENERATED_CONTRACT_VERSION = CONTRACT_VERSION' in text


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
    unknown = contract.evaluate_verification_completeness(
        ids, rows[:-1] + [{'id': ids[-1], 'outcome': 'unknown'}],
        positive, True, True)
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
