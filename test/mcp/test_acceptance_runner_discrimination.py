"""The acceptance runner must reject the R01 defect shapes, not just any error."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from fakenet.mcp import egress_contract


def load_runner():
    path = Path(__file__).parent / 'acceptance' / 'run_egress_verification.py'
    spec = spec_from_file_location('run_egress_verification', path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load_runner()


def base_result():
    steps = [{'id': key, 'outcome': 'pass'}
             for key in egress_contract.matrix_step_ids(50001, 50002)]
    plan = {
        'run_id': 'run', 'vm_epoch': 'epoch', 'policy_identity': 'policy',
        'execution_context_identity': 'context', 'probe_nonce': 'nonce',
        'required_control_ports': [28787, 28788, 28790],
        'qualification_profile': 'ipv4-v1',
        'required_matrix_ids': list(egress_contract.IPV4_REQUIRED_IDS),
        'diagnostic_matrix_ids': list(egress_contract.IPV6_DIAGNOSTIC_IDS),
    }
    checks = {
        key: {'value': value, 'evidence_refs': ['evidence']}
        for key, value in egress_contract.EXPECTED_CHECKS.items()
    }
    facts = {
        'schema': 'fakenetng.ipv6-exposure.v1', 'complete': True,
        'interfaces': [{'index': 1, 'forwarding': 'Disabled',
                        'connection_state': 'Up'}],
        'addresses': [{'interface_index': 1, 'address': '::1',
                       'prefix_length': 128, 'state': 'Preferred'}],
        'routes': [{'interface_index': 1, 'prefix': '::1/128',
                    'next_hop': '::'},
                   {'interface_index': 1, 'prefix': 'ff00::/8',
                    'next_hop': '::'}],
        'os_map': [{'index': 1, 'type': 'Loopback'}], 'errors': []}
    observation = dict(plan, contract_version=3,
                       qualification_profile='ipv4-v1',
                       ipv6_exposure=facts,
                       scope_guard=egress_contract.normalize_ipv6_exposure(
                           facts))
    observation.update({
        'response_nonce': 'nonce',
        'effective_control_exclusion_ports': [28787, 28788, 28790],
        'checks': checks,
        'verification_completeness': {
            'schema': 'fakenetng.verification-completeness.v1',
            'complete': True, 'status': 'complete',
            'qualification_profile': egress_contract.QUALIFICATION_PROFILE,
            'required_ids': list(egress_contract.IPV4_REQUIRED_IDS),
            'diagnostic_ids': list(egress_contract.IPV6_DIAGNOSTIC_IDS),
            'planned': 30, 'observed': 30,
            'missing_steps': [], 'unknown_steps': [], 'failed_steps': [],
        },
    })
    return {
        'contract_version': 3, 'qualification_profile': 'ipv4-v1',
        'phase': 'running', 'verdict': 'pass', 'authorized': False,
        'lifecycle': {'state': 'completed'},
        'conclusion': {'status': 'qualified_in_scope',
                       'sample_path_qualified': True,
                       'failed_checks': [],
                       'matrix_completeness': {'complete': True}},
        'coverage': {'matrix_planned': 30, 'matrix_executed': 30, 'matrix_not_run': []},
        'checks': checks,
        'helper_input': {'plan': plan, 'observation': observation},
        'steps': steps,
        'probe_completion': {'completed_at': 'now'},
        'artifact': {'sha256': 'a' * 64},
        'manifest': {'sha256': 'm'},
    }


def test_normal_requires_complete_matrix_and_artifact():
    good = base_result()
    assert runner.expectation('normal', good) is True
    bad = base_result()
    bad['conclusion']['matrix_completeness']['complete'] = False
    bad['coverage']['matrix_not_run'] = [{'id': 'x', 'reason': 'not_run'}]
    assert runner.expectation('normal', bad) is False
    bad = base_result()
    bad.pop('artifact')
    assert runner.expectation('normal', bad) is False


def test_host_unknown_cannot_be_a_pass():
    value = base_result()
    value.update(verdict='unknown')
    value['conclusion'].update(status='underdetermined',
                               matrix_completeness={'complete': False})
    value['coverage']['matrix_not_run'] = [{'id': 'x'}]
    value['checks']['running_egress_contained'] = {'value': None}
    assert runner.expectation('host_unknown', value) is True
    value['verdict'] = 'pass'
    assert runner.expectation('host_unknown', value) is False


def test_control_missing_requires_the_control_reason():
    value = base_result()
    value.update(verdict='fail')
    value['conclusion']['status'] = 'invalid_environment'
    value['conclusion']['failed_checks'] = ['firewall_disabled']
    assert runner.expectation('control_missing', value) is False
    value['conclusion']['failed_checks'] = ['mcp_control_exclusions_effective']
    assert runner.expectation('control_missing', value) is True


def test_nonce_mismatch_and_identity_need_their_own_reason():
    value = base_result()
    value.update(verdict='fail')
    value['conclusion']['status'] = 'invalid_environment'
    assert runner.expectation('nonce_mismatch', value) is False
    value['conclusion']['failed_checks'] = ['response_nonce_mismatch']
    assert runner.expectation('nonce_mismatch', value) is True
    value = base_result()
    value.update(verdict='fail')
    value['conclusion']['status'] = 'invalid_environment'
    value['conclusion']['reason'] = 'state_conflict'
    assert runner.expectation('identity_change', value) is True


def test_timeout_requires_timeout_lifecycle_and_reason():
    value = base_result()
    value.update(verdict='unknown', lifecycle={'state': 'completed'})
    value['error'] = {'code': 'deadline_exceeded'}
    assert runner.expectation('timeout', value) is False
    value['lifecycle'] = {'state': 'timed_out'}
    assert runner.expectation('timeout', value) is True


def test_host_unknown_rejects_transport_failures():
    value = base_result()
    value['verdict'] = 'unknown'
    value['conclusion']['status'] = 'underdetermined'
    value['coverage']['matrix_not_run'] = [{'id': 'x', 'reason': 'guest_transport_error'}]
    value['checks']['running_egress_contained'] = {'value': None}
    for code in ('guest_transport_error', 'windows_transport_error', 'not_allowed_in_state'):
        value['error'] = {'code': code}
        value['lifecycle']['state'] = 'ownership_unknown'
        assert runner.expectation('host_unknown', value) is False
