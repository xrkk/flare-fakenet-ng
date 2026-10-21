"""Merge passive running observations, Windows probes and guest facts.

The merge never upgrades a second blocker or an absent observation to pass.  The eight checks are
projected into the single-author contract's helper input; MalTrace remains
the qualification authority.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime

from fakenet.mcp import egress_contract, host_policy, host_probe


def _sha(value):
    return egress_contract.sha256_text(egress_contract.canonical_json(value))


def _ref(side, path, digest, kind):
    return {'side': side, 'path': str(path), 'sha256': digest, 'kind': kind}


def _check(value, refs):
    return {'value': value, 'evidence_refs': list(refs)}


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _identity_context(identity, sample):
    fields = ('account', 'sid', 'session', 'image_path', 'image_sha256',
              'vm_uuid', 'boot_id')
    payload = {key: identity.get(key) for key in fields}
    payload['sample'] = {
        key: sample.get(key) for key in
        ('account', 'sid', 'session', 'image_path', 'image_sha256')
    } if isinstance(sample, dict) else None
    return _sha(payload)


def _sample_matches(identity, sample):
    return egress_contract.sample_context_matches(identity, sample)


def _firewall_value(probe):
    profiles = probe.get('firewall') or []
    if probe.get('firewall_error') or len(profiles) != 3:
        return None
    names = {str(row.get('name')) for row in profiles}
    if names != {'Domain', 'Private', 'Public'}:
        return None
    return all(row.get('enabled') is False for row in profiles)


def _scope_guard(probe, observation_report=None):
    facts = probe.get('ipv6_exposure') if isinstance(probe, dict) else None
    if not isinstance(facts, dict):
        return {
            'schema': egress_contract.SCOPE_GUARD_SCHEMA,
            'value': None, 'reason': 'ipv6_exposure_missing',
            'reasons': ['ipv6_exposure_missing'], 'fingerprint': None,
            'evidence_refs': [],
        }
    guard = egress_contract.normalize_ipv6_exposure(facts)
    leaks = (observation_report or {}).get('leaks') or []
    if any(row.get('family') == 'ipv6' for row in leaks):
        guard = dict(guard)
        guard['value'] = False
        guard['reason'] = 'ipv6_running_leak_observed'
        guard['reasons'] = ['ipv6_running_leak_observed']
    guard['evidence_refs'] = ['windows-probe#ipv6_exposure']
    return guard


def _scoped_containment(report, family):
    # Family facts only exist after the common evidence has been verified.
    # Leakage remains decisive even when that verification cannot finish.
    if report.get('value') is False or report.get('leaks'):
        return False
    if report.get('common_complete') is not True:
        return None
    if report.get('value') is True:
        return True
    path = (report.get('families') or {}).get(family) or {}
    return True if path.get('value') is True else None


def _parse_endpoint(value):
    text = str(value or '')
    if ':' not in text:
        return None, None
    host, _, port = text.rpartition(':')
    try:
        port = int(port)
    except ValueError:
        return None, None
    return host.strip('[]').split('%')[0], port


def _drop_evidence(row, host_snapshot, final_host_snapshot, probe=None):
    if not isinstance(row, dict) or row.get('kind') != 'tcp':
        return None
    for key in ('family', 'destination', 'port'):
        if row.get(key) in (None, ''):
            return None
    probe = probe or {}
    instance = probe.get('instance') or {}
    if (row.get('exclusive') is not True or row.get('connect_called') is not True
            or not instance.get('pid') or not instance.get('creation_ticks')
            or row.get('probe_pid') != instance.get('pid')
            or row.get('probe_birth_ticks') != instance.get('creation_ticks')
            or not row.get('script_hash')
            or row.get('script_hash') != instance.get('script_hash')
            or row.get('bound_local_endpoint') != row.get('local_endpoint')):
        return None
    if row.get('attempted') is not True or row.get('received'):
        return None
    if not row.get('connect_started') or not row.get('connect_ended'):
        return None
    local = _parse_endpoint(row.get('local_endpoint'))
    if local[0] is None or local[1] is None:
        return None
    if local[0] in ('0.0.0.0', '::', '0:0:0:0:0:0:0:0'):
        return None
    pre = (host_snapshot or {}).get('observer') or {}
    final = (final_host_snapshot or {}).get('observer') or {}
    if not pre.get('available') or not final.get('available'):
        return None
    if pre.get('phase') != 'pre' or final.get('phase') != 'final':
        return None
    if not pre.get('command_id') or pre.get('command_id') != final.get('command_id'):
        return None
    pre_facts = pre.get('facts') or {}
    final_facts = final.get('facts') or {}
    if pre_facts.get('target') != final_facts.get('target'):
        return None
    pre_producer = pre.get('producer') or {}
    final_producer = final.get('producer') or {}
    for key in ('pid', 'birth_ticks', 'boot_id', 'script_sha256'):
        if not pre_producer.get(key) or pre_producer.get(key) != final_producer.get(key):
            return None
    if (host_snapshot.get('policy') or {}).get('ok') is not True or (final_host_snapshot.get('policy') or {}).get('ok') is not True:
        return None
    if not (host_snapshot.get('policy') or {}).get('identity') or (host_snapshot.get('policy') or {}).get('identity') != (final_host_snapshot.get('policy') or {}).get('identity'):
        return None
    try:
        start = datetime.fromisoformat(row['connect_started'].replace('Z', '+00:00')).timestamp()
        end = datetime.fromisoformat(row['connect_ended'].replace('Z', '+00:00')).timestamp()
        before = pre['response']['collected_at']
        after = final['response']['collected_at']
        if not before - 1 <= start <= end <= after + 1 or after - before > 50:
            return None
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    if (probe.get('identity') or {}).get('boot_id') != pre_facts.get('target', {}).get('boot_id'):
        return None
    family = str(row.get('family') or '').lower()
    delta = host_policy.drop_delta(
        pre_facts, final_facts, family=family,
        source=local[0], source_port=local[1],
        destination=str(row.get('destination')),
        destination_port=int(row.get('port')))
    return delta if delta is not None and delta > 0 else None


def _matrix_steps(probe, expected_map, boundary_verified=None,
                  evidence_refs=(), host_snapshot=None,
                  final_host_snapshot=None):
    observed = {row.get('id'): row for row in probe.get('steps') or []
                if isinstance(row, dict)}
    steps = []
    matrix_run = probe.get('matrix_run') is True
    for step_id, expected in expected_map.items():
        row = observed.get(step_id)
        if row is None:
            steps.append({
                'id': step_id,
                'outcome': 'not_run' if not matrix_run else 'unknown',
                'expected': expected.get('expected'),
                'observed': {'reason': probe.get('not_run_reason',
                                                 'missing_matrix_row')},
                'reason_code': probe.get('not_run_reason',
                                         'missing_matrix_row'),
                'evidence_refs': [], 'started_at': None, 'ended_at': None,
            })
            continue
        instance = probe.get('instance') or {}
        execution_verified = bool(instance.get('pid') and instance.get('creation_ticks') and
            instance.get('script_hash') and row.get('probe_pid') == instance['pid'] and
            row.get('probe_birth_ticks') == instance['creation_ticks'] and
            row.get('script_hash') == instance['script_hash'])
        if any(row.get(k) != expected.get(k) for k in ('kind', 'family', 'destination', 'port')):
            execution_verified = False
        observation_report = probe.get('running_observation') or {}
        containment = _scoped_containment(
            observation_report, expected.get('family'))
        outcome, reason = host_probe.classify_step(
            expected, row, expected.get('expected'),
            containment_observed=containment,
            execution_verified=execution_verified)
        if any(leak.get('family') == expected.get('family') and
               leak.get('destination') == expected.get('destination') and
               (expected.get('port') is None or leak.get('destination_port') == expected.get('port'))
               for leak in observation_report.get('leaks') or []):
            outcome, reason = 'fail', 'running_egress_leak_observed'
        drop_evidence = None
        steps.append({
            'id': step_id, 'outcome': outcome,
            'expected': expected.get('expected'),
            'observed': {'received': row.get('received'),
                         'error': row.get('error'),
                         'outcome': row.get('outcome'),
                         'response_type': row.get('response_type'),
                         'status': row.get('status'),
                         'nonce_match': row.get('nonce_match'),
                         'address_family': row.get('address_family'),
                         'remote_endpoint': row.get('remote_endpoint'),
                         'drop_count_delta': drop_evidence},
            'reason_code': reason,
            'evidence_refs': list(row.get('evidence_refs') or
                                  evidence_refs),
            'started_at': row.get('started'),
            'ended_at': row.get('ended'),
        })
    return steps



def build_host_result(*, command_id, request, guest_result, host_snapshot,
                      probe_result, expected_map, config, channels,
                      host_evidence=None, probe_evidence=None,
                      final_host_evidence=None, host_final_snapshot=None,
                      started_at=None, identity_probe_evidence=None):
    started = started_at or _now()
    ended = _now()
    identity = probe_result.get('identity') or {}
    sample = config.get('sample_context')
    sample_value = _sample_matches(identity, sample)
    process_rules_value = request.get('process_rules_equivalent')
    if 'process_rules_equivalent' in request and sample_value is True and             process_rules_value is not True:
        sample_value = None if process_rules_value is None else False
    firewall_value = _firewall_value(probe_result)
    guest_checks = (guest_result or {}).get('checks') or {}
    guest_health = (guest_checks.get('fakenet_running_healthy') or {}).get(
        'value')
    guest_control = (guest_checks.get(
        'mcp_control_exclusions_effective') or {}).get('value')
    control_values = [channels.get(key) for key in
                      ('windows_mcp', 'fakenet_mcp', 'velo_mcp')]
    if any(value is False for value in control_values):
        control_value = False
    elif all(value is True for value in control_values):
        control_value = True
    else:
        control_value = None
    if guest_control is False or control_value is False:
        exclusion_value = False
    elif guest_control is True and control_value is True:
        exclusion_value = True
    else:
        exclusion_value = None
    positive = probe_result.get('positive') or {}
    positive_present = isinstance(probe_result.get('positive'), dict) and bool(
        probe_result.get('positive'))
    positive_match = positive.get('nonce_match') is True
    producer_match = (guest_result or {}).get('producer_match')
    if positive_match and producer_match is True:
        local_value = True
    elif positive_match and producer_match is None:
        local_value = None
    elif not positive_present:
        local_value = None
    else:
        local_value = False
    blocked_value = False if local_value is True else None
    observation_report = probe_result.get('running_observation') or {}
    scope_guard = _scope_guard(probe_result, observation_report)
    guard_public = {k: v for k, v in scope_guard.items() if k != 'canonical'}
    egress_value = _scoped_containment(observation_report, 'ipv4')
    checks = {
        'firewall_disabled': _check(firewall_value, []),
        'fakenet_running_healthy': _check(guest_health, []),
        'mcp_control_exclusions_effective': _check(exclusion_value, []),
        'blocked_before_interception': _check(blocked_value, []),
        'control_channels_reachable': _check(control_value, []),
        'local_interception_observed': _check(local_value, []),
        'running_egress_contained': _check(egress_value, []),
        'sample_path_equivalent': _check(sample_value, []),
    }
    refs = []
    if host_evidence:
        refs.append(_ref('host', host_evidence['path'],
                         host_evidence['sha256'], 'host-provider'))
    for item in observation_report.get('evidence_refs') or []:
        refs.append(dict(item))
    if identity_probe_evidence:
        refs.append(_ref('host', identity_probe_evidence['path'],
                         identity_probe_evidence['sha256'], 'windows-identity-probe'))
    if probe_evidence:
        refs.append(_ref('host', probe_evidence['path'],
                         probe_evidence['sha256'], 'windows-probe'))
    if final_host_evidence:
        refs.append(_ref('host', final_host_evidence['path'],
                         final_host_evidence['sha256'], 'host-final'))
    guest_manifest = (guest_result or {}).get('manifest') or {}
    for entry in guest_manifest.get('entries') or []:
        if isinstance(entry, dict):
            refs.append(dict(entry))
    ref_strings = [str(item.get('path')) + '#' + str(item.get('sha256'))
                   for item in refs]
    host_refs = [item for item in ref_strings
                 if item.startswith(str((host_evidence or {}).get('path', '')))]
    probe_refs = [item for item in ref_strings
                  if item.startswith(str((probe_evidence or {}).get('path', '')))]
    guest_refs = [item for item in ref_strings if item not in
                  host_refs + probe_refs]
    boundary_value = None  # A second blocker is never qualification evidence.
    matrix_steps = _matrix_steps(probe_result, expected_map,
                                 boundary_verified=boundary_value is True,
                                 evidence_refs=[item for item in refs if item.get('kind') == 'windows-probe'],
                                 host_snapshot=host_snapshot,
                                 final_host_snapshot=host_final_snapshot)
    final_consistency = probe_result.get('final_consistency')
    completeness = egress_contract.evaluate_verification_completeness(
        list(expected_map), matrix_steps, positive, producer_match,
        final_consistency,
        required_ids=egress_contract.IPV4_REQUIRED_IDS,
        diagnostic_ids=egress_contract.IPV6_DIAGNOSTIC_IDS)
    probe_completed = probe_result.get('completed_at')
    if not isinstance(probe_completed, str) or not probe_completed:
        completeness['complete'] = False
        completeness['status'] = 'underdetermined'
        completeness['reason'] = 'probe_completion_missing'
        if 'probe_completion' not in completeness['unknown_steps']:
            completeness['unknown_steps'].append('probe_completion')
    # Attach only the evidence that can actually support each check.
    check_refs = {
        'firewall_disabled': probe_refs,
        'fakenet_running_healthy': guest_refs,
        'mcp_control_exclusions_effective': guest_refs,
        'blocked_before_interception': probe_refs or host_refs,
        'control_channels_reachable': host_refs,
        'local_interception_observed': probe_refs + guest_refs,
        'running_egress_contained': probe_refs + [str(item.get('path')) + '#' + str(item.get('sha256')) for item in observation_report.get('evidence_refs') or []],
        'sample_path_equivalent': probe_refs,
    }
    for key, refs_for_check in check_refs.items():
        if checks[key]['value'] is not None and refs_for_check:
            checks[key]['evidence_refs'] = list(refs_for_check)
    plan = {
        'run_id': request['run_id'],
        'vm_epoch': request['vm_epoch'],
        'policy_identity': request['policy_identity'],
        'execution_context_identity': request['execution_context_identity'],
        'probe_nonce': request['probe_nonce'],
        'required_control_ports': request['required_control_ports'],
        'qualification_profile': egress_contract.QUALIFICATION_PROFILE,
        'required_matrix_ids': list(egress_contract.IPV4_REQUIRED_IDS),
        'diagnostic_matrix_ids': list(egress_contract.IPV6_DIAGNOSTIC_IDS),
    }
    observation = {
        'contract_version': egress_contract.CONTRACT_VERSION,
        'qualification_profile': egress_contract.QUALIFICATION_PROFILE,
        'ipv6_exposure': probe_result.get('ipv6_exposure'),
        'scope_guard': guard_public,
        'run_id': plan['run_id'],
        'vm_epoch': plan['vm_epoch'],
        'policy_identity': plan['policy_identity'],
        'execution_context_identity': plan['execution_context_identity'],
        'response_nonce': (request['probe_nonce'] if positive_match else None),
        'effective_control_exclusion_ports': (
            (guest_result or {}).get('bindings', {}).get(
                'effective_control_exclusion_ports')),
        'checks': checks,
        'verification_completeness': {
            'schema': 'fakenetng.verification-completeness.v1',
            **completeness,
        },
    }
    conclusion = egress_contract.evaluate_interception_qualification(
        plan, observation)
    status = conclusion['status']
    host_steps = [
        {'id': 'host_vmx', 'outcome': 'pass' if host_snapshot.get(
            'vmx', {}).get('available') else 'unknown',
         'expected': 'configured VMX/NIC identity',
         'observed': host_snapshot.get('vmx'),
         'reason_code': 'vmx_read' if host_snapshot.get('vmx', {}).get(
             'available') else 'vmx_unavailable',
         'evidence_refs': refs[:1], 'started_at': started, 'ended_at': ended},
        {'id': 'host_network', 'outcome': 'pass' if host_snapshot.get(
            'networking', {}).get('available') else 'unknown',
         'expected': 'VMnet type/NAT/DHCP configuration',
         'observed': {'networking': host_snapshot.get('networking'),
                      'nat': host_snapshot.get('nat')},
         'reason_code': 'vmnet_read', 'evidence_refs': refs[:1],
         'started_at': started, 'ended_at': ended},
        {'id': 'host_route', 'outcome': 'pass' if host_snapshot.get(
            'route_to_guest', {}).get('returncode') == 0 else 'unknown',
         'expected': 'host route to guest vmnet',
         'observed': host_snapshot.get('route_to_guest'),
         'reason_code': 'host_route_read', 'evidence_refs': refs[:1],
         'started_at': started, 'ended_at': ended},
        {'id': 'host_forwarding', 'outcome': 'pass' if host_snapshot.get(
            'forwarding', {}).get('ipv4') is not None else 'unknown',
         'expected': 'IPv4/IPv6 forwarding facts',
         'observed': host_snapshot.get('forwarding'),
         'reason_code': 'forwarding_read', 'evidence_refs': refs[:1],
         'started_at': started, 'ended_at': ended},
        {'id': 'host_firewall', 'outcome': 'pass' if host_snapshot.get(
            'firewall', {}).get('known') else 'unknown',
         'expected': 'readable host firewall/NAT rule evidence',
         'observed': host_snapshot.get('firewall'),
         'reason_code': 'firewall_read' if host_snapshot.get(
             'firewall', {}).get('known') else 'firewall_unknown',
         'evidence_refs': refs[:1], 'started_at': started, 'ended_at': ended},
        {'id': 'control_28787', 'outcome': 'pass' if channels.get(
            'windows_mcp') is True else 'unknown',
         'expected': 'Windows-MCP request/response during run',
         'observed': channels.get('details', {}).get('windows_mcp'),
         'reason_code': 'control_positive', 'evidence_refs': refs,
         'started_at': started, 'ended_at': ended},
        {'id': 'control_28788', 'outcome': 'pass' if channels.get(
            'fakenet_mcp') is True else 'unknown',
         'expected': 'FakeNet MCP request/response during run',
         'observed': channels.get('details', {}).get('fakenet_mcp'),
         'reason_code': 'control_positive', 'evidence_refs': refs,
         'started_at': started, 'ended_at': ended},
        {'id': 'control_28790', 'outcome': 'pass' if channels.get(
            'velo_mcp') is True else 'unknown',
         'expected': 'Velo MCP request/response during run',
         'observed': channels.get('details', {}).get('velo_mcp'),
         'reason_code': 'control_positive', 'evidence_refs': refs,
         'started_at': started, 'ended_at': ended},
        {'id': 'windows_identity', 'outcome': 'pass' if identity else 'unknown',
         'expected': 'sample-context Windows identity',
         'observed': {key: identity.get(key) for key in
                      ('pid', 'creation_ticks', 'account', 'sid', 'session',
                       'image_path', 'vm_uuid', 'boot_id')},
         'reason_code': 'identity_read' if identity else 'identity_missing',
         'evidence_refs': refs, 'started_at': started, 'ended_at': ended},
        {'id': 'windows_firewall', 'outcome': 'pass' if firewall_value is True
         else ('fail' if firewall_value is False else 'unknown'),
         'expected': 'Domain/Private/Public Enabled=False',
         'observed': {'firewall': probe_result.get('firewall'),
                      'error': probe_result.get('firewall_error')},
         'reason_code': 'firewall_disabled' if firewall_value else
         'firewall_unconfirmed', 'evidence_refs': refs,
         'started_at': started, 'ended_at': ended},
        {'id': 'windows_local_interception',
         'outcome': 'pass' if local_value is True else
         ('fail' if local_value is False else 'unknown'),
         'expected': 'nonce through current WinDivert to local listener',
         'observed': {'positive': positive, 'producer_match': producer_match},
         'reason_code': 'nonce_match_and_producer' if local_value else
         'producer_or_nonce_unconfirmed',
         'evidence_refs': refs, 'started_at': positive.get('started'),
         'ended_at': positive.get('ended')},
        {'id': 'sample_context',
         'outcome': 'pass' if sample_value is True else
         ('fail' if sample_value is False else 'unknown'),
         'expected': 'probe context equals declared sample launcher context',
         'observed': {'probe': {key: identity.get(key) for key in
                                ('account', 'sid', 'session', 'image_path',
                                 'image_sha256')},
                      'declared': sample},
         'reason_code': 'context_match' if sample_value else
         'context_unconfirmed', 'evidence_refs': refs,
         'started_at': started, 'ended_at': ended},
    ]
    positive_step = {
        'id': 'local_interception_positive',
        'outcome': ('pass' if local_value is True else
                    ('fail' if local_value is False else 'unknown')),
        'expected': 'nonce request through the current WinDivert path',
        'observed': {'positive': positive,
                     'producer_match': producer_match},
        'reason_code': ('nonce_and_producer_match' if local_value is True
                        else 'positive_or_producer_unconfirmed'),
        'evidence_refs': refs,
        'started_at': positive.get('started'),
        'ended_at': positive.get('ended'),
    }
    final_step = {
        'id': 'host_final_consistency',
        'outcome': ('pass' if final_consistency is True else
                    ('fail' if final_consistency is False else 'unknown')),
        'expected': 'host/guest/VM/run/config re-read unchanged at the end',
        'observed': probe_result.get('final_consistency_observed'),
        'reason_code': ('final_consistency_verified'
                        if final_consistency is True else
                        'final_consistency_unconfirmed'),
        'evidence_refs': refs, 'started_at': ended, 'ended_at': ended,
    }
    host_steps.append({
        'id': 'host_running_observation',
        'outcome': 'pass' if egress_value is True else 'fail' if egress_value is False else 'unknown',
        'expected': 'passive evidence of no egress during this FakeNet running window',
        'observed': observation_report,
        'reason_code': observation_report.get('reason', 'passive_observation_missing'),
        'evidence_refs': observation_report.get('evidence_refs') or [],
        'started_at': started, 'ended_at': ended,
    })
    guest_steps = (guest_result or {}).get('steps') or []
    steps = host_steps + [positive_step] + matrix_steps + [final_step] + \
        list(guest_steps)
    executed = sum(1 for step in steps if step.get('outcome') != 'not_run')
    failed_checks = list(conclusion['failed_checks'])
    unknown_checks = list(conclusion['unknown_checks'])
    if completeness['status'] == 'invalid_environment':
        status = 'invalid_environment'
        if 'matrix_completeness' not in failed_checks:
            failed_checks.append('matrix_completeness')
    elif completeness['status'] == 'underdetermined':
        if status == 'qualified_in_scope':
            status = 'underdetermined'
        if 'matrix_completeness' not in unknown_checks:
            unknown_checks.append('matrix_completeness')
    if status == 'qualified_in_scope' and not completeness['complete']:
        status = 'underdetermined'
    sample_path_qualified = (conclusion['sample_path_qualified'] and
                             completeness['complete'])
    stop_remaining = bool(conclusion['stop_remaining_probes'] or
                          completeness['status'] == 'invalid_environment')
    entries = refs
    coverage = {
        'matrix_version': request['matrix_version'],
        'planned': len(steps), 'executed': executed,
        'matrix_planned': len(expected_map),
        'qualification_profile': egress_contract.QUALIFICATION_PROFILE,
        'required_matrix_ids': list(egress_contract.IPV4_REQUIRED_IDS),
        'diagnostic_matrix_ids': list(egress_contract.IPV6_DIAGNOSTIC_IDS),
        'matrix_executed': sum(1 for step in matrix_steps
                               if step.get('outcome') != 'not_run'),
        'matrix_not_run': [{'id': step.get('id'),
                            'reason': step.get('reason_code')}
                           for step in matrix_steps
                           if step.get('outcome') == 'not_run'],
        'positive_planned': 1,
        'positive_executed': 1 if positive_step['outcome'] != 'not_run' else 0,
        'final_consistency': final_consistency,
        'completeness': completeness,
        'not_run': [{'id': step.get('id'),
                     'reason': step.get('reason_code')}
                    for step in steps if step.get('outcome') == 'not_run'],
        'families': {
            family: {
                'required': family == 'ipv4',
                'ids': [step_id for step_id in expected_map
                        if str(step_id).startswith(family + '_')],
                'outcomes': {
                    outcome: sum(1 for step in matrix_steps
                                 if step.get('id') in expected_map and
                                 str(step.get('id')).startswith(family + '_') and
                                 step.get('outcome') == outcome)
                    for outcome in ('pass', 'fail', 'unknown', 'not_run')},
            } for family in ('ipv4', 'ipv6')},
    }
    result = {
        'contract_version': egress_contract.CONTRACT_VERSION,
        'qualification_profile': egress_contract.QUALIFICATION_PROFILE,
        'phase': 'running',
        'schema_version': egress_contract.SCHEMA_VERSION,
        'verification_id': request['verification_id'],
        'command_id': command_id,
        'lifecycle': {'state': 'completed', 'started_at': started,
                      'ended_at': ended, 'duration_ms': None, 'reason': None},
        'verdict': egress_contract.verdict_from_status(status),
        'bindings': {
            'run_id': request['run_id'],
            'vm_epoch': request['vm_epoch'],
            'policy_identity': request['policy_identity'],
            'execution_context_identity':
                request['execution_context_identity'],
            'probe_nonce': request['probe_nonce'],
            'response_nonce': observation['response_nonce'],
            'required_control_ports': request['required_control_ports'],
            'effective_control_exclusion_ports':
                observation['effective_control_exclusion_ports'],
            'config_identity': (guest_result or {}).get('bindings', {}).get(
                'config_identity'),
            'final_filter_sha256': (guest_result or {}).get(
                'bindings', {}).get('final_filter_sha256'),
            'host_evidence_sha256': (host_evidence or {}).get('sha256'),
            'guest_evidence_sha256': (guest_result or {}).get(
                'bindings', {}).get('guest_evidence_sha256'),
            'controller_identity': (guest_result or {}).get(
                'bindings', {}).get('controller_identity'),
            'facade_version': (guest_result or {}).get(
                'bindings', {}).get('facade_version'),
            'matrix_version': request['matrix_version'],
            'qualification_profile': egress_contract.QUALIFICATION_PROFILE,
            'scope_guard_fingerprint': scope_guard.get('fingerprint'),
            'required_matrix_ids': list(egress_contract.IPV4_REQUIRED_IDS),
            'diagnostic_matrix_ids': list(egress_contract.IPV6_DIAGNOSTIC_IDS),
        },
        'scope_guard': guard_public,
        'steps': steps,
        'checks': checks,
        'helper_input': {'plan': plan, 'observation': observation},
        'conclusion': {
            'status': status,
            'verdict': egress_contract.verdict_from_status(status),
            'failed_checks': failed_checks,
            'unknown_checks': unknown_checks,
            'sample_path_qualified': sample_path_qualified,
            'stop_remaining_probes': stop_remaining,
            'matrix_completeness': completeness,
            'qualification_profile': egress_contract.QUALIFICATION_PROFILE,
            'scope_guard': guard_public,
            'family_coverage': {
                family: {'required': family == 'ipv4',
                         'outcomes': coverage['families'][family]['outcomes']}
                for family in ('ipv4', 'ipv6')},
            'authorized': False,
            'reason': ('matrix_or_final_incomplete'
                       if status in ('invalid_environment',
                                     'underdetermined') and
                       completeness['status'] != 'complete'
                       else ('host_unknown' if status == 'underdetermined'
                             else status)),
        },
        'coverage': coverage,
        'probe_completion': {
            'completed_at': probe_completed,
            'matrix_run': probe_result.get('matrix_run') is True,
            'matrix_rows': len(probe_result.get('steps') or []),
            'positive_started': (probe_result.get('positive') or {}).get(
                'started'),
            'positive_ended': (probe_result.get('positive') or {}).get(
                'ended'),
        },
        'running_observation': {
            key: observation_report.get(key) for key in
            ('value', 'reason', 'common_complete', 'families', 'leaks',
             'evidence_refs', 'calibration', 'paths')
        },
        'manifest': {'sha256': _sha(entries), 'entries': entries,
                     'invalidation_conditions': [
                         'run_id', 'vm_epoch', 'policy_identity',
                         'execution_context_identity', 'config_identity',
                         'final_filter', 'network_topology', 'visibility_calibration', 'host_evidence',
                         'windows_session', 'service_restart',
                         'command_cache_eviction', 'nonce_reuse',
                         'evidence_hash']},
        'invalidation_conditions': [
            'run_id', 'vm_epoch', 'policy_identity',
            'execution_context_identity', 'config_identity', 'final_filter',
            'network_topology', 'visibility_calibration', 'host_evidence', 'windows_session',
            'service_restart', 'command_cache_eviction', 'nonce_reuse',
            'evidence_hash'],
        'limitations': [
            'host boundary pass requires complete, readable evidence',
            'TEST-NET timeout is not egress-block evidence',
            'LocalSystem guest echo is not sample-context interception',
            'pass requires all 30 diagnostic rows and the fixed IPv4 required 15,',
            'strict IPv6 scope guard, a separate positive,',
            'producer association and a final consistency read',
        ],
        'producer_match': producer_match,
        'authorized': False,
        'error': None,
    }
    return result
