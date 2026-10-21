"""Single authoring source for the egress interception qualification contract.

This module is deliberately standard-library only.  The MalTrace workflow
consumes a generated local copy of this file; neither side imports the other
at runtime.  The eight checks, four bindings, nonce/port rules and status
mapping are the same semantics as the original MalTrace helper.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Mapping

CONTRACT_VERSION = 3
QUALIFICATION_PROFILE = 'ipv4-v1'
SCOPE_GUARD_SCHEMA = 'fakenetng.ipv6-scope-guard.v1'
SCHEMA_VERSION = 'fakenetng.egress-verification.v1'
MATRIX_VERSION = 'v1'
SOURCE_PATH = 'fakenet/mcp/egress_contract.py'

BINDINGS = ('run_id', 'vm_epoch', 'policy_identity',
            'execution_context_identity')
EXPECTED_CHECKS = {
    'firewall_disabled': True,
    'fakenet_running_healthy': True,
    'mcp_control_exclusions_effective': True,
    'blocked_before_interception': False,
    'control_channels_reachable': True,
    'local_interception_observed': True,
    'running_egress_contained': True,
    'sample_path_equivalent': True,
}
CHECK_NAMES = tuple(EXPECTED_CHECKS)
MATRIX_DESTINATIONS = {
    'ipv4': '198.51.100.77',
    'ipv6': '2001:db8::77',
}
MATRIX_TCP_PORTS = (80, 443, 139)
MATRIX_UDP_PORTS = (53, 443, 67, 68, 137, 138, 1900, 5355)
IPV4_REQUIRED_IDS = tuple(
    ['ipv4_tcp_%d' % p for p in MATRIX_TCP_PORTS] + ['ipv4_tcp_random'] +
    ['ipv4_udp_%d' % p for p in MATRIX_UDP_PORTS] + ['ipv4_udp_random'] +
    ['ipv4_icmp', 'ipv4_dns_nonce_invalid'])
IPV6_DIAGNOSTIC_IDS = tuple(
    ['ipv6_tcp_%d' % p for p in MATRIX_TCP_PORTS] + ['ipv6_tcp_random'] +
    ['ipv6_udp_%d' % p for p in MATRIX_UDP_PORTS] + ['ipv6_udp_random'] +
    ['ipv6_icmp', 'ipv6_dns_nonce_invalid'])
if len(IPV4_REQUIRED_IDS) != 15 or len(IPV6_DIAGNOSTIC_IDS) != 15:
    raise RuntimeError('matrix profile family count invalid')


class EgressContractError(ValueError):
    """Stable contract error translated to ExperimentError by MalTrace."""


def _refs(refs):
    return (isinstance(refs, list) and 0 < len(refs) <= 1024 and
            all(isinstance(item, str) and item for item in refs))


def valid_ports(value):
    return (isinstance(value, list) and 0 < len(value) <= 64 and
            all(type(port) is int and 1 <= port <= 65535 for port in value)
            and len(set(value)) == len(value))


def _limit(value):
    return isinstance(value, list) and 0 < len(value) <= 256


def normalize_ipv6_exposure(facts):
    """Return a fail-closed canonical IPv6 scope guard.

    This is a total function: malformed/partial facts never raise.  Only a
    complete OS-index/type map whose every IPv6 interface is Loopback, whose
    only address is ::1/128 and whose routes are exactly ::1/128 or ff00::/8
    on that loopback, with forwarding disabled, can pass.  Link-local,
    on-link multicast, disconnected-but-configured, ULA, tunnels, missing
    mappings, duplicate/truncated facts and empty input are unknown.
    """
    reasons = []
    facts = facts if isinstance(facts, Mapping) else None
    if facts is None:
        return {'schema': SCOPE_GUARD_SCHEMA, 'value': None,
                'reason': 'ipv6_facts_invalid', 'reasons': ['ipv6_facts_invalid'],
                'fingerprint': None, 'canonical': None,
                'evidence_refs': [], 'authorized': False}
    def add(reason):
        if reason not in reasons:
            reasons.append(reason)
    if facts.get('schema') != 'fakenetng.ipv6-exposure.v1':
        add('ipv6_schema_invalid')
    if facts.get('complete') is not True:
        add('ipv6_fact_incomplete')
    errors = facts.get('errors')
    if not isinstance(errors, list) or errors:
        add('ipv6_fact_error')
    interfaces = facts.get('interfaces')
    addresses = facts.get('addresses')
    routes = facts.get('routes')
    os_map = facts.get('os_map')
    for value, reason in ((interfaces, 'ipv6_interfaces_invalid'),
                          (addresses, 'ipv6_addresses_invalid'),
                          (routes, 'ipv6_routes_invalid'),
                          (os_map, 'ipv6_os_map_invalid')):
        if not isinstance(value, list) or len(value) == 0 or len(value) > 256:
            add(reason)
    if reasons:
        # Still construct a minimal canonical representation for the
        # fingerprint, without indexing malformed entries.
        return {'schema': SCOPE_GUARD_SCHEMA, 'value': None,
                'reason': reasons[0], 'reasons': reasons,
                'fingerprint': sha256_text(canonical_json({
                    'schema': SCOPE_GUARD_SCHEMA, 'reasons': reasons})),
                'canonical': None, 'evidence_refs': ['windows-probe#ipv6_exposure'],
                'authorized': False}
    inter = {}
    mapping = {}
    try:
        for row in interfaces:
            if not isinstance(row, Mapping):
                raise TypeError('interface')
            idx = row.get('index')
            if type(idx) is not int or idx < 0:
                raise TypeError('interface index')
            forwarding = str(row.get('forwarding') or '').lower()
            state = str(row.get('connection_state') or row.get('state') or '').lower()
            if not forwarding or not state:
                raise ValueError('interface fields')
            if idx in inter:
                raise ValueError('duplicate interface')
            inter[idx] = {'index': idx, 'forwarding': forwarding,
                          'connection_state': state}
        for row in os_map:
            if not isinstance(row, Mapping):
                raise TypeError('os map')
            idx = row.get('index')
            typ = str(row.get('type') or '')
            if type(idx) is not int or idx < 0 or idx in mapping or not typ:
                raise ValueError('os map identity')
            mapping[idx] = typ
        if set(mapping) != set(inter):
            raise ValueError('os map incomplete')
        address_rows = {}
        for row in addresses:
            if not isinstance(row, Mapping):
                raise TypeError('address')
            idx = row.get('interface_index')
            addr = row.get('address')
            prefix = row.get('prefix_length')
            state = str(row.get('state') or '')
            if (type(idx) is not int or idx not in inter or
                    not isinstance(addr, str) or not addr or
                    type(prefix) is not int or not 0 <= prefix <= 128 or
                    not state):
                raise ValueError('address fields')
            try:
                ipaddress.ip_address(addr)
            except ValueError:
                raise ValueError('address syntax') from None
            key = (idx, addr.lower(), prefix)
            if key in address_rows:
                raise ValueError('duplicate address')
            address_rows[key] = {'interface_index': idx,
                                 'address': addr.lower(),
                                 'prefix_length': prefix, 'state': state}
        route_rows = {}
        for row in routes:
            if not isinstance(row, Mapping):
                raise TypeError('route')
            idx = row.get('interface_index')
            prefix = row.get('prefix')
            next_hop = row.get('next_hop')
            if (type(idx) is not int or idx not in inter or
                    not isinstance(prefix, str) or not prefix or
                    not isinstance(next_hop, str)):
                raise ValueError('route fields')
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                raise ValueError('route syntax') from None
            key = (idx, network.with_prefixlen, next_hop.lower())
            if key in route_rows:
                raise ValueError('duplicate route')
            route_rows[key] = {'interface_index': idx,
                               'prefix': network.with_prefixlen,
                               'next_hop': next_hop.lower()}
        # Strict positive: OS mapping and every configured interface/route.
        for idx, row in inter.items():
            if mapping.get(idx, '').lower() != 'loopback':
                add('ipv6_nonloopback_interface')
            if row['forwarding'] not in ('disabled', 'false', '0'):
                add('ipv6_forwarding_enabled')
            if row['connection_state'] not in ('up', 'connected'):
                add('ipv6_interface_state_not_up')
        if not any(key[1] == '::1' and key[2] == 128 for key in address_rows):
            add('ipv6_loopback_address_missing')
        for key in address_rows:
            idx, addr, prefix = key
            if addr != '::1' or prefix != 128:
                add('ipv6_nonloopback_address')
        if not route_rows:
            add('ipv6_route_list_empty')
        for key in route_rows:
            idx, prefix, next_hop = key
            if not (prefix == '::1/128' and next_hop == '::'):
                if not (prefix == 'ff00::/8' and next_hop == '::'):
                    add('ipv6_nonloopback_route')
        canonical = {
            'schema': SCOPE_GUARD_SCHEMA,
            'complete': True,
            'errors': [],
            'interfaces': [dict(inter[k], type=mapping.get(k))
                           for k in sorted(inter)],
            'addresses': [address_rows[k] for k in sorted(address_rows)],
            'routes': [route_rows[k] for k in sorted(route_rows)],
            'os_map': [{'index': k, 'type': mapping[k]}
                       for k in sorted(mapping)],
        }
        fingerprint = sha256_text(canonical_json(canonical))
        return {'schema': SCOPE_GUARD_SCHEMA,
                'value': True if not reasons else None,
                'reason': 'strict_loopback_ipv6_only' if not reasons else reasons[0],
                'reasons': reasons, 'fingerprint': fingerprint,
                'canonical': canonical,
                'evidence_refs': ['windows-probe#ipv6_exposure'],
                'authorized': False}
    except (TypeError, ValueError, KeyError) as exc:
        reason = 'ipv6_facts_malformed'
        add(reason)
        return {'schema': SCOPE_GUARD_SCHEMA, 'value': None,
                'reason': reasons[0], 'reasons': reasons,
                'fingerprint': sha256_text(canonical_json({
                    'schema': SCOPE_GUARD_SCHEMA, 'reasons': reasons})),
                'canonical': None, 'evidence_refs': ['windows-probe#ipv6_exposure'],
                'authorized': False}


def scope_guard_from_observation(observation):
    guard = observation.get('scope_guard') if isinstance(observation, Mapping) else None
    return guard if isinstance(guard, Mapping) else None


def evaluate_interception_qualification(plan: Mapping,
                                        observation: Mapping):
    """Read-only assessment of supplied qualification material.

    The function does not prove that evidence refs are true, does not control
    the network and always returns authorized=False.
    """
    if not isinstance(plan, Mapping) or not isinstance(observation, Mapping):
        raise EgressContractError('interception_qualification_invalid')
    for key in BINDINGS:
        if not isinstance(plan.get(key), str) or not plan[key].strip():
            raise EgressContractError('interception_binding_missing:' + key)
        if observation.get(key) != plan[key]:
            raise EgressContractError('interception_binding_changed:' + key)
    nonce = plan.get('probe_nonce')
    if not isinstance(nonce, str) or not 1 <= len(nonce) <= 256:
        raise EgressContractError('interception_nonce_invalid')
    ports = plan.get('required_control_ports')
    if not valid_ports(ports):
        raise EgressContractError('interception_control_ports_invalid')
    checks = observation.get('checks')
    if not isinstance(checks, Mapping):
        raise EgressContractError('interception_checks_invalid')
    failed, unknown = [], []
    profile = plan.get('qualification_profile')
    if profile != QUALIFICATION_PROFILE or observation.get(
            'qualification_profile') != profile:
        unknown.append('qualification_profile')
    required = plan.get('required_matrix_ids')
    diagnostic = plan.get('diagnostic_matrix_ids')
    if tuple(required or ()) != IPV4_REQUIRED_IDS or tuple(
            diagnostic or ()) != IPV6_DIAGNOSTIC_IDS:
        unknown.append('matrix_profile_scope')
    guard = scope_guard_from_observation(observation)
    if guard is None:
        unknown.append('scope_guard')
    else:
        if guard.get('schema') != SCOPE_GUARD_SCHEMA:
            raise EgressContractError('scope_guard_schema_invalid')
        try:
            recomputed = normalize_ipv6_exposure(observation.get('ipv6_exposure'))
        except Exception:  # noqa: BLE001 - malformed facts are unknown
            recomputed = {'value': None, 'fingerprint': None}
        same = (guard.get('value') == recomputed.get('value') and
                guard.get('fingerprint') == recomputed.get('fingerprint'))
        if guard.get('value') is True and same:
            pass
        elif guard.get('value') is False and same:
            failed.append('scope_guard')
        else:
            unknown.append('scope_guard')
    if observation.get("contract_version") != CONTRACT_VERSION:
        unknown.append("qualification_contract_version")
    for key, wanted in EXPECTED_CHECKS.items():
        item = checks.get(key)
        if not isinstance(item, Mapping) or item.get('value') is None:
            unknown.append(key)
            continue
        value = item['value']
        if type(value) is not bool:
            raise EgressContractError(
                'interception_check_not_tristate:' + key)
        if not _refs(item.get('evidence_refs')):
            raise EgressContractError(
                'interception_check_evidence_missing:' + key)
        if value is not wanted:
            failed.append(key)
    local = checks.get('local_interception_observed', {})
    if isinstance(local, Mapping) and local.get('value') is True:
        if observation.get('response_nonce') != nonce:
            failed.append('response_nonce_mismatch')
    completeness = observation.get('verification_completeness')
    if completeness is None:
        unknown.append('matrix_completeness')
    else:
        if not isinstance(completeness, Mapping) or completeness.get(
                'schema') != 'fakenetng.verification-completeness.v1':
            raise EgressContractError(
                'interception_completeness_invalid')
        if type(completeness.get('complete')) is not bool:
            raise EgressContractError(
                'interception_completeness_invalid')
        c_status = completeness.get('status')
        c_planned = completeness.get('planned')
        c_observed = completeness.get('observed')
        if type(c_planned) is not int or c_planned != 30 or                 type(c_observed) is not int or c_observed != 30:
            raise EgressContractError(
                'interception_completeness_invalid')
        if (list(completeness.get('required_ids') or []) != list(IPV4_REQUIRED_IDS)
                or list(completeness.get('diagnostic_ids') or []) != list(IPV6_DIAGNOSTIC_IDS)
                or completeness.get('qualification_profile') != QUALIFICATION_PROFILE):
            failed.append('matrix_profile_scope')
        if completeness['complete']:
            if c_status != 'complete' or completeness.get(
                    'missing_steps') or completeness.get(
                    'unknown_steps') or completeness.get('failed_steps'):
                raise EgressContractError(
                    'interception_completeness_invalid')
        else:
            if c_status == 'complete':
                raise EgressContractError(
                    'interception_completeness_invalid')
            if c_status == 'invalid_environment':
                failed.append('matrix_completeness')
            else:
                unknown.append('matrix_completeness')
    effective_ports = observation.get('effective_control_exclusion_ports')
    if effective_ports is None:
        unknown.append('effective_control_exclusion_ports')
    elif not valid_ports(effective_ports):
        raise EgressContractError(
            'interception_effective_control_ports_invalid')
    elif set(ports) - set(effective_ports):
        failed.append('missing_control_exclusion_ports')
    self_blocked = 'blocked_before_interception' in failed
    status = ('self_blocked_environment' if self_blocked else
              'invalid_environment' if failed else
              'underdetermined' if unknown else 'qualified_in_scope')
    return {
        'status': status,
        'failed_checks': failed,
        'unknown_checks': unknown,
        'sample_path_qualified': not failed and not unknown,
        'stop_remaining_probes': bool(failed),
        'authorized': False,
        'run_id': plan['run_id'],
        'qualification_profile': QUALIFICATION_PROFILE,
        'required_matrix_ids': list(IPV4_REQUIRED_IDS),
        'diagnostic_matrix_ids': list(IPV6_DIAGNOSTIC_IDS),
        'scope_guard': guard,
    }


SAMPLE_CONTEXT_REQUIRED = (
    'account', 'sid', 'session', 'token_integrity_level',
    'launcher_path', 'launcher_sha256', 'protocol_class',
)


def sample_context_matches(identity, sample):
    """Compare probe execution context with the declared sample launcher.

    The probe binary is not the sample binary: image path/hash equality is
    never required.  Account/SID/session, token integrity level, the effective
    policy class and the matrix protocol class must be present and equal.  The
    sample launcher path/hash must be real declared facts but are not compared
    to the probe image.  Any missing required fact is unknown, never a pass.
    """
    if not isinstance(identity, Mapping) or not isinstance(sample, Mapping):
        return None
    if any(sample.get(key) in (None, '') for key in SAMPLE_CONTEXT_REQUIRED):
        return None
    if any(str(sample.get(key)).strip().lower() in ('unknown', 'none')
           for key in SAMPLE_CONTEXT_REQUIRED):
        return None
    launcher = str(sample.get('launcher_path') or '')
    digest = str(sample.get('launcher_sha256') or '')
    if not launcher or not launcher.startswith('/') and ':' not in launcher:
        return None
    if len(digest) != 64 or any(ch not in '0123456789abcdefABCDEF'
                                for ch in digest):
        return None
    for key in ('account', 'sid', 'session', 'token_integrity_level',
                'protocol_class'):
        if identity.get(key) in (None, '') or str(
                identity.get(key)).strip().lower() in ('unknown', 'none'):
            return None
        if str(identity[key]) != str(sample[key]):
            return False
    # AppLocker is an optional additional fact, not a normal dependency and
    # not a substitute for FakeNet's own process rules.
    return True


def process_rules_match(sample_path, probe_path, rules):
    """Prove sample and probe are covered by the same FakeNet process rules.

    No process rule means both are captured.  Global/listener blacklists must
    exclude neither; whitelists must include both.  Any host rule whose target
    applicability cannot be proven makes the result unknown.  AppLocker is
    deliberately not consulted here.
    """
    if not isinstance(rules, Mapping):
        return None
    global_rules = rules.get('global')
    listeners = rules.get('listeners')
    if not isinstance(global_rules, Mapping) or not isinstance(
            listeners, Mapping):
        return None
    sample = str(sample_path or '').replace('\\', '/').rsplit('/', 1)[-1].lower()
    probe = str(probe_path or '').replace('\\', '/').rsplit('/', 1)[-1].lower()
    if not sample or not probe:
        return None
    if global_rules.get('host_white') or global_rules.get('host_black'):
        return None
    if global_rules.get('white'):
        if sample not in global_rules['white'] or probe not in global_rules[
                'white']:
            return False
    if sample in (global_rules.get('black') or []) or probe in (
            global_rules.get('black') or []):
        return False
    for rule in listeners.values():
        if not isinstance(rule, Mapping):
            return None
        if rule.get('host_white') or rule.get('host_black'):
            return None
        if rule.get('white'):
            if sample not in rule['white'] or probe not in rule['white']:
                return False
        if sample in (rule.get('black') or []) or probe in (
                rule.get('black') or []):
            return False
    return True


def evaluate_verification_completeness(expected_ids, matrix_steps, positive,
                                       producer_match, final_consistency,
                                       required_ids=None, diagnostic_ids=None):
    """Qualification gate for full matrix/positive/final evidence.

    The original eight-check helper stays unchanged.  This gate adds the
    completeness facts the single-call tool needs: every planned matrix row,
    a separately observed positive, the current producer association and a
    final consistency read.  It is the single authoring source for those
    conditions.
    """
    expected = [str(item) for item in (expected_ids or [])]
    required = [str(item) for item in (required_ids if required_ids is not None else IPV4_REQUIRED_IDS)]
    diagnostic = [str(item) for item in (diagnostic_ids if diagnostic_ids is not None else IPV6_DIAGNOSTIC_IDS)]
    profile_error = None
    try:
        fixed = list(matrix_step_ids(50001, 50002))
    except Exception:  # noqa: BLE001 - malformed module state
        fixed = []
    if (expected != fixed or tuple(required) != IPV4_REQUIRED_IDS or
            tuple(diagnostic) != IPV6_DIAGNOSTIC_IDS or
            len(required) != len(set(required)) or
            len(diagnostic) != len(set(diagnostic)) or
            set(required) & set(diagnostic)):
        profile_error = 'completeness_profile_invalid'
    if not expected or len(expected) != len(set(expected)):
        raise EgressContractError('completeness_expected_invalid')
    if not isinstance(matrix_steps, list):
        raise EgressContractError('completeness_matrix_invalid')
    rows = {}
    for row in matrix_steps:
        if not isinstance(row, Mapping) or not isinstance(row.get('id'), str):
            raise EgressContractError('completeness_row_invalid')
        if row['id'] in rows:
            raise EgressContractError('completeness_row_duplicate')
        rows[row['id']] = row
    missing = [item for item in expected if item not in rows]
    extra = [item for item in rows if item not in expected]
    invalid_outcomes = [item for item in expected if item in rows and
                        rows[item].get('outcome') not in
                        ('pass', 'fail', 'unknown', 'not_run')]
    failed = [item for item in required if item in rows and
              rows[item].get('outcome') == 'fail']
    unknown = [item for item in required if item in rows and
               rows[item].get('outcome') in ('unknown', 'not_run')]
    diagnostic_unknown = [item for item in diagnostic if item in rows and
                          rows[item].get('outcome') in ('unknown', 'not_run')]
    diagnostic_failed = [item for item in diagnostic if item in rows and
                         rows[item].get('outcome') == 'fail']
    if diagnostic_failed:
        failed.extend(diagnostic_failed)
    if extra:
        raise EgressContractError('completeness_row_unplanned')
    if invalid_outcomes:
        failed.extend(invalid_outcomes)
    positive_ok = isinstance(positive, Mapping) and         positive.get('nonce_match') is True
    producer_ok = producer_match is True
    if producer_match is False or (isinstance(positive, Mapping) and
                                   bool(positive) and positive.get(
                                       'nonce_match') is False):
        failed.append('positive_interception')
    elif not positive_ok or not producer_ok:
        unknown.append('positive_interception')
    if final_consistency is False:
        failed.append('final_consistency')
    elif final_consistency is not True:
        unknown.append('final_consistency')
    if missing:
        unknown.extend(missing)
    if profile_error:
        failed.append(profile_error)
    if failed:
        status = 'invalid_environment'
        reason = 'matrix_or_final_failed'
    elif unknown:
        status = 'underdetermined'
        reason = 'matrix_positive_or_final_unknown'
    else:
        status = 'complete'
        reason = 'all_matrix_rows_positive_producer_and_final_passed'
    return {
        'status': status,
        'qualification_profile': QUALIFICATION_PROFILE,
        'profile_error': profile_error,
        'complete': status == 'complete',
        'failed_steps': failed,
        'unknown_steps': unknown,
        'missing_steps': missing,
        'required_ids': required,
        'diagnostic_ids': diagnostic,
        'diagnostic_unknown_steps': diagnostic_unknown,
        'planned': len(expected),
        'observed': len(rows),
        'reason': reason,
        'authorized': False,
    }


def verdict_from_status(status):
    if status == 'qualified_in_scope':
        return 'pass'
    if status in ('self_blocked_environment', 'invalid_environment'):
        return 'fail'
    return 'unknown'


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'))


def sha256_text(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def request_fingerprint(payload):
    return sha256_text(canonical_json(payload))


def matrix_definition(random_tcp_port, random_udp_port):
    """Return the fixed v1 matrix, including one positive probe placeholder.

    The positive probe is not one of the 30 matrix rows; it is returned as a
    separate step so it cannot substitute for matrix coverage.
    """
    if (type(random_tcp_port) is not int or
            type(random_udp_port) is not int or
            not 1 <= random_tcp_port <= 65535 or
            not 1 <= random_udp_port <= 65535):
        raise EgressContractError('matrix_random_port_invalid')
    rows = []
    for family, destination in MATRIX_DESTINATIONS.items():
        for port in MATRIX_TCP_PORTS:
            rows.append({'id': '%s_tcp_%d' % (family, port),
                         'family': family, 'protocol': 'tcp',
                         'port': port, 'destination': destination,
                         'kind': 'tcp'})
        rows.append({'id': '%s_tcp_random' % family,
                     'family': family, 'protocol': 'tcp',
                     'port': random_tcp_port, 'destination': destination,
                     'kind': 'tcp', 'random': True})
        for port in MATRIX_UDP_PORTS:
            rows.append({'id': '%s_udp_%d' % (family, port),
                         'family': family, 'protocol': 'udp',
                         'port': port, 'destination': destination,
                         'kind': 'udp'})
        rows.append({'id': '%s_udp_random' % family,
                     'family': family, 'protocol': 'udp',
                     'port': random_udp_port, 'destination': destination,
                     'kind': 'udp', 'random': True})
        rows.append({'id': '%s_icmp' % family,
                     'family': family, 'protocol': 'icmp',
                     'port': None, 'destination': destination,
                     'kind': 'icmp'})
        rows.append({'id': '%s_dns_nonce_invalid' % family,
                     'family': family, 'protocol': 'udp',
                     'port': 53, 'destination': destination,
                     'kind': 'dns'})
    if len(rows) != 30:
        raise EgressContractError('matrix_definition_invalid')
    return rows


def matrix_step_ids(random_tcp_port, random_udp_port):
    return tuple(row['id'] for row in
                 matrix_definition(random_tcp_port, random_udp_port))


def validate_verification_request(value):
    """Strictly validate the versioned request passed to the guest tool."""
    if not isinstance(value, Mapping):
        raise EgressContractError('verification_request_invalid')
    if value.get('schema_version') != SCHEMA_VERSION:
        raise EgressContractError('verification_request_schema_invalid')
    for key in ('verification_id', 'run_id', 'vm_epoch', 'policy_identity',
                'execution_context_identity', 'probe_nonce',
                'matrix_version', 'host_evidence_sha256', 'budget'):
        if key not in value:
            raise EgressContractError(
                'verification_request_missing:' + key)
    if value.get('matrix_version') != MATRIX_VERSION:
        raise EgressContractError('verification_matrix_version_invalid')
    if not isinstance(value.get('probe_nonce'), str) or not 1 <= len(
            value['probe_nonce']) <= 256:
        raise EgressContractError('verification_nonce_invalid')
    if not valid_ports(value.get('required_control_ports')):
        raise EgressContractError('verification_control_ports_invalid')
    if not isinstance(value.get('budget'), Mapping):
        raise EgressContractError('verification_budget_invalid')
    if not isinstance(value.get('random_tcp_port'), int) or not isinstance(
            value.get('random_udp_port'), int):
        raise EgressContractError('verification_random_port_invalid')
    return dict(value)


def _base_material():
    plan = {
        'run_id': 'contract-case-run',
        'vm_epoch': 'contract-case-epoch',
        'policy_identity': 'contract-case-policy',
        'execution_context_identity': 'contract-case-context',
        'probe_nonce': 'contract-case-nonce',
        'required_control_ports': [28787, 28788, 28790],
        'qualification_profile': QUALIFICATION_PROFILE,
        'required_matrix_ids': list(IPV4_REQUIRED_IDS),
        'diagnostic_matrix_ids': list(IPV6_DIAGNOSTIC_IDS),
    }
    observation = dict(plan)
    observation['contract_version'] = CONTRACT_VERSION
    observation['verification_completeness'] = {
        'schema': 'fakenetng.verification-completeness.v1',
        **evaluate_verification_completeness(
            matrix_step_ids(50001, 50002),
            [{'id': key, 'outcome': 'pass'}
             for key in matrix_step_ids(50001, 50002)],
            {'nonce_match': True}, True, True),
    }
    observation['qualification_profile'] = QUALIFICATION_PROFILE
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
    observation['ipv6_exposure'] = facts
    observation['scope_guard'] = normalize_ipv6_exposure(facts)

    observation['response_nonce'] = plan['probe_nonce']
    observation['effective_control_exclusion_ports'] = [28787, 28788, 28790]
    observation['checks'] = {
        key: {'value': wanted, 'evidence_refs': ['case-evidence']}
        for key, wanted in EXPECTED_CHECKS.items()
    }
    return plan, observation


def _contract_cases():
    cases = []
    plan, observation = _base_material()
    cases.append({
        'name': 'qualified',
        'plan': plan,
        'observation': observation,
        'expected': {'status': 'qualified_in_scope', 'failed_checks': [],
                     'unknown_checks': [], 'sample_path_qualified': True,
                     'stop_remaining_probes': False, 'authorized': False,
                     'run_id': plan['run_id']},
    })
    plan, observation = _base_material()
    observation['checks']['blocked_before_interception']['value'] = True
    observation['checks']['local_interception_observed']['value'] = False
    cases.append({
        'name': 'self_blocked',
        'plan': plan,
        'observation': observation,
        'expected': {'status': 'self_blocked_environment',
                     'sample_path_qualified': False,
                     'stop_remaining_probes': True,
                     'authorized': False},
    })
    plan, observation = _base_material()
    observation['effective_control_exclusion_ports'] = [28787, 28788]
    cases.append({
        'name': 'missing_control_port',
        'plan': plan,
        'observation': observation,
        'expected': {'status': 'invalid_environment',
                     'failed_checks': ['missing_control_exclusion_ports'],
                     'sample_path_qualified': False,
                     'authorized': False},
    })
    plan, observation = _base_material()
    observation['response_nonce'] = 'different-nonce'
    cases.append({
        'name': 'nonce_mismatch',
        'plan': plan,
        'observation': observation,
        'expected': {'status': 'invalid_environment',
                     'failed_checks': ['response_nonce_mismatch'],
                     'sample_path_qualified': False,
                     'authorized': False},
    })
    plan, observation = _base_material()
    observation['checks']['running_egress_contained']['value'] = None
    cases.append({
        'name': 'host_unknown',
        'plan': plan,
        'observation': observation,
        'expected': {'status': 'underdetermined',
                     'unknown_checks': ['running_egress_contained'],
                     'sample_path_qualified': False,
                     'authorized': False},
    })
    plan, observation = _base_material()
    observation['run_id'] = 'different-run'
    cases.append({
        'name': 'binding_changed',
        'plan': plan,
        'observation': observation,
        'expected_error': 'interception_binding_changed:run_id',
    })
    plan, observation = _base_material()
    observation['checks']['blocked_before_interception']['evidence_refs'] = []
    cases.append({
        'name': 'evidence_missing',
        'plan': plan,
        'observation': observation,
        'expected_error':
            'interception_check_evidence_missing:blocked_before_interception',
    })
    plan, observation = _base_material()
    plan['required_control_ports'] = [0]
    cases.append({
        'name': 'invalid_ports',
        'plan': plan,
        'observation': observation,
        'expected_error': 'interception_control_ports_invalid',
    })
    return tuple(cases)


CONTRACT_CASES = _contract_cases()
