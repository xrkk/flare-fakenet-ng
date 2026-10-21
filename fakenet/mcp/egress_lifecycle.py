"""Read-only before/running/after acceptance, never lifecycle authorization."""
from __future__ import annotations

from datetime import datetime
import ipaddress
from collections.abc import Mapping

from fakenet.mcp import egress_contract


def evaluate_lifecycle(before, running, after):
    failed, unknown = [], []
    records = (before, running, after)
    if not all(isinstance(value, Mapping) for value in records):
        return {'verdict': 'unknown', 'failed': [], 'unknown': ['phase_records_missing'], 'authorized': False}
    for phase, record in zip(('before', 'running', 'after'), records):
        if record.get('phase') != phase or not record.get('evidence_refs'):
            unknown.append(phase + '_evidence')
        if record.get('second_blocker_used') is True:
            failed.append(phase + '_second_blocker_used')
        elif record.get('second_blocker_used') is not False:
            unknown.append(phase + '_blocker_provenance')
    for key in ('vm_epoch', 'network_identity', 'execution_context_identity', 'endpoint'):
        values = [record.get(key) for record in records]
        if any(value in (None, '', {}) for value in values):
            unknown.append(key)
        elif any(value != values[0] for value in values):
            unknown.append(key + '_changed')
    try:
        endpoint = before['endpoint']
        if not ipaddress.ip_address(endpoint['address']).is_global or type(endpoint['port']) is not int or not 1 <= endpoint['port'] <= 65535:
            unknown.append('public_endpoint_invalid')
    except (ValueError, KeyError, TypeError):
        unknown.append('public_endpoint_missing')
    try:
        stamps = [(datetime.fromisoformat(record['started_at'].replace('Z', '+00:00')).timestamp(),
                   datetime.fromisoformat(record['ended_at'].replace('Z', '+00:00')).timestamp()) for record in records]
        if not stamps[0][0] <= stamps[0][1] <= stamps[1][0] <= stamps[1][1] <= stamps[2][0] <= stamps[2][1]:
            unknown.append('phase_order')
    except (KeyError, ValueError, AttributeError, TypeError):
        unknown.append('phase_timestamps')
    for phase, record in (('before', before), ('after', after)):
        if record.get('engine_state') != 'stopped' or record.get('run_id') is not None:
            unknown.append(phase + '_engine_state')
        connected = record.get('connected')
        if connected is False:
            failed.append(phase + '_connectivity')
        elif connected is not True or record.get('peer') != record.get('endpoint'):
            unknown.append(phase + '_connectivity')
    result = running.get('verification') or {}
    if result.get('authorized') is not False:
        unknown.append('running_authorization_marker')
    try:
        helper = result['helper_input']
        qualified = egress_contract.evaluate_interception_qualification(helper['plan'], helper['observation'])
        if result.get('contract_version') != egress_contract.CONTRACT_VERSION or result.get('phase') != 'running':
            unknown.append('running_contract')
        elif result.get('verdict') == 'fail' or qualified['failed_checks']:
            failed.append('running_interception')
        elif result.get('verdict') != 'pass' or not qualified['sample_path_qualified'] or not result.get('coverage', {}).get('completeness', {}).get('complete'):
            unknown.append('running_interception')
    except (KeyError, TypeError, egress_contract.EgressContractError):
        unknown.append('running_evidence')
    return {'verdict': 'fail' if failed else 'unknown' if unknown else 'pass',
            'failed': failed, 'unknown': unknown, 'authorized': False,
            'scope': 'same approved endpoint and VM before/running/after; no universal Internet claim'}
