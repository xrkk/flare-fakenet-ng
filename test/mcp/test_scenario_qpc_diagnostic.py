"""Synthetic exact native target matching; no developer-machine Logs input."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).parent / 'acceptance'
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('scenario_qpc_diagnostic',
                                               HERE / 'scenario_qpc_diagnostic.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def event(kind, terminal, offset):
    return {'kind': kind, 'terminal': terminal, 'tcb': '0X1234',
            'text': f'x::2026-09-23 15:23:52.{offset:09d}',
            'ref': {'path': 'pktmon.txt', 'byte_start': offset,
                    'byte_end': offset + 1, 'event_key': 'text'}}


def pair_row(e, seq, payload=None):
    stamp = module.raw_clock.pktmon_filetime(e['text'].split('::')[1] + '+08:00')
    raw = payload if payload is not None else b'x' + (0x1234).to_bytes(8, 'little')
    return dict(seq=seq, default_filetime_100ns=stamp,
                provider=module.TCPIP_PROVIDER, identity_occurrences=1,
                userdata_base64=base64.b64encode(raw).decode(),
                raw_timestamp=1000 + seq, id=1033 + seq, version=1,
                opcode=0, task=1033 + seq, userdata_sha256='sha' + str(seq),
                identity_sha256='identity' + str(seq), binding_status='unique')


def observed_and_paired(tmp_path):
    connect, terminal = event('connect completed', False, 100), event('connection terminated', True, 200)
    observed = dict(events=[connect, terminal], connect=connect, peer=None,
                    termination=[terminal], tuple_terminals=[])
    paired = tmp_path / 'paired.jsonl'
    rows = [pair_row(connect, 0), pair_row(terminal, 1)]
    paired.write_text(''.join(json.dumps(x) + '\n' for x in rows))
    return observed, paired, rows


def test_full_terminal_set_selected(tmp_path):
    observed, paired, _ = observed_and_paired(tmp_path)
    targets, selectors = module.choose_targets(observed, paired)
    assert [x['kind'] for x in targets] == ['connect completed', 'connection terminated']
    assert [x['seq'] for x in selectors] == [0, 1]


def test_duplicate_or_missing_terminal_never_counts_complete(tmp_path):
    observed, paired, rows = observed_and_paired(tmp_path)
    paired.write_text(''.join(json.dumps(x) + '\n' for x in rows + [dict(rows[1], seq=2)]))
    with pytest.raises(module.raw_clock.DiagnosticError, match='ambiguous'):
        module.choose_targets(observed, paired)
    paired.write_text(json.dumps(rows[0]) + '\n')
    with pytest.raises(module.raw_clock.DiagnosticError, match='missing'):
        module.choose_targets(observed, paired)


def test_payload_change_cannot_match_selected_tcb(tmp_path):
    observed, paired, rows = observed_and_paired(tmp_path)
    rows[1] = pair_row(observed['termination'][0], 1, b'not-the-selected-tcb')
    paired.write_text(''.join(json.dumps(x) + '\n' for x in rows))
    with pytest.raises(module.raw_clock.DiagnosticError, match='missing'):
        module.choose_targets(observed, paired)


def test_tdh_wrong_tcb_rejected():
    target = dict(kind='connect completed', terminal=False, tcb='0X1234', local=None, remote=None,
                  pktmon_ref={'path': 'pktmon.txt', 'byte_start': 1})
    def prop(name, raw):
        return dict(name=name, size_status=0, property_status=0,
                    raw_base64=base64.b64encode(raw).decode())
    record = dict(selector=dict(pktmon_ref=target['pktmon_ref'], tcb='0X1234',
                                target_kind='connect completed'),
                  record=dict(provider=module.TCPIP_PROVIDER, id=1033, task=1033,
                              version=1, opcode=0),
                  tdh=dict(parsed=dict(provider_guid=module.TCPIP_PROVIDER,
                      event_descriptor_bytes=module._DIALECT['connect completed'][2],
                      strings=dict(task='TcpConnectTcbComplete', provider='Microsoft-Windows-TCPIP'))),
                  property_results=[prop('Tcb', (0x1234).to_bytes(8, 'little')),
                                    prop('Status', b'\0' * 4),
                                    prop('ProcessId', (1572).to_bytes(4, 'little')),
                                    prop('ProcessStartKey', (1).to_bytes(8, 'little'))])
    assert module.validate_tdh_semantics([record], [target], '0X1234', None, 1572, 8024)['target_count'] == 1
    record['property_results'][0] = prop('Tcb', (0x5678).to_bytes(8, 'little'))
    with pytest.raises(module.raw_clock.DiagnosticError, match='Tcb'):
        module.validate_tdh_semantics([record], [target], '0X1234', None, 1572, 8024)


def _chain():
    target = dict(kind='connect completed', terminal=False, tcb='0X1234',
                  local=None, remote=None, pktmon_ref={'byte_start': 1})
    def prop(name, value):
        return dict(name=name, size_status=0, property_status=0,
                    raw_base64=base64.b64encode(value).decode())
    def row(t, pid, start):
        kind = t['kind']; event_id, version, descriptor, task = module._DIALECT[kind]
        return dict(selector=dict(pktmon_ref=t['pktmon_ref'], tcb=t['tcb'], target_kind=kind),
                    record=dict(provider=module.TCPIP_PROVIDER, id=event_id,
                                task=event_id, version=version, opcode=0),
                    tdh=dict(parsed=dict(provider_guid=module.TCPIP_PROVIDER,
                        event_descriptor_bytes=descriptor,
                        strings=dict(provider='Microsoft-Windows-TCPIP', task=task))),
                    property_results=[prop('Tcb', (0x1234).to_bytes(8, 'little')),
                                      *([prop('Status', b'\0' * 4)] if kind == 'connect completed' else []),
                                      prop('ProcessId', pid.to_bytes(4, 'little')),
                                      prop('ProcessStartKey', start.to_bytes(8, 'little'))])
    close = dict(target, kind='close issued', terminal=True, pktmon_ref={'byte_start': 2})
    return [target, close], [row(target, 1572, 123), row(close, 0, 0)], prop


def test_unattributed_close_retained_and_zero_establishment_rejected():
    targets, records, prop = _chain()
    assert module.validate_tdh_semantics(records, targets, '0X1234', None, 1572, 8024) == {
        'target_count': 2, 'process_start_keys': {'0X1234': (123).to_bytes(8, 'little').hex()}}
    records[0]['property_results'][-1] = prop('ProcessStartKey', b'\0' * 8)
    with pytest.raises(module.raw_clock.DiagnosticError, match='establishment ProcessStartKey'):
        module.validate_tdh_semantics(records, targets, '0X1234', None, 1572, 8024)


def test_changed_identity_wrong_descriptor_and_missing_terminal_rejected():
    targets, records, prop = _chain()
    changed = copy.deepcopy(records)
    changed[1]['property_results'][-2:] = [prop('ProcessId', (1572).to_bytes(4, 'little')),
                                            prop('ProcessStartKey', (124).to_bytes(8, 'little'))]
    with pytest.raises(module.raw_clock.DiagnosticError, match='changed within TCB'):
        module.validate_tdh_semantics(changed, targets, '0X1234', None, 1572, 8024)
    wrong = copy.deepcopy(records)
    wrong[1]['record']['task'] = 1044
    with pytest.raises(module.raw_clock.DiagnosticError, match='descriptor/task'):
        module.validate_tdh_semantics(wrong, targets, '0X1234', None, 1572, 8024)
    with pytest.raises(module.raw_clock.DiagnosticError, match='missing/duplicate'):
        module.validate_tdh_semantics(records[:1], targets, '0X1234', None, 1572, 8024)


def _twelve():
    """Small, self-contained shape of the two-owner Win10 TDH lifecycle."""
    roles = [
        ('connect completed', '0X1234', None, 1572, 123),
        ('accept completed', '0X5678', None, 8024, 124),
        ('connection terminated', '0X5678', None, None, None),
        ('shutdown initiated', '0X5678', None, 8024, 124),
        ('transition', '0X5678', ('Established', 'Closed'), None, None),
        ('close issued', '0X5678', None, 0, 0),
        ('transition', '0X1234', ('Established', 'FinWait1'), None, None),
        ('connection terminated', '0X1234', None, None, None),
        ('shutdown initiated', '0X1234', None, 1572, 123),
        ('transition', '0X1234', ('FinWait1', 'Closed'), None, None),
        ('disconnect completed', '0X1234', None, 0, 0),
        ('close issued', '0X1234', None, 0, 0),
    ]
    def prop(name, raw):
        return dict(name=name, size_status=0, property_status=0,
                    raw_base64=base64.b64encode(raw).decode())
    targets, records = [], []
    states = module._OBSERVED_STATES
    for index, (kind, tcb, pair, pid, start) in enumerate(roles):
        ref = {'path': 'pktmon.txt', 'byte_start': index, 'byte_end': index + 1,
               'event_key': 'text'}
        local = '192.0.2.1:1234' if tcb == '0X1234' else '198.51.100.1:443'
        remote = '198.51.100.1:443' if tcb == '0X1234' else '192.0.2.1:1234'
        if kind == 'transition':
            local = remote = None
        target = dict(kind=kind, tcb=tcb, terminal=index >= 2,
                      transition=pair, local=local, remote=remote, pktmon_ref=ref)
        event_id, version, descriptor, task = module._DIALECT[kind]
        properties = [prop('Tcb', int(tcb, 16).to_bytes(8, 'little'))]
        if local:
            properties += [prop('LocalAddress', module._sockaddr(local).ljust(16, b'\0')),
                           prop('RemoteAddress', module._sockaddr(remote).ljust(16, b'\0'))]
        if kind in ('connect completed', 'accept completed'):
            properties.append(prop('Status', b'\0' * 4))
        if kind == 'connection terminated':
            properties.append(prop('NewState', b'\0' * 4))
        if pair:
            properties += [prop('OldState', states[pair[0]].to_bytes(4, 'little')),
                           prop('NewState', states[pair[1]].to_bytes(4, 'little'))]
        if pid is not None:
            properties += [prop('ProcessId', pid.to_bytes(4, 'little')),
                           prop('ProcessStartKey', start.to_bytes(8, 'little'))]
        record = dict(selector=dict(pktmon_ref=ref, tcb=tcb, target_kind=kind),
                      record=dict(provider=module.TCPIP_PROVIDER, id=event_id,
                                  task=event_id, version=version, opcode=0),
                      tdh=dict(parsed=dict(provider_guid=module.TCPIP_PROVIDER,
                          event_descriptor_bytes=descriptor,
                          strings=dict(task=task, provider='Microsoft-Windows-TCPIP'))),
                      property_results=properties)
        targets.append(target); records.append(record)
    return targets, records, prop


def test_verified_twelve_event_lifecycle_and_finwait_fail_closed():
    targets, records, prop = _twelve()
    result = module.validate_tdh_semantics(records, targets, '0X1234', '0X5678', 1572, 8024)
    assert result['target_count'] == 12
    assert len(result['process_start_keys']) == 2
    wrong = copy.deepcopy(records)
    row = next(p for p in wrong[6]['property_results'] if p['name'] == 'NewState')
    row.update(prop('NewState', (6).to_bytes(4, 'little')))
    with pytest.raises(module.raw_clock.DiagnosticError, match='transition state'):
        module.validate_tdh_semantics(wrong, targets, '0X1234', '0X5678', 1572, 8024)
    wrong = copy.deepcopy(records)
    wrong[10]['record']['task'] = 1038
    with pytest.raises(module.raw_clock.DiagnosticError, match='descriptor/task'):
        module.validate_tdh_semantics(wrong, targets, '0X1234', '0X5678', 1572, 8024)


def test_twelve_event_identity_terminal_and_endpoint_negatives():
    targets, records, prop = _twelve()
    wrong = copy.deepcopy(records)
    next(p for p in wrong[0]['property_results'] if p['name'] == 'ProcessId').update(
        prop('ProcessId', b'\0' * 4))
    with pytest.raises(module.raw_clock.DiagnosticError, match='establishment process'):
        module.validate_tdh_semantics(wrong, targets, '0X1234', '0X5678', 1572, 8024)
    wrong = copy.deepcopy(records)
    next(p for p in wrong[8]['property_results'] if p['name'] == 'ProcessStartKey').update(
        prop('ProcessStartKey', (125).to_bytes(8, 'little')))
    with pytest.raises(module.raw_clock.DiagnosticError, match='changed within TCB'):
        module.validate_tdh_semantics(wrong, targets, '0X1234', '0X5678', 1572, 8024)
    wrong = copy.deepcopy(records)
    next(p for p in wrong[10]['property_results'] if p['name'] == 'RemoteAddress').update(
        prop('RemoteAddress', module._sockaddr('192.0.2.2:1234').ljust(16, b'\0')))
    with pytest.raises(module.raw_clock.DiagnosticError, match='RemoteAddress'):
        module.validate_tdh_semantics(wrong, targets, '0X1234', '0X5678', 1572, 8024)
    with pytest.raises(module.raw_clock.DiagnosticError, match='missing/duplicate'):
        module.validate_tdh_semantics(records[:-1], targets, '0X1234', '0X5678', 1572, 8024)
