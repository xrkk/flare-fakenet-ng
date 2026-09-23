"""Offline guardrails for the unverified auxiliary zero-TCB collector."""
import copy
import base64
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_aux_qpc_diagnostic as aux  # noqa: E402


def ref(index):
    return {'path': 'pktmon.txt', 'byte_start': index,
            'byte_end': index + 1, 'event_key': 'text'}


def order_case(connect=100, peer=105, zeros=(106, 107)):
    events = [dict(pktmon_ref=ref(1)), dict(pktmon_ref=ref(2))]
    events += [dict(pktmon_ref=ref(10 + index)) for index in range(len(zeros))]
    selectors = [dict(raw_qpc=value) for value in (connect, peer, *zeros)]
    observed = {'connect': {'ref': ref(1)}, 'peer': {'ref': ref(2)},
                'tuple_terminals': [{'ref': ref(10 + index)}
                                    for index in range(len(zeros))]}
    return observed, events, selectors


@pytest.mark.parametrize('zeros,expected', [((107, 108), True),
                                             ((106, 108), False),
                                             ((105, 108), False),
                                             ((104, 108), False),
                                             ((), False)])
def test_raw_order_is_diagnostic_only_and_requires_every_zero_tcb(zeros, expected):
    observed, targets, selectors = order_case(zeros=zeros)
    result = aux.diagnostic_order(observed, targets, selectors)
    assert result['status'] == 'UNVERIFIED_TDH_SEMANTICS'
    assert result['all_strictly_later_than_one_tick'] is expected
    assert len(result['gaps_ticks']) == len(zeros)


def test_missing_zero_tcb_selector_is_not_an_order_result():
    observed, targets, selectors = order_case()
    targets.pop()
    selectors.pop()
    with pytest.raises(aux.raw_clock.DiagnosticError, match='zero-TCB target omitted'):
        aux.diagnostic_order(observed, targets, selectors)


def test_duplicate_case_identity_fails_before_windows_export(tmp_path, monkeypatch):
    source = tmp_path / 'input.json'
    data = {'schema': 'sst.aux-qpc-input.v1', 'cases': [
        {'case_index': 2, 'connection_id': 'c'},
        {'case_index': 2, 'connection_id': 'c'}]}
    source.write_text(json.dumps(data), encoding='utf-8')
    monkeypatch.setattr(aux.raw_clock, 'export', lambda *_: pytest.fail('Windows export reached'))
    result = aux.run(source, tmp_path, tmp_path / 'out')
    assert result['status'] == 'INCOMPLETE'
    assert 'duplicate auxiliary case identity' in result['error']['message']
    assert result['inputs_before'] == result['inputs_after']
    assert list(result['inputs_before']) == [str(source)]


def test_auxiliary_identity_requires_matching_boot_frequency_and_capture_brackets():
    from test_scenario_qpc_identity import evidence
    args = evidence()
    capture, ready, child, established, _action, header, candidate, managed_run, pid, created = args
    capture['clock_before'].update(q0=1, q1=2)
    capture['clock_after'].update(q0=3, q1=4)
    result = aux.check_aux_provenance(capture, ready, child, established,
                                      header, candidate, managed_run, pid, created)
    assert result['qpc_frequency'] == 10_000_000
    wrong = copy.deepcopy(capture)
    wrong['native_identity_after']['qpc_frequency'] = 9
    with pytest.raises(aux.check_aux_provenance.__globals__['DiagnosticIdentityError']):
        aux.check_aux_provenance(wrong, ready, child, established,
                                 header, candidate, managed_run, pid, created)


def test_ambiguous_raw_identity_expands_both_timestamps_for_each_zero_ref(tmp_path):
    def event(kind, tcb, suffix, offset, terminal=False):
        return {'kind': kind, 'tcb': tcb, 'terminal': terminal,
                'text': f'x::2026-09-23 15:23:52.{suffix:09d}',
                'ref': ref(offset), 'local': None, 'remote': None}
    connect = event('connect completed', '0X1234', 100, 1)
    terminal = event('connection terminated', '0X1234', 200, 2, True)
    zero_a = event('unattributed_tuple_terminal', '0X0', 300, 3, True)
    zero_b = event('unattributed_tuple_terminal', '0X0', 400, 4, True)
    observed = {'events': [connect, terminal], 'connect': connect, 'peer': None,
                'termination': [terminal], 'tuple_terminals': [zero_a, zero_b]}
    def paired(event, seq, identity, occurrences, payload, *, provider=None):
        stamp = aux.raw_clock.pktmon_filetime(event['text'].split('::')[1] + '+08:00')
        return {'seq': seq, 'provider': provider or aux.qpc.TCPIP_PROVIDER,
                'default_filetime_100ns': stamp, 'identity_sha256': identity,
                'identity_occurrences': occurrences,
                'binding_status': 'ambiguous' if occurrences > 1 else 'unique',
                'userdata_base64': base64.b64encode(payload).decode(),
                'userdata_sha256': 'data-' + str(seq), 'raw_timestamp': 1000 + seq,
                'id': 1479, 'version': 0, 'opcode': 0, 'task': 1466}
    rows = [paired(connect, 0, 'named-a', 1, (0x1234).to_bytes(8, 'little')),
            paired(terminal, 1, 'named-b', 1, (0x1234).to_bytes(8, 'little')),
            paired(zero_a, 2, 'zero-twin', 2, b'zero'),
            paired(zero_b, 3, 'zero-twin', 2, b'zero'),
            paired(zero_a, 4, 'foreign', 1, b'foreign', provider='other-provider')]
    path = tmp_path / 'paired.jsonl'
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
    with pytest.raises(aux.raw_clock.DiagnosticError, match='missing/ambiguous'):
        aux.qpc.choose_targets(observed, path)
    targets, named, sets, candidate_selectors = aux.diagnostic_candidates(observed, path)
    assert [row['seq'] for row in named] == [0, 1]
    assert len(targets) == 2
    assert [row['pktmon_ref'] for row in sets] == [ref(3), ref(4)]
    assert [[item['seq'] for item in row['candidates']] for row in sets] == [[2, 3], [2, 3]]
    assert [item['seq'] for item in candidate_selectors] == [2, 3]
    assert all(row['status'] == 'DIAGNOSTIC_CANDIDATES_UNRESOLVED' for row in sets)
    assert all(item['diagnostic_candidate_refs'] == [ref(3), ref(4)]
               for item in candidate_selectors)


def test_zero_tcb_candidate_identity_group_must_be_complete(tmp_path):
    path = tmp_path / 'paired.jsonl'
    observed, _, _ = order_case()
    observed['connect'].update(kind='connect completed', tcb='0X1', terminal=False,
                               text='x::2026-09-23 15:23:52.000000100')
    observed['peer'] = None
    end = {'ref': ref(2), 'kind': 'connection terminated', 'tcb': '0X1',
           'terminal': True, 'text': 'x::2026-09-23 15:23:52.000000200'}
    zero = {'ref': ref(10), 'kind': 'unattributed_tuple_terminal', 'tcb': '0X0',
            'terminal': True, 'text': 'x::2026-09-23 15:23:52.000000300'}
    observed.update(events=[observed['connect'], end], termination=[end],
                    tuple_terminals=[zero])
    def row(event, seq, identity, count, payload):
        return {'seq': seq, 'provider': aux.qpc.TCPIP_PROVIDER,
                'default_filetime_100ns': aux.raw_clock.pktmon_filetime(
                    event['text'].split('::')[1] + '+08:00'),
                'identity_sha256': identity, 'identity_occurrences': count,
                'binding_status': 'ambiguous' if count > 1 else 'unique',
                'userdata_base64': base64.b64encode(payload).decode(),
                'userdata_sha256': str(seq), 'raw_timestamp': seq,
                'id': 1, 'version': 0, 'opcode': 0, 'task': 1}
    path.write_text(''.join(json.dumps(x) + '\n' for x in [
        row(observed['connect'], 0, 'a', 1, b'\x01' + (1).to_bytes(8, 'little')),
        row(end, 1, 'b', 1, b'\x02' + (1).to_bytes(8, 'little')),
        row(zero, 2, 'z', 2, b'zero')]), encoding='utf-8')
    with pytest.raises(aux.raw_clock.DiagnosticError, match='group count'):
        aux.diagnostic_candidates(observed, path)


def test_incomplete_export_still_sends_every_ambiguous_candidate_to_tdh(tmp_path, monkeypatch):
    import hashlib
    root = tmp_path / 'evidence'
    root.mkdir()
    probe_rows = [dict(event='ready', nonce='n', pid=7),
                  dict(event='case_established', nonce='n', case_index=2,
                       connection_id='c2', pid=7, src='1.1.1.1:1000', actual_dst='2.2.2.2:443'),
                  dict(event='case_close', nonce='n', connection_id='c2', pid=7)]
    probe = ''.join(json.dumps(row) + '\n' for row in probe_rows).encode()
    blobs = {'probe.jsonl': probe, 'pktmon.txt': b'native-text', 'pktmon.etl': b'etl',
             'pktmon-nic.json': b'{}', 'run.log': b'log', 'ipc-parent.jsonl': b'{}\n'}
    for name, raw in blobs.items():
        (root / name).write_bytes(raw)
    refs = []
    start = 0
    for line in probe.splitlines(keepends=True):
        refs.append({'path': 'probe.jsonl', 'byte_start': start,
                     'byte_end': start + len(line), 'event_key': 'json:'})
        start += len(line)
    def event(kind, tcb, time, offset, terminal):
        return {'kind': kind, 'tcb': tcb, 'terminal': terminal,
                'text': f'x::2026-09-23 15:23:52.{time:09d}',
                'ref': ref(offset), 'local': None, 'remote': None}
    connect = event('connect completed', '0X1234', 100, 1, False)
    end = event('connection terminated', '0X1234', 200, 2, True)
    zero_a = event('unattributed_tuple_terminal', '0X0', 300, 3, True)
    zero_b = event('unattributed_tuple_terminal', '0X0', 400, 4, True)
    observed = {'events': [connect, end], 'connect': connect, 'peer': None,
                'termination': [end], 'tuple_terminals': [zero_a, zero_b],
                'generation_manifest': [{'tcb': '0X1234'}]}
    descriptor = {'schema': 'sst.aux-qpc-input.v1', 'candidate_id': 'candidate',
                  'run_id': 'run', 'nonce': 'n',
                  'files': [{'path': name, 'bytes': len(raw),
                             'sha256': hashlib.sha256(raw).hexdigest()}
                            for name, raw in blobs.items()],
                  'capture': {'etl_path': 'pktmon.etl', 'text_path': 'pktmon.txt',
                              'metadata_ref': {'path': 'pktmon-nic.json', 'byte_start': 0,
                                               'byte_end': 2, 'event_key': 'json:'}},
                  'run_log_path': 'run.log', 'ipc_path': 'ipc-parent.jsonl',
                  'cases': [{'case_index': 2, 'connection_id': 'c2', 'pid': 7,
                             'src': '1.1.1.1:1000', 'dst': '2.2.2.2:443',
                             'probe_ref': refs[1], 'end_refs': [refs[2]],
                             'connection_refs': [connect['ref'], end['ref']],
                             'tuple_terminal_refs': [zero_a['ref'], zero_b['ref']],
                             'generation_manifest': observed['generation_manifest']}]}
    case_path = root / 'case.json'
    case_path.write_text(json.dumps(descriptor), encoding='utf-8')
    monkeypatch.setattr(aux.tcpip, 'validate_capture', lambda *args: None)
    monkeypatch.setattr(aux.tcpip, 'managed_identity', lambda *args: (50, 100))
    monkeypatch.setattr(aux.tcpip, 'validate_tuple_probe', lambda *args: None)
    monkeypatch.setattr(aux.tcpip, 'connection_events', lambda *args, **kwargs: observed)
    monkeypatch.setattr(aux, 'check_aux_provenance', lambda *args: {'boot': 'diagnostic'})
    def row(event, seq, identity, count, payload):
        return {'seq': seq, 'provider': aux.qpc.TCPIP_PROVIDER,
                'default_filetime_100ns': aux.raw_clock.pktmon_filetime(
                    event['text'].split('::')[1] + '+08:00'),
                'identity_sha256': identity, 'identity_occurrences': count,
                'binding_status': 'ambiguous' if count > 1 else 'unique',
                'userdata_base64': base64.b64encode(payload).decode(),
                'userdata_sha256': str(seq), 'raw_timestamp': 1000 + seq,
                'id': 1479, 'version': 0, 'opcode': 0, 'task': 1466}
    paired_rows = [row(connect, 0, 'a', 1, (0x1234).to_bytes(8, 'little')),
                   row(end, 1, 'b', 1, (0x1234).to_bytes(8, 'little')),
                   row(zero_a, 2, 'z', 2, b'zero'), row(zero_b, 3, 'z', 2, b'zero')]
    def fake_raw(etl, output):
        output.mkdir()
        (output / 'paired.jsonl').write_text(''.join(json.dumps(row) + '\n'
                                                  for row in paired_rows), encoding='utf-8')
        return {'paired_events': 4, 'input_before': {'sha256': hashlib.sha256(b'etl').hexdigest()},
                'passes': [{'header': {}}]}
    monkeypatch.setattr(aux.raw_clock, 'export', fake_raw)
    observed_selectors = []
    def fake_tdh(etl, selectors_path, output):
        selectors = json.loads(selectors_path.read_text())['selectors']
        observed_selectors.extend(selectors)
        assert sorted(item['seq'] for item in selectors) == [0, 1, 2, 3]
        assert [item['diagnostic_candidate_refs'] for item in selectors if item['seq'] in (2, 3)] == [
            [ref(3), ref(4)], [ref(3), ref(4)]]
        output.mkdir()
        (output / 'metadata.jsonl').write_text(''.join(
            json.dumps({'selector': item}) + '\n' for item in selectors))
        return {'target_count': len(selectors)}
    monkeypatch.setattr(aux.tdh_metadata, 'run', fake_tdh)
    monkeypatch.setattr(aux, 'candidate_field_facts',
                        lambda rows, groups, selected: [{'diagnostic_rows': len(rows),
                                                          'candidate_groups': len(groups)}])
    result = aux.run(case_path, root, tmp_path / 'output')
    assert len(observed_selectors) == 4
    assert result['status'] == 'INCOMPLETE'
    assert 'no verified unique TDH binding' in result['error']['message']
    assert [len(row['candidates']) for row in result['candidate_sets']] == [2, 2]
    assert result['candidate_field_facts'] == [{'diagnostic_rows': 4,
                                                'candidate_groups': 2}]
    assert result['inputs_before'] == result['inputs_after']


def candidate_tdh_fixture():
    selector = {'seq': 7, 'target_kind': 'auxiliary_zero_tcb_diagnostic_candidate'}
    local, remote = '192.168.204.233:50127', '198.51.100.77:1337'
    values = {'Tcb': b'\0' * 8, 'IPTransportProtocol': (6).to_bytes(4, 'little'),
              'AddressFamily': (2).to_bytes(4, 'little'),
              'LocalSockAddrLength': (16).to_bytes(4, 'little'),
              'RemoteSockAddrLength': (16).to_bytes(4, 'little'),
              'LocalSockAddr': aux.qpc._sockaddr(local).ljust(16, b'\0'),
              'RemoteSockAddr': aux.qpc._sockaddr(remote).ljust(16, b'\0'),
              'Reason': b'\0' * 4}
    props = []
    results = []
    for name, value in values.items():
        props.append({'name': name, 'flags': 2 if name.endswith('SockAddr') else 0,
                      'in_type_or_struct_start': 14 if name.endswith('SockAddr') else 8,
                      'out_type_or_struct_members': 25 if name.endswith('SockAddr') else 8,
                      'map_or_schema_offset': 100 if name == 'Reason' else 0})
        results.append({'name': name, 'size_status': 0, 'property_status': 0,
                        'raw_base64': base64.b64encode(value).decode()})
    blob = bytearray(256)
    name = aux.ZERO_TCB_REASON_MAP.encode('utf-16-le') + b'\0\0'
    blob[100:100 + len(name)] = name
    row = {'selector': selector,
           'record': {'provider': aux.qpc.TCPIP_PROVIDER, 'id': 1479,
                      'version': 0, 'opcode': 0, 'task': 1466},
           'tdh': {'parsed': {'provider_guid': aux.qpc.TCPIP_PROVIDER,
                              'event_descriptor_bytes': aux.ZERO_TCB_DESCRIPTOR,
                              'strings': {'provider': 'Microsoft-Windows-TCPIP',
                                          'task': 'TcpRstSend'},
                              'properties': props},
                   'buffer_base64': base64.b64encode(blob).decode()},
           'property_results': results}
    group = {'local': local, 'remote': remote, 'candidates': [{'seq': 7}]}
    return row, group, selector


def test_verified_candidate_field_bytes_still_do_not_prove_reason_label():
    row, group, selector = candidate_tdh_fixture()
    facts = aux.candidate_field_facts([row], [group], [selector])
    assert facts[0]['status'] == 'REASON_MAP_NOT_CAPTURED'
    opaque = b'opaque-event-map!'
    next(x for x in row['property_results'] if x['name'] == 'Reason')['event_map'] = {
        'name': aux.ZERO_TCB_REASON_MAP, 'first_status': 122, 'second_status': 0,
        'buffer_base64': base64.b64encode(opaque).decode(),
        'buffer_sha256': hashlib.sha256(opaque).hexdigest()}
    facts = aux.candidate_field_facts([row], [group], [selector])
    assert facts[0]['status'] == 'REASON_MAP_OPAQUE_UNVERIFIED'
    next(x for x in row['property_results'] if x['name'] == 'Reason')['event_map'][
        'buffer_sha256'] = '0' * 64
    assert aux.candidate_field_facts([row], [group], [selector])[0][
        'status'] == 'REASON_MAP_NOT_CAPTURED'


@pytest.mark.parametrize('mutation,reason', [
    ('provider', 'provider/descriptor/task'), ('descriptor', 'provider/descriptor/task'),
    ('tcb', 'property differs: Tcb'), ('reason', 'property differs: Reason'),
    ('endpoint', 'property differs: LocalSockAddr'),
    ('sockaddr_type', 'SockAddr type'), ('map_name', 'Reason map name'),
    ('property_status', 'property missing/ambiguous')])
def test_candidate_field_corruption_rejected(mutation, reason):
    row, group, selector = candidate_tdh_fixture()
    result = {x['name']: x for x in row['property_results']}
    metadata = {x['name']: x for x in row['tdh']['parsed']['properties']}
    if mutation == 'provider': row['record']['provider'] = 'other'
    elif mutation == 'descriptor': row['tdh']['parsed']['event_descriptor_bytes'] = '00' * 16
    elif mutation == 'tcb': result['Tcb']['raw_base64'] = base64.b64encode((1).to_bytes(8, 'little')).decode()
    elif mutation == 'reason': result['Reason']['raw_base64'] = base64.b64encode((1).to_bytes(4, 'little')).decode()
    elif mutation == 'endpoint': result['LocalSockAddr']['raw_base64'] = base64.b64encode(b'X' * 16).decode()
    elif mutation == 'sockaddr_type': metadata['LocalSockAddr']['in_type_or_struct_start'] = 99
    elif mutation == 'map_name': metadata['Reason']['map_or_schema_offset'] = 0
    elif mutation == 'property_status': result['Reason']['property_status'] = 1168
    with pytest.raises(aux.raw_clock.DiagnosticError, match=reason):
        aux.candidate_field_facts([row], [group], [selector])
