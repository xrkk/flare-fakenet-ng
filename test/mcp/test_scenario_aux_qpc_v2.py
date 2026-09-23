"""Single-callback zero-TCB collection and the new multiset clock gate."""
import ctypes as C
import hashlib
import json
from pathlib import Path
import sys
import uuid

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import etl_raw_clock as raw  # noqa: E402
import scenario_aux_qpc_single_pass as single  # noqa: E402
import scenario_aux_qpc_v2 as v2  # noqa: E402
from test_scenario_aux_qpc_formal import strict_fixture  # noqa: E402

SRC, DST = '192.168.204.233:50127', '198.51.100.77:1337'


def zero_row(seq, qpc):
    row, _, _ = strict_fixture()
    row['selector'] = {'seq': seq, 'raw_qpc': qpc}
    row['record']['timestamp'] = qpc
    return row


def observed(count=2):
    return {'tuple_terminals': [{'local': SRC, 'remote': DST,
             'ref': {'path': 'pktmon.txt', 'byte_start': i, 'byte_end': i + 1}}
            for i in range(count)]}


def test_identical_non_time_records_retain_both_native_instants():
    result = v2.adjudicate_zeros([zero_row(7, 110), zero_row(8, 120)],
                                 observed(), SRC, DST, 100, 99, 130)
    assert result == {'zero_seqs': [7, 8], 'zero_qpc': [110, 120],
                      'native_refs': [None, None],
                      'gaps_ticks': [10, 20], 'zero_constraint': 'VERIFIED',
                      'native_count': 2, 'text_count': 2}
    same_qpc = v2.adjudicate_zeros([zero_row(7, 110), zero_row(8, 110)],
                                   observed(), SRC, DST, 100, 99, 130)
    assert same_qpc['zero_qpc'] == [110, 110] and same_qpc['native_count'] == 2


@pytest.mark.parametrize('change', ['missing_text', 'extra_text', 'wrong_tuple',
                                   'same_qpc', 'one_tick', 'early', 'wrong_descriptor',
                                   'unknown_reason', 'nonzero_tcb', 'outside_capture'])
def test_single_pass_negative_set_is_fail_closed(change):
    rows = [zero_row(7, 110), zero_row(8, 120)]
    view = observed()
    lower, upper = 99, 130
    if change == 'missing_text':
        view = observed(1)
    elif change == 'extra_text':
        view = observed(3)
    elif change == 'wrong_tuple':
        view['tuple_terminals'][0]['remote'] = '198.51.100.78:1337'
    elif change == 'same_qpc':
        rows[1]['record']['timestamp'] = 100
    elif change == 'one_tick':
        rows[1]['record']['timestamp'] = 101
    elif change == 'early':
        rows[1]['record']['timestamp'] = 99
    elif change == 'wrong_descriptor':
        rows[1]['tdh']['parsed']['event_descriptor_bytes'] = '00' * 16
    elif change == 'unknown_reason':
        prop = next(p for p in rows[1]['property_results'] if p['name'] == 'Reason')
        prop['raw_base64'] = 'AQAAAA=='
    elif change == 'nonzero_tcb':
        prop = next(p for p in rows[1]['property_results'] if p['name'] == 'Tcb')
        prop['raw_base64'] = 'AQAAAAAAAAA='
    elif change == 'outside_capture':
        upper = 115
    with pytest.raises(raw.DiagnosticError):
        v2.adjudicate_zeros(rows, view, SRC, DST, 100, lower, upper)


def test_no_zero_is_explicitly_not_applicable():
    result = v2.adjudicate_zeros([], observed(0), SRC, DST, 100, 99, 130)
    assert result['zero_constraint'] == 'NO_ZERO_TCB'
    assert result['native_count'] == result['text_count'] == 0


def test_export_scans_full_stream_and_seals_qpc_with_same_callback_tdh(tmp_path, monkeypatch):
    etl = tmp_path / 'original.etl'
    etl.write_bytes(b'fixed synthetic ETL')
    user = C.create_string_buffer(b'repeated')
    seen = []

    def ptr(qpc, event_id=1479):
        rec = raw.EVENT_RECORD()
        rec.EventHeader.ProviderId = raw.GUID.from_buffer_copy(
            uuid.UUID('2f07e2ee-15db-40f1-90ef-9d7ba282188a').bytes_le)
        rec.EventHeader.EventDescriptor.Id = event_id
        rec.EventHeader.EventDescriptor.Task = 1466
        rec.EventHeader.TimeStamp = qpc
        rec.UserDataLength = 8
        rec.UserData = C.cast(user, C.c_void_p).value
        return C.pointer(rec)

    def decode(pointer, selector, api):
        assert api is sentinel
        record = raw.record_dict(pointer.contents)
        seen.append((id(pointer.contents), record['timestamp'], selector['raw_qpc']))
        return {'selector': selector, 'record': record,
                'tdh': {'second_status': 0}, 'property_results': []}

    sentinel = object()
    monkeypatch.setattr(single.tdh, 'decode_target', decode)
    def walk(path, emit):
        assert path == etl
        for seq, qpc in enumerate((110, 110, 120)):
            emit(ptr(qpc, 100 if seq == 0 else 1479), seq, sentinel)
        return {'header': {'ReservedFlags': 1, 'PerfFreq': 10_000_000,
                'EventsLost': 0, 'BuffersLost': 0, 'PointerSize': 8},
                'events': 3, 'process_trace_return': 0,
                'events_lost_output': 0}
    manifest = single.export(etl, tmp_path / 'export', walk=walk)
    assert manifest['status'] == 'COMPLETE_DIAGNOSTIC_ONLY'
    assert manifest['rst_records'] == 2
    rows = [json.loads(line) for line in
            (tmp_path / 'export/records.jsonl').read_text().splitlines()]
    assert [row['selector']['seq'] for row in rows] == [1, 2]
    assert [row['record']['timestamp'] for row in rows] == [110, 120]
    assert [(qpc, selector_qpc) for _, qpc, selector_qpc in seen] == [(110, 110), (120, 120)]
    indexes = [json.loads(line) for line in
               (tmp_path / 'export/index.jsonl').read_text().splitlines()]
    data = (tmp_path / 'export/records.jsonl').read_bytes()
    assert [ref['seq'] for ref in indexes] == [1, 2]
    for ref in indexes:
        line = data[ref['byte_start']:ref['byte_end']]
        assert hashlib.sha256(line).hexdigest() == ref['sha256']


@pytest.mark.parametrize('change', ['none', 'drop', 'duplicate', 'add', 'byte_ref',
                                    'record', 'clock', 'etl'])
def test_rebuild_checks_complete_single_pass_original_and_byte_refs(tmp_path,
                                                                    monkeypatch, change):
    etl = tmp_path / 'capture.etl'
    etl.write_bytes(b'original ETL')
    export = tmp_path / 'export'
    single_root = export / 'single'
    single_root.mkdir(parents=True)
    record = {'provider': v2.qpc.TCPIP_PROVIDER, 'id': 1479, 'timestamp': 110}
    row = {'record': record, 'selector': {'seq': 2, 'raw_qpc': 110},
           'tdh': {'second_status': 0}, 'property_results': []}
    line = (json.dumps(row, sort_keys=True) + '\n').encode()
    data = line
    index = [{'seq': 2, 'byte_start': 0, 'byte_end': len(line),
              'sha256': hashlib.sha256(line).hexdigest()}]
    if change == 'drop':
        data, index = b'', []
    elif change == 'duplicate':
        data += line
        index.append({**index[0], 'byte_start': len(line), 'byte_end': 2 * len(line)})
    elif change == 'add':
        extra = dict(row, selector={'seq': 3, 'raw_qpc': 110})
        extra_line = (json.dumps(extra, sort_keys=True) + '\n').encode()
        data += extra_line
        index.append({'seq': 3, 'byte_start': len(line),
                      'byte_end': len(data), 'sha256': hashlib.sha256(extra_line).hexdigest()})
    elif change == 'byte_ref':
        index[0]['byte_end'] -= 1
    elif change == 'record':
        altered = dict(row, record=dict(record, id=1480))
        data = (json.dumps(altered, sort_keys=True) + '\n').encode()
        index[0].update(byte_end=len(data), sha256=hashlib.sha256(data).hexdigest())
    elif change == 'etl':
        etl.write_bytes(b'changed ETL')
    (single_root / 'records.jsonl').write_bytes(data)
    (single_root / 'index.jsonl').write_text(''.join(json.dumps(ref) + '\n' for ref in index))
    manifest = {'schema': single.SCHEMA, 'status': 'COMPLETE_DIAGNOSTIC_ONLY',
                'error': None, 'input_before': raw.sha_file(etl),
                'input_after': raw.sha_file(etl), 'rst_records': 1,
                'scan': {'events': 3, 'process_trace_return': 0,
                         'events_lost_output': 0, 'header': {'clock': 'qpc'}}}
    if change == 'etl':
        manifest['input_before'] = manifest['input_after'] = {'bytes': 12, 'sha256': '0' * 64}
    if change == 'clock':
        manifest['scan']['header']['clock'] = 'utc'
    (single_root / 'manifest.json').write_text(json.dumps(manifest))
    monkeypatch.setattr(v2.shared, 'verify_tdh_rows', lambda rows, selectors: None)
    if change == 'none':
        rows, _ = v2._single_rows(export, etl, 3, [record], {'clock': 'qpc'})
        assert rows[0]['record_ref']['sha256'] == index[0]['sha256']
    else:
        with pytest.raises(raw.DiagnosticError):
            v2._single_rows(export, etl, 3, [record], {'clock': 'qpc'})


@pytest.mark.parametrize('failure', ['lost', 'short_count', 'api_error', 'callback'])
def test_export_never_marks_partial_scan_complete(tmp_path, monkeypatch, failure):
    etl = tmp_path / 'original.etl'
    etl.write_bytes(b'fixed synthetic ETL')
    def walk(path, emit):
        if failure == 'callback':
            raise raw.DiagnosticError('TDH failed inside callback')
        return {'header': {'ReservedFlags': 1, 'PerfFreq': 10_000_000,
                'EventsLost': 0, 'BuffersLost': 0, 'PointerSize': 8},
                'events': -1 if failure == 'short_count' else 0,
                'process_trace_return': 5 if failure == 'api_error' else 0,
                'events_lost_output': 1 if failure == 'lost' else 0}
    # Force a count-bearing callback without replacing the export body.
    monkeypatch.setattr(single, 'snapshot', lambda *args: {
        'selector': {'seq': 0}, 'record': {}, 'tdh': {'second_status': 0},
        'property_results': []} if failure == 'short_count' else None)
    if failure == 'short_count':
        original = walk
        def walk(path, emit):
            emit(None, 0, None)
            return original(path, emit)
    result = single.export(etl, tmp_path / failure, walk=walk)
    assert result['status'] == 'INCOMPLETE'
    assert result['error']
