"""Exercise the complete v2 rebuild with a serialized named target graph."""
import base64
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_aux_qpc_v2 as v2  # noqa: E402


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + '\n')


def _fixture(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    export = tmp_path / 'export'
    case_path = tmp_path / 'case.json'
    src, dst = '192.168.204.233:50127', '198.51.100.77:1337'
    connect_ref = {'path': 'text', 'byte_start': 0, 'byte_end': 1}
    terminal_ref = {'path': 'text', 'byte_start': 1, 'byte_end': 2}
    connect = {'kind': 'connect', 'terminal': False, 'tcb': '0X1',
               'local': src, 'remote': dst, 'ref': connect_ref,
               'text': '::2026-09-23 00:00:00.0000000'}
    terminal = {'kind': 'transition', 'terminal': True, 'tcb': '0X1',
                'local': src, 'remote': dst, 'transition': ('Established', 'Closing'),
                'ref': terminal_ref, 'text': '::2026-09-23 00:00:01.0000000'}
    observed = {'events': [connect, terminal], 'connect': connect, 'peer': None,
                'termination': [terminal], 'tuple_terminals': [], 'generation_manifest': []}
    paired = export / 'legacy/raw/paired.jsonl'
    paired.parent.mkdir(parents=True)
    with paired.open('w') as stream:
        for seq, event in enumerate((connect, terminal)):
            stamp = v2.raw.pktmon_filetime(event['text'].split('::')[1] + '+08:00')
            row = {'seq': seq, 'provider': v2.qpc.TCPIP_PROVIDER,
                   'identity_occurrences': 1,
                   'default_filetime_100ns': stamp,
                   'userdata_base64': base64.b64encode(b'\x01' + b'\0' * 7).decode(),
                   'raw_timestamp': 100 + seq * 10,
                   'id': 100 + seq, 'version': 0, 'opcode': 0, 'task': 0,
                   'userdata_sha256': 'a' * 64, 'identity_sha256': 'b' * 64,
                   'binding_status': 'unique'}
            stream.write(json.dumps(row) + '\n')
    targets, selected = v2.qpc.choose_targets(observed, paired)
    for target, selector in zip(targets, selected):
        target.update(run_id='run', case_index=1, connection_id='connection')
        selector.update(run_id='run', case_index=1, connection_id='connection')
    origin = {'event': 'case_established', 'nonce': 'nonce', 'case_index': 1,
              'connection_id': 'connection', 'pid': 7, 'src': src, 'actual_dst': dst}
    ending = {'event': 'case_close', 'nonce': 'nonce', 'pid': 7,
              'connection_id': 'connection'}
    probe = [dict(event='ready', nonce='nonce'), origin, ending]
    case = {'schema': 'sst.aux-qpc-input.v1', 'candidate_id': 'candidate',
            'run_id': 'run', 'nonce': 'nonce',
            'files': [{'path': name} for name in ('etl', 'text', 'log', 'ipc', 'probe')],
            'capture': {'etl_path': 'etl', 'text_path': 'text',
                        'metadata_ref': {'id': 'metadata'}},
            'run_log_path': 'log', 'ipc_path': 'ipc',
            'cases': [{'case_index': 1, 'connection_id': 'connection', 'pid': 7,
                       'src': src, 'dst': dst, 'probe_ref': {'id': 'origin', 'path': 'probe'},
                       'end_refs': [{'id': 'ending'}],
                       'connection_refs': [connect_ref, terminal_ref],
                       'tuple_terminal_refs': [], 'generation_manifest': []}]}
    _write(case_path, case)
    for name in ('etl', 'text', 'log', 'ipc', 'probe'):
        (source / name).parent.mkdir(parents=True, exist_ok=True)
        (source / name).write_bytes(b'fixture\n')
    (source / 'probe').write_text(''.join(json.dumps(row) + '\n' for row in probe))
    (source / 'ipc').write_text('{}\n')
    manifest = {'schema': 'sst.aux-qpc-diagnostic.v1',
                'status': 'COMPLETE_DIAGNOSTIC_ONLY',
                'candidate_binding_status': 'UNIQUE_VERIFIED',
                'targets': json.loads(json.dumps(targets))}
    _write(export / 'legacy/manifest.json', manifest)
    _write(export / 'legacy/selectors.json', {'selectors': selected})
    (export / 'legacy/raw/raw.jsonl').write_text('')
    (export / 'legacy/tdh').mkdir(parents=True)
    (export / 'legacy/tdh/metadata.jsonl').write_text(''.join(
        json.dumps({'selector': selector}) + '\n' for selector in selected))
    for name in ('legacy/raw/manifest.json', 'legacy/raw/default.jsonl',
                 'legacy/tdh/manifest.json', 'single/manifest.json',
                 'single/records.jsonl', 'single/index.jsonl'):
        _write(export / name, {})
    _write(export / 'manifest.json', {'schema': v2.SCHEMA, 'status': 'INCOMPLETE'})

    class Evidence:
        def __init__(self, *_):
            self.data = {name: (source / name).read_bytes()
                         for name in ('etl', 'text', 'log', 'ipc', 'probe')}
        def read(self, ref):
            return {'origin': origin, 'ending': ending, 'metadata': {}}[ref['id']]

    monkeypatch.setattr(v2.fault, 'Evidence', Evidence)
    monkeypatch.setattr(v2.shared, 'verify_case_refs', lambda *_: 1)
    monkeypatch.setattr(v2.shared, 'verify_export', lambda *_: (
        {'selectors': json.loads(json.dumps(selected))}, {'clock': 'qpc'}))
    monkeypatch.setattr(v2.shared, 'verify_tdh_rows', lambda *_: None)
    monkeypatch.setattr(v2, '_single_rows', lambda *_: ([],
        {'scan': {'events': 2}, 'rst_records': 0, 'input_before': v2.raw.sha_file(source / 'etl')}))
    monkeypatch.setattr(v2.tcpip, 'validate_capture', lambda *_: None)
    monkeypatch.setattr(v2.tcpip, 'managed_identity', lambda *_: (8, 99))
    monkeypatch.setattr(v2.tcpip, 'validate_tuple_probe', lambda *_: None)
    monkeypatch.setattr(v2.tcpip, 'connection_events', lambda *_args, **_kw: observed)
    monkeypatch.setattr(v2.aux, 'validate_named_tdh', lambda *_: None)
    monkeypatch.setattr(v2, 'check_aux_provenance', lambda *_: {
        'capture_qpc': {'before': [0, 50], 'after': [200, 210]}})
    return case_path, source, export, manifest, selected


def test_rebuild_accepts_json_roundtrip_of_transition_without_weakening_targets(tmp_path,
                                                                                 monkeypatch):
    case, source, export, manifest, selected = _fixture(tmp_path, monkeypatch)
    assert isinstance(manifest['targets'][1]['transition'], list)
    proof = v2.rebuild(case, source, export, require_windows=False)
    assert proof['status'] == 'COMPLETE_DIAGNOSTIC_REBUILD_ONLY'
    assert proof['cases'][0]['begin_qpc'] == 100
    assert proof['cases'][0]['zero_constraint'] == 'NO_ZERO_TCB'
    with pytest.raises(v2.raw.DiagnosticError, match='Windows v2 export'):
        v2.derive(case, source, export, tmp_path / 'formal')
    assert not (tmp_path / 'formal/derived.json').exists()


@pytest.mark.parametrize('change', ['transition', 'ref', 'run', 'case', 'connection',
                                    'seq', 'missing', 'extra', 'duplicate', 'selector'])
def test_rebuild_rejects_changed_named_graph(tmp_path, monkeypatch, change):
    case, source, export, manifest, selected = _fixture(tmp_path, monkeypatch)
    if change == 'transition':
        manifest['targets'][1]['transition'][1] = 'Closed'
    elif change == 'ref':
        manifest['targets'][1]['pktmon_ref']['byte_start'] = 99
    elif change in ('run', 'case', 'connection'):
        key = {'run': 'run_id', 'case': 'case_index',
               'connection': 'connection_id'}[change]
        manifest['targets'][1][key] = 'wrong'
    elif change == 'seq':
        manifest['targets'][1]['seq'] = 99
    elif change == 'missing':
        manifest['targets'].pop()
    elif change == 'extra':
        manifest['targets'].append({'unexpected': True})
    elif change == 'duplicate':
        manifest['targets'][1] = copy.deepcopy(manifest['targets'][0])
    elif change == 'selector':
        selected[1]['identity_sha256'] = '0' * 64
    _write(export / 'legacy/manifest.json', manifest)
    with pytest.raises(v2.raw.DiagnosticError, match='legacy named selector/target differs'):
        v2.rebuild(case, source, export, require_windows=False)
