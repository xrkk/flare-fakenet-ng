"""Strict auxiliary zero-TCB map and identity gates, without VM or local Logs."""
import base64
import copy
import hashlib
from pathlib import Path
import struct
import sys
import json
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_aux_qpc_diagnostic as aux  # noqa: E402
import scenario_aux_qpc_contract as contract  # noqa: E402
import scenario_aux_qpc_offline as offline  # noqa: E402
from test_scenario_aux_qpc_diagnostic import candidate_tdh_fixture  # noqa: E402


def value_map(*, name=aux.ZERO_TCB_REASON_MAP, label='Receive discarded ',
              flags=1, value_type=0, values=(0, 10)):
    entries = [(values[0], label), (values[1], 'Connection aborted ')]
    table_end = 16 + 8 * len(entries)
    chunks = [name.encode('utf-16-le') + b'\0\0']
    offsets = []
    cursor = table_end + len(chunks[0])
    for _, text in entries:
        offsets.append(cursor)
        raw = text.encode('utf-16-le') + b'\0\0'
        chunks.append(raw)
        cursor += len(raw)
    blob = bytearray(struct.pack('<4I', table_end, flags, len(entries), value_type))
    for (value, _), offset in zip(entries, offsets):
        blob.extend(struct.pack('<2I', offset, value))
    for chunk in chunks:
        blob.extend(chunk)
    return bytes(blob)


def strict_fixture():
    row, group, selector = candidate_tdh_fixture()
    blob = value_map()
    next(x for x in row['property_results'] if x['name'] == 'Reason')['event_map'] = {
        'name': aux.ZERO_TCB_REASON_MAP, 'first_status': 122, 'second_status': 0,
        'required_size': len(blob), 'buffer_base64': base64.b64encode(blob).decode(),
        'buffer_sha256': hashlib.sha256(blob).hexdigest()}
    return row, group, selector


def test_real_layout_manifest_valuemap_resolves_zero_exactly():
    parsed = aux.parse_reason_map(value_map())
    assert parsed['reason_zero_label'] == 'Receive discarded '
    assert [entry['value'] for entry in parsed['entries']] == [0, 10]
    row, group, selector = strict_fixture()
    facts = aux.candidate_field_facts([row], [group], [selector], strict=True)
    assert facts[0]['status'] == 'REASON_MAP_VERIFIED'
    assert facts[0]['reason_label'] == 'Receive discarded '


@pytest.mark.parametrize('change', [
    {'flags': 2}, {'value_type': 1}, {'name': 'WrongMap'},
    {'label': 'Connection aborted '}, {'values': (0, 0)}])
def test_wrong_map_semantics_fail(change):
    with pytest.raises(aux.raw_clock.DiagnosticError):
        aux.parse_reason_map(value_map(**change))


@pytest.mark.parametrize('mutator', [
    lambda data: data[:16],
    lambda data: data[:-2],
    lambda data: data[:16] + struct.pack('<I', 99999) + data[20:],
    lambda data: data[:4] + struct.pack('<I', 2) + data[8:],
    lambda data: data[:8] + struct.pack('<I', 100000) + data[12:],
])
def test_truncated_offset_or_type_corrupt_map_fails(mutator):
    with pytest.raises(aux.raw_clock.DiagnosticError):
        aux.parse_reason_map(mutator(value_map()))


@pytest.mark.parametrize('field', ['buffer_sha256', 'required_size', 'first_status',
                                   'second_status', 'name'])
def test_map_api_original_integrity_is_required(field):
    row, group, selector = strict_fixture()
    event_map = next(x for x in row['property_results'] if x['name'] == 'Reason')['event_map']
    event_map[field] = 'x' if field in ('buffer_sha256', 'name') else -1
    with pytest.raises(aux.raw_clock.DiagnosticError):
        aux.candidate_field_facts([row], [group], [selector], strict=True)


def group(seq=7, occurrences=1, status='unique', anchors=(7,)):
    return {'status': 'DIAGNOSTIC_CANDIDATES_UNRESOLVED',
            'pktmon_ref': {'path': 'pktmon.txt', 'byte_start': 1,
                           'byte_end': 2, 'event_key': 'text'},
            'exact_filetime_anchor_seqs': list(anchors),
            'candidates': [{'seq': seq, 'binding_status': status,
                            'identity_occurrences': occurrences,
                            'selection_reason': 'EXACT_FORMATTED_FILETIME'}]}


def test_only_one_full_native_identity_binds_zero_ref():
    assert next(iter(aux.unique_zero_bindings([group()]).values()))['seq'] == 7


@pytest.mark.parametrize('bad', ['pid', 'creation', 'run', 'candidate', 'identity'])
def test_offline_original_ipc_and_export_summary_must_match(bad):
    case = {'candidate_id': 'candidate', 'run_id': 'run'}
    windows = {'identity': {'boot': 'boot'}, 'targets': [], 'candidate_sets': [],
               'candidate_id': 'candidate', 'run_id': 'run', 'managed_pid': 42,
               'managed_creation_filetime_100ns': 100}
    change = {'pid': ('managed_pid', 43), 'creation': ('managed_creation_filetime_100ns', 101),
              'run': ('run_id', 'other'), 'candidate': ('candidate_id', 'other'),
              'identity': ('identity', {'boot': 'other'})}
    key, value = change[bad]
    windows[key] = value
    with pytest.raises(aux.raw_clock.DiagnosticError, match='summary differs'):
        offline.verify_windows_summary(windows, {'boot': 'boot'}, [], [], case, 42, 100)


@pytest.mark.parametrize('bad', [
    lambda x: x['candidates'].append(copy.deepcopy(x['candidates'][0])),
    lambda x: x['candidates'][0].update(identity_occurrences=2),
    lambda x: x['candidates'][0].update(binding_status='ambiguous'),
    lambda x: x.update(exact_filetime_anchor_seqs=[8]),
    lambda x: x['candidates'][0].update(selection_reason='SAME_AMBIGUOUS_NON_TIME_IDENTITY'),
])
def test_ambiguous_or_inexact_binding_never_promotes(bad):
    item = group()
    bad(item)
    with pytest.raises(aux.raw_clock.DiagnosticError):
        aux.unique_zero_bindings([item])


@pytest.mark.parametrize('bad', [None, 'exit', 'transfer', 'input_sha', 'zip',
                                   'proof_hash', 'candidate', 'nonce', 'wrong_zero',
                                   'no_zero', 'mixed',
                                   'old_version'])
def test_formal_graph_requires_complete_run_and_closed_resources(tmp_path, monkeypatch, bad):
    """Synthetic graph checks the formal adapter; it is not a Windows proof."""
    root = tmp_path / 'evidence/run/auxiliary-qpc'
    (root / 'qpc-native/export').mkdir(parents=True)
    (root / 'qpc-rejudge').mkdir()
    input_sha = 'a' * 64
    process = {'exit_proven': True, 'run_id': 'r'}
    owner = {'run_id': 'r', 'input_sha256': input_sha, 'guest_root': 'guest'}
    terminal = dict(owner, exit_proven=True, guest_error=None)
    transfer = {'error': None, 'host_only_transfer': {'bind': '192.168.204.1',
        'stopped': True, 'sha256': input_sha, 'bytes': 3,
        'requests': [{'status': 200, 'bytes': 3}]},
        'guest': {'input_sha256': input_sha, 'exit_code': 0,
                  'process': process, 'bytes': 0, 'sha256': ''}}
    proof = {'schema': 'sst.aux-qpc-offline.v1', 'status': 'COMPLETE_FORMAL_INPUT',
        'source_windows_status': 'COMPLETE_DIAGNOSTIC_ONLY',
        'candidate_id': 'candidate', 'run_id': 'r', 'nonce': 'n', 'identity': {},
        'cases': [{'zero_constraint': 'VERIFIED'}], 'reason_map_sha256': ['b' * 64]}
    if bad == 'exit': terminal['exit_proven'] = False
    if bad == 'transfer': transfer['host_only_transfer']['stopped'] = False
    if bad == 'input_sha': transfer['host_only_transfer']['sha256'] = 'c' * 64
    if bad == 'candidate': proof['candidate_id'] = 'wrong'
    if bad == 'nonce': proof['nonce'] = 'wrong'
    if bad == 'wrong_zero': proof['cases'][0]['zero_constraint'] = 'UNVERIFIED'
    if bad == 'no_zero': proof['cases'][0]['zero_constraint'] = 'NO_ZERO_TCB'
    if bad == 'mixed': proof['cases'].append({'zero_constraint': 'NO_ZERO_TCB'})
    if bad == 'old_version':
        proof['status'] = 'DIAGNOSTIC_ONLY_INCOMPLETE_SOURCE'
        proof['source_windows_status'] = 'INCOMPLETE'
    def put(path, value):
        path.write_text(json.dumps(value))
        return {'path': path.relative_to(tmp_path).as_posix(),
                'size': path.stat().st_size,
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    put(root/'qpc-native/terminal.json', process)
    put(root/'qpc-native/process-responsibility.json', owner)
    with zipfile.ZipFile(root/'qpc-output.zip', 'w') as archive:
        for name in ('terminal.json', 'process-responsibility.json'):
            archive.write(root/'qpc-native'/name, name)
    zip_bytes = (root/'qpc-output.zip').read_bytes()
    transfer['guest']['bytes'] = len(zip_bytes)
    transfer['guest']['sha256'] = hashlib.sha256(zip_bytes).hexdigest()
    records = {
        'qpc-process-responsibility.json': put(root/'qpc-process-responsibility.json', owner),
        'qpc-process-terminal.json': put(root/'qpc-process-terminal.json', terminal),
        'qpc-transfer.json': put(root/'qpc-transfer.json', transfer)}
    stored = put(root/'qpc-rejudge/derived.json', proof)
    if bad == 'proof_hash': stored['sha256'] = '0' * 64
    if bad == 'zip':
        (root/'qpc-output.zip').write_bytes(b'BAD')
    (root/'auxiliary-qpc-input.json').write_text('{}')
    monkeypatch.setattr(contract.offline, 'derive', lambda *_: proof)
    run = {'run_id': 'r', 'auxiliary_qpc_process': records, 'auxiliary_qpc_proof': stored}
    if bad not in (None, 'no_zero', 'mixed'):
        with pytest.raises(aux.raw_clock.DiagnosticError):
            contract.evaluate(run, tmp_path, expected_candidate='candidate', expected_nonce='n')
    else:
        assert contract.evaluate(run, tmp_path, expected_candidate='candidate',
                                 expected_nonce='n')['source_windows_status'] == 'COMPLETE_DIAGNOSTIC_ONLY'
