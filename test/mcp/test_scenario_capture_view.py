"""Fail-closed shared physical capture bindings; no VM or product substitute."""
import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_capture_view as view


def record(root, name, payload):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    path.write_bytes(raw)
    return {'path': name, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def fixture_result(root):
    physical = [record(root, 'pktmon.etl', b'etl'),
                record(root, 'pktmon.txt', b'text'),
                record(root, 'pktmon-nic.json', {
                    key: {'supported': True, 'candidate_id': 'candidate',
                          'boot': {'boot_identifier': 'boot'},
                          'vm_identity': {'machine_guid': 'machine'}}
                    for key in ('native_identity_before', 'native_identity_after')})]
    owner_id = 'nonce:pktmon'
    owner = {'schema': view.OWNER_SCHEMA, 'owner_id': owner_id, 'nonce': 'nonce',
             'scenario_id': 'sst-012', 'epoch': 1, 'capture_contract': 'scenario-shared-v2',
             'guest_work_root': r'E:\FakeNet-NG-MCP-test-work',
             'tool_sha256': 'tool-sha',
             'run_ids': ['product-1', 'product-2'], 'physical_files': physical,
             'started_utc': 'start', 'stopped_utc': 'stop'}
    owner_record = record(root, 'owner.json', owner)
    runs, records = [], []
    for i in (1, 2):
        label = f'run-0{i}'
        pid = 100 + i
        probe = record(root, label + '/probe.jsonl',
                       (json.dumps({'event': 'ready', 'nonce': 'nonce', 'pid': pid,
                                    'creation_ticks': 504911232000000000 + i,
                                    'utc_ticks': 621355968000000001,
                                    'native_identity': {'run_id': 'nonce:' + label,
                                                        'supported': True, 'nonce': 'nonce',
                                                        'creation_filetime_100ns': i,
                                                        'boot': {'boot_identifier': 'boot'},
                                                        'vm_identity': {'machine_guid': 'machine'},
                                                        'pid': pid, 'candidate_id': 'candidate'}}) + '\n' +
                        json.dumps({'event': 'close', 'nonce': 'nonce',
                                    'utc_ticks': 621355968000000002}) + '\n').encode())
        kernel = [record(root, label + '/' + name, b'kernel-fixture')
                  for name in view.KERNEL_NAMES]
        receipt = ([record(root, label + '/probe-launch.json', {
            'pid':pid, 'creation_ticks':504911232000000000 + i,
            'nonce':'nonce', 'capture_run_id':'nonce:' + label,
            'candidate_id':'candidate'})] if i == 2 else [])
        capture = {'observation_contract': 'con008-shared-v2', 'owner_id': owner_id,
                   'physical_owner': owner_record, 'pktmon_path': physical[1]['path'],
                   'pktmon_etl_path': physical[0]['path'], 'pktmon_nic_path': physical[2]['path'],
                   'pktmon_capture_issues': [], 'files': physical + [probe] + kernel + receipt,
                   'probe_path': probe['path'], 'probe_launcher_pid': pid}
        run = {'label': label, 'run_id': 'product-' + str(i), 'capture': capture}
        v = {'schema': view.VIEW_SCHEMA, 'owner': owner_record, 'owner_id': owner_id,
             'physical_files': physical, 'scenario_id': 'sst-012', 'attempt': 1,
             'run_id': run['run_id'], 'label': label, 'nonce': 'nonce',
             'guest_work_root': owner['guest_work_root'], 'tool_sha256': 'tool-sha',
             'capture_run_id': 'nonce:' + label, 'probe_pid': pid,
             'probe_creation_ticks': 504911232000000000 + i, 'probe': probe,
             'capture_started_utc': 'start', 'capture_stopped_utc': 'stop'}
        vr = record(root, label + '-view.json', v)
        capture['run_view'] = vr
        records.append(vr)
        runs.append(run)
    return {'scenario_id': 'sst-012', 'attempt': 1, 'identity': {'candidate_id': 'candidate'},
            'guest_work_root': owner['guest_work_root'],
            'tool_identity': {'sha256': 'tool-sha'},
            'traffic_evidence': {'nonce': 'nonce', 'capture_views': records}, 'run_chain': runs}


def test_shared_views_bind_each_probe_to_one_owner(tmp_path, monkeypatch):
    monkeypatch.setattr(view.scenario_tcpip, 'validate_capture',
                        lambda *args: (0, 1_000_000_000))
    result = fixture_result(tmp_path)
    view.validate_shared_views(result, tmp_path)


@pytest.mark.parametrize('change', [
    lambda r: r['run_chain'][1]['capture'].update(owner_id='other'),
    lambda r: r['run_chain'][1]['capture'].update(pktmon_etl_path='other.etl'),
    lambda r: r['run_chain'][1]['capture'].update(probe_launcher_pid=101),
    lambda r: r['run_chain'][1]['capture'].update(observation_contract='con008'),
    lambda r: r['run_chain'][1]['capture'].update(run_view=r['run_chain'][0]['capture']['run_view']),
    lambda r: r.update(attempt=2),
    lambda r: r['traffic_evidence'].update(nonce='wrong'),
    lambda r: r['run_chain'][1]['capture']['files'].pop(),
])
def test_shared_views_reject_wrong_binding(tmp_path, monkeypatch, change):
    monkeypatch.setattr(view.scenario_tcpip, 'validate_capture',
                        lambda *args: (0, 1_000_000_000))
    result = fixture_result(tmp_path)
    change(result)
    with pytest.raises((ValueError, KeyError)):
        view.validate_shared_views(result, tmp_path)


def test_shared_views_reject_changed_raw_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(view.scenario_tcpip, 'validate_capture',
                        lambda *args: (0, 1_000_000_000))
    result = fixture_result(tmp_path)
    (tmp_path / 'pktmon.etl').write_bytes(b'changed')
    with pytest.raises(ValueError, match='SHA'):
        view.validate_shared_views(result, tmp_path)


def rewrite_view(root, result, index, change):
    capture = result['run_chain'][index]['capture']
    old = capture['run_view']
    payload = json.loads((root / old['path']).read_text())
    change(payload)
    new = record(root, old['path'], payload)
    capture['run_view'] = new
    result['traffic_evidence']['capture_views'][index] = new


def rewrite_probe(root, result, index, change):
    capture = result['run_chain'][index]['capture']
    old_view = json.loads((root / capture['run_view']['path']).read_text())
    old_probe = old_view['probe']
    rows = [json.loads(x) for x in (root / old_probe['path']).read_text().splitlines()]
    change(rows)
    new_probe = record(root, old_probe['path'],
                       ('\n'.join(json.dumps(x) for x in rows) + '\n').encode())
    capture['files'] = [new_probe if x == old_probe else x for x in capture['files']]
    rewrite_view(root, result, index, lambda v: v.update(probe=new_probe))


@pytest.mark.parametrize('field,value,reason', [
    ('run_id', 'foreign-product-run', 'run view identity/epoch'),
    ('attempt', 2, 'run view identity/epoch'),
    ('nonce', 'foreign-nonce', 'run view identity/epoch'),
    ('capture_run_id', 'foreign:run-02', 'run view identity/epoch'),
    ('probe_creation_ticks', 9, 'launch receipt identity'),
    ('tool_sha256', 'foreign-tool', 'run view identity/epoch'),
])
def test_view_rejects_exact_mutated_field(tmp_path, monkeypatch, field, value, reason):
    monkeypatch.setattr(view.scenario_tcpip, 'validate_capture',
                        lambda *args: (0, 1_000_000_000))
    result = fixture_result(tmp_path)
    rewrite_view(tmp_path, result, 1, lambda v: v.update({field:value}))
    with pytest.raises(ValueError, match=reason):
        view.validate_shared_views(result, tmp_path)


@pytest.mark.parametrize('change,reason', [
    (lambda rows: rows.append(dict(rows[0])), 'ready missing/ambiguous'),
    (lambda rows: rows.pop(), 'close missing'),
    (lambda rows: rows[0]['native_identity'].update(run_id='other-run'), 'probe/native PID creation'),
    (lambda rows: rows[0]['native_identity'].update(creation_filetime_100ns=55), 'probe/native PID creation'),
    (lambda rows: rows[0].update(utc_ticks=621355968020000000), 'lifetime outside'),
])
def test_probe_event_negative_hits_exact_validator(tmp_path, monkeypatch, change, reason):
    monkeypatch.setattr(view.scenario_tcpip, 'validate_capture',
                        lambda *args: (0, 1_000_000_000))
    result = fixture_result(tmp_path)
    rewrite_probe(tmp_path, result, 1, change)
    with pytest.raises(ValueError, match=reason):
        view.validate_shared_views(result, tmp_path)


def test_kernel_archive_missing_and_borrowed_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(view.scenario_tcpip, 'validate_capture',
                        lambda *args: (0, 1_000_000_000))
    result = fixture_result(tmp_path)
    second = result['run_chain'][1]['capture']
    second['files'] = [x for x in second['files']
                       if Path(x['path']).name != 'kernel-network.events.jsonl']
    with pytest.raises(ValueError, match='kernel archive incomplete'):
        view.validate_shared_views(result, tmp_path)
    result = fixture_result(tmp_path)
    first_kernel = next(x for x in result['run_chain'][0]['capture']['files']
                        if Path(x['path']).name == 'kernel-network.events.jsonl')
    second = result['run_chain'][1]['capture']
    second['files'] = [first_kernel if Path(x['path']).name ==
                       'kernel-network.events.jsonl' else x for x in second['files']]
    with pytest.raises(ValueError, match='kernel archive incomplete/borrowed'):
        view.validate_shared_views(result, tmp_path)
    result = fixture_result(tmp_path)
    duplicate = record(tmp_path, 'run-02/extra/kernel-network.events.jsonl', b'kernel-fixture')
    result['run_chain'][1]['capture']['files'].append(duplicate)
    with pytest.raises(ValueError, match='kernel archive incomplete/borrowed'):
        view.validate_shared_views(result, tmp_path)


def test_shared_launch_receipt_mismatch_rejected_after_view_bind(tmp_path, monkeypatch):
    monkeypatch.setattr(view.scenario_tcpip, 'validate_capture',
                        lambda *args: (0, 1_000_000_000))
    result = fixture_result(tmp_path)
    capture = result['run_chain'][1]['capture']
    old = next(x for x in capture['files'] if Path(x['path']).name == 'probe-launch.json')
    receipt = json.loads((tmp_path / old['path']).read_text())
    receipt['candidate_id'] = 'foreign-candidate'
    new = record(tmp_path, old['path'], receipt)
    capture['files'] = [new if x == old else x for x in capture['files']]
    with pytest.raises(ValueError, match='launch receipt identity'):
        view.validate_shared_views(result, tmp_path)
