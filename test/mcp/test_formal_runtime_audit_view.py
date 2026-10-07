"""Exact selected indexed copies with real byte copy and fresh resource gate."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials, write_json, record
from test_formal_runtime_prepare import prepared
from test_formal_runtime_audit import authority
from formal_runtime.context import load_context, MaterialError
from formal_runtime import audit, audit_view


@pytest.fixture
def copy_context(authority, prepared):
    root, material, _, data, plan = prepared
    data = copy.deepcopy(data)
    selected = write_json(Path(data['credited_selection']['path']), {
        'sst-005': next(iter(authority[3]['selected'].values()))['root']})
    data.update(credited_selection=selected, audit_root=str(root / 'Logs/independent-copy'))
    return load_context(material, write_json(material, data)['sha256'], repository_root=root)


def test_actual_indexed_view_copies_independent_bytes_and_freezes_authority(copy_context):
    inventory = audit_view.plan_view(copy_context, 'credited-selection')
    m = audit_view.build_view(copy_context, 'credited-selection')
    assert len(m.selected) == 1 and len(m.contexts) == 1
    assert len(m.records) == inventory['file_count']
    for row in m.records.values():
        source, target = Path(row['source_path']), Path(row['target'])
        assert source.read_bytes() == target.read_bytes()
        assert (source.stat().st_dev,source.stat().st_ino) != (target.stat().st_dev,target.stat().st_ino)
    assert not (m.view / 'results/scenario-sst-006.json').exists()
    terminal = json.loads((copy_context.audit_root / 'source-copy-terminal.json').read_bytes())
    assert terminal['copy_completed'] and terminal['host_copy_writers_ended'] and terminal['new_formal_credit'] == 0
    assert json.loads((copy_context.audit_root / 'source-copy-complete.json').read_bytes())['no_proof_credit']
    with pytest.raises(audit.AuditError, match='not a retry'): audit_view.build_view(copy_context, 'credited-selection')


def test_fresh_capacity_refuses_before_creating_any_copy_output(copy_context, monkeypatch):
    monkeypatch.setattr(audit_view.shutil, 'disk_usage', lambda _: SimpleNamespace(free=23 * 2**30))
    with pytest.raises(audit.AuditError, match='capacity insufficient'): audit_view.build_view(copy_context, 'credited-selection')
    assert not copy_context.audit_root.exists()


def test_changed_source_during_actual_copy_preserves_partial_originals(copy_context, monkeypatch):
    original = audit_view.shutil.copyfileobj
    corrupted = []
    def copy_boundary(source, target, length):
        original(source, target, length)
        if not corrupted:
            path = Path(source.name)
            path.write_bytes(path.read_bytes() + b'changed after copy')
            corrupted.append(path)
    monkeypatch.setattr(audit_view.shutil, 'copyfileobj', copy_boundary)
    with pytest.raises(MaterialError, match='fingerprint mismatch'):
        audit_view.build_view(copy_context, 'credited-selection')
    terminal = json.loads((copy_context.audit_root / 'source-copy-terminal.json').read_bytes())
    assert not terminal['copy_completed'] and terminal['host_copy_writers_ended']
    assert list((copy_context.audit_root / 'view').rglob('*'))
    assert not (copy_context.audit_root / 'source-copy-complete.json').exists()


def test_unknown_host_copy_retains_partial_and_has_no_completed_authority(copy_context, monkeypatch):
    def failing_copy(source, target, length):
        target.write(source.read(1))
        raise OSError('controlled local byte writer failure')
    monkeypatch.setattr(audit_view.shutil, 'copyfileobj', failing_copy)
    with pytest.raises(OSError, match='byte writer failure'):
        audit_view.build_view(copy_context, 'credited-selection')
    terminal = json.loads((copy_context.audit_root / 'source-copy-terminal.json').read_bytes())
    assert not terminal['copy_completed'] and terminal['partial_originals_retained']
    assert terminal['host_copy_writers_ended'] and not (copy_context.audit_root / 'authorities').exists()


def test_unindexed_nested_source_reference_is_not_filled_from_filesystem(copy_context):
    data = json.loads(copy_context.materials_path.read_bytes())
    root = Path(next(iter(json.loads(Path(data['credited_selection']['path']).read_bytes()).values())))
    result_path = root / 'results/scenario-sst-005.json'
    value = json.loads(result_path.read_bytes())
    other = root / 'unindexed.bin'; other.write_bytes(b'same bytes are not source authority')
    value['extra_nested'] = dict(record(other), path='unindexed.bin')
    write_json(result_path, value)
    index = Path(data['source_indices'][0]['path'])
    sealed = json.loads(index.read_bytes())
    for row in sealed['rows']:
        if row['path'].replace('\\', '/') == result_path.relative_to(root).as_posix():
            row.update({k:v for k,v in record(result_path).items() if k != 'path'})
    data['source_indices'] = [write_json(index, sealed)]
    context = load_context(copy_context.materials_path, write_json(copy_context.materials_path,data)['sha256'],
                           repository_root=copy_context.repository_root)
    with pytest.raises(audit.AuditError, match='nested selected source reference missing'):
        audit_view.build_view(context, 'credited-selection')
    assert not context.audit_root.exists()


def test_unindexed_temporary_file_never_enters_independent_view(copy_context):
    root = Path(next(iter(json.loads(Path(copy_context.materials['credited_selection']['path']).read_bytes()).values())))
    unindexed = root / 'evidence/sst-005/attempt-01/run-01/auxiliary-qpc/qpc-native/export/legacy/tmp-unindexed/paired.jsonl'
    unindexed.parent.mkdir()
    unindexed.write_bytes(b'unindexed old temporary, retained untouched')
    m = audit_view.build_view(copy_context, 'credited-selection')
    assert unindexed.read_bytes() == b'unindexed old temporary, retained untouched'
    assert not (m.view / unindexed.relative_to(root)).exists()
    assert str(unindexed) not in {row['source_path'] for row in m.records.values()}


def test_actual_unclosed_selected_transport_stops_copy_before_authority(copy_context):
    data = json.loads(copy_context.materials_path.read_bytes())
    root = Path(next(iter(json.loads(Path(data['credited_selection']['path']).read_bytes()).values())))
    completion = root / 'evidence/sst-005/attempt-01/unclosed/completion.json'
    completion.parent.mkdir()
    write_json(completion, {'local_writer_ended': False})
    index = Path(data['source_indices'][0]['path'])
    sealed = json.loads(index.read_bytes()); sealed['rows'].append(dict(record(completion),path=completion.relative_to(root).as_posix()))
    data['source_indices'] = [write_json(index,sealed)]
    context = load_context(copy_context.materials_path,write_json(copy_context.materials_path,data)['sha256'],
                           repository_root=copy_context.repository_root)
    with pytest.raises(audit.AuditError, match='writer not proven ended'):
        audit_view.build_view(context,'credited-selection')
    terminal = json.loads((context.audit_root / 'source-copy-terminal.json').read_bytes())
    assert not terminal['copy_completed'] and terminal['host_copy_writers_ended']
    assert not (context.audit_root / 'authorities').exists()
