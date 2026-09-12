import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
spec = importlib.util.spec_from_file_location('release_matrix', Path(__file__).parent / 'acceptance/release_matrix.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def args(mode='normal', limit=None):
    return SimpleNamespace(mode=mode, rounds_limit=limit, candidate_id='cid', source_commit='a'*40, package_sha256='b'*64)

def test_full_default_creates_no_manifest(tmp_path):
    assert m.matrix_counts(args(), tmp_path) == m.FULL
    assert not list(tmp_path.iterdir())

def test_reduced_freezes_both_modes_and_summary(tmp_path):
    assert m.matrix_counts(args(limit='builtin=3,custom=2'), tmp_path) == m.REDUCED
    raw = (tmp_path/'matrix-manifest.json').read_bytes()
    assert m.matrix_counts(args('fault','per-class=1'), tmp_path) == m.REDUCED
    assert m.matrix_counts(args('summary'), tmp_path) == m.REDUCED
    assert (tmp_path/'matrix-manifest.json').read_bytes() == raw
    with pytest.raises(ValueError): m.matrix_counts(args(),tmp_path)
    with pytest.raises(ValueError): m.matrix_counts(args('fault','per-class=2'),tmp_path)
    changed = args('summary'); changed.candidate_id='other'
    with pytest.raises(ValueError): m.matrix_counts(changed,tmp_path)

def test_rejects_old_full_and_extra_round(tmp_path):
    p=tmp_path/'normal-builtin-006.json';p.write_text('{}')
    with pytest.raises(ValueError): m.matrix_counts(args(limit='builtin=3,custom=2'),tmp_path)
    p.unlink();m.matrix_counts(args(limit='builtin=3,custom=2'),tmp_path)
    p.write_text('{}')
    with pytest.raises(ValueError): m.matrix_counts(args('summary'),tmp_path)

@pytest.mark.parametrize('mode,value', [('normal','builtin=3,builtin=2'),('normal','builtin=0,custom=2'),('fault','per-class=11'),('normal','builtin=3'),('final','per-class=1')])
def test_bad_limits(mode,value):
    with pytest.raises(ValueError):m.parse_limit(mode,value)
