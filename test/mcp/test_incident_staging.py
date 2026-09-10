"""Two-phase incident staging: bounded, single-use, and swept by the next
preparation of the same run (CHK-055/CHK-069 dedup boundary conditions)."""
import json
import time
import uuid

import pytest

from fakenet.mcp import incident_task


def _directories(tmp_path):
    return {'artifacts': tmp_path, 'baselines': tmp_path / 'baselines'}


def _request(run_id='11111111-1111-4111-8111-111111111111', **extra):
    request = dict(run_id=run_id, config_sha256='a' * 64, reason='managed IPC EOF',
                   live_stacks=None, last_stacks=None, timeline=[{'event': 'stop'}],
                   final_filter=None, managed={'identity': None, 'exit_code': None,
                                               'job_members': []},
                   dump_target=None, exit_report=None, token=str(uuid.uuid4()))
    request.update(extra)
    return request


def _prepare(tmp_path, monkeypatch, request):
    from fakenet.mcp import baseline
    monkeypatch.setattr(baseline, 'capture', lambda deadline: {})
    monkeypatch.setattr(baseline.BaselineStore, 'load', lambda self, run: {'sections': {}})
    directories = _directories(tmp_path)
    return (incident_task.prepare_stage(request, directories, tmp_path,
                                        time.monotonic() + 30),
            directories)


def test_prepare_and_collect_round_trip_one_single_use_staging(tmp_path, monkeypatch):
    run_dir = tmp_path / 'runs' / _request()['run_id']
    run_dir.mkdir(parents=True)
    (run_dir / 'stdout_stderr.log').write_text('managed output', encoding='utf-8')
    request = _request(managed={'identity': None, 'exit_code': None, 'job_members': []})
    summary, directories = _prepare(tmp_path, monkeypatch, request)
    staging = tmp_path / request['run_id'] / ('incident-staging-%s.json' % request['token'])
    assert staging.is_file()
    assert summary['staging'] == str(staging)

    contexts = []

    class Collector:
        def __init__(self, *args, **kwargs):
            self.root = tmp_path / 'incident'
            self.deadline = float('inf')
            self.manifest = []

        def collect(self, context):
            contexts.append(context)

    from fakenet.mcp import incident, exit_files
    monkeypatch.setattr(incident, 'IncidentCollector', Collector)
    monkeypatch.setattr(exit_files, 'root', lambda: tmp_path / 'exit-evidence')
    report = incident_task.collect_stage(
        dict(run_id=request['run_id'], staging=request['token']),
        directories, tmp_path, time.monotonic() + 30)
    assert not staging.exists()
    assert report['incident_path'] == str(tmp_path / 'incident')
    assert contexts[0]['stdout_stderr'] == 'managed output'
    assert contexts[0]['timeline'] == [{'event': 'stop'}]
    # A consumed staging file cannot be collected twice.
    with pytest.raises(RuntimeError, match='staging absent'):
        incident_task.collect_stage(
            dict(run_id=request['run_id'], staging=request['token']),
            directories, tmp_path, time.monotonic() + 30)


def test_abort_collect_removes_staging_and_reports_skip(tmp_path, monkeypatch):
    request = _request()
    summary, directories = _prepare(tmp_path, monkeypatch, request)
    report = incident_task.collect_stage(
        dict(run_id=request['run_id'], staging=request['token'], abort=True),
        directories, tmp_path, time.monotonic() + 30)
    assert report['skipped_same_failure'] is True
    assert not list((tmp_path / request['run_id']).glob('incident-staging-*'))


def test_staging_token_is_strictly_single_use_uuid(tmp_path, monkeypatch):
    request = _request(token='not-a-uuid')
    with pytest.raises(ValueError, match='staging token'):
        _prepare(tmp_path, monkeypatch, request)
    request = _request(token=str(uuid.uuid4()).upper())
    with pytest.raises(ValueError, match='staging token'):
        _prepare(tmp_path, monkeypatch, request)


def test_next_preparation_sweeps_stale_staging_of_the_same_run(tmp_path, monkeypatch):
    request = _request()
    parent = tmp_path / request['run_id']
    parent.mkdir(parents=True)
    stale = parent / ('incident-staging-%s.json' % uuid.uuid4())
    stale.write_text('{}', encoding='utf-8')
    residue = parent / 'incident-staging-partial.json.new'
    residue.write_text('{}', encoding='utf-8')
    _prepare(tmp_path, monkeypatch, request)
    assert not stale.exists()
    assert not residue.exists()


def test_oversized_source_becomes_unavailable_not_unbounded(tmp_path, monkeypatch):
    run_id = _request()['run_id']
    run_dir = tmp_path / 'runs' / run_id
    run_dir.mkdir(parents=True)
    (run_dir / 'stdout_stderr.log').write_bytes(b'x' * (incident_task.STAGING_FILE_CAP + 1))
    request = _request()
    summary, directories = _prepare(tmp_path, monkeypatch, request)

    contexts = []

    class Collector:
        def __init__(self, *args, **kwargs):
            self.root = tmp_path / 'incident'
            self.deadline = float('inf')
            self.manifest = []

        def collect(self, context):
            contexts.append(context)

    from fakenet.mcp import incident, exit_files
    monkeypatch.setattr(incident, 'IncidentCollector', Collector)
    monkeypatch.setattr(exit_files, 'root', lambda: tmp_path / 'exit-evidence')
    incident_task.collect_stage(dict(run_id=run_id, staging=request['token']),
                                directories, tmp_path, time.monotonic() + 30)
    assert contexts[0]['stdout_stderr'] is None
