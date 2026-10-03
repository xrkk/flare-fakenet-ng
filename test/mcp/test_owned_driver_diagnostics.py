# Copyright 2026 Google LLC
"""Internal owned-driver observation: original product seams, no real driver changes."""
import json
import os
import subprocess
import time
from types import SimpleNamespace
import uuid
from pathlib import Path

import pytest

from fakenet.mcp import baseline, native_provenance, tools

RUN = '72751a75-9309-4a46-a691-c67a642bc02b'
FILETIME = '134335748055012290'


def native():
    return {'supported': True, 'pid': os.getpid(), 'creation_filetime_100ns': int(FILETIME)}


def store_for(tmp_path, monkeypatch, enabled='1'):
    monkeypatch.setenv('FAKENET_MCP_OWNED_DRIVER_DIAGNOSTICS', enabled)
    monkeypatch.setattr(native_provenance, 'native_identity', native)
    return tools._make_baseline_store({'baselines': tmp_path / 'baselines', 'logs': tmp_path / 'logs'})


def data():
    return {'run_id': RUN, 'managed_driver_root': r'C:\Program Files\FakeNet-NG-MCP',
            'sections': {'windivert_processes': '{"drivers":[]}'}}


def records(tmp_path):
    return [json.loads(p.read_text()) for p in (tmp_path / 'logs').rglob('*.json')]


def test_opt_in_factory_retains_failed_child_same_run_without_retry(tmp_path, monkeypatch):
    store = store_for(tmp_path, monkeypatch)
    calls = []

    def child(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 1, '', 'owned driver still registered')

    monkeypatch.setattr(baseline.subprocess, 'run', child)
    deadline = time.monotonic() + 10
    with pytest.raises(RuntimeError, match='owned driver compensation failed'):
        store._restore_owned_drivers(data(), deadline)
    rows = records(tmp_path)
    assert len(rows) == 1
    row = rows[0]
    assert row['run_id'] == RUN and row['supervisor_pid'] == os.getpid()
    assert row['supervisor_creation_filetime'] == FILETIME
    assert row['returncode'] == 1 and row['stderr_tail'] == 'owned driver still registered'
    assert row['deadline_monotonic'] == deadline and 0 < row['remaining_at_dispatch'] <= 10
    assert len(calls) == 1


@pytest.mark.parametrize('switch', [None, '', '0', 'true', '01', '1 ', ' 1'])
def test_default_and_nonexact_switch_keep_original_run_contract(tmp_path, monkeypatch, switch):
    if switch is None:
        monkeypatch.delenv('FAKENET_MCP_OWNED_DRIVER_DIAGNOSTICS', raising=False)
    else:
        monkeypatch.setenv('FAKENET_MCP_OWNED_DRIVER_DIAGNOSTICS', switch)
    monkeypatch.setattr(native_provenance, 'native_identity', lambda: pytest.fail('no native query'))
    store = tools._make_baseline_store({'baselines': tmp_path / 'baselines'})
    calls = []
    # Existing callers/stubs accepting exactly the original args still work.
    def original_contract(command, timeout=60):
        calls.append(timeout)
        return 'owned driver compensation complete'
    monkeypatch.setattr(baseline, '_run', original_contract)
    store._restore_owned_drivers(data(), time.monotonic() + 10)
    assert len(calls) == 1 and not (tmp_path / 'logs').exists()


@pytest.mark.parametrize('identity', [None, {'supported': False},
    {'supported': True, 'pid': 0, 'creation_filetime_100ns': 1},
    {'supported': True, 'pid': os.getpid(), 'creation_filetime_100ns': 'fake'}])
def test_untrusted_native_disables_observation_without_altering_result(tmp_path, monkeypatch, caplog, identity):
    monkeypatch.setenv('FAKENET_MCP_OWNED_DRIVER_DIAGNOSTICS', '1')
    monkeypatch.setattr(native_provenance, 'native_identity', lambda: identity)
    store = tools._make_baseline_store({'baselines': tmp_path / 'baselines', 'logs': tmp_path / 'logs'})
    monkeypatch.setattr(baseline, '_run', lambda command, timeout=60: 'ok')
    store._restore_owned_drivers(data(), time.monotonic() + 10)
    assert not records(tmp_path) and 'incomplete' in caplog.text


def test_native_or_factory_preparation_exception_does_not_break_service(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv('FAKENET_MCP_OWNED_DRIVER_DIAGNOSTICS', '1')
    def fail():
        raise RuntimeError('private identity error')
    monkeypatch.setattr(native_provenance, 'native_identity', fail)
    store = tools._make_baseline_store({'baselines': tmp_path / 'a', 'logs': tmp_path / 'logs'})
    assert store.owned_driver_observer is None
    store = tools._make_baseline_store({'baselines': tmp_path / 'b'})
    assert store and 'factory KeyError' in caplog.text and 'private identity error' not in caplog.text


def test_before_deadline_dispatches_no_child(tmp_path, monkeypatch):
    store = store_for(tmp_path, monkeypatch)
    monkeypatch.setattr(baseline.subprocess, 'run', lambda *a, **k: pytest.fail('no child after deadline'))
    with pytest.raises(RuntimeError):
        store._restore_owned_drivers(data(), time.monotonic() - 1)
    row = records(tmp_path)[0]
    assert row['classification'] == 'deadline_before_dispatch'
    assert row['remaining_at_dispatch'] < 0 and row['returncode'] is None


@pytest.mark.parametrize('mode', ['success', 'nonzero', 'empty', 'timeout', 'spawn', 'decode'])
def test_child_result_classification_and_arguments_unchanged_with_optin(tmp_path, monkeypatch, mode):
    store = store_for(tmp_path, monkeypatch)
    calls = []
    def child(command, **kwargs):
        calls.append((command, kwargs))
        if mode == 'timeout':
            raise subprocess.TimeoutExpired(command, kwargs['timeout'], output=b'token=secret', stderr=b'timeout detail')
        if mode == 'spawn':
            raise OSError('private failure message')
        if mode == 'decode':
            raise UnicodeDecodeError('utf8', b'\xff', 0, 1, 'invalid')
        return subprocess.CompletedProcess(command, 1 if mode == 'nonzero' else 0,
            '' if mode == 'empty' else 'ok', 'owned driver deletion failed')
    monkeypatch.setattr(baseline.subprocess, 'run', child)
    deadline = time.monotonic() + 300
    for enabled in [False, True]:
        target = store if enabled else baseline.BaselineStore(tmp_path / 'disabled')
        if mode == 'success':
            assert target._restore_owned_drivers(data(), deadline) is None
        elif mode == 'decode':
            with pytest.raises(UnicodeDecodeError):target._restore_owned_drivers(data(), deadline)
        else:
            with pytest.raises(RuntimeError, match='owned driver compensation failed'):
                target._restore_owned_drivers(data(), deadline)
    assert len(calls) == 2  # one invocation per separately tested lifecycle, no retries
    assert calls[0] == calls[1]
    row = records(tmp_path)[0]
    assert row['subprocess_timeout'] == 60 and row['remaining_at_dispatch'] > 60
    assert row['timeout'] is (mode == 'timeout')
    assert row['exception_type'] == {'timeout': 'TimeoutExpired', 'spawn': 'OSError', 'decode': 'UnicodeDecodeError'}.get(mode)
    assert 'secret' not in row['stdout_tail'] and 'private failure message' not in json.dumps(row)


def test_write_and_serialization_failure_isolated_from_child_failure(tmp_path, monkeypatch, caplog):
    from fakenet.mcp import owned_driver_diagnostics as diag
    store = store_for(tmp_path, monkeypatch)
    count = []
    monkeypatch.setattr(baseline.subprocess, 'run', lambda command, **kw: (count.append(1) or subprocess.CompletedProcess(command, 1, '', 'owned driver stop failed')))
    original_dumps = json.dumps
    def serialization(value, **kwargs):
        if isinstance(value, dict) and 'schema' in value:raise TypeError('private unserializable')
        return original_dumps(value, **kwargs)
    monkeypatch.setattr(diag, 'json', SimpleNamespace(dumps=serialization))
    with pytest.raises(RuntimeError, match='owned driver compensation failed'):
        store._restore_owned_drivers(data(), time.monotonic() + 10)
    assert len(count) == 1 and 'incomplete' in caplog.text and 'private unserializable' not in caplog.text
    assert store.owned_driver_observer.incomplete_reason


def test_directory_write_failure_preserves_success(tmp_path, monkeypatch, caplog):
    store = store_for(tmp_path, monkeypatch)
    (tmp_path / 'logs').write_text('not a directory')
    monkeypatch.setattr(baseline.subprocess, 'run', lambda command, **kw: subprocess.CompletedProcess(command, 0, 'ok', ''))
    assert store._restore_owned_drivers(data(), time.monotonic() + 10) is None
    assert store.owned_driver_observer.incomplete_reason and 'incomplete' in caplog.text


def test_noncanonical_run_preparation_failure_does_not_change_success(tmp_path, monkeypatch):
    store = store_for(tmp_path, monkeypatch)
    monkeypatch.setattr(baseline.subprocess, 'run', lambda command, **kw: subprocess.CompletedProcess(command, 0, 'ok', ''))
    invalid = data();invalid['run_id'] = '../foreign'
    assert store._restore_owned_drivers(invalid, time.monotonic() + 10) is None
    assert store.owned_driver_observer.incomplete_reason and not records(tmp_path)


def test_unique_atomic_records_redacted_and_bounded(tmp_path, monkeypatch):
    from fakenet.mcp import owned_driver_diagnostics as diag
    store = store_for(tmp_path, monkeypatch)
    text = 'X' * 10000 + '\nAuthorization: Bearer secret\npassword="two words" api-key=private'
    monkeypatch.setattr(baseline.subprocess, 'run', lambda command, **kw: subprocess.CompletedProcess(command, 0, 'ok', text))
    for _ in range(2):store._restore_owned_drivers(data(), time.monotonic() + 10)
    files = list((tmp_path / 'logs').rglob('*.json'))
    assert len(files) == 2 and files[0].name != files[1].name
    assert not list((tmp_path / 'logs').rglob('*.tmp'))
    for p in files:
        row = json.loads(p.read_text());assert p.parent.name == RUN and p.stat().st_size <= diag.MAX_RECORD_BYTES
        assert len(row['stderr_tail']) <= 4096
        assert not any(secret in row['stderr_tail'] for secret in ['secret', 'two words', 'private'])
        assert 'argv_sha256' in row and 'environment' not in row and 'argv' not in row


def test_run_quota_stops_observation_without_deleting_or_retrying(tmp_path, monkeypatch, caplog):
    from fakenet.mcp import owned_driver_diagnostics as diag
    store = store_for(tmp_path, monkeypatch);count=[]
    monkeypatch.setattr(baseline.subprocess, 'run', lambda command, **kw: (count.append(1) or subprocess.CompletedProcess(command, 0, 'ok', '')))
    for _ in range(diag.MAX_RECORDS_PER_RUN + 2):store._restore_owned_drivers(data(), time.monotonic() + 10)
    assert len(count) == diag.MAX_RECORDS_PER_RUN + 2
    assert len(records(tmp_path)) == diag.MAX_RECORDS_PER_RUN
    assert store.owned_driver_observer.incomplete_reason and 'incomplete' in caplog.text


def test_directory_growth_quota_and_existing_records_preserved(tmp_path, monkeypatch):
    from fakenet.mcp import owned_driver_diagnostics as diag
    store = store_for(tmp_path, monkeypatch);root=tmp_path / 'logs' / 'owned-driver-diagnostics';root.mkdir(parents=True)
    for _ in range(diag.MAX_RUNS):(root / str(uuid.uuid4())).mkdir()
    monkeypatch.setattr(baseline.subprocess, 'run', lambda command, **kw: subprocess.CompletedProcess(command, 0, 'ok', ''))
    assert store._restore_owned_drivers(data(), time.monotonic() + 10) is None
    assert len(list(root.iterdir())) == diag.MAX_RUNS and store.owned_driver_observer.incomplete_reason


def test_atomic_publication_failure_does_not_replace_compensation_error(tmp_path, monkeypatch):
    from fakenet.mcp import owned_driver_diagnostics as diag
    store = store_for(tmp_path, monkeypatch)
    monkeypatch.setattr(baseline.subprocess, 'run', lambda command, **kw: subprocess.CompletedProcess(command, 1, '', 'owned driver still registered'))
    monkeypatch.setattr(diag.os, 'link', lambda *a: (_ for _ in ()).throw(OSError('publication unavailable')))
    with pytest.raises(RuntimeError, match='owned driver compensation failed'):
        store._restore_owned_drivers(data(), time.monotonic() + 10)
    assert store.owned_driver_observer.incomplete_reason
    assert not records(tmp_path) and not list((tmp_path / 'logs').rglob('*.tmp'))


def test_existing_staging_collision_never_deleted(tmp_path, monkeypatch):
    from fakenet.mcp import owned_driver_diagnostics as diag
    store = store_for(tmp_path, monkeypatch);root=tmp_path / 'logs' / 'owned-driver-diagnostics' / RUN;root.mkdir(parents=True)
    old=root/('f'*32+'.tmp');old.write_text('retained old bytes')
    monkeypatch.setattr(diag.uuid, 'uuid4', lambda: SimpleNamespace(hex='f'*32))
    monkeypatch.setattr(baseline.subprocess, 'run', lambda command, **kw: subprocess.CompletedProcess(command, 0, 'ok', ''))
    assert store._restore_owned_drivers(data(), time.monotonic() + 10) is None
    assert old.read_text() == 'retained old bytes' and store.owned_driver_observer.incomplete_reason


def test_oversized_record_does_not_publish_or_alter_success(tmp_path, monkeypatch):
    from fakenet.mcp import owned_driver_diagnostics as diag
    store = store_for(tmp_path, monkeypatch)
    original = json.dumps
    def dumps(value, **kwargs):
        if isinstance(value, dict) and 'schema' in value:return 'x' * (diag.MAX_RECORD_BYTES + 1)
        return original(value, **kwargs)
    monkeypatch.setattr(diag, 'json', SimpleNamespace(dumps=dumps))
    monkeypatch.setattr(baseline.subprocess, 'run', lambda command, **kw: subprocess.CompletedProcess(command, 0, 'ok', ''))
    assert store._restore_owned_drivers(data(), time.monotonic() + 10) is None
    assert not records(tmp_path) and store.owned_driver_observer.incomplete_reason


def test_record_write_failure_and_logging_failure_do_not_mask_decode(tmp_path, monkeypatch):
    from fakenet.mcp import owned_driver_diagnostics as diag
    store = store_for(tmp_path, monkeypatch)
    monkeypatch.setattr(diag._LOG, 'warning', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('handler failed')))
    monkeypatch.setattr(diag.os, 'fsync', lambda *a: (_ for _ in ()).throw(OSError('disk write failed')))
    def decode(command, **kw):raise UnicodeDecodeError('utf8', b'\xff', 0, 1, 'original')
    monkeypatch.setattr(baseline.subprocess, 'run', decode)
    with pytest.raises(UnicodeDecodeError):store._restore_owned_drivers(data(), time.monotonic() + 10)
    assert store.owned_driver_observer.incomplete_reason and not records(tmp_path)


def test_platform_encoding_is_original_and_no_duplicate_powershell_prefix(tmp_path, monkeypatch):
    store = store_for(tmp_path, monkeypatch);calls=[]
    def child(command, **kw):calls.append((command,kw));return subprocess.CompletedProcess(command,0,'ok','')
    monkeypatch.setattr(baseline.subprocess,'run',child)
    store._restore_owned_drivers(data(), time.monotonic()+10)
    command,kw=calls[0]
    assert kw['capture_output'] is True and kw['text'] is True and kw['errors']=='strict'
    assert kw['encoding']=='utf-8'
    assert command[-1].count('[Console]::OutputEncoding=')==(1 if os.name=='nt' else 0)
    if os.name=='nt':
        import ctypes
        baseline._run(['cmd.exe','/c','echo','ok'])
        assert calls[1][1]['encoding']=='cp%d'%ctypes.windll.kernel32.GetOEMCP()


def test_observation_scope_does_not_leak_to_other_baseline_commands(tmp_path, monkeypatch):
    store=store_for(tmp_path,monkeypatch)
    monkeypatch.setattr(baseline.subprocess,'run',lambda command,**kw:subprocess.CompletedProcess(command,0,'ok',''))
    store._restore_owned_drivers(data(),time.monotonic()+10)
    baseline._run(['powershell','-NoProfile','-Command','unrelated capture'])
    assert len(records(tmp_path))==1
