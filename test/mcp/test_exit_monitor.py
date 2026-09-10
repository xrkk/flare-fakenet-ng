import time

import pytest

from fakenet.mcp import exit_files, exit_guard, exit_monitor, exit_native, service_stop


@pytest.fixture
def monitor_scene(tmp_path, monkeypatch):
    run = '85fa5b14-fdd5-4867-886a-4ebc5b8e074d'
    record = dict(schema='fakenet.exit-target.v1', run_id=run, pid=42, supervisor_pid=40,
                  creation_time='1234', supervisor_creation_time='1230',
                  supervisor_instance='current', budget_seconds=60,
                  image=r'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp-managed.exe',
                  command_line='exact actual managed command line')
    directory = tmp_path / run
    directory.mkdir()
    exit_files.publish(tmp_path / 'target.json', record)
    events = []

    class Gate:
        def acquire(self):
            events.append('gate')
            return True

        def close(self):
            events.append('gate-close')

    class Target:
        def __init__(self, pid):
            events.append('target-open')

        def identity(self):
            return {key: record[key] for key in ('pid', 'creation_time', 'image')}

        def command_line(self):
            return record['command_line']

        def dump(self, path, **kwargs):
            path.write_bytes(b'partial')
            raise OSError('injected target dump failure')

        def close(self):
            events.append('target-close')

    monkeypatch.setattr(exit_guard, 'SingleFlight', Gate)
    monkeypatch.setattr(exit_native, 'TargetHandle', Target)
    monkeypatch.setattr(exit_files, 'root', lambda: tmp_path)
    monkeypatch.setattr(service_stop, 'process_identity', lambda: dict(pid=44,
        creation_time=str(int((time.time() + 11644473600) * 10000000))))
    publish = exit_files.publish
    def owner_ack(path, value):
        publish(path, value)
        if path.name == 'entry.json':
            publish(directory / 'owner-acquired.json', dict(target=record, helper=value['helper']))
    monkeypatch.setattr(exit_files, 'publish', owner_ack)
    return tmp_path, directory, record, events, Gate, Target


def test_busy_entry_opens_no_target_and_writes_nothing(monitor_scene, monkeypatch):
    root, directory, record, events, Gate, Target = monitor_scene
    monkeypatch.setattr(Gate, 'acquire', lambda self: False)
    before = set(root.rglob('*'))
    assert exit_monitor.main(['42', '50', '51', '1']) == 3
    assert 'target-open' not in events
    assert set(root.rglob('*')) == before


def test_foreign_notification_rejects_before_target_open(monitor_scene):
    root, directory, record, events, Gate, Target = monitor_scene
    before = set(root.rglob('*'))
    assert exit_monitor.main(['43', '50', '51', '1']) == 3
    assert 'target-open' not in events
    assert set(root.rglob('*')) == before


def test_creation_mismatch_closes_target_without_output(monitor_scene, monkeypatch):
    root, directory, record, events, Gate, Target = monitor_scene
    monkeypatch.setattr(Target, 'identity', lambda self: dict(creation_time='1235'))
    before = set(root.rglob('*'))
    assert exit_monitor.main(['42', '50', '51', '1']) == 3
    assert events == ['gate', 'target-open', 'target-close', 'gate-close']
    assert set(root.rglob('*')) == before


def test_failed_dump_is_explicit_and_duplicate_does_not_repeat_it(monitor_scene):
    root, directory, record, events, Gate, Target = monitor_scene
    assert exit_monitor.main(['42', '50', '51', '1']) == 2
    result = exit_files.read(directory / 'result.json')
    assert result['complete'] is False
    assert 'injected target dump failure' in result['error']
    assert not (directory / 'target.dmp').exists()
    assert (directory / 'target.dmp.partial').read_bytes() == b'partial'
    assert events == ['gate', 'target-open', 'target-close', 'gate-close']
    before = {path: path.read_bytes() for path in root.rglob('*') if path.is_file()}
    assert exit_monitor.main(['42', '50', '51', '1']) == 3
    assert events.count('target-open') == 1
    assert {path: path.read_bytes() for path in root.rglob('*') if path.is_file()} == before
