"""Actual capture producer/report checks; runtime and control boundaries are seams."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import threading
from unittest.mock import Mock
import pytest

import runpy
_helpers = runpy.run_path(str(Path(__file__).with_name('test_capture_originals.py')))
make_diverter, tcp_packet = _helpers['make_diverter'], _helpers['tcp_packet']
from fakenet.mcp import captureseal
from fakenet.payload_report import load_capture_originals


def ready_capture(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    diverter = make_diverter(tmp_path)
    packet = tcp_packet('192.0.2.10', '198.51.100.20', 43001, 80, 10,
                        b'GET /checkpoint HTTP/1.0\r\n\r\n')
    diverter.record_raw_capture(packet, logical_packet_id='checkpoint-1')
    return diverter, packet


def test_checkpoint_produces_real_files_without_platform_stop(tmp_path, monkeypatch):
    diverter, packet = ready_capture(tmp_path, monkeypatch)
    platform_stop = Mock(side_effect=AssertionError('must retain routing'))
    diverter.stopCallback = platform_stop
    checkpoint = diverter.seal_capture_outputs()
    assert checkpoint['capture_interval_complete'] is True
    assert checkpoint['recording_continues'] is False
    assert {v['role'] for v in checkpoint['files']} == {
        'raw', 'converted', 'observations', 'nbis', 'seal', 'html'}
    files = {v['role']: Path(v['path']) for v in checkpoint['files']}
    loaded = load_capture_originals(files['raw'], files['converted'])
    assert loaded.capture_id == checkpoint['capture_id']
    assert len(loaded.entries) == 1
    before = {k: p.read_bytes() for k, p in files.items()}
    assert diverter.record_raw_capture(packet, logical_packet_id='checkpoint-2') is False
    diverter.logNbi(12345, {'late': 'not recorded'}, 'TCP', 'http', False)
    assert {k: p.read_bytes() for k, p in files.items()} == before
    assert diverter.seal_capture_outputs() == checkpoint
    assert diverter._generate_reports() is None
    platform_stop.assert_not_called()


def test_checkpoint_replay_rejects_changed_original(tmp_path, monkeypatch):
    diverter, _ = ready_capture(tmp_path, monkeypatch)
    checkpoint = diverter.seal_capture_outputs()
    path = Path(next(v['path'] for v in checkpoint['files'] if v['role'] == 'html'))
    path.write_bytes(path.read_bytes() + b'changed')
    with pytest.raises(ValueError, match='original changed'):
        diverter.seal_capture_outputs()


def test_checkpoint_replay_rejects_link(tmp_path, monkeypatch):
    diverter, _ = ready_capture(tmp_path, monkeypatch)
    checkpoint = diverter.seal_capture_outputs()
    path = Path(next(v['path'] for v in checkpoint['files'] if v['role'] == 'html'))
    target = tmp_path / 'controlled-copy'; target.write_bytes(path.read_bytes())
    path.unlink(); path.symlink_to(target)
    with pytest.raises(ValueError, match='linked'):
        diverter.seal_capture_outputs()


def test_ipc_matches_real_process_birth_and_command(tmp_path, monkeypatch):
    diverter, _ = ready_capture(tmp_path, monkeypatch)
    tmp_path.chmod(0o700)  # controlled fixture models a protected product root
    logs = tmp_path / 'Logs'; monkeypatch.setattr(captureseal, 'BASE_LOGS', logs)
    root = captureseal.create_control('a' * 32)
    proc = SimpleNamespace(pid=os.getpid(), poll=lambda: None)
    fakenet = SimpleNamespace(diverter=diverter)
    def prefix(root, request):
        path = root / 'seam-prefix.log'; path.write_bytes(b'local-control-seam\n')
        return dict(captureseal.file_fact(path), role='log'), {'whole_run_complete': False}
    monkeypatch.setattr(captureseal, '_log_prefix', prefix)
    output = []
    command = '88888888-1111-4222-8333-555555555555'
    def request():
        output.append(captureseal.request_checkpoint(root, proc, command, timeout=5))
    task = threading.Thread(target=request); task.start()
    # Bounded local seam wait for its one control file; not a native trial.
    import time
    deadline = time.monotonic() + 5
    while not list(root.glob('request-*.json')) and time.monotonic() < deadline:
        time.sleep(0.001)
    captureseal.service_capture_request(fakenet, root)
    task.join(5)
    assert not task.is_alive() and len(output) == 1
    assert output[0]['process']['pid'] == os.getpid()
    assert output[0]['capture_interval_complete'] is True
    # Same command only reads its existing result, no second producer close.
    assert captureseal.request_checkpoint(root, proc, command)['capture_id'] == output[0]['capture_id']


def test_ipc_rejects_foreign_birth_before_producer(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)  # controlled fixture models a protected product root
    logs = tmp_path / 'Logs'; monkeypatch.setattr(captureseal, 'BASE_LOGS', logs)
    root = captureseal.create_control('b' * 32)
    command = '99999999-1111-4222-8333-555555555555'
    captureseal._write(root / ('request-' + command + '.json'), dict(
        schema='fakenet.capture-control.v1', command_id=command,
        pid=os.getpid(), birth='0', run_id='b' * 32))
    diverter = Mock()
    with pytest.raises(ValueError, match='not bound to this process'):
        captureseal.service_capture_request(SimpleNamespace(diverter=diverter), root)
    diverter.seal_capture_outputs.assert_not_called()
    assert not list(root.glob('response-*.json'))


def test_ipc_timeout_preserves_submitted_command_without_resend(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)  # controlled fixture models a protected product root
    logs = tmp_path / 'Logs'; monkeypatch.setattr(captureseal, 'BASE_LOGS', logs)
    root = captureseal.create_control('c' * 32)
    proc = SimpleNamespace(pid=os.getpid(), poll=lambda: None)
    command = '77777777-1111-4222-8333-555555555555'
    with pytest.raises(TimeoutError, match='outcome unknown; do not resend'):
        captureseal.request_checkpoint(root, proc, command, timeout=0.01)
    paths = list(root.glob('request-*.json'))
    assert len(paths) == 1 and not list(root.glob('response-*.json'))


def test_queued_callback_cannot_append_after_capture_fence(tmp_path, monkeypatch):
    diverter, packet = ready_capture(tmp_path, monkeypatch)
    results=[]
    with diverter._capture_write_lock:
        worker=threading.Thread(target=lambda:results.append(
            diverter.record_raw_capture(packet, logical_packet_id='queued-tail')))
        worker.start()
        checkpoint=diverter.seal_capture_outputs()
        first={x['path']:Path(x['path']).read_bytes() for x in checkpoint['files']}
    worker.join(5)
    assert not worker.is_alive() and results==[False]
    assert {name:Path(name).read_bytes() for name in first}==first


def test_ipc_writable_parent_rejected(tmp_path, monkeypatch):
    logs=tmp_path/'Logs';logs.mkdir();logs.chmod(0o777)
    monkeypatch.setattr(captureseal,'BASE_LOGS',logs)
    with pytest.raises(ValueError,match='writable capture control parent'):
        captureseal.create_control('d'*32)


def test_control_json_is_only_visible_after_complete_write(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    logs=tmp_path/'Logs';monkeypatch.setattr(captureseal,'BASE_LOGS',logs)
    root=captureseal.create_control('e'*32)
    target=root/'request.json';real_replace=os.replace;seen=[]
    def observe_publish(src,dst):
        assert not target.exists()
        assert json.loads(Path(src).read_text())=={'complete':'closed JSON'}
        seen.append(True);return real_replace(src,dst)
    monkeypatch.setattr(captureseal.os,'replace',observe_publish)
    captureseal._write(target,{'complete':'closed JSON'})
    assert seen==[True] and captureseal._read(target)=={'complete':'closed JSON'}
    with pytest.raises(ValueError,match='already published'):
        captureseal._write(target,{'different':'must not overwrite'})
    assert captureseal._read(target)=={'complete':'closed JSON'}
