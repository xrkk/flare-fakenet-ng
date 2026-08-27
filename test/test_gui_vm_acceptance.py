# -*- coding: utf-8 -*-
"""Fail-closed evidence checks for the GUI VM acceptance runner."""

import importlib.util
import os


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNNER_PATH = os.path.join(
    REPO, 'test', 'gui_vm', 'run_gui_vm_acceptance.py')
SPEC = importlib.util.spec_from_file_location(
    'gui_vm_acceptance_runner', RUNNER_PATH)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


def test_start_log_rejects_v14_exception_and_nonzero_exit():
    content = (
        'FakeNet-NG startup: log=fakenet.log\n'
        'Will seek stop flag at stop.flag\n'
        'FakeNet-NG terminated with an error\n'
        'Traceback (most recent call last):\n'
        "UnboundLocalError: cannot access local variable 'fn_addr'\n"
        'Stopping...\n'
        'FakeNet-NG exiting: rc=1\n')

    ok, detail = acceptance.evaluate_start_log(content)

    assert not ok
    assert '异常终止' in detail


def test_start_log_accepts_success_marker_without_failure():
    ok, detail = acceptance.evaluate_start_log(
        'FakeNet-NG startup: log=fakenet.log\n'
        'FakeNet-NG started successfully\n')

    assert ok
    assert '成功启动' in detail


def test_stop_log_accepts_complete_stop_flag_shutdown():
    content = (
        'FakeNet-NG startup: log=fakenet.log\n'
        'FakeNet-NG started successfully\n'
        'Stop flag found at stop.flag\n'
        'Stopping...\n'
        'FakeNet-NG exiting: rc=0\n')

    ok, detail = acceptance.evaluate_stop_log(content)

    assert ok
    assert 'rc=0' in detail


def test_stop_log_rejects_shutdown_without_stop_flag_evidence():
    content = (
        'FakeNet-NG started successfully\n'
        'Stopping...\n'
        'FakeNet-NG exiting: rc=0\n')

    ok, detail = acceptance.evaluate_stop_log(content)

    assert not ok
    assert 'stop flag' in detail


def test_stop_log_rejects_stopping_cleanup_with_nonzero_exit():
    content = (
        'FakeNet-NG started successfully\n'
        'Stop flag found at stop.flag\n'
        'Stopping...\n'
        'FakeNet-NG exiting: rc=1\n')

    ok, detail = acceptance.evaluate_stop_log(content)

    assert not ok
    assert '非零' in detail


def test_smoke_config_contains_only_one_enabled_raw_listener(tmp_path):
    model, errors = acceptance.build_smoke_config(
        str(tmp_path.joinpath('smoke.ini')))

    enabled = [
        section.name for section in model.listener_sections()
        if section.get('Enabled', '').lower() in ('1', 'yes', 'true', 'on')
    ]
    assert not errors
    assert enabled == ['RawTCPListener']


def test_gui_log_collection_copies_only_session_logs(tmp_path):
    import os
    import time

    logs_root = tmp_path / 'pkgroot' / 'Logs'
    logs_root.mkdir(parents=True)
    old = logs_root / 'fakenet-GUI-old.log'
    old.write_text('old session', encoding='utf-8')
    two_hours_ago = time.time() - 7200
    os.utime(str(old), (two_hours_ago, two_hours_ago))

    before = acceptance.snapshot_gui_logs(str(logs_root))
    assert set(before) == {'fakenet-GUI-old.log'}

    # a fresh GUI log appears (this acceptance session) and the old one is
    # untouched -> only the fresh one is collected
    (logs_root / 'fakenet-GUI-new.log').write_text(
        'new session', encoding='utf-8')
    target = tmp_path / 'evidence' / 'gui-logs'
    copied = acceptance.collect_gui_logs(before, str(logs_root),
                                         str(target))
    assert copied == ['fakenet-GUI-new.log']
    assert (target / 'fakenet-GUI-new.log').read_text(
        encoding='utf-8') == 'new session'
    assert not (target / 'fakenet-GUI-old.log').exists()

    # a pre-existing log modified during the session is collected too
    (logs_root / 'fakenet-GUI-old.log').write_text(
        'old session, appended', encoding='utf-8')
    copied = acceptance.collect_gui_logs(before, str(logs_root),
                                         str(target))
    assert sorted(copied) == ['fakenet-GUI-new.log', 'fakenet-GUI-old.log']


def test_gui_log_collection_handles_missing_root(tmp_path):
    assert acceptance.snapshot_gui_logs(str(tmp_path / 'nope')) == {}
    assert acceptance.collect_gui_logs(
        {}, str(tmp_path / 'nope'), str(tmp_path / 'out')) == []


def test_active_fakenet_images_is_read_only(monkeypatch):
    calls = []

    class FakeProc(object):
        def __init__(self, returncode):
            self.returncode = returncode
            self.stdout = '"fakenet-GUI.exe","1"\n"fakenet.exe","2"\n'

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return FakeProc(0)

    monkeypatch.setattr(acceptance.subprocess, 'run', fake_run)
    active = acceptance.active_fakenet_images()
    assert active == ['fakenet-GUI.exe', 'fakenet.exe']
    assert [cmd for cmd, _ in calls] == [
        ['tasklist.exe', '/FI', 'IMAGENAME eq fakenet-GUI.exe',
         '/FO', 'CSV', '/NH'],
        ['tasklist.exe', '/FI', 'IMAGENAME eq fakenet.exe',
         '/FO', 'CSV', '/NH']]
    assert all(kwargs.get('capture_output') for _, kwargs in calls)


def test_active_fakenet_images_silent_when_not_found(monkeypatch):
    class FakeProc(object):
        returncode = 1
        stdout = 'INFO: No tasks are running'

    monkeypatch.setattr(
        acceptance.subprocess, 'run', lambda cmd, **kwargs: FakeProc())
    assert acceptance.active_fakenet_images() == []


def test_request_gui_close_enumerates_process_windows(monkeypatch):
    calls = []

    class FakeProc(object):
        returncode = 0
        stdout = 'CLOSE_REQUESTED count=1\n'
        stderr = ''

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return FakeProc()

    monkeypatch.setattr(acceptance.subprocess, 'run', fake_run)
    ok, detail = acceptance.request_gui_close()

    assert ok
    assert detail == 'CLOSE_REQUESTED count=1'
    assert calls[0][0][:4] == [
        'powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive']
    command = calls[0][0][-1]
    assert 'EnumWindows' in command
    assert 'GetWindowThreadProcessId' in command
    assert 'PostMessageW' in command
    assert '0x0010' in command
    assert 'CloseMainWindow()' not in command
    assert 'taskkill' not in command.lower()


def test_stop_gui_smoke_exe_closes_child_without_terminate(monkeypatch):
    class FakeGuiProc(object):
        returncode = None

        def poll(self):
            return None

        def terminate(self):
            raise AssertionError('formal exe cleanup must be graceful')

        def wait(self, timeout):
            self.returncode = 0
            return 0

    requests = iter(((False, 'NO_TOP_LEVEL_WINDOW'),
                     (True, 'CLOSE_REQUESTED count=1')))
    images = iter((['fakenet-GUI.exe'], []))
    monkeypatch.setattr(
        acceptance, 'request_gui_close',
        lambda: next(requests))
    monkeypatch.setattr(
        acceptance, 'active_fakenet_images', lambda: next(images, []))

    def fake_wait(predicate, timeout, interval=1.0):
        for _unused in range(3):
            if predicate():
                return True
        return False

    monkeypatch.setattr(
        acceptance, 'wait_for', fake_wait)

    ok, detail = acceptance.stop_gui_smoke(FakeGuiProc(), 'exe')

    assert ok
    assert detail == 'CLOSE_REQUESTED count=1;进程已退出'


def test_formal_preflight_refusal_is_persisted_for_the_next_export():
    runner = open(RUNNER_PATH, 'r', encoding='utf-8').read()
    diagnostic_path = os.path.join(
        REPO, 'test', 'gui_vm', 'run_vm_diagnostics.py')
    diagnostic = open(diagnostic_path, 'r', encoding='utf-8').read()
    exporter_path = os.path.join(REPO, 'test', 'gui_vm', 'Export-Logs.ps1')
    exporter = open(exporter_path, 'r', encoding='utf-8-sig').read()

    for marker in (
            'preflight-refused-', 'refusal-transcript.txt',
            'refusal-evidence.json', 'exit_code', 'network_unchanged',
            'core_not_started'):
        assert marker in runner
    assert 'transcript_sink' in diagnostic
    assert 'Logs\\preflight-refused-*' in exporter


def test_a11_uses_exact_sink_divert_matching_at_the_call_site():
    source = open(RUNNER_PATH, 'r', encoding='utf-8').read()
    a11 = source[source.index('def run_a11_sink_reply'):
                 source.index('\ndef ', source.index('def run_a11_sink_reply') + 1)]

    assert 'local_divert = policy.divert_fake_logged(log_text, sink)' in a11
    assert "'original_ip=%s' % sink in log_text" not in a11


def test_preflight_refusal_evidence_proves_no_network_or_core_change(
        monkeypatch, tmp_path):
    import json
    import sys
    import types

    session_path = tmp_path / 'Logs' / 'fnpr-active-session.json'

    def capture(path, label):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(label + '\n')
        return {
            'dns-client': (0, 'dns-original'),
            'route-ipv4': (0, 'route-original'),
        }

    def wait(transcript_sink=None):
        transcript_sink.extend([
            '[ACTION REQUIRED 1/1]',
            '[REFUSED] Ubuntu Sentinel 前置失败',
            '未启动 GUI，未修改 Windows 网络。',
        ])
        return False, 'diag-refused', {
            'tcp': {'ok': False, 'detail': 'unreachable'},
            'udp': {'ok': False, 'detail': 'unreachable'},
        }

    def write_json(path, value):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump(value, handle)

    diagnostic = types.SimpleNamespace(
        SENTINEL_IPV4='192.168.204.1', SENTINEL_PORT=443,
        capture_network_snapshot=capture, wait_for_sentinel=wait,
        write_json=write_json,
        package_identity=lambda: {'source_commit': 'test-commit'})
    monkeypatch.setitem(sys.modules, 'run_vm_diagnostics', diagnostic)
    monkeypatch.setattr(
        acceptance, 'fnpr_session_path', lambda: str(session_path))
    monkeypatch.setattr(acceptance, 'active_fakenet_images', lambda: [])

    ok, nonce, transports, evidence_path = \
        acceptance.preflight_fnpr_sentinel()

    assert not ok
    assert nonce == 'diag-refused'
    assert not transports['tcp']['ok'] and not transports['udp']['ok']
    evidence = json.loads(open(
        evidence_path, 'r', encoding='utf-8').read())
    assert evidence['exit_code'] == acceptance.EXIT_REFUSED
    assert evidence['network_unchanged']
    assert evidence['core_not_started']
    transcript = open(
        evidence['transcript'], 'r', encoding='utf-8').read()
    assert '[REFUSED]' in transcript
    assert '[EVIDENCE]' in transcript


def test_export_logs_collects_package_root_artifacts(tmp_path):
    import datetime
    import shutil
    import subprocess

    layout = tmp_path / 'pkg'
    gui_vm = layout / 'test' / 'gui_vm'
    gui_vm.mkdir(parents=True)
    shutil.copyfile(
        os.path.join(REPO, 'test', 'gui_vm', 'Export-Logs.ps1'),
        str(gui_vm / 'Export-Logs.ps1'))
    (layout / 'Logs').mkdir()
    config = layout / 'configs' / 'manual.ini'
    config.parent.mkdir()
    config.write_text('[FakeNet]\nDivertTraffic: Yes\n', encoding='utf-8')
    (layout / 'Logs' / 'fakenet-1.log').write_text(
        'Loaded configuration file: %s\n'
        'STOP_PHASE_BEGIN phase=complete\n'
        'STOP_PROVIDER_BEGIN name=DomainEgressRelay\n' % config,
        encoding='utf-8')
    (layout / 'Logs' / 'fakenet-GUI-1.log').write_text('gui')
    old_log = layout / 'Logs' / 'fakenet-old.log'
    old_log.write_text('old session', encoding='utf-8')
    old_time = datetime.datetime.now().timestamp() - 3600
    os.utime(str(old_log), (old_time, old_time))
    (layout / 'packets_x.pcap').write_bytes(b'pcap')
    (layout / 'report_x.html').write_text('report')
    (layout / 'noise.txt').write_text('ignored')

    since_utc = (datetime.datetime.now(datetime.timezone.utc) -
                 datetime.timedelta(seconds=60)).isoformat().replace(
                     '+00:00', 'Z')
    proc = subprocess.run(
        ['powershell.exe', '-NoLogo', '-NoProfile', '-ExecutionPolicy',
         'Bypass', '-File', str(gui_vm / 'Export-Logs.ps1'),
         '-SinceUtc', since_utc, '-SessionLabel', 'diagnostic'],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr

    exports = list((layout / 'test' / 'gui_vm' / 'Logs').glob(
        'diagnostic-export-*'))
    if (not exports and os.environ.get('WINEPREFIX') and
            not proc.stdout and not proc.stderr):
        import pytest
        pytest.skip('Wine powershell.exe stub did not execute the script')
    assert len(exports) == 1, (proc.stdout, proc.stderr)
    names = {p.name for p in exports[0].iterdir()}
    assert names == {
        'config-01-manual.ini', 'config-sources.tsv',
        'evidence-sha256.tsv', 'fakenet-1.log', 'fakenet-GUI-1.log',
        'packets_x.pcap', 'report_x.html', 'stop-diagnosis.txt'}
    assert (exports[0] / 'config-01-manual.ini').read_text(
        encoding='utf-8-sig') == '[FakeNet]\nDivertTraffic: Yes\n'
    hashes = (exports[0] / 'evidence-sha256.tsv').read_text(
        encoding='utf-8-sig')
    assert 'config-01-manual.ini' in hashes
    assert 'stop-diagnosis.txt' in hashes
    diagnosis = (exports[0] / 'stop-diagnosis.txt').read_text(
        encoding='utf-8-sig')
    assert 'status=unclosed-stop-boundary' in diagnosis
    assert 'STOP_PROVIDER_BEGIN name=DomainEgressRelay' in diagnosis
    assert 'fakenet-old.log' not in names
    assert 'EVIDENCE_PATH=' in proc.stdout
