# -*- coding: utf-8 -*-
"""Core startup logging behavior (plan v1.3 §12.7)."""

import os
import subprocess
import sys


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_frozen_core_start_writes_one_log_beside_exe_from_any_cwd(tmp_path):
    release_dir = tmp_path.joinpath('release')
    release_dir.mkdir()
    fake_exe = release_dir.joinpath('fakenet.exe')
    launch_dir = tmp_path.joinpath('arbitrary-cwd')
    launch_dir.mkdir()
    script = (
        'import sys\n'
        'from fakenet import fakenet\n'
        'sys.frozen = True\n'
        'sys.executable = r"%s"\n'
        'sys.argv = [r"%s", "--help"]\n'
        'fakenet.main()\n' % (str(fake_exe), str(fake_exe)))
    environment = os.environ.copy()
    environment['PYTHONPATH'] = REPO

    completed = subprocess.run(
        [sys.executable, '-c', script], cwd=str(launch_dir),
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    assert completed.returncode == 0
    files = list(release_dir.joinpath('Logs').glob('*.log'))
    assert len(files) == 1
    content = files[0].read_text(encoding='utf-8')
    assert 'FakeNet-NG startup' in content
    assert 'executable=%s' % fake_exe in content
    assert 'cwd=%s' % launch_dir in content


def test_explicit_log_file_is_the_only_file_even_when_help_exits_early(
        tmp_path):
    release_dir = tmp_path.joinpath('release')
    release_dir.mkdir()
    fake_exe = release_dir.joinpath('fakenet.exe')
    explicit_log = tmp_path.joinpath('requested.log')
    script = (
        'import sys\n'
        'from fakenet import fakenet\n'
        'sys.frozen = True\n'
        'sys.executable = r"%s"\n'
        'sys.argv = [r"%s", "--log-file", r"%s", "--help"]\n'
        'fakenet.main()\n'
        % (str(fake_exe), str(fake_exe), str(explicit_log)))
    environment = os.environ.copy()
    environment['PYTHONPATH'] = REPO

    completed = subprocess.run(
        [sys.executable, '-c', script], env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    assert completed.returncode == 0
    assert explicit_log.is_file()
    assert not release_dir.joinpath('Logs').exists()
    content = explicit_log.read_text(encoding='utf-8')
    assert 'FakeNet-NG startup' in content


def test_core_failure_traceback_is_written_to_automatic_log(tmp_path):
    release_dir = tmp_path.joinpath('release')
    release_dir.mkdir()
    fake_exe = release_dir.joinpath('fakenet.exe')
    script = (
        'import sys\n'
        'from fakenet import fakenet\n'
        'sys.frozen = True\n'
        'sys.executable = r"%s"\n'
        'sys.argv = [r"%s", "-c", "missing.ini", "--no-pause", '
        '"--no-console-output"]\n'
        'fakenet.main()\n' % (str(fake_exe), str(fake_exe)))
    environment = os.environ.copy()
    environment['PYTHONPATH'] = REPO

    completed = subprocess.run(
        [sys.executable, '-c', script], env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    assert completed.returncode == 1
    files = list(release_dir.joinpath('Logs').glob('*.log'))
    assert len(files) == 1
    content = files[0].read_text(encoding='utf-8')
    assert 'Could not open configuration file' in content
    assert 'FakeNet-NG terminated with an error' in content
    assert 'SystemExit: 1' in content
    assert 'FakeNet-NG exiting: rc=1' in content
    assert 'FakeNet-NG started successfully' not in content


def test_successful_start_is_recorded_before_stop_flag_shutdown(tmp_path):
    config_path = tmp_path.joinpath('minimal.ini')
    log_path = tmp_path.joinpath('fakenet.log')
    stop_flag = tmp_path.joinpath('stop.flag')
    config_path.write_text(
        '[FakeNet]\n'
        'DivertTraffic: No\n'
        '\n'
        '[Diverter]\n'
        'NetworkMode: SingleHost\n'
        '\n'
        '[AnonymousTCPListener]\n'
        'Enabled: True\n'
        'Port: 1337\n'
        'Protocol: TCP\n',
        encoding='ascii')
    stop_flag.write_text('stop\n', encoding='ascii')
    script = (
        'import sys\n'
        'from fakenet import fakenet\n'
        'sys.argv = ["fakenet", "--config-file", r"%s", '
        '"--log-file", r"%s", "--stop-flag", r"%s", '
        '"--no-pause", "--no-console-output"]\n'
        'fakenet.main()\n'
        % (str(config_path), str(log_path), str(stop_flag)))
    environment = os.environ.copy()
    environment['PYTHONPATH'] = REPO

    completed = subprocess.run(
        [sys.executable, '-c', script], env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    assert completed.returncode == 0
    content = log_path.read_text(encoding='utf-8')
    assert content.count('FakeNet-NG started successfully') == 1
    assert 'Stop flag found at' in content
    assert 'FakeNet-NG exiting: rc=0' in content
