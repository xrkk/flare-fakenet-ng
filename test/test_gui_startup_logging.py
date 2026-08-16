# -*- coding: utf-8 -*-
"""GUI entry-point logging regressions."""

import os
import subprocess
import sys
import datetime

from fakenet.gui import startup_logging


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_reserve_fakenet_log_is_unique_under_exe_sibling_logs(tmp_path):
    stamp = datetime.datetime(2026, 8, 16, 12, 34, 56, 789000)
    first = startup_logging.reserve_fakenet_log_path(
        now=stamp, pid=42, base_dir=str(tmp_path))
    second = startup_logging.reserve_fakenet_log_path(
        now=stamp, pid=42, base_dir=str(tmp_path))
    assert os.path.dirname(first) == str(tmp_path / 'Logs')
    assert os.path.basename(first) == \
        'fakenet-20260816-123456-789000-gui-p42.log'
    assert second.endswith('-1.log')
    assert os.path.isfile(first) and os.path.isfile(second)


def test_duplicate_gui_instance_activates_existing_and_releases_mutex(
        monkeypatch):
    from fakenet.gui import main

    class Logger(object):
        def info(self, *_args):
            pass

        def warning(self, *_args):
            pass

        def exception(self, *_args):
            pass

    closed = []
    monkeypatch.setattr(main.startup_logging, 'configure',
                        lambda: (Logger(), 'gui.log'))
    monkeypatch.setattr(main, '_close_splash', lambda: None)
    monkeypatch.setattr(main.launcher if hasattr(main, 'launcher') else
                        __import__('fakenet.gui.launcher', fromlist=['x']),
                        'acquire_gui_mutex', lambda: (77, True))
    from fakenet.gui import launcher
    monkeypatch.setattr(launcher, 'activate_existing_gui', lambda: True)
    monkeypatch.setattr(launcher, 'close_handle', closed.append)
    assert main.main() == 0
    assert closed == [77]


def test_duplicate_gui_instance_warns_only_when_activation_fails(monkeypatch):
    from fakenet.gui import launcher, main

    class Logger(object):
        def info(self, *_args):
            pass

        def warning(self, *_args):
            pass

        def exception(self, *_args):
            pass

    warnings = []
    closed = []
    monkeypatch.setattr(main.startup_logging, 'configure',
                        lambda: (Logger(), 'gui.log'))
    monkeypatch.setattr(main, '_close_splash', lambda: None)
    monkeypatch.setattr(main, '_native_warning',
                        lambda title, message: warnings.append(
                            (title, message)))
    monkeypatch.setattr(launcher, 'acquire_gui_mutex', lambda: (88, True))
    monkeypatch.setattr(launcher, 'activate_existing_gui', lambda: False)
    monkeypatch.setattr(launcher, 'close_handle', closed.append)
    assert main.main() == 1
    assert closed == [88]
    assert len(warnings) == 1 and '无法激活' in warnings[0][1]


def test_frozen_gui_creates_one_sibling_log_before_tk_startup(tmp_path):
    release = tmp_path / 'release'
    release.mkdir()
    fake_exe = release / 'fakenet-GUI.exe'
    elsewhere = tmp_path / 'elsewhere'
    elsewhere.mkdir()

    script = r'''
import builtins
import sys

sys.frozen = True
sys.executable = sys.argv[1]
real_import = builtins.__import__

def blocked_import(name, *args, **kwargs):
    if name == 'tkinter' or name.startswith('tkinter.'):
        raise ImportError('forced missing tkinter')
    return real_import(name, *args, **kwargs)

builtins.__import__ = blocked_import
from fakenet.gui import main
raise SystemExit(main.main())
'''
    env = os.environ.copy()
    env['PYTHONPATH'] = REPO
    completed = subprocess.run(
        [sys.executable, '-c', script, str(fake_exe)],
        cwd=str(elsewhere), env=env, capture_output=True, text=True,
        timeout=30)

    assert completed.returncode == 1
    logs = list((release / 'Logs').glob('fakenet-GUI-*.log'))
    assert len(logs) == 1
    content = logs[0].read_text(encoding='utf-8')
    assert 'fakenet-GUI' in content
    assert 'tkinter' in content
