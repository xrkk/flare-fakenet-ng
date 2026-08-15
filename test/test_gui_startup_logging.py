# -*- coding: utf-8 -*-
"""GUI entry-point logging regressions."""

import os
import subprocess
import sys


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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
