# -*- coding: utf-8 -*-
"""Structured all-log grid checks using the real file log format."""

import tkinter as tk

from fakenet.gui import logview


STARTUP_LINE = (
    '09/01/26 09:06:19 PM [INFO    ] [              root] '
    'pid=6832 thread=MainThread FakeNet-NG startup: log=C:\\Logs\\run.log')
ERROR_LINE = (
    '09/01/26 09:06:20 PM [CRITICAL] [          Diverter] '
    'pid=6832 thread=MainThread Invalid EgressControl configuration: '
    'ExternalTakeoverIPv4 cannot equal ExternalDnsServer')
EXIT_LINE = (
    '09/01/26 09:06:20 PM [INFO    ] [              root] '
    'pid=6832 thread=MainThread FakeNet-NG exiting: rc=1')


def test_parse_log_line_exposes_logger_pid_not_only_flow_pid():
    row = logview.parse_log_line(ERROR_LINE)
    assert row == {
        'time': '09/01/26 09:06:20 PM',
        'level': 'CRITICAL',
        'logger': 'Diverter',
        'pid': '6832',
        'thread': 'MainThread',
        'message': ('Invalid EgressControl configuration: '
                    'ExternalTakeoverIPv4 cannot equal ExternalDnsServer'),
    }


class WindowFixture(object):
    def __init__(self, file_path=None):
        self.file_path = file_path

    def __enter__(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.view = logview.LogGridWindow(
            self.root, None, file_path=self.file_path)
        self.view.window.withdraw()
        self.root.update_idletasks()
        return self.view

    def __exit__(self, *_exc):
        try:
            self.view.window.destroy()
        finally:
            self.root.destroy()
        return False


def test_pid_filter_finds_current_fakenet_process_and_traceback_context():
    text = '\n'.join([
        STARTUP_LINE,
        ERROR_LINE,
        'Traceback (most recent call last):',
        '  File "fakenet.py", line 722, in main',
        EXIT_LINE,
    ]) + '\n'
    with WindowFixture() as view:
        view.feed(text)
        assert len(view.rows) == 3
        assert 'Traceback' in view.rows[1]['message']
        view.pid_var.set('6832')
        view._filters_changed()
        assert len(view.visible_rows()) == 3
        view.pid_var.set('9999')
        view._filters_changed()
        assert view.visible_rows() == []


def test_opening_grid_backfills_existing_current_log(tmp_path):
    path = tmp_path / 'finished.log'
    path.write_text('\n'.join([STARTUP_LINE, ERROR_LINE, EXIT_LINE]) + '\n',
                    encoding='utf-8')
    with WindowFixture(str(path)) as view:
        assert len(view.rows) == 3
        assert {row['pid'] for row in view.rows} == {'6832'}
