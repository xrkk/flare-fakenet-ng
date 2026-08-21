# -*- coding: utf-8 -*-
"""Stop button behaviour checks (plan 2026.08.21-01 I4/I9.3).

Covers the three button states, the stop-flag content written on click,
and the explorer /select,<report> single-argument call captured via
monkeypatched Popen (audit A-06 form).
"""

import codecs
import os
import time
import tkinter
from unittest import mock


def _construct_app():
    from fakenet.gui.app import FakenetConfigApp

    root = tkinter.Tk()
    root.withdraw()
    application = FakenetConfigApp(root)
    root.update_idletasks()
    return root, application


def _is_disabled(button):
    return button.instate(['disabled'])


def _simulate_log_tab(application, tmp_path):
    # A real session always builds the log tab (_begin_fakenet_session);
    # mirror that before driving _finish_fakenet_session directly.
    application._ensure_tab(4)
    application._fakenet_log_path = str(tmp_path / 'none.log')
    application._log_decoder = codecs.getincrementaldecoder('utf-8')(
        errors='replace')
    application._log_offset = 0
    application._log_job = None
    application._log_large_warned = False


def test_stop_button_disabled_without_session():
    root, application = _construct_app()
    try:
        assert application._fakenet_process_handle is None
        assert _is_disabled(application.stop_button)
        application._update_action_states()
        assert _is_disabled(application.stop_button)
    finally:
        root.destroy()


def test_stop_button_enabled_with_pending_handle():
    root, application = _construct_app()
    try:
        application._fakenet_process_handle = mock.Mock()
        application._update_action_states()
        assert not _is_disabled(application.stop_button)

        application._stop_pending = True
        application._update_action_states()
        assert _is_disabled(application.stop_button)
    finally:
        root.destroy()


def test_request_stop_writes_flag_content_and_sets_state(tmp_path):
    root, application = _construct_app()
    try:
        flag = tmp_path / 'session.log.stopflag'
        application._fakenet_log_path = str(tmp_path / 'session.log')
        application._fakenet_stop_flag = str(flag)
        application._fakenet_process_handle = mock.Mock()

        application._request_stop()

        assert application._stop_pending is True
        assert flag.read_text(encoding='ascii') == 'stop\n'

        # No handle -> no-op even if called directly.
        application._stop_pending = False
        application._fakenet_process_handle = None
        application._request_stop()
        assert application._stop_pending is False
        assert flag.read_text(encoding='ascii') == 'stop\n'
    finally:
        root.destroy()


def test_finish_opens_explorer_selecting_session_report(
        tmp_path, monkeypatch):
    root, application = _construct_app()
    try:
        work_dir = tmp_path / 'release'
        work_dir.mkdir()
        stale = work_dir / 'report_20200101_000000.html'
        stale.write_text('old', encoding='ascii')
        fresh = work_dir / 'report_20260821_120000.html'
        fresh.write_text('new', encoding='ascii')
        os.utime(str(stale), (1000000, 1000000))
        os.utime(str(fresh), (time.time(), time.time()))

        popen_calls = []
        monkeypatch.setattr(
            'fakenet.gui.app.subprocess.Popen',
            lambda args, *_a, **_k: popen_calls.append(args) or mock.Mock())
        startfile_calls = []
        monkeypatch.setattr(
            'fakenet.gui.app.os.startfile',
            lambda path: startfile_calls.append(path))

        application._fakenet_work_dir = str(work_dir)
        application._fakenet_session_start = time.time() - 60
        _simulate_log_tab(application, tmp_path)
        handle = mock.Mock()
        application._fakenet_process_handle = handle
        application._stop_pending = True

        application._finish_fakenet_session(handle, 0, None)

        assert application._stop_pending is False
        assert len(popen_calls) == 1
        args = popen_calls[0]
        assert len(args) == 2
        assert args[0] == 'explorer'
        assert args[1] == '/select,%s' % os.path.normpath(str(fresh))
        assert startfile_calls == []
    finally:
        root.destroy()


def test_finish_falls_back_to_directory_without_report(
        tmp_path, monkeypatch):
    root, application = _construct_app()
    try:
        work_dir = tmp_path / 'release'
        work_dir.mkdir()
        popen_calls = []
        monkeypatch.setattr(
            'fakenet.gui.app.subprocess.Popen',
            lambda args, *_a, **_k: popen_calls.append(args) or mock.Mock())
        startfile_calls = []
        monkeypatch.setattr(
            'fakenet.gui.app.os.startfile',
            lambda path: startfile_calls.append(path))

        application._fakenet_work_dir = str(work_dir)
        application._fakenet_session_start = time.time() - 60
        _simulate_log_tab(application, tmp_path)
        handle = mock.Mock()
        application._fakenet_process_handle = handle
        application._stop_pending = True

        application._finish_fakenet_session(handle, 0, None)

        assert popen_calls == []
        assert startfile_calls == [str(work_dir)]
        assert application._stop_pending is False
    finally:
        root.destroy()


def test_finish_without_stop_request_skips_report_reveal(
        tmp_path, monkeypatch):
    root, application = _construct_app()
    try:
        work_dir = tmp_path / 'release'
        work_dir.mkdir()
        popen_calls = []
        monkeypatch.setattr(
            'fakenet.gui.app.subprocess.Popen',
            lambda args, *_a, **_k: popen_calls.append(args) or mock.Mock())

        application._fakenet_work_dir = str(work_dir)
        application._fakenet_session_start = None
        _simulate_log_tab(application, tmp_path)
        handle = mock.Mock()
        application._fakenet_process_handle = handle
        application._stop_pending = False

        application._finish_fakenet_session(handle, 0, None)

        assert popen_calls == []
    finally:
        root.destroy()
