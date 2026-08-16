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
