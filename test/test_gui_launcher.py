# -*- coding: utf-8 -*-
"""Launcher gate tests (plan v0.2 §6): VM three-state parsing, duplicate
detection contract, path injection rejection, settings/locate fallback."""

import os
import uuid

import pytest

from fakenet.gui import launcher


def test_parse_vm_state_known_vms():
    assert launcher.parse_vm_state(
        'innotek GmbH', 'VirtualBox').verdict == launcher.VERDICT_VM
    assert launcher.parse_vm_state(
        'VMware, Inc.', 'VMware7,1').verdict == launcher.VERDICT_VM
    assert launcher.parse_vm_state(
        'Microsoft Corporation', 'Virtual Machine').verdict == \
        launcher.VERDICT_VM
    assert launcher.parse_vm_state(
        'QEMU', 'Standard PC (i440FX + PIIX, 1996)').verdict == \
        launcher.VERDICT_VM


def test_parse_vm_state_physical():
    assert launcher.parse_vm_state(
        'Dell Inc.', 'OptiPlex 7090').verdict == launcher.VERDICT_PHYSICAL
    assert launcher.parse_vm_state(
        'LENOVO', '20XW').verdict == launcher.VERDICT_PHYSICAL


def test_parse_vm_state_unknown():
    assert launcher.parse_vm_state('', '').verdict == launcher.VERDICT_UNKNOWN
    assert launcher.parse_vm_state(
        None, None).verdict == launcher.VERDICT_UNKNOWN


def test_query_vm_state_never_raises():
    result = launcher.query_vm_state(timeout=15)
    assert result.verdict in (launcher.VERDICT_VM, launcher.VERDICT_PHYSICAL,
                              launcher.VERDICT_UNKNOWN)
    assert isinstance(result, launcher.VmCheckResult)


def test_is_fakenet_running_bool():
    assert isinstance(launcher.is_fakenet_running(), bool)


def test_validate_config_path(tmp_path):
    good = tmp_path.joinpath('ok.ini')
    good.write_text('[FakeNet]\n', encoding='ascii')
    ok, _ = launcher.validate_config_path(str(good))
    assert ok

    ok, reason = launcher.validate_config_path('')
    assert not ok
    ok, reason = launcher.validate_config_path('relative.ini')
    assert not ok and '绝对' in reason
    ok, reason = launcher.validate_config_path(str(good) + '"')
    assert not ok and '引号' in reason
    ok, reason = launcher.validate_config_path(str(good)[:-1] + '\\')
    assert not ok and '反斜杠' in reason
    ok, reason = launcher.validate_config_path(str(good) + '\x01')
    assert not ok and '控制字符' in reason
    ok, reason = launcher.validate_config_path(
        str(tmp_path.joinpath('missing.ini')))
    assert not ok and '不存在' in reason


def test_validate_log_path(tmp_path):
    logs = tmp_path / 'Logs'
    logs.mkdir()
    good = logs / 'fakenet.log'
    ok, reason = launcher.validate_log_path(str(good))
    assert ok and reason == ''

    for bad in ('relative.log', str(good) + '"', str(good) + '\x01'):
        ok, _reason = launcher.validate_log_path(bad)
        assert not ok
    ok, reason = launcher.validate_log_path(
        str(tmp_path / 'missing' / 'fakenet.log'))
    assert not ok and '目录不存在' in reason


def test_settings_round_trip(tmp_path):
    base = str(tmp_path)
    assert launcher.load_settings(base) == {}
    launcher.save_settings({'fakenet_exe': 'X:\\fn\\fakenet.exe'}, base)
    assert launcher.load_settings(base) == {'fakenet_exe':
                                            'X:\\fn\\fakenet.exe'}


def test_locate_prefers_valid_persisted(tmp_path):
    base = str(tmp_path)
    sibling = tmp_path.joinpath('fakenet.exe')
    sibling.write_bytes(b'MZ')
    persisted = tmp_path.joinpath('custom')
    persisted.mkdir()
    persisted_exe = persisted.joinpath('fakenet.exe')
    persisted_exe.write_bytes(b'MZ')
    path, source, note = launcher.locate_fakenet_exe(
        settings={'fakenet_exe': str(persisted_exe)}, base_dir=base)
    assert source == 'settings' and path == str(persisted_exe)
    assert note == ''


def test_locate_invalid_persisted_falls_back_to_sibling(tmp_path):
    base = str(tmp_path)
    sibling = tmp_path.joinpath('fakenet.exe')
    sibling.write_bytes(b'MZ')
    path, source, note = launcher.locate_fakenet_exe(
        settings={'fakenet_exe': str(tmp_path.joinpath('gone.exe'))},
        base_dir=base)
    assert source == 'sibling' and path == str(sibling)
    assert '回落' in note  # P11 fallback must be surfaced to the user


def test_locate_missing_reports_none(tmp_path):
    path, source, note = launcher.locate_fakenet_exe(base_dir=str(tmp_path))
    assert path is None and source == 'none'
    assert '手工指定' in note


def test_build_dev_command_uses_module_form(tmp_path):
    config = tmp_path.joinpath('c.ini')
    config.write_text('[FakeNet]\n', encoding='ascii')
    logs = tmp_path / 'Logs'
    logs.mkdir()
    log_path = logs / 'session.log'
    target, params, cwd = launcher.build_dev_command(
        str(config), str(log_path))
    assert os.path.isfile(target)  # sys.executable
    assert '-m fakenet.fakenet' in params
    assert '-c' in params
    assert os.path.isdir(cwd)


def test_build_commands_include_exactly_one_explicit_log_file(tmp_path):
    config = tmp_path / 'c.ini'
    config.write_text('[FakeNet]\n', encoding='ascii')
    logs = tmp_path / 'Logs'
    logs.mkdir()
    log_path = logs / 'one.log'

    _target, dev_params, _cwd = launcher.build_dev_command(
        str(config), str(log_path))
    _target, frozen_params, _cwd = launcher.build_frozen_command(
        str(tmp_path / 'fakenet.exe'), str(config), str(log_path))
    for params in (dev_params, frozen_params):
        assert params.count('--log-file') == 1
        assert '"%s"' % log_path in params


def test_build_commands_require_log_path(tmp_path):
    config = tmp_path / 'c.ini'
    config.write_text('[FakeNet]\n', encoding='ascii')
    with pytest.raises(launcher.LaunchError):
        launcher.build_dev_command(str(config))
    with pytest.raises(launcher.LaunchError):
        launcher.build_frozen_command(str(tmp_path / 'fakenet.exe'),
                                      str(config))


def test_build_commands_add_stop_flag_and_no_pause(tmp_path):
    # Plan 2026.08.21-01 I2: the per-session stop flag is <log>.stopflag and
    # -p removes the final console pause so GUI-launched runs need no key.
    config = tmp_path / 'c.ini'
    config.write_text('[FakeNet]\n', encoding='ascii')
    logs = tmp_path / 'Logs'
    logs.mkdir()
    log_path = logs / 'one.log'

    _target, dev_params, _cwd = launcher.build_dev_command(
        str(config), str(log_path))
    _target, frozen_params, _cwd = launcher.build_frozen_command(
        str(tmp_path / 'fakenet.exe'), str(config), str(log_path))
    for params in (dev_params, frozen_params):
        assert '-f "%s.stopflag"' % log_path in params
        assert params.rstrip().endswith(' -p') or ' -p ' in params


def test_launch_elevated_with_handle_maps_success_and_cancel(monkeypatch):
    monkeypatch.setattr(
        launcher, '_shell_execute_ex',
        lambda *_args: (True, 42, 12345, 0))
    assert launcher.launch_elevated_with_handle(
        'fakenet.exe', '-c "x.ini"') == (True, '已启动', 12345)

    monkeypatch.setattr(
        launcher, '_shell_execute_ex',
        lambda *_args: (False, 0, None, launcher.ERROR_CANCELLED))
    ok, detail, handle = launcher.launch_elevated_with_handle(
        'fakenet.exe', '-c "x.ini"')
    assert not ok and '取消 UAC' in detail and handle is None


@pytest.mark.skipif(os.name != 'nt', reason='Windows named mutex contract')
def test_gui_mutex_detects_second_instance_and_releases_handles():
    name = r'Local\FLARE_FakeNet_NG_GUI_Test_%s' % uuid.uuid4().hex
    first = second = None
    try:
        first, duplicate = launcher.acquire_gui_mutex(name)
        assert first and not duplicate
        second, duplicate = launcher.acquire_gui_mutex(name)
        assert second and duplicate
    finally:
        launcher.close_handle(second)
        launcher.close_handle(first)


def test_build_commands_reject_bad_paths():
    with pytest.raises(launcher.LaunchError):
        launcher.build_dev_command('relative.ini')
    with pytest.raises(launcher.LaunchError):
        launcher.build_frozen_command('X:\\fn\\fakenet.exe',
                                      'no\\abs\\path.ini')


def test_manual_command_hint_module_form():
    hint = launcher.manual_command_hint('C:\\cfg\\x.ini')
    assert hint == 'python -m fakenet.fakenet -c "C:\\cfg\\x.ini"'


def test_interpret_shell_result():
    assert launcher.interpret_shell_result(33) == (True, '已启动')
    assert launcher.interpret_shell_result(42) == (True, '已启动')
    ok, detail = launcher.interpret_shell_result(launcher.SE_ERR_ACCESSDENIED)
    assert not ok and '取消 UAC' in detail
    for code in (0, 2, 3, 31):
        ok, detail = launcher.interpret_shell_result(code)
        assert not ok and '失败' in detail
