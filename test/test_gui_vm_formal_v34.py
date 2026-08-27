import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'test' / 'gui_vm' / 'run_formal_stop_acceptance.py'
SPEC = importlib.util.spec_from_file_location('formal_stop_v34', RUNNER)
formal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(formal)


def test_stop_boundary_parser_requires_every_begin_to_end():
    complete = (
        'STOP_PHASE_BEGIN phase=listeners\n'
        'STOP_PROVIDER_BEGIN name=HTTPListener80\n'
        'STOP_PROVIDER_END name=HTTPListener80\n'
        'STOP_PHASE_END phase=listeners\n')
    incomplete = complete.replace(
        'STOP_PROVIDER_END name=HTTPListener80\n', '')

    assert formal.stop_boundaries_closed(complete) == (True, [])
    ok, active = formal.stop_boundaries_closed(incomplete)
    assert not ok
    assert active == ['provider:HTTPListener80']


def test_unique_formal_entry_orders_preflight_ap_and_three_stop_rounds():
    cmd = (ROOT / 'test' / 'gui_vm' / 'Run-Tests.cmd').read_text(
        encoding='utf-8')
    acceptance_at = cmd.index('run_gui_vm_acceptance.py')
    policy_at = cmd.index('run_policy_feature_tests.py')
    stop_at = cmd.index('run_formal_stop_acceptance.py')

    assert acceptance_at < policy_at < stop_at
    assert 'Export-Logs.ps1' in cmd
    assert 'taskkill' not in cmd.lower()


def test_unique_formal_entry_captures_policy_and_stop_exit_codes_at_runtime():
    cmd = (ROOT / 'test' / 'gui_vm' / 'Run-Tests.cmd').read_text(
        encoding='utf-8')

    assert 'setlocal EnableExtensions EnableDelayedExpansion' in cmd
    assert 'set "P_EXIT=!ERRORLEVEL!"' in cmd
    assert 'set "S_EXIT=!ERRORLEVEL!"' in cmd
    assert 'set "P_EXIT=%ERRORLEVEL%"' not in cmd
    assert 'set "S_EXIT=%ERRORLEVEL%"' not in cmd


def test_formal_runners_require_real_sink_and_never_force_kill():
    paths = [
        ROOT / 'test' / 'gui_vm' / 'run_gui_vm_acceptance.py',
        ROOT / 'test' / 'gui_vm' / 'run_policy_feature_tests.py',
        RUNNER,
    ]
    text = '\n'.join(path.read_text(encoding='utf-8') for path in paths)

    assert "probe_fnpr_transports" in text
    assert "'target'" in text
    assert 'ALLOW_TAKEOVER_SINK' in text
    assert 'divert_fake_logged' in text
    assert "['taskkill'" not in text


def test_three_round_contract_and_onedir_gate_are_fixed():
    text = RUNNER.read_text(encoding='utf-8')

    assert 'ROUND_COUNT = 3' in text
    assert 'feedback_seconds <= 1.0' in text
    assert 'exit_seconds <= 5.0' in text
    assert "core_bundle_mode') != 'pyinstaller-onedir'" in text
    assert "os.path.isdir(os.path.join(REPO, '_internal'))" in text


def test_round_cleanup_closes_gui_image_before_testing_mei(monkeypatch):
    events = []
    mei_states = iter(({'old', 'gui-mei'}, {'old'}))

    def fake_stop_gui_smoke(gui, mode):
        events.append(('close', gui, mode))
        return True, 'CLOSE_REQUESTED count=1;进程已退出'

    def fake_new_mei_dirs():
        events.append(('mei',))
        return next(mei_states)

    def fake_wait(predicate, timeout, interval=1.0):
        events.append(('wait', timeout, interval))
        for _unused in range(2):
            if predicate():
                return True
        return False

    monkeypatch.setattr(
        formal.acceptance, 'stop_gui_smoke', fake_stop_gui_smoke)
    monkeypatch.setattr(formal, '_new_mei_dirs', fake_new_mei_dirs)
    monkeypatch.setattr(formal.acceptance, 'wait_for', fake_wait)

    result = formal.cleanup_round_gui(object(), {'old'})

    assert result == (
        True, 'CLOSE_REQUESTED count=1;进程已退出', True, [])
    assert events[0][0] == 'close'
    assert [event[0] for event in events].index('close') < \
        [event[0] for event in events].index('mei')


def test_formal_runner_does_not_close_gui_by_bootloader_pid():
    text = RUNNER.read_text(encoding='utf-8')

    assert 'close_gui_window' not in text
    assert 'acceptance.stop_gui_smoke' in text
