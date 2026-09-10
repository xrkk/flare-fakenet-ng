import hashlib
import json
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest

from fakenet.mcp import exit_installation
from fakenet.mcp.exit_installation import (Observation, verify_assets, HELPER,
                                           HELPER_IMAGE, MANAGED)

EXHAUSTED = 18


@pytest.fixture
def package(tmp_path):
    names = ['fakenetng-mcp.exe', MANAGED, HELPER, 'exit-helper/_internal/python311.dll']
    rows = []
    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'MZtest-asset')
        rows.append(dict(path=name, size=path.stat().st_size,
                         sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    (tmp_path / 'mcp-candidate-manifest.json').write_text(json.dumps(
        dict(schema='fakenet.mcp-candidate-manifest.v1', files=rows)))
    return tmp_path


def test_manifest_checks_helper_dependencies_as_well_as_executable(package):
    assert verify_assets(package) == package / HELPER
    (package / 'exit-helper/_internal/python311.dll').write_bytes(b'changed')
    with pytest.raises(RuntimeError, match='integrity'):
        verify_assets(package)


def test_unlisted_helper_file_prevents_start(package):
    (package / 'exit-helper/injected.dll').write_bytes(b'MZnew')
    with pytest.raises(RuntimeError, match='file set'):
        verify_assets(package)


def test_missing_dedicated_image_prevents_start(package):
    (package / MANAGED).unlink()
    with pytest.raises(OSError):
        verify_assets(package)


@pytest.fixture
def native(monkeypatch):
    """Drive the real snapshot walk with an injected native process table."""
    state = {'rows': [], 'images': {}, 'closed': [], 'handles': [],
             'last_error': EXHAUSTED, 'first_result': None, 'next_result': None,
             'delay': 0.0, 'slow_exit': False, 'clock': None,
             'advance_on_exit': 0.0}
    index = {'value': -1}

    class Api:
        """A native entry point that still accepts argtypes/restype."""

        def __init__(self, function):
            self.function = function

        def __call__(self, *args):
            return self.function(*args)

    def fill(pointer):
        pid, image = state['rows'][index['value']]
        entry = pointer._obj
        entry.th32ProcessID = pid
        entry.szExeFile = image
        return 1

    def snapshot(flags, pid):
        return 0x51

    def first(handle, pointer):
        time.sleep(state['delay'])
        if state['first_result'] is not None or not state['rows']:
            state['last_error'] = (state['first_result']
                                   if state['first_result'] is not None
                                   else EXHAUSTED)
            return 0
        index['value'] = 0
        return fill(pointer)

    def following(handle, pointer):
        time.sleep(state['delay'])
        if state['next_result'] is not None:
            state['last_error'] = state['next_result']
            return 0
        index['value'] += 1
        if index['value'] >= len(state['rows']):
            state['last_error'] = EXHAUSTED
            return 0
        return fill(pointer)

    def close(handle):
        state['closed'].append(handle)

    class FakeKernel:
        CreateToolhelp32Snapshot = Api(snapshot)
        Process32FirstW = Api(first)
        Process32NextW = Api(following)
        CloseHandle = Api(close)

    class FakeTargetHandle:
        def __init__(self, pid, allow_terminate=False):
            if pid not in state['images']:
                raise OSError(87, 'no such process')
            self.pid = pid
            self.allow_terminate = allow_terminate
            self.closed = False
            self.terminated = False
            state['handles'].append(self)

        def identity(self):
            return {'pid': self.pid, 'creation_time': '1',
                    'image': state['images'][self.pid]}

        def terminate_helper(self):
            assert self.allow_terminate
            self.terminated = True
            state['images'].pop(self.pid, None)
            state['rows'] = [row for row in state['rows'] if row[0] != self.pid]

        def exited(self):
            if state['clock'] is not None:
                state['clock'][0] += state['advance_on_exit']
            if state['slow_exit']:
                return False
            return self.pid not in state['images']

        def close(self):
            self.closed = True

    kernel = FakeKernel()
    monkeypatch.setattr(exit_installation, '_kernel32', lambda: kernel)
    monkeypatch.setattr(exit_installation, '_last_error',
                        lambda: state['last_error'])
    monkeypatch.setattr('fakenet.mcp.exit_native.TargetHandle', FakeTargetHandle)
    return state


def _packaged_helper_image(package):
    return str(Path(package).resolve() / HELPER)


def _fake_clock(monkeypatch, native, start=1000.0):
    clock = [start]
    native['clock'] = clock
    monkeypatch.setattr(exit_installation, 'time',
                        types.SimpleNamespace(monotonic=lambda: clock[0],
                                              sleep=lambda _seconds: None))
    return clock


def test_same_named_foreign_image_is_not_this_package_helper(native, package):
    """A foreign program sharing the image name must never be claimed."""
    native['rows'] = [(4242, HELPER_IMAGE)]
    native['images'] = {4242: r'C:\elsewhere\fakenetng-mcp-exit-monitor.exe'}
    assert exit_installation._packaged_helpers(package) == []
    exit_installation.assert_no_helpers(package)
    assert native['handles'][0].closed is True


def test_packaged_helper_is_reported_as_still_active(native, package):
    native['rows'] = [(4242, HELPER_IMAGE)]
    native['images'] = {4242: _packaged_helper_image(package)}
    with pytest.raises(RuntimeError, match='still active: 4242'):
        exit_installation.assert_no_helpers(package)
    assert native['handles'][0].closed is True


def test_cleanup_terminates_only_the_packaged_helper(native, package):
    native['rows'] = [(4242, HELPER_IMAGE), (4343, HELPER_IMAGE),
                      (4444, 'unrelated.exe')]
    native['images'] = {4242: _packaged_helper_image(package),
                        4343: r'C:\elsewhere\fakenetng-mcp-exit-monitor.exe',
                        4444: _packaged_helper_image(package)}
    exit_installation.end_helpers(package, time.monotonic() + 5)
    terminated = [handle.pid for handle in native['handles'] if handle.terminated]
    assert terminated == [4242]
    assert 4343 in native['images'] and 4444 in native['images']


def test_only_no_more_files_ends_the_walk(native, package):
    native['rows'] = [(101, 'first.exe'), (4242, HELPER_IMAGE)]
    native['images'] = {4242: _packaged_helper_image(package)}
    assert list(exit_installation.live_processes()) == [
        (101, 'first.exe'), (4242, HELPER_IMAGE)]
    assert native['closed'] == [0x51]


@pytest.mark.parametrize('code', [5, 87, 1168, 6])
def test_enumeration_failure_is_never_reported_as_exhaustion(native, package, code):
    """A partial process table must not produce a clean 'no helper' verdict."""
    native['rows'] = [(101, 'first.exe'), (4242, HELPER_IMAGE)]
    native['images'] = {4242: _packaged_helper_image(package)}
    native['next_result'] = code
    with pytest.raises(OSError) as captured:
        list(exit_installation.live_processes())
    assert captured.value.winerror == code
    with pytest.raises(OSError):
        exit_installation.assert_no_helpers(package)


def test_snapshot_creation_and_first_call_failures_are_reported(native, package):
    native['rows'] = [(101, 'first.exe')]
    native['first_result'] = 5
    with pytest.raises(OSError) as captured:
        list(exit_installation.live_processes())
    assert captured.value.winerror == 5


def test_snapshot_handle_is_released_on_enumeration_error(native, package):
    native['rows'] = [(101, 'first.exe'), (4242, HELPER_IMAGE)]
    native['images'] = {}
    native['next_result'] = 5
    with pytest.raises(OSError):
        list(exit_installation.live_processes())
    assert native['closed'] == [0x51]


def test_observation_budget_bounds_the_native_walk(native, package):
    native['rows'] = [(pid, 'unrelated.exe') for pid in range(1, 8)]
    with pytest.raises(RuntimeError, match='observation budget exhausted'):
        list(exit_installation.live_processes(Observation(budget=3)))


def test_helper_sweep_is_bounded_by_the_observation_budget(native, package):
    native['rows'] = [(pid, 'unrelated.exe')
                      for pid in range(1, exit_installation.OBSERVATION_BUDGET + 64)]
    with pytest.raises(RuntimeError, match='observation budget exhausted'):
        exit_installation.end_helpers(package, time.monotonic() + 30)
    assert native['handles'] == []


@pytest.mark.parametrize('rows', [[], [(101, 'first.exe')]])
def test_slow_enumeration_fails_closed_instead_of_reporting_no_helpers(
        native, package, rows):
    """A walk that outlives its window must fail, not report an empty result."""
    native['rows'] = rows
    native['delay'] = 0.2
    with pytest.raises(RuntimeError, match='observation budget exhausted'):
        exit_installation._packaged_helpers(
            package, observation=Observation(
                time.monotonic() + 0.01, exit_installation.OBSERVATION_BUDGET))
    assert native['closed'] == [0x51]


def test_helper_sweep_honours_an_expired_deadline(native, package):
    native['rows'] = [(4242, HELPER_IMAGE)]
    native['images'] = {4242: _packaged_helper_image(package)}
    with pytest.raises(RuntimeError, match='observation budget exhausted'):
        exit_installation.end_helpers(package, time.monotonic() - 1)
    assert native['handles'] == []


def test_termination_wait_is_bounded_by_the_deadline(native, package):
    native['rows'] = [(4242, HELPER_IMAGE)]
    native['images'] = {4242: _packaged_helper_image(package)}
    native['slow_exit'] = True
    with pytest.raises(RuntimeError, match='termination did not complete'):
        exit_installation.end_helpers(package, time.monotonic() + 0.05)
    assert native['handles'][0].terminated is True


def test_cleanup_shares_one_deadline_with_the_final_recheck(native, package, monkeypatch):
    """The residual check after termination must not outlive the window."""
    native['rows'] = [(4242, HELPER_IMAGE)]
    native['images'] = {4242: _packaged_helper_image(package)}
    clock = _fake_clock(monkeypatch, native)
    native['advance_on_exit'] = 100.0
    with pytest.raises(RuntimeError, match='observation budget exhausted'):
        exit_installation.end_helpers(package, clock[0] + 10)
    # The failure is at the residual recheck, after the helper was terminated.
    assert native['handles'][0].terminated is True


def test_completed_sweep_cannot_shrink_the_residual_check_budget(native, package):
    """The residual check must spend the same counter, not a fresh one."""
    native['rows'] = [(pid, 'unrelated.exe') for pid in range(1, 6)]
    observation = Observation(time.monotonic() + 30, 5)
    assert exit_installation._packaged_helpers(package, observation=observation) == []
    assert observation.remaining == 0
    with pytest.raises(RuntimeError, match='observation budget exhausted'):
        exit_installation.assert_no_helpers(package, observation=observation)


def test_packaged_helper_path_has_no_unbundled_dependency():
    """The candidate build installs only the pinned SDK set; the installer
    must not import anything that build does not freeze into the package."""
    sources = Path(exit_installation.__file__).resolve().parent.rglob('*.py')
    offenders = [path.name for path in sources
                 if 'psutil' in path.read_text(encoding='utf-8')]
    assert offenders == []


def test_module_import_needs_no_third_party_process_library():
    root = Path(exit_installation.__file__).resolve().parents[2]
    code = ('import sys, fakenet.mcp.exit_installation as m; '
            'assert "psutil" not in sys.modules; '
            'assert callable(m.live_processes)')
    result = subprocess.run([sys.executable, '-c', code], cwd=str(root),
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
