import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from fakenet.mcp import exit_installation
from fakenet.mcp.exit_installation import verify_assets, HELPER, HELPER_IMAGE, MANAGED


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
    """Fake process table for the native helper sweep."""
    state = {'table': {}}

    class FakeTargetHandle:
        def __init__(self, pid, allow_terminate=False):
            if pid not in state['table']:
                raise OSError(87, 'no such process')
            self.pid = pid
            self.allow_terminate = allow_terminate
            self.closed = False
            self.terminated = False
            state['table'][pid].setdefault('handles', []).append(self)

        def identity(self):
            entry = state['table'][self.pid]
            if entry.get('image_error'):
                raise OSError(entry['image_error'], 'unreadable image')
            return {'pid': self.pid, 'creation_time': '1', 'image': entry['image']}

        def terminate_helper(self):
            assert self.allow_terminate
            self.terminated = True
            state['table'].pop(self.pid, None)

        def exited(self):
            return self.pid not in state['table']

        def close(self):
            self.closed = True

    monkeypatch.setattr('fakenet.mcp.exit_native.TargetHandle', FakeTargetHandle)
    monkeypatch.setattr(exit_installation, 'live_processes',
                        lambda: [(pid, entry['name'])
                                 for pid, entry in state['table'].items()])
    return state


def _packaged_helper_image(package):
    return str((Path(package).resolve() / HELPER))


def test_same_named_foreign_image_is_not_this_package_helper(native, package):
    """A foreign program sharing the image name must never be claimed."""
    native['table'][4242] = {'name': HELPER_IMAGE,
                             'image': r'C:\elsewhere\fakenetng-mcp-exit-monitor.exe'}
    assert exit_installation._packaged_helpers(package) == []
    exit_installation.assert_no_helpers(package)
    assert native['table'][4242]['handles'][0].closed is True


def test_packaged_helper_is_reported_as_still_active(native, package):
    native['table'][4242] = {'name': HELPER_IMAGE,
                             'image': _packaged_helper_image(package)}
    with pytest.raises(RuntimeError, match='still active: 4242'):
        exit_installation.assert_no_helpers(package)
    assert native['table'][4242]['handles'][0].closed is True


def test_cleanup_terminates_only_the_packaged_helper(native, package):
    native['table'][4242] = {'name': HELPER_IMAGE,
                             'image': _packaged_helper_image(package)}
    native['table'][4343] = {'name': HELPER_IMAGE,
                             'image': r'C:\elsewhere\fakenetng-mcp-exit-monitor.exe'}
    native['table'][4444] = {'name': 'unrelated.exe',
                             'image': _packaged_helper_image(package)}
    exit_installation.end_helpers(package, time.monotonic() + 5)
    assert native['table'][4343]['handles'][0].terminated is False
    assert native['table'].get(4444) is not None
    assert 4242 not in native['table']


def test_helper_sweep_is_bounded_by_the_observation_budget(native, package):
    for pid in range(1, exit_installation.OBSERVATION_BUDGET + 64):
        native['table'][pid] = {'name': 'unrelated.exe', 'image': 'x'}
    with pytest.raises(RuntimeError, match='observation budget exhausted'):
        exit_installation.end_helpers(package, time.monotonic() + 30)


def test_helper_sweep_honours_its_deadline(native, package):
    native['table'][4242] = {'name': 'unrelated.exe', 'image': 'x'}
    with pytest.raises(RuntimeError, match='observation budget exhausted'):
        exit_installation.end_helpers(package, time.monotonic() - 1)


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
