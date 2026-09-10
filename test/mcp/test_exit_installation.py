import hashlib
import json

import pytest

from fakenet.mcp.exit_installation import verify_assets, HELPER, MANAGED


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
