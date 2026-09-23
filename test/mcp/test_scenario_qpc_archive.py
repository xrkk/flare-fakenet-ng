"""Native export has three full event views, not one transferred file."""
import sys
from pathlib import Path
import zipfile
import pytest
sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_suite as suite

class Evidence:
    def __init__(self): self.paths = []
    def add(self, path): self.paths.append(path)

def test_three_complete_views_can_exceed_single_transfer_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(suite, 'MAX_GUEST_TRANSFER', 192)
    archive = tmp_path / 'native.zip'
    contents = {f'export/raw/{name}.jsonl': (name.encode() * 30)[:90]
                for name in ('raw', 'default', 'paired')}
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in contents.items(): z.writestr(name, data)
    destination = tmp_path / 'output'; destination.mkdir()
    evidence = Evidence()
    suite.extract_qpc_archive(archive, destination, evidence)
    assert {p.relative_to(destination).as_posix(): p.read_bytes() for p in evidence.paths} == contents

@pytest.mark.parametrize('kind', ['member', 'aggregate', 'traversal', 'duplicate', 'symlink', 'count'])
def test_invalid_archive_rejected_before_any_member_written(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(suite, 'MAX_GUEST_TRANSFER', 192)
    archive = tmp_path / 'native.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('valid', b'ok')
        if kind == 'member': z.writestr('large', b'x' * 193)
        elif kind == 'aggregate':
            for n in range(4): z.writestr(str(n), b'x' * 192)
        elif kind == 'traversal': z.writestr('../escape', b'x')
        elif kind == 'duplicate':
            with pytest.warns(UserWarning): z.writestr('valid', b'x')
        elif kind == 'symlink':
            info = zipfile.ZipInfo('link'); info.external_attr = 0o120777 << 16
            z.writestr(info, 'elsewhere')
        elif kind == 'count':
            for n in range(128): z.writestr(str(n), b'')
    destination = tmp_path / 'output'; destination.mkdir()
    evidence = Evidence()
    with pytest.raises(suite.SuiteError):
        suite.extract_qpc_archive(archive, destination, evidence)
    assert not list(destination.iterdir())
    assert not evidence.paths
