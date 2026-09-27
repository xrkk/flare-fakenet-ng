"""The large auxiliary v2 export keeps separate, finite transfer/extract limits."""
import hashlib
import base64
from pathlib import Path
import re
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_suite as suite


class Evidence:
    def __init__(self): self.paths = []
    def add(self, path): self.paths.append(path)


def test_v2_archive_exceeds_ordinary_limit_but_publishes_atomically(tmp_path, monkeypatch):
    monkeypatch.setattr(suite, 'MAX_GUEST_TRANSFER', 8)
    monkeypatch.setattr(suite, 'MAX_AUX_V2_ZIP_TRANSFER', 512)
    monkeypatch.setattr(suite, 'MAX_AUX_V2_MEMBER', 200)
    monkeypatch.setattr(suite, 'MAX_AUX_V2_EXPANDED', 300)
    archive = tmp_path / 'native.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('export/raw.jsonl', b'a' * 150)
        z.writestr('export/manifest.json', b'{}')
    evidence = Evidence()
    target = tmp_path / 'published'
    suite.extract_qpc_archive(archive, target, evidence, auxiliary_v2=True)
    assert (target / 'export/raw.jsonl').read_bytes() == b'a' * 150
    assert len(evidence.paths) == 2


@pytest.mark.parametrize('kind', ['zip', 'member', 'total', 'traversal', 'duplicate',
                                  'casefold', 'symlink'])
def test_v2_rejects_invalid_archive_without_publishing(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(suite, 'MAX_AUX_V2_ZIP_TRANSFER', 512)
    monkeypatch.setattr(suite, 'MAX_AUX_V2_MEMBER', 200)
    monkeypatch.setattr(suite, 'MAX_AUX_V2_EXPANDED', 300)
    archive = tmp_path / 'native.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('good', b'x')
        if kind == 'zip': z.writestr('zip', b'x' * 600)
        elif kind == 'member': z.writestr('large', b'x' * 201)
        elif kind == 'total':
            z.writestr('one', b'x' * 150); z.writestr('two', b'x' * 150)
        elif kind == 'traversal': z.writestr('../escape', b'x')
        elif kind == 'duplicate':
            with pytest.warns(UserWarning): z.writestr('good', b'x')
        elif kind == 'casefold': z.writestr('GOOD', b'x')
        elif kind == 'symlink':
            info = zipfile.ZipInfo('link'); info.external_attr = 0o120777 << 16
            z.writestr(info, b'elsewhere')
    evidence = Evidence()
    target = tmp_path / 'published'
    with pytest.raises(suite.SuiteError):
        suite.extract_qpc_archive(archive, target, evidence, auxiliary_v2=True)
    assert not target.exists() and not evidence.paths
    assert not list(tmp_path.glob('published.extract-*'))


def test_streamed_digest_does_not_call_read_bytes(tmp_path, monkeypatch):
    import scenario_aux_qpc_contract as contract
    path = tmp_path / 'large'; path.write_bytes(b'x' * 1048580)
    monkeypatch.setattr(Path, 'read_bytes', lambda _: (_ for _ in ()).throw(AssertionError('whole read')))
    assert contract._stream_digest(path.open('rb')) == hashlib.sha256(b'x' * 1048580).digest()


def test_only_scoped_auxiliary_v2_zip_gets_larger_transfer_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(suite, 'MAX_GUEST_TRANSFER', 8)
    monkeypatch.setattr(suite, 'MAX_AUX_V2_ZIP_TRANSFER', 24)
    class Vm:
        def powershell(self, command, _timeout):
            offset = int(re.search(r'\$s.Seek\((\d+),', command).group(1))
            length = int(re.search(r'New-Object byte\[\] (\d+)', command).group(1))
            return {'output': base64.b64encode(b'abcdefghijklmnop'[offset:offset + length]).decode()}
    obj = object.__new__(suite.Suite)
    obj.vm = Vm(); obj.root = tmp_path; obj.capture_contract = 'per-run-v1'
    obj.guest_work_root = r'E:\work'
    source = r'E:\work\qpc-contract-123\output.zip'
    target = tmp_path / 'auxiliary-qpc' / 'qpc-output.zip'
    sha = hashlib.sha256(b'abcdefghijklmnop').hexdigest()
    with pytest.raises(suite.SuiteError, match='outside transfer bound'):
        obj._transfer_guest_file(source, 16, sha, target)
    assert obj._transfer_guest_file(source, 16, sha, target,
                                   auxiliary_v2_output=True)['sha256'] == sha
    with pytest.raises(suite.SuiteError, match='scope differs'):
        obj._transfer_guest_file(r'E:\work\other\output.zip', 16, sha,
                                 tmp_path / 'other' / 'qpc-output.zip',
                                 auxiliary_v2_output=True)
    with pytest.raises(suite.SuiteError, match='outside transfer bound'):
        obj._transfer_guest_file(source, 25, sha,
                                 tmp_path / 'auxiliary-qpc' / 'qpc-output.zip',
                                 auxiliary_v2_output=True)
    wrong = tmp_path / 'auxiliary-qpc' / 'wrong-qpc-output.zip'
    with pytest.raises(suite.SuiteError, match='scope differs'):
        obj._transfer_guest_file(source, 16, sha, wrong, auxiliary_v2_output=True)


def test_auxiliary_v2_bad_sha_never_publishes(tmp_path, monkeypatch):
    monkeypatch.setattr(suite, 'MAX_GUEST_TRANSFER', 8)
    monkeypatch.setattr(suite, 'MAX_AUX_V2_ZIP_TRANSFER', 24)
    class Vm:
        def powershell(self, command, _timeout):
            offset = int(re.search(r'\$s.Seek\((\d+),', command).group(1))
            length = int(re.search(r'New-Object byte\[\] (\d+)', command).group(1))
            return {'output': base64.b64encode(b'abcdefghijklmnop'[offset:offset + length]).decode()}
    obj = object.__new__(suite.Suite)
    obj.vm = Vm(); obj.root = tmp_path; obj.capture_contract = 'per-run-v1'
    obj.guest_work_root = r'E:\work'
    target = tmp_path / 'auxiliary-qpc' / 'qpc-output.zip'
    with pytest.raises(suite.SuiteError, match='SHA-256 mismatch'):
        obj._transfer_guest_file(r'E:\work\qpc-contract-123\output.zip', 16,
                                 '0' * 64, target, auxiliary_v2_output=True)
    assert not target.exists()
    assert not list(target.parent.glob('*.transfer-*'))
