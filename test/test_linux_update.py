"""Bounded source-only update fixtures; no real services or credentials."""
import importlib.util
import json
import os
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'deploy/linux/update-idle.py'


@pytest.fixture
def update_fixture(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('idle_update_fixture', SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    monkeypatch.setattr(m, 'OWNER', os.getuid())
    old_umask = os.umask(0o077)
    root = tmp_path / 'root'
    package = tmp_path / 'package'
    package.mkdir(mode=0o700)
    files = {}
    base_files = {}
    for name in m.FILES:
        target = root / 'opt/fakenet-ng' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('old ' + name)
        incoming = package / name
        incoming.parent.mkdir(parents=True, exist_ok=True)
        incoming.write_text('new ' + name)
        files[name] = dict(old_sha256=m.sha(target), new_sha256=m.sha(incoming))
        base_files['opt/fakenet-ng/' + name] = m.sha(target)
    token = root / 'etc/fakenet-ng-linux/token'
    token.parent.mkdir(parents=True)
    token.write_text('a' * 64)
    token.chmod(0o600)
    (package / 'update-idle.py').write_bytes(SCRIPT.read_bytes())
    manifest = dict(base_manifest=m.BASE_MANIFEST, source_commit='a'*40,
                    files=files, base_files=base_files, token_inode=token.stat().st_ino,
                    updater_sha256=m.sha(package / 'update-idle.py'))
    (package / 'manifest.json').write_text(json.dumps(manifest))
    calls = []
    def run(argv):
        calls.append(argv)
        if '--value' in argv:return '123' if any('start' in c for c in calls) else '0'
        return 'active'
    def invoke(**overrides):
        return m.update(package, m.sha(package / 'manifest.json'), 'fixture-S0049',
                        root=root, preflight=lambda _:dict(pid=99), run=overrides.get('run',run),
                        get_status=overrides.get('status',lambda:dict(state='stopped',run_id=None,
                            controller=None,health=dict(process_alive=False))))
    yield m, root, package, calls, invoke
    os.umask(old_umask)


def test_update_preserves_originals_token_and_reentry(update_fixture):
    m, root, package, calls, invoke = update_fixture
    token = root / 'etc/fakenet-ng-linux/token'
    identity = token.stat().st_ino
    receipt = invoke()
    assert receipt['phase'] == 'completed'
    assert calls[0] == ['systemctl','stop',m.UNIT]
    for name, original in receipt['originals'].items():
        assert m.sha(Path(original['backup'])) == original['sha256']
        assert (root/'opt/fakenet-ng'/name).read_text() == 'new '+name
    before = list(calls)
    invoke()
    assert calls == before and token.stat().st_ino == identity and token.read_text() == 'a'*64


def test_changed_source_refuses_before_service_or_transaction(update_fixture):
    m, root, package, calls, invoke = update_fixture
    (root/'opt/fakenet-ng'/m.FILES[0]).write_text('foreign edit')
    with pytest.raises(RuntimeError, match='accepted file changed'):invoke()
    assert calls == [] and not list((root/'opt').glob('.fakenet-update-*'))


def test_missing_payload_and_active_run_refuse(update_fixture):
    m, root, package, calls, invoke = update_fixture
    with pytest.raises(RuntimeError, match='not idle'):
        invoke(status=lambda:dict(state='healthy',run_id='live',controller='A',health=dict(process_alive=True)))
    (package/m.FILES[0]).unlink()
    with pytest.raises(RuntimeError, match='package files'):invoke()
    assert calls == [] and not list((root/'opt').glob('.fakenet-update-*'))


def test_failed_stop_preserves_phase_and_never_publishes(update_fixture):
    m, root, package, calls, invoke = update_fixture
    def fail(argv):
        calls.append(argv)
        raise RuntimeError('service stop failed')
    with pytest.raises(RuntimeError, match='service stop failed'):invoke(run=fail)
    tx=root/'opt/.fakenet-update-fixture-S0049'
    receipt=json.loads((tx/'receipt.json').read_text())
    assert receipt['phase']=='failed' and receipt['failure_at']=='backed_up'
    assert receipt['published']==[]
    assert all((root/'opt/fakenet-ng'/n).read_text()=='old '+n for n in m.FILES)
    with pytest.raises(RuntimeError, match='interrupted update'):invoke()
    assert len(calls)==1


def test_symlink_target_parent_refuses(update_fixture):
    m, root, package, calls, invoke = update_fixture
    path=root/'opt/fakenet-ng'/m.FILES[0]
    path.unlink();path.symlink_to(package/m.FILES[0])
    with pytest.raises(RuntimeError):invoke()
    assert calls==[]
