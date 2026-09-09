import importlib
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def helpers(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / 'acceptance'))
    return importlib.import_module('helpers')


def test_matching_fault_mode_preserves_service_instance(helpers):
    calls = []
    def invoke(command, **kwargs):
        calls.append(command)
        return {'output': json.dumps({'enabled': True, 'grace': 5})}
    result = helpers.configure_fault_service(SimpleNamespace(powershell=invoke), True, 5)
    assert result['reused_service_instance'] and len(calls) == 1


def test_failed_prestop_cannot_change_fault_configuration(helpers):
    calls = []
    def invoke(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            return {'output': json.dumps({'enabled': False, 'grace': 60})}
        if len(calls) == 2:
            return {'output': 'no unconsumed fault'}
        raise helpers.StepError('pre-stop rejected')
    with pytest.raises(helpers.StepError, match='pre-stop rejected'):
        helpers.configure_fault_service(SimpleNamespace(powershell=invoke), True, 5)
    assert len(calls) == 3
    assert all('New-ItemProperty' not in command for command in calls)


def test_fault_nonce_is_written_and_read_back_without_legacy_environment(helpers):
    payloads = []
    def invoke(command, **kwargs):
        assert 'SetEnvironmentVariable' not in command
        assert 'if(Test-Path $path)' in command
        payload = json.loads(re.search(r"WriteAllText\(\$path,'([^']+)'", command).group(1))
        payloads.append(payload)
        return {'output': json.dumps(payload)}
    channel = SimpleNamespace(powershell=invoke)
    first = helpers.arm_fault_file(channel, 'policy_pause')
    second = helpers.arm_fault_file(channel, 'cleanup_error')
    assert first['nonce'] != second['nonce']
    assert payloads == [{'fault': 'policy_pause', 'nonce': first['nonce']},
                        {'fault': 'cleanup_error', 'nonce': second['nonce']}]
    with pytest.raises(ValueError):
        helpers.arm_fault_file(channel, 'fake-log-line')
    assert len(payloads) == 2


def test_incident_export_verifies_members_instead_of_trusting_manifest(helpers, tmp_path):
    import base64
    import hashlib
    import io
    import uuid
    import zipfile
    from fakenet.mcp.incident import BASIC_ITEMS
    run_id = str(uuid.uuid4())
    def archive_bytes(tampered=False):
        entries = []
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as archive:
            for name, _ in BASIC_ITEMS:
                data = ('raw-' + name).encode()
                archive.writestr(name, data)
                entries.append(dict(item=name, result='ok', size=len(data),
                                    sha256=hashlib.sha256(data).hexdigest()))
            if tampered:
                entries[0]['sha256'] = '0' * 64
            entries.append(dict(item='userdump.dmp', result='skipped', size=0,
                                sha256=None, failure_reason='no escalation condition'))
            manifest = json.dumps(dict(run_id=run_id, complete=True, entries=entries)).encode()
            archive.writestr('manifest.json', manifest)
        return out.getvalue(), manifest
    for tampered in (False, True):
        data, manifest = archive_bytes(tampered)
        def invoke(command, **kwargs):
            if 'Compress-Archive' in command:
                return {'output': json.dumps(dict(size=len(data), sha256=hashlib.sha256(data).hexdigest(),
                           manifest_sha256=hashlib.sha256(manifest).hexdigest()))}
            return {'output': base64.b64encode(data).decode()}
        channel = SimpleNamespace(powershell=invoke)
        path = tmp_path / ('bad.zip' if tampered else 'good.zip')
        if tampered:
            with pytest.raises(helpers.StepError, match='member hash/size mismatch'):
                helpers.export_incident_bundle(channel, run_id, path)
        else:
            result = helpers.export_incident_bundle(channel, run_id, path)
            assert result['complete'] and len(result['verified_members']) == len(BASIC_ITEMS)
