import hashlib
import json
import zipfile
from pathlib import Path

from fakenet.mcp.incident import BASIC_ITEMS


def make_bundle(root, name, damaged=False):
    path = root / (name + '.zip')
    entries = []
    with zipfile.ZipFile(path, 'w') as archive:
        for member, _ in BASIC_ITEMS:
            raw = ('real bytes ' + member).encode()
            archive.writestr(member, raw)
            entries.append(dict(item=member, result='ok', size=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
        if damaged:
            entries[-1]['sha256'] = '0' * 64
        archive.writestr('manifest.json', json.dumps(dict(run_id='run', complete=True, entries=entries)))
    raw = path.read_bytes()
    return dict(path=str(path), size=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                complete=True, run_id='run', incident_name=name)


def test_current_archive_hash_does_not_hide_bad_member_hash(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / 'acceptance'))
    from evidence_integrity import validate_incident_export
    assert not validate_incident_export(make_bundle(tmp_path, 'incident'), 'run')
    assert validate_incident_export(make_bundle(tmp_path, 'incident-02', damaged=True), 'run')


def test_all_observed_incidents_must_have_distinct_verified_exports(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / 'acceptance'))
    from evidence_integrity import validate_round
    record = {'class': 'cleanup_error', 'fault_evidence': {'receipt': {'run_id': 'run'},
        'incidents': [{'path': r'C:\artifacts\run\incident\manifest.json'},
                      {'path': r'C:\artifacts\run\incident-02\manifest.json'}]},
        'incident_exports': [make_bundle(tmp_path, 'incident')]}
    assert any('incident export coverage mismatch' in issue for issue in validate_round(record, {}))
    record['incident_exports'].append(make_bundle(tmp_path, 'incident-02'))
    assert not any('incident' in issue for issue in validate_round(record, {}))
    record['incident_exports'][1] = record['incident_exports'][0]
    assert any('incident export coverage mismatch' in issue for issue in validate_round(record, {}))
