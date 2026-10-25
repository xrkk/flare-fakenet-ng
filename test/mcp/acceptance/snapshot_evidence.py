"""Fixed ACC008 byte identities and startup recovery evidence predicates."""
import base64
import hashlib
import json
import math
from pathlib import Path, PureWindowsPath
from urllib.parse import urlparse
from helpers import StepError
from fakenet.mcp.snapshot import valid_fields
from fakenet.mcp.baseline import BASELINE_FIELDS
from process_recovery import identity, require_mutation


def body(item):
    if not isinstance(item, dict) or set(item) != {'path', 'body', 'size', 'sha256'}:
        raise StepError('snapshot file observation incomplete')
    raw = base64.b64decode(item['body'], validate=True)
    if len(raw) != item['size'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
        raise StepError('snapshot file bytes/hash differ')
    return raw


def control(channel, operation, **values):
    import uuid
    inputs = getattr(channel, 'inputs', None) or {}
    expected = dict(values, operation=operation, token=uuid.uuid4().hex,
                    port=inputs.get('endpoint') and urlparse(inputs['endpoint']).port or 28788)
    text = Path(__file__).with_name('snapshot_control.ps1').read_text()
    text = text.replace('__EXPECTED__', base64.b64encode(json.dumps(expected).encode()).decode())
    text = text.replace('__SCOPE_HELPERS__', Path(__file__).with_name('process_scope.ps1').read_text())
    raw = channel.powershell(text, timeout=90)
    result = json.loads(raw['output'])
    if result.get('operation') != operation or result.get('token') != expected['token']:
        raise StepError('snapshot control receipt differs')
    return result, raw


def files_match(channel, value):
    root = PureWindowsPath((getattr(channel, 'inputs', None) or {}).get('programdata_root', r'C:\ProgramData\FakeNet-NG-MCP'))
    state = value.get('marker')
    if state is not None:
        body(state)
        if PureWindowsPath(state['path']) != root / 'state/state.json':
            raise StepError('snapshot marker path differs')
    rows = value.get('baselines')
    if not isinstance(rows, list) or len({r['path'].casefold() for r in rows}) != len(rows):
        raise StepError('baseline collection missing or duplicate')
    for row in rows:
        body(row)
        path = PureWindowsPath(row['path'])
        if path.parent != root / 'baselines' or path.suffix != '.json':
            raise StepError('baseline path outside fixed root')
    service = value.get('service') or {}
    install = PureWindowsPath((getattr(channel, 'inputs', None) or {}).get('installation_root', r'C:\Program Files\FakeNet-NG-MCP'))
    if service.get('state') == 'Running':
        identity(service)
        if PureWindowsPath(service.get('image', '')) != install / 'fakenetng-mcp.exe' or value.get('endpoint_owned') is not True:
            raise StepError('snapshot current service/endpoint image differs')
    elif service.get('state') != 'Stopped' or service.get('pid') != 0:
        raise StepError('snapshot SCM state unknown')
    return value


def read_files(channel, writer, label):
    value, raw = control(channel, 'read')
    writer.add_evidence(label, raw)
    return files_match(channel, value)


def active_identity(channel, files, started, snapshot, controller, command):
    marker = json.loads(body(files['marker']).decode('utf-8-sig'))
    if (not valid_fields(marker) or marker['run_id'] != started['run_id'] or
            snapshot.get('run_id') != started['run_id'] or snapshot.get('state') != 'healthy' or
            marker['controller_id'] != controller or marker['command_id'] != command or
            marker['state_version'] != started['state_version'] or
            marker['config_sha256'] != started.get('config_identity', {}).get('sha256') or
            snapshot.get('config_identity') != started.get('config_identity') or
            marker['needs_recovery'] is not True):
        raise StepError('snapshot run/controller/command/version/config content differs')
    expected = PureWindowsPath(files['marker']['path']).parent.parent / 'baselines' / (marker['run_id'] + '.json')
    if PureWindowsPath(marker['baseline_path']) != expected:
        raise StepError('snapshot baseline pointer differs')
    matches = [r for r in files['baselines'] if PureWindowsPath(r['path']) == expected]
    if len(matches) != 1:
        raise StepError('snapshot baseline original missing')
    baseline = json.loads(body(matches[0]).decode('utf-8-sig'))
    if baseline.get('run_id') != marker['run_id'] or not isinstance(baseline.get('sections'), dict) or set(BASELINE_FIELDS) - set(baseline['sections']) or any(baseline['sections'][f] in (None, '__COLLECTION_FAILED__') for f in BASELINE_FIELDS):
        raise StepError('snapshot baseline identity/sections differ')
    return marker


def startup_failure(before, after, old_events, events, state, reason):
    if (identity(before['service']) == identity(after['service']) or
            after['service'].get('state') != 'Running' or after.get('endpoint_owned') is not True or
            before['service']['image'].casefold() != after['service']['image'].casefold()):
        raise StepError('snapshot recovery current SCM/endpoint unconfirmed')
    rows = events.get('events') or []
    old_epochs = {r.get('epoch') for r in old_events.get('events', [])}
    epochs = {r.get('epoch') for r in rows}
    birth = (int(after['service']['creation_time']) - 116444736000000000) / 10000000
    audit = [r for r in rows if r.get('kind') == 'recovery']
    if (old_events.get('error') or events.get('error') or not old_epochs or
            len(epochs) != 1 or None in epochs or epochs & old_epochs or
            [r.get('state') for r in audit] != ['recovering', state] or
            (reason and audit[-1].get('reason') != reason) or
            any(type(r.get('timestamp')) not in (int,float) or not math.isfinite(r['timestamp']) or not birth <= r['timestamp'] <= after['sampled_at'] for r in rows)):
        raise StepError('snapshot recovery audit not from this incarnation/condition')
    sequence = [r.get('seq') for r in rows]
    if any(type(n) is not int or n <= 0 for n in sequence) or sequence != sorted(set(sequence)):
        raise StepError('snapshot recovery event order differs')
    return True


def scan_matches(channel, value):
    root = PureWindowsPath((getattr(channel, 'inputs', None) or {}).get('installation_root', r'C:\Program Files\FakeNet-NG-MCP')) / '_internal'
    if (PureWindowsPath(value.get('root', '')) != root or value.get('attempted') is not True or
            value.get('complete') is not True or type(value.get('pyc_count')) is not int or
            value['pyc_count'] <= 0 or not isinstance(value.get('files'), list) or
            len(value['files']) != value.get('count') or not value['files']):
        raise StepError('framework scan incomplete or not evaluated')
    seen = set()
    for item in value['files']:
        path = PureWindowsPath(item['path'])
        if not path.is_relative_to(root) or '..' in path.parts or str(path).casefold() in seen:
            raise StepError('framework scan scope/duplicate differs')
        seen.add(str(path).casefold())
        if any('sqlite' in part.lower() or 'dbm' in part.lower() for part in path.relative_to(root).parts):
            return False
    if sum(not i.get('directory', False) and PureWindowsPath(i['path']).suffix.lower() == '.pyc' for i in value['files']) != value['pyc_count']:
        raise StepError('framework pyc count differs from actual listing')
    return True
