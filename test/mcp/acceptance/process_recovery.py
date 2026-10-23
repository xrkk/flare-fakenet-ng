"""ACC007 fixed process identities and current-incarnation recovery evidence."""
import base64
import json
import math
from pathlib import Path, PureWindowsPath
import uuid
from urllib.parse import urlparse

from helpers import StepError
from fakenet.mcp.creation_evidence import CREATION_STAGES

SUPERVISOR = r'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp.exe'
MANAGED = r'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp-managed.exe'


def identity(value):
    if (not isinstance(value, dict) or type(value.get('pid')) is not int or
            value['pid'] <= 0 or not isinstance(value.get('creation_time'), str) or
            not value['creation_time'].isdecimal() or int(value['creation_time']) <= 0):
        raise StepError('invalid pinned process identity')
    return {key: value[key] for key in ('pid', 'creation_time')}


def canonical_run(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise StepError('noncanonical process run identity')
    return value


def marker_matches(marker, run_id, command_id):
    return (isinstance(marker, dict) and marker.get('run_id') == run_id and
            marker.get('command_id') == command_id and bool(command_id) and
            marker.get('needs_recovery') is True)


def require_mutation(payload, command_id, version):
    if (not isinstance(payload, dict) or payload.get('error') or
            payload.get('command_id') != command_id or
            type(payload.get('state_version')) is not int or
            payload['state_version'] < version or payload.get('in_progress')):
        raise StepError('process acceptance mutation receipt unconfirmed; preserve scene')
    return payload


def script(channel, name, expected):
    encoded = base64.b64encode(json.dumps(expected).encode()).decode('ascii')
    path = Path(__file__).with_name(name)
    # Literal helper references are source-pinned by the existing collector.
    text = path.read_text().replace('__EXPECTED__', encoded)
    if '__SCOPE_HELPERS__' in text:
        text = text.replace('__SCOPE_HELPERS__', Path(__file__).with_name('process_scope.ps1').read_text())
    raw = channel.powershell(text, timeout=60)
    if raw.get('is_error') or raw.get('exit_code') != 0:
        raise StepError('process observation/termination did not complete')
    return json.loads(raw['output']), raw


def images(channel):
    root = (getattr(channel, 'inputs', None) or {}).get('installation_root', str(PureWindowsPath(SUPERVISOR).parent))
    return [str(PureWindowsPath(root) / name) for name in ('fakenetng-mcp.exe', 'fakenetng-mcp-managed.exe')]


def observe_service(base, channel, writer, label):
    port = urlparse(base).port
    if type(port) is not int or not 0 < port < 65536:
        raise StepError('process observation requires explicit endpoint port')
    # Literal path retained so source discovery includes this fixed helper.
    Path(__file__).with_name('observe_process_service.ps1')
    value, raw = script(channel, 'observe_process_service.ps1', {'port': port})
    writer.add_evidence(label, raw)
    identity(value)
    if (value.get('state') != 'Running' or value.get('image', '').casefold() != images(channel)[0].casefold() or
            value.get('endpoint_owned') is not True or
            type(value.get('sampled_at')) not in (int, float) or
            not math.isfinite(value['sampled_at'])):
        raise StepError('current SCM/endpoint identity unconfirmed; preserve scene')
    return value


def creation_expected(receipt, stage, armed, command_id, service):
    if stage not in CREATION_STAGES or not isinstance(receipt, dict):
        raise StepError('unknown creation window')
    event = receipt.get('observation') or {}
    run = canonical_run(event.get('run_id'))
    if (receipt.get('nonce') != armed.get('nonce') or
            receipt.get('fault') != 'create_' + stage or
            armed.get('fault') != receipt['fault'] or event.get('stage') != stage or
            identity(event.get('supervisor')) != identity(service) or
            not marker_matches(service.get('marker'), run, command_id)):
        raise StepError('creation consumed receipt/command/supervisor differs')
    canonical_run(receipt['nonce'])
    members = event.get('job_members')
    if (not isinstance(members, list) or any(type(pid) is not int or pid <= 0 for pid in members) or
            len(members) != len(set(members)) or service['pid'] in members):
        raise StepError('invalid creation Job member set')
    child = event.get('child')
    if stage in CREATION_STAGES[:4]:
        if child is not None or members:
            raise StepError('child appeared before CreateProcess')
    elif not child or identity(child)['pid'] not in members:
        raise StepError('created child missing from Job')
    return dict(run_id=run, command_id=command_id, supervisor=identity(service),
                nonce=receipt['nonce'], fault=receipt['fault'], observation=event,
                child=child, job_members=members, managed_image=str(PureWindowsPath(service['image']).parent / 'fakenetng-mcp-managed.exe'))


def crash_failures(actual, expected):
    failures = []
    if (actual.get('run_id') != expected['run_id'] or
            actual.get('supervisor') != expected['supervisor'] or
            not marker_matches(actual.get('marker'), expected['run_id'], expected['command_id']) or
            actual.get('supervisor_exited') is not True):
        failures.append('pinned supervisor/command/exit differs')
    tree = actual.get('observed_tree')
    if not isinstance(tree, list):
        return failures + ['process tree observation missing']
    try:
        ids = [identity(row)['pid'] for row in tree]
        if len(ids) != len(set(ids)) or expected['supervisor']['pid'] in ids:
            raise StepError('duplicate or supervisor in tree')
        child = expected.get('child')
        if child:
            root = next(row for row in tree if row['pid'] == child['pid'])
            if (identity(root) != identity(child) or root.get('parent_pid') != expected['supervisor']['pid'] or
                    root.get('image', '').casefold() != expected['managed_image'].casefold() or root.get('run_id') != expected['run_id']):
                raise StepError('managed child identity/ownership differs')
            reachable = {child['pid']}
            for _ in tree:
                reachable.update(row['pid'] for row in tree if row.get('parent_pid') in reachable)
            if reachable != set(ids):
                raise StepError('foreign descendant')
            by_id = {row['pid']: row for row in tree}
            for row in tree:
                parent = by_id.get(row.get('parent_pid'), expected['supervisor'])
                if int(row['creation_time']) < int(parent['creation_time']):
                    raise StepError('descendant predates parent')
        elif tree:
            raise StepError('unexpected early creation members')
        if not set(expected.get('job_members', [])) <= set(ids):
            raise StepError('Job member not pinned')
        canary = identity(actual.get('canary'))
        if canary['pid'] in ids + [expected['supervisor']['pid']]:
            raise StepError('canary belongs to target')
    except (StepError, StopIteration, KeyError, TypeError, ValueError):
        failures.append('process birth/image/ancestry/member scope differs')
    if (actual.get('remaining_pids') != [] or actual.get('escaped') != [] or
            actual.get('canary_survived') is not True):
        failures.append('tree not collapsed or unrelated canary lost')
    if 'observation' in expected and actual.get('receipt') != {
            'fault': expected['fault'], 'nonce': expected['nonce'], 'observation': expected['observation']}:
        failures.append('consumed creation receipt changed')
    return failures


def creation_failures(facts, receipt, stage):
    rows = [json.loads(line) for line in facts['creation'].splitlines() if line.strip()]
    pipe = [json.loads(line) for line in facts['ipc'].splitlines() if line.strip()]
    expected = list(CREATION_STAGES[:CREATION_STAGES.index(stage) + 1])
    failures = []
    if [row.get('stage') for row in rows] != expected or not rows or rows[-1] != receipt['observation']:
        failures.append('creation stage prefix or consumed observation differs')
    prior_child = None
    for row in rows:
        if row.get('run_id') != receipt['observation']['run_id'] or row.get('supervisor') != receipt['observation']['supervisor']:
            failures.append('creation identity drift')
            break
        members = row.get('job_members')
        child = row.get('child')
        if row.get('stage') in CREATION_STAGES[:4]:
            if child is not None or members != []:
                failures.append('early child/Job member before process creation')
        else:
            try:
                item = identity(child)
                if not isinstance(members, list) or any(type(pid) is not int or pid <= 0 for pid in members) or len(members) != len(set(members)) or item['pid'] not in members or (prior_child and item != prior_child):
                    raise StepError('created child/Job scope drift')
                prior_child = item
            except (StepError, TypeError):
                failures.append('created child/Job identity absent or changed')
    if any((row.get('frame') or {}).get('kind') == 'start' for row in pipe) or facts.get('pcaps') != []:
        failures.append('takeover before selected creation window')
    return failures


def recovery_failures(before, after, events_before, events_after, marker):
    """Use the real per-process EventLog recovery audit, never a log substring."""
    failures = []
    if (identity(before) == identity(after) or before['pid'] == after['pid'] or
            int(after['creation_time']) <= int(before['creation_time']) or
            after.get('state') != 'Running' or after.get('image', '').casefold() != before.get('image', '').casefold() or
            after.get('endpoint_owned') is not True):
        failures.append('new SCM instance unproven')
    current = after.get('marker') or {}
    if (not marker_matches(marker, marker.get('run_id'), marker.get('command_id')) or
            current != dict(marker, needs_recovery=False)):
        failures.append('original recovery responsibility not cleared exactly')
    old = events_before.get('events') or []
    rows = events_after.get('events') or []
    epochs = {r.get('epoch') for r in rows}
    birth = (int(after['creation_time']) - 116444736000000000) / 10000000
    try:
        if events_before.get('error') or events_after.get('error') or not old or not rows or len(epochs) != 1 or None in epochs or '' in epochs or epochs & {r.get('epoch') for r in old}:
            raise ValueError('recovery epoch missing or reused')
        seq = [r['seq'] for r in rows]
        if any(type(n) is not int or n <= 0 for n in seq) or seq != sorted(set(seq)):
            raise ValueError('invalid recovery order')
        if any(type(r.get('timestamp')) not in (int, float) or not math.isfinite(r['timestamp']) or not birth <= r['timestamp'] <= after['sampled_at'] for r in rows):
            raise ValueError('recovery outside current incarnation')
        states = [r.get('state') for r in rows if r.get('kind') == 'recovery']
        if states != ['recovering', 'stopped'] or any(r.get('command_id') or str(r.get('kind','')).startswith('command.') for r in rows):
            raise ValueError('startup recovery/absence of replay unproven')
    except (ValueError, KeyError, TypeError):
        failures.append('current instance startup recovery audit absent/unknown or replayed')
    return failures


def confirm_recovery(base, channel, writer, prefix, before, old_events, marker):
    from run_p03_acc import call, wait_state
    from replay_observation import observe_no_replay
    settled, status = wait_state(base, lambda x: x.get('state') in ('stopped', 'failed'), timeout=420)
    writer.add_evidence(prefix + '-recovered-status', status or {})
    # Bracket the entire read-only MCP window with the same SCM/endpoint birth.
    first = observe_service(base, channel, writer, prefix + '-recovery-instance-before')
    no_replay = observe_no_replay(base, channel, writer, prefix, marker)
    events = call(base, 'get_events', {'limit': 500}, controller=None)
    writer.add_evidence(prefix + '-recovery-events', events)
    last = observe_service(base, channel, writer, prefix + '-recovery-instance-after')
    failures = recovery_failures(before, last, old_events, events, marker)
    if identity(first) != identity(last):
        failures.append('SCM instance changed inside recovery observation')
    if not settled or not status or status.get('state') != 'stopped' or status.get('run_id') or not no_replay:
        failures.append('recovery stopped/no continuation window unproven')
    return failures
