"""Reject mixed identities, missing raw evidence and incomplete round windows."""
import hashlib
from pathlib import Path


IDENTITY_FIELDS = ('candidate_id', 'source_commit', 'package_sha256',
                   'requirements_blob', 'master_plan_blob')


def validate_result(record, expected, root):
    failures = []
    for field in IDENTITY_FIELDS:
        if not expected.get(field) or record.get(field) != expected[field]:
            failures.append('identity mismatch: ' + field)
    if record.get('status') != 'pass' or record.get('blocker'):
        failures.append('result is not an unblocked pass')
    evidence = record.get('evidence')
    if not isinstance(evidence, list) or not evidence:
        return failures + ['raw evidence missing']
    root = Path(root).resolve()
    for item in evidence:
        try:
            path = Path(item['path']).resolve()
            if not path.is_relative_to(root):
                raise ValueError('evidence outside candidate directory')
            raw = path.read_bytes()
            if len(raw) != item['size'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
                raise ValueError('evidence hash/size mismatch')
        except (KeyError, TypeError, OSError, ValueError) as exc:
            failures.append(str(exc))
    return failures


def validate_round(record, expected):
    failures = []
    for field in IDENTITY_FIELDS:
        if not expected.get(field) or record.get(field) != expected[field]:
            failures.append('identity mismatch: ' + field)
    if record.get('failure') or record.get('final_state') != 'stopped':
        failures.append('round did not converge')
    if record.get('audit_diff') or 'audit_diff' not in record:
        failures.append('audit absent or dirty')
    if not record.get('lock_released_after_stop'):
        failures.append('configuration lock not released')
    start, end = record.get('probe_window_start'), record.get('probe_window_end')
    timeline = record.get('probe_timeline')
    if not isinstance(start, (int, float)) or not isinstance(end, (int, float)) or not timeline:
        return failures + ['full probe window absent']
    times = [p.get('t') for p in timeline]
    if (any(not isinstance(t, (int, float)) for t in times) or
            any(not p.get('ok') for p in timeline)):
        return failures + ['invalid or failed probe']
    if times != sorted(times) or times[0] > start or times[-1] < end:
        failures.append('probe window not covered')
    if any(b-a > 2 for a, b in zip(times, times[1:])):
        failures.append('probe sampling gap exceeds two seconds')
    before, after = record.get('vm_before'), record.get('vm_after')
    if not before or before != after:
        failures.append('VM/service identity drift')
    return failures
