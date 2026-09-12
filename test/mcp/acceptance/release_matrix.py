"""Explicit reduced matrix identity; never infer a pass from planned counts."""
import datetime
import json
import re
from pathlib import Path

FAULTS = ('policy_pause', 'listener_stop', 'diverter_stop', 'child_hang', 'cleanup_error')
FULL = dict([('normal-builtin', 50), ('normal-custom', 50)] + [('fault-' + f, 10) for f in FAULTS])
REDUCED = dict([('normal-builtin', 3), ('normal-custom', 2)] + [('fault-' + f, 1) for f in FAULTS])


class MatrixUsageError(ValueError):
    """A valid frozen matrix was requested with different CLI limits."""


def parse_limit(mode, value):
    if mode not in ('normal', 'fault'):
        raise ValueError('rounds-limit is only valid for normal/fault')
    try:
        pairs = [part.split('=') for part in value.split(',')]
        if len({p[0] for p in pairs}) != len(pairs):
            raise ValueError('duplicate limit')
        values = {k: int(v) for k, v in pairs}
    except (TypeError, ValueError):
        raise ValueError('invalid rounds-limit') from None
    expected = {'builtin', 'custom'} if mode == 'normal' else {'per-class'}
    maximum = 50 if mode == 'normal' else 10
    if set(values) != expected or any(not 1 <= n <= maximum for n in values.values()):
        raise ValueError('rounds-limit keys/count outside contract')
    return ({'normal-' + k: v for k, v in values.items()} if mode == 'normal'
            else {'fault-' + f: values['per-class'] for f in FAULTS})


def matrix_counts(args, release):
    root = Path(release).resolve()
    path = root / 'matrix-manifest.json'
    limit = getattr(args, 'rounds_limit', None)
    requested = parse_limit(args.mode, limit) if limit is not None else None
    identity = {k: getattr(args, k) for k in ('candidate_id', 'source_commit', 'package_sha256')}
    if not path.exists() and requested is not None:
        if any(re.fullmatch(r'(?:normal|fault)-.+-\d+\.json', p.name) for p in root.glob('*.json')):
            raise ValueError('cannot mix existing rounds into reduced matrix')
        planned = dict(REDUCED, **requested)
        payload = dict(mode='reduced', **identity, evidence_root=str(root), planned=planned,
                       created_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
        try:
            with path.open('x', encoding='utf-8') as stream:
                json.dump(payload, stream, indent=2)
                stream.write('\n')
        except FileExistsError:
            pass  # Read and validate the winner; never replace it.
    if not path.exists():
        return dict(FULL)
    record = json.loads(path.read_text(encoding='utf-8'))
    if record.get('mode') != 'reduced' or record.get('evidence_root') != str(root):
        raise ValueError('reduced matrix mode/root mismatch')
    if any(record.get(k) != v for k, v in identity.items()):
        raise ValueError('reduced matrix candidate identity mismatch')
    planned = record.get('planned', {})
    if set(planned) != set(FULL) or any(type(n) is not int or not 1 <= n <= FULL[k] for k, n in planned.items()):
        raise ValueError('invalid reduced matrix planned counts')
    if requested is None and args.mode in ('normal', 'fault'):
        raise MatrixUsageError('reduced matrix requires explicit matching rounds-limit')
    if requested and any(planned[k] != n for k, n in requested.items()):
        raise MatrixUsageError('rounds-limit differs from frozen matrix')
    for p in root.glob('*.json'):
        prefix, _, index = p.stem.rpartition('-')
        if index.isdigit() and prefix.startswith(('normal-', 'fault-')):
            if prefix not in planned or not 1 <= int(index) <= planned[prefix]:
                raise ValueError('round outside frozen matrix: ' + p.name)
    return planned
