# Copyright 2026 Google LLC
"""Single current-recovery snapshot: state/state.json (P03 IMP-P03-03).

Sub-plan P03 §3 / master plan OUT-008 / REQ-007 (record 038):

* exactly one plain JSON file with the seven frozen fields
  (run_id, controller_id, state_version, command_id, config_sha256,
  baseline_path, needs_recovery);
* writes go same-dir temp file -> fsync -> atomic ``os.replace``;
* a write failure before start refuses the start (FB-003);
* a corrupt/missing snapshot WITH observed residue means ``failed``
  (FB-004) — never a guessed ``stopped``;
* the snapshot is a recovery note only: no history, no replay, no schema
  migration (CON-006/NON-008).
"""

import json
import os
import re
import tempfile
from pathlib import Path

SNAPSHOT_FIELDS = ('run_id', 'controller_id', 'state_version', 'command_id',
                   'config_sha256', 'baseline_path', 'needs_recovery')


class SnapshotError(RuntimeError):
    pass


def valid_fields(data):
    if not isinstance(data, dict) or set(data) != set(SNAPSHOT_FIELDS):
        return False
    if type(data['needs_recovery']) is not bool or type(data['state_version']) is not int:
        return False
    if data['state_version'] < 1:
        return False
    if not isinstance(data['run_id'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', data['run_id']):
        return False
    for field in ('controller_id', 'command_id'):
        if data[field] is not None and (not isinstance(data[field], str) or not data[field]):
            return False
    if not isinstance(data['config_sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', data['config_sha256']):
        return False
    if not isinstance(data['baseline_path'], str):
        return False
    if data['needs_recovery'] and (not data['baseline_path'] or not data['command_id']):
        return False
    return True


class StateSnapshot:

    def __init__(self, path):
        self.path = Path(path)

    def write(self, **fields):
        missing = [name for name in SNAPSHOT_FIELDS if name not in fields]
        if missing:
            raise SnapshotError('snapshot missing fields: %s' % missing)
        if not valid_fields(fields):
            raise SnapshotError('snapshot field values invalid')
        payload = json.dumps({name: fields[name]
                              for name in SNAPSHOT_FIELDS},
                             ensure_ascii=False, indent=2) + '\n'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle, tmp_name = tempfile.mkstemp(dir=str(self.path.parent),
                                            prefix='.state-',
                                            suffix='.json')
        try:
            with os.fdopen(handle, 'w', encoding='utf-8') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_name, self.path)
        except OSError as exc:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise SnapshotError('snapshot write failed: %r' % exc) from exc

    def clear_recovery(self, **fields):
        fields['needs_recovery'] = False
        self.write(**fields)

    def read(self):
        """Return the parsed snapshot or None when absent/corrupt.

        ``corrupt`` is reported separately from ``absent`` so callers can
        apply FB-004 semantics (corrupt + residue => failed).
        """
        if not self.path.is_file():
            return None, False
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return None, True
        if not valid_fields(data):
            return None, True
        return data, False
