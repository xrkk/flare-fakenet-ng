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
import tempfile
from pathlib import Path

SNAPSHOT_FIELDS = ('run_id', 'controller_id', 'state_version', 'command_id',
                   'config_sha256', 'baseline_path', 'needs_recovery')


class SnapshotError(RuntimeError):
    pass


class StateSnapshot:

    def __init__(self, path):
        self.path = Path(path)

    def write(self, **fields):
        missing = [name for name in SNAPSHOT_FIELDS if name not in fields]
        if missing:
            raise SnapshotError('snapshot missing fields: %s' % missing)
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
        if not isinstance(data, dict) or \
                not all(name in data for name in SNAPSHOT_FIELDS):
            return None, True
        return data, False
