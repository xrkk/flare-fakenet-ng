"""Latest managed stack observation; evidence only, never recovery commands."""
import json
import os
from pathlib import Path
import tempfile
import time


def save_stacks(directory, run_id, identity, stacks):
    payload = {'run_id': run_id, 'identity': identity, 'time_ns': time.time_ns(), 'stacks': stacks}
    root = Path(directory)
    fd, temporary = tempfile.mkstemp(dir=root, prefix='.managed-stacks-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(payload, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, root / 'managed-thread-stacks.json')
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_stacks(directory, run_id, identity):
    try:
        data = json.loads((Path(directory)/'managed-thread-stacks.json').read_text(encoding='utf-8'))
        if (data['run_id'] != run_id or data['identity'] != identity or
                type(data['time_ns']) is not int or not 0 < data['time_ns'] <= time.time_ns() or
                not isinstance(data['stacks'], str) or
                not data['stacks'].strip()):
            return None
        return ('LAST MANAGED PROTOCOL OBSERVATION; NOT A LIVE IPC RESPONSE\n'
                'run=%s identity=%s time_ns=%s\n%s' %
                (run_id, json.dumps(identity, sort_keys=True), data['time_ns'], data['stacks']))
    except (OSError, ValueError, KeyError, TypeError):
        return None
