"""Ordinary run artifacts, never a source of recovery or command execution."""
import hashlib
import os
from pathlib import Path
import uuid


def prepare_run_evidence(directory, config_path, config_sha256):
    directory = Path(directory)
    content = Path(config_path).read_bytes()
    if hashlib.sha256(content).hexdigest() != config_sha256:
        raise RuntimeError('activity-locked configuration changed before evidence copy')
    for name, raw in (('active-config.ini', content), ('stdout_stderr.log', b''), ('run.log', b'')):
        with (directory / name).open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())


def locate_run_evidence(artifacts_root, marker):
    """Resolve only a fixed run directory; configuration must match the marker."""
    if not artifacts_root or not marker:
        return None, None
    run_id = str(uuid.UUID(marker['run_id']))
    root = Path(artifacts_root).resolve()
    directory = root / 'runs' / run_id
    if not directory.is_dir() or directory.resolve() != directory:
        return None, None
    config = directory / 'active-config.ini'
    if (not config.is_file() or config.is_symlink() or
            hashlib.sha256(config.read_bytes()).hexdigest() != marker['config_sha256']):
        config = None
    return directory, config
