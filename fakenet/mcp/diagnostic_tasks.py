# Copyright 2026 Google LLC
"""Closed internal task vocabulary for the installed diagnostic Job.

No caller-provided executable, shell command or arbitrary file path is
accepted. Paths are reconstructed from product roots and validated run IDs.
"""
import json
import math
import os
from pathlib import Path
import sys
import time
import uuid

EXIT_FILES = frozenset(('target.json', 'entry.json', 'result.json', 'owner-acquired.json',
                        'owner-result.json', 'normal-claim.json', 'normal-ack.json',
                        'stop-intent.json', 'capability.json'))


def _run_id(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError('invalid diagnostic run identity')
    return value


def _exit_path(payload):
    from fakenet.mcp.exit_files import root, run_directory
    name = payload['name']
    if name not in EXIT_FILES:
        raise ValueError('unknown exit diagnostic member')
    base = root()
    if name == 'target.json':
        return base / name
    return run_directory(base, _run_id(payload['run_id'])) / name


def execute(operation, payload, deadline, watchdog=None):
    from fakenet.mcp.exit_files import read, publish, root, run_directory, digest, QUOTA
    if time.monotonic() >= deadline:
        raise TimeoutError('diagnostic task already expired')
    if operation == 'exit-init':
        record = payload['record']
        directory = run_directory(root(), _run_id(record['run_id']))
        directory.mkdir(exist_ok=False)
        publish(root() / 'target.json', record)
        return True
    if operation == 'exit-read':
        path = _exit_path(payload)
        try:
            return read(path)
        except FileNotFoundError:
            return None
    if operation == 'exit-publish':
        path = _exit_path(payload)
        path.parent.mkdir(parents=True, exist_ok=True)
        publish(path, payload['record'])
        if time.monotonic() >= deadline:
            raise TimeoutError('exit publication expired')
        return True
    if operation == 'exit-remove-intent':
        path = run_directory(root(), _run_id(payload['run_id'])) / 'stop-intent.json'
        path.unlink(missing_ok=True)
        return True
    if operation == 'exit-verify-dump':
        from fakenet.mcp.exit_native import verify_dump
        path = run_directory(root(), _run_id(payload['run_id'])) / 'target.dmp'
        size = verify_dump(path, payload['pid'], QUOTA)
        sha, observed = digest(path, QUOTA, deadline)
        if size != observed:
            raise ValueError('exit dump changed during validation')
        return dict(size=size, sha256=sha)
    if operation == 'exit-scan':
        from fakenet.mcp.exit_installation import Observation, OBSERVATION_BUDGET, assert_no_helpers, end_helpers
        package = Path(sys.executable).parent
        if not getattr(sys, 'frozen', False):
            package = Path(__file__).resolve().parents[2]
        if payload.get('terminate') is True:
            end_helpers(package, deadline)
        else:
            assert_no_helpers(package, Observation(deadline, OBSERVATION_BUDGET))
        return dict(helpers_ended=True)
    if operation == 'incident-prepare':
        from fakenet.mcp.incident_task import prepare_stage
        from fakenet.mcp.paths import data_directories
        _run_id(payload['run_id'])
        package = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[2]
        return prepare_stage(payload, data_directories(), package, deadline)
    if operation == 'incident-collect':
        from fakenet.mcp.incident_task import collect_stage
        from fakenet.mcp.paths import data_directories
        _run_id(payload['run_id'])
        package = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parents[2]
        return collect_stage(payload, data_directories(), package, deadline, watchdog)
    if operation == 'list-artifacts':
        from fakenet.mcp.paths import data_directories
        from fakenet.mcp.artifacts import ArtifactRegistry
        return ArtifactRegistry(data_directories()['artifacts']).metadata(deadline)
    if operation == 'register-artifacts':
        from fakenet.mcp.paths import data_directories
        from fakenet.mcp.artifacts import ArtifactRegistry
        run_id = _run_id(payload['run_id'])
        artifacts = data_directories()['artifacts']
        copied = ArtifactRegistry(artifacts).register_fakenet_outputs(
            run_id, artifacts / 'runs' / run_id, prefix='')
        return dict(count=len(copied))
    raise ValueError('unknown diagnostic operation')


def main():
    from fakenet.mcp.diagnostic_process import MAX_FRAME
    import ctypes as c
    from ctypes import wintypes as w
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)]
    contained = w.BOOL()
    if not kernel.IsProcessInJob(kernel.GetCurrentProcess(), None, c.byref(contained)) or not contained:
        return 2
    request = None
    watchdog = None
    try:
        raw = sys.stdin.buffer.readline(MAX_FRAME + 1)
        if not raw.endswith(b'\n') or len(raw) > MAX_FRAME:
            return 2
        request = json.loads(raw)
        if request.get('schema') != 'fakenet.diagnostic-call.v1':
            return 2
        _run_id(request['attempt'])
        deadline = request['deadline']
        if not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
            return 2
        from fakenet.mcp.exit_native import TargetHandle
        with TargetHandle(request['parent_pid']) as parent:
            identity = parent.identity()
            if (identity['creation_time'] != request['parent_identity']['creation_time'] or
                    identity['pid'] != request['parent_identity']['pid']):
                return 2
            image = Path(identity['image'])
            if getattr(sys, 'frozen', False) and str(image).casefold() != str(Path(sys.executable).parent / 'fakenetng-mcp.exe').casefold():
                return 2
            from contextlib import nullcontext
            from fakenet.mcp.exit_guard import SingleFlight
            bulk = request['operation'] in ('incident-prepare', 'incident-collect',
                                            'exit-verify-dump', 'register-artifacts')
            watchdog = ItemWatchdog(min(deadline, request['started']+60), reserve=2 if bulk else 0)
            with (SingleFlight() if bulk else nullcontext()):
                result = execute(request['operation'], request['payload'], deadline, watchdog)
        if time.monotonic() >= deadline:
            raise TimeoutError('diagnostic result expired')
        report = dict(attempt=request['attempt'], operation=request['operation'], result=result, error=None)
        code = 0
    except BaseException as exc:
        if not isinstance(request, dict):
            return 2
        report = dict(attempt=request.get('attempt'), operation=request.get('operation'),
                      result=None, error=repr(exc)[:2000])
        code = 1
    encoded = json.dumps(report).encode('utf-8') + b'\n'
    if len(encoded) > MAX_FRAME:
        return 2
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    if watchdog is not None:
        watchdog.done.set()
    return code


class ItemWatchdog:
    """Only this short-lived worker exits; the supervisor keeps its Job."""
    def __init__(self, deadline, reserve=0):
        import threading
        self.deadline = deadline
        self.reserve = reserve
        self.done = threading.Event()
        def watch():
            while not self.done.wait(.01):
                if time.monotonic() >= self.deadline - self.reserve:
                    os._exit(124)
        self.thread = threading.Thread(target=watch, name='diagnostic-item-deadline', daemon=True)
        self.thread.start()
