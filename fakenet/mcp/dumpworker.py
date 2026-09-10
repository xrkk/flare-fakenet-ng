# Copyright 2026 Google LLC
"""Diagnostic subprocess with target identity, bounded writes and owned staging."""
import contextlib
import os
import json
import sys
import time
from pathlib import Path


def collect_dump(pid, creation_time, target, deadline, quota=None):
    import msvcrt
    from fakenet.mcp.jobobject import ManagedJob
    from fakenet.mcp.exit_native import verify_dump
    target = Path(target)
    staging = target.with_name(target.name + '.part')
    limit = min(512 * 1024 * 1024, quota if quota is not None else 512 * 1024 * 1024)
    limit -= 4096  # bounded structured tool output, including failed calls
    if limit < 32 or time.monotonic() >= deadline:
        raise TimeoutError('dump has no remaining budget')
    # The current incident owns this unique directory; never replace another
    # attempt's incomplete evidence or silently adopt its output.
    if staging.exists() or target.exists():
        raise RuntimeError('dump destination already exists')
    prefix = ([sys.executable] if getattr(sys, 'frozen', False) else
              [sys.executable, '-m', 'fakenet.mcp'])
    command = prefix + ['incident-dump', str(pid), str(creation_time), str(staging),
                        str(limit), repr(deadline)]
    job = ManagedJob()
    handles = []
    spawned = False
    try:
        with contextlib.ExitStack() as stack:
            streams = [stack.enter_context(open(os.devnull, 'rb')),
                       stack.enter_context(open(os.devnull, 'wb')),
                       stack.enter_context(open(os.devnull, 'wb'))]
            handles = [msvcrt.get_osfhandle(stream.fileno()) for stream in streams]
            try:
                for handle in handles:
                    os.set_handle_inheritable(handle, True)
                root = (Path(sys.executable).parent if getattr(sys, 'frozen', False)
                        else Path(__file__).resolve().parents[2])
                job.spawn(command, root, handles)
                spawned = True
                while job.poll() is None:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('dump helper exceeded deadline')
                    time.sleep(min(0.02, max(0, deadline - time.monotonic())))
                if job.poll() != 0:
                    raise RuntimeError('dump helper failed; see dump-tool.json')
                verify_dump(staging, pid, limit)
                if time.monotonic() >= deadline:
                    raise TimeoutError('dump exceeded deadline before publication')
                os.replace(staging, target)
                if time.monotonic() >= deadline:
                    target.unlink()
                    raise TimeoutError('dump publication exceeded deadline')
            finally:
                # Stop the writer before removing any staging it owns.
                try:
                    if spawned and job.poll() is None:
                        job.terminate(deadline)
                finally:
                    job.close()
                    for handle in handles:
                        os.set_handle_inheritable(handle, False)
    finally:
        if staging.exists():
            staging.unlink()


def dump_main(pid, creation_time, target, quota=512 * 1024 * 1024, deadline=None):
    diagnostic = Path(target).parent / 'dump-tool.json'
    result = {'pid': pid, 'creation_time': str(creation_time), 'complete': False}
    code = 1
    try:
        from fakenet.mcp.exit_native import TargetHandle
        deadline = deadline if deadline is not None else time.monotonic() + 60
        if quota < 32 or quota > 512 * 1024 * 1024 or time.monotonic() >= deadline:
            raise RuntimeError('invalid dump budget')
        with TargetHandle(pid) as process:
            if process.identity()['creation_time'] != str(creation_time):
                raise RuntimeError('dump target identity changed before the handle opened')
            process.dump(target, quota=quota, deadline=deadline)
        result['complete'], code = True, 0
    except Exception as exc:
        result['exception_type'] = type(exc).__name__
        result['error'] = str(exc)[:400]
        result['winerror'] = getattr(exc, 'winerror', None)
    # ASCII escaping has a known maximum size; exception text is capped above.
    raw = json.dumps(result, ensure_ascii=True).encode('ascii')
    if len(raw) > 4096:
        raise RuntimeError('dump diagnostic exceeds reserved quota')
    diagnostic.write_bytes(raw)
    return code
