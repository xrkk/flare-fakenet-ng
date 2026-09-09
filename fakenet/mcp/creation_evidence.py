# Copyright 2026 Google LLC
"""Actual managed-create stages and locally gated native crash windows."""

import json
import os
import time
from pathlib import Path

from fakenet.mcp import faultinject

CREATION_STAGES = ('before_job', 'job_ready', 'attributes_ready', 'before_api',
                   'after_api', 'before_start')


def observe_creation(run_id, run_dir, job, stage):
    if stage not in CREATION_STAGES:
        raise ValueError('unknown managed creation stage')
    from fakenet.mcp.service_stop import process_identity
    event = {'stage': stage, 'run_id': run_id, 'time': time.time(),
             'monotonic': time.monotonic(),
             'supervisor': process_identity(os.getpid()),
             'child': process_identity(job.pid) if job is not None and job.pid else None,
             'job_members': job.members() if job is not None else []}
    directory = Path(run_dir)
    with (directory / 'creation.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(event) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    expected = 'create_' + stage
    if not faultinject.enabled() or faultinject.armed_fault() != expected:
        return
    path = faultinject._fault_file()
    receipt = json.loads(path.read_text(encoding='utf-8'))
    # Fixed local input only. A changed arming record must not select this window.
    if receipt.get('fault') != expected:
        raise RuntimeError('creation fault changed while consuming')
    with (directory / 'creation-fault-triggered.json').open('x', encoding='utf-8') as stream:
        json.dump(dict(receipt, observation=event), stream)
        stream.flush()
        os.fsync(stream.fileno())
    path.unlink()
    # The native runner kills the pinned supervisor while it is at this stage.
    # Timeout fails closed: it must never silently continue into takeover.
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    raise TimeoutError('native creation fault window expired without supervisor crash')
