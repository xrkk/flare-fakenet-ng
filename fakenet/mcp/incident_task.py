# Copyright 2026 Google LLC
"""Disk and system observations for one isolated incident collection.

Preparation and collection are two fixed diagnostic operations. The
supervisor re-observes the managed Job between them, so a tree that exits
during preparation is judged at the actual collection boundary. The prepared
context crosses the boundary only through one bounded staging file with a
single-use token; every residue is swept by the next preparation of the
same run.
"""
import hashlib
import importlib.metadata
import json
import os
import platform
from pathlib import Path
import sys
import time
import uuid

STAGING_FILE_CAP = 32 * 1024 * 1024
STAGING_TOTAL_CAP = 64 * 1024 * 1024


def _staging_path(artifacts_root, run_id, token):
    if not isinstance(token, str):
        raise ValueError('invalid incident staging token')
    try:
        normalized = str(uuid.UUID(token))
    except ValueError:
        raise ValueError('invalid incident staging token') from None
    if normalized != token:
        raise ValueError('invalid incident staging token')
    return Path(artifacts_root) / str(run_id) / ('incident-staging-%s.json' % token)


def prepare(request, directories, package, deadline):
    from fakenet.mcp.baseline import BaselineStore, capture, audit_compare
    from fakenet.mcp.managed_stacks import read_stacks
    from fakenet.mcp.exit_files import QUOTA, digest
    run_id = request['run_id']
    run_dir = directories['artifacts'] / 'runs' / run_id

    def read_file(name):
        path = run_dir / name
        if not path.is_file():
            return None
        if path.stat().st_size > STAGING_FILE_CAP:
            # An oversized source becomes an explicitly unavailable item;
            # it must not be read into an unbounded in-memory copy.
            return None
        return path.read_bytes().decode('utf-8', 'replace')

    stacks = request.get('live_stacks')
    snapshot_stacks = False
    observed = request.get('managed') or {}
    identity = observed.get('identity')
    if not stacks:
        stop_stacks = read_file('stop-thread-stacks.txt')
        if stop_stacks and 'File "' in stop_stacks:
            stacks = 'MANAGED STOP WATCHDOG; LIVE CHILD CAPTURE\n' + stop_stacks
    if not stacks and identity:
        stacks = read_stacks(run_dir, run_id, identity)
        snapshot_stacks = stacks is not None
    if not stacks and request.get('last_stacks') and observed.get('exit_code') is not None:
        stacks = 'LAST OBSERVATION BEFORE STOP; ROOT HAS EXITED\n' + request['last_stacks']
        extra = read_file('fault-child-stacks.txt')
        if extra:
            stacks += '\nMANAGED FAULT CHILD\n' + extra
    baseline = BaselineStore(directories['baselines']).load(run_id)
    current = capture(deadline)
    versions = dict(python=sys.version, os=platform.platform(),
                    executable=str(package / 'fakenetng-mcp.exe'),
                    config_sha256=request['config_sha256'], dependencies={},
                    managed_process=observed)
    for name in ('mcp', 'pydivert', 'pywin32'):
        try:
            versions['dependencies'][name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions['dependencies'][name] = 'metadata unavailable'
    manifest = package / 'mcp-candidate-manifest.json'
    if manifest.is_file():
        if manifest.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError('candidate manifest exceeds fixed bound')
        versions['candidate_manifest'] = json.loads(manifest.read_text(encoding='utf-8'))
    metadata = []
    if run_dir.is_dir():
        for index, path in enumerate(run_dir.iterdir()):
            if index >= 10000 or time.monotonic() >= deadline:
                raise RuntimeError('incident metadata observation budget exhausted')
            if path.is_symlink():
                raise RuntimeError('linked run evidence')
            if path.is_file():
                sha, size = digest(path, QUOTA, deadline)
                metadata.append(dict(path=str(path), size=size, sha256=sha))
    reason = request['reason']
    target = request.get('dump_target') or {}
    if target.get('role') == 'supervisor':
        versions['dump_target'] = dict(role='supervisor', identity=target['identity'],
                                       phase='post-Job restoration audit')
    identity_target = target.get('identity') or {}
    config = run_dir / 'active-config.ini'
    managed_dump_target = (target.get('role') == 'managed' and
                           type(identity_target.get('pid')) is int and
                           identity_target['pid'] > 0 and
                           isinstance(identity_target.get('creation_time'), str) and
                           identity_target['creation_time'])
    dump_reason = ('restoration audit failure after verified managed Job exit'
                   if target.get('role') == 'supervisor' else
                   ('managed hang/timeout'
                    if 'timeout' in reason.lower() or 'did not exit' in reason.lower() else
                    'live managed IPC stacks unavailable' if snapshot_stacks else
                    None if stacks else 'managed stacks unavailable')
                   if managed_dump_target else None)
    context = dict(timeline=request['timeline'], versions=versions, config_path=config,
                   stdout_stderr=read_file('stdout_stderr.log'),
                   run_log_window=read_file('run.log'), exception_text=reason,
                   managed_thread_stacks=stacks, final_filter=request.get('final_filter'),
                   baseline_diff=dict(before=baseline, after=current,
                        differences=audit_compare((baseline or {}).get('sections'), current)),
                   firewall_baseline=(baseline or {}).get('firewall'), artifact_metadata=metadata,
                   dump_target_pid=identity_target.get('pid'),
                   dump_target_creation=identity_target.get('creation_time'),
                   dump_reason=dump_reason)
    exit_report = request.get('exit_report')
    if exit_report is not None:
        context['exit_evidence'] = exit_report
        if target.get('role') != 'supervisor' and exit_report.get('complete') and exit_report.get('dump'):
            from fakenet.mcp.exit_files import root, run_directory
            context['precollected_exit_dump'] = dict(path=run_directory(root(), run_id) / 'target.dmp',
                    identity=exit_report['target'], dump=exit_report['dump'])
            context['dump_reason'] = 'managed exit requires root-cause evidence'
    return context


def prepare_stage(request, directories, package, deadline):
    staging = _staging_path(directories['artifacts'], request['run_id'], request['token'])
    context = prepare(request, directories, package, deadline)
    parent = staging.parent
    parent.mkdir(parents=True, exist_ok=True)
    # Intermediate staging of this run only: a residue from a killed task can
    # never survive into the next preparation of the same run.
    for stale in parent.glob('incident-staging-*'):
        stale.unlink(missing_ok=True)
    payload = json.dumps(context, ensure_ascii=False, default=str).encode('utf-8')
    if len(payload) > STAGING_TOTAL_CAP:
        raise RuntimeError('incident staging exceeds fixed bound')
    temporary = staging.with_name(staging.name + '.new')
    if temporary.exists():
        raise RuntimeError('incident staging already exists')
    with temporary.open('xb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, staging)
    return dict(staging=str(staging), size=len(payload))


def collect_stage(request, directories, package, deadline, watchdog=None):
    staging = _staging_path(directories['artifacts'], request['run_id'], request['staging'])
    if request.get('abort'):
        for residue in staging.parent.glob('incident-staging-%s.*' % request['staging']):
            residue.unlink(missing_ok=True)
        return dict(skipped_same_failure=True, incident_path=None)
    if not staging.is_file():
        raise RuntimeError('incident staging absent')
    if staging.stat().st_size > STAGING_TOTAL_CAP:
        raise RuntimeError('incident staging exceeds fixed bound')
    context = json.loads(staging.read_bytes().decode('utf-8'))
    staging.unlink()
    from fakenet.mcp.incident import IncidentCollector
    from fakenet.mcp.exit_monitor import active_bytes
    from fakenet.mcp.exit_files import root, QUOTA
    remaining = QUOTA - active_bytes(root())
    if remaining < 64 * 1024:
        raise RuntimeError('global activity quota unavailable for incident metadata')
    collector = IncidentCollector(directories['artifacts'], request['run_id'], quota=remaining)
    collector.deadline = min(collector.deadline, time.time() + max(0, deadline - time.monotonic()))
    collector.watchdog = watchdog
    collector.collect(context)
    complete = bool(collector.manifest) and all(item['result'] == 'ok' for item in collector.manifest)
    has_dump = any(item['item'] == 'userdump.dmp' and item['size'] > 0 for item in collector.manifest)
    return dict(incident_path=str(collector.root), complete=complete, has_dump=has_dump)
