# Copyright 2026 Google LLC
"""Root-cause incident evidence packs (P04 IMP-P04-02, record 034/035).

Each terminal failure collects a bounded, itemized evidence pack under
``%ProgramData%\\FakeNet-NG-MCP\\artifacts\\<run_id>\\incident\\`` with a
manifest recording ``item/result/failure_reason/size/sha256`` for every
entry.  Missing items are recorded explicitly (they fail evidence
completeness acceptance) but never block the bounded safe cleanup.
"""

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ITEM_TIMEOUT_SECONDS = 60
TOTAL_BUDGET_SECONDS = 180
DISK_QUOTA_BYTES = 512 * 1024 * 1024
METADATA_RESERVE_BYTES = 64 * 1024

BASIC_ITEMS = (
    ('timeline.json', 'timeline'),
    ('versions.json', 'versions'),
    ('config_snapshot.ini', 'config_snapshot'),
    ('stdout_stderr.log', 'stdout_stderr'),
    ('run_log.txt', 'run_log'),
    ('exception.txt', 'exception'),
    ('thread_stacks.txt', 'thread_stacks'),
    ('process_tree.txt', 'process_tree'),
    ('handle_summary.txt', 'handle_summary'),
    ('windivert_filter.txt', 'windivert_filter'),
    ('baseline_diff.json', 'baseline_diff'),
    ('firewall_diff.txt', 'firewall_diff'),
    ('event_log.txt', 'event_log'),
    ('artifact_metadata.json', 'artifact_metadata'),
)


def _sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def _run(command, timeout=30):
    encoding = 'utf-8'
    if os.name == 'nt':
        import ctypes
        encoding = 'cp%d' % ctypes.windll.kernel32.GetOEMCP()
        if str(command[0]).lower() in ('powershell', 'powershell.exe'):
            command = list(command)
            command[-1] = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); " + command[-1]
            encoding = 'utf-8'
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=timeout,
        encoding=encoding, errors='strict')
    if completed.returncode != 0:
        raise RuntimeError('collector exited %s: %s' % (
            completed.returncode, (completed.stderr or completed.stdout)[:1000]))
    if not (completed.stdout or '').strip():
        raise RuntimeError('collector returned no observations')
    return completed.stdout + (completed.stderr or '')


class IncidentCollector:

    """Collect one bounded incident pack for a failed run."""

    def __init__(self, artifacts_root, run_id, clock=None, quota=None):
        self._quota = quota
        self.watchdog = None
        parent = Path(artifacts_root) / str(run_id)
        parent.mkdir(parents=True, exist_ok=True)
        number = 1
        while True:
            self.root = parent / ('incident' if number == 1 else 'incident-%02d' % number)
            try:
                self.root.mkdir()
                break
            except FileExistsError:
                number += 1
        self.run_id = run_id
        self.deadline = time.time() + TOTAL_BUDGET_SECONDS
        self.manifest = []
        self._lock = threading.Lock()

    @property
    def quota(self):
        return min(DISK_QUOTA_BYTES, self._quota if self._quota is not None else DISK_QUOTA_BYTES)

    def _arm_item(self):
        if self.watchdog is not None:
            self.watchdog.deadline = time.monotonic() + max(0, min(ITEM_TIMEOUT_SECONDS, self.deadline-time.time()))

    # ------------------------------------------------------------------
    def _record(self, item, result, payload=None, failure_reason=None,
                dump_path=None):
        entry = {'item': item, 'result': result,
                 'failure_reason': failure_reason,
                 'size': 0, 'sha256': None}
        if dump_path is not None:
            path = dump_path
            entry['size'] = path.stat().st_size if path.exists() else 0
            entry['sha256'] = _sha256_bytes(
                path.read_bytes()) if path.exists() else None
        elif payload is not None:
            raw = payload if isinstance(payload, bytes) else str(
                payload).encode('utf-8', 'replace')
            entry['size'] = len(raw)
            entry['sha256'] = _sha256_bytes(raw)
        with self._lock:
            self.manifest.append(entry)
        return entry

    def _write_item(self, name, payload):
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / name
        raw_size = len(payload if isinstance(payload, bytes) else str(payload).encode('utf-8', 'replace'))
        used = sum(p.stat().st_size for p in self.root.rglob('*') if p.is_file())
        if used + raw_size > self.quota - METADATA_RESERVE_BYTES:
            self._record(name, 'failed', failure_reason='disk quota exceeded')
            return None
        try:
            path.write_bytes(payload if isinstance(payload, bytes) else str(
                payload).encode('utf-8', 'replace'))
        except OSError as exc:
            self._record(name, 'failed', failure_reason=repr(exc)[:160])
            return None
        return path

    def _timed_out(self):
        return time.time() >= self.deadline

    def _quota_exceeded(self):
        try:
            used = sum(item.stat().st_size for item in self.root.rglob('*')
                       if item.is_file())
        except OSError:
            used = 0
        return used >= self.quota - METADATA_RESERVE_BYTES

    # ------------------------------------------------------------------
    def collect(self, context):
        """``context`` supplies: timeline, versions, config_path,
        run_log_window, exception_text, final_filter, baseline_diff,
        artifact_metadata, dump_target_pid (optional)."""
        started = time.time()
        written = []
        for name, kind in BASIC_ITEMS:
            self._arm_item()
            if self._timed_out():
                self._record(name, 'failed',
                             failure_reason='total budget exhausted')
                continue
            try:
                self._item_deadline = min(self.deadline, time.time() + ITEM_TIMEOUT_SECONDS)
                payload = self._collect_item(kind, context)
            except Exception as exc:  # noqa: BLE001 - evidence only
                payload = None
                self._record(name, 'failed', failure_reason=repr(exc)[:160])
                continue
            if payload is None or payload == '' or payload == b'':
                self._record(name, 'failed',
                             failure_reason='unavailable')
                continue
            path = self._write_item(name, payload)
            if path is None:
                continue
            if self._timed_out():
                # A collection that only finished after the total budget is
                # not complete evidence, however long the item itself took.
                self._record(name, 'failed', dump_path=path,
                             failure_reason='total budget exhausted')
                continue
            written.append(path)
            self._record(name, 'ok', dump_path=path)

        self._arm_item()
        self._conditional_dump(context)
        self._arm_item()
        if context.get('exit_evidence') is not None:
            evidence = context['exit_evidence']
            path = self._write_item('managed-exit.json', json.dumps(evidence, indent=2))
            if path:
                self._record('managed-exit.json', 'ok' if evidence.get('complete') else 'failed',
                             dump_path=path,
                             failure_reason=None if evidence.get('complete') else 'exit evidence incomplete')
        self._write_manifest(started)
        # Declare the finished members so a reader can tell a final artifact
        # from a file that is still being written.
        from fakenet.mcp.artifacts import write_publication
        write_publication(self.root, [self.root / item['item']
                                     for item in self.manifest
                                     if item['result'] == 'ok'] +
                          [self.root / 'manifest.json'])

    # ------------------------------------------------------------------
    def _collect_item(self, kind, context):
        def run(command):
            remaining = min(self.deadline, self._item_deadline) - time.time()
            if remaining <= 0:
                raise TimeoutError('incident item/total deadline exceeded')
            return _run(command, timeout=remaining)
        if kind == 'timeline':
            return json.dumps(context.get('timeline', []),
                              ensure_ascii=False, indent=2)
        if kind == 'versions':
            return json.dumps(context.get('versions', {}),
                              ensure_ascii=False, indent=2)
        if kind == 'config_snapshot':
            path = context.get('config_path')
            if not path or not os.path.isfile(path):
                return None
            return Path(path).read_bytes()
        if kind == 'stdout_stderr':
            return context.get('stdout_stderr', '')
        if kind == 'run_log':
            return context.get('run_log_window', '')
        if kind == 'exception':
            return context.get('exception_text', '')
        if kind == 'thread_stacks':
            managed = context.get('managed_thread_stacks')
            if not managed:
                return None
            return 'SUPERVISOR\n' + self._thread_stacks() + '\nMANAGED\n' + managed
        if kind == 'process_tree':
            return run(['powershell', '-NoProfile', '-Command',
                         'Get-CimInstance Win32_Process | Select-Object '
                         'ProcessId,ParentProcessId,Name,CommandLine,'
                         'CreationDate | ConvertTo-Json -Compress'])
        if kind == 'handle_summary':
            return run(['powershell', '-NoProfile', '-Command',
                         'Get-Process | Select-Object Id,ProcessName,'
                         'HandleCount,StartTime | ConvertTo-Json -Compress'])
        if kind == 'windivert_filter':
            return json.dumps({
                'final_filter': context.get('final_filter'),
                'tasklist_m': run(['tasklist', '/m', 'WinDivert*']),
            }, ensure_ascii=False, indent=2)
        if kind == 'baseline_diff':
            return json.dumps(context.get('baseline_diff', {}),
                              ensure_ascii=False, indent=2)
        if kind == 'firewall_diff':
            before = context.get('firewall_baseline')
            if before is None:
                return None
            after = run(['netsh', 'advfirewall', 'firewall', 'show', 'rule',
                         'name=FakeNet-NG MCP', 'verbose'])
            return json.dumps({'before': before, 'after': after, 'changed': before != after},
                              ensure_ascii=False, indent=2)
        if kind == 'event_log':
            return (run(['wevtutil', 'qe', 'System', '/c:200', '/f:text',
                          '/rd:true']) + '\n----APPLICATION----\n' +
                    run(['wevtutil', 'qe', 'Application', '/c:200',
                          '/f:text', '/rd:true']))
        if kind == 'artifact_metadata':
            return json.dumps(context.get('artifact_metadata', []),
                              ensure_ascii=False, indent=2)
        return None

    @staticmethod
    def _thread_stacks():
        frames = sys._current_frames()
        blocks = []
        for thread_id, frame in frames.items():
            lines = ['Thread %s:' % thread_id]
            current = frame
            depth = 0
            while current is not None and depth < 40:
                lines.append('  %s:%d %s' % (
                    current.f_code.co_filename, current.f_lineno,
                    current.f_code.co_name))
                current = current.f_back
                depth += 1
            blocks.append('\n'.join(lines))
        return '\n\n'.join(blocks) if blocks else 'NO_FRAMES_AVAILABLE'

    # ------------------------------------------------------------------
    def _conditional_dump(self, context):
        """Escalate to a user-mode process dump when the base layer cannot
        explain the failure (record 035 conditions)."""
        reason = context.get('dump_reason')
        if not reason:
            self._record('userdump.dmp', 'skipped',
                         failure_reason='no escalation condition')
            return
        if os.name != 'nt':
            self._record('userdump.dmp', 'skipped',
                         failure_reason='managed dump requires Windows')
            return
        if self._timed_out() or self._quota_exceeded():
            self._record('userdump.dmp', 'failed',
                         failure_reason='budget/quota exhausted')
            return
        self.root.mkdir(parents=True, exist_ok=True)
        target = self.root / 'userdump.dmp'
        try:
            if context.get('precollected_exit_dump'):
                self._copy_exit_dump(context['precollected_exit_dump'], target)
                self._record('userdump.dmp', 'ok', dump_path=target)
                return
            from fakenet.mcp.dumpworker import collect_dump
            pid = context.get('dump_target_pid')
            creation = context.get('dump_target_creation')
            if not pid or not creation:
                raise RuntimeError('managed dump target identity unavailable')
            remaining = min(ITEM_TIMEOUT_SECONDS, self.deadline - time.time())
            used = sum(p.stat().st_size for p in self.root.rglob('*') if p.is_file())
            collect_dump(pid, creation, target, time.monotonic() + max(0, remaining),
                         quota=max(0, self.quota - METADATA_RESERVE_BYTES - used))
            self._record('userdump.dmp', 'ok', dump_path=target)
        except Exception as exc:
            self._record('userdump.dmp', 'failed', failure_reason=repr(exc)[:160])
        finally:
            diagnostic = self.root / 'dump-tool.json'
            if diagnostic.is_file():
                self._record('dump-tool.json', 'ok', dump_path=diagnostic)

    def _copy_exit_dump(self, evidence, target):
        from fakenet.mcp.exit_native import verify_dump
        import hashlib
        identity, info = evidence['identity'], evidence['dump']
        if identity['run_id'] != self.run_id:
            raise RuntimeError('exit dump belongs to another run')
        source = Path(evidence['path'])
        verify_dump(source, identity['pid'])
        used = sum(path.stat().st_size for path in self.root.rglob('*') if path.is_file())
        if used + info['size'] > self.quota - METADATA_RESERVE_BYTES:
            raise RuntimeError('exit dump exceeds incident quota')
        end = min(self.deadline, time.time() + ITEM_TIMEOUT_SECONDS)
        partial = target.with_suffix('.dmp.partial')
        size, hasher = 0, hashlib.sha256()
        if partial.exists():
            raise RuntimeError('exit dump staging already exists')
        try:
            with source.open('rb') as src, partial.open('xb') as dst:
                while True:
                    if time.time() >= end:
                        raise TimeoutError('exit dump assembly deadline exceeded')
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > info['size'] or used + size > self.quota - METADATA_RESERVE_BYTES:
                        raise RuntimeError('exit dump changed or exceeded quota')
                    dst.write(chunk)
                    hasher.update(chunk)
                dst.flush()
                os.fsync(dst.fileno())
            if size != info['size'] or hasher.hexdigest() != info['sha256'] or time.time() >= end:
                raise RuntimeError('exit dump assembly incomplete/changed/late')
            verify_dump(partial, identity['pid'])
            os.replace(partial, target)
        finally:
            partial.unlink(missing_ok=True)

    def _write_manifest(self, started):
        manifest = {
            'run_id': self.run_id,
            'collected_at': time.time(),
            'elapsed_seconds': round(time.time() - started, 3),
            'budget_seconds': TOTAL_BUDGET_SECONDS,
            'disk_quota_bytes': self.quota,
            'entries': self.manifest,
            'complete': all(e['result'] != 'failed' for e in self.manifest),
        }
        self.root.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(manifest, ensure_ascii=False, indent=2) + '\n'
        if len(payload.encode('utf-8')) > METADATA_RESERVE_BYTES // 2:
            raise RuntimeError('incident manifest exceeds metadata reserve')
        (self.root / 'manifest.json').write_text(payload, encoding='utf-8')
        return manifest
