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
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace')
        return (completed.stdout or '') + (completed.stderr or '')
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 'COLLECTION_FAILED: %r' % exc


class IncidentCollector:

    """Collect one bounded incident pack for a failed run."""

    def __init__(self, artifacts_root, run_id, clock=None):
        self.root = Path(artifacts_root) / str(run_id) / 'incident'
        self.run_id = run_id
        self.deadline = time.time() + TOTAL_BUDGET_SECONDS
        self.manifest = []
        self._lock = threading.Lock()

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
        return used >= DISK_QUOTA_BYTES

    # ------------------------------------------------------------------
    def collect(self, context):
        """``context`` supplies: timeline, versions, config_path,
        run_log_window, exception_text, final_filter, baseline_diff,
        artifact_metadata, dump_target_pid (optional)."""
        started = time.time()
        for name, kind in BASIC_ITEMS:
            if self._timed_out():
                self._record(name, 'failed',
                             failure_reason='total budget exhausted')
                continue
            try:
                payload = self._collect_item(kind, context)
            except Exception as exc:  # noqa: BLE001 - evidence only
                payload = None
                self._record(name, 'failed', failure_reason=repr(exc)[:160])
                continue
            if payload is None:
                self._record(name, 'failed',
                             failure_reason='unavailable')
                continue
            path = self._write_item(name, payload)
            if path is None:
                continue
            self._record(name, 'ok', dump_path=path)

        self._conditional_dump(context)
        self._write_manifest(started)

    # ------------------------------------------------------------------
    def _collect_item(self, kind, context):
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
            return self._thread_stacks()
        if kind == 'process_tree':
            return _run(['powershell', '-NoProfile', '-Command',
                         'Get-CimInstance Win32_Process | Select-Object '
                         'ProcessId,ParentProcessId,Name,CommandLine,'
                         'CreationDate | ConvertTo-Json -Compress'])
        if kind == 'handle_summary':
            return _run(['powershell', '-NoProfile', '-Command',
                         'Get-Process | Select-Object Id,ProcessName,'
                         'HandleCount,StartTime | ConvertTo-Json -Compress'])
        if kind == 'windivert_filter':
            return json.dumps({
                'final_filter': context.get('final_filter'),
                'tasklist_m': _run(['tasklist', '/m', 'WinDivert*.sys']),
            }, ensure_ascii=False, indent=2)
        if kind == 'baseline_diff':
            return json.dumps(context.get('baseline_diff', {}),
                              ensure_ascii=False, indent=2)
        if kind == 'firewall_diff':
            return _run(['netsh', 'advfirewall', 'firewall', 'show', 'rule',
                         'name=FakeNet-NG MCP', 'verbose'])
        if kind == 'event_log':
            return (_run(['wevtutil', 'qe', 'System', '/c:200', '/f:text',
                          '/rd:true']) + '\n----APPLICATION----\n' +
                    _run(['wevtutil', 'qe', 'Application', '/c:200',
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
                         failure_reason='in-process dump requires Windows')
            return
        if self._timed_out() or self._quota_exceeded():
            self._record('userdump.dmp', 'failed',
                         failure_reason='budget/quota exhausted')
            return
        self.root.mkdir(parents=True, exist_ok=True)
        target = self.root / 'userdump.dmp'
        # In-process MiniDumpWriteDump (dbghelp) without new dependencies.
        # The former cross-process route (rundll32 comsvcs MiniDump) wraps
        # the API in its own thread-suspension layer; racing concurrent
        # thread churn it can leave target threads suspended forever,
        # wedging the control link while the SCM still shows Running
        # (r52 ACC-004-S3 repro: three threads stuck in Suspended). The
        # in-process call keeps the suspension bracket entirely inside
        # MiniDumpWriteDump — the pattern used by standard crash handlers.
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            dbghelp = ctypes.WinDLL('dbghelp', use_last_error=True)
            kernel32.CreateFileW.restype = wintypes.HANDLE
            kernel32.CreateFileW.argtypes = [
                wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                wintypes.HANDLE]
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL
            dbghelp.MiniDumpWriteDump.argtypes = [
                wintypes.HANDLE, wintypes.DWORD, wintypes.HANDLE,
                wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID,
                wintypes.LPVOID]
            generic_write = 0x40000000
            create_always = 2
            file_attribute_normal = 0x80
            invalid = wintypes.HANDLE(-1).value
            handle = kernel32.CreateFileW(
                str(target), generic_write, 0, None, create_always,
                file_attribute_normal, None)
            if not handle or handle == invalid:
                self._record('userdump.dmp', 'failed', failure_reason=(
                    'CreateFileW error=%s' % ctypes.get_last_error()))
                return
            try:
                wrote = dbghelp.MiniDumpWriteDump(
                    kernel32.GetCurrentProcess(), os.getpid(), handle,
                    0,  # MiniDumpNormal
                    None, None, None)
            finally:
                kernel32.CloseHandle(handle)
            size = target.stat().st_size if target.exists() else -1
            if wrote and size > 0:
                self._record('userdump.dmp', 'ok', dump_path=target)
            else:
                self._record('userdump.dmp', 'failed', failure_reason=(
                    'MiniDumpWriteDump wrote=%s error=%s size=%s' % (
                        bool(wrote), ctypes.get_last_error(), size)))
        except Exception as exc:  # noqa: BLE001 - evidence only
            self._record('userdump.dmp', 'failed', failure_reason=repr(exc)
                         [:160])

    def _write_manifest(self, started):
        manifest = {
            'run_id': self.run_id,
            'collected_at': time.time(),
            'elapsed_seconds': round(time.time() - started, 3),
            'budget_seconds': TOTAL_BUDGET_SECONDS,
            'disk_quota_bytes': DISK_QUOTA_BYTES,
            'entries': self.manifest,
        }
        self.root.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(manifest, ensure_ascii=False, indent=2) + '\n'
        (self.root / 'manifest.json').write_text(payload, encoding='utf-8')
        return manifest
