# Copyright 2026 Google LLC
"""Supervisor-owned target handle retained independently of the managed Job."""
from pathlib import Path
import threading
import time

from fakenet.mcp.exit_files import read, publish, root, run_directory, digest
from fakenet.mcp.exit_intent import StopIntent
from fakenet.mcp.exit_native import TargetHandle, verify_dump


class ExitRetention:
    def __init__(self, run_id, identity, supervisor_identity, instance, package_root, hard_deadline=None):
        self.done = threading.Event()
        self.result = None
        self.deadline = hard_deadline
        self._failure = None
        self._helper = None
        self._helper_identity = None
        self._cancel = threading.Event()
        self._target = TargetHandle(identity['pid'])
        self.package = Path(package_root).resolve()
        self.helper_image = self.package / 'exit-helper' / 'fakenetng-mcp-exit-monitor.exe'
        try:
            actual = self._target.identity()
            if (actual['creation_time'] != identity['creation_time'] or
                    actual['image'].casefold() != str(self.package / 'fakenetng-mcp-managed.exe').casefold()):
                raise RuntimeError('managed exit handoff identity mismatch')
            self.record = dict(actual, schema='fakenet.exit-target.v1', run_id=run_id,
                command_line=self._target.command_line(), budget_seconds=60,
                supervisor_pid=supervisor_identity['pid'],
                supervisor_creation_time=supervisor_identity['creation_time'],
                supervisor_instance=instance)
            self.base = root()
            self.directory = run_directory(self.base, run_id)
            self.directory.mkdir(exist_ok=False)
            self.intent = StopIntent(self.directory, self.record)
            publish(self.base / 'target.json', self.record)
            self.worker = threading.Thread(target=self._watch, name='managed-exit-evidence', daemon=True)
            self.worker.start()
        except BaseException:
            self._target.close()
            raise

    def _open_helper(self, identity):
        handle = TargetHandle(identity['pid'], allow_terminate=True)
        try:
            actual = handle.identity()
            if (actual['creation_time'] != identity['creation_time'] or
                    actual['image'].casefold() != str(self.helper_image).casefold()):
                raise RuntimeError('exit helper identity mismatch')
            return handle
        except BaseException:
            handle.close()
            raise

    def _read_optional(self, name):
        try:
            return read(self.directory / name)
        except FileNotFoundError:
            return None

    def _check_result(self, report):
        if (report.get('schema') != 'fakenet.exit-result.v1' or
                report.get('target') != self.record or report.get('helper') != self._helper_identity):
            raise RuntimeError('exit result identity mismatch')
        if report.get('classification') == 'controlled_normal_exit':
            if not self.intent.normal_is_valid(report.get('stop_intent_claim')):
                raise RuntimeError('normal exit authorization revoked/expired')
        if report.get('complete'):
            if not report.get('completed_monotonic', float('inf')) <= self.deadline:
                raise RuntimeError('exit collection completed after its deadline')
            if not report.get('target_handle_closed'):
                raise RuntimeError('helper target-handle closure unconfirmed')
            if report.get('dump'):
                info = report['dump']
                if info.get('name') != 'target.dmp':
                    raise RuntimeError('unexpected exit dump path')
                path = self.directory / 'target.dmp'
                sha, size = digest(path, deadline=self.deadline)
                verify_dump(path, self.record['pid'])
                if size != info.get('size') or sha != info.get('sha256'):
                    raise RuntimeError('exit dump integrity mismatch')
            elif report.get('classification') != 'controlled_normal_exit':
                raise RuntimeError('unexpected exit has no verified dump')
        return dict(report)

    def _finish(self, report):
        if self._helper is not None and not self._helper.exited():
            raise RuntimeError('helper has not ended')
        if self._helper is not None:
            # The helper's end is observed on this pinned handle, so it can be
            # released now; the retained target handle may not.
            self._helper.close()
            self._helper = None
        from fakenet.mcp.exit_installation import (OBSERVATION_BUDGET,
                                                   Observation,
                                                   assert_no_helpers)
        # The residual check spends this run's remaining window.  The retained
        # target handle stays independent and open until that check proves no
        # helper of this package is still running: a failed check must not
        # release it early, or late collection loses its target.
        assert_no_helpers(self.package,
                          observation=Observation(self.deadline, OBSERVATION_BUDGET))
        self.intent.invalidate()
        self._target.close()
        report.update(helper_ended=True, retained_target_handle_closed=True)
        self.result = report
        publish(self.directory / 'owner-result.json', report)

    def _watch(self):
        try:
            while True:
                now = time.monotonic()
                if self.deadline is None and (self._target.exited() or self._cancel.is_set()):
                    self.deadline = now + 60
                entry = self._read_optional('entry.json')
                if entry and self._helper is None:
                    if entry.get('target') != self.record or entry.get('acquired') is not True:
                        raise RuntimeError('exit helper acquisition identity mismatch')
                    self._helper_identity = entry['helper']
                    self._helper = self._open_helper(self._helper_identity)
                    publish(self.directory / 'owner-acquired.json',
                            dict(target=self.record, helper=self._helper_identity))
                    created = int(self._helper_identity['creation_time']) / 10000000 - 11644473600
                    native_deadline = now + max(0, 60 - (time.time() - created))
                    self.deadline = min(self.deadline or float('inf'), native_deadline)
                if self._helper is not None:
                    claim = self._read_optional('normal-claim.json')
                    if claim and not (self.directory / 'normal-ack.json').exists():
                        accepted = self.intent.accept_normal(claim.get('claim'), claim.get('notification', {}))
                        publish(self.directory / 'normal-ack.json', dict(claim=claim.get('claim'), accepted=accepted))
                    if self._helper.exited():
                        report = self._read_optional('result.json')
                        if not report:
                            raise RuntimeError('helper ended without final result')
                        self._finish(self._check_result(report))
                        return
                if self.deadline is not None and now >= self.deadline - 1:
                    self.intent.invalidate()
                    from fakenet.mcp.exit_installation import end_helpers
                    end_helpers(self.package, self.deadline)
                    if self._helper is not None:
                        self._helper.terminate_helper()
                        while not self._helper.exited() and time.monotonic() < self.deadline:
                            time.sleep(0.01)
                    self._finish(dict(complete=False, target=self.record,
                                      error='exit evidence deadline exceeded or notification missing'))
                    return
                time.sleep(0.02)
        except BaseException as exc:
            self._failure = repr(exc)
            self.intent.invalidate()
            # A failed helper must still be stopped by its pinned native handle.
            try:
                from fakenet.mcp.exit_installation import end_helpers
                end_helpers(self.package, min(self.deadline or time.monotonic() + 1,
                                              time.monotonic() + 1))
                if self._helper is not None:
                    self._helper.terminate_helper()
                    end = min(self.deadline or time.monotonic() + 1, time.monotonic() + 1)
                    while not self._helper.exited() and time.monotonic() < end:
                        time.sleep(0.01)
                self._finish(dict(complete=False, target=self.record, error=self._failure))
            except BaseException as cleanup:
                # A single owner still reclaims the retained target handle:
                # only once no helper of this package is left to read it.
                closed = False
                try:
                    if self._helper is None or self._helper.exited():
                        self._target.close()
                        closed = True
                except BaseException:
                    closed = False
                self.result = dict(complete=False, target=self.record, error=self._failure,
                                   helper_ended=False, cleanup_error=repr(cleanup),
                                   retained_target_handle_closed=closed)
        finally:
            self.done.set()

    def cancel(self):
        self.intent.invalidate()
        self._cancel.set()

    def wait(self, condition, deadline):
        """Caller owns its lifecycle condition; wait releases all lock levels."""
        while not self.done.is_set() and time.monotonic() < deadline:
            condition.wait(timeout=min(0.05, max(0, deadline - time.monotonic())))
        if not self.done.is_set():
            return dict(complete=False, helper_ended=False, error='exit owner wait deadline exceeded')
        return self.result
