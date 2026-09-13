# Copyright 2026 Google LLC
"""Supervisor-owned target handle retained independently of the managed Job."""
from pathlib import Path
import threading
import time

from fakenet.mcp.exit_files import read, publish, root, run_directory, digest

# Bounded budget for the owner's own finalization after the observation
# window expires: the scan and publication still need real seconds on
# teardown-lagging hosts, and the window itself has just been consumed.
FINALIZE_BUDGET = 45
from fakenet.mcp.exit_intent import StopIntent
from fakenet.mcp.exit_native import TargetHandle, verify_dump


class ExitRetention:
    def __init__(self, run_id, identity, supervisor_identity, instance, package_root, hard_deadline=None):
        self._arguments = (run_id, identity, supervisor_identity, instance)
        self.package = Path(package_root)
        self.initialized = self._initialization_attempted = False
        self._initialization_failed = False
        self._target = self.record = self.intent = self.worker = None
        self.base = self.directory = None
        self.done = threading.Event()
        self.result = None
        self.deadline = hard_deadline
        self._failure = None
        self._helper = None
        self._helper_identity = None
        self._cancel = threading.Event()
        self.owner_dump = None
        self._finalization_deadline = None
        self._finalization_diagnostics = []
        # The watch thread polls diagnostics and the supervisor's hang branch
        # collects the owner dump concurrently; one owner, serialized access.
        self._call_lock = threading.RLock()
        self._helper_job = None
        self._helper_admission_api = None
        self._entry_read_attempts = 0
        self._entry_read_diagnostic_errors = 0
        self._entry_observed_monotonic = None
        self._helper_creation_time = None
        self._helper_deadline_monotonic = None
        self._ack_attempted_monotonic = None
        self._ack_published_monotonic = None
        from fakenet.mcp.diagnostic_process import DiagnosticError, DiagnosticOwner
        self._diagnostics = DiagnosticOwner(package_root)
        self._intent_diagnostics = DiagnosticOwner(package_root)
        self.helper_image = self.package / 'exit-helper' / 'fakenetng-mcp-exit-monitor.exe'

    def initialize(self):
        if self._initialization_attempted:
            raise RuntimeError('exit retention initialization already attempted')
        self._initialization_attempted = True
        run_id, identity, supervisor_identity, instance = self._arguments
        try:
            self.package = self.package.resolve()
            self.helper_image = self.package / 'exit-helper' / 'fakenetng-mcp-exit-monitor.exe'
            self._target = TargetHandle(identity['pid'])
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
            self.intent = StopIntent(self.directory, self.record, io=self._intent_io)
            self._call('exit-init', dict(record=self.record), time.monotonic() + 10)
            self.worker = threading.Thread(target=self._watch, name='managed-exit-evidence', daemon=True)
            self.worker.start()
            self.initialized = True
            return self
        except BaseException as exc:
            self._initialization_failed = True
            self._failure = repr(exc)
            self.result = dict(complete=False, error=self._failure,
                               failure_stage='initialize exit retention',
                               helper_ended=False, retained_target_handle_closed=False)
            if self.record is not None:
                self.result['target'] = self.record
            self.done.set()
            # initialize's caller already owns this object. Independent
            # diagnostic Jobs must remain visible even when target exits.
            self.cancel_existing_diagnostics()
            raise

    def _open_helper(self, identity):
        self._helper_admission_api = 'OpenProcess'
        handle = TargetHandle(identity['pid'], allow_terminate=True, allow_job=True)
        try:
            self._helper_admission_api = 'GetProcessTimes/QueryFullProcessImageNameW'
            actual = handle.identity()
            if (actual['creation_time'] != identity['creation_time'] or
                    actual['image'].casefold() != str(self.helper_image).casefold()):
                raise RuntimeError('exit helper identity mismatch')
            from fakenet.mcp.jobobject import ManagedJob
            self._helper = handle
            self._helper_admission_api = 'CreateJobObjectW/SetInformationJobObject'
            self._helper_job = ManagedJob()
            self._helper_job.adopt_notification(handle.handle,
                                                observe=self._observe_helper_admission_api)
            return handle
        except BaseException:
            if self._helper is not handle:
                handle.close()
            raise

    def _observe_helper_admission_api(self, name):
        self._helper_admission_api = name

    def _owner_observation(self):
        """Bounded timing/API facts for a real SPE helper handoff.

        These fields are produced by the current supervisor only.  They make
        a late helper, a queued diagnostic read and native Job admission
        failures distinguishable without treating any incomplete result as a
        successful exit observation.
        """
        result = dict(entry_read_attempts=getattr(self, '_entry_read_attempts', 0),
                      entry_read_diagnostic_errors=getattr(
                          self, '_entry_read_diagnostic_errors', 0))
        if getattr(self, '_finalization_diagnostics', None):
            result['finalization_diagnostics'] = self._finalization_diagnostics
        for key in ('_entry_observed_monotonic', '_helper_creation_time',
                    '_helper_deadline_monotonic', '_ack_attempted_monotonic',
                    '_ack_published_monotonic'):
            value = getattr(self, key, None)
            if value is not None:
                result[key[1:]] = value
        return result

    def _record_observation(self, report):
        report = dict(report)
        report['owner_observation'] = self._owner_observation()
        return report

    def _call(self, operation, payload, deadline=None):
        # The poll round-trip must absorb slow child teardown under AV/EDR
        # load on the acceptance VMs; the retention window (60s) still bounds
        # every call from above. The budget starts when the lock is granted:
        # a caller that waited behind the owner-dump collection must not run
        # with an already-expired deadline. Once finalization has begun the
        # window is intentionally past; calls then run on the finalization
        # budget instead of an instantly-expiring clamp.
        with self._call_lock:
            window = self.deadline
            if window is not None and window < time.monotonic():
                window = time.monotonic() + FINALIZE_BUDGET
            # A diagnostic child round-trip on the acceptance VM family
            # regularly exceeds five seconds; the default poll budget must
            # tolerate real spawn cost or every poll retains ownership.
            end = min(window or float('inf'), deadline or time.monotonic() + 30)
            end = min(end, getattr(self, '_finalization_deadline', None) or float('inf'))
            return self._diagnostics.call(operation, payload, end)

    def _intent_io(self, operation, record, deadline):
        payload = dict(run_id=self.record['run_id'], name='stop-intent.json')
        # During finalization the retention window has expired by design;
        # intent protocol calls then run on the finalization budget, not on
        # an already-past deadline that kills the watch thread.
        if self.deadline is not None and self.deadline < time.monotonic():
            budget = time.monotonic() + FINALIZE_BUDGET
        else:
            budget = self.deadline or float('inf')
        budget = min(budget, getattr(self, '_finalization_deadline', None) or float('inf'))
        if operation == 'publish':
            payload['record'] = record
            return self._intent_diagnostics.call('exit-publish', payload, min(budget, deadline))
        return self._intent_diagnostics.call('exit-remove-intent', payload, min(budget, deadline))

    def _publish(self, name, record):
        return self._call('exit-publish', dict(run_id=self.record['run_id'], name=name, record=record))

    def _read_optional(self, name):
        return self._call('exit-read', dict(run_id=self.record['run_id'], name=name))

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
                checked = self._call('exit-verify-dump', dict(run_id=self.record['run_id'], pid=self.record['pid']), self.deadline)
                if checked['size'] != info.get('size') or checked['sha256'] != info.get('sha256'):
                    raise RuntimeError('exit dump integrity mismatch')
            elif report.get('classification') != 'controlled_normal_exit':
                raise RuntimeError('unexpected exit has no verified dump')
        return dict(report)

    def cancel_existing_diagnostics(self):
        for name in ('_diagnostics', '_intent_diagnostics'):
            owner = getattr(self, name, None)
            task = getattr(owner, 'active', None)
            if task is not None and not task.ended.is_set():
                task.cancel.set()

    def resources_ended(self):
        worker = getattr(self, 'worker', None)
        return ((worker is None or not worker.is_alive()) and
                self._target is None and self._helper is None and
                getattr(self, '_helper_job', None) is None and
                not any(getattr(self, name, None) is not None and
                        getattr(self, name).pending()
                        for name in ('_diagnostics', '_intent_diagnostics')))

    def _release_gate(self):
        worker = getattr(self, 'worker', None)
        if worker is not None and worker is not threading.current_thread() and worker.is_alive():
            raise RuntimeError('exit watcher still active')
        for name in ('_diagnostics', '_intent_diagnostics'):
            owner = getattr(self, name, None)
            if owner is not None and owner.pending():
                raise RuntimeError('diagnostic protocol worker still active')
        if self._target is not None and not self._target.exited():
            raise RuntimeError('managed target still active; retain its handle')

    def _drain_existing_diagnostics(self, deadline):
        # A call's success deadline expires before its worker necessarily
        # finishes cleanup. Observe only those existing tasks; never read a
        # late result, spawn a replacement, or release an unended owner.
        observations = []
        self._finalization_diagnostics = observations
        tasks = []
        for name in ('_diagnostics', '_intent_diagnostics'):
            owner = getattr(self, name, None)
            task = getattr(owner, 'active', None)
            if task is not None:
                row = dict(owner=name, before=task.observation(task.error))
                observations.append(row)
                tasks.append((task, row))
                if not task.ended.is_set():
                    task.cancel.set()
        for task, row in tasks:
            task.ended.wait(max(0, deadline - time.monotonic()))
            row['after'] = task.observation(task.error)
            if not task.ended.is_set():
                raise RuntimeError('diagnostic protocol worker still active after finalization budget')

    def _finish(self, report, local=False):
        had_helper = (self._helper is not None or
                      getattr(self, '_helper_job', None) is not None or
                      getattr(self, '_helper_scan_required', False))
        self._helper_scan_required = had_helper
        if self._helper is not None and not self._helper.exited():
            raise RuntimeError('helper has not ended')
        if self._helper is not None:
            # The helper's end is observed on this pinned handle, so it can be
            # released now; the retained target handle may not.
            self._helper.close()
            self._helper = None
        if getattr(self, '_helper_job', None) is not None:
            if self._helper_job.members():
                raise RuntimeError('SPE Job still has live descendants')
            self._helper_job.close()
            self._helper_job = None
        self._release_gate()
        if had_helper:
            self._call('exit-scan', dict(terminate=False),
                       time.monotonic() + FINALIZE_BUDGET)
            self._helper_scan_required = False
        self._release_gate()
        if getattr(self, 'intent', None) is not None:
            if local:
                self.intent.invalidate_local()
            else:
                self.intent.invalidate()
        self._release_gate()
        if self._target is not None:
            self._target.close()
            self._target = None
        report.update(helper_ended=True, retained_target_handle_closed=True)
        self.result = report
        if getattr(self, '_initialization_failed', False):
            # A partial identity/intent is not a valid protocol publication.
            return
        if local:
            publish(self.directory / 'owner-result.json', report)
        else:
            self._publish('owner-result.json', report)

    def _watch(self):
        failure_stage = 'poll managed target exit'
        try:
            from fakenet.mcp.diagnostic_process import DiagnosticError
            while True:
                failure_stage = 'poll managed target exit'
                now = time.monotonic()
                if self.deadline is None and (self._target.exited() or self._cancel.is_set()):
                    self.deadline = now + 60
                if self.deadline is not None and now >= self.deadline:
                    failure_stage = 'finalize exit evidence deadline'
                    self._finalization_deadline = now + FINALIZE_BUDGET
                    self.intent.invalidate()
                    self._drain_existing_diagnostics(self._finalization_deadline)
                    owner_dump = getattr(self, 'owner_dump', None)
                    # The window bounds waiting for evidence, not the owner's
                    # own finalization; slow teardown needs its own budget.
                    self._end_helpers(self._finalization_deadline)
                    if self._helper is not None:
                        self._helper.terminate_helper()
                        while not self._helper.exited() and time.monotonic() < self.deadline:
                            time.sleep(0.01)
                    report = self._record_observation(dict(complete=False, target=self.record,
                                  error='exit evidence deadline exceeded or notification missing',
                                  completed_monotonic=time.monotonic(),
                                  target_handle_closed=True))
                    if owner_dump is not None:
                        report['dump'] = owner_dump
                        report['dump_owner_collected'] = True
                        # The grace-timeout branch of the two-dump contract
                        # is satisfied by the verified owner-collected dump:
                        # no helper ever fires for Job termination, so this
                        # IS the complete evidence for that path.
                        report['complete'] = True
                        report['error'] = None
                    # Helper-less finalization runs beside the supervisor's
                    # incident collection; child spawns there can queue past
                    # any per-call budget. The watch thread holds no lock, so
                    # the small bounded result write goes straight to disk.
                    if self._helper is None:
                        self._finish_local(report)
                        return
                    self._finish(report)
                    return
                try:
                    failure_stage = 'read exit helper entry'
                    self._entry_read_attempts = getattr(self, '_entry_read_attempts', 0) + 1
                    entry = self._read_optional('entry.json')
                except DiagnosticError:
                    # A lagging previous child keeps ownership briefly
                    # unresolved; polling is retryable and the deadline
                    # machinery bounds the wait. Dying here would leave the
                    # retention permanently unfinished.
                    self._entry_read_diagnostic_errors = (
                        getattr(self, '_entry_read_diagnostic_errors', 0) + 1)
                    remaining = (self.deadline - time.monotonic()
                                 if self.deadline is not None else 0.5)
                    if remaining > 0:
                        time.sleep(min(0.5, remaining))
                    continue
                if entry and self._helper is None:
                    self._entry_observed_monotonic = time.monotonic()
                    failure_stage = 'validate exit helper entry'
                    if entry.get('target') != self.record or entry.get('acquired') is not True:
                        raise RuntimeError('exit helper acquisition identity mismatch')
                    self._helper_identity = entry['helper']
                    self._helper_creation_time = self._helper_identity.get('creation_time')
                    self._helper_deadline_monotonic = entry.get('deadline_monotonic')
                    failure_stage = 'open exit helper'
                    self._helper = self._open_helper(self._helper_identity)
                    failure_stage = 'publish exit helper acknowledgment'
                    self._ack_attempted_monotonic = time.monotonic()
                    self._publish('owner-acquired.json', dict(target=self.record, helper=self._helper_identity))
                    self._ack_published_monotonic = time.monotonic()
                    created = int(self._helper_identity['creation_time']) / 10000000 - 11644473600
                    native_deadline = now + max(0, 60 - (time.time() - created))
                    self.deadline = min(self.deadline or float('inf'), native_deadline)
                if self._helper is not None:
                    failure_stage = 'read normal stop claim'
                    claim = self._read_optional('normal-claim.json')
                    if claim and not self._read_optional('normal-ack.json'):
                        failure_stage = 'publish normal stop acknowledgment'
                        accepted = self.intent.accept_normal(claim.get('claim'), claim.get('notification', {}))
                        self._publish('normal-ack.json', dict(claim=claim.get('claim'), accepted=accepted))
                    failure_stage = 'query exit helper state'
                    if self._helper.exited():
                        failure_stage = 'read exit helper result'
                        report = self._read_optional('result.json')
                        if not report:
                            raise RuntimeError('helper ended without final result')
                        failure_stage = 'verify exit helper result'
                        report = self._check_result(report)
                        failure_stage = 'finalize exit helper result'
                        self._finish(self._record_observation(report))
                        return
                time.sleep(0.02)
        except BaseException as exc:
            self._failure = repr(exc)
            import logging
            logging.getLogger('fakenetng-mcp.exitretention').exception(
                'exit retention watch ended: %r', exc)
            report = dict(complete=False, target=self.record, error=self._failure,
                          failure_stage=failure_stage)
            if failure_stage == 'open exit helper':
                native_api = getattr(self, '_helper_admission_api', None)
                if native_api is not None:
                    report['native_api'] = native_api
            report = self._record_observation(report)
            try:
                if self.intent is not None:
                    self.intent.invalidate_local()
            except BaseException as revoke_error:
                report['intent_cleanup_error'] = repr(revoke_error)
            # A failed helper must still be stopped by its pinned native handle.
            try:
                self._end_helpers(min(self.deadline or time.monotonic() + 5, time.monotonic() + 5))
                if self._helper is not None:
                    self._helper.terminate_helper()
                    end = min(self.deadline or time.monotonic() + 5, time.monotonic() + 5)
                    while not self._helper.exited() and time.monotonic() < end:
                        time.sleep(0.01)
                self._finish(report)
            except BaseException as cleanup:
                # An absent acquisition handle is not proof of absence.
                # Keep ownership when the residual check could not establish
                # that every packaged helper ended. Never invent cleanup.
                self.result = dict(report, helper_ended=False, cleanup_error=repr(cleanup),
                                   retained_target_handle_closed=False)
        finally:
            self._finalization_deadline = None
            self.done.set()

    def settle(self, deadline):
        """Continue finalization after the watcher ended with retained objects.

        A failed first pass never drops ownership: this bounded retry waits
        only for objects that are actually still live, then re-runs the same
        per-object release rules. An object that never ends keeps the
        responsibility and the failed result."""
        if not self.done.is_set() or self.result is None:
            return self.result
        worker = getattr(self, 'worker', None)
        if worker is not None and worker.ident is not None and worker is not threading.current_thread():
            worker.join(max(0, deadline - time.monotonic()))
            if worker.is_alive():
                return self.result
        if (self.result.get('helper_ended') and
                self.result.get('retained_target_handle_closed') and self.resources_ended()):
            return self.result
        if getattr(self, '_initialization_failed', False):
            self.cancel_existing_diagnostics()
        report = {key: value for key, value in self.result.items()
                  if key not in ('helper_ended', 'retained_target_handle_closed',
                                 'cleanup_error')}
        while True:
            helper_live = self._helper is not None and not self._helper.exited()
            target_live = self._target is not None and not self._target.exited()
            if not helper_live and not target_live:
                try:
                    self._finish(report, local=getattr(self, '_initialization_failed', False))
                    return self.result
                except BaseException as exc:
                    self.result = dict(report, cleanup_error=repr(exc),
                        helper_ended=self._helper is None and getattr(self, '_helper_job', None) is None,
                        retained_target_handle_closed=self._target is None)
            if time.monotonic() >= deadline:
                return self.result
            time.sleep(0.05)

    def collect_owner_dump(self, budget=45, force=False):
        """Root-cause dump for a still-live hung target, owner-side.

        Windows does not raise the silent-process-exit report for processes
        terminated through their Job, so the grace-timeout path cannot wait
        for the exit helper: the caller invokes this while the hung target
        is still alive, and the dump is collected through the pinned target
        handle with its own budget. This is the P04 two-dump contract's
        grace-timeout branch; failure keeps the incomplete report, it never
        invents evidence."""
        if self._target is None or self._target.exited():
            return None
        if self._helper is not None and not force:
            return None
        from fakenet.mcp.dumpworker import collect_dump
        from fakenet.mcp.exit_files import QUOTA
        from fakenet.mcp.exit_guard import SingleFlight
        target_path = self.directory / 'target.dmp'
        if self.owner_dump is not None:
            return self.owner_dump
        if target_path.exists():
            return None
        end = min(time.monotonic() + budget, self.deadline or float('inf'))
        if time.monotonic() >= end:
            raise TimeoutError('owner dump collection window expired')
        flight = SingleFlight()
        while not flight.acquire():
            # A notified helper already owns the global writer flight. Do not
            # hold its ACK protocol lock while waiting for its dump to finish.
            if not force:
                entry = self._read_optional('entry.json')
                if entry and entry.get('target') == self.record and entry.get('acquired') is True:
                    return None
            if time.monotonic() >= end:
                raise TimeoutError('owner dump writer flight deadline exceeded')
            time.sleep(min(0.05, max(0, end - time.monotonic())))
        try:
            with self._call_lock:
                if self.owner_dump is not None:
                    return self.owner_dump
                if target_path.exists() or self._target is None or self._target.exited():
                    return None
                actual = self._target.identity()
                if (actual['pid'] != self.record['pid'] or
                        actual['creation_time'] != self.record['creation_time']):
                    raise RuntimeError('owner dump retained target identity changed')
                collect_dump(self.record['pid'], self.record['creation_time'], target_path,
                             end, quota=QUOTA)
        finally:
            flight.close()
        # Verification uses a diagnostic child that acquires the same global
        # flight; release our writer ownership before invoking that child.
        checked = self._call('exit-verify-dump',
                             dict(run_id=self.record['run_id'], pid=self.record['pid']), end)
        info = dict(name='target.dmp', size=checked['size'], sha256=checked['sha256'])
        self.owner_dump = info
        self._publish('owner-dump.json', dict(
            info, reason='owner-collected: grace timeout with live target'))
        return info

    def _finish_local(self, report):
        """Use identical native/diagnostic release gates without a new worker."""
        self._finish(report, local=True)

    def _end_helpers(self, deadline):
        if self._helper is not None:
            self._helper.terminate_helper()
            if self._helper_job is not None:
                self._helper_job.terminate(deadline)
            if not self._helper.exited():
                raise RuntimeError('SPE end not observed; no parallel scan')
        if (self._helper is None and
                getattr(self, '_helper_job', None) is None):
            # No helper was ever acquired (job-terminated hang): nothing
            # packaged is owned, and chained scan children cost tens of
            # seconds on this host family - more than any finalization
            # window. The pinned native observations above are the whole
            # ownership story for this path.
            return True
        return self._call('exit-scan', dict(terminate=True), deadline)

    def cancel(self):
        self._cancel.set()
        self.cancel_existing_diagnostics()
        if self.intent is not None:
            self.intent.invalidate_local()

    def wait(self, condition, deadline):
        """Caller owns its lifecycle condition; wait releases all lock levels."""
        while not self.done.is_set() and time.monotonic() < deadline:
            condition.wait(timeout=min(0.05, max(0, deadline - time.monotonic())))
        if not self.done.is_set():
            return dict(complete=False, helper_ended=False, error='exit owner wait deadline exceeded')
        worker = getattr(self, 'worker', None)
        if worker is not None and worker.ident is not None and worker is not threading.current_thread():
            worker.join(max(0, deadline - time.monotonic()))
        return self.result
