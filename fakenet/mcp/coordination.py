# Copyright 2026 Google LLC
"""Serial mutation coordinator: identity, state version, idempotency, events.

Sub-plan P02 §3 frozen semantics:

* all mutations execute strictly serially under one lock; conflicting
  requests are rejected immediately (no queueing);
* controller identity is validated BEFORE command-id replay, so a different
  controller replaying someone else's command_id gets ``controller_conflict``
  instead of the cached result (anti replay-hijack);
* a duplicate ``command_id`` from the same controller replays the original
  result without re-executing; the cache lives in-process only (LRU 256) and
  a process restart forgets it (records 023/038: no command continuation);
* ``expected_state_version`` must equal the current version; mismatches are
  ``state_conflict``; every accepted mutation bumps the version;
* no timers anywhere: controller ownership never times out (record 022).
"""

import logging
import threading
import time
import uuid
from collections import OrderedDict, deque

from fakenet.mcp import errors

logger = logging.getLogger('fakenetng-mcp.coordination')

COMMAND_CACHE_LIMIT = 256
EVENT_BUFFER_LIMIT = 500


class EventLog:

    def __init__(self, limit=EVENT_BUFFER_LIMIT):
        self._entries = deque(maxlen=limit)

    def record(self, event_type, **fields):
        entry = {'timestamp': time.time(), 'kind': event_type}
        entry.update(fields)
        self._entries.append(entry)
        return entry

    def snapshot(self, limit=None):
        items = list(self._entries)
        return items[-limit:] if limit else items


class Coordinator:

    def __init__(self, runner, event_log=None):
        self._lock = threading.RLock()
        self._runner = runner
        self._events = event_log or EventLog()
        self._state = 'stopped'
        self._state_version = 1
        self._run_id = None
        self._controller = None
        self._failure_reason = None
        self._config_identity = None
        self._commands = OrderedDict()
        self._draining = False
        self._last_run_outcome = None
        # CHK-022: long-running mutations execute WITHOUT holding the
        # metadata lock; this flag immediately rejects concurrent
        # mutations and keeps read-only queries available throughout.
        self._operation_active = False
        self._active_operations = {}
        self._idle = threading.Condition(self._lock)
        self._exit_fenced = set()
        self._exit_failure = None
        self._operation_context = threading.local()

    # -- read-only surface -------------------------------------------------
    def snapshot(self):
        with self._lock:
            state = self._state
            payload = {
                'state': state,
                'state_version': self._state_version,
                'run_id': self._run_id,
                'controller': self._controller,
                'failure_reason': self._failure_reason,
                'config_identity': self._config_identity,
                'last_run_outcome': self._last_run_outcome,
            }
        # Sample health OUTSIDE the metadata lock: health_detail takes the
        # supervisor lock, and supervisor.stop() calls this snapshot while
        # already holding the supervisor lock. Nesting coordinator-lock ->
        # supervisor-lock (as the in-lock call did) inverts against that
        # path and deadlocks the control link: the stop thread holds the
        # supervisor lock waiting for the metadata lock while a concurrent
        # snapshot holds the metadata lock waiting for the supervisor lock
        # (r53 ACC-004-S3 py-spy evidence). The supervisor lock is an
        # RLock, so the stop thread's own re-entry stays safe.
        payload['health'] = self._runner.health_detail(state)
        return payload

    def events(self, limit=None):
        with self._lock:
            return self._events.snapshot(limit)

    @property
    def running(self):
        with self._lock:
            return self._run_id is not None

    @property
    def controller(self):
        with self._lock:
            return self._controller

    # -- mutation surface --------------------------------------------------
    def _active_conflicts(self, conflict_names):
        # Record 033 permits disjoint configuration work only while cleanly
        # stopped. Each accepted operation owns its scope until it finishes.
        if not self._active_operations:
            return False
        if self._state != 'stopped' or self._controller is not None:
            return True
        return any(names is None or conflict_names is None or
                   bool(set(names) & set(conflict_names))
                   for names in self._active_operations.values())

    def _finish_operation(self, command_id):
        self._active_operations.pop(command_id, None)
        self._operation_active = bool(self._active_operations)
        self._idle.notify_all()
        # Never evict an in-flight command; a retry must find its original.
        completed = [key for key in self._commands
                     if key not in self._active_operations]
        for key in completed[:-COMMAND_CACHE_LIMIT]:
            del self._commands[key]

    def submit(self, *, command_id, expected_version, controller,
               controller_valid, kind, describe, execute,
               internal=False, conflict_names=None):
        """Run one serialized mutation.

        CHK-022 three-phase design: validation and state updates run under
        the short-held metadata lock; the (potentially long) ``execute``
        callback runs with the lock RELEASED so read-only queries stay
        available and concurrent mutations are rejected immediately
        (``operation_busy``) instead of queueing behind the lock.

        ``execute`` is called with this coordinator; it returns
        ``dict(result fields)`` and may raise ``McpError``.
        """
        # Phase 1: validate under the metadata lock (fast, no execution).
        with self._lock:
            # 0. controlled-exit gate (P04 IMP-P04-06): once draining,
            # every new CLIENT mutation is rejected immediately, never
            # queued; the service's own protective/controlled stop is an
            # internal transition and may proceed.
            if (self._draining or self._state == 'recovering') and not internal:
                raise errors.McpError(
                    errors.NOT_ALLOWED_IN_STATE,
                    'service is in controlled shutdown; new mutations '
                    'rejected')
            if not controller_valid:
                raise errors.McpError(
                    errors.CONTROLLER_IDENTITY_MISSING,
                    'mutation requires a valid X-FakeNet-Controller-ID '
                    'header')
            if self._controller is not None and controller != self._controller:
                raise errors.McpError(
                    errors.CONTROLLER_CONFLICT,
                    'another controller owns the active run',
                    {'active_controller': self._controller})
            if controller is None and not internal:
                raise errors.McpError(
                    errors.CONTROLLER_IDENTITY_MISSING,
                    'mutation requires controller identity')

            # Identity precedes replay, but replay precedes busy/version:
            # an in-flight retry identifies the original operation immediately.
            cached = self._commands.get(command_id)
            if cached is not None:
                if cached.get('controller') != controller:
                    raise errors.McpError(
                        errors.CONTROLLER_CONFLICT,
                        'command_id belongs to another controller')
                if 'exception' in cached:
                    raise cached['exception']
                replay = dict(cached['response'])
                replay['replayed'] = True
                return replay

            if self._active_conflicts(conflict_names):
                raise errors.McpError(
                    errors.OPERATION_BUSY, 'another mutation is executing',
                    {'kind': kind, 'command_id': command_id})

            # 3. version gate.
            if expected_version != self._state_version:
                raise errors.McpError(
                    errors.STATE_CONFLICT,
                    'expected_state_version does not match current state',
                    {'expected': expected_version,
                     'current': self._state_version})

            self._state_version += 1
            self._active_operations[command_id] = conflict_names
            self._operation_active = True
            self._commands[command_id] = {
                'controller': controller, 'describe': describe,
                'response': {'state': self._state,
                             'state_version': self._state_version,
                             'run_id': self._run_id, 'changed': False,
                             'error': None, 'command_id': command_id,
                             'in_progress': True},
            }
            self._events.record('command.accepted', command_id=command_id,
                                controller=controller, kind=kind)

        # Phase 2: execute WITHOUT the metadata lock — read-only queries
        # (snapshot/events) and health transitions stay responsive; any
        # concurrent mutation hits the busy gate in Phase 1 immediately.
        try:
            self._operation_context.command_id = command_id
            result = execute(self)
        except BaseException as exc:
            with self._lock:
                self._commands[command_id]['exception'] = exc
                self._events.record('command.failed', command_id=command_id,
                                    kind=kind, reason=str(exc),
                                    state_version=self._state_version)
                self._finish_operation(command_id)
            raise

        # Phase 3: update state under the metadata lock (fast).
        with self._lock:
            fenced = command_id in self._exit_fenced
            self._exit_fenced.discard(command_id)
            self._finish_operation(command_id)
            if fenced:
                result = dict(result)
                result.update(state='failed', failure_reason=self._exit_failure,
                              release_controller=False)
                if result.get('run_id') is None:
                    result.pop('run_id', None)
            self._run_id = result.get('run_id', self._run_id)
            if 'state' in result:
                self._state = result['state']
            self._failure_reason = result.get('failure_reason')
            if result.get('controller') is not None:
                self._controller = result['controller']
            if result.get('release_controller'):
                self._controller = None
            if 'config_identity' in result:
                self._config_identity = result['config_identity']
            self._events.record(
                'command.completed', command_id=command_id, kind=kind,
                state=self._state, state_version=self._state_version)

            if 'last_run_outcome' in result:
                self._last_run_outcome = result['last_run_outcome']
            elif result.get('release_controller') and result.get('changed', True) and \
                    result.get('state') == 'stopped':
                self._last_run_outcome = 'ok'
            response = {
                'state': self._state,
                'state_version': self._state_version,
                'run_id': self._run_id,
                'changed': bool(result.get('changed', True)),
                'error': None,
                'command_id': command_id,
                'last_run_outcome': self._last_run_outcome,
            }
            self._commands[command_id] = {
                'controller': controller, 'response': response,
                'describe': describe,
            }
            self._finish_operation(command_id)
            return dict(response)

    def record_terminal_failure(self, reason):
        """P04/CHK-041: terminal-failure bookkeeping. When the protective
        stop CONVERGED (real stopped), the contract keeps that terminal
        state with last_run_outcome=failed and the reason observable —
        only a non-converged outcome lands in failed."""
        with self._lock:
            if self._state == 'stopped':
                self._run_id = None
                self._controller = None
            if self._state != 'stopped':
                self._state = 'failed'
            self._failure_reason = reason
            self._last_run_outcome = 'failed'
            self._events.record('terminal_failure', reason=reason)

    @property
    def last_run_outcome(self):
        with self._lock:
            return getattr(self, '_last_run_outcome', None)

    def begin_draining(self):
        with self._lock:
            self._draining = True
            self._events.record('draining.begin')

    @property
    def current_command_id(self):
        return getattr(self._operation_context, 'command_id', None)

    @property
    def operation_fenced(self):
        with self._lock:
            return self.current_command_id in self._exit_fenced

    def restore_responsibility(self, marker, state, reason=None):
        with self._lock:
            self._state = state
            self._failure_reason = reason
            if marker and marker.get('needs_recovery'):
                self._run_id = marker.get('run_id')
                self._controller = marker.get('controller_id')
            if state == 'stopped':
                self._run_id = None
                self._controller = None
            self._events.record('recovery', state=state, reason=reason)

    def wait_for_idle(self, timeout):
        with self._idle:
            return self._idle.wait_for(lambda: not self._active_operations,
                                       timeout=max(0, timeout))

    def fail_controlled_exit(self, reason):
        with self._lock:
            self._draining = True
            self._exit_failure = reason
            self._exit_fenced.update(self._active_operations)
            self._state = 'failed'
            self._failure_reason = reason
            self._events.record('draining.failed', reason=reason)

    @property
    def draining(self):
        with self._lock:
            return self._draining

    def update_health_state(self, state, failure_reason=None):
        """Autonomous health transition (observation, not a mutation):
        records state/failure_reason without touching state_version."""
        with self._lock:
            if self._exit_failure and state in ('healthy', 'starting', 'degraded'):
                state, failure_reason = 'failed', self._exit_failure
            self._state = state
            self._failure_reason = failure_reason
            self._events.record('health', state=state,
                                failure_reason=failure_reason)

    def forget_commands(self):
        """Test/verification hook: simulate process restart semantics."""
        with self._lock:
            self._commands.clear()

    # -- helpers used by executions ---------------------------------------
    def new_run_id(self):
        return str(uuid.uuid4())

    def set_config_identity(self, identity):
        with self._lock:
            self._config_identity = identity
