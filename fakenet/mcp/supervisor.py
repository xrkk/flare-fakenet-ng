# Copyright 2026 Google LLC
"""Real FakeNet-NG lifecycle supervisor and health monitor (P03 IMP-P03-02).

Runs the in-process ``Fakenet`` instance on a worker thread and enforces
the real-health contract (REQ-005 / record 004):

* ``healthy`` only while ALL three conditions hold — managed instance
  alive with diverter handle + bound listeners, active internal probe
  passing, and no unhandled-exception signature in this run's log;
* the health thread polls every ``health_interval`` seconds (frozen at
  2.0s by sub-plan P03 §3);
* a detected unhandled exception demotes/revoes health immediately and
  reports the reason (never "process exists therefore healthy");
* terminal internal failure triggers the unified stop sequence and the
  state machine lands in ``failed`` (the incident evidence pack itself
  belongs to P04).

Start sequence (frozen order): validate config -> inject control-link
exclusion into diverter config -> capture baseline -> take activity lock
(IMP-P03-05 order: lock before content use is enforced by the caller
flow in tools: lock is taken by this supervisor at start on the resolved
config path BEFORE Fakenet parses it) -> write recovery-marked snapshot
-> run Fakenet.start() in the worker thread.
"""

import hashlib
import logging
import os
import re
import sys
import threading
import time

from fakenet.mcp import errors

logger = logging.getLogger('fakenetng-mcp.supervisor')

HEALTH_INTERVAL_SECONDS = 2.0
RESTART_SETTLE_SECONDS = 5.0
UNHEALTHY_TERMINAL_CYCLES = 2
UNHANDLED_EXCEPTION_PATTERN = re.compile(
    r'Traceback \(most recent call last\)|Unhandled exception', re.I)


class SupervisorStartError(RuntimeError):
    pass


class RealSupervisor:

    """Drop-in replacement for the P02 LifecycleDouble (same call shape
    used by the tools), driving a real in-process Fakenet."""

    name = 'real'

    def __init__(self, coordination_cls=None, snapshot=None,
                 baseline_store=None, config_path_resolver=None,
                 stop_grace_seconds=60.0, health_interval=None,
                 log_reader=None, probe_impl=None, exclusion=None,
                 artifacts_root=None, fault_injector=None):
        from fakenet.mcp.snapshot import StateSnapshot
        from fakenet.mcp.baseline import BaselineStore

        self._lock = threading.RLock()
        self._fakenet = None
        self._worker = None
        self._health_thread = None
        self._stop_event = threading.Event()
        self._health_interval = health_interval or HEALTH_INTERVAL_SECONDS
        self._stop_grace = stop_grace_seconds
        self._failure_reason = None
        self._log_reader = log_reader
        self._probe_impl = probe_impl
        self._log_offset = 0
        self._log_size_probe = None
        # Test hooks (sub-plan P03 IMP-P03-08 frozen injection means).
        self.stop_blocker = None
        self.fail_health_probe = False
        self._config_path_resolver = config_path_resolver
        self._snapshot = snapshot
        self._baseline_store = baseline_store
        self._exclusion = dict(exclusion or {})
        self._coordinator = None
        self._activity_lock = None
        self._last_snapshot_fields = None
        self._artifacts_root = artifacts_root
        if fault_injector is None:
            from fakenet.mcp import faultinject

            if faultinject.enabled():
                fault_injector = faultinject.FaultInjector()
        self._faults = fault_injector
        self._terminal_evidence = None
        self._last_run_outcome = None
        self._log_exception_seen_count = 0

    # -- health inputs -----------------------------------------------------
    def _probe(self):
        if self._probe_impl is not None:
            return self._probe_impl(self)
        fakenet = self._fakenet
        if fakenet is None:
            return False
        diverter = getattr(fakenet, 'diverter', None)
        handle_ok = diverter is not None and \
            getattr(diverter, 'handle', None) is not None
        listeners_ok = bool(getattr(fakenet, 'running_listener_providers',
                                    None))
        return bool(handle_ok and listeners_ok)

    def _init_evidence(self):
        fakenet = self._fakenet
        if fakenet is None:
            return False
        return bool(getattr(fakenet, 'running_listener_providers', None))

    def _scan_log_for_unhandled(self):
        if self._log_reader is None:
            return False
        try:
            content = self._log_reader(self._log_offset)
        except Exception:  # noqa: BLE001 - diagnostics must not kill health
            return False
        return bool(UNHANDLED_EXCEPTION_PATTERN.search(content or ''))

    def health_detail(self, state):
        with self._lock:
            return {
                'process_alive': self._fakenet is not None,
                'init_evidence': self._init_evidence(),
                'probe': self._probe(),
            }

    def evaluate_health(self):
        """Return (healthy, reason)."""
        with self._lock:
            if self._fakenet is None:
                return False, 'not running'
            if self._scan_log_for_unhandled():
                return False, 'unhandled exception signature in run log'
            if self.fail_health_probe or not self._probe():
                return False, 'active probe failed'
            if not self._init_evidence():
                return False, 'initialization evidence missing'
            return True, None

    def _health_loop(self):
        while not self._stop_event.wait(self._health_interval):
            healthy, reason = self.evaluate_health()
            if self._fakenet is None:
                continue
            if healthy:
                self._log_exception_seen_count = 0
                if self._coordinator is not None and \
                        self._coordinator.snapshot()['state'] == 'starting':
                    self._coordinator.update_health_state('healthy')
            elif self._worker is not None and not self._worker.is_alive() \
                    and not self._init_evidence():
                self._failure_reason = 'run thread exited without init'
                self._handle_terminal_failure(self._failure_reason)
            elif healthy is False and reason and \
                    'unhandled exception' in reason:
                self._log_exception_seen_count += 1
                probe_dead = not self._probe()
                if probe_dead or self._log_exception_seen_count >= \
                        UNHEALTHY_TERMINAL_CYCLES:
                    self._handle_terminal_failure(reason)
            else:
                logger.warning('health revoked/demoted: %s', reason)
                self._failure_reason = reason
                if self._coordinator is not None:
                    previous = self._coordinator.snapshot()['state']
                    if previous in ('healthy', 'starting', 'degraded'):
                        self._coordinator.update_health_state(
                            'degraded' if previous != 'starting'
                            else 'starting', reason)

    # -- lifecycle operations (Coordinator execute callbacks) --------------
    def start(self, coordinator, controller, config_identity):
        with self._lock:
            if self._fakenet is not None:
                raise errors.McpError(
                    errors.NOT_ALLOWED_IN_STATE,
                    'a managed FakeNet-NG run is already active')
            from fakenet.fakenet import Fakenet

            config_path = self._resolve_config_path(
                config_identity['name'], config_identity.get('builtin'))
            self._verify_config_sha(config_path, config_identity['sha256'])

            # IMP-P03-05 frozen order: lock BEFORE reading/parsing — the
            # active config is locked whether builtin or custom.
            from fakenet.mcp.configlock import ActivityLock

            self._active_config_path = config_path
            self._activity_lock = ActivityLock(config_path).acquire()

            # Fakenet resolves packaged resources (defaultFiles/, report
            # templates) relative to the process CWD; the service runs from
            # System32, so pin the CWD to the package root (exe directory
            # when frozen, source root otherwise) for the run.
            import sys

            if getattr(sys, 'frozen', False):
                package_root = os.path.dirname(os.path.abspath(
                    sys.executable))
            else:
                package_root = os.path.dirname(os.path.dirname(
                    os.path.dirname(os.path.abspath(__file__))))
            self._previous_cwd = os.getcwd()
            os.chdir(package_root)
            instance = Fakenet()
            instance.parse_config(config_path)
            self._inject_exclusion(instance)

            run_id = coordinator.new_run_id()
            if self._baseline_store is not None:
                self._baseline_store.save(run_id)
            if self._snapshot is not None:
                self._snapshot.write(
                    run_id=run_id, controller_id=controller,
                    state_version=coordinator.snapshot()['state_version'],
                    command_id=None,
                    config_sha256=config_identity['sha256'],
                    baseline_path=str(getattr(self._baseline_store, 'root',
                                              '')),
                    needs_recovery=True)
            self._last_snapshot_fields = {
                'run_id': run_id, 'controller_id': None,
                'state_version': coordinator.snapshot()['state_version'],
                'command_id': None,
                'config_sha256': config_identity['sha256'],
                'baseline_path': str(getattr(self._baseline_store, 'root',
                                             '')),
            }

            self._failure_reason = None
            self._stop_event.clear()
            self._coordinator = coordinator
            # Only this run's log window participates in the exception scan
            # (older tracebacks in the same file must not revoke health).
            try:
                self._log_offset = self._current_log_size()
            except Exception:  # noqa: BLE001
                self._log_offset = 0
            self._fakenet = instance

            start_error = {}

            def run():
                try:
                    instance.start()
                except SystemExit as exc:
                    start_error['reason'] = (
                        'fakenet start exited (code=%r)' % exc.code)
                except Exception as exc:  # noqa: BLE001
                    start_error['reason'] = repr(exc)
                finally:
                    if start_error:
                        # Never let a start-thread death pass silently: the
                        # r37 gate showed orphaned errors (evidence loop had
                        # already returned healthy) hiding half-started runs.
                        logger.error('fakenet start thread ended with error: '
                                     '%s', start_error['reason'])

            self._worker = threading.Thread(target=run, name='fakenet-run',
                                            daemon=True)
            self._worker.start()
            deadline = time.time() + min(self._stop_grace, 30.0)
            while time.time() < deadline and not start_error and \
                    not self._init_evidence():
                time.sleep(0.2)
            # Construction-phase evidence (WinDivert queue params, DNS probe)
            # can satisfy the loop while the listener loop is still binding
            # (the SSL listener alone takes seconds). The start thread must
            # FINISH before any state is reported: returning early lets a
            # concurrent stop race the listener loop and leak every socket
            # bound after the stop passed that provider.
            self._worker.join(max(0.5, deadline - time.time()))
            if start_error or self._worker.is_alive():
                logger.error('managed start failed: %s',
                             start_error.get('reason') or
                             'start thread did not finish within the '
                             'startup budget')
                try:
                    try:
                        instance.stop()
                    except BaseException:  # noqa: BLE001 - rollback
                        logger.exception('rollback stop after failed start '
                                         'raised')
                finally:
                    self._force_close_listener_sockets(instance)
                    self._restore_cwd()
                self._teardown()
                if self._snapshot is not None and \
                        self._last_snapshot_fields is not None:
                    try:
                        self._snapshot.clear_recovery(
                            **self._last_snapshot_fields)
                    except Exception:  # noqa: BLE001
                        logger.exception('clearing marker after failed '
                                         'start failed')
                return {'state': 'failed', 'changed': True,
                        'failure_reason': start_error['reason'],
                        'run_id': None, 'controller': None,
                        'release_controller': True,
                        'config_identity': config_identity}
            if self._faults is not None:
                # Run-path fault classes fire once after a successful start
                # (env-armed, test builds only).
                listeners = getattr(instance, 'running_listener_providers',
                                   None) or []
                try:
                    self._faults.inject_listener_stop(listeners)
                    self._faults.inject_diverter_stop(
                        getattr(instance, 'diverter', None))
                    self._faults.inject_child_hang()
                except Exception:  # noqa: BLE001 - injection is test-only
                    logger.exception('fault injection raised')
            state = 'healthy' if self.evaluate_health()[0] else 'starting'
            self._health_thread = threading.Thread(
                target=self._health_loop, name='fakenet-health', daemon=True)
            self._health_thread.start()
            return {'state': state, 'changed': True, 'run_id': run_id,
                    'controller': controller,
                    'config_identity': config_identity}

    def stop(self, coordinator, baseline_audit=True):
        with self._lock:
            if self._fakenet is None:
                return {'state': 'stopped', 'changed': False}
            if self.stop_blocker is not None:
                self.stop_blocker()
            if self._worker is not None and self._worker.is_alive():
                # Belt-and-braces vs a start thread that outlived its budget
                # (start() already joins before reporting state; this guards
                # any future path that skips that join — stopping mid-start
                # leaves listeners that bind AFTER the stop, forever).
                logger.warning('stop requested while start thread is still '
                               'running; waiting for it to finish')
                self._worker.join(min(self._stop_grace, 30.0))
            self._stop_event.set()
            from fakenet.payload_report import PayloadReportError

            stop_outcome = {}

            def guarded_stop():
                if self._faults is not None:
                    # Fault hooks live INSIDE the guarded stop so a hung
                    # fault (policy_pause) is bounded by the stop grace.
                    self._faults.before_listener_phase()
                    self._faults.on_stop_error()
                try:
                    self._fakenet.stop()
                except PayloadReportError as exc:
                    # Platform cleanup and capture close already succeeded
                    # when the report layer raises; the report artifact is a
                    # P04 concern, not an environment recovery failure.
                    stop_outcome['report_warning'] = repr(exc)
                except BaseException as exc:  # noqa: BLE001
                    stop_outcome['error'] = exc

            stop_worker = threading.Thread(target=guarded_stop, daemon=True)
            stop_worker.start()
            stop_worker.join(self._stop_grace)
            if stop_worker.is_alive():
                # Bounded stop (FB-005 P03 share): keep the recovery marker,
                # drop references and report failed; the next service start
                # runs the recovery audit.
                logger.error('stop grace (%ss) exceeded', self._stop_grace)
                self._teardown()
                return {'state': 'failed', 'changed': True,
                        'failure_reason': 'stop grace exceeded',
                        'run_id': None, 'release_controller': True}
            self._force_close_listener_sockets(self._fakenet)
            if 'report_warning' in stop_outcome:
                logger.warning('payload report generation failed: %s',
                               stop_outcome['report_warning'])
            if 'error' in stop_outcome:
                logger.error('fakenet stop raised: %r', stop_outcome['error'])
                self._teardown()
                return {'state': 'failed', 'changed': True,
                        'failure_reason': 'stop failed: %r' %
                                          stop_outcome['error'],
                        'run_id': None, 'release_controller': True}
            self._restore_cwd()
            run_id = coordinator.snapshot().get('run_id')
            if self._baseline_store is not None and run_id:
                # P04 normalized audit comparison (per-section volatility
                # immunity); the raw diff misfires on netstat PID noise.
                differences = self._baseline_store.full_audit_diff(
                    str(run_id))
                if differences:
                    self._teardown()
                    return {'state': 'failed', 'changed': True,
                            'failure_reason':
                                'environment differs from pre-start baseline',
                            'run_id': None, 'release_controller': True}
            self._teardown()
            if self._snapshot is not None and \
                    self._last_snapshot_fields is not None:
                try:
                    self._snapshot.clear_recovery(
                        **self._last_snapshot_fields)
                except Exception:  # noqa: BLE001 - snapshot is a note
                    logger.exception('clearing recovery marker failed')
            return {'state': 'stopped', 'changed': True, 'run_id': None,
                    'failure_reason': None, 'release_controller': True}

    def restart(self, coordinator, controller, config_identity):
        self.stop(coordinator)
        # Real-VM evidence (P03 round): OS socket TIME_WAIT and the
        # WinDivert service teardown race an immediate in-process restart;
        # a bounded settle makes restart deterministic. Record 023 requires
        # restart to actually bring the run back, so the settle is part of
        # the stop->start sequence, not a retry fallback.
        time.sleep(RESTART_SETTLE_SECONDS)
        return self.start(coordinator, controller, config_identity)

    # -- helpers -------------------------------------------------------------
    def _current_log_size(self):
        if self._log_size_probe is None:
            return 0
        return self._log_size_probe()

    def _resolve_config_path(self, name, builtin):
        if self._config_path_resolver is not None:
            return self._config_path_resolver(name, builtin)
        raise SupervisorStartError('config path resolver missing')

    @staticmethod
    def _verify_config_sha(config_path, expected):
        digest = hashlib.sha256(open(config_path, 'rb').read()).hexdigest()
        if digest != expected:
            raise SupervisorStartError(
                'config content changed since load (sha mismatch)')

    def _inject_exclusion(self, instance):
        """Inject the control-link exclusion keys into the parsed diverter
        config; validity of ip/port is enforced fail-closed by the diverter
        (windows.py build_control_link_exclusion_clause).  Empty values
        leave the filter byte-identical (regression-safe)."""
        instance.diverter_config['ControlLinkExcludeIp'] = \
            self._exclusion.get('ip', '')
        instance.diverter_config['ControlLinkExcludePort'] = \
            self._exclusion.get('port', '')

    def _handle_terminal_failure(self, reason):
        """Terminal internal failure (record 034): bounded incident first,
        then the unified stop sequence; never waits for the controller."""
        logger.error('terminal internal failure: %s', reason)
        self._terminal_evidence = reason
        try:
            self._collect_incident(reason)
        except Exception:  # noqa: BLE001 - evidence must not block cleanup
            logger.exception('incident collection failed')
        coord = self._coordinator
        if coord is None:
            return
        coord.update_health_state('failed', reason)
        import uuid as _uuid

        try:
            coord.submit(
                command_id='protective-stop-%s' % _uuid.uuid4(),
                expected_version=coord.snapshot()['state_version'],
                controller=coord.controller,
                controller_valid=True, kind='protective_stop',
                describe={'reason': reason},
                execute=lambda c: self.stop(c), internal=True)
        except Exception:  # noqa: BLE001 - raw stop then forced release
            logger.exception('protective stop via coordinator failed; '
                             'falling back to raw stop + forced release')
            try:
                self.stop(coord)
            except Exception:  # noqa: BLE001
                logger.exception('raw protective stop failed')
        finally:
            coord.record_terminal_failure(reason)

    def _collect_incident(self, reason):
        from fakenet.mcp.incident import IncidentCollector

        if not self._artifacts_root or not self._coordinator:
            return
        run_id = self._coordinator.snapshot().get('run_id')
        if not run_id:
            return
        context = {
            'timeline': self._coordinator.events(500),
            'versions': {
                'python': sys.version,
                'platform': sys.platform,
                'service': 'fakenetng-mcp',
            },
            'config_path': getattr(self, '_active_config_path', None),
            'stdout_stderr': '',
            'run_log_window': self._log_reader(
                getattr(self, '_log_offset', 0)) if self._log_reader else '',
            'exception_text': reason,
            'final_filter': getattr(self._fakenet.diverter, 'filter', None)
            if self._fakenet and getattr(self._fakenet, 'diverter', None)
            else None,
            'baseline_diff': {},
            'artifact_metadata': [],
            'dump_reason': 'unhandled exception signature' if 'exception'
                           in reason else None,
        }
        collector = IncidentCollector(self._artifacts_root, run_id)
        collector.collect(context)

    def _restore_cwd(self):
        previous = getattr(self, '_previous_cwd', None)
        if previous:
            try:
                os.chdir(previous)
            except OSError:
                pass
            self._previous_cwd = None

    @staticmethod
    def _force_close_listener_sockets(instance):
        """P05 release gate evidence: FakeNet's own listener stop can leave
        sockets open in the in-process model (the CLI process used to exit,
        releasing them). Best-effort, logged sweep so a stopped run never
        leaks listening ports into the next round."""
        providers = getattr(instance, 'running_listener_providers', None) \
            or []
        for provider in providers:
            for attr in ('server', 'sock', 'socket'):
                target = getattr(provider, attr, None)
                if target is None:
                    continue
                closer = getattr(target, 'server_close', None) or \
                    getattr(target, 'close', None)
                if closer is None:
                    continue
                try:
                    closer()
                    logger.info('listener %s.%s force-closed',
                                type(provider).__name__, attr)
                except Exception as exc:  # noqa: BLE001 - best effort
                    logger.debug('listener %s.%s close raised %r',
                                 type(provider).__name__, attr, exc)

    def _teardown(self):
        if self._faults is not None:
            try:
                self._faults.release()
            except Exception:  # noqa: BLE001
                pass
        self._fakenet = None
        self._worker = None
        self._coordinator = None
        if self._activity_lock is not None:
            self._activity_lock.release()
            self._activity_lock = None
        if self._health_thread is not None:
            self._health_thread = None

def perform_startup_recovery(snapshot, baseline_store, coordinator):
    """P03 IMP-P03-06: SCM restart path (record 025/026, FB-004).

    Returns 'stopped' | 'failed'.  With ``needs_recovery`` set: verify the
    environment against the recorded baseline; all-consistent -> real
    stopped; any unexplained difference (or a corrupt/missing snapshot with
    residue) -> failed with start forbidden.  Never restarts FakeNet-NG,
    never replays commands.
    """
    data, corrupt = snapshot.read()
    if data is None:
        # corrupt or absent: residue check = any baseline residue present
        residue = False
        if not corrupt and baseline_store is not None:
            for path in sorted(baseline_store.root.glob('*.json')):
                residue = True
                break
        if corrupt or residue:
            coordinator._failure_reason = (
                'snapshot corrupt/missing with residue')
            return 'failed'
        return 'stopped'
    if not data.get('needs_recovery'):
        return 'stopped'
    run_id = data.get('run_id')
    differences = None
    if baseline_store is not None and run_id:
        differences = baseline_store.diff(run_id)
    if differences:
        coordinator._failure_reason = (
            'environment differs from pre-start baseline')
        return 'failed'
    snapshot.clear_recovery(
        run_id=data.get('run_id'), controller_id=None,
        state_version=data.get('state_version'),
        command_id=data.get('command_id'),
        config_sha256=data.get('config_sha256'),
        baseline_path=data.get('baseline_path'))
    return 'stopped'
