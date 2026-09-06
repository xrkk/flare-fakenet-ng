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
        self._health_cache = None
        # Wall-clock stamp of the current run's start; artifact
        # registration only picks up files this run produced.
        self._run_started_at = None

    # -- health inputs -----------------------------------------------------
    def _probe(self):
        if self._probe_impl is not None:
            return self._probe_impl(self)
        fakenet = self._fakenet
        if fakenet is None:
            return False
        diverter = getattr(fakenet, 'diverter', None)
        handle = getattr(diverter, 'handle', None) if diverter else None
        # CHK-039: a referenced object is not liveness. pydivert's
        # close() nulls the underlying WinDivert handle, so is_open
        # (never a blocking recv) is the true validity signal — a
        # closed/released diverter revokes health immediately.
        handle_ok = bool(handle) and bool(getattr(handle, 'is_open', True))
        providers = getattr(fakenet, 'running_listener_providers',
                            None) or []
        listeners_ok = bool(providers) and all(
            self._provider_socket_alive(provider) for provider in providers)
        return bool(handle_ok and listeners_ok)

    @staticmethod
    def _provider_socket_alive(provider):
        """CHK-039: sample the provider's actual listening socket, not
        the object's existence. A closed/invalid socket revokes health
        even while the provider object stays referenced."""
        for attr in ('server', 'sock', 'socket'):
            target = getattr(provider, attr, None)
            if target is None:
                continue
            fileno = getattr(target, 'fileno', None)
            if not callable(fileno):
                continue  # no fd signal on this attribute
            try:
                fd = fileno()
            except (OSError, ValueError):
                return False
            if fd is None or int(fd) < 0:
                return False
        return True

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

    def health_detail(self, state, max_wait=0.05):
        """CHK-046: reads are bounded. The supervisor lock is held for a
        whole start/stop, so a blocking detail would stall every
        get_status behind long operations. Try briefly; when busy serve
        the last sampled detail (the health loop refreshes it every
        interval under the lock)."""
        if not self._lock.acquire(timeout=max_wait):
            cached = getattr(self, '_health_cache', None)
            if cached is not None:
                return dict(cached)
            return {
                'process_alive': self._fakenet is not None,
                'init_evidence': False, 'probe': False,
                'degraded': 'supervisor busy',
            }
        try:
            detail = self._health_detail_locked()
            self._health_cache = dict(detail)
            return detail
        finally:
            self._lock.release()

    def _health_detail_locked(self):
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
            self._health_cache = self._health_detail_locked()
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
            # FB-007/CHK-041: a live recovery marker forbids new runs.
            # The previous run did not converge; recovery must complete
            # (a converging stop or the service-startup audit) before
            # any new start — never overwrite an unverified failure.
            if self._snapshot is not None:
                marker, corrupt = self._snapshot.read()
                if corrupt or (marker and marker.get('needs_recovery')):
                    raise errors.McpError(
                        errors.NOT_ALLOWED_IN_STATE,
                        'recovery marker is live; the previous run did '
                        'not converge — resolve recovery before starting')
            from fakenet.fakenet import Fakenet

            config_path = self._resolve_config_path(
                config_identity['name'], config_identity.get('builtin'))
            self._run_started_at = time.time()

            # IMP-P03-05/CHK-047 frozen order: lock FIRST, then verify
            # the SHA and parse — the content that runs is exactly the
            # content that was locked, with no read-SHA-then-lock window.
            from fakenet.mcp.configlock import ActivityLock

            self._active_config_path = config_path
            self._activity_lock = ActivityLock(config_path).acquire()
            self._verify_config_sha(config_path, config_identity['sha256'])

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
            # CHK-048: run outputs (PCAPs, reports) belong under
            # ProgramData in a per-run directory, never loose in the
            # ProgramFiles package root. Relative dump prefixes are
            # absolutized to the run directory before the run starts.
            self._active_run_dir = None
            try:
                from fakenet.mcp import paths as mcp_paths
                run_dir = (mcp_paths.data_directories()['artifacts'] /
                           'runs' / str(run_id))
                run_dir.mkdir(parents=True, exist_ok=True)
                self._active_run_dir = run_dir
                for key in ('DumpPacketsFilePrefix', 'DumpHTTPWebRoot'):
                    value = str(instance.fakenet_config.get(key, '') or
                                '').strip()
                    if value and not os.path.isabs(value):
                        instance.fakenet_config[key] = os.path.join(
                            str(run_dir), value)
            except OSError:
                logger.exception('per-run output directory unavailable; '
                                 'outputs stay at configured paths')
                self._active_run_dir = None
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
                    if self._worker.is_alive():
                        # The rollback stop must not race a still-running
                        # start thread (a listener bound after the rollback
                        # passes it leaks); give it a short final grace.
                        self._worker.join(10.0)
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
                        'failure_reason': start_error.get('reason') or
                        'start thread did not finish within the startup '
                        'budget',
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

    def _audit_retained_recovery(self, coordinator, run_id, marker):
        """CHK-041: complete the recovery audit for a grace-exceeded run
        whose instance references were dropped but whose marker is live.
        Clean result clears the marker and reports stopped; anything
        unverifiable or differing reports failed and retains it."""
        if self._baseline_store is None:
            coordinator._failure_reason = (
                'baseline store unavailable; cannot verify recovery')
            return {'state': 'failed', 'changed': True,
                    'failure_reason': coordinator._failure_reason,
                    'run_id': None, 'release_controller': True}
        differences = self._baseline_store.full_audit_diff(run_id)
        if differences is None:
            coordinator._failure_reason = (
                'baseline for run %s unreadable; cannot verify recovery'
                % run_id)
            logger.error('retained recovery audit cannot read baseline '
                         'for run %s', run_id)
            return {'state': 'failed', 'changed': True,
                    'failure_reason': coordinator._failure_reason,
                    'run_id': None, 'release_controller': True}
        if differences:
            try:
                import json as _json
                logger.error(
                    'retained recovery audit differences for run %s: %s',
                    run_id,
                    _json.dumps(differences, ensure_ascii=False,
                                default=str)[:2000])
            except Exception:  # noqa: BLE001 - logging only
                pass
            coordinator._failure_reason = (
                'environment differs from pre-start baseline')
            return {'state': 'failed', 'changed': True,
                    'failure_reason': coordinator._failure_reason,
                    'run_id': None, 'release_controller': True}
        try:
            self._snapshot.clear_recovery(
                run_id=marker.get('run_id'), controller_id=None,
                state_version=marker.get('state_version'),
                command_id=marker.get('command_id'),
                config_sha256=marker.get('config_sha256'),
                baseline_path=marker.get('baseline_path'))
        except Exception:  # noqa: BLE001 - snapshot is a note
            logger.exception('clearing recovery marker failed')
        if self._activity_lock is not None:
            self._activity_lock.release()
            self._activity_lock = None
        return {'state': 'stopped', 'changed': True,
                'failure_reason': None, 'run_id': None,
                'release_controller': True}

    def stop(self, coordinator, baseline_audit=True):
        with self._lock:
            if self._fakenet is None:
                # CHK-041: no live instance is not automatically clean —
                # a grace-exceeded stop retains the recovery marker and
                # the coordinator's run_id. A stop in that state must
                # complete the recovery audit before claiming stopped,
                # never short-circuit past it.
                retained = coordinator.snapshot().get('run_id')
                marker = None
                if self._snapshot is not None:
                    marker, _corrupt = self._snapshot.read()
                if retained and marker and marker.get('needs_recovery'):
                    return self._audit_retained_recovery(coordinator,
                                                         str(retained),
                                                         marker)
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
                # CHK-041: ALL fault hooks live inside the guarded stop
                # so a hung fault (policy_pause, cleanup_error) is
                # bounded by the stop grace.
                try:
                    if self._faults is not None:
                        self._faults.before_listener_phase()
                    self._fakenet.stop()
                    if self._faults is not None:
                        # cleanup_error fires at the END of the guarded
                        # stop, inside the grace bracket (CHK-041).
                        self._faults.on_stop_error()
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
                # runs the recovery audit. The hung stop never reaches its
                # own socket release, so run the best-effort listener sweep
                # here — a grace-exceeded stop must not leak listening ports
                # into the fault-matrix environment audit (r41 gate:
                # policy_pause round 1 flagged listen_ports drift).
                logger.error('stop grace (%ss) exceeded', self._stop_grace)
                self._force_close_listener_sockets(self._fakenet)
                # CHK-017/CHK-041: the hung stop has NOT completed its
                # recovery audit — the marker, the coordinator's run_id
                # AND the activity lock all stay held. The next service
                # start must verify, not guess 'stopped'; only supervisor
                # references are dropped so the next stop is not
                # short-circuited by a dead instance.
                self._fakenet = None
                self._worker = None
                return {'state': 'failed', 'changed': True,
                        'failure_reason': 'stop grace exceeded',
                        'run_id': None, 'release_controller': False}
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
                    try:
                        import json as _json
                        logger.error(
                            'stop audit differences for run %s: %s', run_id,
                            _json.dumps(differences, ensure_ascii=False,
                                        default=str)[:2000])
                    except Exception:  # noqa: BLE001 - logging only
                        logger.error('stop audit differences (raw): %r',
                                     differences)
                    self._register_run_artifacts(run_id)
                    self._teardown()
                    return {'state': 'failed', 'changed': True,
                            'failure_reason':
                                'environment differs from pre-start baseline',
                            'run_id': None, 'release_controller': True}
            # CHK-029: register the run's FakeNet outputs (PCAPs, log,
            # report) into the managed artifacts tree so list_artifacts
            # reflects the actual run products, not only incident packs.
            self._register_run_artifacts(run_id)
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
        stop_result = self.stop(coordinator)
        # CHK-016: a restart may only proceed to a new start when the
        # stop converged cleanly (real 'stopped'); a failed or
        # grace-exceeded stop must retain the recovery responsibility —
        # starting a new run over it would bypass the stop/audit gate.
        if stop_result.get('state') not in ('stopped',):
            reason = stop_result.get('failure_reason') or \
                stop_result.get('state') or 'stop did not converge'
            logger.error('restart refused: previous stop state=%s reason=%s',
                         stop_result.get('state'), reason)
            stop_result['restart_refused'] = True
            return stop_result
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
        leave the filter byte-identical (regression-safe).

        CHK-038: a config that carries its OWN ControlLinkExcludeIp/Port
        is validated HERE, at the layer that feeds the filter builder —
        invalid protection parameters refuse the start (FB-002) instead
        of being silently overwritten. Valid custom ports merge into the
        exclusion list; the service control address stays authoritative
        (the control link must never lose its own exclusion)."""
        own_ip = str(instance.diverter_config.get(
            'ControlLinkExcludeIp', '') or '').strip()
        own_port = str(instance.diverter_config.get(
            'ControlLinkExcludePort', '') or '').strip()
        ports = str(self._exclusion.get('port', '') or '')
        if own_ip or own_port:
            from fakenet.mcp.controlfilter import \
                build_control_link_exclusion_clause
            try:
                build_control_link_exclusion_clause(
                    own_ip or self._exclusion.get('ip', ''),
                    own_port or ports)
            except Exception as exc:  # noqa: BLE001 - fail closed
                raise SupervisorStartError(
                    'invalid protection parameters in config '
                    '(ControlLinkExcludeIp/Port): %s' % exc)
            if own_port:
                merged = {item for item in
                          ports.split(',') + own_port.split(',')
                          if item}
                ports = ','.join(sorted(merged))
            if own_ip and own_ip != self._exclusion.get('ip', ''):
                logger.warning(
                    'config ControlLinkExcludeIp %s overridden by the '
                    'service control address %s', own_ip,
                    self._exclusion.get('ip', ''))
        instance.diverter_config['ControlLinkExcludeIp'] = \
            self._exclusion.get('ip', '')
        instance.diverter_config['ControlLinkExcludePort'] = ports

    def _handle_terminal_failure(self, reason):
        """Terminal internal failure (record 034): the failed state is
        published FIRST (CHK-039 — a high-confidence terminal condition
        never waits for evidence collection), then the bounded incident
        pack, then the unified stop sequence; never waits for the
        controller."""
        logger.error('terminal internal failure: %s', reason)
        self._terminal_evidence = reason
        coord = self._coordinator
        if coord is not None:
            coord.update_health_state('failed', reason)
        try:
            self._collect_incident(reason)
        except Exception:  # noqa: BLE001 - evidence must not block cleanup
            logger.exception('incident collection failed')
        if coord is None:
            return
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

    def _register_run_artifacts(self, run_id):
        """CHK-029: copy the run's FakeNet outputs (PCAPs, log, report)
        from the package root into the managed artifacts tree. Only files
        produced DURING this run are registered — earlier runs' outputs
        stay where they are; re-copying them every stop made registration
        grow quadratically over a release matrix (r54/r55 evidence)."""
        if not run_id or not self._artifacts_root:
            return
        try:
            import sys
            from fakenet.mcp.artifacts import ArtifactRegistry
            if getattr(sys, 'frozen', False):
                package_root = os.path.dirname(os.path.abspath(
                    sys.executable))
            else:
                package_root = os.path.dirname(os.path.dirname(
                    os.path.dirname(os.path.abspath(__file__))))
            started = self._run_started_at
            registry = ArtifactRegistry(self._artifacts_root)
            copied = []
            # CHK-048: per-run outputs land in the run directory under
            # ProgramData — register that complete set directly; the
            # mtime-filtered package-root scan stays as fallback for
            # outputs produced before the redirection existed.
            run_dir = getattr(self, '_active_run_dir', None)
            if run_dir is not None and run_dir.is_dir():
                copied = registry.register_fakenet_outputs(
                    run_id, run_dir, prefix='')

            def _fresh(path):
                if started is None:
                    return True
                try:
                    return path.stat().st_mtime >= started - 1.0
                except OSError:
                    return False

            copied += registry.register_fakenet_outputs(
                run_id, package_root, keep=_fresh)
            if copied:
                logger.info('registered %d run artifacts for %s',
                            len(copied), run_id)
        except Exception:  # noqa: BLE001 - best-effort registration
            logger.exception('run artifact registration failed')

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
        self._run_started_at = None
        self._active_run_dir = None
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
    if not run_id:
        # needs_recovery is set but the run_id is absent: the snapshot
        # cannot identify which run to verify — fail closed (CHK-015).
        coordinator._failure_reason = (
            'recovery marker has no run_id; cannot verify')
        return 'failed'
    # CHK-015: a needs_recovery run with no readable baseline is an
    # unverifiable recovery — fail closed, never guess 'stopped'.
    if baseline_store is None:
        coordinator._failure_reason = (
            'baseline store unavailable; cannot verify recovery')
        return 'failed'
    baseline_path = baseline_store.root / (str(run_id) + '.json')
    if not baseline_path.is_file():
        coordinator._failure_reason = (
            'baseline file for run %s not found; cannot verify' % run_id)
        return 'failed'
    # CHK-040: an unreadable/corrupt baseline is an UNVERIFIABLE
    # recovery — fail closed, never treat it as a clean match. The
    # comparison uses the same normalized, attributable audit as the
    # stop path (one schema across P03/P04/P05; CHK-042).
    differences = baseline_store.full_audit_diff(run_id)
    if differences is None:
        coordinator._failure_reason = (
            'baseline for run %s unreadable; cannot verify recovery'
            % run_id)
        logger.error('recovery audit cannot read baseline for run %s',
                     run_id)
        return 'failed'
    if differences:
        try:
            import json as _json
            logger.error(
                'recovery audit differences for run %s: %s', run_id,
                _json.dumps(differences, ensure_ascii=False,
                            default=str)[:2000])
        except Exception:  # noqa: BLE001 - logging only
            logger.error('recovery audit differences (raw): %r', differences)
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
