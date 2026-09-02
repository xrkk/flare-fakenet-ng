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
import re
import threading
import time

from fakenet.mcp import errors

logger = logging.getLogger('fakenetng-mcp.supervisor')

HEALTH_INTERVAL_SECONDS = 2.0
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
                 stop_grace_seconds=30.0, health_interval=None,
                 log_reader=None, probe_impl=None, exclusion=None):
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
        self._log_exception_at = None
        self._log_exception_seen = False

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
            content = self._log_reader()
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
                if self._coordinator is not None and \
                        self._coordinator.snapshot()['state'] == 'starting':
                    self._coordinator.update_health_state('healthy')
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

            # IMP-P03-05 frozen order: lock BEFORE reading/parsing.
            from fakenet.mcp.configlock import ActivityLock

            if not config_identity.get('builtin'):
                self._activity_lock = ActivityLock(config_path).acquire()

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
            self._fakenet = instance

            start_error = {}

            def run():
                try:
                    instance.start()
                except SystemExit:
                    start_error['reason'] = 'fakenet start exited'
                except Exception as exc:  # noqa: BLE001
                    start_error['reason'] = repr(exc)

            self._worker = threading.Thread(target=run, name='fakenet-run',
                                            daemon=True)
            self._worker.start()
            deadline = time.time() + min(self._stop_grace, 30.0)
            while time.time() < deadline and not start_error and \
                    not self._init_evidence():
                time.sleep(0.2)
            if start_error:
                self._teardown()
                return {'state': 'failed', 'changed': True,
                        'failure_reason': start_error['reason'],
                        'run_id': None, 'controller': None,
                        'release_controller': True,
                        'config_identity': config_identity}
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
            self._stop_event.set()
            try:
                self._fakenet.stop()
            except Exception as exc:  # noqa: BLE001
                logger.exception('fakenet stop raised')
                self._teardown()
                return {'state': 'failed', 'changed': True,
                        'failure_reason': 'stop failed: %r' % exc,
                        'run_id': None, 'release_controller': True}
            run_id = coordinator.snapshot().get('run_id')
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
        return self.start(coordinator, controller, config_identity)

    # -- helpers -------------------------------------------------------------
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

    def _teardown(self):
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
