# Copyright 2026 Google LLC
"""Single MCP supervisor for a separately Job-contained FakeNet lifecycle."""

import hashlib
import logging
import os
import sys
import threading
import time
from pathlib import Path

from fakenet.mcp import errors

logger = logging.getLogger('fakenetng-mcp.supervisor')
HEALTH_INTERVAL_SECONDS = 2.0
RESTART_SETTLE_SECONDS = 5.0


def evaluate_health_evidence(detail, run_log):
    """The same three-input predicate is used by IPC and listener regression."""
    if not all(detail.get(k) for k in ('process_alive', 'init_evidence', 'probe')):
        return False, 'managed initialization/handle probe failed'
    if 'Traceback (most recent call last)' in run_log or 'Unhandled exception' in run_log:
        return False, 'unhandled exception in current run log'
    return True, None


class SupervisorStartError(RuntimeError):
    pass


class RealSupervisor:
    name = 'real'

    def __init__(self, coordination_cls=None, snapshot=None, baseline_store=None,
                 config_path_resolver=None, stop_grace_seconds=60,
                 health_interval=None, log_reader=None, probe_impl=None,
                 exclusion=None, artifacts_root=None, fault_injector=None,
                 start_guard=None):
        self._snapshot = snapshot
        self._baseline_store = baseline_store
        self._config_path_resolver = config_path_resolver
        self._stop_grace = stop_grace_seconds
        self._start_guard = start_guard
        self._exclusion = dict(exclusion or {})
        self._artifacts_root = artifacts_root
        self._fakenet = None
        self._activity_lock = None
        self._lock = threading.RLock()
        self._exit_condition = threading.Condition(self._lock)
        import uuid
        self._exit_instance = str(uuid.uuid4())
        self._exit_capability = None
        self._exit_retention = None
        self._last_exit_evidence = None
        self._health_stop = threading.Event()
        self._health_publication_lock = threading.Lock()
        self._health_thread = None
        self._health_cache = {'process_alive': False, 'init_evidence': False, 'probe': False}
        self._coordinator = None
        self._marker = None
        self._active_config_path = None
        self._run_dir = None
        self._log_reader = log_reader
        self._last_run_outcome = None
        self._last_managed_stacks = None
        self._last_managed_process = None
        self._last_final_filter = None
        self._endpoint_observation = None
        self._completed_failure_evidence = None

    def health_detail(self, state, max_wait=0.05):
        # Observations are updated by a bounded IPC poll, never queried under
        # the lifecycle lock by HTTP handlers.
        return dict(self._health_cache)

    def _resolve_config_path(self, name, builtin):
        if self._config_path_resolver is None:
            raise SupervisorStartError('config path resolver missing')
        return self._config_path_resolver(name, builtin)

    def _result(self, state, reason=None):
        result = {'state': state, 'changed': True, 'failure_reason': reason,
                  'release_controller': state == 'stopped'}
        if state == 'failed':
            self._last_run_outcome = 'failed'
            result['last_run_outcome'] = 'failed'
        if state == 'stopped':
            result['run_id'] = None
        elif self._marker:
            result.update(run_id=self._marker['run_id'],
                          controller=self._marker['controller_id'])
        return result

    def start(self, coordinator, controller, config_identity):
        if self._start_guard:
            self._start_guard()
        if os.name == 'nt' and self._fakenet is None:
            marker, corrupt = self._snapshot.read()
            if not corrupt and not (marker and marker['needs_recovery']):
                self._ensure_exit_capability()
        with self._lock:
            if self._start_guard:
                self._start_guard()
            if os.name != 'nt':
                raise SupervisorStartError('real lifecycle requires Windows')
            if self._fakenet is not None:
                raise SupervisorStartError('managed process already exists')
            if not self._finish_endpoint_observation():
                raise SupervisorStartError('previous endpoint observer cleanup unverified')
            marker, corrupt = self._snapshot.read()
            if corrupt or (marker and marker['needs_recovery']):
                raise SupervisorStartError('unresolved recovery responsibility')
            from fakenet.fakenet import Fakenet
            from fakenet.mcp.configlock import ActivityLock
            from fakenet.mcp.managed import ManagedProcess
            self._coordinator = coordinator
            config_path = self._resolve_config_path(config_identity['name'],
                                                    config_identity.get('builtin'))
            self._activity_lock = ActivityLock(config_path).acquire()
            self._active_config_path = config_path
            try:
                digest = hashlib.sha256(Path(config_path).read_bytes()).hexdigest()
                if digest != config_identity['sha256']:
                    raise SupervisorStartError('locked configuration hash changed')
                parsed = Fakenet()
                parsed.parse_config(config_path)
                self._inject_exclusion(parsed)
                run_id = coordinator.new_run_id()
                self._last_run_outcome = None
                self._last_managed_stacks = None
                self._last_managed_process = None
                self._last_exit_evidence = None
                self._exit_retention = None
                self._last_final_filter = None
                self._run_dir = Path(self._artifacts_root) / 'runs' / run_id
                self._run_dir.mkdir(parents=True, exist_ok=False)
                from fakenet.mcp.run_evidence import prepare_run_evidence
                prepare_run_evidence(self._run_dir, config_path, digest)
                from fakenet.mcp.endpoint_observation import EndpointObservation
                self._endpoint_observation = EndpointObservation(self._run_dir, run_id)
                self._endpoint_observation.start()
                for key in ('dumppacketsfileprefix', 'dumphttpwebroot'):
                    value = str(parsed.diverter_config.get(key, '') or '').strip()
                    if value and not os.path.isabs(value):
                        parsed.diverter_config[key] = str(self._run_dir / value)
                saved = self._baseline_store.save(run_id)
                self._marker = dict(run_id=run_id, controller_id=controller,
                                    state_version=coordinator.snapshot()['state_version'],
                                    command_id=coordinator.current_command_id,
                                    config_sha256=digest, baseline_path=saved['path'],
                                    needs_recovery=True)
                self._snapshot.write(**self._marker)
                coordinator.restore_responsibility(self._marker, 'starting')
                root = (Path(sys.executable).parent if getattr(sys, 'frozen', False)
                        else Path(__file__).resolve().parents[2])
                self._fakenet = ManagedProcess(run_id, self._run_dir, root)
                from fakenet.mcp.exit_retention import ExitRetention
                from fakenet.mcp.service_stop import process_identity
                self._exit_retention = ExitRetention(run_id, self._fakenet.identity,
                    process_identity(), self._exit_instance, root)
                self._fakenet.observe_creation('before_start')
                detail = self._fakenet.request('start', {
                    'config_path': str(config_path),
                    'fakenet_config': parsed.fakenet_config,
                    'diverter_config': parsed.diverter_config}, timeout=30)
                self._health_cache = dict(detail, process_alive=self._fakenet.alive(),
                                          identity=self._fakenet.identity)
                self._last_final_filter = detail.get('final_filter')
                if not all(self._health_cache.get(k) for k in
                           ('process_alive', 'init_evidence', 'probe')):
                    raise SupervisorStartError('managed initialization/active probe failed')
                if coordinator.operation_fenced:
                    return self._result('failed', 'start completed after pre-stop timeout')
                self._health_stop.clear()
                self._health_thread = threading.Thread(target=self._health_loop,
                                                        name='fakenet-health', daemon=True)
                self._health_thread.start()
                return dict(self._result('healthy'), run_id=run_id, controller=controller,
                            config_identity=config_identity)
            except BaseException as exc:
                reason = 'managed start failed: ' + repr(exc)
                coordinator.update_health_state('failed', reason)
                if self._marker and self._marker['needs_recovery']:
                    self._collect_incident(reason)
                    result = self.stop(coordinator)
                    coordinator.record_terminal_failure(reason)
                    return dict(result, last_run_outcome='failed', failure_reason=reason)
                if self._activity_lock:
                    self._activity_lock.release()
                    self._activity_lock = None
                self._finish_endpoint_observation()
                raise

    def _ensure_exit_capability(self):
        from fakenet.mcp.exit_installation import verify
        from fakenet.mcp.exit_capability import verify_native
        from fakenet.mcp.service_stop import process_identity
        if self._exit_retention is not None:
            previous = self._exit_retention.result or {}
            if (not self._exit_retention.done.is_set() or not previous.get('helper_ended')
                    or not previous.get('retained_target_handle_closed')):
                raise SupervisorStartError('previous exit evidence cleanup unverified')
        package = Path(sys.executable).parent
        verify(package)
        if self._exit_capability is None:
            self._exit_capability = verify_native(package, process_identity(), self._exit_instance)

    def _await_exit_evidence(self, deadline):
        retained = self._exit_retention
        if retained is None:
            return None
        with self._exit_condition:
            report = retained.wait(self._exit_condition, deadline)
        self._last_exit_evidence = report
        return report

    def _finish_endpoint_observation(self, deadline=None):
        observation = getattr(self, '_endpoint_observation', None)
        if observation is None:
            return True
        try:
            report = observation.finish(deadline)
            if report.get('absent'):
                return True
        except Exception:
            logger.exception('endpoint observation finalization failed')
        return False

    def _publish_health(self, child, state, evidence, reason=None):
        # Publication is short and never performs IPC or file I/O. Stop takes
        # the same lock after revoking observations, so an in-flight probe
        # cannot restore healthy while the engine is being torn down.
        with self._health_publication_lock:
            if self._health_stop.is_set() or self._fakenet is not child:
                return False
            self._health_cache = dict(evidence)
            if evidence.get('final_filter'):
                self._last_final_filter = evidence['final_filter']
            self._coordinator.update_health_state(state, reason)
            from fakenet.mcp.managed import record_ipc
            record_ipc(self._run_dir, 'parent', 'health_state',
                       {'run_id': child.run_id, 'state': state,
                        'identity': child.identity, 'reason': reason})
            return True

    def _health_loop(self):
        failures = 0
        next_probe = time.monotonic() + HEALTH_INTERVAL_SECONDS
        while not self._health_stop.wait(max(0, next_probe - time.monotonic())):
            # The period is between request starts, not an extra sleep after
            # a one-second timeout (which would stretch it to three seconds).
            next_probe = time.monotonic() + HEALTH_INTERVAL_SECONDS
            child = self._fakenet
            if child is None:
                return
            try:
                detail = child.request('health', timeout=1)
                evidence = dict(detail, process_alive=child.alive(), identity=child.identity)
                run_log = self._run_dir / 'run.log'
                log_text = ''
                if run_log.exists():
                    with run_log.open('rb') as stream:
                        stream.seek(max(0, run_log.stat().st_size - 65536))
                        log_text = stream.read().decode('utf-8', 'replace')
                healthy, reason = evaluate_health_evidence(evidence, log_text)
                if not healthy:
                    if 'unhandled exception' in reason:
                        failures += 1
                        if failures < 2:
                            if not self._publish_health(child, 'degraded', evidence, reason):
                                return
                            continue
                    raise RuntimeError(reason)
                failures = 0
                if not self._publish_health(child, 'healthy', evidence):
                    return
                continue
            except TimeoutError as exc:
                failures += 1
                reason = str(exc)
                if failures < 2:
                    if not self._publish_health(child, 'degraded', dict(self._health_cache, probe=False), reason):
                        return
                    continue
            except BaseException as exc:
                reason = str(exc)
            if not self._publish_health(child, 'failed', dict(self._health_cache, probe=False), reason):
                return
            self._collect_incident(reason)
            # Never race an already accepted operation or fall back to a raw
            # uncoordinated stop. Its existing bounded operation finishes first.
            if self._coordinator.wait_for_idle(60):
                import uuid
                try:
                    self._coordinator.submit(
                        command_id='protective-' + str(uuid.uuid4()),
                        expected_version=self._coordinator.snapshot()['state_version'],
                        controller=self._coordinator.controller, controller_valid=True,
                        kind='protective_stop', describe={}, internal=True,
                        execute=lambda c: self.stop(c))
                except Exception:
                    logger.exception('protective stop could not complete')
            self._coordinator.record_terminal_failure(reason)
            return

    def stop(self, coordinator, baseline_audit=True, deadline=None):
        deadline = deadline or time.monotonic() + self._stop_grace + 360
        if not self._lock.acquire(timeout=max(0, deadline - time.monotonic())):
            return self._result('failed', 'lifecycle lock deadline exceeded')
        try:
            self._health_stop.set()
            marker, corrupt = self._snapshot.read()
            if corrupt:
                return self._result('failed', 'recovery snapshot corrupt')
            self._marker = marker
            if marker and marker['needs_recovery']:
                expected = self._baseline_store.root / (marker['run_id'] + '.json')
                if Path(marker['baseline_path']).resolve() != expected.resolve():
                    return self._result('failed', 'baseline identity/path mismatch')
                if coordinator.current_command_id:
                    marker = dict(marker, command_id=coordinator.current_command_id,
                                  state_version=coordinator.snapshot()['state_version'])
                    self._snapshot.write(**marker)
                    self._marker = marker
            if self._fakenet is None and not (marker and marker['needs_recovery']):
                if not self._finish_endpoint_observation(deadline):
                    return self._result('failed', 'endpoint observation cleanup unverified')
                if self._activity_lock:
                    self._activity_lock.release()
                    self._activity_lock = None
                return dict(self._result('stopped'), changed=False)
            if not marker or not marker['run_id']:
                return self._result('failed', 'managed run has no recovery identity')
            self._coordinator = coordinator
            with self._health_publication_lock:
                if coordinator.snapshot()['state'] != 'failed':
                    coordinator.update_health_state('recovering')
            reason = None
            if self._fakenet is not None:
                grace_deadline = min(deadline, time.monotonic() + self._stop_grace)
                try:
                    self._last_managed_stacks = self._fakenet.request('stacks', timeout=min(
                        1, max(0, grace_deadline - time.monotonic())))['stacks']
                    if self._exit_retention is not None:
                        self._exit_retention.intent.publish(grace_deadline)
                    self._fakenet.request('stop', timeout=max(0, grace_deadline - time.monotonic()))
                    while self._fakenet.job.members() and time.monotonic() < grace_deadline:
                        time.sleep(0.05)
                    if self._fakenet.job.members():
                        raise TimeoutError('managed descendants did not exit within stop grace')
                except BaseException as exc:
                    if self._exit_retention is not None:
                        self._exit_retention.intent.invalidate()
                    reason = str(exc)
                    coordinator.update_health_state('failed', reason)
                    # A lost stop reply can outlive the entire managed tree.
                    # Keep the failure outcome, but do not request a new dump
                    # from an already exited target. Unknown/live membership
                    # and protocol errors retain the normal evidence path.
                    exited_after_transport_failure = (
                        isinstance(exc, (TimeoutError, EOFError)) and
                        self._fakenet.job.poll() is not None and
                        not self._fakenet.job.members() and
                        self._completed_failure_evidence == (
                            marker['run_id'], self._fakenet.identity, reason))
                    if exited_after_transport_failure:
                        logger.warning('stop transport failed after verified Job exit: %s', reason)
                    else:
                        self._collect_incident(reason, deadline=deadline)
                try:
                    # Even a successful root stop may leave descendants. The
                    # Job is the sole scope and emptiness is independently read.
                    self._fakenet.terminate(min(deadline, time.monotonic() + 30))
                    self._last_managed_process = {
                        'identity': self._fakenet.identity,
                        'exit_code': self._fakenet.job.poll(),
                        'job_members': self._fakenet.job.members()}
                    self._fakenet.close()
                    self._fakenet = None
                except BaseException as exc:
                    return self._result('failed', 'Job termination failed: ' + repr(exc))
            exit_report = self._await_exit_evidence(min(deadline, time.monotonic() + 60))
            if exit_report is not None and not exit_report.get('complete'):
                reason = reason or 'managed exit evidence incomplete'
                self._last_run_outcome = 'failed'
            if self._health_cache.get('final_filter'):
                self._last_final_filter = self._health_cache['final_filter']
            self._health_cache = {'process_alive': False, 'init_evidence': False, 'probe': False}
            self._baseline_store.compensate(marker['run_id'], deadline)
            differences = self._baseline_store.full_audit_diff(marker['run_id'], deadline=deadline,
                                                              settle_seconds=30,
                                                              observation=self._endpoint_observation)
            if not self._finish_endpoint_observation(deadline):
                return self._result('failed', 'endpoint observation cleanup unverified')
            if differences:
                logger.error('full restoration audit failed: %r', differences)
                self._collect_incident('environment restoration audit failed', deadline=deadline)
                return self._result('failed', 'environment restoration audit failed')
            if exit_report is not None and not exit_report.get('helper_ended'):
                return self._result('failed', 'exit helper cleanup unverified')
            if coordinator.operation_fenced:
                return self._result('failed', 'late operation cannot clear recovery responsibility')
            self._register_run_artifacts(marker['run_id'])
            # A failed release/write cannot be reported as a clean stop.
            if self._activity_lock:
                self._activity_lock.release()
                self._activity_lock = None
            self._snapshot.clear_recovery(**{k: v for k, v in marker.items() if k != 'needs_recovery'})
            self._marker = dict(marker, needs_recovery=False)
            if reason:
                self._last_run_outcome = 'failed'
            return dict(self._result('stopped'), last_run_outcome=self._last_run_outcome or 'ok')
        except BaseException as exc:
            logger.exception('stop/recovery failed')
            self._collect_incident('stop/recovery failed: ' + repr(exc), deadline=deadline)
            return self._result('failed', str(exc))
        finally:
            self._finish_endpoint_observation(deadline)
            self._lock.release()

    def recover(self, coordinator):
        self._coordinator = coordinator
        marker, corrupt = self._snapshot.read()
        self._marker = marker
        # Recover diagnostic file locations only. The current state marker
        # remains the sole authority for recovery; artifacts never replay work.
        if marker and not corrupt:
            from fakenet.mcp.run_evidence import locate_run_evidence
            self._run_dir, self._active_config_path = locate_run_evidence(
                self._artifacts_root, marker)
        coordinator.restore_responsibility(marker, 'recovering')
        if os.name == 'nt' and self._artifacts_root:
            try:
                from fakenet.mcp.endpoint_observation import (
                    EndpointObservation, stop_orphan_observers, write_evidence)
                import uuid
                active_run = (marker['run_id'] if marker and not corrupt and
                              marker['needs_recovery'] and self._run_dir else None)
                stopped = stop_orphan_observers(self._artifacts_root, active_run)
                if stopped:
                    log_root = self._baseline_store.root.parent / 'logs'
                    log_root.mkdir(parents=True, exist_ok=True)
                    write_evidence(log_root / ('endpoint-orphans-%s.json' % uuid.uuid4()), stopped)
                if active_run:
                    self._endpoint_observation = EndpointObservation(self._run_dir, active_run)
            except Exception as exc:
                coordinator.restore_responsibility(marker, 'failed',
                    'endpoint observer cleanup failed: ' + repr(exc))
                return 'failed'
        if corrupt:
            coordinator.restore_responsibility(marker, 'failed', 'corrupt recovery snapshot')
            return 'failed'
        if marker is None and any(self._baseline_store.root.glob('*.json')):
            coordinator.restore_responsibility(marker, 'failed', 'missing recovery snapshot with baseline residue')
            return 'failed'
        result = self.stop(coordinator)
        coordinator.restore_responsibility(marker, result['state'], result.get('failure_reason'))
        return result['state']

    def restart(self, coordinator, controller, config_identity):
        result = self.stop(coordinator)
        if result['state'] != 'stopped':
            return dict(result, restart_refused=True)
        time.sleep(RESTART_SETTLE_SECONDS)
        return self.start(coordinator, controller, config_identity)

    def _register_run_artifacts(self, run_id):
        if self._artifacts_root and self._run_dir:
            from fakenet.mcp.artifacts import ArtifactRegistry
            ArtifactRegistry(self._artifacts_root).register_fakenet_outputs(
                run_id, self._run_dir, prefix='')

    def _collect_incident(self, reason, deadline=None):
        try:
            return self._collect_incident_impl(reason, deadline)
        except BaseException:
            logger.exception('incident preparation failed; continuing cleanup')

    def _collect_incident_impl(self, reason, deadline=None):
        if not self._artifacts_root or not self._marker:
            return
        from fakenet.mcp.incident import IncidentCollector
        deadline = min(deadline or float('inf'), time.monotonic() + 180)
        child = self._fakenet
        retained = self._exit_retention
        exit_report = None
        if retained is not None and (child is None or not child.alive() or retained.deadline is not None):
            exit_report = self._await_exit_evidence(min(deadline, time.monotonic() + 60))
        stacks = None
        snapshot_stacks = False
        if child:
            try:
                stacks = child.request('stacks', timeout=1)['stacks']
            except BaseException:
                pass
        def read_file(name):
            path = self._run_dir / name if self._run_dir else None
            return path.read_bytes() if path and path.exists() else None
        if not stacks:
            stop_stacks = read_file('stop-thread-stacks.txt')
            if stop_stacks and b'File "' in stop_stacks:
                stacks = 'MANAGED STOP WATCHDOG; LIVE CHILD CAPTURE\n' + stop_stacks.decode('utf-8', 'replace')
        observed_identity = (child.identity if child else
                             (self._last_managed_process or {}).get('identity'))
        if not stacks and observed_identity and self._run_dir:
            from fakenet.mcp.managed_stacks import read_stacks
            stacks = read_stacks(self._run_dir, self._marker['run_id'], observed_identity)
            snapshot_stacks = stacks is not None
        import json
        import platform
        import importlib.metadata
        from fakenet.mcp.baseline import capture, audit_compare
        from fakenet.mcp.service_stop import process_identity
        baseline = self._baseline_store.load(self._marker['run_id'])
        current = capture(deadline)
        versions = {'python': sys.version, 'os': platform.platform(),
                    'executable': sys.executable,
                    'config_sha256': self._marker['config_sha256'], 'dependencies': {}}
        # Only the pinned candidate dependency set is recorded; the frozen
        # package cannot load anything the build does not install.
        for package in ('mcp', 'pydivert', 'pywin32'):
            try:
                versions['dependencies'][package] = importlib.metadata.version(package)
            except importlib.metadata.PackageNotFoundError:
                versions['dependencies'][package] = 'metadata unavailable'
        manifest = Path(sys.executable).parent / 'mcp-candidate-manifest.json'
        if manifest.is_file():
            versions['candidate_manifest'] = json.loads(manifest.read_text(encoding='utf-8'))
        metadata = []
        if self._run_dir:
            for path in self._run_dir.iterdir():
                if path.is_file():
                    raw = path.read_bytes()
                    metadata.append({'path': str(path), 'size': len(raw),
                                     'sha256': hashlib.sha256(raw).hexdigest()})
        target_creation = None
        target_pid = None
        if child:
            try:
                members = child.job.members()
                target_pid = child.pid if child.alive() else (members[0] if members else None)
                target_creation = process_identity(target_pid)['creation_time'] if target_pid else None
            except OSError:
                pass
        versions['managed_process'] = {'identity': child.identity if child else None,
                                       'exit_code': child.job.poll() if child else None,
                                       'job_members': child.job.members() if child else []}
        if child is None and self._last_managed_process:
            versions['managed_process'] = dict(self._last_managed_process)
        post_job_audit = (
            reason == 'environment restoration audit failed' and child is None and
            self._last_managed_process is not None and
            self._last_managed_process.get('exit_code') is not None and
            self._last_managed_process.get('job_members') == [])
        if post_job_audit:
            # Recovery auditing executes in this live supervisor after the
            # managed Job is verified empty. Capture that actual failure site;
            # never present its dump as a replacement for a managed crash dump.
            audit_identity = process_identity(os.getpid())
            target_pid = audit_identity['pid']
            target_creation = audit_identity['creation_time']
            versions['dump_target'] = dict(role='supervisor', identity=audit_identity,
                                          phase='post-Job restoration audit')
        if not stacks and child and not child.alive() and self._last_managed_stacks:
            stacks = 'LAST OBSERVATION BEFORE STOP; ROOT HAS EXITED\n' + self._last_managed_stacks
            extra = read_file('fault-child-stacks.txt')
            if extra:
                stacks += '\nMANAGED FAULT CHILD\n' + extra.decode('utf-8')
        context = {'timeline': self._coordinator.events(500),
                   'versions': versions,
                   'config_path': self._active_config_path,
                   'stdout_stderr': read_file('stdout_stderr.log'),
                   'run_log_window': read_file('run.log'),
                   'exception_text': reason, 'managed_thread_stacks': stacks,
                   'final_filter': self._last_final_filter,
                   'baseline_diff': {'before': baseline, 'after': current,
                       'differences': audit_compare((baseline or {}).get('sections'), current)},
                   'firewall_baseline': (baseline or {}).get('firewall'),
                   'artifact_metadata': metadata, 'dump_target_pid': target_pid,
                   'dump_target_creation': target_creation,
                   'dump_reason': ('restoration audit failure after verified managed Job exit' if post_job_audit else
                                   'managed hang/timeout' if 'timeout' in reason.lower() or
                                   'did not exit' in reason.lower() else
                                   'live managed IPC stacks unavailable' if snapshot_stacks else
                                   None if stacks else 'managed stacks unavailable')}
        if exit_report is not None:
            context['exit_evidence'] = exit_report
            if not post_job_audit and exit_report.get('complete') and exit_report.get('dump'):
                context['precollected_exit_dump'] = {
                    'path': retained.directory / 'target.dmp',
                    'identity': retained.record,
                    'dump': exit_report['dump'], 'deadline': retained.deadline}
                context['dump_reason'] = 'managed exit requires root-cause evidence'
        # The tree may exit while the bounded stack/baseline observations
        # above are running. Recheck at the actual collection boundary, not
        # just when stop first observes its missing response.
        if (child and child.job.poll() is not None and not child.job.members() and
                self._completed_failure_evidence == (
                    self._marker['run_id'], child.identity, reason)):
            logger.warning('same failure already fully captured; Job exited during incident preparation: %s', reason)
            return
        collector = IncidentCollector(self._artifacts_root, self._marker['run_id'])
        if deadline:
            collector.deadline = min(collector.deadline, time.time() + max(0, deadline-time.monotonic()))
        collector.collect(context)
        if (child and collector.manifest and
                all(entry['result'] == 'ok' for entry in collector.manifest) and
                any(entry['item'] == 'userdump.dmp' and entry['size'] > 0
                    for entry in collector.manifest)):
            self._completed_failure_evidence = (
                self._marker['run_id'], dict(child.identity), reason)
        self._health_cache['incident_path'] = str(collector.root)

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



def perform_startup_recovery(snapshot, baseline_store, coordinator):
    """Compatibility call shape for isolated recovery-unit checks."""
    marker, corrupt = snapshot.read()
    if corrupt or (marker is None and any(baseline_store.root.glob('*.json'))):
        coordinator._failure_reason = 'snapshot corrupt/missing with residue'
        return 'failed'
    if not marker or not marker['needs_recovery']:
        return 'stopped'
    if not marker['run_id'] or baseline_store is None:
        coordinator._failure_reason = 'recovery identity/baseline missing'
        return 'failed'
    if baseline_store.full_audit_diff(marker['run_id']):
        coordinator._failure_reason = 'environment differs from baseline'
        return 'failed'
    snapshot.clear_recovery(**{k:v for k,v in marker.items() if k != 'needs_recovery'})
    return 'stopped'
