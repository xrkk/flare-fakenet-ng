# Copyright 2026 Google LLC
"""Domain tool surface for fakenetng-mcp (P02 slice, sub-plan §3/§4).

Read-only tools are side-effect free and answer any reachable connection.
Mutations go through :class:`fakenet.mcp.coordination.Coordinator` (serial,
versioned, idempotent, identity-gated).  Structured failures are returned
in the ``error`` field per the master-plan §6.1 response contract.
"""

import os
import sys
import uuid
from pathlib import Path
from typing import Optional, Union

from pydantic import StrictFloat, StrictInt

from fakenet.mcp import MCP_PACKAGE_NAME, MCP_PACKAGE_VERSION
from fakenet.mcp import errors
from fakenet.mcp.configstore import ConfigStore
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.testdouble import LifecycleDouble
from fakenet.mcp.transportguard import (classify_controller_header,
                                        controller_header_state)


def _validated_run_id(value):
    """Canonical-UUID gate shared by the read-only query filters.

    Mirrors the diagnostic worker's ``_run_id`` rule (str(uuid.UUID(value))
    == value): non-strings, non-UUIDs and non-canonical spellings are
    structured rejections, never a silent fallback to the full set.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise errors.McpError(
            errors.INVALID_REQUEST, 'run_id must be a canonical UUID')
    try:
        canonical = str(uuid.UUID(value))
    except (ValueError, AttributeError):
        raise errors.McpError(
            errors.INVALID_REQUEST, 'run_id must be a canonical UUID') from None
    if canonical != value:
        raise errors.McpError(
            errors.INVALID_REQUEST, 'run_id must be a canonical UUID')
    return value


def _validated_artifact_type(value):
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise errors.McpError(
            errors.INVALID_REQUEST,
            'artifact_type must be a non-empty string')
    return value


def _make_snapshot(dirs):
    from fakenet.mcp.snapshot import StateSnapshot

    return StateSnapshot(dirs['state'] / 'state.json')


def _make_baseline_store(dirs):
    from fakenet.mcp.baseline import BaselineStore

    store = BaselineStore(dirs['baselines'])
    if os.environ.get('FAKENET_MCP_OWNED_DRIVER_DIAGNOSTICS') == '1':
        try:
            from fakenet.mcp import owned_driver_diagnostics
            store.owned_driver_observer = owned_driver_diagnostics.create(dirs['logs'])
        except Exception as exc:
            # Preparation/import failures must not turn diagnostics into a
            # service-start or compensation dependency. No exception data/env.
            import logging
            try:
                logging.getLogger(__name__).warning(
                    'owned-driver-diagnostics incomplete: factory %s',
                    type(exc).__name__)
            except Exception:
                pass
    return store


def _builtin_configs_root():
    """Built-in (read-only) configs ship next to the frozen exe; in source
    checkouts they live in the fakenet package directory."""
    import sys
    from pathlib import Path

    exe_dir = Path(sys.executable).resolve().parent
    bundled = exe_dir / 'configs'
    if bundled.is_dir():
        return bundled
    return Path(__file__).resolve().parent.parent / 'configs'


class AppContext:

    def __init__(self, config, runner=None, store=None, coordinator=None,
                 real_supervisor=None):
        from fakenet.mcp import paths

        self.config = config
        dirs = paths.ensure_data_directories()
        self.store = store or ConfigStore(
            custom_root=dirs['configs_custom'],
            builtin_root=_builtin_configs_root(),
            audit_path=dirs['logs'] / 'config-audit.jsonl')
        if runner is not None:
            self.runner = runner
        elif real_supervisor is not None:
            self.runner = real_supervisor
        else:
            import os

            if os.environ.get('FAKENETNG_MCP_TESTDOUBLE') == '1':
                self.runner = LifecycleDouble()
            else:
                from fakenet.mcp.supervisor import RealSupervisor

                log_path = dirs['logs'] / 'service.log'

                def log_reader(offset=0):
                    if not log_path.is_file():
                        return ''
                    with open(log_path, 'rb') as handle:
                        handle.seek(0, 2)
                        size = handle.tell()
                        handle.seek(min(offset, size))
                        window = handle.read()[-65536:]
                    return window.decode('utf-8', 'replace')

                def log_size():
                    return log_path.stat().st_size if \
                        log_path.is_file() else 0

                def verify_start_boundary():
                    from fakenet.mcp import firewall
                    try:
                        ok, detail = firewall.verify_rule(
                            config.listen_port, config.allowed_host_ips)
                    except (RuntimeError, OSError) as exc:
                        ok, detail = False, str(exc)
                    if not ok:
                        raise errors.McpError(
                            errors.VALIDATION_FAILED,
                            'firewall protection unverifiable; start refused',
                            {'reason': detail})

                supervisor = RealSupervisor(
                    start_guard=verify_start_boundary,
                    snapshot=_make_snapshot(dirs),
                    baseline_store=_make_baseline_store(dirs),
                    stop_grace_seconds=config.stop_grace_seconds,
                    config_path_resolver=self._default_config_resolver,
                    artifacts_root=dirs['artifacts'],
                    exclusion={
                        'ip': (config.allowed_host_ips[0]
                               if config.allowed_host_ips else ''),
                        'port': ','.join(
                            str(port) for port in
                            [config.listen_port] +
                            list(getattr(config, 'extra_control_ports',
                                         []))),
                    },
                    log_reader=log_reader,
                )
                supervisor._log_size_probe = log_size
                self.runner = supervisor
        self.coordinator = coordinator or Coordinator(self.runner)
        if store is None:
            self.coordinator.on_run_end(lambda: self.store.set_active(None))
        if (runner is None and real_supervisor is None and
                os.environ.get('FAKENETNG_MCP_TESTDOUBLE') != '1'):
            self.coordinator.update_health_state('recovering')
        self.artifacts_root = dirs['artifacts']
        # Artifact enumeration reads and hashes evidence files; it runs in the
        # fixed diagnostic task with its own budget so no HTTP handler ever
        # performs potentially blocking evidence I/O inline.
        from fakenet.mcp.diagnostic_process import DiagnosticOwner
        package = Path(sys.executable).parent if getattr(sys, 'frozen', False) \
            else Path(__file__).resolve().parents[2]
        self.diagnostics = DiagnosticOwner(package)

    def _default_config_resolver(self, name, builtin):
        if builtin:
            return str(self.store.builtin_root / name)
        return str(self.store.custom_root / name)

    # ---------------------------------------------------------------------
    def controller_identity(self):
        value = controller_header_state.get()
        classification = classify_controller_header(value)
        return (value.strip() if classification == 'valid_uuid' else None,
                classification)

    def error_response(self, exc):
        snap = self.coordinator.snapshot()
        return {
            'state': snap['state'],
            'state_version': snap['state_version'],
            'run_id': snap['run_id'],
            'changed': False,
            'error': exc.to_dict(),
            'command_id': None,
        }


def register_tools(server, ctx):

    def tool_result(payload):
        return payload

    # -- read-only diagnostics --------------------------------------------
    @server.tool()
    def get_status() -> dict:
        snap = ctx.coordinator.snapshot()
        snap['service'] = MCP_PACKAGE_NAME
        snap['error'] = None
        return snap

    @server.tool()
    def get_command_status(command_id: str) -> dict:
        """Read-only reconciliation for one submitted command.

        Answers from the in-process command cache only: in_progress,
        completed, failed (with the command's own error) or unknown (this
        process has no record — never submitted, evicted, or after a
        restart). Requires the caller's controller identity and respects
        the current run's controller ownership; the reply is an isolated
        copy and never mutates cache, replay, versions or state.
        """
        controller, classification = ctx.controller_identity()
        try:
            return ctx.coordinator.command_status(
                command_id=command_id, controller=controller,
                controller_valid=classification == 'valid_uuid')
        except errors.McpError as exc:
            return {
                'command_id': command_id if isinstance(command_id, str)
                else None,
                'status': None,
                'cache_scope': 'process',
                'persistent': False,
                'response': None,
                'command_error': None,
                'error': exc.to_dict(),
            }

    @server.tool()
    def get_events(limit: int = 100, cursor: str = None,
                   run_id: str = None) -> dict:
        from fakenet.mcp import queries
        limit = max(1, min(int(limit), 500))
        try:
            _validated_run_id(run_id)
        except errors.McpError as exc:
            return {'events': [], 'error': exc.to_dict()}
        epoch, entries, oldest, latest = ctx.coordinator.events_window()
        try:
            page = queries.events_page(
                entries, epoch, oldest, latest,
                limit=limit, cursor_token=cursor, run_id=run_id)
        except queries.InvalidCursor as exc:
            return {'events': [], 'error': errors.McpError(
                errors.INVALID_REQUEST,
                'invalid cursor: %s' % exc).to_dict()}
        payload = dict(page)
        payload['limit'] = limit
        payload['run_id'] = run_id
        payload['error'] = None
        # Read-only by construction: snapshot/events_window never touch
        # state_version, controller or commands.
        return payload

    @server.tool()
    async def wait_status(states: list = None,
                          after_state_version: Optional[StrictInt] = None,
                          timeout_seconds: Union[StrictInt, StrictFloat] = 10) -> dict:
        """Bounded single-call wait for a service-state condition.

        Waits until the state is one of ``states`` (when given) AND the
        state version exceeds ``after_state_version`` (when given), for at
        most ``timeout_seconds`` (0..30, finite). Numeric arguments are
        strictly typed at the registration boundary: booleans, numeric
        strings and float versions never reach the tool, let alone the
        domain validation. The wait is read-only:
        no version growth, no events, no ownership, no state changes —
        and it never blocks the service loop (bounded async polling, no
        locks held across sleeps, nothing left running after the reply).
        The returned ``status`` is exactly the last observation the
        decision used; ``timed_out=true`` is a normal bounded outcome,
        never a claim the condition held.
        """
        from fakenet.mcp import queries
        try:
            queries.validate_wait_request(states, after_state_version,
                                          timeout_seconds)
        except queries.InvalidWaitRequest as exc:
            return {'matched': False, 'timed_out': False,
                    'elapsed_seconds': 0.0, 'status': None,
                    'error': errors.McpError(
                        errors.INVALID_REQUEST, str(exc)).to_dict()}
        result = await queries.wait_for_status(
            observe=ctx.coordinator.snapshot, states=states,
            after_state_version=after_state_version,
            timeout_seconds=timeout_seconds)
        status = dict(result['observation'])
        status['service'] = MCP_PACKAGE_NAME
        status['error'] = None
        return {'matched': result['matched'],
                'timed_out': result['timed_out'],
                'elapsed_seconds': round(result['elapsed_seconds'], 3),
                'status': status, 'error': None}

    @server.tool()
    def get_run_overview(run_id: str = None, event_limit: int = 100,
                         event_cursor: str = None,
                         artifact_type: str = None) -> dict:
        """One read-only aggregate: current service status plus the run's
        events page and filtered artifacts for the selected run.

        The three pieces are NOT one atomic transaction: the response
        reports the state versions observed before and after and
        ``consistent`` is false when a mutation landed in between. The
        service_status block is always the CURRENT service snapshot — a
        selected historical run never inherits its health or recovery
        fields. Each sub-query failure keeps the other results and is
        surfaced through ``partial`` plus the sub-query's own error; a
        failed or empty sub-list is never presented as complete success.
        """
        import time

        from fakenet.mcp import queries
        from fakenet.mcp.diagnostic_process import DiagnosticError
        event_limit = max(1, min(int(event_limit), 500))
        try:
            run_id = _validated_run_id(run_id)
            artifact_type = _validated_artifact_type(artifact_type)
        except errors.McpError as exc:
            return {'error': exc.to_dict()}

        # Metadata-lock-held reads only: the coordinator snapshot and event
        # window release the lock immediately; artifact hashing stays in the
        # diagnostic task, never inline under this aggregate.
        status_before = ctx.coordinator.snapshot()
        if run_id is None:
            current = status_before.get('run_id')
            if current is None:
                selected, selection = None, 'no_current_run'
            else:
                selected, selection = current, 'current'
        else:
            selected, selection = run_id, 'explicit'

        partial = False
        problems = []

        if selected is None:
            events_query = {
                'events': [], 'error': None, 'limit': event_limit,
                'run_id': None, 'selection_note': 'no_current_run',
            }
            artifacts_query = {
                'artifacts': [], 'error': None, 'matched_count': 0,
                'query': {'run_id': None, 'artifact_type': artifact_type},
                'selection_note': 'no_current_run',
            }
        else:
            try:
                epoch, entries, oldest, latest = ctx.coordinator.events_window()
                page = queries.events_page(
                    entries, epoch, oldest, latest, limit=event_limit,
                    cursor_token=event_cursor, run_id=selected)
                events_query = dict(page)
                events_query['limit'] = event_limit
                events_query['run_id'] = selected
                events_query['error'] = None
            except queries.InvalidCursor as exc:
                partial = True
                problems.append('events_query')
                events_query = {'events': [], 'error': errors.McpError(
                    errors.INVALID_REQUEST,
                    'invalid cursor: %s' % exc).to_dict()}
            payload = {'run_id': selected}
            if artifact_type is not None:
                payload['artifact_type'] = artifact_type
            try:
                items = ctx.diagnostics.call(
                    'list-artifacts', payload, time.monotonic() + 60)
                artifacts_query = {
                    'artifacts': items, 'error': None,
                    'matched_count': len(items),
                    'query': {'run_id': selected,
                              'artifact_type': artifact_type},
                }
            except (DiagnosticError, AttributeError) as exc:
                partial = True
                problems.append('artifacts_query')
                artifacts_query = {
                    'artifacts': [], 'error': str(exc), 'matched_count': 0,
                    'query': {'run_id': selected,
                              'artifact_type': artifact_type},
                }

        status_after = ctx.coordinator.snapshot()
        service_status = dict(status_after)
        service_status['service'] = MCP_PACKAGE_NAME
        service_status['error'] = None
        return {
            'selected_run_id': selected,
            'selection': selection,
            'service_status': service_status,
            'events_query': events_query,
            'artifacts_query': artifacts_query,
            'status_before_version': status_before['state_version'],
            'status_after_version': status_after['state_version'],
            'consistent': (status_before['state_version']
                           == status_after['state_version']),
            'partial': partial,
            'error': ('; '.join(problems) + ' failed') if problems else None,
        }

    @server.tool()
    def list_configs() -> dict:
        return {'configs': ctx.store.list(), 'error': None}

    @server.tool()
    def validate_config(name: str = None, content: str = None) -> dict:
        try:
            if content is not None:
                result = ctx.store.validate_content(content)
            elif name is not None:
                record = ctx.store.read(name)
                result = ctx.store.validate_content(record['content'])
            else:
                raise errors.McpError(
                    errors.INVALID_REQUEST,
                    'name or content is required')
            result['error'] = None
            return result
        except errors.McpError as exc:
            return {'error': exc.to_dict()}

    @server.tool()
    def read_config(name: str) -> dict:
        try:
            record = ctx.store.read(name)
            record['error'] = None
            return record
        except errors.McpError as exc:
            return {'error': exc.to_dict()}

    @server.tool()
    def list_artifacts(run_id: str = None, artifact_type: str = None) -> dict:
        import time

        from fakenet.mcp.diagnostic_process import DiagnosticError
        try:
            run_id = _validated_run_id(run_id)
            artifact_type = _validated_artifact_type(artifact_type)
        except errors.McpError as exc:
            return {'artifacts': [], 'error': exc.to_dict()}
        payload = {}
        if run_id is not None:
            payload['run_id'] = run_id
        if artifact_type is not None:
            payload['artifact_type'] = artifact_type
        try:
            items = ctx.diagnostics.call(
                'list-artifacts', payload, time.monotonic() + 60)
        except DiagnosticError as exc:
            return {'artifacts': [], 'error': str(exc)}
        except AttributeError:
            return {'artifacts': [], 'error': 'artifact enumeration unavailable'}
        # A zero match is exactly that: it never claims the run itself
        # succeeded or completed.
        return {'artifacts': items, 'error': None,
                'query': {'run_id': run_id, 'artifact_type': artifact_type},
                'matched_count': len(items)}

    # -- lifecycle mutations ----------------------------------------------
    @server.tool()
    def load_config(name: str, command_id: str,
                    expected_state_version: int) -> dict:
        controller, classification = ctx.controller_identity()

        def execute(coord):
            if coord.running:
                raise errors.McpError(
                    errors.NOT_ALLOWED_IN_STATE,
                    'load_config is not allowed while a run is active')
            record = ctx.store.read(name)
            verdict = ctx.store.validate_content(record['content'])
            if not verdict.get('valid'):
                raise errors.McpError(
                    errors.VALIDATION_FAILED, 'configuration invalid')
            coord.set_config_identity(
                {'name': name, 'sha256': record['sha256'],
                 'builtin': record['builtin']})
            return {'state': coord.snapshot()['state'], 'changed': True,
                    'config_identity': {'name': name,
                                        'sha256': record['sha256'],
                                        'builtin': record['builtin']}}

        try:
            return ctx.coordinator.submit(
                command_id=command_id, expected_version=int(
                    expected_state_version),
                controller=controller,
                controller_valid=classification == 'valid_uuid',
                kind='load_config', describe={'name': name},
                execute=execute)
        except errors.McpError as exc:
            return ctx.error_response(exc)

    @server.tool()
    def start(command_id: str, expected_state_version: int) -> dict:
        controller, classification = ctx.controller_identity()

        def execute(coord):
            snap = coord.snapshot()
            identity = snap.get('config_identity')
            if not identity:
                raise errors.McpError(
                    errors.INVALID_REQUEST,
                    'no configuration loaded; call load_config first')
            result = ctx.runner.start(coord, controller, identity)
            if result.get('state') in ('healthy', 'degraded'):
                ctx.store.set_active(identity['name'])
            return result

        try:
            return ctx.coordinator.submit(
                command_id=command_id,
                expected_version=int(expected_state_version),
                controller=controller,
                controller_valid=classification == 'valid_uuid',
                kind='start', describe={},
                execute=execute)
        except errors.McpError as exc:
            return ctx.error_response(exc)

    @server.tool()
    def stop(command_id: str, expected_state_version: int) -> dict:
        controller, classification = ctx.controller_identity()

        def execute(coord):
            if not coord.running and not coord.needs_recovery:
                # Nothing is running and nothing is owned; the stop is a
                # no-op, but it still releases any run-scoped config lock.
                ctx.store.set_active(None)
                return {'state': 'stopped', 'changed': False}
            result = ctx.runner.stop(coord)
            if result.get('state') == 'stopped' and not result.get('run_id'):
                ctx.store.set_active(None)
            return result

        try:
            return ctx.coordinator.submit(
                command_id=command_id,
                expected_version=int(expected_state_version),
                controller=controller,
                controller_valid=classification == 'valid_uuid',
                kind='stop', describe={},
                execute=execute)
        except errors.McpError as exc:
            return ctx.error_response(exc)

    @server.tool()
    def restart(command_id: str, expected_state_version: int) -> dict:
        controller, classification = ctx.controller_identity()

        def execute(coord):
            if not coord.running:
                raise errors.McpError(
                    errors.NOT_ALLOWED_IN_STATE,
                    'restart requires an active run bound to its run_id')
            identity = coord.snapshot().get('config_identity')
            previous_run_id = coord.snapshot()['run_id']
            result = ctx.runner.restart(coord, controller, identity)
            # The request is bound to the run it was issued against (record
            # 023) so a retry cannot restart another instance, but the
            # response reports the instance that actually exists now.
            result['bound_run_id'] = previous_run_id
            return result

        try:
            return ctx.coordinator.submit(
                command_id=command_id,
                expected_version=int(expected_state_version),
                controller=controller,
                controller_valid=classification == 'valid_uuid',
                kind='restart', describe={},
                execute=execute)
        except errors.McpError as exc:
            return ctx.error_response(exc)

    # -- configuration mutations ------------------------------------------
    def config_mutation(kind, describe, mutate, conflict_names=None):
        def invoke(command_id, expected_state_version):
            controller, classification = ctx.controller_identity()

            def execute(coord):
                stored = mutate(controller)
                result = dict(stored)
                # The stored receipt comes from THIS completed commit's own
                # return value — the actually stored name and the hash of
                # the bytes on disk — never a post-commit re-read of a file
                # another writer may have replaced, and never the caller's
                # input string or expected_sha256.
                if kind == 'delete_config':
                    result['config_result'] = {
                        'name': stored.get('name'), 'sha256': None,
                        'builtin': False, 'deleted': True}
                else:
                    result['config_result'] = {
                        'name': stored.get('name'),
                        'sha256': stored.get('sha256'),
                        'builtin': bool(stored.get('builtin', False)),
                        'deleted': False}
                return result

            def audit_rejected(exc):
                # CHK-047: every real attempt — including rejections —
                # lands in the ordinary audit with full identity/kind/
                # target/result so failures stay attributable.
                try:
                    ctx.store.audit(
                        controller=controller,
                        command_id=command_id,
                        target=str(describe.get('name', '')),
                        operation=kind,
                        before_sha256=None, after_sha256=None,
                        result='rejected: %s' % exc.code)
                except errors.McpError:
                    pass  # audit store unavailable; the error stands

            try:
                return ctx.coordinator.submit(
                    command_id=command_id,
                    expected_version=int(expected_state_version),
                    controller=controller,
                    controller_valid=classification == 'valid_uuid',
                    kind=kind, describe=describe,
                    execute=execute,
                    # CHK-046: config mutations scope conflicts to the
                    # touched names — disjoint configs run in parallel
                    # (contract 033); lifecycle stays global.
                    conflict_names=conflict_names)
            except errors.McpError as exc:
                audit_rejected(exc)
                return ctx.error_response(exc)
        return invoke

    @server.tool()
    def create_config(name: str, content: str, command_id: str,
                      expected_state_version: int) -> dict:
        try:
            ctx.store.validate_content(content)
        except errors.McpError as exc:
            try:
                ctx.store.audit(
                    controller=ctx.controller_identity()[0],
                    command_id=command_id, target=name,
                    operation='validate', before_sha256=None,
                    after_sha256=None,
                    result='rejected: %s' % exc.code)
            except errors.McpError:
                pass
            return ctx.error_response(exc)
        return config_mutation(
            'create_config', {'name': name},
            lambda controller: ctx.store.create(
                controller=controller, command_id=command_id, name=name,
                content=content), conflict_names=frozenset((name,)))(
            command_id, expected_state_version)

    @server.tool()
    def import_config(name: str, content: str, command_id: str,
                      expected_state_version: int) -> dict:
        try:
            ctx.store.validate_content(content)
        except errors.McpError as exc:
            try:
                ctx.store.audit(
                    controller=ctx.controller_identity()[0],
                    command_id=command_id, target=name,
                    operation='validate', before_sha256=None,
                    after_sha256=None,
                    result='rejected: %s' % exc.code)
            except errors.McpError:
                pass
            return ctx.error_response(exc)
        return config_mutation(
            'import_config', {'name': name},
            lambda controller: ctx.store.create(
                controller=controller, command_id=command_id, name=name,
                content=content), conflict_names=frozenset((name,)))(
            command_id, expected_state_version)

    @server.tool()
    def edit_config(name: str, content: str, expected_sha256: str,
                    command_id: str, expected_state_version: int) -> dict:
        try:
            ctx.store.validate_content(content)
        except errors.McpError as exc:
            try:
                ctx.store.audit(
                    controller=ctx.controller_identity()[0],
                    command_id=command_id, target=name,
                    operation='validate', before_sha256=None,
                    after_sha256=None,
                    result='rejected: %s' % exc.code)
            except errors.McpError:
                pass
            return ctx.error_response(exc)
        return config_mutation(
            'edit_config', {'name': name},
            lambda controller: ctx.store.edit(
                controller=controller, command_id=command_id, name=name,
                content=content, expected_sha256=expected_sha256), conflict_names=frozenset((name,)))(
            command_id, expected_state_version)

    @server.tool()
    def rename_config(name: str, new_name: str, expected_sha256: str,
                      command_id: str, expected_state_version: int) -> dict:
        return config_mutation(
            'rename_config', {'name': name, 'new_name': new_name},
            lambda controller: ctx.store.rename(
                controller=controller, command_id=command_id, name=name,
                new_name=new_name, expected_sha256=expected_sha256),
            conflict_names=frozenset((name, new_name)))(
            command_id, expected_state_version)

    @server.tool()
    def delete_config(name: str, expected_sha256: str, command_id: str,
                      expected_state_version: int) -> dict:
        return config_mutation(
            'delete_config', {'name': name},
            lambda controller: ctx.store.delete(
                controller=controller, command_id=command_id, name=name,
                expected_sha256=expected_sha256), conflict_names=frozenset((name,)))(
            command_id, expected_state_version)

    return server
