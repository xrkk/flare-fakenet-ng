# Copyright 2026 Google LLC
"""Domain tool surface for fakenetng-mcp (P02 slice, sub-plan §3/§4).

Read-only tools are side-effect free and answer any reachable connection.
Mutations go through :class:`fakenet.mcp.coordination.Coordinator` (serial,
versioned, idempotent, identity-gated).  Structured failures are returned
in the ``error`` field per the master-plan §6.1 response contract.
"""

import os

from fakenet.mcp import MCP_PACKAGE_NAME, MCP_PACKAGE_VERSION
from fakenet.mcp import errors
from fakenet.mcp.artifacts import is_published
from fakenet.mcp.configstore import ConfigStore
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.testdouble import LifecycleDouble
from fakenet.mcp.transportguard import (classify_controller_header,
                                        controller_header_state)


def _make_snapshot(dirs):
    from fakenet.mcp.snapshot import StateSnapshot

    return StateSnapshot(dirs['state'] / 'state.json')


def _make_baseline_store(dirs):
    from fakenet.mcp.baseline import BaselineStore

    return BaselineStore(dirs['baselines'])


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
    def get_events(limit: int = 100) -> dict:
        limit = max(1, min(int(limit), 500))
        return {'events': ctx.coordinator.events(limit), 'error': None}

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
    def list_artifacts() -> dict:
        items = []
        if ctx.artifacts_root.is_dir():
            for path in sorted(ctx.artifacts_root.rglob('*')):
                if not path.is_file() or path.is_symlink():
                    continue
                stat_result = path.stat()
                import hashlib

                published = is_published(path.name)
                items.append({
                    'path': str(path),
                    'type': path.suffix.lstrip('.') or 'file',
                    'size': stat_result.st_size,
                    'complete': published,
                    'sha256': (hashlib.sha256(path.read_bytes()).hexdigest()
                               if published else None),
                })
        return {'artifacts': items, 'error': None}

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
                return mutate(controller)

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
