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
from fakenet.mcp.configstore import ConfigStore
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.testdouble import LifecycleDouble
from fakenet.mcp.transportguard import (classify_controller_header,
                                        controller_header_state)


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

    def __init__(self, config, runner=None, store=None, coordinator=None):
        from fakenet.mcp import paths

        self.config = config
        dirs = paths.ensure_data_directories()
        self.runner = runner or LifecycleDouble()
        self.store = store or ConfigStore(
            custom_root=dirs['configs_custom'],
            builtin_root=_builtin_configs_root(),
            audit_path=dirs['logs'] / 'config-audit.jsonl')
        self.coordinator = coordinator or Coordinator(self.runner)
        self.artifacts_root = dirs['artifacts']

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

    @server.tool()
    def ping() -> dict:
        controller, classification = ctx.controller_identity()
        return {'service': MCP_PACKAGE_NAME, 'version': MCP_PACKAGE_VERSION,
                'protocol': '2026-07-28',
                'controller_header': classification}

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

                items.append({
                    'path': str(path),
                    'type': path.suffix.lstrip('.') or 'file',
                    'size': stat_result.st_size,
                    'complete': not path.name.endswith('.part'),
                    'sha256': hashlib.sha256(
                        path.read_bytes()).hexdigest(),
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
            if not coord.running:
                return {'state': 'stopped', 'changed': False}
            result = ctx.runner.stop(coord)
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
            # restart stays bound to the original run_id (record 023).
            result['run_id'] = previous_run_id
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
    def config_mutation(kind, describe, mutate):
        def invoke(command_id, expected_state_version):
            controller, classification = ctx.controller_identity()

            def execute(coord):
                return mutate(controller)

            try:
                return ctx.coordinator.submit(
                    command_id=command_id,
                    expected_version=int(expected_state_version),
                    controller=controller,
                    controller_valid=classification == 'valid_uuid',
                    kind=kind, describe=describe,
                    execute=execute)
            except errors.McpError as exc:
                return ctx.error_response(exc)
        return invoke

    @server.tool()
    def create_config(name: str, content: str, command_id: str,
                      expected_state_version: int) -> dict:
        try:
            ctx.store.validate_content(content)
        except errors.McpError as exc:
            return ctx.error_response(exc)
        return config_mutation(
            'create_config', {'name': name},
            lambda controller: ctx.store.create(
                controller=controller, command_id=command_id, name=name,
                content=content))(
            command_id, expected_state_version)

    @server.tool()
    def import_config(name: str, content: str, command_id: str,
                      expected_state_version: int) -> dict:
        try:
            ctx.store.validate_content(content)
        except errors.McpError as exc:
            return ctx.error_response(exc)
        return config_mutation(
            'import_config', {'name': name},
            lambda controller: ctx.store.create(
                controller=controller, command_id=command_id, name=name,
                content=content))(
            command_id, expected_state_version)

    @server.tool()
    def edit_config(name: str, content: str, expected_sha256: str,
                    command_id: str, expected_state_version: int) -> dict:
        try:
            ctx.store.validate_content(content)
        except errors.McpError as exc:
            return ctx.error_response(exc)
        return config_mutation(
            'edit_config', {'name': name},
            lambda controller: ctx.store.edit(
                controller=controller, command_id=command_id, name=name,
                content=content, expected_sha256=expected_sha256))(
            command_id, expected_state_version)

    @server.tool()
    def rename_config(name: str, new_name: str, expected_sha256: str,
                      command_id: str, expected_state_version: int) -> dict:
        return config_mutation(
            'rename_config', {'name': name, 'new_name': new_name},
            lambda controller: ctx.store.rename(
                controller=controller, command_id=command_id, name=name,
                new_name=new_name, expected_sha256=expected_sha256))(
            command_id, expected_state_version)

    @server.tool()
    def delete_config(name: str, expected_sha256: str, command_id: str,
                      expected_state_version: int) -> dict:
        return config_mutation(
            'delete_config', {'name': name},
            lambda controller: ctx.store.delete(
                controller=controller, command_id=command_id, name=name,
                expected_sha256=expected_sha256))(
            command_id, expected_state_version)

    return server
