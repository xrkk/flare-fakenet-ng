# Copyright 2026 Google LLC
"""End-to-end domain-tool semantics over the guarded HTTP endpoint (P02).

Drives the real transport (guard + coordinator + store + test double) on
an ephemeral local port with an isolated ProgramData root, mirroring the
acceptance-runner checks: read-only zero side effects, identity gates,
version/idempotency races, lifecycle double, config authorization split.
"""

import hashlib
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

mcp = pytest.importorskip('mcp')

from fakenet.mcp import server as server_module  # noqa: E402
from fakenet.mcp.config import ServiceConfig  # noqa: E402

CONTROLLER_A = '11111111-2222-4333-8444-555555555555'
CONTROLLER_B = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
VALID_INI = '[FakeNet]\nDumpPackets = No\nLogConsole = No\n'
OTHER_INI = '[FakeNet]\nDumpPackets = Yes\nLogConsole = No\n'


def sha_of(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture(scope='module')
def endpoint(tmp_path_factory):
    programdata = tmp_path_factory.mktemp('p02-programdata')
    os.environ['FAKENETNG_MCP_PROGRAMDATA'] = str(programdata)
    os.environ['FAKENETNG_MCP_TESTDOUBLE'] = '1'
    port = _free_port()
    config = ServiceConfig(listen_ip='127.0.0.1', listen_port=port,
                           allowed_host_ips=['127.0.0.1'])
    ready = threading.Event()
    failure = {}

    def serve():
        try:
            server_module.run_server(config, ready_event=ready)
        except BaseException:
            import traceback

            failure['error'] = traceback.format_exc()
            ready.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(timeout=30), failure
    assert not failure, failure
    time.sleep(0.3)
    yield 'http://127.0.0.1:%d/mcp' % port
    server_module.request_shutdown()
    os.environ.pop('FAKENETNG_MCP_PROGRAMDATA', None)
    os.environ.pop('FAKENETNG_MCP_TESTDOUBLE', None)


def envelope():
    return {
        'io.modelcontextprotocol/protocolVersion': '2026-07-28',
        'io.modelcontextprotocol/clientInfo': {'name': 'pytest-p02',
                                               'version': '0'},
        'io.modelcontextprotocol/clientCapabilities': {},
    }


def call(endpoint_url, tool, arguments=None, controller=CONTROLLER_A):
    body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': tool, 'arguments': arguments or {},
                       '_meta': envelope()}}
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2026-07-28',
        'Mcp-Method': 'tools/call',
        'Mcp-Name': tool,
    }
    if controller is not None:
        headers['X-FakeNet-Controller-ID'] = controller
    request = urllib.request.Request(endpoint_url,
                                     data=json.dumps(body).encode('utf-8'),
                                     method='POST', headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as error:
        raw = error.read().decode('utf-8', 'replace')
    envelope_response = json.loads(raw)
    if envelope_response.get('error'):
        return {'transport_error': envelope_response['error']}
    return json.loads(envelope_response['result']['content'][0]['text'])


def err_code(payload):
    return (payload.get('error') or {}).get('code')


def test_read_only_tools_zero_side_effect(endpoint):
    before = call(endpoint, 'get_status')
    call(endpoint, 'get_events')
    call(endpoint, 'list_configs')
    call(endpoint, 'list_artifacts')
    after = call(endpoint, 'get_status')
    assert before['state_version'] == after['state_version']
    assert before['run_id'] == after['run_id']
    assert err_code(before) is None


def test_mutation_without_identity_rejected(endpoint):
    payload = call(endpoint, 'create_config',
                   {'name': 'x.ini', 'content': VALID_INI,
                    'command_id': 'c-no-id', 'expected_state_version': 1},
                   controller=None)
    assert err_code(payload) == 'controller_identity_missing'
    payload_bad = call(endpoint, 'create_config',
                       {'name': 'x.ini', 'content': VALID_INI,
                        'command_id': 'c-bad-id',
                        'expected_state_version': 1},
                       controller='not-a-uuid')
    assert err_code(payload_bad) == 'controller_identity_missing'


def test_full_lifecycle_with_config(endpoint):
    created = call(endpoint, 'create_config',
                   {'name': 'run.ini', 'content': VALID_INI,
                    'command_id': 'cmd-create', 'expected_state_version': 1})
    assert created['error'] is None
    version = created['state_version']

    loaded = call(endpoint, 'load_config',
                  {'name': 'run.ini', 'command_id': 'cmd-load',
                   'expected_state_version': version})
    assert loaded['error'] is None
    version = loaded['state_version']

    started = call(endpoint, 'start',
                   {'command_id': 'cmd-start',
                    'expected_state_version': version})
    assert started['error'] is None
    assert started['state'] in ('healthy', 'degraded')
    assert started['run_id']
    version = started['state_version']

    status = call(endpoint, 'get_status')
    assert status['state'] in ('healthy', 'degraded')
    assert status['run_id'] == started['run_id']

    # Active config is locked while running.
    locked = call(endpoint, 'edit_config',
                  {'name': 'run.ini', 'content': OTHER_INI,
                   'expected_sha256': sha_of(VALID_INI),
                   'command_id': 'cmd-edit-active',
                   'expected_state_version': version})
    assert err_code(locked) == 'config_in_use'
    # The command was accepted then rejected by the configuration guard.
    # Use the returned current version; acceptance advances it even on error.
    assert locked['state_version'] == version + 1
    version = locked['state_version']

    # Non-owner cannot mutate while a run is active.
    outsider = call(endpoint, 'create_config',
                    {'name': 'other.ini', 'content': VALID_INI,
                     'command_id': 'cmd-other',
                     'expected_state_version': version},
                    controller=CONTROLLER_B)
    assert err_code(outsider) == 'controller_conflict'

    stopped = call(endpoint, 'stop',
                   {'command_id': 'cmd-stop',
                    'expected_state_version': version})
    assert stopped['error'] is None
    assert stopped['state'] == 'stopped'

    # After stop the same controller can still act; ownership released.
    after = call(endpoint, 'create_config',
                 {'name': 'other.ini', 'content': VALID_INI,
                  'command_id': 'cmd-after',
                  'expected_state_version': stopped['state_version']})
    assert after['error'] is None


def test_stopped_state_optimistic_concurrency(endpoint):
    created = call(endpoint, 'create_config',
                   {'name': 'opt.ini', 'content': VALID_INI,
                    'command_id': 'opt-create',
                    'expected_state_version': call(
                        endpoint, 'get_status')['state_version']})
    assert created['error'] is None
    sha = sha_of(VALID_INI)
    stale = call(endpoint, 'edit_config',
                 {'name': 'opt.ini', 'content': OTHER_INI,
                  'expected_sha256': 'stale-sha',
                  'command_id': 'opt-stale',
                  'expected_state_version':
                      created['state_version']})
    assert err_code(stale) == 'version_conflict'


def test_command_replay_and_version_race(endpoint):
    version = call(endpoint, 'get_status')['state_version']
    first = call(endpoint, 'create_config',
                 {'name': 'replay.ini', 'content': VALID_INI,
                  'command_id': 'replay-1',
                  'expected_state_version': version})
    assert first['error'] is None
    replay = call(endpoint, 'create_config',
                  {'name': 'replay.ini', 'content': OTHER_INI,
                   'command_id': 'replay-1',
                   'expected_state_version': 999999})
    assert replay.get('replayed') is True
    assert replay['state_version'] == first['state_version']

    stale_version = call(endpoint, 'create_config',
                         {'name': 'never.ini', 'content': VALID_INI,
                          'command_id': 'stale-version',
                          'expected_state_version': 1})
    assert err_code(stale_version) == 'state_conflict'


def test_restart_requires_active_run(endpoint):
    version = call(endpoint, 'get_status')['state_version']
    payload = call(endpoint, 'restart',
                   {'command_id': 'restart-idle',
                    'expected_state_version': version})
    assert err_code(payload) == 'not_allowed_in_state'


def test_validate_config_rejects_invalid(endpoint):
    payload = call(endpoint, 'validate_config',
                   {'content': '[Broken\ngarbage'})
    assert err_code(payload) == 'validation_failed'


def test_unknown_tool_is_protocol_level(endpoint):
    # tools/call for an unregistered name is rejected by the SDK with
    # -32602; the guard passes it through, proving the surface is closed.
    body = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
            'params': {'name': 'execute_command', 'arguments': {'x': 1},
                       '_meta': envelope()}}
    request = urllib.request.Request(
        endpoint, data=json.dumps(body).encode('utf-8'), method='POST',
        headers={'Content-Type': 'application/json',
                 'Accept': 'application/json, text/event-stream',
                 'MCP-Protocol-Version': '2026-07-28',
                 'Mcp-Method': 'tools/call',
                 'Mcp-Name': 'execute_command',
                 'X-FakeNet-Controller-ID': CONTROLLER_A})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read().decode('utf-8', 'replace')
            status_code = response.status
    except urllib.error.HTTPError as error:
        raw = error.read().decode('utf-8', 'replace')
        status_code = error.code
    assert status_code == 200
    body = json.loads(raw)
    assert body['result']['isError'] is True


def test_audit_lines_written_for_domain_ops(endpoint):
    root = Path(os.environ['FAKENETNG_MCP_PROGRAMDATA'])
    audit = root / 'FakeNet-NG-MCP' / 'logs' / 'config-audit.jsonl'
    assert audit.is_file()
    lines = [json.loads(line) for line in
             audit.read_text(encoding='utf-8').splitlines() if line.strip()]
    assert lines
    for line in lines:
        assert {'timestamp', 'controller', 'command_id', 'target',
                'operation', 'before_sha256', 'after_sha256',
                'result'} <= set(line)
