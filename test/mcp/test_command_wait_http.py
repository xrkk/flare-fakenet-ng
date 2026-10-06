# Copyright 2026 Google LLC
"""HTTP-surface checks for get_command_status and wait_status.

Real SDK localhost endpoint (guard + coordinator + store + test double):
both new tools are discoverable and callable, identity/error envelopes
behave, a pending wait does not block the service loop (a concurrent
get_status and a controlled mutation complete while it waits), and a
client-abandoned wait leaves the external in-flight command untouched.
"""

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

mcp = pytest.importorskip('mcp')

from fakenet.mcp import server as server_module  # noqa: E402
from fakenet.mcp.config import ServiceConfig  # noqa: E402

CONTROLLER = '11111111-2222-4333-8444-555555555555'
OTHER = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
VALID_INI = '[FakeNet]\nDumpPackets = No\nLogConsole = No\n'


def _free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture(scope='module')
def endpoint(tmp_path_factory):
    programdata = tmp_path_factory.mktemp('cmdwait-programdata')
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
        'io.modelcontextprotocol/clientInfo': {'name': 'pytest-cmdwait',
                                               'version': '0'},
        'io.modelcontextprotocol/clientCapabilities': {},
    }


def raw_call(endpoint_url, tool, arguments=None, controller=CONTROLLER,
             timeout=20):
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
    request = urllib.request.Request(
        endpoint_url, data=json.dumps(body).encode('utf-8'),
        method='POST', headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode('utf-8', 'replace')
    outer = json.loads(raw)
    if outer.get('error'):
        return {'transport_error': outer['error']}
    return json.loads(outer['result']['content'][0]['text'])


def list_tools(endpoint_url):
    body = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list',
            'params': {'_meta': envelope()}}
    request = urllib.request.Request(
        endpoint_url, data=json.dumps(body).encode('utf-8'),
        method='POST', headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': '2026-07-28',
            'Mcp-Method': 'tools/list', 'Mcp-Name': 'tools/list'})
    with urllib.request.urlopen(request, timeout=20) as response:
        outer = json.loads(response.read().decode('utf-8', 'replace'))
    return [tool['name'] for tool in outer['result']['tools']]


def test_new_tools_discoverable_and_callable(endpoint):
    names = list_tools(endpoint)
    assert 'get_command_status' in names
    assert 'wait_status' in names
    # Callable with proper envelopes: unknown command and immediate match.
    unknown = raw_call(endpoint, 'get_command_status',
                       {'command_id': 'never-seen'})
    assert unknown['status'] == 'unknown'
    assert unknown['cache_scope'] == 'process'
    assert unknown['persistent'] is False
    matched = raw_call(endpoint, 'wait_status',
                       {'states': ['stopped'], 'timeout_seconds': 0})
    assert matched['error'] is None
    assert matched['matched'] is True and matched['timed_out'] is False
    assert matched['status']['state'] == 'stopped'


def test_command_status_identity_envelopes(endpoint):
    no_identity = raw_call(endpoint, 'get_command_status',
                           {'command_id': 'x'}, controller=None)
    assert no_identity['error']['code'] == 'controller_identity_missing'
    assert no_identity['status'] is None
    bad_id = raw_call(endpoint, 'get_command_status', {'command_id': ''})
    assert bad_id['error']['code'] == 'invalid_request'
    # A real command from CONTROLLER, then cross-controller denial.
    version = raw_call(endpoint, 'get_status')['state_version']
    created = raw_call(endpoint, 'create_config',
                       {'name': 'cmdwait.ini', 'content': VALID_INI,
                        'command_id': 'cw-create',
                        'expected_state_version': version})
    assert created['error'] is None
    status = raw_call(endpoint, 'get_command_status',
                      {'command_id': 'cw-create'})
    assert status['status'] == 'completed'
    assert status['response']['state_version'] == created['state_version']
    denied = raw_call(endpoint, 'get_command_status',
                      {'command_id': 'cw-create'}, controller=OTHER)
    assert denied['error']['code'] == 'controller_conflict'


def test_wait_status_validation_envelope(endpoint):
    payload = raw_call(endpoint, 'wait_status', {'timeout_seconds': 5})
    assert payload['error']['code'] == 'invalid_request'
    payload = raw_call(endpoint, 'wait_status',
                       {'states': ['bogus'], 'timeout_seconds': 5})
    assert payload['error']['code'] == 'invalid_request'
    payload = raw_call(endpoint, 'wait_status',
                       {'states': ['stopped'], 'timeout_seconds': 999})
    assert payload['error']['code'] == 'invalid_request'


def test_pending_wait_does_not_block_service_loop(endpoint):
    version = raw_call(endpoint, 'get_status')['state_version']
    outcome = {}

    def waiter():
        outcome['result'] = raw_call(
            endpoint, 'wait_status',
            {'after_state_version': version, 'timeout_seconds': 8})

    thread = threading.Thread(target=waiter, daemon=True)
    thread.start()
    time.sleep(0.2)
    # While the wait is pending, the service loop still answers instantly
    # and accepts a real mutation — no global lock, no blocked loop.
    started = time.monotonic()
    status = raw_call(endpoint, 'get_status')
    assert status['error'] is None
    assert time.monotonic() - started < 2
    bumped = raw_call(endpoint, 'create_config',
                      {'name': 'cmdwait-bump.ini', 'content': VALID_INI,
                       'command_id': 'cw-bump',
                       'expected_state_version':
                           status['state_version']})
    assert bumped['error'] is None
    thread.join(timeout=10)
    result = outcome['result']
    assert result['matched'] is True and result['timed_out'] is False
    assert result['status']['state_version'] == bumped['state_version']
    assert result['elapsed_seconds'] >= 0.2


def test_abandoned_wait_leaves_inflight_command_untouched(endpoint):
    # A blocked stop command (real submitted mutation) stays in flight
    # while a client's wait_status call is abandoned mid-wait: the wait
    # never cancels anyone else's command.
    version = raw_call(endpoint, 'get_status')['state_version']
    created = raw_call(endpoint, 'create_config',
                       {'name': 'cmdwait-run.ini', 'content': VALID_INI,
                        'command_id': 'cw-create-run',
                        'expected_state_version': version})
    loaded = raw_call(endpoint, 'load_config',
                      {'name': 'cmdwait-run.ini',
                       'command_id': 'cw-load-run',
                       'expected_state_version': created['state_version']})
    started = raw_call(endpoint, 'start',
                       {'command_id': 'cw-start-run',
                        'expected_state_version': loaded['state_version']})
    assert started['error'] is None
    double = server_module._active_context.runner
    release = threading.Event()
    double.stop_blocker = release.wait

    stop_outcome = {}

    def stop_worker():
        stop_outcome['response'] = raw_call(
            endpoint, 'stop', {'command_id': 'cw-stop-run',
                               'expected_state_version':
                                   raw_call(endpoint, 'get_status')[
                                       'state_version']})

    stopper = threading.Thread(target=stop_worker, daemon=True)
    stopper.start()
    time.sleep(0.2)
    in_flight = raw_call(endpoint, 'get_command_status',
                         {'command_id': 'cw-stop-run'})
    assert in_flight['status'] == 'in_progress'

    # The client abandons a wait for a condition that never becomes true.
    def abandoned_call():
        try:
            raw_call(endpoint, 'wait_status',
                     {'states': ['failed'], 'timeout_seconds': 6},
                     timeout=0.5)
        except (urllib.error.URLError, TimeoutError, OSError):
            pass  # the expected client-side abandonment

    abandoned = threading.Thread(target=abandoned_call, daemon=True)
    abandoned.start()
    abandoned.join(timeout=5)

    # The external command is still in flight and completes once released.
    still = raw_call(endpoint, 'get_command_status',
                     {'command_id': 'cw-stop-run'})
    assert still['status'] == 'in_progress'
    release.set()
    stopper.join(timeout=10)
    assert stop_outcome['response']['error'] is None
    done = raw_call(endpoint, 'get_command_status',
                    {'command_id': 'cw-stop-run'})
    assert done['status'] == 'completed'
