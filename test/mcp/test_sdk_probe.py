# Copyright 2026 Google LLC
"""End-to-end MCP protocol probe against the assembled service (P01 IMP-P01-02/04).

Skipped when the ``mcp`` SDK is not importable in the running interpreter
(e.g. the plain host Python); it always runs inside the pinned builder image
where the wheelhouse set is installed, and in any environment provisioned
for the acceptance runner.
"""

import json
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


def _free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture(scope='module')
def endpoint():
    port = _free_port()
    config = ServiceConfig(listen_ip='127.0.0.1', listen_port=port,
                           allowed_host_ips=['127.0.0.1'])
    ready = threading.Event()
    failure = {}

    def serve():
        try:
            server_module.run_server(config, ready_event=ready)
        except BaseException as exc:  # pragma: no cover - diagnostic only
            import traceback

            failure['error'] = traceback.format_exc()
            failure['repr'] = repr(exc)
            ready.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(timeout=30), failure
    time.sleep(0.5)
    assert not failure, failure
    yield 'http://127.0.0.1:%d/mcp' % port
    server_module.request_shutdown()


def _post(url, body, headers):
    request = urllib.request.Request(
        url, data=json.dumps(body).encode('utf-8'), method='POST',
        headers={'Content-Type': 'application/json',
                 'Accept': 'application/json, text/event-stream',
                 **headers})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode('utf-8', 'replace')


def _envelope(version='2026-07-28'):
    return {
        'io.modelcontextprotocol/protocolVersion': version,
        'io.modelcontextprotocol/clientInfo': {'name': 'pytest',
                                               'version': '0'},
        'io.modelcontextprotocol/clientCapabilities': {},
    }


def _tools_call(meta=None):
    return {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': 'ping', 'arguments': {},
                       '_meta': meta or _envelope()}}


FULL_HEADERS = {
    'MCP-Protocol-Version': '2026-07-28',
    'Mcp-Method': 'tools/call',
    'Mcp-Name': 'ping',
}


def test_ping_with_controller_header(endpoint):
    status, text = _post(endpoint, _tools_call(),
                         {**FULL_HEADERS,
                          'X-FakeNet-Controller-ID': CONTROLLER})
    assert status == 200
    payload = json.loads(text)
    result = json.loads(payload['result']['content'][0]['text'])
    assert result['service'] == 'fakenetng-mcp'
    assert result['protocol'] == '2026-07-28'
    assert result['controller_header'] == 'valid_uuid'


def test_ping_without_controller_header_still_read_only(endpoint):
    status, text = _post(endpoint, _tools_call(), dict(FULL_HEADERS))
    assert status == 200
    result = json.loads(json.loads(text)['result']['content'][0]['text'])
    assert result['controller_header'] == 'missing'


def test_invalid_controller_header_reported_not_blocked(endpoint):
    status, text = _post(endpoint, _tools_call(),
                         {**FULL_HEADERS,
                          'X-FakeNet-Controller-ID': 'bogus'})
    assert status == 200
    result = json.loads(json.loads(text)['result']['content'][0]['text'])
    assert result['controller_header'] == 'invalid_format'


def test_missing_version_header_rejected(endpoint):
    headers = {key: value for key, value in FULL_HEADERS.items()
               if key != 'MCP-Protocol-Version'}
    status, text = _post(endpoint, _tools_call(), headers)
    assert status == 400
    assert json.loads(text)['error']['code'] == -32020


def test_unknown_version_lists_supported(endpoint):
    status, text = _post(endpoint, _tools_call(_envelope('1990-01-01')),
                         {**FULL_HEADERS,
                          'MCP-Protocol-Version': '1990-01-01'})
    assert status == 400
    error = json.loads(text)['error']
    assert error['code'] == -32022
    assert error['data']['supported'] == ['2026-07-28']


def test_get_not_allowed(endpoint):
    try:
        with urllib.request.urlopen(endpoint, timeout=10) as response:
            status = response.status
    except urllib.error.HTTPError as error:
        status = error.code
    assert status == 405


def test_legacy_initialize_rejected(endpoint):
    body = {'jsonrpc': '2.0', 'id': 9, 'method': 'initialize',
            'params': {'protocolVersion': '2025-06-18', 'capabilities': {},
                       'clientInfo': {'name': 'legacy', 'version': '0'}}}
    # A modern-shaped request line (all required headers present) whose
    # method is the legacy handshake: the guard must refuse the legacy era
    # and name the supported versions.
    status, text = _post(endpoint, body,
                         {'MCP-Protocol-Version': '2026-07-28',
                          'Mcp-Method': 'initialize'})
    assert status == 400
    error = json.loads(text)['error']
    assert error['code'] == -32022
    assert error['data']['supported'] == ['2026-07-28']


def test_legacy_initialize_without_version_header_is_header_error(endpoint):
    body = {'jsonrpc': '2.0', 'id': 10, 'method': 'initialize',
            'params': {'protocolVersion': '2025-06-18', 'capabilities': {},
                       'clientInfo': {'name': 'legacy', 'version': '0'}}}
    status, text = _post(endpoint, body, {'Mcp-Method': 'initialize'})
    assert status == 400
    assert json.loads(text)['error']['code'] == -32020


def test_header_body_version_mismatch_rejected(endpoint):
    status, text = _post(endpoint, _tools_call(_envelope('1990-01-01')),
                         dict(FULL_HEADERS))
    assert status == 400
    assert json.loads(text)['error']['code'] == -32020


def test_method_header_mismatch_rejected(endpoint):
    status, text = _post(endpoint, _tools_call(),
                         {**FULL_HEADERS, 'Mcp-Method': 'tools/list'})
    assert status == 400
    assert json.loads(text)['error']['code'] == -32020


def test_server_discover(endpoint):
    body = {'jsonrpc': '2.0', 'id': 3, 'method': 'server/discover',
            'params': {'_meta': _envelope()}}
    status, text = _post(endpoint, body,
                         {'MCP-Protocol-Version': '2026-07-28',
                          'Mcp-Method': 'server/discover'})
    assert status == 200
    assert json.loads(text)['result']['supportedVersions'] == ['2026-07-28']


def test_tools_list_frozen_surface(endpoint):
    body = {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/list',
            'params': {'_meta': _envelope()}}
    status, text = _post(endpoint, body,
                         {'MCP-Protocol-Version': '2026-07-28',
                          'Mcp-Method': 'tools/list'})
    assert status == 200
    names = sorted(tool['name']
                   for tool in json.loads(text)['result']['tools'])
    # P01 probe surface plus the P02 domain tools (sub-plan P02 §3).
    assert names == sorted([
        'ping', 'get_status', 'get_events', 'list_configs',
        'validate_config', 'read_config', 'list_artifacts', 'load_config',
        'start', 'stop', 'restart', 'create_config', 'import_config',
        'edit_config', 'rename_config', 'delete_config',
    ])
