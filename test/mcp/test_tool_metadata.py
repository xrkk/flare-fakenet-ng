# Copyright 2026 Google LLC
"""Public tool metadata: descriptions, annotations, typed output schemas.

Real SDK localhost endpoint: all 19 public tools expose a non-empty terse
description, honest read/write annotations and a concrete outputSchema
(typed fields, not an object shell); responses still carry every existing
field (extras included) and structuredContent matches the text payload.
A canonical snapshot with its SHA is written for later knowledge sync.
"""

import hashlib
import json
import os
import socket
import threading
import time
import urllib.request

import pytest

mcp = pytest.importorskip('mcp')

from fakenet.mcp import server as server_module  # noqa: E402
from fakenet.mcp.config import ServiceConfig  # noqa: E402

EXPECTED_TOOLS = {
    'ping',
    'get_status', 'get_events', 'list_configs', 'validate_config',
    'read_config', 'list_artifacts', 'get_command_status', 'wait_status',
    'get_run_overview',
    'load_config', 'start', 'stop', 'restart',
    'create_config', 'import_config', 'edit_config', 'rename_config',
    'delete_config',
}
READ_ONLY = EXPECTED_TOOLS - {
    'load_config', 'start', 'stop', 'restart', 'create_config',
    'import_config', 'edit_config', 'rename_config', 'delete_config'}
LIFECYCLE = {'start', 'stop', 'restart'}
SNAPSHOT = os.environ.get('FAKENET_T003_SNAPSHOT')  # evidence path opt-in


def _free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture(scope='module')
def endpoint(tmp_path_factory):
    programdata = tmp_path_factory.mktemp('meta-programdata')
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
        'io.modelcontextprotocol/clientInfo': {'name': 'pytest-meta',
                                               'version': '0'},
        'io.modelcontextprotocol/clientCapabilities': {},
    }


def post(endpoint_url, method, params):
    body = {'jsonrpc': '2.0', 'id': 1, 'method': method,
            'params': dict(params, _meta=envelope())}
    # The guard wants the CALLED TOOL name in Mccp-Name, not the method.
    header_name = params.get('name', method)
    request = urllib.request.Request(
        endpoint_url, data=json.dumps(body).encode('utf-8'),
        method='POST', headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': '2026-07-28',
            'Mcp-Method': method, 'Mcp-Name': header_name})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode('utf-8', 'replace'))


def tool_list(endpoint_url):
    outer = post(endpoint_url, 'tools/list', {})
    return outer['result']['tools']


def test_real_validate_read_list_configs_success_paths(endpoint):
    """The entries R01's schema mismatch hid, now over real SDK output."""
    CONTROLLER = '11111111-2222-4333-8444-555555555555'
    VALID_INI = '[FakeNet]\nDumpPackets = No\nLogConsole = No\n'

    def call(name, arguments):
        body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                'params': {'name': name, 'arguments': arguments,
                           '_meta': envelope()}}
        request = urllib.request.Request(
            endpoint, data=json.dumps(body).encode('utf-8'), method='POST',
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json, text/event-stream',
                     'MCP-Protocol-Version': '2026-07-28',
                     'Mcp-Method': 'tools/call', 'Mcp-Name': name,
                     'X-FakeNet-Controller-ID': CONTROLLER})
        with urllib.request.urlopen(request, timeout=20) as response:
            outer = json.loads(response.read().decode('utf-8', 'replace'))
        assert outer['result']['isError'] is False
        return outer['result']['structuredContent']

    version = call('get_status', {})['state_version']
    created = call('create_config', {
        'name': 'meta-cover.ini', 'content': VALID_INI,
        'command_id': 'mc-create', 'expected_state_version': version})
    assert created['error'] is None

    # validate by content and by name: real sections mapping (an object,
    # not a list), both through the typed schema.
    by_content = call('validate_config', {'content': VALID_INI})
    assert by_content['valid'] is True
    sections = by_content['sections']
    assert set(sections) == {'fakenet', 'diverter', 'listeners'}
    assert isinstance(sections['fakenet'], dict) and sections['fakenet']
    by_name = call('validate_config', {'name': 'meta-cover.ini'})
    assert by_name['valid'] is True
    assert isinstance(by_name['sections']['listeners'], dict)

    # read_config: non-empty content plus stored identity matching the
    # creation receipt.
    record = call('read_config', {'name': 'meta-cover.ini'})
    assert record['content'] == VALID_INI
    assert record['name'] == 'meta-cover.ini'
    assert record['sha256'] == created['config_result']['sha256']
    assert record['builtin'] is False

    # list_configs: non-empty listing containing the created name.
    listing = call('list_configs', {})
    assert any(entry.get('name') == 'meta-cover.ini'
               for entry in listing['configs'])

    # Invalid content stays a domain error, never a success default.
    rejected = call('validate_config', {'content': '[Broken\ngarbage'})
    assert rejected['error'] is not None
    assert rejected['valid'] is None


def test_all_nineteen_tools_have_full_metadata(endpoint):
    tools = {tool['name']: tool for tool in tool_list(endpoint)}
    assert set(tools) == EXPECTED_TOOLS
    for name, tool in tools.items():
        assert tool.get('description'), name
        assert len(tool['description']) <= 220, (name, tool['description'])
        annotations = tool.get('annotations') or {}
        assert annotations.get('readOnlyHint') is (name in READ_ONLY), name
        assert annotations.get('destructiveHint') is (name not in READ_ONLY)
        if name not in READ_ONLY:
            # process-cache dedupe is not durable idempotence
            assert annotations.get('idempotentHint') is False, name
        assert annotations.get('openWorldHint') is (name in LIFECYCLE), name
        schema = tool.get('outputSchema')
        assert isinstance(schema, dict), name
        assert schema.get('type') == 'object', name
        properties = schema.get('properties') or {}
        assert len(properties) >= 2, (name, properties)
        # Not an untyped shell: at least one concrete property type (a
        # nullable field expresses it inside anyOf).
        def has_type(value):
            if not isinstance(value, dict):
                return False
            if value.get('type'):
                return True
            return any(isinstance(item, dict) and item.get('type')
                       for item in value.get('anyOf', []))
        assert any(has_type(value) for value in properties.values()), name


def test_discovery_snapshot_canonical_bytes(endpoint):
    listing = tool_list(endpoint)
    canonical = json.dumps(
        listing, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    digest = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    assert digest
    if SNAPSHOT:
        with open(SNAPSHOT, 'w', encoding='utf-8') as handle:
            json.dump({'canonical_sha256': digest, 'tools': listing},
                      handle, ensure_ascii=False, indent=1, sort_keys=True)
    # The tool SET is identical to the pre-metadata surface.
    assert {tool['name'] for tool in listing} == EXPECTED_TOOLS


def test_structured_content_matches_text_and_keeps_fields(endpoint):
    outer = post(endpoint, 'tools/call',
                 {'name': 'get_status', 'arguments': {}})
    result = outer['result']
    assert result['isError'] is False
    structured = result.get('structuredContent')
    text = result['content'][0]['text']
    assert structured is not None
    assert json.loads(text) == structured  # same semantics, one payload
    # Pre-existing fields survive model validation untouched.
    for field in ('state', 'state_version', 'run_id', 'controller',
                  'failure_reason', 'config_identity', 'last_run_outcome',
                  'health', 'service', 'error'):
        assert field in structured, field

    outer = post(endpoint, 'tools/call',
                 {'name': 'get_events', 'arguments': {'limit': 3}})
    events = outer['result']['structuredContent']
    for field in ('events', 'epoch', 'next_cursor', 'has_more', 'gap',
                  'reset_required', 'oldest_seq', 'latest_seq', 'error'):
        assert field in events, field

    # get_command_status needs the controller header on the wire.
    body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': 'get_command_status',
                       'arguments': {'command_id': 'never-seen'},
                       '_meta': envelope()}}
    request = urllib.request.Request(
        endpoint, data=json.dumps(body).encode('utf-8'), method='POST',
        headers={'Content-Type': 'application/json',
                 'Accept': 'application/json, text/event-stream',
                 'MCP-Protocol-Version': '2026-07-28',
                 'Mcp-Method': 'tools/call',
                 'Mcp-Name': 'get_command_status',
                 'X-FakeNet-Controller-ID':
                     '11111111-2222-4333-8444-555555555555'})
    with urllib.request.urlopen(request, timeout=20) as response:
        outer = json.loads(response.read().decode('utf-8', 'replace'))
    unknown = outer['result']['structuredContent']
    assert unknown['status'] == 'unknown'
    for field in ('command_id', 'status', 'cache_scope', 'cache_epoch',
                  'persistent', 'response', 'command_error', 'error'):
        assert field in unknown, field
