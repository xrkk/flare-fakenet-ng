# Copyright 2026 Google LLC
"""Real-SDK-HTTP config receipt chain (no mirrored production mapping).

Every call goes through the guarded HTTP endpoint into the real
register_tools surface; the create→edit→rename→delete chain uses ONLY
each prior response's state_version/config_result.sha256 (zero
read_config calls — the recorded request log proves it), the stored
bytes are hashed independently from the temp ProgramData tree, and
replays plus get_command_status keep the ORIGINAL receipt after later
changes. If tools.py dropped the config_result mapping, these
assertions fail on the missing key — the mirrored-helper path is gone.
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

CONTROLLER = '11111111-2222-4333-8444-555555555555'
ASCII_INI = '[FakeNet]\nDumpPackets = No\nLogConsole = No\n'
UNICODE_INI = '[FakeNet]\n; 采集配置 中文\nDumpPackets = No\n'


def _free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture(scope='module')
def endpoint(tmp_path_factory):
    programdata = tmp_path_factory.mktemp('receipt-programdata')
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


class Rpc:
    """Records each real tool request (name + identity-bearing args)."""

    def __init__(self, endpoint_url):
        self.url = endpoint_url
        self.calls = []

    def __call__(self, tool, arguments=None, controller=CONTROLLER):
        self.calls.append({'name': tool,
                           'identity_args': {
                               key: value for key, value in
                               (arguments or {}).items()
                               if key in ('name', 'new_name', 'command_id',
                                          'expected_sha256')}})
        body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                'params': {'name': tool, 'arguments': arguments or {},
                           '_meta': {
                               'io.modelcontextprotocol/protocolVersion':
                                   '2026-07-28',
                               'io.modelcontextprotocol/clientInfo': {
                                   'name': 'pytest-receipts', 'version': '0'},
                               'io.modelcontextprotocol/clientCapabilities':
                                   {}}}}
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': '2026-07-28',
            'Mcp-Method': 'tools/call', 'Mcp-Name': tool,
        }
        if controller is not None:
            headers['X-FakeNet-Controller-ID'] = controller
        request = urllib.request.Request(
            self.url, data=json.dumps(body).encode('utf-8'),
            method='POST', headers=headers)
        with urllib.request.urlopen(request, timeout=20) as response:
            outer = json.loads(response.read().decode('utf-8', 'replace'))
        assert not outer.get('error'), outer
        result = outer['result']
        assert result['isError'] is False, (tool, result['content'])
        payload = result['structuredContent']
        # structuredContent and text carry the same semantics: the model
        # materializes absent declared fields as explicit nulls, so the
        # recursively non-null projections must match exactly.
        text_payload = json.loads(result['content'][0]['text'])

        def non_null(value):
            if isinstance(value, dict):
                return {key: non_null(item) for key, item in value.items()
                        if item is not None}
            if isinstance(value, list):
                return [non_null(item) for item in value if item is not None]
            return value

        assert non_null(payload) == non_null(text_payload)
        return payload


def stored_sha(name):
    root = os.environ['FAKENETNG_MCP_PROGRAMDATA']
    path = os.path.join(root, 'FakeNet-NG-MCP', 'configs', 'custom', name)
    return hashlib.sha256(open(path, 'rb').read()).hexdigest()


def test_real_http_receipt_chain_and_replay_identity(endpoint):
    rpc = Rpc(endpoint)

    created = rpc('create_config', {
        'name': 'receipt.ini', 'content': ASCII_INI,
        'command_id': 'rc-create', 'expected_state_version':
            rpc('get_status')['state_version']})
    assert created['error'] is None
    receipt = created['config_result']
    assert receipt['name'] == 'receipt.ini'
    assert receipt['sha256'] == stored_sha('receipt.ini')  # independent bytes
    assert receipt['builtin'] is False and receipt['deleted'] is False

    edited = rpc('edit_config', {
        'name': 'receipt.ini', 'content': UNICODE_INI,
        'expected_sha256': receipt['sha256'],
        'command_id': 'rc-edit',
        'expected_state_version': created['state_version']})
    assert edited['config_result']['sha256'] == stored_sha('receipt.ini')
    assert edited['config_result']['sha256'] != receipt['sha256']  # non-ASCII

    noop = rpc('edit_config', {
        'name': 'receipt.ini', 'content': UNICODE_INI,
        'expected_sha256': edited['config_result']['sha256'],
        'command_id': 'rc-noop',
        'expected_state_version': edited['state_version']})
    assert noop['config_result']['sha256'] == edited['config_result']['sha256']

    imported = rpc('import_config', {
        'name': 'imported.ini', 'content': ASCII_INI,
        'command_id': 'rc-import',
        'expected_state_version': noop['state_version']})
    assert imported['config_result']['sha256'] == stored_sha('imported.ini')

    loaded = rpc('load_config', {
        'name': 'imported.ini', 'command_id': 'rc-load',
        'expected_state_version': imported['state_version']})
    assert loaded['config_identity'] == {
        'name': 'imported.ini',
        'sha256': imported['config_result']['sha256'],
        'builtin': False}

    renamed = rpc('rename_config', {
        'name': 'receipt.ini', 'new_name': 'renamed.ini',
        'expected_sha256': edited['config_result']['sha256'],
        'command_id': 'rc-rename',
        'expected_state_version': loaded['state_version']})
    assert renamed['config_result']['name'] == 'renamed.ini'
    assert renamed['config_result']['sha256'] == stored_sha('renamed.ini')

    deleted = rpc('delete_config', {
        'name': 'renamed.ini',
        'expected_sha256': renamed['config_result']['sha256'],
        'command_id': 'rc-delete',
        'expected_state_version': renamed['state_version']})
    assert deleted['config_result'] == {
        'name': 'renamed.ini', 'sha256': None,
        'builtin': False, 'deleted': True}

    # Replay after everything changed: the ORIGINAL receipt stands.
    replay = rpc('create_config', {
        'name': 'receipt.ini', 'content': ASCII_INI,
        'command_id': 'rc-create', 'expected_state_version': 999999})
    assert replay['replayed'] is True
    assert replay['config_result'] == receipt
    status = rpc('get_command_status', {'command_id': 'rc-create'})
    assert status['status'] == 'completed'
    assert status['response']['config_result'] == receipt
    status['response']['config_result']['sha256'] = 'tampered'
    again = rpc('get_command_status', {'command_id': 'rc-create'})
    assert again['response']['config_result'] == receipt  # isolated copy

    # Zero reconciliation reads across the whole chain.
    names = [call['name'] for call in rpc.calls]
    assert 'read_config' not in names
    # The recorded request log is the RPC counter (identity args only —
    # config content never lands in evidence).
    assert names.count('create_config') == 2  # create + replay
    assert names.count('edit_config') == 2    # edit + no-op
    assert names.count('rename_config') == 1
    assert names.count('delete_config') == 1
    assert names.count('import_config') == 1
    assert names.count('load_config') == 1


def test_failures_never_fabricate_receipts(endpoint):
    rpc = Rpc(endpoint)
    version = rpc('get_status')['state_version']
    created = rpc('create_config', {
        'name': 'honest.ini', 'content': ASCII_INI,
        'command_id': 'hf-create', 'expected_state_version': version})
    assert created['error'] is None
    # CAS rejection: the domain error response carries no config_result.
    body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': 'edit_config', 'arguments': {
                'name': 'honest.ini', 'content': UNICODE_INI,
                'expected_sha256': 'wrong-sha',
                'command_id': 'hf-cas',
                'expected_state_version': created['state_version']},
                '_meta': {
                    'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                    'io.modelcontextprotocol/clientInfo': {'name': 'x',
                                                           'version': '0'},
                    'io.modelcontextprotocol/clientCapabilities': {}}}}
    request = urllib.request.Request(
        endpoint, data=json.dumps(body).encode('utf-8'), method='POST',
        headers={'Content-Type': 'application/json',
                 'Accept': 'application/json, text/event-stream',
                 'MCP-Protocol-Version': '2026-07-28',
                 'Mcp-Method': 'tools/call', 'Mcp-Name': 'edit_config',
                 'X-FakeNet-Controller-ID': CONTROLLER})
    with urllib.request.urlopen(request, timeout=20) as response:
        outer = json.loads(response.read().decode('utf-8', 'replace'))
    rejected = outer['result']['structuredContent']
    assert rejected['error'] is not None
    # No committed receipt is fabricated (the model materializes the
    # declared field as null; the value must be absent/null).
    assert rejected.get('config_result') is None
    # Missing identity: no receipt either.
    no_identity = rpc('create_config', {
        'name': 'x.ini', 'content': ASCII_INI, 'command_id': 'hf-noid',
        'expected_state_version': rejected['state_version']},
        controller=None)
    assert no_identity['error']['code'] == 'controller_identity_missing'
    assert no_identity.get('config_result') is None
