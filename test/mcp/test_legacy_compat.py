"""Opt-in legacy HTTP compatibility through the real assembled SDK app."""
import json

import pytest

pytest.importorskip('mcp')
from starlette.testclient import TestClient
from fakenet.mcp.config import ConfigError, ServiceConfig
from fakenet.mcp.server import build_app


def config():
    cfg = ServiceConfig('127.0.0.1', 28788, ['127.0.0.1'])
    cfg.allow_legacy_protocol = True
    return cfg


def app_client():
    return TestClient(build_app(config()), base_url='http://127.0.0.1:28788')


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv('FAKENETNG_MCP_PROGRAMDATA', str(tmp_path))


def post(client, method, params=None, headers=None):
    return client.post('/mcp', json={'jsonrpc': '2.0', 'id': 1,
                      'method': method, 'params': params or {}},
                      headers={'Accept': 'application/json, text/event-stream',
                               **(headers or {})})


@pytest.mark.parametrize('version', ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25'])
def test_legacy_initialize_and_tool_discovery(version):
    with app_client() as client:
        response = post(client, 'initialize', {
            'protocolVersion': version, 'capabilities': {},
            'clientInfo': {'name': 'compat-test', 'version': '1'}})
        assert response.status_code == 200, response.text
        assert response.json()['result']['protocolVersion'] == version
        headers = {'MCP-Protocol-Version': version}
        initialized = client.post('/mcp', json={'jsonrpc': '2.0',
            'method': 'notifications/initialized'}, headers={
            'Accept': 'application/json, text/event-stream', **headers})
        assert initialized.status_code == 202
        response = post(client, 'tools/list', headers=headers)
        assert response.status_code == 200, response.text
        assert 'get_status' in {t['name'] for t in response.json()['result']['tools']}
        for identity, expected in [(None, 'missing'), ('bad', 'invalid_format'),
                ('11111111-2222-4333-8444-555555555555', 'valid_uuid')]:
            request_headers = dict(headers)
            if identity:
                request_headers['X-FakeNet-Controller-ID'] = identity
            response = post(client, 'tools/call', {'name': 'ping', 'arguments': {}}, request_headers)
            assert response.status_code == 200, response.text
            payload = json.loads(response.json()['result']['content'][0]['text'])
            assert payload['controller_header'] == expected


def test_modern_path_remains_strict_in_compat_mode():
    headers = {'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/list'}
    meta = {'io.modelcontextprotocol/protocolVersion': '2026-07-28',
            'io.modelcontextprotocol/clientInfo': {'name': 'test', 'version': '1'},
            'io.modelcontextprotocol/clientCapabilities': {}}
    with app_client() as client:
        assert post(client, 'tools/list', {'_meta': meta}, headers).status_code == 200
        headers.pop('Mcp-Method')
        assert post(client, 'tools/list', {'_meta': meta}, headers).status_code == 400


@pytest.mark.parametrize('headers,params', [
    ({'MCP-Protocol-Version': '2025-11-25', 'Mcp-Method': 'tools/call'}, {}),
    ({'MCP-Protocol-Version': '2025-11-25'}, {'_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28'}}),
    ({'MCP-Protocol-Version': '2025-11-25'}, []),
])
def test_legacy_malformed_or_contradictory_request(headers, params):
    with app_client() as client:
        response = client.post('/mcp', json={'jsonrpc': '2.0', 'id': 1,
            'method': 'tools/list', 'params': params}, headers={
            'Accept': 'application/json, text/event-stream', **headers})
        assert response.status_code == 400


def test_missing_identity_cannot_mutate_via_legacy():
    with app_client() as client:
        response = post(client, 'tools/call', {'name': 'start', 'arguments': {
            'command_id': 'test-denied', 'expected_state_version': 1}},
            {'MCP-Protocol-Version': '2025-11-25'})
        assert response.status_code == 200, response.text
        payload = json.loads(response.json()['result']['content'][0]['text'])
        assert payload['error'] is not None


def test_controller_context_restored():
    from fakenet.mcp.transportguard import controller_header_state
    token = controller_header_state.set('outer-context')
    try:
        with app_client() as client:
            post(client, 'tools/list', headers={'MCP-Protocol-Version': '2025-11-25'})
        assert controller_header_state.get() == 'outer-context'
    finally:
        controller_header_state.reset(token)


def test_compat_does_not_allow_headerless_tool_call():
    with app_client() as client:
        assert post(client, 'tools/list').status_code == 400


def test_compat_rejects_unknown_version():
    with app_client() as client:
        assert post(client, 'tools/list', headers={'MCP-Protocol-Version': '1990-01-01'}).status_code == 400


def test_config_compat_flag_roundtrip_and_validation():
    cfg = config()
    assert ServiceConfig.from_dict(cfg.to_dict()).allow_legacy_protocol is True
    assert ServiceConfig('127.0.0.1', 28788, ['127.0.0.1']).allow_legacy_protocol is False
    for value in ('true', 1, None):
        data = cfg.to_dict()
        data['allow_legacy_protocol'] = value
        with pytest.raises(ConfigError):
            ServiceConfig.from_dict(data)
