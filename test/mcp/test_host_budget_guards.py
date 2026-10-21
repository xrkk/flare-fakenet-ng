"""Whole-action budgets and nonblocking ownership at the real host entry."""
import base64
import gzip
import hashlib
import importlib.util
import multiprocessing
import re
from pathlib import Path
import time
from types import SimpleNamespace
import urllib.request

import anyio
import httpx2 as httpx
import pytest

from fakenet.mcp import host_probe, host_stdio
from fakenet.mcp.host_state import HostStateStore, HostStateError


def test_expired_budget_does_not_start_second_guest_request(monkeypatch):
    clock = [0.0]
    calls = []
    monkeypatch.setattr(host_stdio.time, 'monotonic', lambda: clock[0])
    class Guest:
        def get_status(self, timeout):
            calls.append(('status', timeout))
            clock[0] = 2.0
            return {}
        def read_config(self, name, timeout):
            calls.append(('config', timeout))
            return {}
    facade = object.__new__(host_stdio.HostFacade)
    with pytest.raises(host_stdio.HostFacadeError) as exc:
        facade._guest_state(Guest(), 'benign.ini', 1.0)
    assert exc.value.code == 'deadline_exceeded'
    assert calls == [('status', 1.0)]


def test_velo_discovery_and_call_share_one_budget(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(host_stdio.time, 'monotonic', lambda: clock[0])
    client = host_stdio.VeloMcpClient({
        'url': 'http://127.0.0.1:9/mcp', 'tool': 'read_health',
        'allowed_tools': ['read_health'], 'arguments': {}})
    def discovery(timeout):
        assert timeout == 1.0
        clock[0] = 2.0
        return SimpleNamespace(tools=[SimpleNamespace(name='read_health')])
    monkeypatch.setattr(client, 'list_tools', discovery)
    # No actual Client/network construction is allowed after discovery expires.
    monkeypatch.setattr(host_stdio, 'Client', lambda *a, **k:
                        pytest.fail('second client started after deadline'))
    assert client.probe(timeout=1.0) == (False, {'error': 'deadline'})


def test_http_total_deadline_cancels_slow_body_without_network(monkeypatch):
    original = httpx.AsyncClient
    class SlowBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'{'
            await anyio.sleep(1)
            yield b'}'
    async def handler(request):
        return httpx.Response(200, stream=SlowBody())
    def local_client(**kwargs):
        assert kwargs['trust_env'] is False
        assert kwargs['follow_redirects'] is False
        return original(transport=httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(host_stdio.httpx, 'AsyncClient', local_client)
    client = host_stdio.FakeNetHttpClient({'url': 'http://127.0.0.1:9/mcp'})
    started = time.monotonic()
    with pytest.raises(host_stdio.HostFacadeError) as exc:
        client._post(urllib.request.Request(client.url, data=b'{}'), 0.02)
    assert exc.value.code == 'guest_transport_error'
    assert time.monotonic() - started < 0.5


def _hold_command(root, ready, release):
    store = HostStateStore(root)
    with store.lock('00000000-0000-4000-8000-000000000001'):
        ready.set()
        release.wait(5)


def test_same_command_lock_returns_busy_across_processes(tmp_path):
    ready, release = multiprocessing.Event(), multiprocessing.Event()
    child = multiprocessing.Process(target=_hold_command,
                                    args=(str(tmp_path), ready, release))
    child.start()
    try:
        assert ready.wait(2)
        started = time.monotonic()
        with pytest.raises(HostStateError, match='command_busy'):
            with HostStateStore(tmp_path).lock(
                    '00000000-0000-4000-8000-000000000001'):
                pytest.fail('duplicate command admitted')
        assert time.monotonic() - started < 0.5
    finally:
        release.set()
        child.join(5)
        assert not child.is_alive()


def test_facade_passes_remaining_budget_to_discovery(tmp_path):
    path = Path(__file__).with_name('test_host_stdio.py')
    spec = importlib.util.spec_from_file_location('budget_fixture', path)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    timeouts = []
    class Guest(fixture.FakeFakeNet):
        def list_tools(self, timeout=None):
            timeouts.append(timeout)
            return super().list_tools(timeout=timeout)
    class Windows(fixture.FakeWindows):
        def list_tools(self, timeout=None):
            timeouts.append(timeout)
            return super().list_tools(timeout=timeout)
    facade = fixture.HostFacade(
        fixture.config_for(tmp_path), provider=fixture.FakeProvider(),
        fakenet_client=Guest(), windows_client=Windows(),
        velo_client=fixture.FakeVelo())
    result = facade.verify(fixture.COMMAND_ID)
    assert result['verdict'] == 'unknown', result
    assert result['coverage']['matrix_executed'] == 30
    assert len(timeouts) == 2
    assert all(value is not None and 0 < value <= 20 for value in timeouts)


def _window_client_and_capture(monkeypatch, response='MALTRACE_JSON:{}\n\nStatus Code: 0'):
    calls = []

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def call_tool(self, name, arguments):
            calls.append((name, arguments))
            return SimpleNamespace(
                content=[SimpleNamespace(text=response)],
                is_error=False,
            )

    monkeypatch.setattr(host_stdio, 'Client', FakeClient)
    return host_stdio.WindowsMcpClient({
        'url': 'http://127.0.0.1:9/mcp', 'timeout_seconds': 5,
    }), calls


def test_windows_probe_compresses_fixed_script_and_preserves_bytes(monkeypatch):
    nonce = 'T006-boundary-nonce'
    script = host_probe.probe_script(
        nonce, host_probe.matrix_steps(49152, 49153, nonce=nonce))
    assert len(host_probe.matrix_steps(49152, 49153, nonce=nonce)) == 30
    client, calls = _window_client_and_capture(monkeypatch)
    result, raw = client.probe(script, timeout=5)
    assert result == {}
    assert raw.endswith('Status Code: 0')
    assert len(calls) == 1
    name, arguments = calls[0]
    assert name == 'PowerShell'
    command = arguments['command']
    match = re.search(r"FromBase64String\('([^']+)'\)", command)
    assert match
    assert gzip.decompress(base64.b64decode(match.group(1))).decode('utf-8') == script
    assert hashlib.sha256(script.encode('utf-8')).hexdigest() in command
    direct = len(command.encode('utf-16-le')) // 2
    encoded = len(base64.b64encode(command.encode('utf-16-le')))
    assert direct < host_stdio.WINDOWS_COMMAND_LIMIT - host_stdio.WINDOWS_COMMAND_MARGIN
    assert encoded < host_stdio.WINDOWS_COMMAND_LIMIT - host_stdio.WINDOWS_COMMAND_MARGIN


def test_windows_probe_oversize_rejects_before_client(monkeypatch):
    client, calls = _window_client_and_capture(monkeypatch)
    oversized = ''.join(hashlib.sha256(str(i).encode()).hexdigest()
                        for i in range(5000))
    monkeypatch.setattr(host_stdio, 'Client', lambda *a, **k:
                        pytest.fail('Client must not start for oversize input'))
    with pytest.raises(host_stdio.HostFacadeError) as exc:
        client.probe(oversized, timeout=5)
    assert exc.value.code == 'windows_command_too_long'
    assert calls == []


def test_windows_probe_encoding_budget_exhausted_before_client(monkeypatch):
    client, calls = _window_client_and_capture(monkeypatch)
    clock = [0.0]
    monkeypatch.setattr(host_stdio.time, 'monotonic', lambda: clock[0])
    original = host_stdio._windows_probe_command

    def slow_command(script):
        clock[0] += 6.0
        return original(script)

    monkeypatch.setattr(host_stdio, '_windows_probe_command', slow_command)
    monkeypatch.setattr(host_stdio, 'Client', lambda *a, **k:
                        pytest.fail('Client must not start after encode budget'))
    with pytest.raises(host_stdio.HostFacadeError) as exc:
        client.probe('Write-Output 1', timeout=5)
    assert exc.value.code == 'windows_timeout'
    assert calls == []


def test_windows_probe_nonzero_status_never_passes(monkeypatch):
    client, calls = _window_client_and_capture(
        monkeypatch, response='MALTRACE_JSON:{}\n\nStatus Code: 206')
    with pytest.raises(host_stdio.HostFacadeError) as exc:
        client.probe('Write-Output 1', timeout=5)
    assert exc.value.code == 'windows_probe_failed'
    assert len(calls) == 1


@pytest.mark.parametrize('prefix', ['Response: ', 'Response: \r\n', 'Response:\t'])
def test_windows_probe_parses_real_response_envelope(monkeypatch, prefix):
    raw = prefix + 'MALTRACE_JSON:{"signal":"console"}\r\n\nStatus Code: 0'
    client, calls = _window_client_and_capture(monkeypatch, response=raw)
    parsed, original = client.probe('Write-Output 1', timeout=5)
    assert parsed == {'signal': 'console'}
    assert original == raw
    assert len(calls) == 1


@pytest.mark.parametrize('payload', [
    'MALTRACE_JSON:{}\r\nMALTRACE_JSON:{}',
    'embedded MALTRACE_JSON:{}',
])
def test_windows_probe_rejects_ambiguous_or_embedded_markers(monkeypatch, payload):
    raw = 'Response: ' + payload + '\r\n\nStatus Code: 0'
    client, calls = _window_client_and_capture(monkeypatch, response=raw)
    with pytest.raises(host_stdio.HostFacadeError) as exc:
        client.probe('Write-Output 1', timeout=5)
    assert exc.value.code == 'windows_probe_failed'
    assert len(calls) == 1


def test_final_probe_uses_available_budget_above_five_seconds(tmp_path):
    """A healthy final OS inventory can need over five seconds after reboot."""
    path = Path(__file__).with_name('test_host_stdio.py')
    spec = importlib.util.spec_from_file_location('final_budget_fixture', path)
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    observed = []
    class Windows(fixture.FakeWindows):
        def probe(self, script, timeout=None):
            if self.calls == 2:
                observed.append(timeout)
            return super().probe(script, timeout=timeout)
    facade = fixture.HostFacade(fixture.config_for(tmp_path),
        provider=fixture.FakeProvider(), fakenet_client=fixture.FakeFakeNet(),
        windows_client=Windows(), velo_client=fixture.FakeVelo())
    result = facade.verify('11111111-2222-4333-8444-555555555555')
    assert result['error'] is None
    assert len(observed) == 1
    assert 5 < observed[0] <= 10
