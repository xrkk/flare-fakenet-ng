"""Whole-action budgets and nonblocking ownership at the real host entry."""
import importlib.util
import multiprocessing
from pathlib import Path
import time
from types import SimpleNamespace
import urllib.request

import anyio
import httpx2 as httpx
import pytest

from fakenet.mcp import host_stdio
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
    assert result['verdict'] == 'pass', result
    assert len(timeouts) == 2
    assert all(value is not None and 0 < value <= 20 for value in timeouts)
