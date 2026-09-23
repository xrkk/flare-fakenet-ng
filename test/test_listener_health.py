"""All listener owners report actual descriptors and required thread liveness."""
import importlib
import socket
import threading
from types import SimpleNamespace

import pytest

from fakenet.mcp.managed import probe_instance

NAMES = ['DNSListener', 'FTPListener', 'HTTPListener', 'IRCListener', 'POPListener',
         'ProxyListener', 'RawListener', 'SMTPListener', 'TFTPListener', 'DomainEgressRelay']


@pytest.mark.parametrize('name', NAMES)
def test_provider_resource_combinations(name):
    cls = getattr(importlib.import_module('fakenet.listeners.' + name), name)
    provider = cls(dict(ipaddr='127.0.0.1', port=0, protocol='UDP', usessl='No'))
    assert provider.health_snapshot()['alive'] is False
    # Use live OS resources at each class's own documented ownership slots.
    # No copied parser, fake fileno, or inferred health inside managed.
    release = threading.Event()
    thread = threading.Thread(target=release.wait)
    descriptor = socket.socket()
    thread.start()
    try:
        if name == 'DomainEgressRelay':
            provider._listener, provider._accept_thread = descriptor, thread
            thread_field = '_accept_thread'
        else:
            provider.server = SimpleNamespace(socket=descriptor)
            provider.server_thread = thread
            thread_field = 'server_thread'
        report = provider.health_snapshot()
        assert report == {'handles': [descriptor.fileno()], 'alive': True}
        setattr(provider, thread_field, None)
        assert provider.health_snapshot()['alive'] is False
        setattr(provider, thread_field, thread)
        release.set()
        thread.join(1)
        assert not thread.is_alive() and descriptor.fileno() >= 0
        assert provider.health_snapshot()['alive'] is False
        descriptor.close()
        assert provider.health_snapshot()['alive'] is False
    finally:
        release.set()
        thread.join(1)
        descriptor.close()


@pytest.mark.parametrize('name', NAMES)
def test_provider_actual_start_stop(name, tmp_path):
    cls = getattr(importlib.import_module('fakenet.listeners.' + name), name)
    provider = cls(dict(ipaddr='127.0.0.1', port=0, protocol='UDP', usessl='No',
                        ftproot=str(tmp_path), webroot=str(tmp_path), tftproot=str(tmp_path)))
    if name == 'DomainEgressRelay':
        provider.callbacks = SimpleNamespace(egressPolicyEnabled=lambda: True,
            getEgressSettings=lambda: dict(relay_port=0, max_pending=4))
    try:
        provider.start()
        assert provider.health_snapshot()['alive'] is True, provider.health_snapshot()
    finally:
        provider.stop()
    assert provider.health_snapshot()['alive'] is False


@pytest.mark.parametrize('provider', [SimpleNamespace(),
    SimpleNamespace(health_snapshot=lambda: (_ for _ in ()).throw(OSError('query failed')))])
def test_unknown_provider_never_uses_legacy_layout(provider):
    provider.server = SimpleNamespace(socket=SimpleNamespace(fileno=lambda: 7))
    provider.server_thread = threading.current_thread()
    instance = SimpleNamespace(running_listener_providers=[provider],
        diverter=SimpleNamespace(handle=SimpleNamespace(is_open=True),
                                 diverter_thread=threading.current_thread()))
    result = probe_instance(instance)
    assert result['probe'] is False
    assert result['listeners'][0]['alive'] is False
    assert result['listeners'][0]['error']


@pytest.mark.parametrize('name', NAMES)
@pytest.mark.parametrize('state', ['running', 'missing_thread', 'dead_thread_open_socket',
                                    'closed_socket', 'stopped'])
def test_actual_provider_resource_lifecycle(name, state, tmp_path, monkeypatch):
    """Observe the resources created by this provider's own start method."""
    cls = getattr(importlib.import_module('fakenet.listeners.' + name), name)
    provider = cls(dict(ipaddr='127.0.0.1', port=0, protocol='UDP', usessl='No',
                        ftproot=str(tmp_path), webroot=str(tmp_path), tftproot=str(tmp_path)))
    if name == 'DomainEgressRelay':
        provider.callbacks = SimpleNamespace(egressPolicyEnabled=lambda: True,
            getEgressSettings=lambda: dict(relay_port=0, max_pending=4))
    ftp_fault = None
    if name == 'FTPListener' and state == 'dead_thread_open_socket':
        from pyftpdlib.ioloop import IOLoop
        ftp_fault = threading.Event()
        original_poll = IOLoop.poll
        def bounded_poll(loop, timeout):
            if ftp_fault.is_set():
                raise OSError('injected FTP poll boundary failure')
            return original_poll(loop, timeout)
        # Install before serve_forever captures its poll method locally.
        monkeypatch.setattr(IOLoop, 'poll', bounded_poll)
    provider.start()
    thread = (provider._accept_thread if name == 'DomainEgressRelay'
              else provider.server_thread)
    sock = (provider._listener if name == 'DomainEgressRelay'
            else provider.server.socket)
    try:
        assert thread.is_alive() and sock.fileno() >= 0
        assert provider.health_snapshot() == {'handles': [sock.fileno()], 'alive': True}
        if state == 'missing_thread':
            field = '_accept_thread' if name == 'DomainEgressRelay' else 'server_thread'
            setattr(provider, field, None)
            try:
                assert provider.health_snapshot()['alive'] is False
            finally:
                setattr(provider, field, thread)
        elif state == 'dead_thread_open_socket':
            if name == 'DomainEgressRelay':
                provider._stop.set()
            elif name == 'FTPListener':
                ftp_fault.set()
                # The bounded native poll returns within one second; its
                # next iteration faults without closing the accept socket.
            else:
                provider.server.shutdown()
            thread.join(3)
            assert not thread.is_alive() and sock.fileno() >= 0
            assert provider.health_snapshot()['alive'] is False
        elif state == 'closed_socket':
            sock.close()
            assert sock.fileno() < 0
            assert provider.health_snapshot()['alive'] is False
        elif state == 'stopped':
            provider.stop()
            assert provider.health_snapshot()['alive'] is False
    finally:
        if name == 'FTPListener' and state == 'dead_thread_open_socket':
            monkeypatch.undo()
        provider.stop()
        thread.join(3)
        assert not thread.is_alive(), '%s leaked service thread' % name
