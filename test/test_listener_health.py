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
