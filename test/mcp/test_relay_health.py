"""Managed health must observe the actual relay socket and accept thread."""
import threading
from types import SimpleNamespace

import pytest

from fakenet.listeners.DomainEgressRelay import DomainEgressRelay
from fakenet.mcp.managed import probe_instance


@pytest.fixture
def relay_instance():
    relay = DomainEgressRelay({'port': 0})
    relay.callbacks = SimpleNamespace(
        egressPolicyEnabled=lambda: True,
        getEgressSettings=lambda: {'relay_port': 0, 'max_pending': 4})
    instance = SimpleNamespace(
        diverter=SimpleNamespace(handle=SimpleNamespace(is_open=True),
                                 diverter_thread=threading.current_thread()),
        running_listener_providers=[relay])
    try:
        yield relay, instance
    finally:
        relay.stop()


def test_real_relay_start_and_stop_health(relay_instance):
    relay, instance = relay_instance
    assert not probe_instance(instance)['probe']
    relay.start()
    result = probe_instance(instance)
    assert result['probe']
    assert result['listeners'][0]['handles'] == [relay._listener.fileno()]
    assert result['listeners'][0]['alive']
    relay.stop()
    assert not probe_instance(instance)['probe']


def test_accept_thread_exit_revokes_health_with_socket_still_open(relay_instance):
    relay, instance = relay_instance
    relay.start()
    assert probe_instance(instance)['probe']
    relay._stop.set()
    relay._accept_thread.join(2)
    assert not relay._accept_thread.is_alive()
    assert relay._listener.fileno() >= 0
    assert not probe_instance(instance)['probe']


def test_missing_accept_thread_does_not_count_as_healthy(relay_instance):
    relay, instance = relay_instance
    relay.start()
    relay._stop.set()
    relay._accept_thread.join(2)
    relay._accept_thread = None
    assert relay._listener.fileno() >= 0
    assert not probe_instance(instance)['probe']
