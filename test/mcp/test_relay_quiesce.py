"""Relay quiesce must abortively close client flows while the rewrite lives.

The fail-safe reused by the failed-stop path: SO_LINGER(1,0) close of every
live client/upstream socket (kernel RST, translated by the retained mapping
rewrite), reject-mode accept loop for new SYNs, and no TLS_SNI_DENY pollution
for sockets the quiesce itself aborted.
"""
import socket
import struct
import threading
from types import SimpleNamespace

import pytest

from fakenet.listeners.DomainEgressRelay import DomainEgressRelay, _LINGER_ABORT


class _FakeSocket:
    def __init__(self, name):
        self.name = name
        self.setsockopt_calls = []
        self.closed = False

    def setsockopt(self, level, option, value):
        self.setsockopt_calls.append((level, option, bytes(value)))

    def close(self):
        self.closed = True

    def shutdown(self, how):
        pass


class _FakeCallbacks:
    def __init__(self):
        self.events = []
        self.closed_generations = []

    def isLocalAddress(self, source):
        return True

    def logEgressEvent(self, name, **fields):
        self.events.append((name, fields))

    def consumeRelayTarget(self, source, sport):
        return SimpleNamespace(generation=7, server_ip='198.51.100.77',
                               server_port=1337)

    def closeRelayMapping(self, generation):
        self.closed_generations.append(generation)


def _relay_with(port=0):
    relay = DomainEgressRelay({'port': port})
    relay.callbacks = _FakeCallbacks()
    return relay


def test_quiesce_aborts_every_live_connection_with_linger_zero():
    relay = _relay_with()
    sockets = [_FakeSocket('client-a'), _FakeSocket('upstream-a'),
               _FakeSocket('client-b')]
    relay._connections = set(sockets)
    relay.quiesce('managed_stop_failed')
    for sock in sockets:
        assert sock.closed
        assert (socket.SOL_SOCKET, socket.SO_LINGER, _LINGER_ABORT) in \
            sock.setsockopt_calls
    name, fields = relay.callbacks.events[-1]
    assert name == 'RELAY_QUIESCE'
    assert fields['reason'] == 'managed_stop_failed'
    assert fields['aborted_connections'] == 3


def test_quiesce_is_idempotent_and_reports_zero():
    relay = _relay_with()
    relay.quiesce('managed_stop_failed')
    relay.quiesce('managed_stop_failed')
    assert relay.callbacks.events[-1][1]['aborted_connections'] == 0


def test_quiesced_accept_aborts_new_client_and_retires_mapping():
    relay = _relay_with()
    client = _FakeSocket('late-client')
    state = {'accepts': 0}

    def accept():
        state['accepts'] += 1
        if state['accepts'] == 1:
            return (client, ('192.168.204.233', 50271))
        relay._stop.set()
        raise OSError('listener closed')

    relay._listener = SimpleNamespace(accept=accept, close=lambda: None)
    relay.quiesce('managed_stop_failed')
    relay._accept_loop()
    assert state['accepts'] == 2
    assert client.closed
    assert (socket.SOL_SOCKET, socket.SO_LINGER, _LINGER_ABORT) in \
        client.setsockopt_calls
    assert relay.callbacks.closed_generations == [7]
    quiesce_rst = [event for event in relay.callbacks.events
                   if event[0] == 'RELAY_QUIESCE_RST']
    assert len(quiesce_rst) == 1
    fields = quiesce_rst[0][1]
    assert fields['reason_code'] == 'relay_quiesced'
    assert fields['sport'] == 50271
    assert fields['original_ip'] == '198.51.100.77'
    assert fields['original_port'] == 1337
    assert not [event for event in relay.callbacks.events
                if event[0] == 'TLS_SNI_DENY']


def test_worker_socket_error_during_quiesce_is_not_a_sni_deny():
    relay = _relay_with()
    relay._quiesce.set()
    relay._settings = {'hello_timeout': 0.01, 'idle_timeout': 30}
    client = _FakeSocket('client')
    client.settimeout = lambda value: None
    relay.callbacks.consumeRelayTarget = lambda source, sport: None
    relay.callbacks.closeRelayMapping = lambda generation: None

    def _read_client_hello(sock):
        raise OSError('connection aborted by quiesce')

    relay._read_client_hello = _read_client_hello
    mapping = SimpleNamespace(generation=9, domain='api.deepseek.com',
                              server_ip='119.188.220.215', server_port=443)
    worker = threading.Thread(target=relay._handle_client,
                              args=(client, ('192.168.204.233', 50254), mapping),
                              daemon=True)
    worker.start()
    worker.join(5)
    assert not worker.is_alive()
    assert client.closed
    assert not [event for event in relay.callbacks.events
                if event[0] == 'TLS_SNI_DENY'], \
        'quiesce-aborted sockets must not be reported as SNI denies'
