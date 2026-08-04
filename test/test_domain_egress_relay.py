import socket
import types
import unittest
from unittest import mock

from fakenet.listeners import DomainEgressRelay as relay_module
from fakenet.listeners.DomainEgressRelay import (
    ClientHelloError, DomainEgressRelay)


def extension(ext_type, payload):
    return (ext_type.to_bytes(2, 'big') +
            len(payload).to_bytes(2, 'big') + payload)


def client_hello(host='api.deepseek.com', trailing=b''):
    encoded = host.encode('ascii')
    server_name = (len(encoded) + 3).to_bytes(2, 'big') + b'\x00' + \
        len(encoded).to_bytes(2, 'big') + encoded
    extensions = extension(0, server_name)
    body = (b'\x03\x03' + b'R' * 32 + b'\x00' + b'\x00\x02' +
            b'\x13\x01' + b'\x01\x00' +
            len(extensions).to_bytes(2, 'big') + extensions)
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    record = b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake
    return record + trailing


class ChunkSocket(object):
    def __init__(self, chunks=None, events=None, name='client'):
        self.chunks = list(chunks or [])
        self.events = events if events is not None else []
        self.name = name
        self.timeouts = []
        self.connected = []
        self.bound = []
        self.closed = False

    def recv(self, count):
        return self.chunks.pop(0) if self.chunks else b''

    def settimeout(self, value):
        self.timeouts.append(value)

    def setblocking(self, value):
        return None

    def bind(self, address):
        self.bound.append(address)

    def getsockname(self):
        return ('10.0.0.5', 57000)

    def connect(self, address):
        self.events.append(('connect', address))
        self.connected.append(address)

    def close(self):
        self.events.append(('close', self.name))
        self.closed = True


def settings():
    return {
        'hello_timeout': 5,
        'hello_max_bytes': 65536,
        'max_pending': 256,
        'max_pending_per_source': 32,
        'max_active': 128,
        'max_active_per_source': 16,
        'idle_timeout': 300,
        'buffer_bytes': 1048576,
    }


class DomainEgressRelayTests(unittest.TestCase):
    def setUp(self):
        self.relay = DomainEgressRelay({'port': 38927})
        self.relay._settings = settings()

    def test_fragmented_client_hello_preserves_trailing_record(self):
        trailing = b'\x17\x03\x03\x00\x01X'
        payload = client_hello(trailing=trailing)
        client = ChunkSocket([payload[:8], payload[8:31], payload[31:]])

        buffered, sni = self.relay._read_client_hello(client)

        self.assertEqual(payload, buffered)
        self.assertTrue(buffered.endswith(trailing))
        self.assertEqual('api.deepseek.com', sni)

    def test_client_hello_size_and_timeout_fail_closed(self):
        self.relay._settings['hello_max_bytes'] = 8
        with self.assertRaisesRegex(ClientHelloError, 'size limit'):
            self.relay._read_client_hello(
                ChunkSocket([client_hello()[:8]]))

        self.relay._settings['hello_max_bytes'] = 65536
        timed_client = ChunkSocket([client_hello()])
        with mock.patch.object(relay_module.time, 'monotonic',
                               side_effect=[100.0, 106.0]):
            with self.assertRaisesRegex(ClientHelloError, 'timeout'):
                self.relay._read_client_hello(timed_client)
        self.assertEqual([], timed_client.timeouts)

    def test_pending_and_rate_limits_fail_closed(self):
        self.relay._settings['max_pending'] = 2
        self.relay._settings['max_pending_per_source'] = 1
        self.assertTrue(self.relay._acquire_pending('10.0.0.5'))
        self.assertFalse(self.relay._acquire_pending('10.0.0.5'))
        self.assertTrue(self.relay._acquire_pending('10.0.0.6'))
        self.assertFalse(self.relay._acquire_pending('10.0.0.7'))
        self.relay._release_pending('10.0.0.5')
        self.assertTrue(self.relay._acquire_pending('10.0.0.7'))

        with mock.patch.object(relay_module.time, 'monotonic',
                               return_value=100.0):
            for unused in range(64):
                self.assertTrue(self.relay._allow_new_flow_rate(
                    '10.0.0.8'))
            self.assertFalse(self.relay._allow_new_flow_rate('10.0.0.8'))

    def test_control_permit_is_registered_before_upstream_connect(self):
        events = []
        client = ChunkSocket(events=events, name='client')
        upstream = ChunkSocket(events=events, name='upstream')
        mapping = types.SimpleNamespace(
            generation=7, domain='api.deepseek.com',
            server_ip='93.184.216.34', server_port=443)
        callbacks = mock.Mock()
        callbacks.selectSourceIPv4.return_value = '10.0.0.5'
        callbacks.registerControlFlow.side_effect = lambda *args, **kwargs: (
            events.append(('register', args, kwargs)) or 'token')
        callbacks.activateRelayMapping.side_effect = lambda generation: (
            events.append(('activate', generation)) or True)
        callbacks.revokeControlFlow.side_effect = lambda token: events.append(
            ('revoke', token))
        callbacks.closeRelayMapping.side_effect = lambda generation: (
            events.append(('close_mapping', generation)))
        self.relay.callbacks = callbacks
        self.relay._promote_active = mock.Mock(return_value=True)
        self.relay._release_active = mock.Mock()
        self.relay._read_client_hello = mock.Mock(
            return_value=(b'hello-and-trailing-record', 'api.deepseek.com'))
        self.relay._relay = mock.Mock(
            side_effect=lambda client_sock, upstream_sock, initial: events.append(
                ('relay', initial)))

        with mock.patch.object(relay_module.socket, 'socket',
                               return_value=upstream):
            self.relay._handle_client(client, ('10.0.0.5', 50000),
                                      mapping)

        names = [entry[0] for entry in events]
        self.assertLess(names.index('register'), names.index('connect'))
        self.assertLess(names.index('connect'), names.index('activate'))
        self.assertIn(('relay', b'hello-and-trailing-record'), events)
        self.assertIn(('revoke', 'token'), events)
        self.assertIn(('close_mapping', 7), events)
        callbacks.registerControlFlow.assert_called_once_with(
            'tls_relay', 'TCP', '10.0.0.5', 57000,
            '93.184.216.34', 443, domain='api.deepseek.com',
            ttl=330, generation=7)

    def test_control_registration_failure_never_connects(self):
        client = ChunkSocket(name='client')
        upstream = ChunkSocket(name='upstream')
        mapping = types.SimpleNamespace(
            generation=8, domain='api.deepseek.com',
            server_ip='93.184.216.34', server_port=443)
        callbacks = mock.Mock()
        callbacks.selectSourceIPv4.return_value = '10.0.0.5'
        callbacks.registerControlFlow.side_effect = RuntimeError('denied')
        self.relay.callbacks = callbacks
        self.relay._promote_active = mock.Mock(return_value=True)
        self.relay._release_active = mock.Mock()
        self.relay._read_client_hello = mock.Mock(
            return_value=(b'hello', 'api.deepseek.com'))

        with mock.patch.object(relay_module.socket, 'socket',
                               return_value=upstream):
            self.relay._handle_client(client, ('10.0.0.5', 50001),
                                      mapping)

        self.assertEqual([], upstream.connected)
        callbacks.activateRelayMapping.assert_not_called()
        callbacks.revokeControlFlow.assert_not_called()
        callbacks.closeRelayMapping.assert_called_once_with(8)
        callbacks.logEgressEvent.assert_called_once()

    def test_shutdown_socket_close_is_not_reported_as_sni_denial(self):
        client = ChunkSocket(name='client')
        mapping = types.SimpleNamespace(
            generation=9, domain='api.deepseek.com',
            server_ip='93.184.216.34', server_port=443)
        callbacks = mock.Mock()
        self.relay.callbacks = callbacks
        self.relay._stop.set()

        self.relay._handle_client(client, ('10.0.0.5', 50002), mapping)

        callbacks.logEgressEvent.assert_not_called()
        callbacks.closeRelayMapping.assert_called_once_with(9)
        self.assertTrue(client.closed)


if __name__ == '__main__':
    unittest.main()
