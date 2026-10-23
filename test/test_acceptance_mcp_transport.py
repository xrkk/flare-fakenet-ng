"""Real stdlib HTTP construction through the recorded BoundarySession seam."""
import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import sys
import threading
import uuid
import unittest
import urllib.request
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance_mcp as mcp

PAYLOAD = b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\\"state\\": \\"stopped\\"}"}]}}'
RESPONSE = (b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
            + str(len(PAYLOAD)).encode() + b'\r\nConnection: close\r\n\r\n' + PAYLOAD)
ERROR_RESPONSE = b'HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\nConnection: close\r\n\r\nfail!'


def proof_root(name):
    configured = os.environ.get('FN_TRANSPORT_CHECK_DIR')
    base = Path(configured) if configured else ROOT / 'Logs/acceptance/mcp-transport-selftest' / uuid.uuid4().hex
    path = base / 'proofs' / name
    path.mkdir(parents=True, exist_ok=False)
    return path


class ByteSocket:
    def __init__(self, response=RESPONSE):
        self.response = response
        self.sent = []
        self.closed = False

    def sendall(self, data):
        self.sent.append(data)

    def makefile(self, mode, *args, **kwargs):
        return io.BytesIO(self.response)

    def settimeout(self, value):
        pass

    def setsockopt(self, *args):
        pass

    def close(self):
        self.closed = True


class FreshBoundary(mcp.NativeBoundary):
    """The exact fresh-opener path that exposed the original failure."""
    def exchange(self, kind, value):
        if kind == 'http':
            return raw_http(value)
        return super().exchange(kind, value)


def raw_http(value):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(value['url'], data=value['data'],
                                     headers=value['headers'], method=value['method'])
    with opener.open(request, timeout=value['timeout']) as response:
        return {'status': response.status, 'headers': dict(response.headers),
                'body': response.read(), 'http_error': False}


def make_boundary(base, cls=mcp.NativeBoundary):
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    config = base / 'channel.toml'
    config.write_text('[mcp_servers.windows]\nurl="http://192.0.2.1:28787/mcp"\n')
    return cls(ROOT, {'channel': {'mcp_config_ref': str(config), 'mcp_server': 'windows'}},
               base / 'channel')


class SourceBoundary:
    fixture = True
    def exchange(self, kind, value):
        if kind == 'http-source':
            return {'status': 200, 'headers': {}, 'body': b'ok', 'http_error': False}
        raise AssertionError('unexpected source boundary action: ' + kind)


def request_value():
    return {'url': 'http://192.0.2.1:28788/mcp', 'method': 'POST',
            'headers': {'Content-Type': 'application/json', 'Connection': 'close'},
            'data': b'{"method":"fixture-byte-input"}', 'timeout': 1}


class HTTPBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.base = proof_root('transport-' + self._testMethodName)
        self.value = request_value()

    def test_standard_and_fresh_paths_keep_real_class_contract(self):
        sockets = []
        def fake_connect(address, timeout=30, source_address=None, **kwargs):
            stream = ByteSocket()
            sockets.append(stream)
            return stream
        with mock.patch.object(mcp.socket, 'create_connection', fake_connect), \
                mock.patch.object(urllib.request, '_opener', None), \
                mock.patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*',
                                             'HTTP_PROXY': '', 'http_proxy': '',
                                             'HTTPS_PROXY': '', 'https_proxy': '',
                                             'ALL_PROXY': '', 'all_proxy': ''}):
            for cls, name in ((mcp.NativeBoundary, 'standard'), (FreshBoundary, 'fresh')):
                with self.subTest(path=name):
                    boundary = make_boundary(self.base / name, cls)
                    session = mcp.BoundarySession(boundary)
                    original_class = http.client.HTTPConnection
                    with session.activate():
                        response = session.operation('http', self.value)
                    self.assertEqual(PAYLOAD, response['body'])
                    self.assertIs(original_class, http.client.HTTPConnection)
                    self.assertEqual(['http'], [row['kind'] for row in session.records])
                    self.assertIn(b'Content-Length: 31', sockets[-1].sent[0])
                    self.assertTrue(sockets[-1].closed)

    def test_http_error_still_closes_the_last_socket(self):
        sockets = []
        def fake_connect(address, timeout=30, source_address=None, **kwargs):
            stream = ByteSocket(ERROR_RESPONSE)
            sockets.append(stream)
            return stream
        with mock.patch.object(mcp.socket, 'create_connection', fake_connect), \
                mock.patch.object(urllib.request, '_opener', None), \
                mock.patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*'}):
            boundary = make_boundary(self.base / 'error')
            session = mcp.BoundarySession(boundary)
            with session.activate():
                result = session.operation('http', self.value)
            self.assertTrue(result['http_error'])
            self.assertEqual(500, result['status'])
            self.assertTrue(sockets and sockets[0].closed)

    def test_explicit_source_is_recorded_and_replayed(self):
        source_session = mcp.BoundarySession(SourceBoundary())
        with source_session.activate():
            connection = http.client.HTTPConnection('192.0.2.1', 28788, timeout=1,
                                                        source_address=('192.0.2.2', 0))
            connection.request('POST', '/mcp', body=b'body', headers={'X-Test': '1'})
            response = connection.getresponse()
        self.assertEqual(200, response.status)
        rows = [row for row in source_session.records if row['kind'] == 'http-source']
        self.assertEqual(1, len(rows))
        self.assertEqual(['192.0.2.2', 0], rows[0]['input']['source_address'])
        replay = mcp.ReplayBoundary(source_session.records, str(self.base), str(self.base / 'replay'))
        replay_session = mcp.BoundarySession(replay)
        with replay_session.activate():
            replay_connection = http.client.HTTPConnection('192.0.2.1', 28788, timeout=1,
                                                                source_address=('192.0.2.2', 0))
            replay_connection.request('POST', '/mcp', body=b'body', headers={'X-Test': '1'})
            self.assertEqual(200, replay_connection.getresponse().status)
        replay.finish()

    def test_missing_and_invalid_controller_are_not_injected(self):
        class Echo:
            fixture = True
            def __init__(self):
                self.values = []
            def exchange(self, kind, value):
                self.values.append(value)
                body = {'result': {'content': [{'text': json.dumps(
                    {'error': {'code': 'controller_identity_missing'}})}]}}
                return {'status': 200, 'headers': {}, 'http_error': False,
                        'body': json.dumps(body).encode()}
        boundary = Echo()
        session = mcp.BoundarySession(boundary)
        requests = [
            ('create_config', {'name': 'x.ini', 'content': '[FakeNet]\nDumpPackets = No\n',
                               'command_id': 'neg-12345678-1234-4234-8234-123456789abc',
                               'expected_state_version': 1}, None),
            ('stop', {'command_id': 'neg-12345678-1234-4234-8234-123456789abc',
                      'expected_state_version': 1}, 'not-a-uuid'),
        ]
        for tool, arguments, controller in requests:
            body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                    'params': {'name': tool, 'arguments': arguments}}
            headers = {'Content-Type': 'application/json'}
            if controller is not None:
                headers['X-FakeNet-Controller-ID'] = controller
            request = urllib.request.Request('http://192.0.2.1:28788/mcp',
                                             data=json.dumps(body).encode(),
                                             headers=headers, method='POST')
            session.urlopen(request, timeout=1)
        self.assertEqual(2, len(boundary.values))
        rows = [row for row in session.records if row['kind'] == 'http']
        first = {k.lower(): v for k, v in rows[0]['input']['headers'].items()}
        second = {k.lower(): v for k, v in rows[1]['input']['headers'].items()}
        self.assertNotIn('x-fakenet-controller-id', first)
        self.assertEqual('not-a-uuid', second.get('x-fakenet-controller-id'))

    def test_http_failure_keeps_mutation_unknown_and_restores_context(self):
        sockets = []
        def fake_connect(address, timeout=30, source_address=None, **kwargs):
            stream = ByteSocket(ERROR_RESPONSE)
            sockets.append(stream)
            return stream
        before_class = http.client.HTTPConnection
        with mock.patch.object(mcp.socket, 'create_connection', fake_connect), \
                mock.patch.object(urllib.request, '_opener', None), \
                mock.patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*'}):
            session = mcp.BoundarySession(make_boundary(self.base / 'unknown-mutation'))
            body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                    'params': {'name': 'create_config', 'arguments': {
                        'name': 'owned.ini', 'content': '[FakeNet]\n',
                        'command_id': 'owned-test', 'expected_state_version': 1}}}
            request = urllib.request.Request('http://192.0.2.1:28788/mcp',
                data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'}, method='POST')
            with self.assertRaises(urllib.error.HTTPError):
                with session.activate():
                    urllib.request.urlopen(request, timeout=1)
            self.assertTrue(session.preserve_scene)
            self.assertEqual(1, len(session.mutation_operations))
            self.assertTrue(session.mutation_operations[0]['response_unknown'])
            self.assertEqual(set(), session.owned_configs)
            self.assertEqual(['http'], [row['kind'] for row in session.records])
            self.assertTrue(sockets and sockets[0].closed)
            self.assertFalse(getattr(session._local, 'inside_transport', False))
        self.assertIs(before_class, http.client.HTTPConnection)

    def test_unrecorded_connection_without_explicit_source_is_refused(self):
        session = mcp.BoundarySession(SourceBoundary())
        with session.activate():
            with self.assertRaisesRegex(ValueError, 'explicit source required'):
                http.client.HTTPConnection('192.0.2.1', 28788)
        self.assertEqual([], session.records)

    def test_two_threads_record_once_each_and_restore_activation(self):
        original = http.client.HTTPConnection
        sockets, responses, errors, states = [], [], [], []
        barrier = threading.Barrier(2)
        def fake_connect(address, timeout=30, source_address=None, **kwargs):
            stream = ByteSocket()
            sockets.append(stream)
            return stream
        with mock.patch.object(mcp.socket, 'create_connection', fake_connect), \
                mock.patch.object(urllib.request, '_opener', None), \
                mock.patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*'}):
            session = mcp.BoundarySession(make_boundary(self.base / 'threads', FreshBoundary))
            def worker():
                try:
                    states.append(getattr(session._local, 'inside_transport', False))
                    barrier.wait(timeout=3)
                    responses.append(session.operation('http', self.value))
                    states.append(getattr(session._local, 'inside_transport', False))
                except BaseException as exc:
                    errors.append(repr(exc))
            with session.activate():
                self.assertTrue(issubclass(http.client.HTTPConnection, original))
                self.assertEqual(0, http.client.HTTPConnection.debuglevel)
                workers = [threading.Thread(target=worker) for unused in range(2)]
                for thread in workers:
                    thread.start()
                for thread in workers:
                    thread.join(timeout=5)
                self.assertTrue(all(not thread.is_alive() for thread in workers))
            self.assertEqual([], errors)
            self.assertEqual([PAYLOAD, PAYLOAD], [r['body'] for r in responses])
            self.assertEqual([False] * 4, states)
            rows = [r for r in session.records if r['kind'] == 'http']
            self.assertEqual(2, len(rows))
            self.assertEqual(2, len({r['thread'] for r in rows}))
            self.assertFalse(any(r['kind'] in ('http-source', 'socket-open') for r in session.records))
            self.assertEqual(2, len(sockets))
            self.assertTrue(all(stream.closed for stream in sockets))
        self.assertIs(original, http.client.HTTPConnection)
        self.assertFalse(getattr(session._local, 'inside_transport', False))


if __name__ == '__main__':
    unittest.main()
