"""Real stdlib HTTP construction through the recorded BoundarySession seam."""
import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import sys
import tempfile
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
    base = Path(os.environ.get('FN_TRANSPORT_CHECK_DIR', tempfile.mkdtemp(prefix='mcp-http-')))
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
                mock.patch.object(urllib.request, '_opener', None):
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
            connection = source_session.http_connection('192.0.2.1', 28788, timeout=1,
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
            replay_connection = replay_session.http_connection('192.0.2.1', 28788, timeout=1,
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

    def test_thread_local_and_activation_restore(self):
        original = http.client.HTTPConnection
        session = mcp.BoundarySession(SourceBoundary())
        with session.activate():
            self.assertNotEqual(original, http.client.HTTPConnection)
            self.assertTrue(issubclass(http.client.HTTPConnection, original))
            self.assertEqual(0, http.client.HTTPConnection.debuglevel)
            self.assertIsInstance(http.client.HTTPConnection._get_content_length, object)
        self.assertIs(original, http.client.HTTPConnection)
        self.assertFalse(getattr(session._local, 'inside_transport', False))


if __name__ == '__main__':
    unittest.main()
