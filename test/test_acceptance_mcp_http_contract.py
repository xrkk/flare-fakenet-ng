"""Original HTTP/JSON-RPC contract tests for the MCP acceptance boundary."""
import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'test/mcp/acceptance'))
import acceptance_mcp as mcp


def _response(payload, status=200, http_error=False):
    return {'status': status, 'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(payload).encode('utf-8'), 'http_error': http_error}


class _Boundary:
    fixture = False

    def __init__(self, mode='normal'):
        self.mode = mode

    def exchange(self, kind, value):
        if kind == 'uuid':
            return '00000000-0000-4000-8000-000000000001'
        if kind in ('time', 'monotonic'):
            return 1.0
        if kind == 'sleep':
            return None
        if kind != 'http':
            raise AssertionError(kind)
        request = json.loads(value['data'])
        tool = request['params']['name']
        if self.mode == 'http-error':
            return _response({'error': {'code': -32001}}, status=401, http_error=True)
        if self.mode == 'outer-error':
            return _response({'jsonrpc': '2.0', 'id': 1,
                              'error': {'code': -32602, 'message': 'invalid'}})
        if self.mode == 'discover':
            return _response({'jsonrpc': '2.0', 'id': 1,
                              'result': {'serverInfo': {'name': 'fakenetng-mcp'}, 'tools': []}})
        if tool == 'stop' and self.mode == 'empty':
            return _response({'jsonrpc': '2.0', 'id': 1,
                              'result': {'content': [{'type': 'text', 'text': '{}'}]}})
        return _response({'jsonrpc': '2.0', 'id': 1,
                          'result': {'content': [{'type': 'text', 'text': json.dumps({'service': 'fakenetng-mcp'})}]}})


class OriginalHttpContractTests(unittest.TestCase):
    def _base(self, name):
        return 'http://192.0.2.1:28788'

    def test_original_http_post_discover_shape_is_not_reparsed(self):
        session = mcp.BoundarySession(_Boundary('discover'))
        body = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                'params': {'name': 'discover'}}
        with session.activate():
            with session.original_http_contract():
                status, headers, text = __import__('run_p01_acc').http_post(
                    self._base('p01'), body, {})
        self.assertEqual(200, status)
        self.assertEqual('fakenetng-mcp', json.loads(text)['result']['serverInfo']['name'])

    def test_original_call_outer_error_is_returned_to_original_parser(self):
        session = mcp.BoundarySession(_Boundary('outer-error'))
        with session.activate():
            with session.original_http_contract():
                value = __import__('run_p02_acc').call(self._base('p02'), 'ping')
        self.assertEqual(-32602, value['transport_error']['code'])

    def test_empty_mutation_reaches_original_receipt_check_and_stays_unknown(self):
        session = mcp.BoundarySession(_Boundary('empty'))
        with session.activate():
            with session.original_http_contract():
                value = __import__('run_p02_acc').call(
                    self._base('p02'), 'stop', {'command_id': 'empty-1',
                                                'expected_state_version': 0})
        self.assertEqual({}, value)
        operation = session.mutation_operations[-1]
        self.assertTrue(operation['response_unknown'])
        self.assertNotIn('accepted', operation)
        self.assertEqual(set(), session.owned_runs)
        self.assertTrue(session.preserve_scene)

    def test_default_is_strict_and_context_exit_restores_it(self):
        session = mcp.BoundarySession(_Boundary('discover'))
        request = urllib.request.Request(
            self._base('default') + '/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                             'params': {'name': 'discover', 'arguments': {}}}).encode(),
            headers={'Content-Type': 'application/json'}, method='POST')
        with self.assertRaisesRegex(ValueError, 'MCP operation'):
            session.urlopen(request)
        with session.original_http_contract():
            response = session.urlopen(request)
            self.assertEqual(200, response.status)
        with self.assertRaisesRegex(ValueError, 'MCP operation'):
            session.urlopen(request)

    def test_http_error_preserves_status_headers_and_body(self):
        session = mcp.BoundarySession(_Boundary('http-error'))
        with session.activate():
            with session.original_http_contract():
                status, headers, text = __import__('run_p01_acc').http_post(
                    self._base('p01'), {'jsonrpc': '2.0', 'id': 1,
                                        'method': 'initialize',
                                        'params': {'name': 'discover'}}, {})
        self.assertEqual(401, status)
        self.assertEqual('application/json', headers['Content-Type'])
        self.assertEqual(-32001, json.loads(text)['error']['code'])

    def test_context_applies_to_original_worker_thread_and_is_not_leaked(self):
        session = mcp.BoundarySession(_Boundary('outer-error'))
        result = []

        def worker():
            with session.activate():
                result.append(__import__('run_p02_acc').call(
                    self._base('p02'), 'ping'))

        with session.original_http_contract():
            thread = threading.Thread(target=worker)
            thread.start()
            thread.join()
        self.assertEqual(-32602, result[0]['transport_error']['code'])

        def strict_after_context():
            request = urllib.request.Request(
                self._base('after') + '/mcp',
                data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                 'params': {'name': 'discover', 'arguments': {}}}).encode(),
                headers={'Content-Type': 'application/json'}, method='POST')
            with self.assertRaisesRegex(ValueError, 'MCP operation'):
                session.urlopen(request)
        strict_after_context()


if __name__ == '__main__':
    unittest.main()
