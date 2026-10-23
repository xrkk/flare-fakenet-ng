"""Original HTTP/JSON-RPC contract tests for the MCP acceptance boundary."""
import json
import os
import tempfile
import sys
import threading
import unittest
from unittest import mock
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


class ReceiptAndExceptionRegressions(unittest.TestCase):
    def proof(self):
        root = Path(os.environ.get('FN_COMPAT_CHECK_DIR', ROOT / 'Logs/acceptance-http-contract'))
        root.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix='receipt-', dir=root))

    def test_three_os_boundaries_match_real_noop_and_version_conflict(self):
        from test_acceptance_mcp import (inputs_at, FaultProcessBoundary,
                                         IpcProcessBoundary, SnapshotProcessBoundary)
        from fakenet.mcp.coordination import Coordinator
        from fakenet.mcp.testdouble import LifecycleDouble
        from fakenet.mcp.errors import McpError
        controller = '11111111-2222-4333-8444-555555555555'
        for boundary_type in (FaultProcessBoundary, IpcProcessBoundary, SnapshotProcessBoundary):
            with self.subTest(boundary=boundary_type.__name__):
                base = self.proof()
                inputs = inputs_at(base)
                boundary = (boundary_type(inputs, base / 'snapshot')
                            if boundary_type is SnapshotProcessBoundary else boundary_type(inputs))
                coord = Coordinator(LifecycleDouble())
                initial = boundary.version
                expected = coord.snapshot()['state_version']
                actual = coord.submit(command_id='noop', expected_version=expected,
                    controller=controller, controller_valid=True, kind='stop', describe={},
                    execute=lambda c: {'state': 'stopped', 'changed': False})
                request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                    'params': {'name': 'stop', 'arguments': {
                        'command_id': 'noop', 'expected_state_version': initial}}}
                response = boundary.exchange('http', {'data': json.dumps(request).encode()})
                payload = json.loads(json.loads(response['body'])['result']['content'][0]['text'])
                self.assertEqual(actual['command_id'], payload['command_id'])
                self.assertEqual(actual['changed'], payload['changed'])
                self.assertEqual(actual['state_version'] - expected,
                                 payload['state_version'] - initial)
                before = boundary.version
                request['params']['arguments'].update(command_id='future', expected_state_version=before + 10)
                response = boundary.exchange('http', {'data': json.dumps(request).encode()})
                rejected = json.loads(json.loads(response['body'])['result']['content'][0]['text'])
                with self.assertRaises(McpError) as caught:
                    coord.submit(command_id='future', expected_version=coord.snapshot()['state_version'] + 10,
                        controller=controller, controller_valid=True, kind='stop', describe={},
                        execute=lambda c: self.fail('version mismatch executed production action'))
                self.assertEqual(caught.exception.to_dict()['code'], rejected['error']['code'])
                self.assertFalse(rejected['changed'])
                self.assertIsNone(rejected['command_id'])
                self.assertEqual(before, boundary.version)
                (base / 'comparison.json').write_text(json.dumps({
                    'production_noop': actual, 'fixture_noop': payload,
                    'production_conflict': caught.exception.to_dict(),
                    'fixture_conflict': rejected}, indent=2))

    def test_internal_exceptions_escape_original_context_and_depth_is_restored(self):
        real_copy = mcp.copy.deepcopy
        for exception in (KeyboardInterrupt, RuntimeError):
            with self.subTest(exception=exception.__name__):
                class Boundary(_Boundary):
                    def exchange(self, kind, value):
                        if kind != 'http':
                            return super().exchange(kind, value)
                        return _response({'result': {'content': [{'text': json.dumps({
                            'state': 'stopped', 'state_version': 2, 'changed': False,
                            'error': None, 'command_id': 'noop'})}]}})
                session = mcp.BoundarySession(Boundary())
                def observe(value):
                    if isinstance(value, dict) and value.get('command_id') == 'noop' and 'state' in value:
                        raise exception('original observation interrupted')
                    return real_copy(value)
                with self.assertRaises(exception):
                    with session.original_http_contract():
                        with mock.patch.object(mcp.copy, 'deepcopy', side_effect=observe):
                            session.urlopen(
                                urllib.request.Request('http://192.0.2.1:28788/mcp', data=json.dumps({
                                    'method': 'tools/call', 'params': {'name': 'stop', 'arguments': {
                                        'command_id': 'noop', 'expected_state_version': 1}}}).encode()))
                self.assertEqual(0, session._original_http_depth)
                self.assertTrue(session.mutation_operations[-1]['response_unknown'])
                self.assertFalse(session.owned_configs)
                self.assertFalse(session.owned_runs)


if __name__ == '__main__':
    unittest.main()
