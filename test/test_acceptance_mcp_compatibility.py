"""Compatibility roots for the existing MCP offline acceptance fixtures."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance as entry
import acceptance_mcp as mcp
import acceptance_package as package
from test_acceptance_mcp import inputs_at


class CompatibilityRoots(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='mcp-compat-'))

    def test_legacy_inputs_make_a_complete_benign_package(self):
        inputs = inputs_at(self.base)
        candidate = {
            'schema': entry.CANDIDATE_V2,
            'source_commit': inputs['identity']['source_commit'],
            'package_path': inputs['package'],
            'package_manifest': inputs['manifest'],
            'package_sha256': inputs['identity']['package_sha256'],
            'offline_fixture': True,
        }
        frozen = package.freeze_candidate(candidate)
        self.assertEqual(inputs['manifest'], frozen['package_manifest'])
        self.assertTrue(inputs['manifest_sha256'])

    def test_accepted_noop_receipt_is_not_an_unknown_mutation(self):
        class Boundary:
            fixture = True
            def exchange(self, kind, value):
                payload = {'state': 'stopped', 'state_version': 3,
                           'changed': False, 'error': None,
                           'command_id': None}
                body = {'result': {'content': [{'text': json.dumps(payload)}]}}
                return {'status': 200, 'headers': {}, 'http_error': False,
                        'body': json.dumps(body).encode()}
        session = mcp.BoundarySession(Boundary())
        request = urllib.request.Request(
            'http://192.0.2.1:28788/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                             'params': {'name': 'load_config', 'arguments': {
                                 'name': 'default.ini', 'command_id': 'compat-noop',
                                 'expected_state_version': 2}}}).encode(),
            headers={'Content-Type': 'application/json'}, method='POST')
        result = session.urlopen(request, timeout=1)
        self.assertEqual(200, result.status)
        operation = session.mutation_operations[-1]
        self.assertTrue(operation['accepted'])
        self.assertTrue(operation.get('no_op'))
        self.assertFalse(operation['response_unknown'])


if __name__ == '__main__':
    unittest.main()
