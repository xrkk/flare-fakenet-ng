"""Receipt regressions for accepted-vs-rejected snapshot start failures."""
import json
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance_mcp as mcp


class SnapshotReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.inputs = mcp.__dict__['inputs_at'](self.base) if 'inputs_at' in mcp.__dict__ else None

    def _inputs(self):
        # inputs_at lives in the protected original test module.
        from test_acceptance_mcp import inputs_at
        return inputs_at(self.base)

    def test_write_denied_start_has_accepted_failure_receipt(self):
        from test_acceptance_mcp import SnapshotProcessBoundary
        inputs = self._inputs()
        boundary = SnapshotProcessBoundary(inputs, self.base / 'guest')
        # Establish the real active marker first; a write-denied start is an
        # accepted mutation of that live state, not a bare in-memory object.
        normal_command = 'snapshot-normal-marker'
        normal = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                  'params': {'name': 'start', 'arguments': {
                      'command_id': normal_command,
                      'expected_state_version': boundary.version}}}
        normal_response = boundary.exchange('http', {'data': json.dumps(normal).encode()})
        normal_payload = json.loads(json.loads(normal_response['body'])['result']['content'][0]['text'])
        self.assertEqual('healthy', normal_payload.get('state'))
        boundary.denied = True
        expected = boundary.version
        command = 'snapshot-write-denied-receipt'
        session = mcp.BoundarySession(boundary, inputs)
        request = urllib.request.Request(
            'http://192.0.2.1:28788/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                             'params': {'name': 'start', 'arguments': {
                                 'command_id': command,
                                 'expected_state_version': expected}}}).encode(),
            headers={'Content-Type': 'application/json'}, method='POST')
        response = session.urlopen(request)
        payload = json.loads(json.loads(response.read().decode())['result']['content'][0]['text'])
        self.assertEqual(command, payload.get('command_id'))
        self.assertIs(False, payload.get('changed'))
        self.assertEqual(expected + 1, payload.get('state_version'))
        self.assertEqual('failed', payload.get('state'))
        self.assertIsNone(payload.get('error'))
        operation = session.mutation_operations[-1]
        self.assertTrue(operation.get('accepted'))
        self.assertFalse(operation.get('response_unknown'))
        self.assertEqual(set(), session.owned_runs)


if __name__ == '__main__':
    unittest.main()
