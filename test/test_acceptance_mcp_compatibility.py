"""Compatibility roots for the existing MCP offline acceptance fixtures."""
import json
import os
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
        proof = Path(os.environ.get('FN_COMPAT_CHECK_DIR', ROOT / 'Logs/acceptance-compatibility'))
        proof.mkdir(parents=True, exist_ok=True)
        self.base = Path(tempfile.mkdtemp(prefix='mcp-compat-', dir=proof))

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

    def request(self, tool, command='compat-noop', expected=1):
        return urllib.request.Request(
            'http://192.0.2.1:28788/mcp',
            data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                             'params': {'name': tool, 'arguments': {
                                 'name': 'default.ini', 'command_id': command,
                                 'expected_state_version': expected}}}).encode(),
            headers={'Content-Type': 'application/json'}, method='POST')

    def session_for(self, produce):
        class Boundary:
            fixture = True

            def exchange(self, kind, value):
                if kind != 'http':
                    raise AssertionError('unexpected boundary operation: ' + kind)
                payload = produce()
                body = {'result': {'content': [{'text': json.dumps(payload)}]}}
                return {'status': 200, 'headers': {}, 'http_error': False,
                        'body': json.dumps(body).encode()}
        return mcp.BoundarySession(Boundary())

    def test_real_coordinator_noop_keeps_command_and_consumes_version(self):
        from fakenet.mcp.coordination import Coordinator
        from fakenet.mcp.testdouble import LifecycleDouble
        coord = Coordinator(LifecycleDouble())
        initial = coord.snapshot()
        # Same no-work result as tools.stop: production submit forms the receipt.
        session = self.session_for(lambda: coord.submit(
            command_id='compat-noop', expected_version=initial['state_version'],
            controller='11111111-2222-4333-8444-555555555555',
            controller_valid=True, kind='stop', describe={},
            execute=lambda c: {'state': 'stopped', 'changed': False}))
        self.assertEqual(200, session.urlopen(self.request('stop'), timeout=1).status)
        operation = session.mutation_operations[-1]
        self.assertTrue(operation['accepted'])
        self.assertFalse(operation['response_unknown'])
        self.assertFalse(operation['response']['changed'])
        self.assertEqual('compat-noop', operation['response']['command_id'])
        self.assertEqual(initial['state_version'] + 1,
                         operation['response']['state_version'])
        mcp._verified_version_chain(session, initial, coord.snapshot())
        # No-op still consumes a version: it cannot hide an unrelated advance.
        with self.assertRaisesRegex(ValueError, 'continuity'):
            mcp._verified_version_chain(session, initial,
                                        {'state_version': initial['state_version'] + 2})
        self.assertFalse(session.owned_configs)
        self.assertFalse(session.owned_runs)
        (self.base / 'real-noop.json').write_text(json.dumps({
            'initial': initial, 'final': coord.snapshot(),
            'operation': operation, 'records': session.records}, indent=2))

    def test_unbound_noop_and_version_leap_cannot_establish_ownership(self):
        for command, version in ((None, 1), (None, 2), (None, 9), ('foreign', 2)):
            with self.subTest(command=command, version=version):
                payload = {'state': 'stopped', 'state_version': version,
                           'changed': False, 'error': None, 'command_id': command}
                session = self.session_for(lambda: payload)
                with self.assertRaisesRegex(ValueError, 'command/version receipt incomplete'):
                    session.urlopen(self.request('load_config'), timeout=1)
                self.assertTrue(session.mutation_operations[-1]['response_unknown'])
                self.assertTrue(session.preserve_scene)
                self.assertFalse(session.mutation_operations[-1].get('accepted'))
                self.assertFalse(session.owned_configs)
                self.assertFalse(session.owned_runs)
                with self.assertRaisesRegex(ValueError, 'unresolved'):
                    mcp._verified_version_chain(session, {'state_version': 1},
                                                {'state_version': version})
                (self.base / ('unbound-%s-%s.json' % (command, version))).write_text(
                    json.dumps({'payload': payload,
                                'operations': session.mutation_operations,
                                'records': session.records}, indent=2))


if __name__ == '__main__':
    unittest.main()
