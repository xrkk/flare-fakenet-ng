"""Snapshot refusal: real registered SDK receipts and original runner negatives."""
import asyncio
import hashlib
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from test_acceptance_mcp import ROOT, SnapshotRecoveryBoundary, inputs_at, m

CONTROL = '11111111-2222-4333-8444-555555555555'


def proof_root(label):
    root = Path(os.environ['FN_COMPAT_CHECK_DIR']) / label
    root.mkdir(parents=True)
    return root


class SnapshotReceiptTests(unittest.TestCase):
    def test_original_runner_rejects_unbound_failure_and_unknown_health(self):
        for fault in ('old-reason', 'missing-health', 'wrong-state', 'foreign-command',
                      'same-version', 'error-response', 'replayed'):
            with self.subTest(fault=fault):
                root = proof_root(fault)
                inputs = inputs_at(root)

                class Fault(SnapshotRecoveryBoundary):
                    def exchange(self, kind, value):
                        result = super().exchange(kind, value)
                        if kind != 'http' or not self.denied:
                            return result
                        req = json.loads(value['data'])
                        tool = req['params']['name']
                        payload = json.loads(json.loads(result['body'])['result']['content'][0]['text'])
                        if tool == 'get_status' and fault == 'old-reason':
                            payload['failure_reason'] = 'snapshot write failed: old operation'
                        if tool == 'get_status' and hasattr(self, '_denied_seen'):
                            if fault == 'missing-health': payload.pop('health', None)
                            if fault == 'wrong-state': payload['state'] = 'stopped'
                        if tool == 'start':
                            self._denied_seen = True
                            if fault == 'foreign-command': payload['command_id'] = 'foreign'
                            if fault == 'same-version':
                                payload['state_version'] = req['params']['arguments']['expected_state_version']
                            if fault == 'error-response': payload['error'] = {'code': 'internal_error'}
                            if fault == 'replayed': payload['replayed'] = True
                        return self.response(payload)

                boundary = Fault(inputs, root / 'guest')
                out = root / 'run'
                result = m.run('MCP-P03-FULL', out, inputs, selected=['ACC-008'],
                               boundary=boundary, fixture=True)
                self.assertNotEqual('pass', result['checks']['ACC-008']['status'], fault)
                self.assertTrue((out / 'units/ACC-008/acc008-original-acl-restored.json').is_file())

    def test_actual_registered_sdk_refusal_replay_and_new_incarnation(self):
        from fakenet.mcp.server import build_mcp_server
        from fakenet.mcp.tools import AppContext
        from fakenet.mcp.config import ServiceConfig
        from fakenet.mcp.configstore import ConfigStore
        from fakenet.mcp.coordination import Coordinator
        from fakenet.mcp.testdouble import LifecycleDouble
        from fakenet.mcp.snapshot import StateSnapshot, SnapshotError
        from fakenet.mcp.transportguard import controller_header_state
        root = proof_root('registered-sdk')

        class FileBoundary(LifecycleDouble):
            calls = 0
            def start(self, coord, controller, identity):
                self.calls += 1
                snap = StateSnapshot(root / 'state/state.json')
                fields = dict(run_id='isolated-file-fault', controller_id=controller,
                              state_version=coord.snapshot()['state_version'],
                              command_id=coord.current_command_id,
                              config_sha256=identity['sha256'],
                              baseline_path=str(root / 'unused-baseline.json'), needs_recovery=True)
                try:
                    with mock.patch('fakenet.mcp.snapshot.os.replace', side_effect=PermissionError('receipt test OS boundary')):
                        snap.write(**fields)
                except SnapshotError as exc:
                    return {'state': 'failed', 'run_id': None, 'changed': False,
                            'failure_reason': str(exc)}
                raise AssertionError('original snapshot writer did not fail')

        async def exercise():
            runner = FileBoundary()
            coord = Coordinator(runner)
            coord.set_config_identity({'name': 'default.ini', 'builtin': True,
                'sha256': hashlib.sha256((ROOT / 'fakenet/configs/default.ini').read_bytes()).hexdigest()})
            store = ConfigStore(root / 'custom', ROOT / 'fakenet/configs', root / 'audit.jsonl')
            config = ServiceConfig(listen_ip='127.0.0.1', listen_port=28788, allowed_host_ips=['127.0.0.1'])
            server = build_mcp_server(context=AppContext(config, runner=runner, store=store, coordinator=coord))
            records = []
            async def call(name, args, target=server):
                raw = (await target.call_tool(name, args)).model_dump(mode='json', by_alias=True)
                records.append({'tool': name, 'args': args, 'result': raw})
                self.assertFalse(raw.get('isError'))
                return raw.get('structuredContent') or json.loads(raw['content'][0]['text'])
            token = controller_header_state.set(CONTROL)
            try:
                before = await call('get_status', {})
                future = await call('start', {'command_id': 'future', 'expected_state_version': before['state_version'] + 9})
                self.assertEqual('state_conflict', future['error']['code'])
                self.assertEqual(0, runner.calls)
                request = {'command_id': 'owned', 'expected_state_version': before['state_version']}
                first = await call('start', request)
                fresh = await call('get_status', {})
                cached = await call('get_command_status', {'command_id': 'owned'})
                self.assertNotIn('failure_reason', first)
                self.assertEqual('owned', first['command_id'])
                self.assertEqual(before['state_version'] + 1, first['state_version'])
                self.assertEqual('failed', fresh['state'])
                self.assertIn('snapshot write failed', fresh['failure_reason'])
                self.assertEqual('completed', cached['status'])
                replay = await call('start', request)
                self.assertTrue(replay['replayed'])
                self.assertEqual(first['state_version'], replay['state_version'])
                self.assertEqual(1, runner.calls)
                fresh_coord = Coordinator(runner)
                replacement = build_mcp_server(context=AppContext(config, runner=runner, store=store, coordinator=fresh_coord))
                unknown = await call('get_command_status', {'command_id': 'owned'}, replacement)
                self.assertEqual('unknown', unknown['status'])
                self.assertNotEqual(cached['cache_epoch'], unknown['cache_epoch'])
            finally:
                controller_header_state.reset(token)
                (root / 'sdk-records.json').write_text(json.dumps(records, indent=2) + '\n')
        asyncio.run(exercise())

    def test_os_fixture_itself_uses_sdk_cache_without_resynchronizing_retries(self):
        root = proof_root('fixture-sdk-cache')
        inputs = inputs_at(root)
        boundary = SnapshotRecoveryBoundary(inputs, root / 'guest')
        boundary.snapshot.write(run_id='33333333-3333-4333-8333-333333333333',
            controller_id=CONTROL, state_version=boundary.version, command_id='preimage',
            config_sha256=inputs['config_identity']['sha256'],
            baseline_path=str(root / 'unused-baseline.json'), needs_recovery=False)
        boundary.denied = True
        records = []
        def call(tool, args):
            req = {'params': {'name': tool, 'arguments': args}}
            raw = boundary.exchange('http', {'data': json.dumps(req).encode()})
            result = json.loads(raw['body'])['result']
            self.assertFalse(result.get('isError'))
            payload = result.get('structuredContent') or json.loads(result['content'][0]['text'])
            records.append({'tool': tool, 'args': args, 'payload': payload})
            return payload
        try:
            before = call('get_status', {})
            version = before['state_version']
            wrong = call('start', {'command_id': 'future', 'expected_state_version': version + 5})
            self.assertEqual('state_conflict', wrong['error']['code'])
            self.assertEqual(version, boundary.version)
            request = {'command_id': 'write', 'expected_state_version': version}
            first = call('start', request)
            self.assertEqual(version + 1, first['state_version'])
            self.assertNotIn('failure_reason', first)
            self.assertEqual('failed', first['state'])
            cache = call('get_command_status', {'command_id': 'write'})
            self.assertEqual('completed', cache['status'])
            replay = call('start', request)
            self.assertTrue(replay['replayed'])
            self.assertEqual(version + 1, boundary.version)
            status = call('get_status', {})
            self.assertIn('snapshot write failed', status['failure_reason'])
            self.assertFalse(status['health']['process_alive'])
            boundary.normalize_recovery()
            unknown = call('get_command_status', {'command_id': 'write'})
            self.assertEqual('unknown', unknown['status'])
            self.assertNotEqual(cache['cache_epoch'], unknown['cache_epoch'])
        finally:
            (root / 'fixture-sdk-records.json').write_text(json.dumps(records, indent=2) + '\n')
