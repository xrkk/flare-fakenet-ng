import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance_manual as M
import acceptance_manual_oracles as O
import acceptance_native as N


class _Iface:
    ifaces = {'eth0': []}

    def get_ips(self, versions, iface=None):
        return ['192.0.2.10'] if 4 in versions else []


class _Backend:
    instances = []
    fail_stop = False

    def __init__(self, *args, **kwargs):
        self.start_calls = 0
        self.stop_calls = 0
        self.wait_calls = 0
        self.started = False
        self.stopped = False
        type(self).instances.append(self)

    def start(self):
        self.start_calls += 1
        self.started = True

    def wait_for_capture_failure(self, timeout):
        self.wait_calls += 1
        time.sleep(min(float(timeout), 0.02))
        return False

    def stop(self):
        self.stop_calls += 1
        self.stopped = True
        return not self.fail_stop


class _Failing(_Backend):
    fail_stop = True


@contextlib.contextmanager
def fixture(backend=_Backend):
    _Backend.instances = []
    _Backend.fail_stop = False
    with mock.patch('fakenet.fakenet.platform.system', return_value='Linux'), \
            mock.patch('fakenet.fakenet.IfaceIpInfo', _Iface), \
            mock.patch.dict(sys.modules, {'fakenet.diverters.linux': types.SimpleNamespace(Diverter=backend)}):
        yield


class CtrIcIpcTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(os.environ['FN_MANUAL_CHECK_DIR']) / 'retained' / self.id().split('.')[-1]
        self.base.mkdir(parents=True, exist_ok=False)

    def inputs(self, out):
        return {'schema': 'fakenet.manual-input.v1', 'case': 'GAP-CTRLC-IPC',
                'candidate_id': 'ctrlc-fixture', 'source_commit': 'a' * 40,
                'package_sha256': 'b' * 64, 'execution_id': 'ctrlc-fixture-01',
                'config': str(out / 'config'), 'owned_root': str(out), 'fixture': True}

    def produce(self, out, backend=_Backend):
        inputs = self.inputs(out)
        with fixture(backend):
            value = M.run('GAP-CTRLC-IPC', out, inputs)
        return inputs, value

    def test_real_main_ctrlc_and_file_ipc(self):
        out = self.base / 'case'
        inputs, value = self.produce(out)
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs, allow_fixture=True)
        self.assertTrue(clean, detail)
        self.assertEqual(['ctrlc', 'ipc-stop', 'owned-exit'], [row['id'] for row in rows])
        unused, fixture_clean, fixture_detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs, allow_fixture=False)
        self.assertFalse(fixture_clean, fixture_detail)
        self.assertEqual({'ctrlc', 'ipc'}, set(value['ctrlc_ipc']['branches']))
        self.assertEqual(2, len(_Backend.instances))
        self.assertTrue(all(item['runtime']['start_calls'] == 1 and item['runtime']['stop_calls'] == 1
                            for item in value['ctrlc_ipc']['branches'].values()))
        self.assertFalse((out / 'ctrlc' / 'stop-ctrlc-fixture-01-ctrlc.flag').exists())
        self.assertFalse((out / 'ipc' / 'stop-ctrlc-fixture-01-ipc.flag').exists())
        self.assertTrue((out / 'ipc' / 'unrelated.flag').is_file())

    def test_bad_originals_stop_fault_and_unrelated_flag_are_rejected(self):
        import copy
        out = self.base / 'case'
        inputs, value = self.produce(out)
        base = json.loads((out / 'manual-result.json').read_text())

        def reject(label, changed):
            (out / 'manual-result.json').write_text(json.dumps(changed))
            rows, clean, detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs, allow_fixture=True)
            self.assertFalse(clean, (label, detail))
            (out / 'manual-result.json').write_text(json.dumps(base))

        variants = {
            'owner': lambda v: v['ctrlc_ipc'].__setitem__('owner_pid', v['ctrlc_ipc']['owner_pid'] + 1),
            'token': lambda v: v['ctrlc_ipc'].__setitem__('execution_token', 'foreign-token'),
            'path': lambda v: v['ctrlc_ipc']['branches']['ipc'].__setitem__('flag', '/foreign/stop.flag'),
            'wait': lambda v: v['ctrlc_ipc']['branches']['ctrlc'].__setitem__('wait_entered', False),
            'stop': lambda v: v['ctrlc_ipc']['branches']['ipc']['runtime'].__setitem__('stop_result', False),
            'thread': lambda v: v['ctrlc_ipc']['branches']['ctrlc'].__setitem__('watcher_alive', True),
            'branch': lambda v: v['ctrlc_ipc']['branches'].pop('ipc'),
            'cleanup': lambda v: v['cleanup'].__setitem__('system_network_restored', 'restored'),
            'source': lambda v: v['source_hashes'].__setitem__('fakenet/fakenet.py', '0' * 64),
            'fixture': lambda v: v.__setitem__('fixture', False),
            'flag': lambda v: v['ctrlc_ipc']['branches']['ipc'].__setitem__('flag_exists_after', True),
        }
        for label, change in variants.items():
            with self.subTest(fault=label):
                value_copy = copy.deepcopy(base)
                change(value_copy)
                reject(label, value_copy)
        unrelated = out / 'ipc' / 'unrelated.flag'
        prior = unrelated.read_bytes()
        unrelated.write_bytes(b'damaged')
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs, allow_fixture=True)
        self.assertFalse(clean, detail)
        unrelated.write_bytes(prior)
        for label, path, damaged in (('config', out / 'config' / 'shutdown.ini', b'[FakeNet]\nDivertTraffic: No\n'),
                                     ('log', out / 'ipc' / 'main.log', b'not the original log\n'),
                                     ('lifecycle', out / 'lifecycle.json', b'{}\n')):
            with self.subTest(original=label):
                (out / 'manual-result.json').write_text(json.dumps(base))
                prior = path.read_bytes(); path.write_bytes(damaged)
                rows, clean, detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs, allow_fixture=True)
                self.assertFalse(clean, detail)
                path.write_bytes(prior)
        (out / 'manual-result.json').write_text(json.dumps(base))
        flag = out / 'ipc' / 'stop-ctrlc-fixture-01-ipc.flag'
        flag.write_text('late\n')
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs, allow_fixture=True)
        self.assertFalse(clean, detail)
        flag.unlink()

        failure_out = self.base / 'stop-failure'
        failure_inputs, failure_value = self.produce(failure_out, _Failing)
        self.assertFalse(failure_value['cleanup']['stopped'])
        self.assertEqual(1, failure_value['ctrlc_ipc']['branches']['ipc']['rc'])
        self.assertFalse(failure_value['ctrlc_ipc']['branches']['ipc']['runtime']['stop_result'])
        rows, clean, detail = O.evaluate(ROOT, failure_out, 'GAP-CTRLC-IPC', failure_inputs, allow_fixture=True)
        self.assertFalse(clean, detail)

    def test_same_central_cli_and_independent_rejection(self):
        import acceptance as A

        def write(path, value):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))

        def cli(*args):
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = A.main(['--root', str(ROOT), *map(str, args)])
            return code, stdout.getvalue(), stderr.getvalue()

        identity = {'platform': 'linux', 'hostname': socket.gethostname()}
        write(self.base / 'candidate.json', dict(schema=A.CANDIDATE_V2, source_commit=A.git_head(ROOT),
                                                   deployed_identity=identity, package_sha256='b' * 64,
                                                   offline_fixture=True))
        write(self.base / 'environment.json', dict(schema=A.ENVIRONMENT_V2, targets=['host-linux'],
                                                     interpreters={'python': sys.executable},
                                                     work_root=str(self.base), allowed_actions=['native'],
                                                     endpoints=[], auth_refs=[],
                                                     native_runtime={'transport': 'manual-loopback-fixture', 'identity': identity},
                                                     manual={'schema': 'fakenet.manual-options.v1'}))
        real_popen = subprocess.Popen

        class Child:
            pid = 999987

            def __init__(self, code):
                self.code = code

            def wait(self, timeout=None):
                return self.code

        def popen(argv, **kwargs):
            if isinstance(argv, list) and argv[0] == 'git':
                return real_popen(argv, **kwargs)
            self.assertEqual(str(ROOT / 'tools/acceptance_manual.py'), argv[1])
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                code = M.main(argv[2:])
            kwargs['stdout'].write(captured.getvalue().encode())
            return Child(code)

        run = self.base / 'run'
        result = cli('plan', '--mode', 'selected', '--case', 'GAP-CTRLC-IPC',
                     '--candidate', self.base / 'candidate.json', '--environment', self.base / 'environment.json',
                     '--output', run / 'plan.json')
        self.assertEqual(0, result[0], result)
        with fixture(), mock.patch.object(subprocess, 'Popen', side_effect=popen):
            result = cli('execute', '--plan', run / 'plan.json')
        self.assertEqual(0, result[0], result)
        result = cli('judge', '--plan', run / 'plan.json', '--results', run / 'results', '--output', run / 'judge.json')
        self.assertEqual(0, result[0], result)
        self.assertFalse(json.loads((run / 'judge.json').read_text())['full_functional_pass'])

        produced = run / 'results' / 'GAP-CTRLC-IPC' / 'driver' / 'manual-result.json'
        original = json.loads(produced.read_text())
        damaged = json.loads(produced.read_text())
        damaged['ctrlc_ipc']['owner_pid'] += 1
        produced.write_text(json.dumps(damaged))
        result = cli('judge', '--plan', run / 'plan.json', '--results', run / 'results', '--output', run / 'rejected.json')
        self.assertNotEqual(0, result[0], result)
        produced.write_text(json.dumps(original))

        failure_run = self.base / 'failure-run'
        result = cli('plan', '--mode', 'selected', '--case', 'GAP-CTRLC-IPC',
                     '--candidate', self.base / 'candidate.json', '--environment', self.base / 'environment.json',
                     '--output', failure_run / 'plan.json')
        self.assertEqual(0, result[0], result)
        with fixture(_Failing), mock.patch.object(subprocess, 'Popen', side_effect=popen):
            result = cli('execute', '--plan', failure_run / 'plan.json')
        self.assertNotEqual(0, result[0], result)
        result = cli('judge', '--plan', failure_run / 'plan.json', '--results', failure_run / 'results',
                     '--output', failure_run / 'judge.json')
        self.assertNotEqual(0, result[0], result)

    def test_plain_backend_without_test_counters(self):
        class PlainBackend:
            def __init__(self, *args, **kwargs):
                pass
            def start(self):
                pass
            def wait_for_capture_failure(self, timeout):
                time.sleep(min(float(timeout), .02))
                return False
            def stop(self):
                return True
        out = self.base / 'plain'
        inputs, value = self.produce(out, PlainBackend)
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs, allow_fixture=True)
        self.assertTrue(clean, detail)

    def test_independent_restoration_and_empty_checks_rejected(self):
        import copy
        out = self.base / 'mutations'
        inputs, value = self.produce(out)
        result = out / 'manual-result.json'
        statefile = out / 'lifecycle.json'
        original = result.read_bytes()
        state = statefile.read_bytes()
        for fault in ('signal', 'logger', 'checks', 'inner-checks', 'stop-order'):
            with self.subTest(fault=fault):
                v = json.loads(original)
                st = json.loads(state)
                if fault == 'signal': st['signal_ids_after']['SIGINT'] += 1
                elif fault == 'logger': st['logger_after'][0]['level'] += 10
                elif fault == 'checks': v['checks'] = []
                elif fault == 'inner-checks': v['ctrlc_ipc']['checks'] = []
                else:
                    events = v['ctrlc_ipc']['branches']['ipc']['calls']
                    events[:] = [row for row in events if not (row.get('method') == 'stop' and row.get('event') == 'return')]
                result.write_text(json.dumps(v)); statefile.write_text(json.dumps(st))
                try:
                    rows, clean, detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs, allow_fixture=True)
                    self.assertFalse(clean, detail)
                finally:
                    result.write_bytes(original); statefile.write_bytes(state)

    def test_backend_wait_error_classification_is_exact(self):
        out = self.base / 'backend-errors'
        inputs, value = self.produce(out)
        result = out / 'manual-result.json'
        original = result.read_bytes()

        def observations(value, mode):
            return value['ctrlc_ipc']['branches'][mode]['runtime']['backend_observations']

        def wait_type_to_runtime(value):
            row = next(item for item in observations(value, 'ctrlc')
                       if item.get('method') == 'wait_for_capture_failure' and item.get('event') == 'error')
            row['type'] = 'RuntimeError'

        def stop_to_interrupt(value):
            rows = observations(value, 'ctrlc')
            index = next(index for index, item in enumerate(rows)
                         if item.get('method') == 'stop' and item.get('event') == 'return')
            rows[index] = {'method': 'stop', 'event': 'error', 'type': 'KeyboardInterrupt'}

        def ipc_wait_to_interrupt(value):
            rows = observations(value, 'ipc')
            index = next(index for index, item in enumerate(rows)
                         if item.get('method') == 'wait_for_capture_failure' and item.get('event') == 'return')
            rows[index] = {'method': 'wait_for_capture_failure', 'event': 'error', 'type': 'KeyboardInterrupt'}

        variants = {
            'ctrlc-wait-runtime-error': wait_type_to_runtime,
            'ctrlc-stop-interrupt': stop_to_interrupt,
            'ipc-wait-interrupt': ipc_wait_to_interrupt,
        }
        for label, change in variants.items():
            with self.subTest(fault=label):
                value_copy = json.loads(original)
                change(value_copy)
                result.write_text(json.dumps(value_copy))
                try:
                    rows, clean, detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs, allow_fixture=True)
                    self.assertFalse(clean, detail)
                finally:
                    result.write_bytes(original)

    def test_central_registration(self):
        self.assertEqual('manual-ctrlc-ipc', N.driver_table(ROOT)['manual-ctrlc-ipc']['production_kind'])


if __name__ == '__main__':
    unittest.main()
