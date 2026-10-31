"""RF owned-child closure tests (T066-R01): the executecmd producer keeps the
REAL spawn path but wraps the single owned Popen, reaps it naturally, and
records child-lifecycle.json; the v5 oracle refuses every lifecycle defect.
All handles here are controlled fakes - no real OS spawn in this suite."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance_manual as M
import acceptance_manual_oracles as O

HEAD = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                               text=True).strip()


import unittest as _unittest

def _hit(name):
    def boom(*a, **k):
        raise AssertionError('REAL_EFFECT_HIT: ' + name)
    return boom


def _hit(name):
    def boom(*a, **k):
        raise AssertionError('REAL_EFFECT_HIT: ' + name)
    return boom


class _NoRealEffects(_unittest.TestCase):
    """Full product-test guard scope (R328): every real OS creation, network,
    VM/driver/EventLog exit refused before any selected node runs; only exact
    read-only git passthrough and the controlled fake-handle path stay live."""

    def setUp(self):
        real_popen = subprocess.Popen
        import socket as _socket
        import acceptance_native as _N

        def guarded(argv, *a, **k):
            if isinstance(argv, (list, tuple)) and argv and str(argv[0]).endswith('git'):
                return real_popen(argv, *a, **k)
            raise AssertionError('REAL_EFFECT_HIT: subprocess.Popen')
        patches = [mock.patch('subprocess.Popen', side_effect=guarded),
                   mock.patch('subprocess.run', side_effect=_hit('subprocess.run')),
                   mock.patch('subprocess.call', side_effect=_hit('subprocess.call')),
                   mock.patch('subprocess.check_call', side_effect=_hit('subprocess.check_call')),
                   mock.patch('subprocess.check_output', side_effect=_hit('subprocess.check_output')),
                   mock.patch('os.system', side_effect=_hit('os.system')),
                   mock.patch('socket.create_connection', side_effect=_hit('socket.create_connection')),
                   mock.patch('socket.socket.bind', side_effect=_hit('socket.socket.bind')),
                   mock.patch('socket.socket.listen', side_effect=_hit('socket.socket.listen')),
                   mock.patch('socket.socket.connect', side_effect=_hit('socket.socket.connect')),
                   mock.patch('socket.socket.sendto', side_effect=_hit('socket.socket.sendto'))]
        import logging.handlers
        patches.append(mock.patch.object(logging.handlers, 'NTEventLogHandler',
                                         side_effect=_hit('NTEventLogHandler')))
        for attr in ('run_driver', 'run_production', 'run_remote'):
            patches.append(mock.patch.object(_N, attr, side_effect=_hit('native.' + attr)))
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        super().setUp()


class _FakeProc:
    def __init__(self, pid=43210, wait_result=0, wait_error=None):
        self.pid = pid
        self._wait_result = wait_result
        self._wait_error = wait_error
        self.returncode = wait_result if wait_error is None else None
        self.wait_calls = []
        self.terminate_calls = 0
        self.kill_calls = 0

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        if self._wait_error is not None:
            raise self._wait_error
        return self._wait_result

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminate_calls += 1
        self.returncode = 0

    def kill(self):
        self.kill_calls += 1
        self.returncode = -9


import os as _os
_GUARD_ROOT = Path(_os.environ.get('FN_MANUAL_CHECK_DIR',
                                  '/home/adminn/projects/flare-fakenet-ng/Logs/fnreg-T066-R04-executecmd-child-native/fixtures'))
_GUARD_ROOT.mkdir(parents=True, exist_ok=True)


def _run_producer(fake):
    work = Path(tempfile.mkdtemp(prefix='fnreg-rf-child-', dir=str(_GUARD_ROOT)))
    out = work / 'driver'
    inputs = {'schema': 'fakenet.manual-input.v5', 'case': 'GAP-EXECUTECMD',
              'candidate_id': 'manual-candidate', 'source_commit': HEAD,
              'package_sha256': None, 'execution_id': 'rf-child-exit-01',
              'owned_root': str(out), 'config': str(out / 'config'),
              'responsea': '192.0.2.55', 'fixture': True,
              'source_deployment_identity': {
                  'schema': 'fakenet.source-deployment-identity.v1',
                  'source_commit': HEAD, 'case_id': 'GAP-EXECUTECMD',
                  'source_hashes_sha256': '0' * 64}}
    def fake_popen(argv, *a, **k):
        # controlled benign echo surrogate: writes the six-field line the real
        # cmd.exe child would produce, then reports the fake handle outcome
        out.mkdir(parents=True, exist_ok=True)
        marker = argv.rsplit('echo ', 1)[1].split('>>"', 1)[0]
        (out / 'command-output.txt').write_text(marker + '\n')
        return fake
    with mock.patch('subprocess.Popen', side_effect=fake_popen):
        M.run('GAP-EXECUTECMD', out, inputs)
    return out, inputs


def _lifecycle(out):
    return json.loads((out / 'child-lifecycle.json').read_text())


class ChildLifecycleTests(_NoRealEffects):
    def test_natural_exit_recorded_and_v5_passes(self):
        fake = _FakeProc()
        out, inputs = _run_producer(fake)
        life = _lifecycle(out)
        row = life['children'][0]
        self.assertEqual(1, life['spawn_count'])
        self.assertEqual(0, row['returncode'])
        self.assertFalse(row['forced'])
        self.assertFalse(row['timeout'])
        self.assertTrue(row['observer_restored'])
        self.assertTrue(row['reaped'])
        self.assertEqual('observed',
                         json.loads((out / 'manual-result.json').read_text())['cleanup']['child_exit'])
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-EXECUTECMD', inputs,
                                         allow_fixture=True)
        self.assertTrue(clean, detail)

    def test_nonzero_child_exit_refused(self):
        out, inputs = _run_producer(_FakeProc(wait_result=3))
        value = json.loads((out / 'manual-result.json').read_text())
        self.assertNotEqual('observed', value['cleanup']['child_exit'])
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-EXECUTECMD', inputs,
                                         allow_fixture=True)
        self.assertFalse(clean, detail)
        self.assertTrue(any('naturally observed' in f or 'child_exit' in f
                            for f in detail['failures']), detail)

    def test_timeout_forced_terminate_refused(self):
        fake = _FakeProc(wait_error=subprocess.TimeoutExpired(cmd='x', timeout=2))
        out, inputs = _run_producer(fake)
        self.assertGreaterEqual(fake.terminate_calls, 1)
        value = json.loads((out / 'manual-result.json').read_text())
        self.assertNotEqual('observed', value['cleanup']['child_exit'])

    def test_tampered_lifecycle_hash_refused(self):
        out, inputs = _run_producer(_FakeProc())
        path = out / 'child-lifecycle.json'
        life = _lifecycle(out)
        life['children'][0]['returncode'] = 0
        path.write_text(json.dumps(life) + '\n')
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-EXECUTECMD', inputs,
                                         allow_fixture=True)
        self.assertFalse(clean, detail)
        self.assertIn('child lifecycle original missing/changed', detail['failures'])

    def test_wrong_owner_or_pid_refused(self):
        out, inputs = _run_producer(_FakeProc())
        path = out / 'child-lifecycle.json'
        life = _lifecycle(out)
        life['children'][0]['pid'] = 999
        import hashlib
        path.write_text(json.dumps(life, indent=1) + '\n')
        value = json.loads((out / 'manual-result.json').read_text())
        value['executecmd']['child_lifecycle_sha256'] = hashlib.sha256(
            path.read_bytes()).hexdigest()
        (out / 'manual-result.json').write_text(json.dumps(value, indent=1) + '\n')
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-EXECUTECMD', inputs,
                                         allow_fixture=True)
        self.assertFalse(clean, detail)
        self.assertTrue(any('naturally observed' in f for f in detail['failures']),
                        detail)


def _refresh_chain(out):
    """Re-close lifecycle+result hashes after a mutation (chain stays legal so
    only the TARGET oracle check can refuse)."""
    import hashlib
    life_path = out / 'child-lifecycle.json'
    value = json.loads((out / 'manual-result.json').read_text())
    value['executecmd']['child_lifecycle_sha256'] = hashlib.sha256(
        life_path.read_bytes()).hexdigest()
    (out / 'manual-result.json').write_text(json.dumps(value, indent=1) + '\n')


class ControllerCounterexampleTests(_NoRealEffects):
    """EC03/04: the five controller-found non-refusing mutations must now be
    refused by the target oracle checks after re-closing the hash chain."""

    def _mutate_and_evaluate(self, mutate):
        out, inputs = _run_producer(_FakeProc())
        life = _lifecycle(out)
        mutate(life, json.loads((out / 'manual-result.json').read_text()))
        (out / 'child-lifecycle.json').write_text(json.dumps(life, indent=1) + '\n')
        _refresh_chain(out)
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-EXECUTECMD', inputs,
                                         allow_fixture=True)
        self.assertFalse(clean, detail)
        return detail['failures']

    def test_wait_poll_missing_refused(self):
        def mutate(life, value):
            for key in ('wait_result', 'poll'):
                life['children'][0].pop(key, None)
        failures = self._mutate_and_evaluate(mutate)
        self.assertTrue(any('strict natural zeros' in f for f in failures), failures)

    def test_wait_poll_nonzero_refused(self):
        def mutate(life, value):
            life['children'][0]['wait_result'] = 3
            life['children'][0]['poll'] = 3
            life['children'][0]['returncode'] = 3
        failures = self._mutate_and_evaluate(mutate)
        self.assertTrue(any('strict natural zeros' in f or
                            'naturally observed' in f for f in failures), failures)

    def test_top_observer_false_refused(self):
        def mutate(life, value):
            life['observer_restored'] = False
        failures = self._mutate_and_evaluate(mutate)
        self.assertTrue(any('lifecycle incomplete' in f for f in failures), failures)

    def test_row_owner_wrong_refused(self):
        def mutate(life, value):
            life['children'][0]['owner_execution'] = 'foreign-owner'
        failures = self._mutate_and_evaluate(mutate)
        self.assertTrue(any('naturally observed' in f for f in failures), failures)

    def test_v1_native_missing_lifecycle_refused(self):
        out, inputs = _run_producer(_FakeProc())
        v1 = dict(inputs, schema='fakenet.manual-input.v1',
                  package_sha256='ab' * 32, fixture=False)
        v1.pop('source_deployment_identity', None)
        value = json.loads((out / 'manual-result.json').read_text())
        value['inputs'] = v1
        value['fixture'] = False  # native v1 evidence claim
        value['executecmd']['os_platform'] = 'windows'
        value['executecmd'].pop('child_lifecycle', None)  # the actual gap: no lifecycle claim
        value['executecmd'].pop('child_lifecycle_sha256', None)
        value['identity'] = {k: v1[k] for k in
                             ('candidate_id', 'source_commit', 'package_sha256',
                              'execution_id')}
        # keep the v1 historical cleanup shape (still the produced bytes) -
        # the strict non-fixture branch must refuse on lifecycle/cleanup, not
        # on the fixture gate
        (out / 'manual-result.json').write_text(json.dumps(value, indent=1) + '\n')
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-EXECUTECMD', v1,
                                         allow_fixture=False)
        self.assertFalse(clean, detail)
        self.assertTrue(any('child lifecycle' in f or 'cleanup mismatch' in f
                            for f in detail['failures']), detail)


if __name__ == '__main__':
    unittest.main()
