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


def _run_producer(fake):
    work = Path(tempfile.mkdtemp(prefix='fnreg-rf-child-', dir='/tmp'))
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


class ChildLifecycleTests(unittest.TestCase):
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

if __name__ == '__main__':
    unittest.main()
