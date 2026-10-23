"""Offline tests for the headless policy unit and its independent oracle."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import acceptance_policy as POLICY
import acceptance_policy_oracles as ORACLE
import acceptance_native as NATIVE


class PolicyConfigTests(unittest.TestCase):
    def test_config_is_deterministic_and_headless(self):
        first = POLICY.config_text('domain')
        second = POLICY.config_text('domain')
        self.assertEqual(first, second)
        self.assertIn('ExternalAllowedDomains = api.example.test, *.example.test', first)
        self.assertIn('ExternalVerifyTLSSNI = Yes', first)
        self.assertNotIn('gui', first.lower())
        self.assertIn('ExternalTakeoverIPv4 = 192.0.2.50',
                      POLICY.config_text('takeover'))

    def test_driver_table_exposes_policy_drivers(self):
        drivers = NATIVE.driver_table(ROOT)
        for name, scenario in (('policy-domain', 'domain'),
                               ('policy-ipv4', 'ipv4'),
                               ('policy-takeover', 'takeover'),
                               ('policy-combined', 'combined')):
            self.assertIn(name, drivers)
            self.assertTrue(drivers[name]['implemented'])
            self.assertEqual(POLICY.CHECKS[scenario], drivers[name]['checks'])


class PolicyOracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name) / 'driver'
        POLICY.fixture('domain', self.out)

    def evaluate(self):
        rows, clean = ORACLE.evaluate(self.out, 'domain',
                                      POLICY.CHECKS['domain'],
                                      allow_fixture=True)
        return NATIVE._judge_rows(rows, POLICY.CHECKS['domain']), clean

    def mutate(self, callback):
        path = self.out / 'policy-result.json'
        value = json.loads(path.read_text(encoding='utf-8'))
        callback(value)
        path.write_text(json.dumps(value), encoding='utf-8')

    def test_fixture_passes_contract(self):
        evaluation, clean = self.evaluate()
        self.assertEqual('pass', evaluation['verdict'])
        self.assertTrue(clean)

    def test_missing_check_is_not_pass(self):
        self.mutate(lambda value: value['checks'].pop())
        self.assertNotEqual('pass', self.evaluate()[0]['verdict'])

    def test_duplicate_check_is_not_pass(self):
        self.mutate(lambda value: value['checks'].append(
            dict(value['checks'][0])))
        self.assertNotEqual('pass', self.evaluate()[0]['verdict'])

    def test_observed_status_is_not_pass(self):
        self.mutate(lambda value: value['checks'][0].update(status='observed'))
        self.assertNotEqual('pass', self.evaluate()[0]['verdict'])

    def test_empty_nonce_is_not_pass(self):
        self.mutate(lambda value: value['checks'][0].update(nonce=''))
        self.assertNotEqual('pass', self.evaluate()[0]['verdict'])

    def test_allow_check_requires_application_round_trip(self):
        self.mutate(lambda value: value['checks'][4].pop('application'))
        self.assertNotEqual('pass', self.evaluate()[0]['verdict'])

    def test_unrestored_network_is_not_clean(self):
        self.mutate(lambda value: value.update(network_restored=False))
        evaluation, clean = self.evaluate()
        self.assertEqual('pass', evaluation['verdict'])
        self.assertFalse(clean)

    def test_fixture_is_rejected_without_explicit_fixture_contract(self):
        with self.assertRaises(ValueError):
            ORACLE.evaluate(self.out, 'domain', POLICY.CHECKS['domain'])

    def test_combined_fixture_covers_ip_and_takeover(self):
        out = Path(self.temp.name) / 'combined'
        POLICY.fixture('combined', out)
        rows, clean = ORACLE.evaluate(out, 'combined', POLICY.CHECKS['combined'],
                                      allow_fixture=True)
        self.assertTrue(clean)
        self.assertEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['combined'])['verdict'])

    def test_adapter_discovers_and_reads_policy_artifact(self):
        rows = NATIVE._read_oracle('policy-result',
                                   self.out / 'policy-result.json')
        self.assertEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['domain'])['verdict'])


class PolicyLifecycleTests(unittest.TestCase):
    def test_live_path_never_fabricates_probe_pass(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        core = root / 'fake_core.py'
        core.write_text(
            "import pathlib,sys,time\n"
            "args=sys.argv[1:]\n"
            "log=pathlib.Path(args[args.index('-l')+1])\n"
            "stop=pathlib.Path(args[args.index('-f')+1])\n"
            "log.write_text('EGRESS_CONTROL_READY\\n',encoding='utf-8')\n"
            "while not stop.exists(): time.sleep(0.05)\n",
            encoding='utf-8')
        out = root / 'run'
        rc = POLICY.run('domain', out, [sys.executable, str(core)], 10)
        self.assertEqual(0, rc)
        rows, clean = ORACLE.evaluate(out, 'domain', POLICY.CHECKS['domain'])
        self.assertFalse(clean)
        self.assertNotEqual('pass', NATIVE._judge_rows(rows, POLICY.CHECKS['domain'])['verdict'])
        value = json.loads((out / 'policy-result.json').read_text(encoding='utf-8'))
        self.assertTrue(all(row['status'] == 'not_run' for row in value['checks']))


if __name__ == '__main__':
    unittest.main()
