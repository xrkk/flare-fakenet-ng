"""Offline tests for policy configuration, wire probes and content oracle."""
import json
import shutil
import subprocess
from unittest import mock
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
    def test_config_is_deterministic_and_uses_reviewed_grammar(self):
        first = POLICY.config_text('domain')
        second = POLICY.config_text('domain')
        self.assertEqual(first, second)
        self.assertIn('ExternalAllowedDomains = api.example.test, *.example.test', first)
        self.assertIn('ExternalVerifyTLSSNI = Yes', first)
        self.assertNotIn('gui', first.lower())
        self.assertIn('ExternalTakeoverIPv4 = 192.0.2.50',
                      POLICY.config_text('takeover'))
        ipv4 = POLICY.config_text('ipv4')
        self.assertIn('ExternalAllowedIPv4Rules = TCP/8.8.8.8/443', ipv4)
        self.assertNotIn('ExternalAllowedIPv4 =', ipv4)

    def test_guest_request_carries_explicit_policy_inputs(self):
        import acceptance_guest
        catalog = json.loads((ROOT / 'docs/acceptance/catalog.json').read_text())
        case = next(c for suite in catalog['suites']
                    for c in suite.get('cases') or []
                    if c['id'] == 'POL-DOMAIN-ALLOW')
        policy = POLICY._inputs()
        with tempfile.TemporaryDirectory() as temp:
            request = {
                'schema': 'fakenet.native-guest-request.v1',
                'case_id': case['id'], 'case': case,
                'checks': POLICY.CHECKS['domain'], 'source_hashes': {},
                'candidate': {'source_commit': 'offline-fixture'},
                'target': {'platform': 'windows', 'hostname': 'substitute'},
                'output_root': str(Path(temp) / 'guest-output'),
                'execution_id': 'execution-fixture', 'actions': ['native'],
                'policy': policy,
            }
            receipt = {'status': 'pass'}
            with mock.patch.object(NATIVE, 'run_production',
                                   return_value=receipt) as run, \
                    mock.patch('acceptance_runtime.require_target'):
                self.assertEqual(0, acceptance_guest.execute(request, ROOT))
        self.assertEqual(policy, run.call_args.args[2]['environment']['policy'])

    def test_production_argv_requires_frozen_policy_inputs(self):
        case = {'id': 'POL-DOMAIN-ALLOW', 'native_driver': 'policy-domain',
                'platforms': ['windows'], 'modes': ['singlehost']}
        with self.assertRaises(ValueError):
            NATIVE.production_command(ROOT, case, {'environment': {}},
                                      Path('/tmp/not-used'), sys.executable)
        argv = NATIVE.production_command(
            ROOT, case, {'environment': {'policy': POLICY._inputs()}},
            Path('/tmp/not-used'), sys.executable)
        self.assertIn('--inputs', argv)
        self.assertTrue(argv[argv.index('--inputs') + 1].endswith(
            'policy-inputs.json'))

    def test_driver_table_exposes_policy_drivers(self):
        drivers = NATIVE.driver_table(ROOT)
        for name, scenario in (('policy-domain', 'domain'),
                               ('policy-ipv4', 'ipv4'),
                               ('policy-takeover', 'takeover'),
                               ('policy-combined', 'combined')):
            self.assertIn(name, drivers)
            self.assertTrue(drivers[name]['implemented'])
            self.assertEqual(POLICY.CHECKS[scenario], drivers[name]['checks'])


class PolicyFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name) / 'driver'
        POLICY.fixture('domain', self.out)

    def evaluate(self, allow_fixture=True):
        rows, clean = ORACLE.evaluate(self.out, 'domain',
                                      POLICY.CHECKS['domain'],
                                      allow_fixture=allow_fixture)
        return NATIVE._judge_rows(rows, POLICY.CHECKS['domain']), clean

    def test_fixture_only_passes_explicit_fixture_contract(self):
        evaluation, clean = self.evaluate()
        self.assertEqual('pass', evaluation['verdict'])
        self.assertTrue(clean)
        with self.assertRaises(ValueError):
            ORACLE.evaluate(self.out, 'domain', POLICY.CHECKS['domain'])

    def test_adapter_discovers_and_reads_policy_artifact(self):
        rows = NATIVE._read_oracle('policy-result',
                                   self.out / 'policy-result.json')
        self.assertEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['domain'])['verdict'])


class PolicyCliSubstituteTests(unittest.TestCase):
    def test_same_plan_execute_judge_cli_uses_fixture_contract(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        root = base / 'root'
        for name in ('tools', 'fakenet', 'docs', 'test', 'deploy'):
            source = ROOT / name
            if source.is_dir():
                shutil.copytree(source, root / name,
                                ignore=shutil.ignore_patterns('__pycache__'))
        for pattern in ('Build-*.ps1', 'Build-*.sh'):
            for source in ROOT.glob(pattern):
                shutil.copy2(source, root / source.name)
        catalog_path = root / 'docs/acceptance/catalog.json'
        catalog = json.loads(catalog_path.read_text())
        mapping = {
            'POL-DOMAIN-ALLOW': 'policy-substitute-domain',
            'POL-TAKEOVER': 'policy-substitute-takeover',
            'POL-TCP-UDP-RECOVERY': 'policy-substitute-takeover',
            'IP-REVIEWED-TLS-MATRIX': 'policy-substitute-ipv4',
            'IP-TAKEOVER-COEXIST': 'policy-substitute-combined',
            'EGRESS-ALLOW-CHAIN': 'policy-substitute-domain',
            'EGRESS-NEGATIVES': 'policy-substitute-domain',
            'EGRESS-RESTORE': 'policy-substitute-domain',
        }
        for suite in catalog['suites']:
            for case in suite.get('cases') or []:
                if case['id'] in mapping:
                    case['adapter'] = 'native'
                    case['native_driver'] = mapping[case['id']]
                    case['platforms'] = ['linux']
                    case['oracle'] = {'kind': 'policy-result',
                                      'driver': mapping[case['id']]}
                    case['blocked_reason'] = 'fixture-only substitute; no native credit'
        catalog_path.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + '\n')
        config = base / 'config'
        config.mkdir()
        (config / 'candidate.json').write_text(json.dumps({
            'schema': 'fakenet.acceptance-candidate.v2',
            'source_commit': 'offline-fixture', 'offline_fixture': True}))
        run = base / 'run'
        (config / 'environment.json').write_text(json.dumps({
            'schema': 'fakenet.acceptance-environment.v2',
            'targets': ['host-linux'],
            'interpreters': {'python': sys.executable},
            'endpoints': [], 'auth_refs': [],
            'work_root': str(run), 'allowed_actions': ['native']}))
        python = sys.executable
        base_cmd = [python, 'tools/acceptance.py']
        cases = []
        for case_id in mapping:
            cases.extend(['--case', case_id])
        completed = subprocess.run(
            base_cmd + ['plan', '--mode', 'selected'] + cases +
            ['--candidate', str(config / 'candidate.json'),
             '--environment', str(config / 'environment.json'),
             '--output', str(run / 'plan.json')],
            cwd=root, capture_output=True, text=True)
        self.assertEqual(0, completed.returncode, completed.stderr)
        completed = subprocess.run(
            base_cmd + ['execute', '--plan', str(run / 'plan.json')],
            cwd=root, capture_output=True, text=True)
        self.assertEqual(0, completed.returncode, completed.stderr)
        completed = subprocess.run(
            base_cmd + ['judge', '--plan', str(run / 'plan.json'),
                        '--results', str(run / 'results'),
                        '--output', str(run / 'summary-independent.json')],
            cwd=root, capture_output=True, text=True)
        self.assertEqual(0, completed.returncode, completed.stderr)
        summary = json.loads((run / 'summary-independent.json').read_text())
        self.assertTrue(summary['fixture_contract_pass'])
        self.assertFalse(summary['full_functional_pass'])
        self.assertEqual(8, summary['checks']['passed'])


class PolicySubstituteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def run_scenario(self, scenario):
        out = self.base / ('run-' + scenario)
        self.assertEqual(0, POLICY.run(scenario, out, substitute=True))
        return out

    def evaluate(self, out, scenario):
        return ORACLE.evaluate(out, scenario, POLICY.CHECKS[scenario])

    def test_all_scenarios_use_real_probe_code_and_content_oracle(self):
        for scenario in ('domain', 'ipv4', 'takeover', 'combined'):
            with self.subTest(scenario=scenario):
                out = self.run_scenario(scenario)
                rows, clean = self.evaluate(out, scenario)
                self.assertTrue(clean)
                self.assertEqual('pass', NATIVE._judge_rows(
                    rows, POLICY.CHECKS[scenario])['verdict'])
                result = json.loads((out / 'policy-result.json').read_text())
                self.assertFalse(result['fixture'])
                self.assertGreater(len(result['attempts']), 0)
                self.assertTrue(result['pcap'])
                self.assertNotEqual(0, (out / result['pcap'][0]['path']).stat().st_size)

    def test_empty_capture_cannot_be_native_evidence(self):
        out = self.base / 'empty'
        POLICY.fixture('domain', out)
        value = json.loads((out / 'policy-result.json').read_text())
        value['fixture'] = False
        (out / 'policy-result.json').write_text(json.dumps(value))
        rows, clean = self.evaluate(out, 'domain')
        self.assertFalse(clean)
        self.assertNotEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['domain'])['verdict'])

    def test_changed_config_and_empty_evidence_are_rejected(self):
        out = self.run_scenario('domain')
        (out / 'policy.ini').write_text('[Diverter]\nExternalAccessPolicy=Off\n')
        value = json.loads((out / 'policy-result.json').read_text())
        value['config']['sha256'] = POLICY.sha256(out / 'policy.ini')
        for row in value['checks']:
            row['evidence'] = []
            row['tuple'] = {'proto': 'NONE', 'src': 'bad', 'dst': 'bad',
                            'port': -1}
        (out / 'policy-result.json').write_text(json.dumps(value))
        rows, clean = self.evaluate(out, 'domain')
        self.assertFalse(clean)
        self.assertNotEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['domain'])['verdict'])

    def test_wrong_nonce_and_missing_attempt_fail(self):
        out = self.run_scenario('domain')
        value = json.loads((out / 'policy-result.json').read_text())
        value['checks'][0]['nonce'] = 'wrong-nonce'
        (out / 'policy-result.json').write_text(json.dumps(value))
        rows, clean = self.evaluate(out, 'domain')
        self.assertFalse(clean)
        self.assertNotEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['domain'])['verdict'])
        value['attempts'] = []
        (out / 'policy-result.json').write_text(json.dumps(value))
        rows, clean = self.evaluate(out, 'domain')
        self.assertFalse(clean)
        self.assertNotEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['domain'])['verdict'])

    def test_wrong_destination_and_missing_capture_fail(self):
        out = self.run_scenario('ipv4')
        value = json.loads((out / 'policy-result.json').read_text())
        value['checks'][0]['tuple']['dst'] = '192.0.2.99'
        (out / 'policy-result.json').write_text(json.dumps(value))
        rows, clean = self.evaluate(out, 'ipv4')
        self.assertFalse(clean)
        self.assertNotEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['ipv4'])['verdict'])
        value = json.loads((out / 'policy-result.json').read_text())
        value['pcap'] = []
        (out / 'policy-result.json').write_text(json.dumps(value))
        rows, clean = self.evaluate(out, 'ipv4')
        self.assertFalse(clean)
        self.assertNotEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['ipv4'])['verdict'])


if __name__ == '__main__':
    unittest.main()
