"""Pure-memory tests for headless process-redirect and payload evidence."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import acceptance_headless as HEADLESS
import acceptance_headless_oracles as ORACLE
import acceptance_native as NATIVE

PROCESS_CHECKS = ['identity', 'target-positive', 'non-target-negative',
                  'owner-bounded', 'budget', 'pcap-restore']
PAYLOAD_CHECKS = ['integrity', 'report', 'reassembly']


class HeadlessMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def process(self, name='process'):
        out = self.base / name
        HEADLESS.run('process', out, memory=True)
        return out

    def payload(self, name='payload'):
        out = self.base / name
        HEADLESS.run('payload', out, memory=True)
        return out

    def check_process(self, out):
        rows, clean, detail = ORACLE.evaluate(
            ROOT, out, 'process', PROCESS_CHECKS, allow_fixture=True)
        return NATIVE._judge_rows(rows, PROCESS_CHECKS), clean, detail

    def check_payload(self, out):
        rows, clean, detail = ORACLE.evaluate(
            ROOT, out, 'payload', PAYLOAD_CHECKS, allow_fixture=True)
        return NATIVE._judge_rows(rows, PAYLOAD_CHECKS), clean, detail

    def test_memory_process_and_payload_use_real_content_oracles(self):
        for mode in ('process', 'payload'):
            with self.subTest(mode=mode):
                out = self.process() if mode == 'process' else self.payload()
                evaluation, clean, detail = (
                    self.check_process(out) if mode == 'process'
                    else self.check_payload(out))
                self.assertEqual('pass', evaluation['verdict'], detail)
                self.assertTrue(clean)

    def test_process_identity_non_target_budget_and_capture_mutations_fail(self):
        value = json.loads((self.process('process-id')).joinpath(
            'headless-result.json').read_text())
        value['target']['sha256'] = '0' * 64
        (self.base / 'process-id/headless-result.json').write_text(
            json.dumps(value))
        self.assertNotEqual('pass', self.check_process(self.base / 'process-id')[0]['verdict'])

        out = self.process('process-negative')
        log = out / 'non-target.jsonl'
        rows = [json.loads(line) for line in log.read_text().splitlines()]
        rows[1]['success'] = True
        rows[1]['failure_stage'] = ''
        rows[1]['winsock_error'] = 0
        rows[-1]['failures'] = 0
        log.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        self.assertNotEqual('pass', self.check_process(out)[0]['verdict'])

        out = self.process('process-budget')
        core = out / 'core.log'
        core.write_text(core.read_text().replace('owner_query_budget_exhausted=1\n', ''))
        self.assertNotEqual('pass', self.check_process(out)[0]['verdict'])

        out = self.process('process-pcap')
        pcap = out / 'wire.pcapng'
        pcap.unlink()
        HEADLESS._write_pcapng(pcap, [HEADLESS._tcp_ipv4(
            '192.0.2.10', '198.51.100.20', 3585, 40000, 1,
            b'FNPR/1|x|target\n')])
        self.assertNotEqual('pass', self.check_process(out)[0]['verdict'])

    def test_payload_missing_or_changed_original_artifacts_fail(self):
        out = self.payload('payload-raw')
        raw = out / 'raw.pcap'
        raw.write_bytes(raw.read_bytes()[:24])
        self.assertNotEqual('pass', self.check_payload(out)[0]['verdict'])

        out = self.payload('payload-wire')
        wire = out / 'wire.pcapng'
        wire.write_bytes(wire.read_bytes()[:100])
        self.assertNotEqual('pass', self.check_payload(out)[0]['verdict'])

        out = self.payload('payload-html')
        html = out / 'report.html'
        text = html.read_text().replace('</script>', 'x</script>', 1)
        html.write_text(text)
        self.assertNotEqual('pass', self.check_payload(out)[0]['verdict'])


class HeadlessCliTests(unittest.TestCase):
    def test_same_catalog_cli_runs_four_memory_cases(self):
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
            'PR-REDIRECT-POSITIVE': 'process-substitute',
            'PR-OWNER-BOUNDED': 'process-substitute',
            'PR-PCAP-RESTORE': 'process-substitute',
            'PAYLOAD-THREE-WAY': 'payload-substitute',
        }
        for suite in catalog['suites']:
            for case in suite.get('cases') or []:
                if case['id'] in mapping:
                    case['adapter'] = 'native'
                    case['native_driver'] = mapping[case['id']]
                    case['platforms'] = ['linux']
                    case['oracle'] = {'kind': 'headless-result',
                                      'driver': mapping[case['id']]}
                    case['blocked_reason'] = 'fixture-only memory boundary; no native credit'
        catalog_path.write_text(json.dumps(catalog, ensure_ascii=False,
                                           indent=2) + '\n')
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
            'endpoints': [], 'auth_refs': [], 'work_root': str(run),
            'allowed_actions': ['native']}))
        cmd = [sys.executable, 'tools/acceptance.py']
        args = []
        for case_id in mapping:
            args += ['--case', case_id]
        completed = subprocess.run(
            cmd + ['plan', '--mode', 'selected'] + args +
            ['--candidate', str(config / 'candidate.json'),
             '--environment', str(config / 'environment.json'),
             '--output', str(run / 'plan.json')],
            cwd=root, capture_output=True, text=True)
        self.assertEqual(0, completed.returncode, completed.stderr)
        completed = subprocess.run(
            cmd + ['execute', '--plan', str(run / 'plan.json')],
            cwd=root, capture_output=True, text=True)
        self.assertEqual(0, completed.returncode, completed.stderr)
        completed = subprocess.run(
            cmd + ['judge', '--plan', str(run / 'plan.json'),
                   '--results', str(run / 'results'),
                   '--output', str(run / 'summary-independent.json')],
            cwd=root, capture_output=True, text=True)
        self.assertEqual(0, completed.returncode, completed.stderr)
        summary = json.loads((run / 'summary-independent.json').read_text())
        self.assertEqual(4, summary['checks']['passed'])
        self.assertTrue(summary['fixture_contract_pass'])
        self.assertFalse(summary['full_functional_pass'])


if __name__ == '__main__':
    unittest.main()
