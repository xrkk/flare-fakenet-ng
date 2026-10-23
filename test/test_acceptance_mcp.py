"""Pure-memory MCP acceptance tests with original content validators."""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import acceptance_mcp as MCP
import acceptance_mcp_oracles as ORACLE
import acceptance_native as NATIVE


class McpMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def run_case(self, case, name=None):
        out = self.base / (name or case)
        MCP.run(case, out, memory=True)
        return out

    def evaluate(self, out, case):
        rows, clean, detail = ORACLE.evaluate(
            ROOT, out, case, MCP.CHECKS[case])
        return NATIVE._judge_rows(rows, MCP.CHECKS[case]), clean, detail

    def test_six_memory_cases_use_original_validators(self):
        for case in MCP.CASES:
            with self.subTest(case=case):
                out = self.run_case(case)
                evaluation, clean, detail = self.evaluate(out, case)
                self.assertEqual('pass', evaluation['verdict'], detail)
                self.assertTrue(clean)

    def test_identity_evidence_capture_ipc_and_fault_mutations_fail(self):
        out = self.run_case('MCP-P01-FULL', 'p01-identity')
        value = json.loads((out / 'mcp-result.json').read_text())
        value['candidate_id'] = 'other'
        (out / 'mcp-result.json').write_text(json.dumps(value))
        self.assertNotEqual('pass', self.evaluate(out, 'MCP-P01-FULL')[0]['verdict'])

        out = self.run_case('MCP-P02-FULL', 'p02-evidence')
        value = json.loads((out / 'mcp-result.json').read_text())
        value['evidence'][0]['sha256'] = '0' * 64
        (out / 'mcp-result.json').write_text(json.dumps(value))
        self.assertNotEqual('pass', self.evaluate(out, 'MCP-P02-FULL')[0]['verdict'])

        out = self.run_case('MCP-P03-FULL', 'p03-capture')
        value = json.loads((out / 'mcp-result.json').read_text())
        value['capture_evidence'] = value['capture_evidence'][:1]
        (out / 'mcp-result.json').write_text(json.dumps(value))
        self.assertNotEqual('pass', self.evaluate(out, 'MCP-P03-FULL')[0]['verdict'])

        out = self.run_case('MCP-SPECIAL-IPC', 'ipc-bad')
        value = json.loads((out / 'mcp-result.json').read_text())
        first = 'ipc_once_timeout'
        path = Path(value['ipc'][first]['rows'])
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows = [row for row in rows if row.get('event') != 'failure']
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        self.assertNotEqual('pass', self.evaluate(out, 'MCP-SPECIAL-IPC')[0]['verdict'])

        out = self.run_case('MCP-SPECIAL-FAULT-RECOVERY', 'fault-missing')
        value = json.loads((out / 'mcp-result.json').read_text())
        value['faults'] = value['faults'][:-1]
        (out / 'mcp-result.json').write_text(json.dumps(value))
        self.assertNotEqual('pass', self.evaluate(
            out, 'MCP-SPECIAL-FAULT-RECOVERY')[0]['verdict'])


class McpCliTests(unittest.TestCase):
    def test_same_catalog_cli_runs_six_memory_cases(self):
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
        mapping = {case: 'mcp-substitute' for case in MCP.CASES}
        for suite in catalog['suites']:
            for case in suite.get('cases') or []:
                if case['id'] in mapping:
                    case['adapter'] = 'native'
                    case['native_driver'] = mapping[case['id']]
                    case['platforms'] = ['linux']
                    case['oracle'] = {'kind': 'mcp-result',
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
        for case in MCP.CASES:
            args += ['--case', case]
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
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
        completed = subprocess.run(
            cmd + ['judge', '--plan', str(run / 'plan.json'),
                   '--results', str(run / 'results'),
                   '--output', str(run / 'summary-independent.json')],
            cwd=root, capture_output=True, text=True)
        self.assertEqual(0, completed.returncode, completed.stderr)
        summary = json.loads((run / 'summary-independent.json').read_text())
        self.assertEqual(6, summary['checks']['passed'])
        self.assertTrue(summary['fixture_contract_pass'])
        self.assertFalse(summary['full_functional_pass'])


if __name__ == '__main__':
    unittest.main()
