"""Current harness identity and old package-source layering.

The test replaces only the target transport.  Planning, execution and the
independent judge are the formal acceptance entry points; package verification
is the original read-only builder verifier.
"""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance as entry
import acceptance_mcp as mcp

OLD_SOURCE = 'e493a236ca8297373dc4157a6c4bd8aef8683b4e'
CHECKS = ['ACC-005']


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def proof_dir(name):
    configured = os.environ.get('FN_IDENTITY_CHECK_DIR')
    root = Path(configured) if configured else ROOT / 'Logs/acceptance/mcp-identity-selftest'
    path = root / 'proofs' / (name + '-' + uuid.uuid4().hex)
    path.mkdir(parents=True, exist_ok=False)
    return path


def synthetic_package(base, source=None):
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    source = source or entry.git_head(ROOT)
    body = b'benign MCP identity bytes; never executed'
    body_sha = hashlib.sha256(body).hexdigest()
    manifest = {
        'schema': 'fakenet.mcp-candidate-manifest.v1',
        'source_commit': source,
        'source_snapshot_mode': 'commit',
        'exe_sha256': body_sha,
        'qualification_status': 'PARTIAL',
        'native_gaps': ['benign identity fixture'],
        'zip_entry_timestamp_utc': '2000-01-01T00:00:00Z',
        'files': [{'path': 'fakenetng-mcp.exe', 'size': len(body), 'sha256': body_sha}],
    }
    manifest_path = base / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
    package_path = base / 'candidate.zip'
    with zipfile.ZipFile(package_path, 'x') as archive:
        archive.writestr(zipfile.ZipInfo('fakenetng-mcp.exe', (2000, 1, 1, 0, 0, 0)), body)
        archive.writestr(zipfile.ZipInfo('mcp-candidate-manifest.json', (2000, 1, 1, 0, 0, 0)),
                         manifest_path.read_bytes())
    return package_path, manifest_path, manifest


def mcp_inputs(base, package, manifest, source):
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    target = {'platform': 'windows', 'hostname': 'DESKTOP-3FI41GR',
              'vm_uuid': '564de0b3-b23d-3d9f-4d52-3ec22c4cfdc0'}
    identity = {
        'candidate_id': 'mcp-' + source[:12],
        'source_commit': source,
        'package_sha256': sha256(package),
        'requirements_blob': 'b' * 40,
        'master_plan_blob': 'c' * 64,
    }
    channel = {'mcp_config_ref': str(base / 'protected-reference.toml'),
               'mcp_server': 'windows'}
    value = {
        'schema': 'fakenet.mcp-input.v2',
        'identity': identity,
        'package': str(Path(package).resolve()),
        'manifest': str(Path(manifest).resolve()),
        'manifest_sha256': sha256(manifest),
        'target': target,
        'config_identity': {'name': 'default.ini',
                            'sha256': sha256(ROOT / 'fakenet/configs/default.ini')},
        'endpoint': 'http://192.168.204.149:28788',
        'listen_ip': '192.168.204.149',
        'allowed_host': '192.168.204.1',
        'channel': channel,
        'actions': ['observe', 'mcp', 'core', 'service', 'fault', 'network', 'config', 'artifact'],
        'work_root': str(base),
        'installation_root': 'C:\\Program Files\\FakeNet-NG-MCP',
        'programdata_root': 'C:\\ProgramData\\FakeNet-NG-MCP',
        'guest_work_root': 'E:/acceptance-evidence',
    }
    return value


def environment(base, inputs, case='MCP-P02-FULL', checks=None):
    checks = CHECKS if checks is None else checks
    target = inputs['target']
    return {
        'schema': 'fakenet.acceptance-environment.v2',
        'targets': ['windows-vm'],
        'interpreters': {'python': sys.executable},
        'work_root': str(Path(base).resolve()),
        'allowed_actions': ['native', 'vm-execute'],
        'endpoints': [],
        'auth_refs': [],
        'native_runtime': {'transport': 'windows-mcp-velo',
                           'identity': target, **inputs['channel']},
        'mcp': inputs,
        'mcp_checks': {case: list(checks)},
    }


def candidate(package, manifest, inputs):
    return {
        'schema': 'fakenet.acceptance-candidate.v2',
        'source_commit': inputs['identity']['source_commit'],
        'package_path': str(Path(package).resolve()),
        'package_manifest': str(Path(manifest).resolve()),
        'package_sha256': inputs['identity']['package_sha256'],
        'offline_fixture': True,
    }


def cli(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = entry.main(['--root', str(ROOT), *map(str, args)])
    configured = os.environ.get('FN_IDENTITY_CHECK_DIR')
    if configured:
        with (Path(configured) / 'cli-transcripts.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'entry': 'acceptance.main', 'argv': ['--root', str(ROOT), *map(str, args)],
                         'returncode': code, 'stdout': stdout.getvalue(), 'stderr': stderr.getvalue()}) + '\n')
    return code, stdout.getvalue(), stderr.getvalue()


class MemoryBoundary:
    fixture = True

    def __init__(self, inputs):
        self.inputs = inputs

    def exchange(self, kind, value):
        if kind == 'target':
            return self.inputs['target']
        if kind == 'observe':
            return {'sections': {'routes': 'IPv4 fixed', 'dns_servers': [],
                                 'listen_ports': 'fixed scoped listener',
                                 'windivert_processes': {'services': [], 'processes': []},
                                 'services': 'Running'},
                    'service': {'computer': self.inputs['target']['hostname'],
                                'pid': 12, 'created': 'birth', 'state': 'Running'}}
        if kind == 'uuid':
            return '00000000-0000-4000-8000-000000000001'
        if kind == 'powershell':
            from pathlib import PureWindowsPath
            manifest = mcp.read(self.inputs['manifest'])
            exe = next(item for item in manifest['files']
                       if item['path'] == 'fakenetng-mcp.exe')
            payload = {
                'image': str(PureWindowsPath(self.inputs['installation_root']) / 'fakenetng-mcp.exe'),
                'sha256': exe['sha256'],
                'pid': 12, 'birth': '1234', 'enabled': False, 'grace': 60,
                'fault_exists': False,
                'service_config': {'listen_ip': self.inputs['listen_ip'], 'listen_port': 28788,
                                   'allowed_host_ips': [self.inputs['allowed_host']],
                                   'extra_control_ports': []},
            }
            if 'fault_exists=' not in value['command']:
                if 'grace=$cfg.stop_grace_seconds' in value['command']:
                    payload = {'enabled': False, 'grace': 60}
                else:
                    raise AssertionError('unexpected original PowerShell command')
            return {'output': json.dumps(payload), 'raw': json.dumps(payload),
                    'exit_code': 0, 'is_error': False}
        if kind != 'http':
            raise AssertionError('unexpected pure-memory boundary action: ' + kind)
        request = json.loads(value['data'])
        tool = request['params']['name']
        args = request['params']['arguments']
        if tool == 'get_status':
            payload = {'state': 'stopped', 'state_version': 7, 'run_id': None,
                       'config_identity': self.inputs['config_identity']}
        elif tool == 'ping':
            payload = {'service': 'fakenetng-mcp',
                       'build_identity': {'source_commit': self.inputs['identity']['source_commit'],
                                          'manifest_sha256': self.inputs['manifest_sha256']}}
        elif tool in ('create_config', 'stop'):
            payload = {'error': {'code': 'controller_identity_missing'}}
        elif tool == 'read_config' and ('..' in args['name'] or ':' in args['name']):
            payload = {'error': {'code': 'path_escape_blocked'}}
        elif tool == 'list_artifacts':
            payload = {'artifacts': []}
        elif tool == 'read_config':
            payload = {'name': 'default.ini', 'content': '[FakeNet]\nDumpPackets = No\n',
                       'sha256': self.inputs['config_identity']['sha256']}
        else:
            payload = {}
        body = {'jsonrpc': '2.0', 'id': 1,
                'result': {'content': [{'type': 'text', 'text': json.dumps(payload)}]}}
        return {'status': 200, 'headers': {'Content-Type': 'application/json'},
                'body': json.dumps(body).encode(), 'http_error': False}


class PackageLayerTests(unittest.TestCase):
    def prepare(self, package, manifest, inputs, base):
        candidate_value = candidate(package, manifest, inputs)
        environment_value = environment(base, inputs)
        write_json(base / 'candidate.json', candidate_value)
        write_json(base / 'environment.json', environment_value)
        result = cli('plan', '--mode', 'selected', '--case', 'MCP-P02-FULL',
                     '--candidate', base / 'candidate.json',
                     '--environment', base / 'environment.json',
                     '--output', base / 'run/plan.json')
        self.assertEqual(0, result[0], result)
        return json.loads((base / 'run/plan.json').read_text(encoding='utf-8'))

    def test_old_package_current_harness_plan_execute_independent_judge(self):
        base = proof_dir('old-package-current-harness')
        package, manifest, unused = synthetic_package(base / 'package', OLD_SOURCE)
        self.assertEqual(OLD_SOURCE, json.loads(manifest.read_text())['source_commit'])
        before = (sha256(package), sha256(manifest))
        inputs = mcp_inputs(base, package, manifest, OLD_SOURCE)
        plan = self.prepare(package, manifest, inputs, base)
        self.assertEqual(OLD_SOURCE, plan['source_commit'])
        self.assertEqual(OLD_SOURCE, plan['candidate']['source_commit'])
        self.assertEqual(sha256(manifest), plan['candidate']['package_manifest_sha256'])
        self.assertEqual(entry.sha256(ROOT / 'tools/acceptance.py'),
                         plan['native_source_hashes']['tools/acceptance.py'])
        self.assertFalse(plan['blocked'])
        self.assertEqual('PARTIAL', json.loads(manifest.read_text())['qualification_status'])
        with mock.patch.object(mcp, 'NativeBoundary',
                                        side_effect=lambda *args, **kwargs: MemoryBoundary(inputs)):
            result = cli('execute', '--plan', base / 'run/plan.json')
        self.assertEqual(0, result[0], result)
        result = cli('judge', '--plan', base / 'run/plan.json',
                     '--results', base / 'run/results',
                     '--output', base / 'run/independent.json')
        self.assertEqual(0, result[0], result)
        summary = json.loads((base / 'run/independent.json').read_text())
        self.assertTrue(summary['fixture_contract_pass'])
        self.assertFalse(summary['full_functional_pass'])
        self.assertEqual(1, summary['checks']['passed'])
        result_value = mcp.read(base / 'run/results/MCP-P02-FULL/driver/mcp-result.json')
        self.assertEqual(OLD_SOURCE, result_value['identity']['source_commit'])
        self.assertTrue(result_value['fixture'])
        self.assertEqual(before, (sha256(package), sha256(manifest)))

        self.assert_rehashed_judge_rejects(base, inputs, plan)

    def assert_rehashed_judge_rejects(self, base, inputs, plan):
        import shutil
        original = base / 'run'
        for mutation in ('missing-pins', 'receipt-target', 'trace-target'):
            root = proof_dir('independent-' + mutation)
            run = root / 'run'
            shutil.copytree(original, run)
            # Relocate every original path and rebuild all legitimate outer hashes.
            for path in run.rglob('*.json'):
                path.write_text(path.read_text().replace(str(original), str(run)), encoding='utf-8')
            plan_path = run / 'plan.json'
            candidate_plan = mcp.read(plan_path)
            receipt_path = run / 'results/MCP-P02-FULL/receipt.json'
            receipt = mcp.read(receipt_path)
            if mutation == 'missing-pins':
                candidate_plan.pop('native_source_hashes')
                write_json(plan_path, candidate_plan)
            elif mutation == 'receipt-target':
                receipt['native_target']['hostname'] = 'FOREIGN-HOST'
            else:
                trace_path = run / 'results/MCP-P02-FULL/driver/units/ACC-005/trace.json'
                trace = mcp.read(trace_path)
                trace['target']['hostname'] = 'FOREIGN-HOST'
                write_json(trace_path, trace)
            # Relocation changes legitimate nested path evidence too; refresh
            # its exact indexed hashes before testing the semantic mismatch.
            def refresh_links(value):
                if isinstance(value, dict):
                    if isinstance(value.get('path'), str) and 'sha256' in value:
                        path = Path(value['path'])
                        if path.is_file():
                            value['sha256'] = sha256(path)
                    for child in value.values():
                        refresh_links(child)
                elif isinstance(value, list):
                    for child in value:
                        refresh_links(child)
            for iteration in range(4):
                for path in (run / 'results').rglob('*.json'):
                    if path == receipt_path or path.name == 'results.json':
                        continue
                    value = mcp.read(path)
                    refresh_links(value)
                    write_json(path, value)
            for artifact in receipt['artifacts']:
                artifact['sha256'] = sha256(artifact['path'])
            write_json(receipt_path, receipt)
            index_path = run / 'results/results.json'
            index = mcp.read(index_path)
            index['plan_sha256'] = sha256(plan_path)
            for item in index['receipts']:
                item['sha256'] = sha256(item['path'])
            write_json(index_path, index)
            response = cli('judge', '--plan', plan_path, '--results', run / 'results',
                           '--output', root / 'refused.json')
            write_json(root / 'cli-response.json', {'rc': response[0], 'stdout': response[1], 'stderr': response[2]})
            self.assertNotEqual(0, response[0], response)
            combined = response[1] + response[2]
            if mutation == 'missing-pins':
                self.assertIn('complete native source pins', combined)
            else:
                summary = mcp.read(root / 'refused.json')
                combined += json.dumps(summary)
                self.assertIn('receipt identity differs' if mutation == 'receipt-target' else 'unit trace identity mismatch', combined)
                self.assertFalse(summary['fixture_contract_pass'])

    def test_dependency_expansion_keeps_only_package_cases_in_layer(self):
        base = proof_dir('dependency-expansion')
        package, manifest, unused = synthetic_package(base / 'package')
        source = entry.git_head(ROOT)
        inputs = mcp_inputs(base, package, manifest, source)
        env = environment(base, inputs, 'MCP-P04-FULL', ['ACC-019'])
        candidate_value = candidate(package, manifest, inputs)
        write_json(base / 'candidate.json', candidate_value)
        write_json(base / 'environment.json', env)
        result = cli('plan', '--mode', 'selected', '--case', 'MCP-P04-FULL',
                     '--candidate', base / 'candidate.json',
                     '--environment', base / 'environment.json',
                     '--output', base / 'run/plan.json')
        self.assertEqual(0, result[0], result)
        plan = json.loads((base / 'run/plan.json').read_text())
        self.assertEqual(['MCP-P03-FULL', 'MCP-P04-FULL'], plan['required_cases'])
        self.assertEqual(['ACC-008'], plan['required_checks']['MCP-P03-FULL'])
        self.assertEqual([], list(plan['blocked']))
        old = proof_dir('mixed-old-source')
        old_package, old_manifest, unused = synthetic_package(old / 'package', source='a' * 40)
        old_inputs = mcp_inputs(old, old_package, old_manifest, 'a' * 40)
        old_candidate = candidate(old_package, old_manifest, old_inputs)
        old_env = environment(old, old_inputs)
        write_json(old / 'candidate.json', old_candidate)
        write_json(old / 'environment.json', old_env)
        result = cli('plan', '--mode', 'selected', '--case', 'MCP-P02-FULL',
                     '--case', 'CORE-REGRESSION-SELFTEST',
                     '--candidate', old / 'candidate.json',
                     '--environment', old / 'environment.json',
                     '--output', old / 'run/plan.json')
        self.assertNotEqual(0, result[0], result)
        self.assertIn('does not match current HEAD', result[2])
        self.assertFalse((old / 'run/plan.json').exists())

    def test_real_historical_blob_equality_and_mixed_build_compatibility(self):
        import subprocess
        base = proof_dir('source-identity')
        previous = '4f09102f503bad49d390179b6751d71ceb7f2845'
        compared = '2c70e2318372f022934b6feda19642885bed3be1'
        current = entry.git_head(ROOT)
        # The received T011 commit left the scheduler unchanged, but changed the planner.
        self.assertTrue(entry._git_objects_equal(ROOT, previous, compared, ['tools/acceptance_scheduler.py']))
        self.assertFalse(entry._git_objects_equal(ROOT, previous, compared, ['tools/acceptance.py']))
        self.assertFalse(entry._git_objects_equal(ROOT, previous, compared, ['missing-required-source.py']))
        write_json(base / 'blob-observations.json', {'source': previous, 'head': compared,
                   'unchanged': 'tools/acceptance_scheduler.py', 'changed': 'tools/acceptance.py',
                   'unrelated_path_reuse': True, 'changed_or_missing_refused': True,
                   'scope': 'real Git batch parser; not full source/mixed functional execution'})
        package, manifest, unused = synthetic_package(base / 'package', current)
        inputs = mcp_inputs(base, package, manifest, current)
        env = environment(base, inputs)
        # No offline-pytest permission: the source case remains honestly blocked.
        env['allowed_actions'] = ['offline-artifacts']
        write_json(base / 'candidate.json', candidate(package, manifest, inputs))
        write_json(base / 'environment.json', env)
        response = cli('plan', '--mode', 'selected', '--case', 'BUILD-PACKAGE-IDENTITY',
                       '--case', 'CORE-REGRESSION-SELFTEST', '--candidate', base / 'candidate.json',
                       '--environment', base / 'environment.json', '--output', base / 'run/plan.json')
        write_json(base / 'response.json', {'rc': response[0], 'stdout': response[1], 'stderr': response[2]})
        self.assertEqual(0, response[0], response)
        plan = mcp.read(base / 'run/plan.json')
        self.assertEqual(sha256(manifest), plan['candidate']['package_manifest_sha256'])
        self.assertNotIn('BUILD-PACKAGE-IDENTITY', plan['blocked'])
        # Exercise the full registry gate with protocol bytes supplied only at
        # the Git process boundary. This is an OS-metadata fixture, not a new
        # repository/commit and not a claim that a deployed candidate is equal.
        metadata_records = []
        for mode in ('unchanged', 'changed', 'missing'):
            def metadata(argv, **kwargs):
                if argv[-2:] == ['rev-parse', '--show-toplevel']:
                    return subprocess.CompletedProcess(argv, 0, str(ROOT) + '\n', '')
                if argv[-2:] == ['rev-parse', 'HEAD']:
                    return subprocess.CompletedProcess(argv, 0, 'f' * 40 + '\n', '')
                self.assertEqual('cat-file', argv[-2])
                self.assertEqual('--batch-check', argv[-1])
                queries = kwargs['input'].splitlines()
                rows = []
                for i, query in enumerate(queries):
                    name = query.split(':', 1)[1]
                    digest = sha256(ROOT / name)[:40]
                    rows.append(query + ' missing' if mode == 'missing' and i == 1 else
                                ('e' * 40 if mode == 'changed' and i == 1 else digest) + ' blob 1')
                output = '\n'.join(rows) + '\n'
                metadata_records.append({'mode': mode, 'argv': argv, 'input': kwargs['input'],
                                         'returncode': 0, 'stdout': output, 'fixture': True})
                return subprocess.CompletedProcess(argv, 0, output, '')
            with mock.patch.object(entry.subprocess, 'run', side_effect=metadata):
                if mode == 'unchanged':
                    entry.validate_plan_registry(ROOT, plan, base / 'run/plan.json')
                else:
                    with self.assertRaisesRegex(entry.InputError, 'source plan is not valid'):
                        entry.validate_plan_registry(ROOT, plan, base / 'run/plan.json')
        write_json(base / 'metadata-protocol-originals.json', metadata_records)

    def test_bad_source_package_target_and_pin_rejected_before_driver(self):
        base = proof_dir('rejections')
        package, manifest, unused = synthetic_package(base / 'package')
        source = entry.git_head(ROOT)
        inputs = mcp_inputs(base, package, manifest, source)
        plan = self.prepare(package, manifest, inputs, base)
        mutations = {
            'package': lambda p: p['candidate'].update(package_sha256='f' * 64),
            'manifest': lambda p: p['candidate'].update(
                package_manifest=str(base / 'other-manifest.json')),
            'source': lambda p: (p.update(source_commit='a' * 40),
                                p['candidate'].update(source_commit='a' * 40)),
            'target': lambda p: p['environment']['mcp']['target'].update(hostname='OTHER-HOST'),
            'pin': lambda p: p['native_source_hashes'].update(
                {'tools/acceptance.py': 'f' * 64}),
            'missing-source': lambda p: p['source_hashes']['MCP-P02-FULL'].pop(
                'test/mcp/acceptance/run_p02_acc.py'),
        }
        reasons = {'package': 'MCP package candidate differs',
                   'manifest': 'MCP package candidate differs',
                   'source': 'MCP package candidate differs',
                   'target': 'MCP target differs',
                   'pin': 'native candidate source changed',
                   'missing-source': 'source set differs'}
        with mock.patch.object(mcp, 'NativeBoundary',
                                        side_effect=AssertionError('driver must not start')) as boundary:
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    bad = copy.deepcopy(plan)
                    mutate(bad)
                    local = base / ('bad-' + name)
                    local.mkdir()
                    path = local / 'plan.json'
                    bad['run_dir'] = str(local)
                    write_json(path, bad)
                    with self.assertRaisesRegex(entry.InputError, reasons[name]) as caught:
                        entry.execute_plan(ROOT, path)
                    write_json(local / 'refusal.json', {'mutation': name, 'reason': str(caught.exception),
                                                       'driver_calls': boundary.call_count})
                    self.assertEqual(0, boundary.call_count)
                    self.assertFalse((local / 'results').exists())
                    self.assertFalse((base / 'run/results').exists())


if __name__ == '__main__':
    unittest.main()
