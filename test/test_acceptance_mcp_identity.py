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
import tempfile
import unittest
from unittest import mock
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance as entry
import acceptance_mcp as mcp

OLD_PACKAGE = ROOT / 'dist/fakenet-egress-e493a23-20261021/fakenetng-mcp-candidate.zip'
OLD_MANIFEST = ROOT / 'dist/fakenet-egress-e493a23-20261021/mcp-candidate-manifest.json'
OLD_SOURCE = 'e493a236ca8297373dc4157a6c4bd8aef8683b4e'
OLD_PACKAGE_SHA = '64b1539f2ea60b6b0c0473107cab570023d720f240662bcbf396683c39dc3478'
OLD_MANIFEST_SHA = '2cb37dc7a2ada39b0f6e03a7595feb0760e94e18bb86053abb510f2a71892f54'
CHECKS = ['ACC-005']


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def proof_dir(name):
    root = Path(os.environ.get('FN_IDENTITY_CHECK_DIR', tempfile.mkdtemp(prefix='t011-proof-')))
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
        package, manifest = OLD_PACKAGE, OLD_MANIFEST
        self.assertEqual(OLD_SOURCE, json.loads(manifest.read_text())['source_commit'])
        before = (sha256(package), sha256(manifest))
        inputs = mcp_inputs(base, package, manifest, OLD_SOURCE)
        plan = self.prepare(package, manifest, inputs, base)
        self.assertEqual(OLD_SOURCE, plan['source_commit'])
        self.assertEqual(OLD_SOURCE, plan['candidate']['source_commit'])
        self.assertEqual(OLD_MANIFEST_SHA, plan['candidate']['package_manifest_sha256'])
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
        with mock.patch.object(mcp, 'NativeBoundary',
                                        side_effect=AssertionError('driver must not start')):
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    bad = copy.deepcopy(plan)
                    mutate(bad)
                    local = base / ('bad-' + name)
                    local.mkdir()
                    path = local / 'plan.json'
                    write_json(path, bad)
                    with self.assertRaises((ValueError, KeyError, OSError, RuntimeError)):
                        entry.execute_plan(ROOT, path)
                    self.assertFalse((local / 'results').exists())
                    self.assertFalse((base / 'run/results').exists())


if __name__ == '__main__':
    unittest.main()
