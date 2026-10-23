"""MCP actual configuration baseline and current-run recovery ownership.

The OS target is replaced only by an in-memory HTTP/service boundary.  The
formal plan/execute/judge entry points, package verifier, original ACC-005
business function and the independent oracle remain the product code.
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
import acceptance_mcp_oracles as oracle

DEFAULT_CONTENT = (ROOT / 'fakenet/configs/default.ini').read_text(encoding='utf-8')
DEFAULT_SHA = hashlib.sha256(DEFAULT_CONTENT.encode()).hexdigest()


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def proof_dir(name):
    root = Path(os.environ.get('FN_IDENTITY_CHECK_DIR', tempfile.mkdtemp(prefix='mcp-baseline-')))
    path = root / 'proofs' / (name + '-' + uuid.uuid4().hex)
    path.mkdir(parents=True, exist_ok=False)
    return path


def synthetic_package(base):
    base = Path(base)
    base.mkdir(parents=True, exist_ok=True)
    body = b'benign MCP baseline service bytes; never executed'
    body_sha = hashlib.sha256(body).hexdigest()
    manifest = {
        'schema': 'fakenet.mcp-candidate-manifest.v1',
        'source_commit': entry.git_head(ROOT),
        'source_snapshot_mode': 'commit',
        'exe_sha256': body_sha,
        'qualification_status': 'PARTIAL',
        'native_gaps': ['benign baseline fixture'],
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


def make_inputs(base, package, manifest, source):
    base = Path(base)
    target = {'platform': 'windows', 'hostname': 'DESKTOP-3FI41GR',
              'vm_uuid': '564de0b3-b23d-3d9f-4d52-3ec22c4cfdc0'}
    channel = {'mcp_config_ref': str(base / 'protected-reference.toml'),
               'mcp_server': 'windows'}
    identity = {'candidate_id': 'mcp-' + source[:12], 'source_commit': source,
                'package_sha256': sha256(package), 'requirements_blob': 'b' * 40,
                'master_plan_blob': 'c' * 64}
    return {
        'schema': 'fakenet.mcp-input.v2', 'identity': identity,
        'package': str(Path(package).resolve()), 'manifest': str(Path(manifest).resolve()),
        'manifest_sha256': sha256(manifest), 'target': target,
        'config_identity': {'name': 'default.ini', 'sha256': DEFAULT_SHA},
        'endpoint': 'http://192.168.204.149:28788', 'listen_ip': '192.168.204.149',
        'allowed_host': '192.168.204.1', 'channel': channel,
        'actions': ['observe', 'mcp', 'core', 'service', 'fault', 'network', 'config', 'artifact'],
        'work_root': str(base.resolve()),
        'installation_root': 'C:\\Program Files\\FakeNet-NG-MCP',
        'programdata_root': 'C:\\ProgramData\\FakeNet-NG-MCP',
        'guest_work_root': 'E:/acceptance-evidence',
    }


def make_environment(base, inputs, case, checks):
    target = inputs['target']
    return {
        'schema': 'fakenet.acceptance-environment.v2', 'targets': ['windows-vm'],
        'interpreters': {'python': sys.executable}, 'work_root': str(Path(base).resolve()),
        'allowed_actions': ['native', 'vm-execute'], 'endpoints': [], 'auth_refs': [],
        'native_runtime': {'transport': 'windows-mcp-velo', 'identity': target, **inputs['channel']},
        'mcp': inputs, 'mcp_checks': {case: list(checks)},
    }


def make_candidate(inputs, package, manifest):
    return {'schema': 'fakenet.acceptance-candidate.v2', 'source_commit': inputs['identity']['source_commit'],
            'package_path': str(Path(package).resolve()), 'package_manifest': str(Path(manifest).resolve()),
            'package_sha256': inputs['identity']['package_sha256'], 'offline_fixture': True}


def cli(*args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = entry.main(['--root', str(ROOT), *map(str, args)])
    return code, stdout.getvalue(), stderr.getvalue()


class MemoryBoundary:
    fixture = True

    def __init__(self, inputs, service=None):
        self.inputs = inputs
        self.service = service

    def _payload(self, payload):
        body = {'jsonrpc': '2.0', 'id': 1,
                'result': {'content': [{'type': 'text', 'text': json.dumps(payload)}]}}
        return {'status': 200, 'headers': {'Content-Type': 'application/json'},
                'body': json.dumps(body).encode(), 'http_error': False}

    def exchange(self, kind, value):
        if kind == 'target':
            return self.inputs['target']
        if kind == 'observe':
            return {'sections': {'routes': 'fixed', 'dns_servers': [], 'listen_ports': 'fixed',
                                 'windivert_processes': {'services': [], 'processes': []},
                                 'services': 'Running'},
                    'service': {'computer': self.inputs['target']['hostname'], 'pid': 12,
                                'created': 'birth', 'state': 'stopped'}}
        if kind == 'uuid':
            return '00000000-0000-4000-8000-000000000001'
        if kind in ('sleep', 'time', 'monotonic'):
            return None if kind == 'sleep' else 1700000000.0
        if kind == 'powershell':
            from pathlib import PureWindowsPath
            manifest = mcp.read(self.inputs['manifest'])
            exe = next(item for item in manifest['files'] if item['path'] == 'fakenetng-mcp.exe')
            payload = {'image': str(PureWindowsPath(self.inputs['installation_root']) / 'fakenetng-mcp.exe'),
                       'sha256': exe['sha256'], 'pid': 12, 'birth': '1234',
                       'enabled': False, 'grace': 60, 'fault_exists': False,
                       'service_config': {'listen_ip': self.inputs['listen_ip'], 'listen_port': 28788,
                                          'allowed_host_ips': [self.inputs['allowed_host']],
                                          'extra_control_ports': []}}
            if 'fault_exists=' not in value['command']:
                if 'grace=$cfg.stop_grace_seconds' in value['command']:
                    payload = {'enabled': False, 'grace': 60}
                else:
                    raise AssertionError('unexpected PowerShell action')
            return {'output': json.dumps(payload), 'raw': json.dumps(payload),
                    'exit_code': 0, 'is_error': False}
        if kind != 'http':
            raise AssertionError('unexpected OS action: ' + kind)
        request = json.loads(value['data'])
        tool = request['params']['name']
        args = request['params']['arguments']
        headers = {key.lower(): item for key, item in value['headers'].items()}
        controller = headers.get('x-fakenet-controller-id')
        return self._payload(self.http(tool, args, controller))

    def http(self, tool, args, controller):
        if tool == 'get_status':
            return self.status()
        if tool == 'ping':
            return {'service': 'fakenetng-mcp',
                    'build_identity': {'source_commit': self.inputs['identity']['source_commit'],
                                       'manifest_sha256': self.inputs['manifest_sha256']}}
        if tool == 'read_config':
            name = args.get('name')
            if name != 'default.ini':
                return {'error': {'code': 'path_escape_blocked' if ('/' in name or '\\' in name or ':' in name or '..' in name) else 'config_not_found'}}
            return {'name': 'default.ini', 'sha256': DEFAULT_SHA, 'content': DEFAULT_CONTENT}
        if tool == 'get_events':
            return {'events': []}
        if tool == 'list_configs':
            return {'configs': [{'name': 'default.ini', 'builtin': True, 'size': len(DEFAULT_CONTENT), 'sha256': DEFAULT_SHA}]}
        if tool == 'list_artifacts':
            return {'artifacts': []}
        if tool == 'validate_config':
            return {'valid': True}
        if tool == 'create_config':
            return {'error': {'code': 'controller_identity_missing'}} if controller is None else self.create(args, controller)
        if tool == 'stop':
            return {'error': {'code': 'controller_identity_missing'}} if controller is None else self.stop(args, controller)
        raise AssertionError('unexpected HTTP tool: ' + str(tool))

    def status(self):
        raise NotImplementedError

    def create(self, args, controller):
        raise NotImplementedError

    def stop(self, args, controller):
        raise NotImplementedError


class NullBoundary(MemoryBoundary):
    def __init__(self, inputs, service=None):
        super().__init__(inputs, service)
        self.version = 1

    def status(self):
        return {'service': 'fakenetng-mcp', 'state': 'stopped', 'state_version': self.version,
                'run_id': None, 'controller': None, 'config_identity': None, 'error': None}

    def create(self, args, controller):
        raise AssertionError('read-only ACC-005 must not create a configuration')

    def stop(self, args, controller):
        return {'error': {'code': 'controller_identity_missing'}, 'state_version': self.version}


class MutableBoundary(MemoryBoundary):
    def __init__(self, inputs, service=None):
        super().__init__(inputs, service)
        self.version = 1
        self.state = 'stopped'
        self.run_id = None
        self.active = {'name': 'default.ini', 'sha256': DEFAULT_SHA}
        self.files = {'default.ini': (DEFAULT_CONTENT, DEFAULT_SHA)}
        self.controller = None

    def status(self):
        return {'service': 'fakenetng-mcp', 'state': self.state, 'state_version': self.version,
                'run_id': self.run_id, 'controller': self.controller,
                'config_identity': copy.deepcopy(self.active), 'error': None}

    def _version(self, changed=True, **extra):
        if changed:
            self.version += 1
        value = {'command_id': None, 'state_version': self.version,
                 'changed': bool(changed), 'in_progress': False, 'error': None}
        value.update(extra)
        return value

    def create(self, args, controller):
        name = args.get('name')
        if not isinstance(name, str) or name in self.files:
            return {'error': {'code': 'state_conflict'}, 'state_version': self.version}
        content = args.get('content')
        if not isinstance(content, str):
            return {'error': {'code': 'validation_failed'}, 'state_version': self.version}
        digest = hashlib.sha256(content.encode()).hexdigest()
        self.files[name] = (content, digest)
        return self._version(command_id=args.get('command_id'),
                             config_result={'name': name, 'sha256': digest,
                                            'builtin': False, 'deleted': False})

    def load(self, args, controller):
        name = args.get('name')
        if name not in self.files:
            return {'error': {'code': 'config_not_found'}, 'state_version': self.version}
        if self.state != 'stopped':
            return {'error': {'code': 'not_allowed_in_state'}, 'state_version': self.version}
        self.active = {'name': name, 'sha256': self.files[name][1]}
        return self._version(command_id=args.get('command_id'),
                             config_identity=copy.deepcopy(self.active))

    def start(self, args, controller):
        if controller is None or self.state != 'stopped':
            return {'error': {'code': 'state_conflict'}, 'state_version': self.version}
        self.state = 'healthy'
        self.controller = controller
        self.run_id = '11111111-1111-4111-8111-111111111111'
        return self._version(command_id=args.get('command_id'), run_id=self.run_id,
                             state='healthy', config_identity=copy.deepcopy(self.active))

    def stop(self, args, controller):
        if controller is None:
            return {'error': {'code': 'controller_identity_missing'}, 'state_version': self.version}
        if self.state != 'healthy' or self.controller != controller:
            return {'error': {'code': 'controller_conflict'}, 'state_version': self.version}
        self.state = 'stopped'
        self.run_id = None
        self.controller = None
        return self._version(command_id=args.get('command_id'), state='stopped',
                             run_id=None, config_identity=copy.deepcopy(self.active))

    def http(self, tool, args, controller):
        if tool == 'read_config':
            name = args.get('name')
            if name in self.files:
                return {'name': name, 'sha256': self.files[name][1], 'content': self.files[name][0]}
            return {'error': {'code': 'config_not_found'}}
        if tool == 'load_config':
            return self.load(args, controller)
        if tool == 'start':
            return self.start(args, controller)
        if tool == 'delete_config':
            name = args.get('name')
            if name == 'default.ini':
                return {'error': {'code': 'builtin_readonly'}, 'state_version': self.version}
            if name not in self.files or args.get('expected_sha256') != self.files[name][1]:
                return {'error': {'code': 'state_conflict'}, 'state_version': self.version}
            del self.files[name]
            return self._version(command_id=args.get('command_id'), name=name)
        return super().http(tool, args, controller)


class BaselineTests(unittest.TestCase):
    def prepare_plan(self, base, boundary_class, case, checks):
        package, manifest, unused = synthetic_package(base / 'package')
        source = entry.git_head(ROOT)
        inputs = make_inputs(base, package, manifest, source)
        env = make_environment(base, inputs, case, checks)
        candidate = make_candidate(inputs, package, manifest)
        write_json(base / 'candidate.json', candidate)
        write_json(base / 'environment.json', env)
        result = cli('plan', '--mode', 'selected', '--case', case,
                     '--candidate', base / 'candidate.json',
                     '--environment', base / 'environment.json',
                     '--output', base / 'run/plan.json')
        self.assertEqual(0, result[0], result)
        with mock.patch.object(mcp, 'NativeBoundary',
                               side_effect=lambda *a, **kw: boundary_class(inputs)):
            result = cli('execute', '--plan', base / 'run/plan.json')
        self.assertEqual(0, result[0], result)
        result = cli('judge', '--plan', base / 'run/plan.json',
                     '--results', base / 'run/results',
                     '--output', base / 'run/independent.json')
        self.assertEqual(0, result[0], result)
        return json.loads((base / 'run/independent.json').read_text()), inputs

    def test_null_baseline_keeps_null_and_runs_full_acc005_matrix(self):
        base = proof_dir('null-baseline')
        summary, inputs = self.prepare_plan(base, NullBoundary, 'MCP-P02-FULL', ['ACC-005'])
        self.assertTrue(summary['fixture_contract_pass'])
        self.assertFalse(summary['full_functional_pass'])
        trace = mcp.read(base / 'run/results/MCP-P02-FULL/driver/units/ACC-005/trace.json')
        self.assertEqual('stopped', trace['initial_status']['state'])
        self.assertIsNone(trace['initial_status']['config_identity'])
        self.assertIsNone(trace['final_status']['config_identity'])
        self.assertEqual([], [op for op in trace['config_operations'] if op.get('tool') == 'load_config'])
        result = mcp.read(base / 'run/results/MCP-P02-FULL/driver/units/ACC-005/result.json')
        checks = next(item for item in result['evidence'] if item['name'] == 'acc005-checks')
        values = mcp.read(checks['path'])
        self.assertTrue(all(values.values()), values)
        self.assertEqual(1, summary['checks']['passed'])

    def test_nonnull_owned_load_is_restored_and_owner_file_removed(self):
        base = proof_dir('nonnull-recovery')
        summary, inputs = self.prepare_plan(base, MutableBoundary, 'MCP-P02-FULL', ['ACC-010'])
        self.assertTrue(summary['fixture_contract_pass'])
        trace = mcp.read(base / 'run/results/MCP-P02-FULL/driver/units/ACC-010/trace.json')
        self.assertEqual('default.ini', trace['initial_status']['config_identity']['name'])
        self.assertEqual('default.ini', trace['final_status']['config_identity']['name'])
        self.assertEqual(DEFAULT_SHA, trace['final_status']['config_identity']['sha256'])
        self.assertTrue(any(op.get('tool') == 'load_config' for op in trace['config_operations']))
        result = mcp.read(base / 'run/results/MCP-P02-FULL/driver/units/ACC-010/result.json')
        names = [item['name'] for item in result['evidence']]
        self.assertIn('owned-restore-config', names)
        self.assertTrue(any(name.startswith('owned-config-delete-') for name in names))
        self.assertEqual(1, summary['checks']['passed'])


if __name__ == '__main__':
    unittest.main()
