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
    configured = os.environ.get('FN_BASELINE_CHECK_DIR')
    root = Path(configured) if configured else ROOT / 'Logs/acceptance/mcp-baseline-selftest'
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
    configured = os.environ.get('FN_BASELINE_CHECK_DIR')
    if configured:
        with (Path(configured) / 'cli-transcripts.jsonl').open('a') as stream:
            stream.write(json.dumps({'entry': 'acceptance.main', 'argv': ['--root', str(ROOT), *map(str, args)],
                         'returncode': code, 'stdout': stdout.getvalue(), 'stderr': stderr.getvalue()}) + '\n')
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
        try:
            uuid.UUID(controller)
        except (ValueError, TypeError, AttributeError):
            return {'error': {'code': 'controller_identity_missing'}, 'state_version': self.version}
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


# Frozen b5eb4e6 run_unit source is fixture data, not a copy of the current
# restoration algorithm. It runs against the same pure-memory transport.
RECEIVED_RUN_UNIT_SOURCE = "def run_unit(unit,inputs,out,boundary,*,root=ROOT,fixture=None):\n mods=modules(root);session=BoundarySession(boundary,inputs);out=Path(out);writer=mods['helpers'].EvidenceWriter(out,'original-unit')\n args=original_args(inputs,out)\n if unit=='ACC-014' and 'ACC-014' in inputs.get('references',{}):\n  writer.add_evidence('capability-request-reference',inputs['references']['ACC-014'])\n  writer.add_evidence('capability-reference-scope',{'native_operation_performed':False,'reused_capability_only':True,'current_deployment_observed':False})\n  code=2;error=None\n  try:\n   code=__import__('acceptance_mcp_capabilities').evaluate(inputs['references']['ACC-014'],inputs,root,writer,fixture=bool(boundary.fixture) if fixture is None else fixture)\n  except (OSError,ValueError,KeyError,TypeError,AssertionError) as exc:\n   error={'type':type(exc).__name__,'message':str(exc)};writer.blocker=error\n  status={0:'pass',1:'fail',2:'blocked',3:'unknown'}.get(code,'unknown')\n  result=writer.write_result(acc_id=unit,p_id='headless',**inputs['identity'],environment_identity=json.dumps(inputs['target'],sort_keys=True),status=status)\n  trace={'schema':'fakenet.mcp-unit-trace.v1','unit':unit,'identity':inputs['identity'],'target':inputs['target'],'config_identity':inputs['config_identity'],'unit_root':str(out.resolve()),'records':[],'returncode':code,'error':error,'recovery_observed':True,'recovery_error':None,'origin':'closed-independent-capability-no-native-action'}\n  return result,trace\n code=3;error=None;before=None;after=None;service_before=None;recovery_error=None\n with session.activate():\n  # Original classes importing a channel still get this same recorded transport.\n  from unittest.mock import patch\n  with contextlib.ExitStack() as stack:\n   for module in mods.values():\n    if hasattr(module,'Win10VmChannel'):stack.enter_context(patch.object(module,'Win10VmChannel',lambda *a,**kw:session))\n   try:\n    actual=session.operation('target',{})\n    if actual!=inputs['target']:raise ValueError('observed VM differs from frozen identity')\n    initial=mods['run_p02_acc'].status(args.target_base_url)\n    if initial.get('state')!='stopped' or initial.get('run_id'):raise ValueError('MCP entry not idle; preserve foreign run')\n    ping=mods['run_p02_acc'].call(args.target_base_url,'ping',controller=None)\n    build=ping.get('build_identity') or {}\n    if build.get('source_commit')!=args.source_commit or build.get('manifest_sha256')!=inputs['manifest_sha256']:raise ValueError('deployed candidate build differs')\n    active=initial.get('config_identity')\n    if active and any(active.get(k)!=inputs['config_identity'][k] for k in ('name','sha256')):raise ValueError('active configuration differs')\n    service_before=service_preflight(session,inputs);writer.add_evidence('installed-service-before',service_before)\n    before=session.operation('observe',{})\n    writer.add_evidence('environment-before',before)\n    code=invoke_unit(unit,args,session,writer,mods)\n   except Exception as exc:error={'type':type(exc).__name__,'message':str(exc)};writer.blocker=error\n   finally:\n    if before is not None:\n     try:\n      if getattr(session,'preserve_scene',False):raise ValueError('controlled operation unresolved; preserve scene')\n      final=mods['run_p02_acc'].status(args.target_base_url)\n      if final.get('run_id') in session.owned_runs:\n       stopped=mods['run_p02_acc'].call(args.target_base_url,'stop',{'command_id':mods['run_p02_acc'].unique_command('owned-final-stop'),'expected_state_version':final['state_version']},timeout=420)\n       writer.add_evidence('owned-final-stop',stopped);final=mods['run_p02_acc'].status(args.target_base_url)\n      if final.get('state')=='stopped' and not final.get('run_id'):\n       current=final.get('config_identity') or {}\n       if any(current.get(k)!=inputs['config_identity'][k] for k in ('name','sha256')):\n        frozen=mods['run_p02_acc'].call(args.target_base_url,'read_config',{'name':inputs['config_identity']['name']},controller=None)\n        if frozen.get('sha256')!=inputs['config_identity']['sha256']:raise ValueError('frozen configuration changed; do not restore by name alone')\n        restored=mods['run_p02_acc'].call(args.target_base_url,'load_config',{'name':inputs['config_identity']['name'],'command_id':mods['run_p02_acc'].unique_command('owned-restore-config'),'expected_state_version':final['state_version']})\n        writer.add_evidence('owned-restore-config',restored)\n        if restored.get('error'):raise ValueError('configuration restore rejected')\n       for name in sorted(session.owned_configs.copy()):\n        item=mods['run_p02_acc'].call(args.target_base_url,'read_config',{'name':name},controller=None)\n        if item.get('error'):raise ValueError('owned config observation missing')\n        state=mods['run_p02_acc'].status(args.target_base_url)\n        deleted=mods['run_p02_acc'].call(args.target_base_url,'delete_config',{'name':name,'expected_sha256':item['sha256'],'command_id':mods['run_p02_acc'].unique_command('owned-config-delete'),'expected_state_version':state['state_version']})\n        writer.add_evidence('owned-config-delete-'+str(len(writer.evidence)),deleted)\n        if deleted.get('error'):raise ValueError('owned config cleanup rejected')\n       final=mods['run_p02_acc'].status(args.target_base_url)\n      writer.add_evidence('final-status',final)\n      if any((final.get('config_identity') or {}).get(k)!=inputs['config_identity'][k] for k in ('name','sha256')):raise ValueError('restored configuration identity not observed')\n      if service_before is not None:\n       restored_mode=mods['helpers'].configure_fault_service(session,service_before['enabled'],service_before['grace'])\n       writer.add_evidence('service-settings-restored',restored_mode)\n       service_after=service_preflight(session,inputs);writer.add_evidence('installed-service-after',service_after)\n       if any(service_after[k]!=service_before[k] for k in ('image','sha256','enabled','grace','fault_exists','service_config')):raise ValueError('service settings/image restoration not observed')\n      after=session.operation('observe',{});writer.add_evidence('environment-after',after)\n      from fakenet.mcp.baseline import audit_compare\n      differences=audit_compare(before['sections'],after['sections'])\n      writer.add_evidence('environment-diff',differences)\n      if differences or final.get('state')!='stopped' or final.get('run_id'):raise ValueError('MCP recovery not established; preserve original failed state')\n     except Exception as exc:\n      recovery_error={'type':type(exc).__name__,'message':str(exc)};error=error or recovery_error;writer.blocker=error;code=1\n status={0:'pass',1:'fail',2:'blocked',3:'unknown'}.get(code,'unknown')\n result=writer.write_result(acc_id=unit,p_id='headless',**inputs['identity'],environment_identity=json.dumps(inputs['target'],sort_keys=True),status=status)\n trace={'schema':'fakenet.mcp-unit-trace.v1','unit':unit,'identity':inputs['identity'],'target':inputs['target'],'config_identity':inputs['config_identity'],'unit_root':str(out.resolve()),'records':session.records,'returncode':code,'error':error,'recovery_observed':before is not None and after is not None,'recovery_error':recovery_error}\n if isinstance(boundary,ReplayBoundary):\n  try:boundary.finish()\n  except ReplayMismatch as exc:\n   reason=(error or {}).get('message') or status\n   raise ReplayMismatch(str(exc)+'; original unit failure: '+reason) from exc\n return result,trace\n"
RECEIVED_RUN_UNIT_SHA256 = '84e179f42cfb83835ec3285f16e63f2c16ae83c890f0761cc3852632657342f6'


class FaultNullBoundary(NullBoundary):
    def __init__(self, inputs, fault):
        super().__init__(inputs)
        self.fault, self.calls, self.status_count = fault, [], 0

    def status(self):
        self.status_count += 1
        value = super().status()
        if self.status_count == 1:
            if self.fault == 'missing': value.pop('config_identity')
            if self.fault == 'empty': value['config_identity'] = {}
            if self.fault == 'bool-version': value['state_version'] = True
            if self.fault == 'read-failed': raise OSError('fixture status unavailable')
        if self.status_count >= 4 and self.fault in ('foreign-active', 'foreign-version'):
            value['state_version'] = 2
            if self.fault == 'foreign-active': value['config_identity'] = {'name':'foreign.ini','sha256':'e'*64}
        return value

    def http(self, tool, args, controller):
        self.calls.append((tool, copy.deepcopy(args)))
        if tool == 'create_config' and self.fault == 'lost':
            raise OSError('fixture mutation reply lost')
        if tool == 'create_config' and self.fault == 'malformed': return {}
        response = super().http(tool, args, controller)
        if tool == 'read_config' and args.get('name') == 'default.ini' and self.fault == 'wrong-binding':
            response['sha256'] = 'e' * 64
        return response


class FaultMutableBoundary(MutableBoundary):
    def __init__(self, inputs, fault):
        super().__init__(inputs)
        self.fault, self.calls, self.injected = fault, [], False

    def http(self, tool, args, controller):
        self.calls.append((tool, copy.deepcopy(args)))
        response = super().http(tool, args, controller)
        if tool == 'load_config' and not response.get('error') and args['name'] != 'default.ini':
            if self.fault == 'lost': raise OSError('fixture load reply lost after acceptance')
            if self.fault == 'wrong-name': response['config_identity']['name'] = 'other.ini'
            if self.fault == 'foreign-replay': response['replayed'] = True
            if self.fault == 'wrong-version': response['state_version'] = args['expected_state_version']
        if tool == 'stop' and not response.get('error') and not self.injected:
            self.injected = True
            if self.fault == 'foreign-version': self.version += 1
            if self.fault == 'foreign-file':
                name = next(name for name in self.files if name != 'default.ini')
                self.files[name] = ('foreign bytes', 'e' * 64)
        return response


class AuditNullBoundary(MutableBoundary):
    def __init__(self, inputs):
        super().__init__(inputs)
        self.active, self.calls = None, []

    def http(self, tool, args, controller):
        self.calls.append((tool, copy.deepcopy(args)))
        if tool == 'read_config' and any(part in args['name'] for part in ('/', '\\', ':', '..')):
            return MemoryBoundary.http(self, tool, args, controller)
        return super().http(tool, args, controller)


class IndependentBaselineTests(unittest.TestCase):
    def inputs(self, base):
        package, manifest, unused = synthetic_package(base / 'package')
        return make_inputs(base, package, manifest, entry.git_head(ROOT)), package, manifest

    def execute(self, base, boundary, check):
        inputs, package, manifest = self.inputs(base)
        target = boundary(inputs)
        write_json(base/'candidate.json', make_candidate(inputs, package, manifest))
        write_json(base/'environment.json', make_environment(base, inputs, 'MCP-P02-FULL', [check]))
        planned = cli('plan','--mode','selected','--case','MCP-P02-FULL',
                      '--candidate',base/'candidate.json','--environment',base/'environment.json',
                      '--output',base/'run/plan.json')
        self.assertEqual(0,planned[0],planned)
        with mock.patch.object(mcp,'NativeBoundary',side_effect=lambda *a,**kw:target):
            executed=cli('execute','--plan',base/'run/plan.json')
        judged=cli('judge','--plan',base/'run/plan.json','--results',base/'run/results',
                   '--output',base/'run/independent.json')
        write_json(base/'responses.json',{'execute':executed,'judge':judged})
        trace=mcp.read(base/('run/results/MCP-P02-FULL/driver/units/'+check+'/trace.json'))
        return inputs,target,executed,judged,trace

    def test_exact_received_algorithm_changes_null_and_current_preserves_it(self):
        base=proof_dir('received-algorithm')
        inputs,unused,unused2=self.inputs(base)
        self.assertEqual(RECEIVED_RUN_UNIT_SHA256,hashlib.sha256(RECEIVED_RUN_UNIT_SOURCE.encode()).hexdigest())
        namespace=dict(vars(mcp))
        exec(compile(RECEIVED_RUN_UNIT_SOURCE,'received-b5eb4e6-run-unit.py','exec'),namespace)
        old=AuditNullBoundary(inputs)
        old_result,old_trace=namespace['run_unit']('ACC-005',inputs,base/'old',old,root=ROOT)
        new=AuditNullBoundary(inputs)
        new_result,new_trace=mcp.run_unit('ACC-005',inputs,base/'new',new,root=ROOT)
        self.assertEqual('pass',old_result['status'],old_trace)
        self.assertIsNotNone(old.active)
        self.assertTrue(any(tool=='load_config' for tool,args in old.calls))
        self.assertEqual('pass',new_result['status'],new_trace)
        self.assertIsNone(new.active)
        self.assertFalse(any(tool=='load_config' for tool,args in new.calls))
        write_json(base/'comparison.json',{'received_function_sha256':RECEIVED_RUN_UNIT_SHA256,
          'old_final':old.active,'new_final':new.active,'old_calls':old.calls,'new_calls':new.calls,
          'old_status':old_result['status'],'new_status':new_result['status']})

    def test_complete_snapshot_unknown_and_external_state_fail_without_cleanup_writes(self):
        faults={'missing':'complete snapshot','empty':'identity name missing','bool-version':'state_version',
                'read-failed':'fixture status unavailable','wrong-binding':'input configuration binding differs',
                'foreign-active':'version continuity',
                'foreign-version':'version continuity','lost':'response is unresolved','malformed':'response is unresolved'}
        for fault,reason in faults.items():
            with self.subTest(fault=fault):
                base=proof_dir('null-'+fault)
                inputs,target,executed,judged,trace=self.execute(base,lambda x:FaultNullBoundary(x,fault),'ACC-005')
                self.assertNotEqual(0,executed[0],executed)
                self.assertNotEqual(0,judged[0],judged)
                details=json.dumps(trace.get('error'))+json.dumps(trace.get('recovery_error'))
                self.assertIn(reason,details)
                self.assertFalse(trace['recovery_observed'])
                self.assertFalse(any(tool in ('load_config','delete_config') for tool,args in target.calls))

    def test_owned_receipt_hash_replay_and_continuity_fail_for_corresponding_reason(self):
        faults={'lost':'response is unresolved','wrong-name':'response is unresolved',
                'foreign-replay':'response is unresolved','wrong-version':'response is unresolved',
                'foreign-version':'version continuity','foreign-file':'owned config content changed'}
        for fault,reason in faults.items():
            with self.subTest(fault=fault):
                base=proof_dir('owned-'+fault)
                inputs,target,executed,judged,trace=self.execute(base,lambda x:FaultMutableBoundary(x,fault),'ACC-010')
                self.assertNotEqual(0,executed[0],executed)
                self.assertNotEqual(0,judged[0],judged)
                self.assertIn(reason,json.dumps(trace.get('recovery_error')))
                self.assertFalse(trace['recovery_observed'])
                self.assertFalse(any(tool=='delete_config' for tool,args in target.calls))

    def test_rehashed_original_status_cannot_grant_null_recovery(self):
        base=proof_dir('rehash-original')
        inputs,target,executed,judged,trace=self.execute(base,NullBoundary,'ACC-005')
        self.assertEqual(0,executed[0],executed);self.assertEqual(0,judged[0],judged)
        unit=base/'run/results/MCP-P02-FULL/driver/units/ACC-005'
        path=unit/'trace.json';value=mcp.read(path)
        changed=0
        for row in value['records']:
            if row['kind']!='http':continue
            request=json.loads(mcp.unpack(row['input'])['data'])
            if request.get('params',{}).get('name')!='get_status':continue
            output=mcp.unpack(row['output']);body=json.loads(output['body'])
            payload=json.loads(body['result']['content'][0]['text'])
            payload.pop('config_identity',None)
            body['result']['content'][0]['text']=json.dumps(payload)
            output['body']=json.dumps(body).encode();row['output']=mcp.pack(output);changed+=1
            break
        self.assertEqual(1,changed);write_json(path,value)
        receipt_path=base/'run/results/MCP-P02-FULL/receipt.json';receipt=mcp.read(receipt_path)
        for artifact in receipt['artifacts']:artifact['sha256']=sha256(artifact['path'])
        write_json(receipt_path,receipt)
        index_path=base/'run/results/results.json';index=mcp.read(index_path)
        for row in index['receipts']:row['sha256']=sha256(row['path'])
        write_json(index_path,index)
        response=cli('judge','--plan',base/'run/plan.json','--results',base/'run/results',
                     '--output',base/'run/refused.json')
        write_json(base/'rehashed-judge-response.json',response)
        self.assertNotEqual(0,response[0],response)
        result=mcp.read(base/'run/refused.json')
        self.assertIn('original replay refused',json.dumps(result))
        self.assertIn('initial status is not a complete snapshot',json.dumps(result))
        self.assertFalse(result['fixture_contract_pass'])


if __name__ == '__main__':
    unittest.main()
