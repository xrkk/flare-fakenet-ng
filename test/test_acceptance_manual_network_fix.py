import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
# Import-time compatibility for the Windows modules on this Linux acceptance
# host.  The actual registry operations are replaced below; no registry access
# is possible or attempted here.
try:
    import winreg  # noqa: F401
except ModuleNotFoundError:
    _winreg = types.ModuleType('winreg')
    for _name, _value in (('HKEY_LOCAL_MACHINE', 1), ('KEY_READ', 2),
                          ('KEY_WRITE', 3), ('REG_SZ', 4)):
        setattr(_winreg, _name, _value)
    for _name in ('OpenKey', 'QueryValueEx', 'CloseKey', 'CreateKeyEx', 'SetValueEx'):
        setattr(_winreg, _name, lambda *a, **k: None)
    sys.modules['winreg'] = _winreg
try:
    import netfilterqueue  # noqa: F401
except ModuleNotFoundError:
    _nfq = types.ModuleType('netfilterqueue')
    _nfq.NetfilterQueue = object
    sys.modules['netfilterqueue'] = _nfq
from fakenet.diverters.winutil import WinUtilMixin
from fakenet.diverters.windows import Diverter as WindowsDiverter
from fakenet.diverters.linutil import LinUtilMixin
import acceptance_manual as M
import acceptance_manual_oracles as O
import acceptance_native as N

WINDOWS_DHCP = 'netsh interface ip set address name="Ethernet" static 192.0.2.10 255.255.255.0 192.0.2.1'
WINDOWS_DNS = 'netsh interface ip set dns name="Ethernet" static 192.0.2.10'
WINDOWS_RESTORE_DHCP = 'netsh interface ip set address name="Ethernet" dhcp'
WINDOWS_DELETE_DNS = 'netsh interface ip delete dns name="Ethernet" all'
WINDOWS_RESTORE_DNS = 'netsh interface ip set dns "Ethernet" dhcp'
WINDOWS_FLUSH = 'ipconfig /flushdns'
RESOLV_BEFORE = 'nameserver 8.8.8.8\nsearch example.test\n'
RESOLV_AFTER = 'nameserver 192.0.2.10\n'
RESOLV_RESTORED = RESOLV_BEFORE


class _State:
    def __init__(self, out, win_restore_fail=False, linux_restore_fail=False):
        self.out = Path(out)
        self.win_restore_fail = win_restore_fail
        self.linux_restore_fail = linux_restore_fail
        self.resolv = RESOLV_BEFORE
        self.initial_resolv = self.resolv
        self.registry = {}
        self.service_state = 4  # SERVICE_RUNNING
        self.events = []

    def _write_resolv(self):
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / 'resolv-before.txt').write_text(self.initial_resolv)
        (self.out / 'resolv-after.txt').write_text(self.resolv)

    def record(self, kind, **fields):
        marker = self.out / 'active-branch'
        branch = marker.read_text().strip() if marker.is_file() else 'unknown'
        row = {'branch': branch, 'kind': kind}
        row.update(fields)
        self.events.append(row)
        with (self.out / 'test-os-calls.jsonl').open('a') as stream:
            stream.write(json.dumps(row, sort_keys=True) + '\n')

    def open_resolv(self, path, mode='r', *args, **kwargs):
        state = self
        if path != '/etc/resolv.conf':
            return open(path, mode, *args, **kwargs)
        class File:
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False
            def read(self):
                return state.resolv
            def write(self, text):
                if state.linux_restore_fail and '192.0.2.10' not in text:
                    state.record('resolv_error', path=path, mode=mode)
                    raise OSError('injected resolver restore failure')
                state.resolv = text
                state.record('resolv', path=path, mode=mode, data=text)
                state._write_resolv()
        return File()


@contextlib.contextmanager
def _fixture(out, win_restore_fail=False, linux_restore_fail=False):
    state = _State(out, win_restore_fail=win_restore_fail,
                   linux_restore_fail=linux_restore_fail)
    real_call = subprocess.call
    real_open = open

    def win_call(command, *args, **kwargs):
        branch = (state.out / 'active-branch').read_text().strip() if (state.out / 'active-branch').is_file() else ''
        rc = 0
        if state.win_restore_fail and branch == 'win_fix' and 'dhcp' in command:
            state.record('win_command', command=command, rc=1)
            raise subprocess.CalledProcessError(1, command)
        state.record('win_command', command=command, rc=rc)
        return rc

    def win_output(command, *args, **kwargs):
        state.record('win_command', command=command, rc=0)
        return b''

    class WinSubprocess:
        PIPE = subprocess.PIPE
        CalledProcessError = subprocess.CalledProcessError
        check_call = staticmethod(win_call)
        check_output = staticmethod(win_output)

    class Advapi:
        def OpenSCManagerA(self, *args):
            state.record('service', op='OpenSCManager')
            return 1
        def OpenServiceA(self, *args):
            state.record('service', op='OpenService', name=args[1])
            return 2
        def CloseServiceHandle(self, *args):
            state.record('service', op='CloseServiceHandle')
            return 1
        def ChangeServiceConfigA(self, *args):
            state.record('service', op='ChangeServiceConfig', start_type=args[2])
            return 1
        def QueryServiceStatusEx(self, handle, level, buffer, size, needed):
            buffer._obj.dwCurrentState = state.service_state
            state.record('service', op='QueryServiceStatus', state=state.service_state)
            return 1
        def ControlService(self, handle, control, status):
            state.service_state = 1
            state.record('service', op='ControlService', control=control.value if hasattr(control, 'value') else control)
            return 1
        def StartServiceA(self, *args):
            state.service_state = 4
            state.record('service', op='StartService')
            return 1

    class Dhcp:
        def DhcpNotifyConfigChange(self, *args):
            state.record('service', op='DhcpNotifyConfigChange', name=args[1])
            return 0

    fake_windll = types.SimpleNamespace(advapi32=Advapi(), dhcpcsvc=Dhcp())

    def open_key(key, sub_key, reserved, sam):
        state.record('registry', op='OpenKey', sub_key=sub_key)
        return ('key', sub_key)

    def query_value(handle, value):
        sub_key = handle[1]
        state.record('registry', op='QueryValueEx', sub_key=sub_key, value=value)
        return state.registry.get((sub_key, value), ''), 4

    def create_key(key, sub_key, reserved, sam):
        state.record('registry', op='CreateKeyEx', sub_key=sub_key)
        return ('key', sub_key)

    def set_value(handle, value, reserved, type_, data):
        state.registry[(handle[1], value)] = data
        state.record('registry', op='SetValueEx', sub_key=handle[1], value=value, data=data)

    def close_key(handle):
        state.record('registry', op='CloseKey', sub_key=handle[1])

    def get_adapters(self):
        branch = (state.out / 'active-branch').read_text().strip() if (state.out / 'active-branch').is_file() else ''
        return [types.SimpleNamespace(DhcpEnabled=True, Index=1)]

    def check_ip(self, adapter):
        return True

    def addresses(self, adapter):
        return iter(['192.0.2.10'])

    def addresses_netmask(self, adapter):
        return iter([('192.0.2.10', '255.255.255.0')])

    def friendly(self, index):
        branch = (state.out / 'active-branch').read_text().strip() if (state.out / 'active-branch').is_file() else ''
        return 'Ethernet'

    def active_adapters(self):
        return [types.SimpleNamespace(AdapterName=b'{GUID}', FriendlyName='Ethernet')]

    def fake_linux_call(argv, *args, **kwargs):
        state.record('linux_command', argv=list(argv), rc=0)
        return 0

    def fake_open(path, mode='r', *args, **kwargs):
        return state.open_resolv(path, mode, *args, **kwargs)

    @contextlib.contextmanager
    def original_fixture():
        with mock.patch('fakenet.diverters.winutil.subprocess', WinSubprocess), \
                mock.patch('fakenet.diverters.windows.subprocess', WinSubprocess), \
                mock.patch('fakenet.diverters.linutil.subprocess', types.SimpleNamespace(Popen=FakePopen, call=fake_linux_call, PIPE=subprocess.PIPE)), \
                mock.patch('fakenet.diverters.linutil.open', side_effect=fake_open, create=True), \
                mock.patch('fakenet.diverters.winutil.windll', fake_windll, create=True), \
                mock.patch('fakenet.diverters.winutil.WindowsError', OSError, create=True), \
                mock.patch('fakenet.diverters.winutil.OpenKey', side_effect=open_key), \
                mock.patch('fakenet.diverters.winutil.QueryValueEx', side_effect=query_value), \
                mock.patch('fakenet.diverters.winutil.CreateKeyEx', side_effect=create_key), \
                mock.patch('fakenet.diverters.winutil.SetValueEx', side_effect=set_value), \
                mock.patch('fakenet.diverters.winutil.CloseKey', side_effect=close_key), \
                mock.patch.object(WinUtilMixin, 'get_adapters_info', get_adapters), \
                mock.patch.object(WinUtilMixin, 'check_ipaddresses_interface', check_ip), \
                mock.patch.object(WinUtilMixin, 'get_ipaddresses', addresses), \
                mock.patch.object(WinUtilMixin, 'get_ipaddresses_netmask', addresses_netmask), \
                mock.patch.object(WinUtilMixin, 'get_adapter_friendlyname', friendly), \
                mock.patch.object(WinUtilMixin, 'get_active_ethernet_adapters', active_adapters):
            yield state
    from fakenet.diverters import linux, linutil
    from test_acceptance_manual_linux_flush_interface import _FakeNfq, _FakeSocket, _FakeNetPolicy
    class FakePopen:
        def __init__(self, *args, **kwargs):
            self.stdout = io.BytesIO(b'*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n')
        def wait(self, *args, **kwargs): return 0
    class FakeHandle:
        def close(self): pass
    def driver_open(self): self.handle = FakeHandle()
    def driver_close(self): self.handle.close(); self.handle = None
    def receiver(self): self._stopping.wait(1)
    def gateways(self, adapter):
        branch = (state.out / 'active-branch').read_text().strip()
        return iter([b'0.0.0.0' if branch == 'win_fix' else b'192.0.2.1'])
    def network_params(self):
        branch = (state.out / 'active-branch').read_text().strip()
        return types.SimpleNamespace(DnsServerList=types.SimpleNamespace(IpAddress=types.SimpleNamespace(String=b'' if branch == 'win_fix' else b'203.0.113.53')))
    def linux_gateway(self):
        branch = (state.out / 'active-branch').read_text().strip()
        return None if branch == 'linux_gateway' else '192.0.2.1'
    with contextlib.ExitStack() as extra:
        for patcher in (
            mock.patch('fakenet.diverters.diverterbase.socket.gethostbyname', side_effect=lambda name: '127.0.0.1' if name == 'localhost' else '192.0.2.10'),
            mock.patch.object(WinUtilMixin, 'check_active_ethernet_adapters', return_value=True),
            mock.patch.object(WinUtilMixin, 'get_best_ipaddress', return_value='192.0.2.10'),
            mock.patch.object(WinUtilMixin, 'get_gateways', gateways),
            mock.patch.object(WinUtilMixin, 'get_network_params', network_params),
            mock.patch.object(WindowsDiverter, '_open_windivert_handle', driver_open),
            mock.patch.object(WindowsDiverter, '_close_windivert_handle', driver_close),
            mock.patch.object(WindowsDiverter, 'divert_thread', receiver),
            mock.patch('fakenet.diverters.linuxnetpolicy.NetPolicy', _FakeNetPolicy),
            mock.patch('fakenet.diverters.linutil.netfilterqueue.NetfilterQueue', _FakeNfq),
            mock.patch('fakenet.diverters.linutil.socket.fromfd', side_effect=lambda *a, **k: _FakeSocket()),
            mock.patch.object(linux.Diverter, 'check_privileged', return_value=True),
            mock.patch.object(linux.Diverter, '_linux_get_ifaces', return_value=['eth0']),
            mock.patch.object(linux.Diverter, 'linux_get_current_nfnlq_bindings', return_value=[]),
            mock.patch.object(linux.Diverter, 'linux_get_default_gw', linux_gateway),
            mock.patch('fakenet.diverters.linux.subprocess', types.SimpleNamespace(Popen=FakePopen, call=fake_linux_call, PIPE=-1)),
        ): extra.enter_context(patcher)
        with original_fixture():
            yield state


class NetworkFixTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(os.environ['FN_MANUAL_CHECK_DIR']) / 'retained' / self.id().split('.')[-1]
        self.base.mkdir(parents=True, exist_ok=False)

    def inputs(self, out):
        return {'schema': 'fakenet.manual-input.v1', 'case': 'GAP-NETWORK-FIX',
                'candidate_id': 'network-fix-fixture', 'source_commit': 'a' * 40,
                'package_sha256': 'b' * 64, 'execution_id': 'network-fix-01',
                'config': str(out / 'config'), 'owned_root': str(out), 'fixture': True}

    def produce(self, out, **kwargs):
        inputs = self.inputs(out)
        with _fixture(out, **kwargs) as state:
            value = M.run('GAP-NETWORK-FIX', out, inputs)
            state._write_resolv()
        return inputs, value, state

    def test_real_network_fix_methods(self):
        out = self.base / 'case'
        inputs, value, state = self.produce(out)
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-NETWORK-FIX', inputs, allow_fixture=True)
        self.assertTrue(clean, detail)
        self.assertEqual(['fix-gateway', 'fix-dns', 'modify-local-dns', 'stop-dns'], [row['id'] for row in rows])
        self.assertTrue(value['network_fix']['windows']['fix']['gateway_result'])
        self.assertTrue(value['network_fix']['windows']['fix']['dns_result'])
        self.assertFalse(value['network_fix']['windows']['existing']['gateway_result'])
        self.assertFalse(value['network_fix']['windows']['existing']['dns_result'])
        self.assertTrue(value['network_fix']['linux']['gateway']['gateway_result'])
        self.assertFalse(value['network_fix']['linux']['unsupported']['fix_gateway_result'])
        self.assertFalse(value['network_fix']['linux']['unsupported']['fix_dns_result'])
        self.assertFalse(value['network_fix']['linux']['unsupported']['stop_dns_service_supported'])
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-NETWORK-FIX', inputs, allow_fixture=False)
        self.assertFalse(clean, detail)

    def test_bad_originals_and_restore_failures(self):
        out = self.base / 'case'
        inputs, value, state = self.produce(out)
        result = out / 'manual-result.json'
        original = result.read_bytes()
        base = json.loads(original)

        def reject(label, changed):
            result.write_text(json.dumps(changed))
            rows, clean, detail = O.evaluate(ROOT, out, 'GAP-NETWORK-FIX', inputs, allow_fixture=True)
            self.assertFalse(clean, (label, detail))
            result.write_bytes(original)

        variants = {
            'owner': lambda v: v['network_fix'].__setitem__('owner_pid', v['network_fix']['owner_pid'] + 1),
            'token': lambda v: v['network_fix'].__setitem__('execution_token', 'foreign-token'),
            'fixture': lambda v: v.__setitem__('fixture', False),
            'checks': lambda v: v.__setitem__('checks', []),
            'gateway': lambda v: v['network_fix']['windows']['fix'].__setitem__('gateway_result', False),
            'dns': lambda v: v['network_fix']['windows']['fix'].__setitem__('dns_result', False),
            'linux-todo': lambda v: v['network_fix']['linux']['unsupported'].__setitem__('fix_gateway_result', True),
            'service': lambda v: v['network_fix']['branches']['win_modify'].__setitem__('service_after', 1),
            'cleanup': lambda v: v['cleanup'].__setitem__('system_network_restored', 'restored'),
            'source': lambda v: v['source_hashes'].__setitem__('fakenet/diverters/winutil.py', '0' * 64),
        }
        for label, change in variants.items():
            with self.subTest(fault=label):
                changed = json.loads(original)
                change(changed)
                reject(label, changed)

        config = out / 'config' / 'network-fix.ini'
        log = out / 'network-fix.log'
        calls = out / 'producer-os-calls.jsonl'
        resolv = out / 'manual-result.json'
        for label, path, damaged in (('config', config, b'[Diverter]\nNetworkMode: SingleHost\n'),
                                     ('log', log, b'not the original log\n'),
                                     ('commands', calls, b'{"branch":"win_fix","kind":"win_command","command":"foreign","rc":0}\n'),
                                     ('resolv', resolv, b'foreign\n')):
            with self.subTest(original=label):
                (out / 'manual-result.json').write_bytes(original)
                prior = path.read_bytes(); path.write_bytes(damaged)
                rows, clean, detail = O.evaluate(ROOT, out, 'GAP-NETWORK-FIX', inputs, allow_fixture=True)
                self.assertFalse(clean, (label, detail))
                path.write_bytes(prior)

        failure_out = self.base / 'windows-restore-failure'
        failure_inputs, failure_value, failure_state = self.produce(failure_out, win_restore_fail=True)
        rows, clean, detail = O.evaluate(ROOT, failure_out, 'GAP-NETWORK-FIX', failure_inputs, allow_fixture=True)
        self.assertFalse(clean, detail)

        linux_failure = self.base / 'linux-restore-failure'
        linux_inputs, linux_value, linux_state = self.produce(linux_failure, linux_restore_fail=True)
        self.assertFalse(linux_value['network_fix']['linux']['modify']['resolv_restored'])
        rows, clean, detail = O.evaluate(ROOT, linux_failure, 'GAP-NETWORK-FIX', linux_inputs, allow_fixture=True)
        self.assertFalse(clean, detail)

    def test_same_central_cli_and_independent_rejection(self):
        import acceptance as A

        def write(path, value):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))

        def cli(*args):
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = A.main(['--root', str(ROOT), *map(str, args)])
            return code, stdout.getvalue(), stderr.getvalue()

        identity = {'platform': 'linux', 'hostname': socket.gethostname()}
        write(self.base / 'candidate.json', dict(schema=A.CANDIDATE_V2, source_commit=A.git_head(ROOT),
                                                   deployed_identity=identity, package_sha256='b' * 64,
                                                   offline_fixture=True))
        write(self.base / 'environment.json', dict(schema=A.ENVIRONMENT_V2, targets=['host-linux'],
                                                     interpreters={'python': sys.executable},
                                                     work_root=str(self.base), allowed_actions=['native'],
                                                     endpoints=[], auth_refs=[],
                                                     native_runtime={'transport': 'manual-loopback-fixture', 'identity': identity},
                                                     manual={'schema': 'fakenet.manual-options.v1'}))
        real_popen = subprocess.Popen

        class Child:
            pid = 999989

            def __init__(self, code):
                self.code = code

            def wait(self, timeout=None):
                return self.code

        def popen(argv, **kwargs):
            if isinstance(argv, list) and argv[0] == 'git':
                return real_popen(argv, **kwargs)
            self.assertEqual(str(ROOT / 'tools/acceptance_manual.py'), argv[1])
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                code = M.main(argv[2:])
            kwargs['stdout'].write(captured.getvalue().encode())
            return Child(code)

        run = self.base / 'run'
        result = cli('plan', '--mode', 'selected', '--case', 'GAP-NETWORK-FIX',
                     '--candidate', self.base / 'candidate.json', '--environment', self.base / 'environment.json',
                     '--output', run / 'plan.json')
        self.assertEqual(0, result[0], result)
        driver = run / 'results' / 'GAP-NETWORK-FIX' / 'driver'
        with _fixture(driver) as fixture_state, mock.patch.object(subprocess, 'Popen', side_effect=popen):
            result = cli('execute', '--plan', run / 'plan.json')
            fixture_state._write_resolv()
        self.assertEqual(0, result[0], result)
        result = cli('judge', '--plan', run / 'plan.json', '--results', run / 'results', '--output', run / 'judge.json')
        self.assertEqual(0, result[0], result)
        self.assertFalse(json.loads((run / 'judge.json').read_text())['full_functional_pass'])

        produced = driver / 'manual-result.json'
        original = json.loads(produced.read_text())
        damaged = json.loads(produced.read_text())
        damaged['network_fix']['windows']['fix']['gateway_result'] = False
        produced.write_text(json.dumps(damaged))
        result = cli('judge', '--plan', run / 'plan.json', '--results', run / 'results', '--output', run / 'rejected.json')
        self.assertNotEqual(0, result[0], result)
        produced.write_text(json.dumps(original))

        failure_run = self.base / 'failure-run'
        result = cli('plan', '--mode', 'selected', '--case', 'GAP-NETWORK-FIX',
                     '--candidate', self.base / 'candidate.json', '--environment', self.base / 'environment.json',
                     '--output', failure_run / 'plan.json')
        self.assertEqual(0, result[0], result)
        failure_driver = failure_run / 'results' / 'GAP-NETWORK-FIX' / 'driver'
        with _fixture(failure_driver, win_restore_fail=True) as failure_state, mock.patch.object(subprocess, 'Popen', side_effect=popen):
            result = cli('execute', '--plan', failure_run / 'plan.json')
            failure_state._write_resolv()
        self.assertNotEqual(0, result[0], result)
        result = cli('judge', '--plan', failure_run / 'plan.json', '--results', failure_run / 'results',
                     '--output', failure_run / 'judge.json')
        self.assertNotEqual(0, result[0], result)

    def test_producer_records_without_test_recorder(self):
        out = self.base / 'without-recorder'
        inputs = self.inputs(out)
        with _fixture(out), mock.patch.object(_State, 'record', return_value=None):
            M.run('GAP-NETWORK-FIX', out, inputs)
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-NETWORK-FIX', inputs, allow_fixture=True)
        self.assertTrue(clean, detail)

    def test_original_config_and_startup_paths_are_exercised(self):
        from fakenet.diverters.diverterbase import DiverterBase
        from fakenet.diverters.linux import Diverter as LinuxDiverter
        calls = []
        def wrap(label, original):
            def observed(*args, **kwargs):
                calls.append(label)
                return original(*args, **kwargs)
            return observed
        with mock.patch.object(DiverterBase, '__init__', new=wrap('base-init', DiverterBase.__init__)), \
                mock.patch.object(WindowsDiverter, 'startCallback', new=wrap('windows-start', WindowsDiverter.startCallback)), \
                mock.patch.object(LinuxDiverter, 'startCallback', new=wrap('linux-start', LinuxDiverter.startCallback)):
            self.produce(self.base / 'original-paths')
        self.assertTrue({'base-init', 'windows-start', 'linux-start'}.issubset(calls), calls)

    def test_missing_registry_restore_rejected(self):
        out = self.base / 'missing-registry-restore'
        with mock.patch.object(WinUtilMixin, 'restore_dns_server', new=lambda self: None):
            inputs, value, state = self.produce(out)
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-NETWORK-FIX', inputs, allow_fixture=True)
        self.assertFalse(clean, detail)

    def test_arbitrary_initial_dns_state(self):
        original = _State.__init__
        registry_path = 'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{GUID}'
        resolver = 'nameserver 203.0.113.9\nsearch preserved.test\n'
        def initial(state, *args, **kwargs):
            original(state, *args, **kwargs)
            state.resolv = resolver
            state.initial_resolv = resolver
            state.registry[(registry_path, 'NameServer')] = '203.0.113.10'
        with mock.patch.object(_State, '__init__', new=initial):
            inputs, value, state = self.produce(self.base / 'arbitrary-initial')
        self.assertEqual(resolver, state.resolv)
        self.assertEqual('203.0.113.10', state.registry[(registry_path, 'NameServer')])
        rows, clean, detail = O.evaluate(ROOT, self.base / 'arbitrary-initial', 'GAP-NETWORK-FIX', inputs, allow_fixture=True)
        self.assertTrue(clean, detail)

    def test_central_registration(self):
        self.assertEqual('manual-network-fix', N.driver_table(ROOT)['manual-network-fix']['production_kind'])


if __name__ == '__main__':
    unittest.main()
