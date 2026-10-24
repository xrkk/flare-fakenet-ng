import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
# The acceptance host has no real netfilterqueue extension.  This test-only
# module shim only satisfies the production import; the fixture below replaces
# its NetfilterQueue class and never binds a kernel queue.
try:
    import netfilterqueue  # noqa: F401
except ModuleNotFoundError:
    _nfq_module = types.ModuleType('netfilterqueue')
    _nfq_module.NetfilterQueue = object
    sys.modules['netfilterqueue'] = _nfq_module
from fakenet.diverters.linux import Diverter
import acceptance_manual as M
import acceptance_manual_oracles as O
import acceptance_native as N

SNAPSHOT = b'# fake iptables-save\n*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n'
TABLES = ('raw', 'filter', 'mangle', 'nat')


class _State:
    def __init__(self, out, restore_rc=0, remove_rc=0):
        self.out = Path(out)
        self.restore_rc = restore_rc
        self.remove_rc = remove_rc
        self.events = []

    def record(self, kind, **fields):
        marker = self.out / 'active-branch'
        branch = marker.read_text().strip() if marker.is_file() else 'unknown'
        row = {'branch': branch, 'kind': kind}
        row.update(fields)
        self.events.append(row)
        path = self.out / 'os-calls.jsonl'
        with path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(row, sort_keys=True) + '\n')


class _FakeNfq:
    def __init__(self):
        self.qno = None
        self.state = None

    def bind(self, qno, callback):
        self.qno = qno
        if self.state is not None:
            self.state.record('bind', qno=qno)

    def get_fd(self):
        return 42

    def run_socket(self, sock):
        time.sleep(0.01)

    def unbind(self):
        if self.state is not None:
            self.state.record('unbind', qno=self.qno)


class _FakeSocket:
    def settimeout(self, timeout):
        self.timeout = timeout


class _FakeNetPolicy:
    instances = []

    def __init__(self, control_endpoints=(), logger=None):
        self.calls = []
        self.mode = None
        type(self).instances.append(self)

    def adopt_leftovers(self):
        self.calls.append('adopt_leftovers')
        return []

    def install_control_exclusions_v4(self):
        self.calls.append('install_control_exclusions_v4')

    def block_ipv6(self):
        self.calls.append('block_ipv6')
        return []

    def stop(self):
        self.calls.append('stop')
        return {'stopped': True, 'ipv6_block_leftover': False}


@contextlib.contextmanager
def _fixture(out, restore_rc=0, remove_rc=0):
    state = _State(out, restore_rc=restore_rc, remove_rc=remove_rc)

    class FakePopen:
        def __init__(self, argv, stdout=None, stdin=None, **kwargs):
            self.argv = list(argv)
            self.rc = 0
            self.stdout = io.BytesIO(SNAPSHOT) if self.argv == ['iptables-save'] else None
            state.record('popen', argv=self.argv)

        def wait(self):
            rc = state.restore_rc if self.argv == ['iptables-restore'] else 0
            state.record('wait', argv=self.argv, rc=rc)
            return rc

        def communicate(self, input=None):
            state.record('communicate', argv=self.argv,
                         input_hex=bytes(input or b'').hex())
            return b'', b''

    def fake_call(argv, *args, **kwargs):
        branch = (state.out / 'active-branch').read_text().strip() if (state.out / 'active-branch').is_file() else ''
        rc = 0
        if branch == 'dns_nonzero' and argv and argv[0] == 'false':
            rc = 1
        if remove_rc and argv and argv[0] == 'iptables' and '-D' in argv:
            rc = remove_rc
        state.record('call', argv=list(argv), rc=rc)
        return rc

    fake_subprocess = types.SimpleNamespace(Popen=FakePopen, call=fake_call, PIPE=-1)

    class FakeNfq(_FakeNfq):
        pass

    real_fake_nfq = FakeNfq

    def fake_nfq():
        item = real_fake_nfq()
        item.state = state
        return item

    class FakeNfqFactory:
        def __call__(self):
            return fake_nfq()

    with mock.patch('fakenet.diverters.linuxnetpolicy.NetPolicy', _FakeNetPolicy), \
            mock.patch('fakenet.diverters.linutil.netfilterqueue.NetfilterQueue', FakeNfqFactory()), \
            mock.patch('fakenet.diverters.linutil.socket.fromfd', side_effect=lambda *a, **k: _FakeSocket()), \
            mock.patch('fakenet.diverters.linux.subprocess', fake_subprocess), \
            mock.patch('fakenet.diverters.linutil.subprocess', fake_subprocess), \
            mock.patch('fakenet.diverters.diverterbase.socket.gethostbyname', side_effect=lambda name: '127.0.0.1' if 'localhost' in name else '192.0.2.10'), \
            mock.patch.object(Diverter, 'check_privileged', return_value=True), \
            mock.patch.object(Diverter, 'check_active_ethernet_adapters', return_value=True), \
            mock.patch.object(Diverter, 'check_ipaddresses', return_value=True), \
            mock.patch.object(Diverter, 'check_gateways', return_value=True), \
            mock.patch.object(Diverter, 'check_dns_servers', return_value=True), \
            mock.patch.object(Diverter, 'linux_get_current_nfnlq_bindings', return_value=[7]), \
            mock.patch.object(Diverter, 'linux_get_next_nfqueue_numbers', side_effect=lambda n: list(range(n))):
        yield state


class LinuxFlushInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(os.environ['FN_MANUAL_CHECK_DIR']) / 'retained' / self.id().split('.')[-1]
        self.base.mkdir(parents=True, exist_ok=False)

    def inputs(self, out):
        return {'schema': 'fakenet.manual-input.v1', 'case': 'GAP-LINUX-FLUSH-INTERFACE',
                'candidate_id': 'linux-flush-fixture', 'source_commit': 'a' * 40,
                'package_sha256': 'b' * 64, 'execution_id': 'linux-flush-01',
                'config': str(out / 'config'), 'owned_root': str(out), 'fixture': True}

    def produce(self, out, **kwargs):
        inputs = self.inputs(out)
        with _fixture(out, **kwargs) as state:
            value = M.run('GAP-LINUX-FLUSH-INTERFACE', out, inputs)
        return inputs, value, state

    def test_real_callbacks_and_three_fields(self):
        out = self.base / 'case'
        inputs, value, state = self.produce(out)
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-LINUX-FLUSH-INTERFACE', inputs, allow_fixture=True)
        self.assertTrue(clean, detail)
        self.assertEqual(['flush-iptables', 'flush-dns', 'restrict-interface'], [row['id'] for row in rows])
        self.assertEqual({'flush_on', 'flush_off', 'dns_nonzero', 'multihost_iface', 'multihost_off', 'singlehost_iface'},
                         set(value['linux_flush_interface']['branches']))
        self.assertGreater(len(state.events), 20)
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-LINUX-FLUSH-INTERFACE', inputs, allow_fixture=False)
        self.assertFalse(clean, detail)

    def test_bad_originals_and_restore_failure(self):
        out = self.base / 'case'
        inputs, value, state = self.produce(out)
        result = out / 'manual-result.json'
        original = result.read_bytes()
        base = json.loads(original)

        def reject(label, changed):
            result.write_text(json.dumps(changed))
            rows, clean, detail = O.evaluate(ROOT, out, 'GAP-LINUX-FLUSH-INTERFACE', inputs, allow_fixture=True)
            self.assertFalse(clean, (label, detail))
            result.write_bytes(original)

        for label, change in {
            'owner': lambda v: v['linux_flush_interface'].__setitem__('owner_pid', v['linux_flush_interface']['owner_pid'] + 1),
            'token': lambda v: v['linux_flush_interface'].__setitem__('execution_token', 'foreign-token'),
            'fixture': lambda v: v.__setitem__('fixture', False),
            'checks': lambda v: v.__setitem__('checks', []),
            'branch': lambda v: v['linux_flush_interface']['branches'].pop('flush_on'),
            'flush': lambda v: v['linux_flush_interface']['branches']['flush_on'].__setitem__('flush_iptables', False),
            'dns': lambda v: v['linux_flush_interface']['branches']['dns_nonzero'].__setitem__('dns_command', None),
            'iface': lambda v: v['linux_flush_interface']['branches']['multihost_iface']['queues_after_start'][0].__setitem__('add', 'foreign'),
            'stop': lambda v: v['linux_flush_interface']['branches']['flush_on'].__setitem__('stop_result', False),
            'queue': lambda v: v['linux_flush_interface']['branches']['flush_on']['queues_after_start'][0].__setitem__('add', 'foreign'),
            'cleanup': lambda v: v['cleanup'].__setitem__('system_iptables_restored', 'restored'),
            'source': lambda v: v['source_hashes'].__setitem__('fakenet/diverters/linux.py', '0' * 64),
        }.items():
            with self.subTest(fault=label):
                changed = json.loads(original)
                change(changed)
                reject(label, changed)

        config = out / 'config' / 'flush_on.ini'
        snapshot = out / 'snapshot-flush_on.sav'
        log = out / 'diverter.log'
        calls = out / 'os-calls.jsonl'
        for label, path, damaged in (('config', config, b'[Diverter]\nNetworkMode: SingleHost\nLinuxFlushIptables: No\n'),
                                     ('snapshot', snapshot, b'corrupt snapshot'),
                                     ('log', log, b'not the original log\n'),
                                     ('commands', calls, b'{"branch":"flush_on","kind":"call","argv":["foreign"],"rc":0}\n')):
            with self.subTest(original=label):
                (out / 'manual-result.json').write_bytes(original)
                prior = path.read_bytes(); path.write_bytes(damaged)
                rows, clean, detail = O.evaluate(ROOT, out, 'GAP-LINUX-FLUSH-INTERFACE', inputs, allow_fixture=True)
                self.assertFalse(clean, (label, detail))
                path.write_bytes(prior)

        failure_out = self.base / 'restore-failure'
        failure_inputs, failure_value, failure_state = self.produce(failure_out, restore_rc=1)
        self.assertTrue(failure_value['linux_flush_interface']['branches']['flush_on']['stop_result'])
        rows, clean, detail = O.evaluate(ROOT, failure_out, 'GAP-LINUX-FLUSH-INTERFACE', failure_inputs, allow_fixture=True)
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
            pid = 999988

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
        result = cli('plan', '--mode', 'selected', '--case', 'GAP-LINUX-FLUSH-INTERFACE',
                     '--candidate', self.base / 'candidate.json', '--environment', self.base / 'environment.json',
                     '--output', run / 'plan.json')
        self.assertEqual(0, result[0], result)
        driver = run / 'results' / 'GAP-LINUX-FLUSH-INTERFACE' / 'driver'
        with _fixture(driver), mock.patch.object(subprocess, 'Popen', side_effect=popen):
            result = cli('execute', '--plan', run / 'plan.json')
        self.assertEqual(0, result[0], result)
        result = cli('judge', '--plan', run / 'plan.json', '--results', run / 'results', '--output', run / 'judge.json')
        self.assertEqual(0, result[0], result)
        self.assertFalse(json.loads((run / 'judge.json').read_text())['full_functional_pass'])

        produced = driver / 'manual-result.json'
        original = json.loads(produced.read_text())
        damaged = json.loads(produced.read_text())
        damaged['linux_flush_interface']['branches']['flush_on']['queues_after_start'][0]['add'] = 'foreign'
        produced.write_text(json.dumps(damaged))
        result = cli('judge', '--plan', run / 'plan.json', '--results', run / 'results', '--output', run / 'rejected.json')
        self.assertNotEqual(0, result[0], result)
        produced.write_text(json.dumps(original))

        failure_run = self.base / 'failure-run'
        result = cli('plan', '--mode', 'selected', '--case', 'GAP-LINUX-FLUSH-INTERFACE',
                     '--candidate', self.base / 'candidate.json', '--environment', self.base / 'environment.json',
                     '--output', failure_run / 'plan.json')
        self.assertEqual(0, result[0], result)
        failure_driver = failure_run / 'results' / 'GAP-LINUX-FLUSH-INTERFACE' / 'driver'
        with _fixture(failure_driver, restore_rc=1), mock.patch.object(subprocess, 'Popen', side_effect=popen):
            result = cli('execute', '--plan', failure_run / 'plan.json')
        self.assertNotEqual(0, result[0], result)
        result = cli('judge', '--plan', failure_run / 'plan.json', '--results', failure_run / 'results',
                     '--output', failure_run / 'judge.json')
        self.assertNotEqual(0, result[0], result)

    def test_central_registration(self):
        self.assertEqual('manual-linux-flush-interface',
                         N.driver_table(ROOT)['manual-linux-flush-interface']['production_kind'])


if __name__ == '__main__':
    unittest.main()
