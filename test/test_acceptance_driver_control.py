"""DV guarded tests (T068-R01): the protected driver-two-case v3/v6 chain
through the REAL consumers - plan CLI options/control, input derivation and
identity, pre-effect refusals, and the v6 oracle reconstruction with real
pure-function filters. Benign static fixtures only; no real OS/network/VM."""
import contextlib
import copy
import hashlib
import io
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))
import acceptance as A
import acceptance_manual as M
import acceptance_manual_oracles as O
import acceptance_native as native

HEAD = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                               text=True).strip()
CONTROL = {'host_ipv4': '192.168.204.1', 'tcp_source_ports': [28788, 28790]}
CASES = ('GAP-CTRLC-IPC', 'GAP-DIVERTER-SWITCH')


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _work(prefix):
    """Retained per-test work root under the task-owned check directory (never a
    hardcoded old-task path; FN_MANUAL_CHECK_DIR is set by the guarded runner)."""
    root = Path(os.environ.get('FN_MANUAL_CHECK_DIR') or tempfile.gettempdir())
    base = root / 'driver-control'
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))


class _NoRealEffects(unittest.TestCase):
    def setUp(self):
        real_popen = subprocess.Popen

        def guarded(argv, *a, **k):
            if isinstance(argv, (list, tuple)) and argv and str(argv[0]).endswith('git'):
                return real_popen(argv, *a, **k)
            raise AssertionError('REAL_EFFECT_HIT: subprocess.Popen')
        import socket as _socket
        import acceptance_native as _N
        import logging.handlers
        patches = [mock.patch('subprocess.Popen', side_effect=guarded),
                   mock.patch('socket.socket.bind', side_effect=self._hit('bind')),
                   mock.patch('socket.socket.listen', side_effect=self._hit('listen')),
                   mock.patch('socket.socket.connect', side_effect=self._hit('connect')),
                   mock.patch('socket.socket.sendto', side_effect=self._hit('sendto'))]
        for attr in ('run_driver', 'run_production', 'run_remote'):
            patches.append(mock.patch.object(_N, attr, side_effect=self._hit('native.' + attr)))
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        super().setUp()

    @staticmethod
    def _hit(name):
        def boom(*a, **k):
            raise AssertionError('REAL_EFFECT_HIT: ' + name)
        return boom


def _v6_inputs(out, case_id, execution):
    return {'schema': 'fakenet.manual-input.v6', 'case': case_id,
            'candidate_id': 'manual-candidate', 'source_commit': HEAD,
            'package_sha256': None, 'execution_id': execution,
            'owned_root': str(out), 'config': str(out / 'config'),
            'responsea': '192.0.2.55', 'fixture': False,
            'source_deployment_identity': {
                'schema': 'fakenet.source-deployment-identity.v1',
                'source_commit': HEAD, 'case_id': case_id,
                'source_hashes_sha256': '0' * 64},
            'control': copy.deepcopy(CONTROL)}


def _source_plan(work, case_id):
    run = work / 'run'
    run.mkdir(parents=True, exist_ok=True)
    candidate = {'schema': A.CANDIDATE_V2, 'source_commit': HEAD,
                 'deployed_identity': {'platform': 'windows', 'hostname': 'DESKTOP-3FI41GR'},
                 'deployment_kind': 'source'}
    (work / 'candidate.json').write_text(json.dumps(candidate))
    environment = {'schema': A.ENVIRONMENT_V2, 'targets': ['windows-vm'],
                   'interpreters': {'python': sys.executable}, 'work_root': str(run),
                   'allowed_actions': ['native'], 'endpoints': [], 'auth_refs': [],
                   'native_runtime': {'transport': 'windows-mcp-velo',
                                      'identity': {'platform': 'windows', 'hostname': 'DESKTOP-3FI41GR'},
                                      'python': 'C:\\py.exe', 'source_root': 'E:\\src',
                                      'work_root': 'E:\\w',
                                      'transfer': {'expected_vm_identity': {
                                          'vm_uuid': 'u' * 36, 'boot_identity': 'b', 'vm_epoch': 'e'}}},
                   'manual': {'schema': 'fakenet.manual-options.v3',
                              'responsea': '192.0.2.55',
                              'control': copy.deepcopy(CONTROL)}}
    (work / 'environment.json').write_text(json.dumps(environment))
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        code = A.main(['--root', str(ROOT), 'plan', '--mode', 'selected',
                       '--case', case_id, '--candidate', str(work / 'candidate.json'),
                       '--environment', str(work / 'environment.json'),
                       '--output', str(run / 'plan.json')])
    assert code == 0
    return json.loads((run / 'plan.json').read_text())


def _expected_filter():
    from fakenet.mcp.controlfilter import apply_control_link_exclusion, apply_loopback_exclusion
    return apply_loopback_exclusion(apply_control_link_exclusion(
        'outbound and ip', '192.168.204.1', '28788,28790'))


def _driver_row(token):
    return {'opened': True, 'filter_validated': True, 'filter': _expected_filter(),
            'owner_execution': token,
            'pydivert_module': {'path': 'E:\\src\\pydivert\\windivert.py', 'sha256': 'a' * 64},
            'dll': {'path': 'E:\\src\\pydivert\\windivert_dll\\WinDivert64.dll', 'sha256': 'b' * 64},
            'sys': {'path': 'E:\\src\\pydivert\\windivert_dll\\WinDivert64.sys', 'sha256': 'c' * 64}}


def _write_result(out, inputs, body):
    payload = {'schema': 'fakenet.manual-result.v1', 'case': inputs['case'],
               'fixture': False, 'inputs': inputs,
               'identity': {k: inputs[k] for k in
                            ('candidate_id', 'source_commit', 'package_sha256',
                             'execution_id', 'source_deployment_identity')}}
    payload.update(body)
    (out / 'manual-result.json').write_text(json.dumps(payload, indent=1) + '\n',
                                            encoding='utf-8')


class _Handle:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class _WinDivert:
    @staticmethod
    def check_filter(filter_string):
        return True, 0, ''


class ControlledWindowsDiverter:
    """Controlled in-process stand-in for the source-local Windows Diverter.

    The REAL Fakenet core constructs/starts/stops it and the REAL original-open
    observer wraps `_open_windivert_handle`; the final filter is produced with
    the product's own pure exclusion functions, so the recorded evidence is the
    actual value the observed open received.  Nothing here touches WinDivert,
    the OS driver, networking or a VM."""

    instances = []
    fail_open = False
    drop_exclusion = False

    def __init__(self, diverter_config, listeners_config, ip_addrs,
                 logging_level=logging.INFO):
        from fakenet.mcp.controlfilter import (apply_control_link_exclusion,
                                               apply_loopback_exclusion)
        self._control = apply_control_link_exclusion
        self._loopback = apply_loopback_exclusion
        self.diverter_config = diverter_config
        self.filter = 'outbound and ip'
        self.handle = None
        self.start_calls = 0
        self.stop_calls = 0
        self.wait_calls = 0
        type(self).instances.append(self)

    def _open_windivert_handle(self):
        if type(self).fail_open:
            raise RuntimeError('controlled original-open failure')
        if self.handle is not None:
            return
        if not type(self).drop_exclusion:
            ip = self.diverter_config.get('controllinkexcludeip')
            port = self.diverter_config.get('controllinkexcludeport')
            if ip is not None or port is not None:
                self.filter = self._loopback(self._control(self.filter, ip, port))
        self.handle = _Handle()

    def start(self):
        self.start_calls += 1
        self._open_windivert_handle()

    def wait_for_capture_failure(self, timeout):
        self.wait_calls += 1
        time.sleep(min(float(timeout), 0.02))
        return False

    def stop(self):
        self.stop_calls += 1
        if self.handle is not None:
            self.handle.close()
            self.handle = None
        return True


class _IfaceInfo:
    ifaces = {'eth0': []}

    def get_ips(self, versions, iface=None):
        return ['192.0.2.10'] if 4 in versions else []


@contextlib.contextmanager
def _windows_environment(work, diverter=ControlledWindowsDiverter):
    """The controlled Windows-shaped, source-local dependency tree: a fake
    windows diverter module, source-local pydivert module/DLL/SYS files and the
    actual platform probe.  Benign controlled valid tests only."""
    import fakenet.diverters as diverters_package
    work = Path(work)
    module_file = work / 'pydivert' / 'windivert.py'
    dll = work / 'pydivert' / 'windivert_dll' / 'WinDivert64.dll'
    sysfile = work / 'pydivert' / 'windivert_dll' / 'WinDivert64.sys'
    for path, payload in ((module_file, b'# controlled pydivert module\n'),
                          (dll, b'controlled-dll'), (sysfile, b'controlled-sys')):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    win = types.ModuleType('fakenet.diverters.windows')
    win.Diverter = diverter
    win.WinDivert = _WinDivert
    package = types.ModuleType('pydivert')
    package.__path__ = []
    wd = types.ModuleType('pydivert.windivert')
    wd.__file__ = str(module_file)
    dllmod = types.ModuleType('pydivert.windivert_dll')
    dllmod.DLL_PATH = str(dll)
    package.windivert = wd
    package.windivert_dll = dllmod
    with mock.patch.dict(sys.modules, {
            'fakenet.diverters.windows': win, 'pydivert': package,
            'pydivert.windivert': wd, 'pydivert.windivert_dll': dllmod}), \
            mock.patch.object(diverters_package, 'windows', win, create=True), \
            mock.patch('platform.system', return_value='Windows'), \
            mock.patch('fakenet.fakenet.IfaceIpInfo', _IfaceInfo):
        yield win


def _v6_case_inputs(work, case_id, execution=None):
    out = work / 'driver'
    inputs = _v6_inputs(out, case_id, execution or
                        ('dv-controlled-' + case_id.split('-')[1].lower()))
    return out, inputs


def _refresh_config_hashes(out, case_id):
    """Hash-aware tampering: recompute the result's own artifact hashes so a
    refusal must come from the ORIGINAL business assertion, not a stale hash."""
    path = out / 'manual-result.json'
    value = json.loads(path.read_text())
    if case_id == 'GAP-CTRLC-IPC':
        config = out / 'config' / 'shutdown.ini'
        digest = _sha(config)
        value['ctrlc_ipc']['config_sha256'] = digest
        for branch in value['ctrlc_ipc']['branches'].values():
            branch['config_sha256'] = digest
            branch['log_sha256'] = _sha(Path(branch['log']))
    else:
        for mode, item in value['diverter_switch'].items():
            item['config_sha256'] = _sha(Path(item['config']))
            item['observation_sha256'] = _sha(Path(item['observation']))
            item['core_log_sha256'] = _sha(Path(item['core_log']))
    path.write_text(json.dumps(value))
    return value


class DriverControlPlanTests(_NoRealEffects):
    def test_v3_options_and_v6_plan_derivation(self):
        for case_id in CASES:
            with self.subTest(case=case_id):
                work = _work('fnreg-dv-plan-')
                plan = _source_plan(work, case_id)
                with mock.patch('platform.system', return_value='Windows'):
                    value = native.manual_inputs(plan, next(
                        c for s in json.loads((ROOT / 'docs/acceptance/catalog.json').read_text())['suites']
                        for c in s.get('cases', []) if c['id'] == case_id), str(work / 'run'))
                    self.assertEqual('fakenet.manual-input.v6', value['schema'])
                    self.assertEqual(CONTROL, value['control'])
                    M.validate_inputs(case_id, value)
                self.assertEqual(M._result_identity(value),
                                 {k: value[k] for k in (*M.IDENTITY, 'source_deployment_identity')})

    def test_wrong_control_rejected_by_options_consumer(self):
        base = {'schema': 'fakenet.manual-options.v3', 'responsea': '192.0.2.55',
                'control': copy.deepcopy(CONTROL)}
        for label, mutate in (('host', lambda v: v['control'].update(host_ipv4='192.0.2.2')),
                              ('bool', lambda v: v['control'].update(tcp_source_ports=[True, 28790])),
                              ('dup', lambda v: v['control'].update(tcp_source_ports=[28790, 28790])),
                              ('string', lambda v: v['control'].update(tcp_source_ports=['28788', '28790'])),
                              ('partial', lambda v: v['control'].update(tcp_source_ports=[28790])),
                              ('extra', lambda v: v['control'].update(extra=1)),
                              ('missing', lambda v: v['control'].pop('tcp_source_ports'))):
            with self.subTest(mutation=label):
                value = copy.deepcopy(base)
                mutate(value)
                with self.assertRaises(ValueError):
                    native.manual_options({'manual': value})

    def test_v5_native_and_foreign_case_rejected_pre_effect(self):
        work = _work('fnreg-dv-rej-')
        for case_id in CASES:
            owned = work / (case_id + '-owned')
            value = _v6_inputs(owned, case_id, 'dv-reject')
            v5 = copy.deepcopy(value)
            v5['schema'] = 'fakenet.manual-input.v5'
            v5.pop('control')
            with self.subTest(case=case_id, kind='v5-native'):
                with self.assertRaisesRegex(ValueError, 'v6 control or explicit fixture'):
                    M.run(case_id, owned, v5)
                self.assertFalse(owned.exists())
            with self.subTest(case=case_id, kind='bad-control'):
                broken = copy.deepcopy(value)
                broken['control']['host_ipv4'] = '192.0.2.2'
                with self.assertRaises(ValueError):
                    M.run(case_id, owned, broken)
                self.assertFalse(owned.exists())
        foreign = _v6_inputs(work / 'x', 'GAP-SYSLOG-ICMP-LOG', 'dv-foreign')
        with self.assertRaisesRegex(ValueError, 'fixed to the protected driver cases'):
            M.validate_inputs('GAP-SYSLOG-ICMP-LOG', foreign)

    def test_legacy_v5_fixture_still_valid(self):
        work = _work('fnreg-dv-leg-')
        value = _v6_inputs(work / 'd', CASES[0], 'dv-legacy')
        v5 = copy.deepcopy(value)
        v5['schema'] = 'fakenet.manual-input.v5'
        v5.pop('control')
        v5['fixture'] = True
        M.validate_inputs(CASES[0], v5)


class DriverControlOracleTests(_NoRealEffects):
    def _ctrlc_fixture(self, work):
        out = work / 'driver'
        out.mkdir(parents=True)
        inputs = _v6_inputs(out, 'GAP-CTRLC-IPC', 'dv-oracle-ctrlc')
        token = inputs['execution_id']
        (out / 'config').mkdir()
        cfg = out / 'config/shutdown.ini'
        cfg.write_text('[FakeNet]\nDivertTraffic: Yes\n[Diverter]\nNetworkMode: SingleHost\n'
                       'LinuxRestrictInterface: Off\nControlLinkExcludeIp: 192.168.204.1\n'
                       'ControlLinkExcludePort: 28788,28790\n', encoding='ascii')
        _write_result(out, inputs, {
            'evidence_kind': 'original-main-ctrl-c-and-file-ipc',
            'checks': [{'id': x} for x in M.CHECKS['GAP-CTRLC-IPC']],
            'ctrlc_ipc': {'config': str(cfg), 'config_sha256': _sha(cfg),
                           'checks': ['ctrlc', 'ipc-stop', 'owned-exit'],
                           'branches': {'ctrlc': {'rc': 0}, 'ipc': {'rc': 0}},
                           'owner_pid': 43210, 'execution_token': inputs['execution_id']},
            'driver_control': {'schema': 'fakenet.driver-control-observation.v1',
                               'control': copy.deepcopy(CONTROL),
                               'branches': {'ctrlc': _driver_row(token),
                                            'ipc': _driver_row(token)}},
            'cleanup': {'scope': 'owned-main-ctrlc-file-ipc-and-runtime-state',
                        'stopped': True, 'threads_joined': True, 'flags_removed': True,
                        'logger_restored': True, 'argv_restored': True,
                        'profile_restored': True, 'signals_restored': True,
                        'system_network_restored': 'outer-native-guard',
                        'system_console_used': False}})
        return out, inputs

    def _ctrlc_detail(self, out, inputs):
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs,
                                         allow_fixture=False)
        return clean, json.dumps(detail)

    def test_ctrlc_v6_oracle_intact_control_evidence(self):
        work = _work('fnreg-dv-oc-')
        out, inputs = self._ctrlc_fixture(work)
        clean, detail = self._ctrlc_detail(out, inputs)
        # the remaining ctrlc business assertions demand full originals; the
        # driver-control gate itself must NOT appear among the refusals
        self.assertNotIn('driver-control', detail)

    def test_ctrlc_tampered_filter_refused(self):
        work = _work('fnreg-dv-tf-')
        out, inputs = self._ctrlc_fixture(work)
        value = json.loads((out / 'manual-result.json').read_text())
        value['driver_control']['branches']['ctrlc']['filter'] = 'outbound and ip'
        (out / 'manual-result.json').write_text(json.dumps(value))
        clean, detail = self._ctrlc_detail(out, inputs)
        self.assertFalse(clean)
        self.assertIn('driver-control', detail)

    def test_ctrlc_invented_off_and_missing_dependency_refused(self):
        work = _work('fnreg-dv-off-')
        out, inputs = self._ctrlc_fixture(work)
        value = json.loads((out / 'manual-result.json').read_text())
        value['driver_control']['branches']['ipc'] = None  # open branch invented as off
        (out / 'manual-result.json').write_text(json.dumps(value))
        clean, detail = self._ctrlc_detail(out, inputs)
        self.assertFalse(clean)
        self.assertIn('driver-control', detail)
        value2 = json.loads((out / 'manual-result.json').read_text())
        value2['driver_control']['branches']['ipc'] = _driver_row(inputs['execution_id'])
        value2['driver_control']['branches']['ipc']['dll'] = None
        (out / 'manual-result.json').write_text(json.dumps(value2))
        clean2, detail2 = self._ctrlc_detail(out, inputs)
        self.assertFalse(clean2)
        self.assertIn('driver-control', detail2)

    def test_switch_v6_config_and_off_null_reconstruction(self):
        from fakenet.mcp.controlfilter import apply_control_link_exclusion, apply_loopback_exclusion
        work = _work('fnreg-dv-sw-')
        out = work / 'driver'
        out.mkdir(parents=True)
        inputs = _v6_inputs(out, 'GAP-DIVERTER-SWITCH', 'dv-oracle-switch')
        token = inputs['execution_id']
        (out / 'config').mkdir()
        for mode, traffic in (('on', 'Yes'), ('off', 'No')):
            (out / ('config/' + mode + '.ini')).write_text(
                '[FakeNet]\nDivertTraffic: ' + traffic + '\n[Diverter]\nNetworkMode: SingleHost\n'
                'LinuxRestrictInterface: Off\nControlLinkExcludeIp: 192.168.204.1\n'
                'ControlLinkExcludePort: 28788,28790\n', encoding='ascii')
        expected_filter = apply_loopback_exclusion(apply_control_link_exclusion(
            'outbound and ip', '192.168.204.1', '28788,28790'))
        row = _driver_row(token)
        row['filter'] = expected_filter
        _write_result(out, inputs, {
            'diverter_switch': {}, 'driver_control': {
                'schema': 'fakenet.driver-control-observation.v1',
                'control': copy.deepcopy(CONTROL),
                'branches': {'on': row, 'off': None}},
            'cleanup': {'stopped': True, 'scope': 'observed-core-start-stop',
                        'system_network_restored': 'outer-native-guard'}})
        # full switch business assertions require complete originals; the
        # v6 config mismatch must surface when the control lines are dropped
        value = json.loads((out / 'manual-result.json').read_text())
        (out / 'config/on.ini').write_text(
            '[FakeNet]\nDivertTraffic: Yes\n[Diverter]\nNetworkMode: SingleHost\n'
            'LinuxRestrictInterface: Off\n', encoding='ascii')
        try:
            O.evaluate(ROOT, out, 'GAP-DIVERTER-SWITCH', inputs, allow_fixture=False)
        except ValueError as exc:
            self.assertNotIn('driver-control', str(exc))  # refusal came from config, not dc


class DriverControlledProducerTests(_NoRealEffects):
    """S92-F5: the REAL producers run against a controlled in-process Windows
    backend; the ORIGINAL oracles must reach their full positive verdict, and
    every controlled fault must be refused without a real exit."""

    def setUp(self):
        super().setUp()
        ControlledWindowsDiverter.instances = []
        ControlledWindowsDiverter.fail_open = False
        ControlledWindowsDiverter.drop_exclusion = False

    def _original_open(self):
        return ControlledWindowsDiverter.__dict__['_open_windivert_handle']

    def _run(self, case_id, execution):
        work = _work('fnreg-dv-ctrl-')
        out, inputs = _v6_case_inputs(work, case_id, execution)
        with _windows_environment(work):
            value = M.run(case_id, out, inputs)
        return work, out, inputs, value

    def test_ctrlc_v6_controlled_original_producer_positive(self):
        work, out, inputs, value = self._run('GAP-CTRLC-IPC', 'dv-ctrl-ctrlc')
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs,
                                         allow_fixture=False)
        self.assertTrue(clean, detail)
        self.assertEqual(['ctrlc', 'ipc-stop', 'owned-exit'],
                         [row['id'] for row in rows])
        self.assertTrue(all(row['status'] == 'pass' for row in rows), rows)
        observation = value['driver_control']
        self.assertEqual('fakenet.driver-control-observation.v1', observation['schema'])
        self.assertEqual(CONTROL, observation['control'])
        self.assertEqual({'ctrlc', 'ipc'}, set(observation['branches']))
        for mode, row in observation['branches'].items():
            self.assertIsNotNone(row, mode)
            self.assertTrue(row['opened'], mode)
            self.assertTrue(row['filter_validated'], mode)
            self.assertEqual(_expected_filter(), row['filter'], mode)
            self.assertEqual(inputs['execution_id'], row['owner_execution'], mode)
            for field in ('pydivert_module', 'dll', 'sys'):
                self.assertEqual(64, len(row[field]['sha256']), (mode, field))
        self.assertEqual(2, len(ControlledWindowsDiverter.instances))
        for backend in ControlledWindowsDiverter.instances:
            self.assertEqual(1, backend.start_calls)
            self.assertEqual(1, backend.stop_calls)
            self.assertIsNone(backend.handle)
        self.assertEqual('outer-native-guard',
                         value['cleanup']['system_network_restored'])

    def test_filter_validation_win32_bool_and_exception(self):
        original = self._original_open()
        outcomes = ((True, True), (1, True), (False, False), (0, False))
        for valid, expected in outcomes:
            with self.subTest(value=valid, value_type=type(valid).__name__):
                with mock.patch.object(_WinDivert, 'check_filter',
                                       return_value=(valid, 0, '')):
                    work, out, inputs, value = self._run(
                        'GAP-DIVERTER-SWITCH', 'dv-bool-' + type(valid).__name__
                        + '-' + str(valid))
                self.assertIs(expected, value['driver_control']['branches']['on']
                              ['filter_validated'])
                if expected:
                    rows, clean, detail = O.evaluate(
                        ROOT, out, 'GAP-DIVERTER-SWITCH', inputs, allow_fixture=False)
                    self.assertTrue(clean, detail)
                    self.assertTrue(all(row['status'] == 'pass' for row in rows), rows)
                else:
                    with self.assertRaisesRegex(ValueError, 'open evidence incomplete'):
                        O.evaluate(ROOT, out, 'GAP-DIVERTER-SWITCH', inputs,
                                   allow_fixture=False)
                self.assertIs(original, self._original_open())
                self.assertTrue(all(backend.handle is None
                                    for backend in ControlledWindowsDiverter.instances))
        with mock.patch.object(_WinDivert, 'check_filter',
                               side_effect=RuntimeError('controlled check failure')):
            work, out, inputs, value = self._run(
                'GAP-DIVERTER-SWITCH', 'dv-bool-check-error')
        self.assertIs(False, value['driver_control']['branches']['on']['filter_validated'])
        with self.assertRaisesRegex(ValueError, 'open evidence incomplete'):
            O.evaluate(ROOT, out, 'GAP-DIVERTER-SWITCH', inputs, allow_fixture=False)
        self.assertIs(original, self._original_open())
        self.assertTrue(all(backend.handle is None
                            for backend in ControlledWindowsDiverter.instances))

    def test_switch_v6_controlled_original_producer_positive(self):
        original = self._original_open()
        work, out, inputs, value = self._run('GAP-DIVERTER-SWITCH', 'dv-ctrl-switch')
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-DIVERTER-SWITCH', inputs,
                                         allow_fixture=False)
        self.assertTrue(clean, detail)
        self.assertEqual(['on', 'off', 'restore'], [row['id'] for row in rows])
        self.assertTrue(all(row['status'] == 'pass' for row in rows), rows)
        observation = value['driver_control']
        self.assertEqual(CONTROL, observation['control'])
        self.assertEqual({'on', 'off'}, set(observation['branches']))
        self.assertIsNone(observation['branches']['off'])
        row = observation['branches']['on']
        self.assertTrue(row['opened'] and row['filter_validated'])
        self.assertEqual(_expected_filter(), row['filter'])
        self.assertEqual(inputs['execution_id'], row['owner_execution'])
        self.assertEqual(1, len(ControlledWindowsDiverter.instances))
        backend = ControlledWindowsDiverter.instances[0]
        self.assertEqual(1, backend.start_calls)
        self.assertEqual(1, backend.stop_calls)
        self.assertIsNone(backend.handle)
        self.assertEqual(_expected_filter(), backend.filter)
        # the global original-open wrapper is restored after a normal exit
        self.assertIs(original, ControlledWindowsDiverter.__dict__['_open_windivert_handle'])

    def test_wrong_filter_is_refused_by_the_driver_control_gate(self):
        ControlledWindowsDiverter.drop_exclusion = True
        work, out, inputs, value = self._run('GAP-DIVERTER-SWITCH', 'dv-bad-filter')
        self.assertEqual('outbound and ip', value['driver_control']['branches']['on']['filter'])
        with self.assertRaisesRegex(ValueError, 'final filter differs'):
            O.evaluate(ROOT, out, 'GAP-DIVERTER-SWITCH', inputs, allow_fixture=False)

    def test_invented_off_open_and_missing_source_are_refused(self):
        work, out, inputs, value = self._run('GAP-DIVERTER-SWITCH', 'dv-bad-off')
        path = out / 'manual-result.json'
        base = json.loads(path.read_text())
        invented = copy.deepcopy(base)
        invented['driver_control']['branches']['off'] = copy.deepcopy(
            invented['driver_control']['branches']['on'])
        path.write_text(json.dumps(invented))
        with self.assertRaisesRegex(ValueError, 'off branch must not open'):
            O.evaluate(ROOT, out, 'GAP-DIVERTER-SWITCH', inputs, allow_fixture=False)
        missing = copy.deepcopy(base)
        missing['driver_control']['branches']['on']['dll'] = None
        path.write_text(json.dumps(missing))
        with self.assertRaisesRegex(ValueError, 'dependency identity missing: dll'):
            O.evaluate(ROOT, out, 'GAP-DIVERTER-SWITCH', inputs, allow_fixture=False)
        path.write_text(json.dumps(base))

    def test_hash_aware_config_tamper_reaches_the_business_assertion(self):
        # both producers: mutate the owned config and refresh the result's own
        # hashes, so only the exact-config business assertion can refuse it
        work, out, inputs, value = self._run('GAP-DIVERTER-SWITCH', 'dv-cfg-switch')
        (out / 'config' / 'on.ini').write_text(
            '[FakeNet]\nDivertTraffic: Yes\n[Diverter]\nNetworkMode: SingleHost\n'
            'LinuxRestrictInterface: Off\n', encoding='ascii')
        _refresh_config_hashes(out, 'GAP-DIVERTER-SWITCH')
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-DIVERTER-SWITCH', inputs,
                                         allow_fixture=False)
        self.assertFalse(clean)
        self.assertIn('traffic configuration differs', json.dumps(detail))
        work, out, inputs, value = self._run('GAP-CTRLC-IPC', 'dv-cfg-ctrlc')
        (out / 'config' / 'shutdown.ini').write_text(
            '[FakeNet]\nDivertTraffic: Yes\n[Diverter]\nNetworkMode: SingleHost\n'
            'LinuxRestrictInterface: Off\n', encoding='ascii')
        _refresh_config_hashes(out, 'GAP-CTRLC-IPC')
        rows, clean, detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs,
                                         allow_fixture=False)
        self.assertFalse(clean)
        self.assertIn('exact configuration mismatch', json.dumps(detail))

    def test_unprotected_v1_packaged_and_v5_native_refused_before_effect(self):
        for case_id in CASES:
            with self.subTest(case=case_id):
                work = _work('fnreg-dv-v1-')
                out, value = _v6_case_inputs(work, case_id, 'dv-v1-reject')
                legacy = copy.deepcopy(value)
                legacy.update(schema='fakenet.manual-input.v1', package_sha256='1' * 64)
                legacy.pop('control')
                legacy.pop('source_deployment_identity')
                name = ('real_ctrlc_ipc' if case_id == CASES[0]
                        else 'real_diverter_switch')
                with mock.patch.object(M, name,
                                       side_effect=AssertionError('REAL_EFFECT_HIT')):
                    with self.assertRaisesRegex(ValueError, 'v6 control or explicit fixture'):
                        M.run(case_id, out, legacy)
                self.assertFalse(out.exists())

    def test_wrong_target_platform_refused_before_effect(self):
        work = _work('fnreg-dv-linux-')
        out, value = _v6_case_inputs(work, 'GAP-CTRLC-IPC', 'dv-linux-consume')
        with mock.patch('platform.system', return_value='Linux'):
            with self.assertRaisesRegex(ValueError, 'fixed to the Windows target'):
                M.run('GAP-CTRLC-IPC', out, value)
        self.assertFalse(out.exists())
        plan = {'candidate': {'source_commit': HEAD, 'deployment_kind': 'source',
                              'package_sha256': None, 'offline_fixture': False},
                'execution_id': 'dv-linux-plan',
                'native_source_hashes': {'tools/acceptance_native.py':
                                         _sha(ROOT / 'tools/acceptance_native.py')},
                'source_hashes': {},
                'environment': {'native_runtime': {'identity': {'platform': 'linux'}},
                                'manual': {'schema': 'fakenet.manual-options.v3',
                                           'responsea': '192.0.2.55',
                                           'control': copy.deepcopy(CONTROL)}}}
        with self.assertRaisesRegex(ValueError, 'fixed to the Windows target'):
            native.manual_remote_inputs(plan, {'id': 'GAP-DIVERTER-SWITCH'},
                                        str(work / 'linux-plan'))


class DriverObserverRestorationTests(_NoRealEffects):
    """S92-F4: constructor/parse/config/handler/start failures restore the
    original global open wrapper and preserve the original exception."""

    class ControlledSetupFailure(Exception):
        pass

    def setUp(self):
        super().setUp()
        ControlledWindowsDiverter.instances = []
        ControlledWindowsDiverter.fail_open = False
        ControlledWindowsDiverter.drop_exclusion = False
        self._profile = sys.getprofile()

    def _original_open(self):
        return ControlledWindowsDiverter.__dict__['_open_windivert_handle']

    def _assert_restored(self, original):
        self.assertIs(original, ControlledWindowsDiverter.__dict__['_open_windivert_handle'])
        self.assertIs(self._profile, sys.getprofile())
        self.assertFalse(any(item.handle is not None
                             for item in ControlledWindowsDiverter.instances))

    def test_switch_setup_failures_restore_the_wrapper(self):
        failure = self.ControlledSetupFailure
        original = self._original_open()

        def raising(message):
            def boom(*args, **kwargs):
                raise failure(message)
            return boom

        def config_failure(work, out):
            out.mkdir()
            (out / 'config').write_text('not-a-directory', encoding='ascii')
            return contextlib.nullcontext()

        class FailingStart(ControlledWindowsDiverter):
            def start(self):
                raise failure('controlled start failure')

        cases = (
            ('constructor', mock.patch('fakenet.fakenet.Fakenet.__init__',
                                       raising('controlled constructor failure')), True),
            ('parse', mock.patch('fakenet.fakenet.Fakenet.parse_config',
                                 raising('controlled parse failure')), True),
            ('handler', mock.patch('logging.FileHandler',
                                   raising('controlled FileHandler failure')), True),
            ('config', config_failure, True),
            ('start', None, False),
        )
        for name, patch, raises in cases:
            with self.subTest(failure=name):
                work = _work('fnreg-dv-rst-' + name + '-')
                out = work / 'driver'
                inputs = _v6_inputs(out, 'GAP-DIVERTER-SWITCH', 'dv-rst-' + name)
                diverter = FailingStart if name == 'start' else ControlledWindowsDiverter
                if name != 'config':
                    out.mkdir()
                with _windows_environment(work, diverter=diverter):
                    if name == 'config':
                        with config_failure(work, out):
                            with self.assertRaises(FileExistsError):
                                M.real_diverter_switch('GAP-DIVERTER-SWITCH', out, inputs)
                    elif patch is not None:
                        with patch:
                            with self.assertRaises(failure):
                                M.real_diverter_switch('GAP-DIVERTER-SWITCH', out, inputs)
                    else:
                        # a failing backend start is folded into the recorded
                        # production error by the original producer (no raise),
                        # never into a claimed success
                        value = M.real_diverter_switch('GAP-DIVERTER-SWITCH', out, inputs)
                        self.assertEqual('ControlledSetupFailure',
                                         value['diverter_switch']['on']['error']['type'])
                        self.assertFalse(value['cleanup']['stopped'])
                self._assert_restored(original)

    def test_ctrlc_setup_failures_restore_the_wrapper(self):
        failure = self.ControlledSetupFailure
        original = self._original_open()

        def constructor(*args, **kwargs):
            raise failure('controlled constructor failure')

        def handler(*args, **kwargs):
            raise failure('controlled FileHandler failure')

        for name, patch in (('constructor', mock.patch('fakenet.fakenet.Fakenet.__init__',
                                                       constructor)),
                            ('handler', mock.patch('logging.FileHandler', handler))):
            with self.subTest(failure=name):
                work = _work('fnreg-dv-crst-' + name + '-')
                out = work / 'driver'
                inputs = _v6_inputs(out, 'GAP-CTRLC-IPC', 'dv-crst-' + name)
                with _windows_environment(work):
                    with patch:
                        out.mkdir()
                        value = M.real_ctrlc_ipc('GAP-CTRLC-IPC', out, inputs)
                # the original main folds the setup failure into rc=1; the
                # producer never claims success and the wrapper is restored
                self.assertEqual(1, value['ctrlc_ipc']['branches']['ctrlc']['rc'])
                self.assertFalse(value['cleanup']['stopped'])
                self._assert_restored(original)
                rows, clean, detail = O.evaluate(ROOT, out, 'GAP-CTRLC-IPC', inputs,
                                                 allow_fixture=False)
                self.assertFalse(clean, detail)
        work = _work('fnreg-dv-crst-config-')
        out = work / 'driver'
        inputs = _v6_inputs(out, 'GAP-CTRLC-IPC', 'dv-crst-config')
        out.mkdir()
        (out / 'config').write_text('not-a-directory', encoding='ascii')
        with _windows_environment(work):
            with self.assertRaises(FileExistsError):
                M.real_ctrlc_ipc('GAP-CTRLC-IPC', out, inputs)
        self._assert_restored(original)


if __name__ == '__main__':
    unittest.main()
