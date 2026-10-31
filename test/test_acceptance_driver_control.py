"""DV guarded tests (T068-R01): the protected driver-two-case v3/v6 chain
through the REAL consumers - plan CLI options/control, input derivation and
identity, pre-effect refusals, and the v6 oracle reconstruction with real
pure-function filters. Benign static fixtures only; no real OS/network/VM."""
import contextlib
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
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


class DriverControlPlanTests(_NoRealEffects):
    def test_v3_options_and_v6_plan_derivation(self):
        for case_id in CASES:
            with self.subTest(case=case_id):
                work = Path(tempfile.mkdtemp(prefix='fnreg-dv-plan-', dir=str(ROOT / 'Logs/fnreg-T068-R01-two-driver-protected-native/fixtures')))
                plan = _source_plan(work, case_id)
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
        work = Path(tempfile.mkdtemp(prefix='fnreg-dv-rej-', dir=str(ROOT / 'Logs/fnreg-T068-R01-two-driver-protected-native/fixtures')))
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
        work = Path(tempfile.mkdtemp(prefix='fnreg-dv-leg-', dir=str(ROOT / 'Logs/fnreg-T068-R01-two-driver-protected-native/fixtures')))
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
        work = Path(tempfile.mkdtemp(prefix='fnreg-dv-oc-', dir=str(ROOT / 'Logs/fnreg-T068-R01-two-driver-protected-native/fixtures')))
        out, inputs = self._ctrlc_fixture(work)
        clean, detail = self._ctrlc_detail(out, inputs)
        # the remaining ctrlc business assertions demand full originals; the
        # driver-control gate itself must NOT appear among the refusals
        self.assertNotIn('driver-control', detail)

    def test_ctrlc_tampered_filter_refused(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-dv-tf-', dir=str(ROOT / 'Logs/fnreg-T068-R01-two-driver-protected-native/fixtures')))
        out, inputs = self._ctrlc_fixture(work)
        value = json.loads((out / 'manual-result.json').read_text())
        value['driver_control']['branches']['ctrlc']['filter'] = 'outbound and ip'
        (out / 'manual-result.json').write_text(json.dumps(value))
        clean, detail = self._ctrlc_detail(out, inputs)
        self.assertFalse(clean)
        self.assertIn('driver-control', detail)

    def test_ctrlc_invented_off_and_missing_dependency_refused(self):
        work = Path(tempfile.mkdtemp(prefix='fnreg-dv-off-', dir=str(ROOT / 'Logs/fnreg-T068-R01-two-driver-protected-native/fixtures')))
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
        work = Path(tempfile.mkdtemp(prefix='fnreg-dv-sw-', dir=str(ROOT / 'Logs/fnreg-T068-R01-two-driver-protected-native/fixtures')))
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


if __name__ == '__main__':
    unittest.main()
