"""Offline tests for policy configuration, wire probes and content oracle."""
import json
import shutil
import subprocess
from unittest import mock
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import acceptance_policy as POLICY
import acceptance_policy_oracles as ORACLE
import acceptance_native as NATIVE


class PolicyConfigTests(unittest.TestCase):
    def test_config_is_deterministic_and_uses_reviewed_grammar(self):
        first = POLICY.config_text('domain')
        second = POLICY.config_text('domain')
        self.assertEqual(first, second)
        self.assertIn('ExternalAllowedDomains = api.example.test, *.example.test', first)
        self.assertIn('ExternalVerifyTLSSNI = Yes', first)
        self.assertNotIn('gui', first.lower())
        self.assertIn('ExternalTakeoverIPv4 = 192.0.2.50',
                      POLICY.config_text('takeover', strict=False))
        ipv4 = POLICY.config_text('ipv4')
        self.assertIn('ExternalAllowedIPv4Rules = TCP/8.8.8.8/443', ipv4)
        self.assertNotIn('ExternalAllowedIPv4 =', ipv4)

    def test_guest_request_carries_explicit_policy_inputs(self):
        import acceptance_guest
        catalog = json.loads((ROOT / 'docs/acceptance/catalog.json').read_text())
        case = next(c for suite in catalog['suites']
                    for c in suite.get('cases') or []
                    if c['id'] == 'POL-DOMAIN-ALLOW')
        policy = POLICY._inputs()
        with tempfile.TemporaryDirectory() as temp:
            request = {
                'schema': 'fakenet.native-guest-request.v1',
                'case_id': case['id'], 'case': case,
                'checks': POLICY.CHECKS['domain'], 'source_hashes': {},
                'candidate': {'source_commit': 'offline-fixture'},
                'target': {'platform': 'windows', 'hostname': 'substitute'},
                'output_root': str(Path(temp) / 'guest-output'),
                'execution_id': 'execution-fixture', 'actions': ['native'],
                'policy': policy,
            }
            receipt = {'status': 'pass'}
            with mock.patch.object(NATIVE, 'run_production',
                                   return_value=receipt) as run, \
                    mock.patch('acceptance_runtime.require_target'):
                self.assertEqual(0, acceptance_guest.execute(request, ROOT))
        self.assertEqual(policy, run.call_args.args[2]['environment']['policy'])

    def test_production_argv_requires_frozen_policy_inputs(self):
        case = {'id': 'POL-DOMAIN-ALLOW', 'native_driver': 'policy-domain',
                'platforms': ['windows'], 'modes': ['singlehost']}
        with self.assertRaises(ValueError):
            NATIVE.production_command(ROOT, case, {'environment': {}},
                                      Path('/tmp/not-used'), sys.executable)
        argv = NATIVE.production_command(
            ROOT, case, {'environment': {'policy': POLICY._inputs()}},
            Path('/tmp/not-used'), sys.executable)
        self.assertIn('--inputs', argv)
        self.assertTrue(argv[argv.index('--inputs') + 1].endswith(
            'policy-inputs.json'))

    def test_driver_table_exposes_policy_drivers(self):
        drivers = NATIVE.driver_table(ROOT)
        for name, scenario in (('policy-domain', 'domain'),
                               ('policy-ipv4', 'ipv4'),
                               ('policy-takeover', 'takeover'),
                               ('policy-combined', 'combined')):
            self.assertIn(name, drivers)
            self.assertTrue(drivers[name]['implemented'])
            self.assertEqual(POLICY.CHECKS[scenario], drivers[name]['checks'])


class PolicyFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name) / 'driver'
        POLICY.fixture('domain', self.out)

    def evaluate(self, allow_fixture=True):
        rows, clean = ORACLE.evaluate(self.out, 'domain',
                                      POLICY.CHECKS['domain'],
                                      allow_fixture=allow_fixture)
        return NATIVE._judge_rows(rows, POLICY.CHECKS['domain']), clean

    def test_empty_fixture_never_passes_content_oracle(self):
        with self.assertRaises(ValueError):ORACLE.evaluate(self.out,'domain',POLICY.CHECKS['domain'])
        rows,clean=ORACLE.evaluate(self.out,'domain',POLICY.CHECKS['domain'],allow_fixture=True)
        self.assertFalse(clean);self.assertNotEqual('pass',NATIVE._judge_rows(rows,POLICY.CHECKS['domain'])['verdict'])

    def test_adapter_does_not_accept_empty_fixture_as_content(self):
        rows=NATIVE._read_oracle('policy-result',self.out/'policy-result.json')
        self.assertNotEqual('pass',NATIVE._judge_rows(rows,POLICY.CHECKS['domain'])['verdict'])


class PolicyProductionCliMemoryTests(unittest.TestCase):
    """Keep the real registry, dispatcher, driver and judge; replace OS edges."""
    CASES = ('POL-DOMAIN-ALLOW', 'POL-TAKEOVER', 'POL-TCP-UDP-RECOVERY',
             'IP-REVIEWED-TLS-MATRIX', 'IP-TAKEOVER-COEXIST',
             'EGRESS-ALLOW-CHAIN', 'EGRESS-NEGATIVES', 'EGRESS-RESTORE')

    def setUp(self):
        import acceptance
        self.acc = acceptance
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.run = self.base / 'run'
        self.catalog_hash = POLICY.sha256(ROOT / 'docs/acceptance/catalog.json')
        self.identity = {'platform': 'windows', 'hostname': 'memory-boundary'}
        candidate = {'schema': self.acc.CANDIDATE_V2,
                     'source_commit': self.acc.git_head(ROOT),
                     'offline_fixture': True, 'deployed_identity': self.identity}
        environment = {'schema': self.acc.ENVIRONMENT_V2,
                       'targets': ['windows'],
                       'interpreters': {'python': sys.executable},
                       'endpoints': [], 'auth_refs': [],
                       'work_root': str(self.base), 'allowed_actions': ['native'],
                       'native_runtime': {'transport': 'local-target',
                                          'identity': self.identity},
                       'policy': POLICY.memory_inputs()}
        for name, value in [('candidate', candidate), ('environment', environment)]:
            (self.base / (name + '.json')).write_text(json.dumps(value))

    def cli(self, *args):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.acc.main(['--root', str(ROOT)] + list(map(str, args)))
        return code, out.getvalue(), err.getvalue()

    def execute(self, cases=None):
        selection = []
        for case in cases or self.CASES:
            selection.extend(['--case', case])
        result = self.cli('plan', '--mode', 'selected', *selection,
                          '--candidate', self.base / 'candidate.json',
                          '--environment', self.base / 'environment.json',
                          '--output', self.run / 'plan.json')
        self.assertEqual(0, result[0], result)
        original = subprocess.Popen
        calls = []

        class Process:
            pid = 123456789
            def __init__(self, argv):
                calls.append(argv)
                if '--substitute' not in argv:
                    raise AssertionError('offline candidate did not select memory boundary')
                self.returncode = POLICY.main(argv[2:])
            def wait(self, timeout=None):
                return self.returncode

        def popen(argv, *args, **kwargs):
            if isinstance(argv, list) and len(argv) > 1 and argv[1].endswith('acceptance_policy.py'):
                return Process(argv)
            return original(argv, *args, **kwargs)

        with mock.patch.object(NATIVE.subprocess, 'Popen', side_effect=popen), \
                mock.patch('acceptance_runtime.require_target', return_value=self.identity):
            result = self.cli('execute', '--plan', self.run / 'plan.json')
        self.assertEqual(0, result[0], result)
        self.assertEqual(len(cases or self.CASES), len(calls))
        result = self.cli('judge', '--plan', self.run / 'plan.json',
                          '--results', self.run / 'results',
                          '--output', self.run / 'independent.json')
        self.assertEqual(0, result[0], result)
        value = json.loads((self.run / 'independent.json').read_text())
        self.assertTrue(value['fixture_contract_pass'])
        self.assertFalse(value['full_functional_pass'])
        self.assertEqual(len(cases or self.CASES), value['checks']['passed'])
        self.assertEqual(self.catalog_hash, POLICY.sha256(ROOT / 'docs/acceptance/catalog.json'))

    def rehash_and_judge(self, case):
        directory = self.run / 'results' / case
        receipt_path = directory / 'receipt.json'
        receipt = json.loads(receipt_path.read_text())
        for row in receipt['artifacts']:
            row['sha256'] = POLICY.sha256(row['path'])
        receipt_path.write_text(json.dumps(receipt))
        index_path = self.run / 'results/results.json'
        index = json.loads(index_path.read_text())
        for row in index['receipts']:
            if row['case_id'] == case:
                row['sha256'] = POLICY.sha256(receipt_path)
        index_path.write_text(json.dumps(index))
        result = self.cli('judge', '--plan', self.run / 'plan.json',
                          '--results', self.run / 'results',
                          '--output', self.run / 'negative.json')
        self.assertNotEqual(0, result[0], result)
        value = json.loads((self.run / 'negative.json').read_text())
        self.assertFalse(value['fixture_contract_pass'])
        self.assertFalse(value['full_functional_pass'])
        return value

    def test_unchanged_production_catalog_eight_cases(self):
        self.execute()

    def test_forbidden_success_is_rejected_by_independent_cli(self):
        import struct
        case = 'IP-REVIEWED-TLS-MATRIX'
        self.execute([case])
        directory = self.run / 'results' / case / 'driver'
        path = directory / 'policy-result.json'
        value = json.loads(path.read_text())
        attempt = next(a for a in value['attempts'] if a['id'] == 'port_80_denied')
        flow = attempt['tuple']
        stamp = (attempt['started_at'] + attempt['ended_at']) / 2
        payload = ('FNPR/1|%s|OK\n' % attempt['nonce']).encode()
        raw = POLICY._frame(flow['dst'], flow['src'], flow['port'], flow['sport'], 'TCP', payload)
        capture = directory / value['pcap'][0]['path']
        sec = int(stamp)
        with capture.open('ab') as stream:
            stream.write(struct.pack('<IIII', sec, int((stamp-sec)*1e6), len(raw), len(raw)) + raw)
        value['pcap'][0]['sha256'] = POLICY.sha256(capture)
        path.write_text(json.dumps(value))
        summary = self.rehash_and_judge(case)
        self.assertEqual(['port_80_denied'], summary['cases'][0]['evaluation']['failed'])

    def test_one_way_tls_is_rejected_by_independent_cli(self):
        import struct
        case = 'POL-DOMAIN-ALLOW'
        self.execute([case])
        directory = self.run / 'results' / case / 'driver'
        path = directory / 'policy-result.json'
        value = json.loads(path.read_text())
        attempt = next(a for a in value['attempts'] if a['id'] == 'tls_application')
        flow = attempt['tuple']
        capture = directory / value['pcap'][0]['path']
        data = capture.read_bytes()
        changed = bytearray(data[:24])
        offset = 24
        while offset < len(data):
            header = data[offset:offset+16]
            sec, usec, size, original = struct.unpack('<IIII', header)
            raw = data[offset+16:offset+16+size]
            offset += 16 + size
            packet = ORACLE._decode_frame(raw, 1, sec+usec/1e6)
            if packet and packet['proto'] == 'TCP' and packet['src'] == flow['dst'] and packet['sport'] == flow['port']:
                raw = POLICY._frame(flow['src'], flow['dst'], flow['sport'], flow['port'], 'TCP', b'outbound only')
                header = struct.pack('<IIII', sec, usec, len(raw), len(raw))
            changed.extend(header + raw)
        capture.write_bytes(changed)
        value['pcap'][0]['sha256'] = POLICY.sha256(capture)
        path.write_text(json.dumps(value))
        summary = self.rehash_and_judge(case)
        self.assertEqual(['tls_application'], summary['cases'][0]['evaluation']['failed'])


class PolicySubstituteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def run_scenario(self, scenario):
        out = self.base / ('run-' + scenario)
        self.assertEqual(0, POLICY.run(scenario, out, substitute=True))
        return out

    def evaluate(self, out, scenario):
        return ORACLE.evaluate(out, scenario, POLICY.CHECKS[scenario], allow_fixture=True)

    def test_all_scenarios_use_real_probe_code_and_content_oracle(self):
        for scenario in ('domain', 'ipv4', 'takeover', 'combined'):
            with self.subTest(scenario=scenario):
                out = self.run_scenario(scenario)
                rows, clean = self.evaluate(out, scenario)
                self.assertTrue(clean)
                self.assertEqual('pass', NATIVE._judge_rows(
                    rows, POLICY.CHECKS[scenario])['verdict'])
                result = json.loads((out / 'policy-result.json').read_text())
                self.assertTrue(result['fixture'])
                self.assertGreater(len(result['attempts']), 0)
                self.assertTrue(result['pcap'])
                self.assertNotEqual(0, (out / result['pcap'][0]['path']).stat().st_size)

    def test_empty_capture_cannot_be_native_evidence(self):
        out = self.base / 'empty'
        POLICY.fixture('domain', out)
        value = json.loads((out / 'policy-result.json').read_text())
        value['fixture'] = False
        (out / 'policy-result.json').write_text(json.dumps(value))
        rows,clean=self.evaluate(out,'domain')
        self.assertFalse(clean);self.assertNotEqual('pass',NATIVE._judge_rows(rows,POLICY.CHECKS['domain'])['verdict'])

    def test_changed_config_and_empty_evidence_are_rejected(self):
        out = self.run_scenario('domain')
        (out / 'policy.ini').write_text('[Diverter]\nExternalAccessPolicy=Off\n')
        value = json.loads((out / 'policy-result.json').read_text())
        value['config']['sha256'] = POLICY.sha256(out / 'policy.ini')
        for row in value['checks']:
            row['evidence'] = []
            row['tuple'] = {'proto': 'NONE', 'src': 'bad', 'dst': 'bad',
                            'port': -1}
        (out / 'policy-result.json').write_text(json.dumps(value))
        rows, clean = self.evaluate(out, 'domain')
        self.assertFalse(clean)
        self.assertNotEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['domain'])['verdict'])

    def test_wrong_nonce_and_missing_attempt_fail(self):
        out = self.run_scenario('domain')
        value = json.loads((out / 'policy-result.json').read_text())
        value['checks'][0]['nonce'] = 'wrong-nonce'
        (out / 'policy-result.json').write_text(json.dumps(value))
        rows, clean = self.evaluate(out, 'domain')
        self.assertFalse(clean)
        self.assertNotEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['domain'])['verdict'])
        value['attempts'] = []
        (out / 'policy-result.json').write_text(json.dumps(value))
        rows, clean = self.evaluate(out, 'domain')
        self.assertFalse(clean)
        self.assertNotEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['domain'])['verdict'])

    def test_wrong_destination_and_missing_capture_fail(self):
        out = self.run_scenario('ipv4')
        value = json.loads((out / 'policy-result.json').read_text())
        value['checks'][0]['tuple']['dst'] = '192.0.2.99'
        (out / 'policy-result.json').write_text(json.dumps(value))
        rows, clean = self.evaluate(out, 'ipv4')
        self.assertFalse(clean)
        self.assertNotEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['ipv4'])['verdict'])
        value = json.loads((out / 'policy-result.json').read_text())
        value['pcap'] = []
        (out / 'policy-result.json').write_text(json.dumps(value))
        rows, clean = self.evaluate(out, 'ipv4')
        self.assertFalse(clean)
        self.assertNotEqual('pass', NATIVE._judge_rows(
            rows, POLICY.CHECKS['ipv4'])['verdict'])



class PolicySafetyAndFidelityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)

    def test_missing_inputs_and_unknown_selection_have_no_effects(self):
        with mock.patch.object(POLICY.subprocess,'Popen',side_effect=AssertionError('unexpected process')):
            for values,selection in [({},None),(POLICY._inputs(),{'unexpected'})]:
                out=self.base/('missing' if not values else 'selection')
                with self.assertRaises(ValueError):POLICY.run('domain',out,core_command=['never'],inputs=values,selected=selection)
                self.assertFalse(out.exists())

    def test_route_selection_sends_nothing_and_observes_cleanup(self):
        out=self.base/'route'
        with mock.patch.object(POLICY,'_dns_query',side_effect=AssertionError('unselected DNS')),mock.patch.object(POLICY,'_tcp_exchange',side_effect=AssertionError('unselected TCP')),mock.patch.object(POLICY,'_udp_exchange',side_effect=AssertionError('unselected UDP')),mock.patch.object(POLICY,'_ping',side_effect=AssertionError('unselected ping')):
            self.assertEqual(0,POLICY.run('domain',out,substitute=True,selected={'route_restore'}))
        rows,clean=ORACLE.evaluate(out,'domain',['route_restore'],allow_fixture=True)
        self.assertTrue(clean);self.assertEqual(['pass'],[r['status'] for r in rows])

    def test_denied_success_cannot_be_hidden_by_a_deny_log(self):
        import struct
        out=self.base/'denied';POLICY.run('ipv4',out,substitute=True)
        p=out/'policy-result.json';v=json.loads(p.read_text());a=next(x for x in v['attempts'] if x['id']=='port_80_denied');flow=a['tuple']
        stamp=(a['started_at']+a['ended_at'])/2;payload=('FNPR/1|%s|OK\n'%a['nonce']).encode()
        raw=POLICY._frame(flow['dst'],flow['src'],flow['port'],flow['sport'],'TCP',payload)
        path=out/v['pcap'][0]['path'];sec=int(stamp)
        path.write_bytes(path.read_bytes()+struct.pack('<IIII',sec,int((stamp-sec)*1e6),len(raw),len(raw))+raw)
        v['pcap'][0]['sha256']=POLICY.sha256(path);p.write_text(json.dumps(v))
        rows,clean=ORACLE.evaluate(out,'ipv4',POLICY.CHECKS['ipv4'],allow_fixture=True)
        rejected=next(x for x in rows if x['id']=='port_80_denied')
        self.assertEqual('fail',rejected['status']);self.assertIn('successful',rejected['reason']);self.assertFalse(clean)

    def test_same_direction_packets_are_not_a_roundtrip(self):
        import struct
        out=self.base/'one-way';POLICY.run('domain',out,substitute=True)
        p=out/'policy-result.json';v=json.loads(p.read_text());a=next(x for x in v['attempts'] if x['id']=='tls_application');f=a['tuple']
        path=out/v['pcap'][0]['path'];data=path.read_bytes();new=bytearray(data[:24]);offset=24
        while offset<len(data):
            h=data[offset:offset+16];sec,usec,n,orig=struct.unpack('<IIII',h);raw=data[offset+16:offset+16+n];offset+=16+n
            packet=ORACLE._decode_frame(raw,1,sec+usec/1e6)
            if packet and packet['proto']=='TCP' and packet['src']==f['dst'] and packet['sport']==f['port']:
                raw=POLICY._frame(f['src'],f['dst'],f['sport'],f['port'],'TCP',b'outbound only')
                h=struct.pack('<IIII',sec,usec,len(raw),len(raw))
            new.extend(h+raw)
        path.write_bytes(new);v['pcap'][0]['sha256']=POLICY.sha256(path);p.write_text(json.dumps(v))
        rows,clean=ORACLE.evaluate(out,'domain',POLICY.CHECKS['domain'],allow_fixture=True)
        self.assertEqual('fail',next(r for r in rows if r['id']=='tls_application')['status']);self.assertFalse(clean)

    def test_changed_network_original_prevents_cleanup_credit(self):
        out=self.base/'restore';POLICY.run('domain',out,substitute=True)
        p=out/'policy-result.json';v=json.loads(p.read_text());after=out/'network-after.json';after.write_text('{"routes":["changed"]}')
        v['observations']['network-after']['sha256']=POLICY.sha256(after);p.write_text(json.dumps(v))
        rows,clean=ORACLE.evaluate(out,'domain',POLICY.CHECKS['domain'],allow_fixture=True)
        self.assertFalse(clean);self.assertEqual('fail',next(r for r in rows if r['id']=='route_restore')['status'])


class PolicyOwnedEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.inputs = POLICY.memory_inputs()
        self.inputs['host_service'] = {'bind_ipv4': self.inputs['sink_ip'],
                                      'allowed_peer_ipv4': self.inputs['local_source'],
                                      'max_seconds': 30}

    def test_endpoint_authorization_is_checked_before_construction(self):
        with mock.patch.object(POLICY.socketserver, 'ThreadingTCPServer') as server:
            with self.assertRaisesRegex(ValueError, 'policy-services'):
                POLICY.HostServices(self.inputs, ['sink_tcp'], [], self.base / 'service')
        server.assert_not_called()
        self.assertFalse((self.base / 'service').exists())

    def test_partial_endpoint_start_closes_only_owned_servers(self):
        psutil = mock.Mock()
        import socket
        server = mock.Mock()
        thread = mock.Mock()
        thread.is_alive.return_value = False
        class Server:
            def __new__(cls, *args):
                return server
        class FailedServer:
            def __init__(self, *args):
                raise OSError('injected bind failure')
        service = POLICY.HostServices(self.inputs, ['sink_tcp', 'sink_udp'],
                                      ['policy-services'], self.base / 'service')
        address = mock.Mock(family=socket.AF_INET, address=self.inputs['sink_ip'])
        with mock.patch.dict(sys.modules, {'psutil': psutil}), \
                mock.patch.object(psutil, 'net_if_addrs', return_value={'fixture': [address]}), \
                mock.patch.object(psutil, 'Process') as process, \
                mock.patch.object(POLICY.socketserver, 'ThreadingTCPServer', Server), \
                mock.patch.object(POLICY.socketserver, 'ThreadingUDPServer', FailedServer), \
                mock.patch.object(POLICY.threading, 'Thread', return_value=thread):
            process.return_value.create_time.return_value = 123.0
            with self.assertRaisesRegex(OSError, 'injected'):
                service.start()
        server.shutdown.assert_called_once()
        server.server_close.assert_called_once()
        thread.join.assert_called_once()
        self.assertTrue(json.loads((self.base / 'service/lifecycle.json').read_text())['stopped'])

    def test_independent_sink_original_binds_peer_bytes_and_lifetime(self):
        out = self.base / 'driver'
        POLICY.run('takeover', out, substitute=True, selected={'sink_tcp', 'sink_udp'})
        value = json.loads((out / 'policy-result.json').read_text())
        service = self.base / 'service'
        service.mkdir()
        life = {'id': 'separate-owner', 'pid': 123, 'birth': 5.0,
                'started_at': 1.0, 'ended_at': 3.0, 'ready': True, 'stopped': True,
                'bind_ipv4': self.inputs['sink_ip'], 'port': self.inputs['sink_port'],
                'allowed_peer_ipv4': self.inputs['local_source']}
        (service / 'ready.json').write_text(json.dumps(dict(life, stopped=False)))
        (service / 'lifecycle.json').write_text(json.dumps(life))
        events = []
        for attempt in value['attempts']:
            trace = json.loads((out / attempt['probe']['path']).read_text())
            events.append({'owner': life['id'], 'time': 2.0, 'nonce': attempt['nonce'],
                           'transport': trace['tuple']['proto'],
                           'peer_ip': trace['tuple']['src'], 'peer_port': trace['tuple']['sport'],
                           'request_hex': trace['request_hex'], 'response_hex': trace['response_hex']})
        path = service / 'events.jsonl'
        path.write_text(''.join(json.dumps(e) + '\n' for e in events))
        self.assertTrue(ORACLE.verify_host_services(out, service, ['sink_tcp', 'sink_udp'], self.inputs))
        for key, wrong in [('peer_port', 1), ('response_hex', '00'), ('time', 99.0)]:
            with self.subTest(key=key):
                bad = [dict(e) for e in events]
                bad[0][key] = wrong
                path.write_text(''.join(json.dumps(e) + '\n' for e in bad))
                with self.assertRaises(ValueError):
                    ORACLE.verify_host_services(out, service, ['sink_tcp', 'sink_udp'], self.inputs)

    def test_guest_main_uses_verified_request_without_undefined_context(self):
        import acceptance_guest as guest
        path = self.base / 'request.json'
        path.write_text(json.dumps({'target': {'platform': 'windows'},
                                   'output_root': str(self.base / 'guest')}))
        with mock.patch.object(guest, 'execute', return_value=0) as execute:
            self.assertEqual(0, guest.main(['--request', str(path),
                                           '--request-sha256', guest.file_sha(path)]))
        execute.assert_called_once()

    def test_remote_unknown_stops_owned_sink_and_never_pulls(self):
        import acceptance_windows as windows
        catalog = json.loads((ROOT / 'docs/acceptance/catalog.json').read_text())
        case = next(c for suite in catalog['suites'] for c in suite.get('cases') or []
                    if c['id'] == 'POL-TAKEOVER')
        inputs = POLICY._inputs()
        inputs['sink_ip'] = '192.168.204.1'
        inputs['local_source'] = '192.168.204.100'
        inputs['host_service'] = {'bind_ipv4': inputs['sink_ip'],
                                  'allowed_peer_ipv4': inputs['local_source'],
                                  'max_seconds': 30}
        identity = {'platform': 'windows', 'hostname': 'memory-channel'}
        runtime = {'transport': 'windows-mcp-velo', 'identity': identity,
                   'work_root': 'E:/runs', 'source_root': 'E:/candidate',
                   'python': 'E:/python.exe', 'mcp_config_ref': 'existing',
                   'mcp_server': 'existing', 'transfer': {}}
        plan = {'execution_id': 'memory-channel', 'candidate': {},
                'native_source_hashes': {}, 'source_hashes': {case['id']: {}},
                'environment': {'native_runtime': runtime, 'policy': inputs,
                                'allowed_actions': ['native', 'vm-execute', 'vm-transfer', 'policy-services']}}
        channel = mock.Mock()
        channel.identity.return_value = identity
        channel.execute.return_value = {'process_exited': False, 'returncode': None}
        service = mock.Mock()
        order = mock.Mock()
        order.attach_mock(channel, 'channel')
        order.attach_mock(service, 'service')
        directory = self.base / 'remote'
        directory.mkdir()
        with mock.patch.object(windows, 'ExistingWindowsChannel', return_value=channel), \
                mock.patch.object(POLICY, 'HostServices', return_value=service):
            receipt = NATIVE.run_remote(ROOT, case, plan, directory, sys.executable)
        self.assertEqual('unknown', receipt['status'])
        self.assertFalse(receipt['cleanup']['recovered'])
        self.assertFalse(receipt['cleanup']['process_exit']['exited'])
        service.stop.assert_called_once()
        self.assertEqual('push', channel.transfer.call_args.args[1])
        channel.transfer.assert_called_once()
        names = [call[0] for call in order.mock_calls]
        self.assertLess(names.index('channel.identity'), names.index('service.start'))
        self.assertLess(names.index('channel.execute'), names.index('service.stop'))

    def test_network_observation_failure_is_preserved_after_owned_exit(self):
        from acceptance_runtime import OwnedCore
        out = self.base / 'failed-observation'
        owned = mock.Mock()
        owned.process.pid = 123456789
        owned.state = {'stopped': True, 'returncode': 0, 'forced': False}
        with mock.patch.object(POLICY, '_snapshot', side_effect=[{'routes': []}, OSError('observation failed')]), \
                mock.patch.object(POLICY, '_run_checks', return_value=([], [])), \
                mock.patch('acceptance_runtime.OwnedCore', return_value=owned), \
                mock.patch.dict(sys.modules, {'psutil': mock.Mock()}) as modules:
            process = modules['psutil'].Process
            process.return_value.create_time.return_value = 1.0
            self.assertEqual(1, POLICY.run('domain', out, ['never'], inputs=POLICY._inputs(), selected={'route_restore'}))
        owned.stop.assert_called_once()
        result = json.loads((out / 'policy-result.json').read_text())
        self.assertIn('observation failed', result['error'])
        rows, clean = ORACLE.evaluate(out, 'domain', ['route_restore'])
        self.assertFalse(clean)
        self.assertNotEqual('pass', rows[0]['status'])

    def test_pcapng_endian_and_timestamp_resolution_and_truncation(self):
        import struct
        for endian in ('<', '>'):
            with self.subTest(endian=endian):
                def block(kind, body):
                    size = len(body) + 12
                    return struct.pack(endian+'II', kind, size) + body + struct.pack(endian+'I', size)
                section = block(0x0a0d0d0a, struct.pack(endian+'IHHq', 0x1a2b3c4d, 1, 0, -1))
                interface = block(1, struct.pack(endian+'HHI', 1, 0, 65535) + struct.pack(endian+'HH', 9, 1) + b'\x09\0\0\0')
                raw = POLICY._frame('127.0.0.1', '127.0.0.2', 123, 456, 'UDP', b'benign')
                stamp = 2_000_000_000
                packet = block(6, struct.pack(endian+'IIIII', 0, stamp >> 32, stamp & 0xffffffff, len(raw), len(raw)) + raw + b'\0'*((-len(raw))%4))
                data = section + interface + packet
                result = ORACLE._pcapng_packets(data)
                self.assertEqual(2.0, result[0]['time'])
                self.assertEqual(b'benign', result[0]['payload'])
                with self.assertRaises(ValueError):
                    ORACLE._pcapng_packets(data[:-1])

if __name__ == '__main__':
    unittest.main()
