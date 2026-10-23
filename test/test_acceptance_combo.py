import json,shutil,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import acceptance_policy as P, acceptance_policy_oracles as O, acceptance_native as N
CHECKS=['exact_domain','wildcard_domain','tls_application','reviewed_ip_tls','sink_tcp','sink_udp','port_80_denied','port_444_denied','udp443_denied','other_ip_denied','adjacent_denied','route_restore']
class ComboTests(unittest.TestCase):
 def setUp(self): self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.base=Path(self.t.name)
 def run_combo(self): out=self.base/'combo';P.run('combo',out,substitute=True);return out
 def test_combo_has_exact_twelve_and_consumes_denied_dns(self):
  self.assertEqual(CHECKS,P.CHECKS['combo'])
  out=self.run_combo();rows,clean=O.evaluate(out,'combo',CHECKS,allow_fixture=True);self.assertTrue(clean);self.assertEqual('pass',N._judge_rows(rows,CHECKS)['verdict'])
  result=json.loads((out/'policy-result.json').read_text());self.assertEqual(12,len(result['checks']));self.assertTrue(any((out/'probes'/'sink_tcp-dns.json').is_file() for _ in [0]));self.assertEqual(6,len(P.CHECKS['combined']))
 def test_old_combined_checks_remain_six(self):
  self.assertEqual(6,len(P.CHECKS['combined']))
 def test_wrong_nonce_and_config_fail(self):
  out=self.run_combo();v=json.loads((out/'policy-result.json').read_text());v['attempts'][0]['nonce']='wrong';(out/'policy-result.json').write_text(json.dumps(v));rows,clean=O.evaluate(out,'combo',CHECKS,allow_fixture=True);self.assertFalse(clean);self.assertNotEqual('pass',N._judge_rows(rows,CHECKS)['verdict'])
  out=self.base/'combo2';P.run('combo',out,substitute=True);p=out/'policy.ini';t=p.read_text().replace('ExternalAccessPolicy = EgressControl','ExternalAccessPolicy = Off');p.write_text(t);v=json.loads((out/'policy-result.json').read_text());v['config']['sha256']=P.sha256(p);(out/'policy-result.json').write_text(json.dumps(v));rows,clean=O.evaluate(out,'combo',CHECKS,allow_fixture=True);self.assertFalse(clean);self.assertNotEqual('pass',N._judge_rows(rows,CHECKS)['verdict'])

if __name__=='__main__':unittest.main()

# Controller-owned independent cases. Keep the received direct tests above.
class ControllerComboTests(unittest.TestCase):
    def setUp(self):
        import os
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.old = None
        guard = sys.modules.get('sitecustomize')
        old = Path(guard.__file__).resolve().parents[1] / 'received_oracle.py' if guard else None
        if old and old.is_file():
            import hashlib, importlib.util
            self.assertEqual('406127b1fe837eddecbc03dc3edf1f585b378577956c90512584087277d5c429', hashlib.sha256(old.read_bytes()).hexdigest())
            spec = importlib.util.spec_from_file_location('received_combo_oracle', old)
            self.old = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.old)

    def make(self, name='original', inputs=None):
        out = self.base / name
        self.assertEqual(0, P.run('combo', out, inputs=inputs, substitute=True))
        return out

    def read(self, out):
        return json.loads((out / 'policy-result.json').read_text())

    def write(self, path, value):
        path.write_text(json.dumps(value, indent=2) + '\n')

    def refresh_context(self, out, value):
        context_path = out / value['combo_context']['path']
        context = json.loads(context_path.read_text())
        context['lifecycle'] = value['observations']['core-lifecycle']
        context['pcap'] = [{k: p[k] for k in ('path', 'sha256')} for p in value['pcap']]
        self.write(context_path, context)
        value['combo_context']['sha256'] = P.sha256(context_path)
        self.write(out / 'policy-result.json', value)

    def change_dns(self, out, mutate):
        value = self.read(out)
        attempt = next(a for a in value['attempts'] if a['id'] == 'sink_tcp')
        trace_path = out / attempt['probe']['path']
        trace = json.loads(trace_path.read_text())
        dns_path = out / trace['dns_resolution']['path']
        dns = json.loads(dns_path.read_text())
        mutate(dns)
        self.write(dns_path, dns)
        trace['dns_resolution']['sha256'] = P.sha256(dns_path)
        self.write(trace_path, trace)
        attempt['probe']['sha256'] = P.sha256(trace_path)
        self.write(out / 'policy-result.json', value)

    def rejected(self, out, text=None, old_would_pass=False):
        rows, clean = O.evaluate(out, 'combo', CHECKS, allow_fixture=True)
        self.assertFalse(clean, rows)
        self.assertNotEqual('pass', N._judge_rows(rows, CHECKS)['verdict'])
        if text:
            self.assertIn(text, str(rows))
        if old_would_pass and self.old:
            old_rows, old_clean = self.old.evaluate(out, 'combo', CHECKS, allow_fixture=True)
            self.assertTrue(old_clean, old_rows)
            self.assertEqual('pass', N._judge_rows(old_rows, CHECKS)['verdict'])
            import os
            location = os.environ.get('FN_COMBO_CHECK_DIR')
            if location:
                with (Path(location) / 'old-new-discrimination.jsonl').open('a') as stream:
                    stream.write(json.dumps({'original': str(out), 'old': 'pass', 'current': rows}) + '\n')

    def test_original_positive_has_one_context_and_fixed_sink_controls(self):
        out = self.make()
        rows, clean = O.evaluate(out, 'combo', CHECKS, allow_fixture=True)
        self.assertTrue(clean, rows)
        value = self.read(out)
        context = json.loads((out / value['combo_context']['path']).read_text())
        self.assertEqual(12, len(value['checks']))
        self.assertEqual(1, len({a['nonce'].split('-', 1)[0] for a in value['attempts'] if a['id'] != 'route_restore'}))
        controls = {a['id']: a for a in value['controls']}
        for name in ('sink_tcp', 'sink_udp'):
            self.assertIn(name, controls)
            self.assertEqual(value['inputs']['sink_ip'], controls[name]['tuple']['dst'])
            self.assertLessEqual(controls[name]['ended_at'], context['started_at'])

    def test_consumed_dns_must_be_sent_to_the_real_entry_in_order_and_on_wire(self):
        variants = [
            ('not-sent', lambda d: d.update(sent=False), 'send/endpoint'),
            ('wrong-dns-entry', lambda d: d['tuple'].update(dst='127.0.0.99'), 'send/endpoint'),
            ('absent-wire', lambda d: d['tuple'].update(sport=d['tuple']['sport'] + 100), 'wire exchange'),
            ('late-dns', lambda d: d.update(started_at=d['started_at'] + 100, ended_at=d['ended_at'] + 100), 'capture window'),
        ]
        for name, mutation, reason in variants:
            with self.subTest(name=name):
                out = self.make(name)
                self.change_dns(out, mutation)
                self.rejected(out, reason, old_would_pass=True)

    def test_different_config_and_run_cannot_be_spliced_after_rehashing(self):
        out = self.make('first')
        other = self.make('second', dict(P.memory_inputs(), allowed_domain='other.allowed.test'))
        first, second = self.read(out), self.read(other)
        b = next(a for a in second['attempts'] if a['id'] == 'sink_tcp')
        trace = json.loads((other / b['probe']['path']).read_text())
        (out / 'spliced').mkdir()
        dns = out / 'spliced/sink-dns.json'
        dns.write_bytes((other / trace['dns_resolution']['path']).read_bytes())
        trace['dns_resolution']['path'] = 'spliced/sink-dns.json'
        trace['dns_resolution']['sha256'] = P.sha256(dns)
        trace_path = out / 'spliced/sink.json'
        self.write(trace_path, trace)
        b['probe'] = {'path': 'spliced/sink.json', 'sha256': P.sha256(trace_path)}
        first['attempts'] = [b if a['id'] == 'sink_tcp' else a for a in first['attempts']]
        second_row = next(r for r in second['checks'] if r['id'] == 'sink_tcp')
        first['checks'] = [second_row if r['id'] == 'sink_tcp' else r for r in first['checks']]
        capture = out / first['pcap'][0]['path']
        # Replace this flow with actual bytes from the other run. Appending all
        # of its unrelated, reused-port streams would trigger TCP conflict first.
        import struct
        flow = b['tuple']
        def records(path):
            data = path.read_bytes()
            self.assertEqual(b'\xd4\xc3\xb2\xa1', data[:4])
            offset = 24
            while offset < len(data):
                sec, frac, size, original = struct.unpack('<IIII', data[offset:offset + 16])
                self.assertEqual(size, original)
                end = offset + 16 + size
                packet = O._decode_frame(data[offset + 16:end], 1, sec + frac / 1e6)
                yield data[offset:end], packet
                offset = end
        def is_flow(packet):
            return packet and packet['proto'] == flow['proto'] and (
                (packet['src'], packet['sport'], packet['dst'], packet['dport']) ==
                (flow['src'], flow['sport'], flow['dst'], flow['port']) or
                (packet['src'], packet['sport'], packet['dst'], packet['dport']) ==
                (flow['dst'], flow['port'], flow['src'], flow['sport']))
        retained = [raw for raw, packet in records(capture) if not is_flow(packet)]
        foreign = [raw for raw, packet in records(other / second['pcap'][0]['path']) if is_flow(packet)]
        self.assertEqual(2, len(foreign))
        capture.write_bytes(capture.read_bytes()[:24] + b''.join(retained + foreign))
        first['pcap'][0]['sha256'] = P.sha256(capture)
        self.refresh_context(out, first)
        self.rejected(out, 'different combo', old_would_pass=True)

    def test_claimed_sink_success_without_fixed_endpoint_control_is_rejected(self):
        out = self.make()
        value = self.read(out)
        control = next(c for c in value['controls'] if c['id'] == 'sink_tcp')
        path = out / control['probe']['path']
        trace = json.loads(path.read_text())
        trace['response_hex'] = ''
        self.write(path, trace)
        control['probe']['sha256'] = P.sha256(path)
        self.write(out / 'policy-result.json', value)
        self.rejected(out, 'stopped-state endpoint', old_would_pass=True)

    def test_missing_application_and_false_recovery_never_become_pass(self):
        out = self.make('missing')
        value = self.read(out)
        value['checks'] = [r for r in value['checks'] if r['id'] != 'tls_application']
        self.write(out / 'policy-result.json', value)
        self.rejected(out)
        out = self.make('bad-cleanup')
        value = self.read(out)
        path = out / value['observations']['core-lifecycle']['path']
        life = json.loads(path.read_text())
        life['exited'] = False
        self.write(path, life)
        value['observations']['core-lifecycle']['sha256'] = P.sha256(path)
        value['cleanup']['recovered'] = True
        self.refresh_context(out, value)
        self.rejected(out)

    def test_exact_twelve_registry_and_real_cli_dependency_chain(self):
        import acceptance as A, acceptance_runtime as runtime
        import contextlib, io, os
        from unittest import mock
        case_ids = ['EGRESS-ALLOW-CHAIN', 'POL-TAKEOVER', 'IP-TAKEOVER-COEXIST', 'GAP-COMBO-SCENARIO']
        base = self.base / 'cli'
        base.mkdir()
        run = base / 'run'
        identity = {'platform': 'windows', 'hostname': 'combo-os-boundary'}
        candidate = {'schema': A.CANDIDATE_V2, 'source_commit': A.git_head(ROOT),
                     'offline_fixture': True, 'deployed_identity': identity}
        environment = {'schema': A.ENVIRONMENT_V2, 'targets': ['windows'],
                       'interpreters': {'python': sys.executable}, 'endpoints': [],
                       'auth_refs': [], 'work_root': str(base), 'allowed_actions': ['native'],
                       'native_runtime': {'transport': 'local-target', 'identity': identity},
                       'policy': P.memory_inputs()}
        self.write(base / 'candidate.json', candidate)
        self.write(base / 'environment.json', environment)

        def cli(*args):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = A.main(['--root', str(ROOT), *map(str, args)])
            return code, out.getvalue(), err.getvalue()

        selected = [x for case in case_ids for x in ('--case', case)]
        planned = cli('plan', '--mode', 'selected', *selected,
                      '--candidate', base / 'candidate.json', '--environment', base / 'environment.json',
                      '--output', run / 'plan.json')
        self.assertEqual(0, planned[0], planned)
        plan = json.loads((run / 'plan.json').read_text())
        self.assertEqual(set(case_ids), set(plan['required_cases']))
        self.assertEqual(set(CHECKS), set(plan['required_checks']['GAP-COMBO-SCENARIO']))
        guard = sys.modules.get('sitecustomize')
        guard_path = str(Path(guard.__file__).parent) if guard else None
        copy_environment = os.environ.copy

        class BoundaryEnvironment(dict):
            def __setitem__(self, key, value):
                if key == 'PYTHONPATH' and guard_path:
                    value = guard_path + os.pathsep + value
                return super().__setitem__(key, value)

        def observe_command(argv, timeout=15):
            # Replace the OS command observation, leaving require_target intact.
            self.assertEqual(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command'], argv[:4])
            self.assertIn('Get-CimInstance Win32_ComputerSystem', argv[4])
            return b''

        with mock.patch.object(runtime.platform, 'system', return_value='Windows'), \
             mock.patch.object(runtime.socket, 'gethostname', return_value=identity['hostname']), \
             mock.patch.object(runtime, 'command', side_effect=observe_command), \
             mock.patch.object(os.environ, 'copy', side_effect=lambda: BoundaryEnvironment(copy_environment())):
            executed = cli('execute', '--plan', run / 'plan.json')
        self.assertEqual(0, executed[0], executed)
        judged = cli('judge', '--plan', run / 'plan.json', '--results', run / 'results', '--output', run / 'independent.json')
        self.assertEqual(0, judged[0], judged)
        summary = json.loads((run / 'independent.json').read_text())
        self.assertTrue(summary['fixture_contract_pass'])
        self.assertFalse(summary['full_functional_pass'])
        self.assertEqual(4, summary['checks']['passed'])
        driver = run / 'results/GAP-COMBO-SCENARIO/driver'
        self.change_dns(driver, lambda d: d.update(sent=False))
        receipt_path = driver.parent / 'receipt.json'
        receipt = json.loads(receipt_path.read_text())
        for item in receipt['artifacts']:
            item['sha256'] = P.sha256(item['path'])
        self.write(receipt_path, receipt)
        index_path = run / 'results/results.json'
        index = json.loads(index_path.read_text())
        for item in index['receipts']:
            if item['case_id'] == 'GAP-COMBO-SCENARIO':
                item['sha256'] = P.sha256(receipt_path)
        self.write(index_path, index)
        bad = cli('judge', '--plan', run / 'plan.json', '--results', run / 'results', '--output', run / 'bad.json')
        self.assertNotEqual(0, bad[0], bad)
        bad_summary = json.loads((run / 'bad.json').read_text())
        failed = next(c for c in bad_summary['cases'] if c['case_id'] == 'GAP-COMBO-SCENARIO')
        self.assertEqual('fail', failed['status'])
        self.assertEqual(['sink_tcp'], failed['evaluation']['failed'])
        original_rows, original_clean = O.evaluate(driver, 'combo', CHECKS, allow_fixture=True)
        self.assertFalse(original_clean)
        self.assertIn('combo DNS send/endpoint', next(r for r in original_rows if r['id'] == 'sink_tcp')['reason'])
