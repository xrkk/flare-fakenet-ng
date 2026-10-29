"""Direct tests for the FN-REGRESSION-DUMP-RELOCATION-01 seams (DC-01..05).

Host-runnable matrix: the strict loader defaults, the source finalizer, the
Windows execute closure parsing, and the shared host relocation context
builder (built here over a REAL dump production), including the DC-A3
self-consistent batch-swap counterexample.  The full Windows entry chain is
covered separately by the pinned WindowsPython/Wine fixture run (DC-A2/A7).
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT))
import acceptance_manual as M
import acceptance_native as N
import acceptance_windows as W
from fakenet.payload_report import load_capture_originals, PayloadReportError


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Base(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix='fnreg-dump-reloc-', dir='/tmp'))
        self.catalog_case = next(
            c for suite in json.loads((ROOT / 'docs/acceptance/catalog.json').read_text())['suites']
            for c in suite.get('cases', []) if c['id'] == 'GAP-DUMPPACKETS')
        self.identity = {'platform': 'linux', 'hostname': 'fixture-vm'}
        self.vm = {'vm_uuid': '564de0b3-b23d-3d9f-4d52-3ec22c4cfdc0',
                   'boot_identity': 'boot-1', 'vm_epoch': 'epoch-1'}
        self.runtime = {'transport': 'windows-mcp-velo', 'identity': self.identity,
                        'source_root': str(ROOT), 'python': sys.executable,
                        'work_root': str(self.base / 'work'),
                        'transfer': {'expected_vm_identity': dict(self.vm)}}
        self.plan = {
            'candidate': {'candidate_id': 'dump-reloc-test', 'source_commit': 'a' * 40,
                          'package_sha256': 'b' * 64, 'offline_fixture': True},
            'environment': {'native_runtime': dict(self.runtime),
                            'manual': {'schema': 'fakenet.manual-options.v1',
                                       'responsea': '192.0.2.55'}},
            'execution_id': 'dump-reloc-exec-1',
            'native_source_hashes': {},
            'source_hashes': {'GAP-DUMPPACKETS': {
                'tools/acceptance_guest.py': _sha(ROOT / 'tools/acceptance_guest.py')}}}
        self.output_root = (self.base / 'work' / self.plan['execution_id'] /
                            'GAP-DUMPPACKETS' / 'output')

    def produce_dump(self):
        """REAL dump production into the guest output layout plus a closed
        guest-result wrapper; returns (request, request_sha, closure)."""
        self.output_root.mkdir(parents=True)
        inputs = N.manual_inputs(self.plan, self.catalog_case, str(self.output_root))
        M.run('GAP-DUMPPACKETS', self.output_root / 'driver', inputs)
        (self.output_root / 'manual-inputs.json').write_text(
            json.dumps(inputs, indent=2) + '\n', encoding='utf-8')
        driver, checks, expected_request = N._expected_remote_request(
            ROOT, self.catalog_case, self.plan)
        receipt = {'status': 'pass', 'detail': '', 'returncode': 0, 'command': 'fixed',
                   'required_checks': checks, 'native_target': self.identity,
                   'artifacts': [], 'cleanup': {
                       'source': 'driver', 'resources': [], 'recovered': True,
                       'process_exit': {'exited': True, 'returncode': 0, 'timed_out': False}}}
        result = {'schema': 'fakenet.native-guest-result.v1',
                  'execution_id': self.plan['execution_id'], 'case_id': 'GAP-DUMPPACKETS',
                  'request': expected_request, 'receipt': receipt}
        (self.output_root / 'guest-result.json').write_text(
            json.dumps(result, indent=2) + '\n', encoding='utf-8')
        request_path = self.base / 'guest-request.json'
        request_path.write_text(json.dumps(expected_request, indent=2) + '\n',
                                encoding='utf-8')
        request_sha = _sha(request_path)
        closure = N.finalize_dump_evidence(
            ROOT, expected_request, request_sha, str(self.output_root))
        return expected_request, request_sha, closure

    def build_run_dir(self, request, request_sha, closure, source_root=None):
        """Host-side journal + Velo pull + incoming layout around a closure."""
        self._runs = getattr(self, '_runs', 0) + 1
        run = self.base / ('run-%d-%s' % (self._runs, hashlib.sha1(
            json.dumps([request_sha, closure['inventory_sha256'],
                        str(source_root)]).encode()).hexdigest()[:8]))
        transport = run / 'transport'
        transport.mkdir(parents=True)
        (run / 'guest-request.json').write_text(json.dumps(request, indent=2) + '\n',
                                                encoding='utf-8')
        entry = str(Path(self.runtime['source_root']) / 'tools/acceptance_guest.py')
        command = ('fixed entry=%s request-sha=%s' % (entry, request_sha))
        (transport / 'execute-intent.json').write_text(
            json.dumps({'operation': 'execute', 'command': command}) + '\n', encoding='utf-8')
        payload = {'returncode': 0, 'process_exited': True, 'recovered': True,
                   'guest_stdout': json.dumps(closure, ensure_ascii=False, sort_keys=True,
                                              separators=(',', ':'))}
        (transport / 'execute-response.json').write_text(json.dumps(
            {'exit_code': 0, 'is_error': False,
             'output': json.dumps(payload)}) + '\n', encoding='utf-8')
        (transport / 'identity-response.json').write_text(json.dumps(
            {'exit_code': 0, 'is_error': False,
             'output': json.dumps(dict(self.identity, vm_uuid=self.vm['vm_uuid']))})
            + '\n', encoding='utf-8')
        spec = {'direction': 'pull',
                'expected_vm_identity': dict(self.vm),
                'sources': [{'absolute_path': str(self.output_root),
                             'relative_path': 'originals'}],
                'destination_directory': str((run / 'incoming').resolve()),
                'transfer_id': 't' * 32}
        (transport / 'pull-originals-spec.json').write_text(
            json.dumps(spec) + '\n', encoding='utf-8')
        files = [{'relative_path': 'originals/' + f['relative_path'],
                  'size': f['size'], 'sha256': f['sha256']} for f in closure['files']]
        origin = source_root if source_root is not None else self.output_root
        velo = {'schema': 'velo.transfer.result.v1', 'transfer_id': spec['transfer_id'],
                'direction': 'pull', 'phase': 'COMPLETE', 'outcome': 'complete',
                'published_ever': True, 'destination_verified': True,
                'cleanup': {'host': True, 'guest': True},
                'source_vm_identity': dict(self.vm), 'files': files}
        result_path = run / 'velo-result.json'
        result_path.write_text(json.dumps(velo, indent=2) + '\n', encoding='utf-8')
        (transport / 'pull-originals-terminal.json').write_text(json.dumps(
            {'result_path': str(result_path), 'sha256': _sha(result_path),
             'spec_path': str(transport / 'pull-originals-spec.json')}) + '\n',
            encoding='utf-8')
        incoming = run / 'incoming/originals'
        incoming.mkdir(parents=True)
        for path in sorted(origin.rglob('*')):
            if path.is_file():
                target = incoming.joinpath(*path.relative_to(origin).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
        return run


class StrictLoaderDefaults(Base):
    """DC-A1/DC-06: the default entry keeps the physical semantics; the
    explicit non-physical mode only waives the equality, never the facts."""

    def test_default_refuses_identical_byte_replacement_both_positions(self):
        request, sha, closure = self.produce_dump()
        enabled = self.output_root / 'driver/enabled'
        raw = enabled / next(n for n in sorted(p.name for p in enabled.glob('*.pcap'))
                             if not n.endswith('-converted.pcap'))
        journal = Path(str(raw) + '.observations.ndjson')
        for target in (raw, journal):
            with self.subTest(position=target.name):
                data = target.read_bytes()
                temporary = target.with_suffix(target.suffix + '.swap')
                temporary.write_bytes(data)
                os.replace(temporary, target)
                with self.assertRaisesRegex(PayloadReportError, 'physical replacement'):
                    load_capture_originals(raw, None)

    def test_relocated_copy_passes_only_with_explicit_flag(self):
        request, sha, closure = self.produce_dump()
        copy_root = self.base / 'copy'
        copy_root.mkdir()
        enabled = self.output_root / 'driver/enabled'
        raw = enabled / next(n for n in sorted(p.name for p in enabled.glob('*.pcap'))
                             if not n.endswith('-converted.pcap'))
        converted = enabled / next(n for n in sorted(p.name for p in enabled.glob('*.pcap'))
                                   if n.endswith('-converted.pcap'))
        for member in (raw, converted, Path(str(raw) + '.observations.ndjson'),
                       Path(str(raw) + '.nbis.ndjson'),
                       Path(str(raw) + '.capture-originals.json')):
            shutil.copyfile(member, copy_root / member.name)
        raw_copy = copy_root / raw.name
        converted_copy = copy_root / converted.name
        with self.assertRaisesRegex(PayloadReportError, 'physical replacement'):
            load_capture_originals(raw_copy, converted_copy)
        loaded = load_capture_originals(raw_copy, converted_copy, verify_physical=False)
        self.assertEqual(closure['capture']['capture_id'], loaded.capture_id)

    def test_missing_or_bad_device_fact_refused_even_non_physical(self):
        request, sha, closure = self.produce_dump()
        copy_root = self.base / 'copy2'
        copy_root.mkdir()
        enabled = self.output_root / 'driver/enabled'
        raw = enabled / next(n for n in sorted(p.name for p in enabled.glob('*.pcap'))
                             if not n.endswith('-converted.pcap'))
        converted = enabled / next(n for n in sorted(p.name for p in enabled.glob('*.pcap'))
                                   if n.endswith('-converted.pcap'))
        for member in (raw, converted, Path(str(raw) + '.observations.ndjson'),
                       Path(str(raw) + '.nbis.ndjson'),
                       Path(str(raw) + '.capture-originals.json')):
            shutil.copyfile(member, copy_root / member.name)
        seal_path = copy_root / (raw.name + '.capture-originals.json')
        seal = json.loads(seal_path.read_text())
        for mutation in ('missing', 'bad-type'):
            with self.subTest(mutation=mutation):
                broken = json.loads(json.dumps(seal))
                if mutation == 'missing':
                    broken['raw_pcap'].pop('device')
                else:
                    broken['raw_pcap']['device'] = 'not-an-int'
                seal_path.write_text(json.dumps(broken))
                with self.assertRaises(PayloadReportError):
                    load_capture_originals(copy_root / raw.name,
                                           copy_root / converted.name,
                                           verify_physical=False)
                seal_path.write_text(json.dumps(seal))


class SourceClosure(Base):
    """DC-02/DC-03: the finalizer gates on a passing recovered result, keeps
    the schema/digest contract, and refuses unstable or failing sources."""

    def test_closure_contract_and_stability(self):
        request, sha, closure = self.produce_dump()
        self.assertEqual('fakenet.dump-source-closure.v1', closure['schema'])
        self.assertEqual(sha, closure['request_sha256'])
        self.assertEqual('pass', closure['source_verdict'])
        self.assertTrue(closure['cleanup_recovered'])
        self.assertEqual(request['candidate'], closure['candidate'])
        self.assertEqual(request['source_hashes'], closure['source_hashes'])
        self.assertEqual(request['target'], closure['target'])
        self.assertEqual(request['output_root'], closure['output_root'])
        names = {f['relative_path'] for f in closure['files']}
        self.assertIn('guest-result.json', names)
        for member in ('raw', 'converted', 'seal'):
            self.assertIn(closure['capture'][member], names)
        digest = hashlib.sha256(json.dumps(
            closure['files'], ensure_ascii=False, sort_keys=True,
            separators=(',', ':')).encode('utf-8')).hexdigest()
        self.assertEqual(digest, closure['inventory_sha256'])
        self.assertEqual(sorted(names), [f['relative_path'] for f in closure['files']])

    def test_failing_receipt_or_unstable_set_refused(self):
        request, sha, closure = self.produce_dump()
        result_path = self.output_root / 'guest-result.json'
        result = json.loads(result_path.read_text())
        result['receipt']['status'] = 'fail'
        result_path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'passing recovered'):
            N.finalize_dump_evidence(ROOT, request, sha, str(self.output_root))
        result['receipt']['status'] = 'pass'
        result_path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        # An output that changes during finalization: the second inventory
        # differs because a foreign file appears between the two snapshots.
        with unittest.mock.patch.object(
                N, '_closure_inventory',
                side_effect=[N._closure_inventory(self.output_root),
                             dict(N._closure_inventory(self.output_root),
                                  foreign={'relative_path': 'foreign',
                                           'size': 1, 'sha256': '0' * 64})]):
            with self.assertRaisesRegex(ValueError, 'changed during'):
                N.finalize_dump_evidence(ROOT, request, sha, str(self.output_root))
        # Restoring the passing result keeps the source finalizable.
        again = N.finalize_dump_evidence(ROOT, request, sha, str(self.output_root))
        self.assertEqual(closure['inventory_sha256'], again['inventory_sha256'])


class WindowsClosureCapture(Base):
    """DC-04: the channel command captures THIS invocation's stdout and the
    parser accepts exactly one closure object."""

    def test_command_captures_stdout_and_parser_is_strict(self):
        channel = object.__new__(W.ExistingWindowsChannel)
        channel.runtime = dict(self.runtime)
        channel.journal = self.base / 'journal'
        channel.journal.mkdir()
        captured = {}

        def invoke(name, command, timeout):
            captured['command'] = command
            return {'returncode': 0, 'process_exited': True, 'recovered': True}
        channel.invoke = invoke
        terminal = channel.execute('req.json', 'a' * 64, r'E:\out', {
            'tools/acceptance_guest.py': 'e' * 64}, 30, capture_stdout=True)
        self.assertIn('guest_stdout', captured['command'])
        self.assertIn('Out-String', captured['command'])
        closure = {'schema': 'fakenet.dump-source-closure.v1', 'files': []}
        good = json.dumps(closure)
        self.assertEqual(closure, W.ExistingWindowsChannel.parse_source_closure(
            {'guest_stdout': good}))
        for stdout in ('', '   ', good + '\n' + good, '{"schema": "other"}',
                       'not json'):
            with self.subTest(stdout=stdout[:24]):
                with self.assertRaises(W.ChannelError):
                    W.ExistingWindowsChannel.parse_source_closure(
                        {'guest_stdout': stdout})


class RelocationContext(Base):
    """DC-05/DC-A3/DC-A4/DC-A5: the ONE shared host builder accepts only the
    real chain and refuses every divergence with a specific reason."""

    def context_for(self, run):
        return N.dump_relocation_context(ROOT, self.catalog_case, self.plan, run)

    def test_valid_chain_builds_context(self):
        request, sha, closure = self.produce_dump()
        run = self.build_run_dir(request, sha, closure)
        context = self.context_for(run)
        self.assertEqual(closure['inventory_sha256'], context['inventory_sha256'])

    def test_dc_a3_self_consistent_batch_swap_refused(self):
        # Keep A's closure and A's execute response, but replace EVERY pulled
        # guest-side file with a fresh self-consistent B production and make
        # the Velo record truthfully describe B.  Only the closure-to-batch
        # exact-set comparison can refuse this.
        request, sha, closure = self.produce_dump()
        run = self.build_run_dir(request, sha, closure)
        b_root = self.base / 'work-b' / self.plan['execution_id'] / 'GAP-DUMPPACKETS' / 'output'
        b_root.mkdir(parents=True)
        inputs = N.manual_inputs(self.plan, self.catalog_case, str(b_root))
        M.run('GAP-DUMPPACKETS', b_root / 'driver', inputs)
        (b_root / 'manual-inputs.json').write_text(json.dumps(inputs) + '\n')
        result_b = {'schema': 'fakenet.native-guest-result.v1',
                    'execution_id': self.plan['execution_id'],
                    'case_id': 'GAP-DUMPPACKETS', 'request': request,
                    'receipt': {'status': 'pass', 'cleanup': {
                        'recovered': True,
                        'process_exit': {'exited': True, 'returncode': 0}}}}
        (b_root / 'guest-result.json').write_text(json.dumps(result_b) + '\n')
        # Velo truthfully describes the B batch.
        incoming = run / 'incoming/originals'
        shutil.rmtree(incoming)
        incoming.mkdir(parents=True)
        files = []
        for path in sorted(b_root.rglob('*')):
            if path.is_file():
                target = incoming.joinpath(*path.relative_to(b_root).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
                files.append({'relative_path': 'originals/' + path.relative_to(b_root).as_posix(),
                              'size': path.stat().st_size, 'sha256': _sha(path)})
        velo_path = run / 'velo-result.json'
        velo = json.loads(velo_path.read_text())
        velo['files'] = files
        velo_path.write_text(json.dumps(velo))
        terminal = run / 'transport/pull-originals-terminal.json'
        record = json.loads(terminal.read_text())
        record['sha256'] = _sha(velo_path)
        terminal.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'pulled set differs'):
            self.context_for(run)

    def test_dc_a4_response_divergences(self):
        request, sha, closure = self.produce_dump()
        for name, mutate in (
                ('inner-nonzero', lambda p: p.update(returncode=1)),
                ('process-not-exited', lambda p: p.update(process_exited=False)),
                ('not-recovered', lambda p: p.update(recovered=False)),
                ('stdout-missing', lambda p: p.pop('guest_stdout')),
                ('stdout-two-objects', lambda p: p.update(
                    guest_stdout=json.dumps(closure) + '\n' + json.dumps(closure))),
                ('stdout-foreign-schema', lambda p: p.update(
                    guest_stdout=json.dumps({'schema': 'other.v1'})))):
            with self.subTest(name=name):
                run = self.build_run_dir(request, sha, closure)
                path = run / 'transport/execute-response.json'
                response = json.loads(path.read_text())
                payload = json.loads(response['output'])
                mutate(payload)
                response['output'] = json.dumps(payload)
                path.write_text(json.dumps(response))
                with self.assertRaises(ValueError):
                    self.context_for(run)

    def test_dc_a5_identity_and_batch_divergences(self):
        request, sha, closure = self.produce_dump()
        # request digest missing from the pinned execute command
        run = self.build_run_dir(request, sha, closure)
        path = run / 'transport/execute-intent.json'
        path.write_text(json.dumps({'operation': 'execute', 'command': 'no tokens'}))
        with self.assertRaisesRegex(ValueError, 'pinned entry/digest'):
            self.context_for(run)
        # wrong VM uuid in the MCP identity journal
        run = self.build_run_dir(request, sha, closure)
        path = run / 'transport/identity-response.json'
        response = json.loads(path.read_text())
        identity = json.loads(response['output'])
        identity['vm_uuid'] = 'f' * 36
        response['output'] = json.dumps(identity)
        path.write_text(json.dumps(response))
        with self.assertRaisesRegex(ValueError, 'identity differs'):
            self.context_for(run)
        # Velo result transfer id differs from the spec
        run = self.build_run_dir(request, sha, closure)
        path = run / 'velo-result.json'
        velo = json.loads(path.read_text())
        velo['transfer_id'] = 'd' * 32
        path.write_text(json.dumps(velo))
        record = run / 'transport/pull-originals-terminal.json'
        value = json.loads(record.read_text())
        value['sha256'] = _sha(path)
        record.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'Velo pull result contract'):
            self.context_for(run)
        # tampered terminal record digest
        run = self.build_run_dir(request, sha, closure)
        record = run / 'transport/pull-originals-terminal.json'
        value = json.loads(record.read_text())
        value['sha256'] = '0' * 64
        record.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'terminal result record differs'):
            self.context_for(run)
        for name, mutate in (
                ('missing-file', lambda incoming: (incoming / 'driver/manual-result.json').unlink()),
                ('extra-file', lambda incoming: (incoming / 'extra.bin').write_bytes(b'x')),
                ('one-byte-tamper', lambda incoming: (incoming / 'driver/packet-0.bin').write_bytes(
                    (incoming / 'driver/packet-0.bin').read_bytes()[:-1] + b'X')),
                ('symlink', lambda incoming: (incoming / 'link.bin').symlink_to('driver/packet-0.bin'))):
            with self.subTest(batch=name):
                run = self.build_run_dir(request, sha, closure)
                incoming = run / 'incoming/originals'
                mutate(incoming)
                with self.assertRaises(ValueError):
                    self.context_for(run)
        # closure inventory digest lies about its files
        run = self.build_run_dir(request, sha, closure)
        response_path = run / 'transport/execute-response.json'
        response = json.loads(response_path.read_text())
        payload = json.loads(response['output'])
        forged = json.loads(payload['guest_stdout'])
        forged['inventory_sha256'] = '0' * 64
        payload['guest_stdout'] = json.dumps(forged)
        response['output'] = json.dumps(payload)
        response_path.write_text(json.dumps(response))
        with self.assertRaisesRegex(ValueError, 'inventory digest'):
            self.context_for(run)


class OracleRelocatedMode(Base):
    """DC-05.4: evaluate() threads the explicit context down to the SAME
    strict loader's verify_physical switch.  The full remote copy judging
    (backslash producer-path rendering) is Windows-guest-specific and runs in
    the pinned Wine chain (DC-A2); content damage on a copy is already
    covered at the loader level in StrictLoaderDefaults."""

    def test_context_flag_reaches_the_shared_loader(self):
        import acceptance_manual_oracles as O
        request, sha, closure = self.produce_dump()
        expected_inputs = N.manual_inputs(self.plan, self.catalog_case,
                                          str(self.output_root))
        seen = []
        real = load_capture_originals

        def spy(raw, converted=None, verify_physical=True):
            seen.append(verify_physical)
            return real(raw, converted, verify_physical=verify_physical)
        with unittest.mock.patch.dict('fakenet.payload_report.__dict__',
                                      {'load_capture_originals': spy}):
            rows, clean, detail = O.evaluate(ROOT, self.output_root / 'driver',
                                             'GAP-DUMPPACKETS', expected_inputs,
                                             allow_fixture=True)
            self.assertTrue(clean, detail)
            self.assertEqual([True], seen)
            seen.clear()
            rows, clean, detail = O.evaluate(ROOT, self.output_root / 'driver',
                                             'GAP-DUMPPACKETS', expected_inputs,
                                             allow_fixture=True,
                                             relocated_context=closure)
            self.assertTrue(clean, detail)
            self.assertEqual([False], seen)


if __name__ == '__main__':
    unittest.main()
