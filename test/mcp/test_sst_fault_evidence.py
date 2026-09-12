"""Negative-oracle tests: synthetic bytes never qualify the real Spike."""
import importlib.util
import json
import hashlib
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).parent / 'acceptance' / 'sst_fault_evidence.py'
SPEC = importlib.util.spec_from_file_location('sst_fault_evidence', PATH)
sst = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sst)

L1 = '''2026-09-12 19:29:15,055 ERROR managed.thread Unhandled exception in managed thread Thread-4 (serve_forever)
Traceback (most recent call last):
  File "threading.py", line 1045, in _bootstrap_inner
  File "threading.py", line 982, in run
  File "socketserver.py", line 233, in serve_forever
  File "selectors.py", line 323, in select
  File "selectors.py", line 314, in _select
OSError: [WinError 10038] localised error
'''
C1 = '''2026-09-12 19:30:00,000 ERROR managed Traceback (most recent call last):
  File "C:\\workspace\\fakenet\\mcp\\managed.py", line 341, in child_main
    fault.on_stop_error()
  File "C:\\workspace\\fakenet\\mcp\\faultinject.py", line 140, in on_stop_error
    raise RuntimeError('injected cleanup error')
RuntimeError: injected cleanup error
'''


class EvidenceOracleTests(unittest.TestCase):
    def test_domain_probe_uses_connected_numeric_endpoint(self):
        event = {'dst': 'api.deepseek.com:443', 'actual_dst': '60.28.220.199:443'}
        self.assertEqual(sst.connection_destination(event), '60.28.220.199:443')
        self.assertTrue(sst.packet_matches_session(
            '192.168.204.233.61824 > 60.28.220.199.443: Flags [R.]',
            '192.168.204.233:61824', sst.connection_destination(event)))
        self.assertEqual(sst.connection_destination({'dst': '198.51.100.77:1337'}),
                         '198.51.100.77:1337')

    def test_packet_requires_exact_both_endpoints_in_either_direction(self):
        src, dst = '192.168.204.233:61824', '198.51.100.77:1337'
        packet = 'length 66: 192.168.204.233.61824 > 198.51.100.77.1337: Flags [R.], seq 1'
        self.assertTrue(sst.packet_matches_session(packet, src, dst))
        reverse = 'length 66: 198.51.100.77.1337 > 192.168.204.233.61824: Flags [F.], seq 1'
        self.assertTrue(sst.packet_matches_session(reverse, src, dst))
        for wrong in (packet.replace('.61824 >', '.618240 >'),
                      packet.replace('198.51.100.77', '198.51.100.78'),
                      packet.replace('.1337:', '.13370:'),
                      packet.replace('192.168.204.233', '1192.168.204.233'),
                      'comment 192.168.204.233 61824 Flags [R.]',
                      packet + '\n' + reverse):
            with self.subTest(packet=wrong):
                self.assertFalse(sst.packet_matches_session(wrong, src, dst))

    def test_exact_native_listener_block(self):
        self.assertEqual(sst.exception_kind(L1), 'L1')
        self.assertEqual(sst.exception_kind(L1.replace('Thread-4', 'Thread-892')), 'L1')

    def test_same_thread_wrong_error_rejected(self):
        self.assertIsNone(sst.exception_kind(L1.replace('10038', '10054')))
        self.assertIsNone(sst.exception_kind(L1.replace('OSError:', 'ValueError:')))

    def test_missing_frame_and_chained_error_rejected(self):
        self.assertIsNone(sst.exception_kind(L1.replace('selectors.py', 'unrelated.py')))
        self.assertIsNone(sst.exception_kind(L1 + 'During handling of the above exception\n'))

    def test_cleanup_message_needs_hook(self):
        self.assertEqual(sst.exception_kind(C1), 'C1')
        self.assertIsNone(sst.exception_kind(C1.replace('on_stop_error', 'unrelated')))
        self.assertIsNone(sst.exception_kind(C1.replace('injected cleanup error\n', 'injected cleanup error extra\n')))

    def test_scan_does_not_drop_unmatched_blocks(self):
        full = 'preamble\n' + L1 + '2026-09-12 19:29:16,000 INFO managed normal\n' + C1
        self.assertEqual([sst.exception_kind(b) for b in sst.exception_blocks(full)], ['L1', 'C1'])
        self.assertEqual(len(sst.exception_blocks('Unhandled exception without timestamp')), 1)

    def test_interval_full_containment_not_intersection(self):
        self.assertTrue(sst.contains_session(10, 20, 30, 40))
        self.assertFalse(sst.contains_session(10, 20, 45, 40))
        self.assertFalse(sst.contains_session(21, 20, 30, 40))

    def test_receipt_early_does_not_prove_later_action_overlap(self):
        self.assertTrue(10 <= 20 <= 30)  # tempting receipt-only assertion
        self.assertFalse(sst.contains_session(10, 20, 50, 30))

    def test_native_precision_and_zone(self):
        lo, hi = sst.iso_ns('2026-09-12T19:29:15.055+08:00')
        self.assertEqual(hi - lo, 999999)
        self.assertEqual(sst.iso_ns('2026-09-12T11:29:15.055Z')[0], lo)
        with self.assertRaises(sst.EvidenceError):
            sst.iso_ns('2026-09-12T11:29:15.055')

    def test_manifest_escape_and_changed_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'event.json'; p.write_bytes(b'{}')
            item = {'path': 'event.json', 'bytes': 2, 'sha256': hashlib.sha256(b'{}').hexdigest()}
            e = sst.Evidence(temp, [item])
            self.assertEqual(e.read(dict(path='event.json', byte_start=0, byte_end=2, event_key='json:')), {})
            p.write_bytes(b'[]')
            with self.assertRaises(sst.EvidenceError): sst.Evidence(temp, [item])
            with self.assertRaises(sst.EvidenceError):
                sst.Evidence(temp, [dict(item, path='../outside')])

    def minimal_case(self, fault, detail):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        files = []; root = Path(temp.name)
        def put(name, obj):
            raw = obj.encode() if isinstance(obj, str) else json.dumps(obj).encode()
            (root / name).write_bytes(raw)
            files.append(dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
            return dict(path=name, byte_start=0, byte_end=len(raw), event_key='text' if isinstance(obj, str) else 'json:')
        receipt = put('fault-triggered.json', dict(fault=fault, nonce='nonce'))
        start = put('ipc.json', dict(event='response', time=1789212555.055, frame=dict(run_id='run', seq=1, result=detail)))
        put('run.log', '2026-09-12 19:29:15,000 INFO managed normal\n')
        return root, dict(schema='sst.fault-evidence.case.v1', synthetic=True, case_id='synthetic',
                          candidate_id=sst.CANDIDATE, run_id='run', fault=fault, nonce='nonce',
                          clock=dict(domain='vm-utc', resolution_ns=100, discontinuities=[]),
                          receipt_ref=receipt, start_response_ref=start, trigger=dict(success_refs=[]),
                          session={}, health_refs=[], stop_refs=[], recovery_refs=[], exception_refs=[], files=files)

    def test_child_hang_healthy_is_not_wrong_start(self):
        root, case = self.minimal_case('child_hang', dict(init_evidence=True, probe=True))
        result = sst.assess(case, root)
        self.assertTrue(next(x for x in result['checks'] if x['id'] == 'start_attribution')['passed'])
        self.assertFalse(result['passed'])  # missing native trigger/recovery never passes

    def test_candidate_expectation_is_independent_of_case(self):
        root, case = self.minimal_case('child_hang', dict(init_evidence=True, probe=True))
        case['candidate_id'] = 'new-candidate'
        old = sst.assess(case, root)
        new = sst.assess(case, root, expected_candidate='new-candidate')
        self.assertFalse(next(x for x in old['checks'] if x['id'] == 'candidate')['passed'])
        self.assertTrue(next(x for x in new['checks'] if x['id'] == 'candidate')['passed'])
        self.assertFalse(new['passed'])

    def test_native_diverter_action_needs_same_handle_invalid_after_close(self):
        root, case = self.minimal_case('diverter_stop', dict(init_evidence=True, probe=False,
                     capture_error=None,listeners=[dict(alive=True)]))
        action = dict(schema='fakenet.fault-action.v1',run_id='run',nonce='nonce',fault='diverter_stop',
                      action='WinDivertClose',pid=123,start_time_ns=10,end_time_ns=20,
                      before=dict(api='GetHandleInformation',supported=True,handle=100,return_code=1,last_error=0),
                      after=dict(api='GetHandleInformation',supported=True,handle=100,return_code=0,last_error=6))
        def observe():
            raw=json.dumps(action).encode();(root/'action.json').write_bytes(raw)
            case['files']=[f for f in case['files'] if f['path']!='action.json']
            case['files'].append(dict(path='action.json',bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
            case['trigger']['success_refs']=[dict(path='action.json',byte_start=0,byte_end=len(raw),event_key='json:')]
            return {x['id']:x['passed'] for x in sst.assess(case,root)['checks']}
        self.assertTrue(observe()['trigger_success'])
        self.assertTrue(observe()['start_attribution'])
        action['after']['handle']=101
        self.assertFalse(observe()['trigger_success'])
        action['after'].update(handle=100,last_error=5)
        self.assertFalse(observe()['trigger_success'])
        action['after']['last_error']=6;action['run_id']='other'
        self.assertFalse(observe()['start_attribution'])

    def test_native_creation_date_retains_its_precision(self):
        value='2026-09-12T21:47:45.466644+08:00'
        self.assertEqual(sst.time_bounds(value),sst.iso_ns(value))

    def test_frozen_pause_frame_requires_exact_source_mapping(self):
        root, case = self.minimal_case('policy_pause', dict(init_evidence=True, probe=True))
        source = (PATH.parents[3] / 'fakenet/mcp/faultinject.py').read_bytes()
        stack = b'LIVE STOP STACKS timestamp=1789212555.055\n  File "fakenet\\mcp\\faultinject.py", line 127, in before_listener_phase\n'
        def add(name, raw):
            (root / name).write_bytes(raw)
            case['files'] = [f for f in case['files'] if f['path'] != name]
            case['files'].append(dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
            return dict(path=name, byte_start=0, byte_end=len(raw), event_key='text')
        sr = add('stack.txt', stack)
        case['trigger']['success_refs'] = [sr]
        def success():
            return next(x for x in sst.assess(case, root)['checks'] if x['id'] == 'trigger_success')['passed']
        self.assertFalse(success())
        case['trigger']['success_refs'].append(add('source.py', source))
        self.assertTrue(success())
        case['trigger']['success_refs'][0] = add('stack.txt', stack.replace(b'127', b'126'))
        self.assertFalse(success())

    def test_unrelated_dead_relay_prevents_listener_attribution(self):
        detail = dict(init_evidence=True, probe=False, capture_threads_alive=True, capture_error=None,
                      listeners=[dict(name='UDP', handles=[-1], alive=False),
                                 dict(name='DomainEgressRelay', handles=[], alive=False)])
        root, case = self.minimal_case('listener_stop', detail)
        result = sst.assess(case, root)
        self.assertFalse(next(x for x in result['checks'] if x['id'] == 'start_attribution')['passed'])

    def test_receipt_alone_and_missing_recovery_fail(self):
        root, case = self.minimal_case('child_hang', dict(init_evidence=True, probe=True))
        result = sst.assess(case, root)
        self.assertFalse(next(x for x in result['checks'] if x['id'] == 'trigger_success')['passed'])
        self.assertFalse(next(x for x in result['checks'] if x['id'] == 'recovery')['passed'])
        self.assertTrue(result['synthetic'])


if __name__ == '__main__':
    unittest.main()
