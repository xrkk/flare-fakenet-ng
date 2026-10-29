"""Seven Windows-only manual-input.v1 cases on the SAME remote contract as
GAP-NCSI/GAP-RAW-DATE: real central plan/execute/judge CLI, real guest entry
and the real local manual producers, with only the VM/OS boundary substituted
by the controlled stand-in from test_acceptance_manual_remote.  Fixture credit
only — never Windows native or full functional credit.
"""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

import os as _os
ROOT = Path(_os.environ.get('FN_MANUAL_PRODUCT_ROOT',
                            str(Path(__file__).resolve().parents[1])))
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'test')]
import test_acceptance_manual_remote as base_mod  # noqa: E402
import manual_remote_fixture_support as support  # noqa: E402
from test_acceptance_manual_remote import sha, portable_ignore  # noqa: E402
import acceptance_windows as win  # noqa: E402

SEVEN = ('GAP-EXECUTECMD', 'GAP-STANDALONE-LISTENERS', 'GAP-CTRLC-IPC',
         'GAP-DIVERTER-SWITCH', 'GAP-SYSLOG-ICMP-LOG', 'GAP-DUMPPACKETS',
         'GAP-LIST-MUTEX')


class RemoteV1ManualTests(base_mod.RemoteManualTests):
    def setUp(self):
        super().setUp()
        if support.faithful_enabled():
            self.runtime.update(support.faithful_runtime(self.identity, self.source))
            (self.base / 'environment.json').write_text(json.dumps(self.environment))
    @classmethod
    def setUpClass(cls):
        # Idempotent shared product-root copy: this class may run alongside
        # the base class under one FN_MANUAL_CHECK_DIR.
        import os
        import shutil
        import uuid
        shared = Path(os.environ.get('FN_MANUAL_CHECK_DIR',
                                     str(ROOT / 'Logs' / 'manual-tests' / uuid.uuid4().hex)))
        shared.mkdir(parents=True, exist_ok=True)
        cls.shared = shared
        cls.source = shared / 'product-root'
        import shutil as _sh
        _sh.copytree(ROOT, cls.source, ignore=portable_ignore, dirs_exist_ok=True)

    def channel_class(self):
        if support.faithful_enabled():
            outer = self
            class Faithful(support.FaithfulWindowsStandIn):
                def __init__(self, root, runtime, journal):
                    super().__init__(outer.source, runtime['identity'])
            return Faithful
        return self.stand_in()

    def test_seven_v1_cases_full_roundtrip_and_rejudge(self):
        plan = self.plan(cases=SEVEN, name='v1-seven')
        with mock.patch.object(win, 'ExistingWindowsChannel', side_effect=self.channel_class()):
            code, out, err = self.cli('execute', '--plan', plan)
        self.assertEqual(0, code, out + err)
        if not support.faithful_enabled():
            for case_id in SEVEN:
                self.assertTrue(self.guest_dir(case_id).is_dir(), case_id)
        self.assertEqual(0, self.cli('judge', '--plan', plan, '--results', plan.parent / 'results',
                                     '--output', plan.parent / 'independent.json')[0])
        summary = json.loads((plan.parent / 'independent.json').read_text())
        self.assertEqual(['pass'] * 7, [row['status'] for row in summary['cases']])
        self.assertTrue(summary['fixture_contract_pass'])
        self.assertFalse(summary['full_functional_pass'])
        self.assertEqual(7, summary['checks']['passed'])
        # The retained originals re-judge identically.
        self.assertEqual(0, self.cli('judge', '--plan', plan, '--results', plan.parent / 'results',
                                     '--output', plan.parent / 'independent-again.json')[0])

    def test_remote_plan_accepts_each_v1_case_individually(self):
        for case_id in SEVEN:
            with self.subTest(case=case_id):
                plan = self.plan(cases=(case_id,), name='solo-' + case_id)
                value = json.loads(plan.read_text())
                self.assertEqual(case_id, value['required_cases'][0])
                self.assertNotIn(case_id, value['blocked'])

    def test_v1_guest_config_field_cannot_be_satisfied_by_host_alias(self):
        # Keep the FROZEN inputs untouched and alias only the guest config PATH
        # FIELD to the host copy: the two-root oracle must refuse the host
        # alias at the owned-path identity gate (this is the exact defect the
        # controller's syslog counterexample demonstrated).
        plan = self.real_remote_results('GAP-SYSLOG-ICMP-LOG')

        def alias(target):
            path = target / 'driver' / 'manual-result.json'
            value = json.loads(path.read_text())
            value['syslog_icmp']['config'] = str(target / 'driver' / 'config' / 'syslog.ini')
            path.write_text(json.dumps(value, indent=2) + '\n')

        code, summary = self.rehashed_judge(plan, 'GAP-SYSLOG-ICMP-LOG', alias)
        self.assertNotEqual(0, code)
        self.assertNotEqual('pass', summary['verdict'])
        self.assertIn('owned original path mismatch: config', json.dumps(summary))

    def test_v1_producer_bytes_negative_rejected(self):
        plan = self.real_remote_results('GAP-EXECUTECMD')

        def tamper(target):
            path = target / 'driver' / 'manual-result.json'
            value = json.loads(path.read_text())
            # Forge the recorded hex of the command output: the oracle hashes
            # the retained original file itself, so the forged content must be
            # refused by the real byte-identity predicate.
            recorded = value['executecmd']['command_output_bytes']
            value['executecmd']['command_output_bytes'] = ('00' * (len(recorded) // 2 + 1))
            path.write_text(json.dumps(value, indent=2) + '\n')

        code, summary = self.rehashed_judge(plan, 'GAP-EXECUTECMD', tamper)
        self.assertNotEqual(0, code)
        self.assertNotEqual('pass', summary['verdict'])
        self.assertIn('command output', json.dumps(summary))

    def test_v1_foreign_execution_identity_rejected(self):
        plan = self.real_remote_results('GAP-STANDALONE-LISTENERS')

        def foreign(target):
            path = target / 'driver' / 'manual-result.json'
            value = json.loads(path.read_text())
            value['identity']['execution_id'] = 'foreign-execution'
            path.write_text(json.dumps(value, indent=2) + '\n')

        code, summary = self.rehashed_judge(plan, 'GAP-STANDALONE-LISTENERS', foreign)
        self.assertNotEqual(0, code)
        self.assertIn('identity mismatch', json.dumps(summary))

    def test_list_mutex_independent_single_case_chain(self):
        # ListMutex shares no resource with the DumpPackets seal gap: its own
        # selected single-case plan must run the full real chain without the
        # shared-plan scheduler recovery blocking it.
        plan = self.plan(cases=('GAP-LIST-MUTEX',), name='solo-list-mutex')
        with mock.patch.object(win, 'ExistingWindowsChannel', side_effect=self.channel_class()):
            code, out, err = self.cli('execute', '--plan', plan)
        self.assertEqual(0, code, out + err)
        self.assertEqual(0, self.cli('judge', '--plan', plan, '--results', plan.parent / 'results',
                                     '--output', plan.parent / 'independent.json')[0])
        summary = json.loads((plan.parent / 'independent.json').read_text())
        row = summary['cases'][0]
        self.assertEqual('pass', row['status'])
        self.assertTrue(row['cleanup_ok'])
        self.assertEqual(['blacklist', 'whitelist', 'mutex'],
                         [check['id'] for check in json.loads(
                             (plan.parent / 'results' / 'GAP-LIST-MUTEX' / 'incoming' / 'originals' /
                              'driver' / 'manual-result.json').read_text())['checks']])

    def test_dumppackets_remote_seal_gap_is_precise_and_finite(self):
        # The controller-proved gap: load_capture_originals pins the sealed
        # PCAP's st_dev/st_ino identity; a pulled cross-host copy is a PHYSICAL
        # REPLACEMENT and must be refused. This pins the refusal reason and the
        # exact artifact path so the gap stays precise, not a mystery failure.
        plan = self.plan(cases=('GAP-DUMPPACKETS',), name='solo-dump-seal-gap')
        with mock.patch.object(win, 'ExistingWindowsChannel', side_effect=self.channel_class()):
            code, out, err = self.cli('execute', '--plan', plan)
        self.assertEqual(0, code, out + err)
        self.assertEqual(0, self.cli('judge', '--plan', plan, '--results', plan.parent / 'results',
                                     '--output', plan.parent / 'independent.json')[0])
        summary = json.loads((plan.parent / 'independent.json').read_text())
        row = summary['cases'][0]
        self.assertEqual('fail', row['status'])
        self.assertIn('physical replacement', json.dumps(row.get('evaluation') or {}))
        guest = json.loads((plan.parent / 'results' / 'GAP-DUMPPACKETS' / 'incoming' /
                            'originals' / 'guest-result.json').read_text())
        self.assertEqual('pass', guest['receipt']['status'])
        self.assertTrue(guest['receipt']['cleanup']['recovered'])

    def test_out_of_cohort_manual_v2_case_still_refuses_options(self):
        # GAP-NETWORK-FIX is manual but v2/network-configuring: it must NOT
        # gain remote options from this cohort (plan keeps no-remote block).
        plan = self.plan(cases=('GAP-NETWORK-FIX',), name='v2-blocked')
        value = json.loads(plan.read_text())
        self.assertIn('no remote fallback', value['blocked']['GAP-NETWORK-FIX'])


if __name__ == '__main__':
    unittest.main()
