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

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'test')]
import test_acceptance_manual_remote as base_mod  # noqa: E402
from test_acceptance_manual_remote import sha, portable_ignore  # noqa: E402
import acceptance_windows as win  # noqa: E402

SEVEN = ('GAP-EXECUTECMD', 'GAP-STANDALONE-LISTENERS', 'GAP-CTRLC-IPC',
         'GAP-DIVERTER-SWITCH', 'GAP-SYSLOG-ICMP-LOG', 'GAP-DUMPPACKETS',
         'GAP-LIST-MUTEX')


class RemoteV1ManualTests(base_mod.RemoteManualTests):
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

    def test_seven_v1_cases_full_roundtrip_and_rejudge(self):
        plan = self.plan(cases=SEVEN, name='v1-seven')
        with mock.patch.object(win, 'ExistingWindowsChannel', side_effect=self.stand_in()):
            code, out, err = self.cli('execute', '--plan', plan)
        self.assertEqual(0, code, out + err)
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

    def test_v1_guest_owned_root_cannot_be_satisfied_by_host_alias(self):
        # A mutated owned_root that names the HOST copy path instead of the
        # frozen GUEST producer root must fail the oracle's identity gate even
        # when every byte/hash layer is re-pinned consistently.
        plan = self.real_remote_results('GAP-LIST-MUTEX')

        def alias(target):
            path = target / 'driver' / 'manual-result.json'
            value = json.loads(path.read_text())
            value['inputs']['owned_root'] = str(target / 'driver')
            path.write_text(json.dumps(value, indent=2) + '\n')

        code, summary = self.rehashed_judge(plan, 'GAP-LIST-MUTEX', alias)
        self.assertNotEqual(0, code)
        self.assertNotEqual('pass', summary['verdict'])
        self.assertIn('owned root mismatch', json.dumps(summary))

    def test_v1_producer_bytes_negative_rejected(self):
        plan = self.real_remote_results('GAP-EXECUTECMD')

        def tamper(target):
            path = target / 'driver' / 'manual-result.json'
            value = json.loads(path.read_text())
            value['observations'][0]['exit_code'] = 0
            path.write_text(json.dumps(value, indent=2) + '\n')

        code, summary = self.rehashed_judge(plan, 'GAP-EXECUTECMD', tamper)
        self.assertNotEqual(0, code)
        self.assertNotEqual('pass', summary['verdict'])

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

    def test_out_of_cohort_manual_v2_case_still_refuses_options(self):
        # GAP-NETWORK-FIX is manual but v2/network-configuring: it must NOT
        # gain remote options from this cohort (plan keeps no-remote block).
        plan = self.plan(cases=('GAP-NETWORK-FIX',), name='v2-blocked')
        value = json.loads(plan.read_text())
        self.assertIn('no remote fallback', value['blocked']['GAP-NETWORK-FIX'])


if __name__ == '__main__':
    unittest.main()
