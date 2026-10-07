# Copyright 2026 Google LLC
"""LNX-FN net policy unit tests (no real iptables mutation)."""
import sys
import unittest
from unittest import mock

sys.path.insert(0, '.')

from fakenet.diverters import linuxnetpolicy as lnp


class FakeRunner:
    def __init__(self, existing=()):
        self.calls = []
        self.existing = set(existing)

    def __call__(self, argv):
        self.calls.append(list(argv))
        # -C checks membership; -I adds; -D removes
        if '-C' in argv:
            key = ' '.join(argv)
            return mock.Mock(returncode=0 if any(
                self._matches(c, argv) for c in self.existing) else 1)
        return mock.Mock(returncode=0)

    def _matches(self, existing, check_argv):
        return existing in ' '.join(check_argv)


class NetPolicyTests(unittest.TestCase):
    def test_block_ipv6_applies_allow_then_drop(self):
        runner = FakeRunner()
        policy = lnp.NetPolicy(control_endpoints=[('127.0.0.1', 8765)])
        with mock.patch.object(lnp, '_run', runner):
            applied = policy.block_ipv6()
        inserts = [c for c in runner.calls if '-I' in c]
        # loopback accept + DROP, control endpoint is v4 (no v6 accept)
        self.assertEqual(len(inserts), 2)
        self.assertTrue(all(c[0] == 'ip6tables' for c in inserts))
        self.assertEqual(inserts[-1][-2:], ['-j', 'DROP'])
        self.assertEqual(applied, inserts)
        # DROP placed after the loopback ACCEPT (later -I = lower priority)
        self.assertIn('-d', inserts[0])
        self.assertEqual(inserts[0][inserts[0].index('-d') + 1], '::1')

    def test_control_endpoints_v4_exclusion(self):
        runner = FakeRunner()
        policy = lnp.NetPolicy(control_endpoints=[('192.168.1.10', 28765)])
        with mock.patch.object(lnp, '_run', runner):
            count = policy.install_control_exclusions_v4()
        self.assertEqual(count, 4)  # lo both ways + OUTPUT exclude + INPUT keep
        calls = [c for c in runner.calls if '-I' in c]
        self.assertTrue(any(c[1:3] == ['-t', 'raw'] and 'OUTPUT' in c
                            for c in calls))
        self.assertTrue(any(c[1:3] == ['-t', 'mangle'] and 'INPUT' in c
                            for c in calls))
        ep_calls = [c for c in calls if '192.168.1.10' in c]
        self.assertEqual(len(ep_calls), 2)
        self.assertTrue(all(c[-2:] == ['-j', 'ACCEPT'] for c in ep_calls))

    def test_bad_inputs_rejected(self):
        with self.assertRaises(ValueError):
            lnp.NetPolicy(control_endpoints=[('not-an-ip', 80)])
        with self.assertRaises(ValueError):
            lnp.NetPolicy(control_endpoints=[('127.0.0.1', 99999)])

    def test_stop_removes_owned_and_reports(self):
        runner = FakeRunner()
        policy = lnp.NetPolicy()
        with mock.patch.object(lnp, '_run', runner):
            policy.block_ipv6()
            result = policy.stop()
        deletes = [c for c in runner.calls if '-D' in c]
        self.assertEqual(len(deletes), 2)  # ::1 accept + DROP
        self.assertTrue(result['stopped'])
        self.assertFalse(result['ipv6_block_leftover'])

    def test_mode_switch_real_then_isolated(self):
        runner = FakeRunner()
        policy = lnp.NetPolicy(control_endpoints=[('10.0.0.5', 9000)])
        paused = []
        resumed = []
        with mock.patch.object(lnp, '_run', runner):
            policy.block_ipv6()
            policy.mode = 'isolated'
            policy.set_mode('real',
                            takeover_pause=lambda: paused.append(1))
            self.assertEqual(policy.mode, 'real')
            policy.set_mode('isolated',
                            takeover_resume=lambda: resumed.append(1))
            self.assertEqual(policy.mode, 'isolated')
        self.assertEqual(paused, [1])
        self.assertEqual(resumed, [1])
        idempotent = policy.set_mode('isolated')
        self.assertEqual(idempotent['mode'], 'isolated')

    def test_adopt_leftovers_drops_prior_drop(self):
        runner = FakeRunner(existing=('OUTPUT -j DROP',))
        policy = lnp.NetPolicy()
        with mock.patch.object(lnp, '_run', runner):
            # simulate prior crash state visible in -S listing
            def fake_run(argv):
                if '-S' in argv:
                    return mock.Mock(
                        returncode=0,
                        stdout=b'-P OUTPUT ACCEPT\n-A OUTPUT -j DROP\n')
                return runner.__call__(argv)
            with mock.patch.object(lnp, '_run', fake_run):
                adopted = policy.adopt_leftovers()
        self.assertIn('ipv6-DROP', adopted)

    def test_evidence_captures_rule_state(self):
        policy = lnp.NetPolicy()
        with mock.patch.object(
                lnp, '_run',
                return_value=mock.Mock(returncode=0, stdout=b'-P OUTPUT ACCEPT\n')):
            policy.block_ipv6()
            evidence = policy.evidence()
        self.assertEqual(evidence['mode'], None)
        self.assertIn('ip6tables_output', evidence)
        self.assertTrue(any('DROP' in ' '.join(r) for r in evidence['owned_rules']))


if __name__ == '__main__':
    unittest.main()
