# Copyright 2026 Google LLC
"""Ordered Linux policy model: no real firewall or network operations."""
from types import SimpleNamespace
import ipaddress
import unittest
from unittest import mock
from fakenet.diverters import linuxnetpolicy as lnp

class OrderedRules:
    """iptables -I inserts at index zero; table and complete spec identify rules."""
    def __init__(self):
        self.chains = {}
        self.calls = []
    def __call__(self, argv):
        self.calls.append(list(argv))
        table = argv[argv.index('-t')+1] if '-t' in argv else 'filter'
        op = next((x for x in ('-I','-C','-D') if x in argv), None)
        if op is None:
            return SimpleNamespace(returncode=0, stdout=b'')
        i = argv.index(op)
        key = (argv[0], table, argv[i+1])
        spec = tuple(argv[i+2:])
        rows = self.chains.setdefault(key, [])
        rc = 0
        if op == '-I': rows.insert(0, spec)
        elif op == '-C': rc = 0 if spec in rows else 1
        elif spec in rows: rows.remove(spec)
        else: rc = 1
        return SimpleNamespace(returncode=rc, stdout=b'')



class NetPolicyTests(unittest.TestCase):
    def setUp(self):
        self.model = OrderedRules()
        self.patch = mock.patch.object(lnp, '_run', self.model)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.policy = lnp.NetPolicy([('192.168.204.1', 2222)])

    def test_allow_precedes_drop_after_head_insertion(self):
        self.policy.block_ipv6()
        rows = self.model.chains['ip6tables', 'filter', 'OUTPUT']
        self.assertEqual([r[-1] for r in rows], ['ACCEPT', 'DROP'])
        self.assertIn('::1', rows[0])

    def test_exact_v4_and_table_preserving_exists(self):
        self.policy.install_control_exclusions_v4()
        before = {k:list(v) for k,v in self.model.chains.items()}
        self.policy.install_control_exclusions_v4()
        self.assertEqual(before, self.model.chains)
        for key, port in [(('iptables','mangle','INPUT'),'--dport'),
                          (('iptables','raw','OUTPUT'),'--sport')]:
            endpoint = next(r for r in self.model.chains[key] if '192.168.204.1' in r)
            self.assertIn('tcp', endpoint)
            self.assertEqual(endpoint[endpoint.index(port)+1], '2222')

    def input_verdict(self, packet):
        rows = self.model.chains.get(('iptables', 'mangle', 'INPUT'), [])
        for row in rows:
            constraints = {'-i': 'interface', '-s': 'source', '-d': 'destination',
                           '-p': 'protocol', '--sport': 'sport', '--dport': 'dport'}
            matched = True
            for option, field in constraints.items():
                if option not in row:
                    continue
                wanted = row[row.index(option) + 1]
                actual = packet[field]
                if option in ('-s', '-d'):
                    matched &= ipaddress.ip_address(actual) in ipaddress.ip_network(wanted)
                else:
                    matched &= str(actual) == wanted
            if matched:
                return row[row.index('-j') + 1]
        return 'NFQUEUE'

    def test_redirected_loopback_reply_reaches_nfqueue(self):
        self.policy.install_control_exclusions_v4()
        # Actual SingleHost SYN-ACK: redirected listener -> original local client.
        reply = dict(interface='lo', source='127.0.0.1',
                     destination='192.168.204.230', protocol='tcp',
                     sport=80, dport=58844)
        self.assertEqual(self.input_verdict(reply), 'NFQUEUE')
        # Genuine local management/DNS endpoints remain excluded, including aliases.
        for source, destination in [('127.0.0.1', '127.0.0.1'),
                                    ('127.0.0.54', '127.0.0.53')]:
            self.assertEqual(self.input_verdict(dict(reply, source=source,
                                                   destination=destination)), 'ACCEPT')
        self.assertEqual(self.input_verdict(dict(reply, interface='ens33',
                                               source='192.168.204.1',
                                               dport=2222)), 'ACCEPT')
        self.assertEqual(self.input_verdict(dict(reply, interface='ens33',
                                               source='192.168.204.1',
                                               dport=80)), 'NFQUEUE')

    def test_adopts_previous_tagged_broad_loopback_rule(self):
        old = lnp.NetPolicy._tagged('iptables', 'mangle', 'INPUT', ['-i', 'lo'])
        self.model(old.argv)
        self.policy.install_control_exclusions_v4()
        self.policy.block_ipv6()
        lnp.NetPolicy([('192.168.204.1', 2222)]).adopt_leftovers()
        self.assertFalse(any(self.model.chains.values()))

    def test_bad_inputs(self):
        for endpoint in [('not-an-ip',80), ('127.0.0.1',99999)]:
            with self.assertRaises(ValueError):lnp.NetPolicy([endpoint])

    def test_cleanup_keeps_foreign_rules(self):
        foreign = ('-d','fd00::2','-j','ACCEPT')
        self.model.chains['ip6tables','filter','OUTPUT'] = [foreign]
        self.policy.block_ipv6()
        self.assertTrue(self.policy.stop()['stopped'])
        self.assertEqual(self.model.chains['ip6tables','filter','OUTPUT'], [foreign])

    def test_mode_transition_and_repeat(self):
        self.policy.set_mode('isolated')
        before = {k:list(v) for k,v in self.model.chains.items()}
        self.policy.set_mode('isolated')
        self.assertEqual(before, self.model.chains)
        self.policy.set_mode('real')
        self.assertFalse(any(self.model.chains.values()))

    def test_adoption_of_only_tagged_rules(self):
        self.policy.install_control_exclusions_v4()
        self.policy.block_ipv6()
        successor = lnp.NetPolicy([('192.168.204.1',2222)])
        self.assertEqual(len(successor.adopt_leftovers()), 6)
        self.assertFalse(any(self.model.chains.values()))

    def test_failed_deletion_is_not_success_or_lost_ownership(self):
        self.policy.block_ipv6()
        def fail_delete(argv):
            if '-D' in argv:return SimpleNamespace(returncode=2, stdout=b'failed')
            return self.model(argv)
        with mock.patch.object(lnp, '_run', fail_delete):
            with self.assertRaises(RuntimeError):self.policy.stop()
        self.assertEqual(len(self.policy._owned), 2)
        self.assertTrue(self.policy.stop()['stopped'])

    def test_probe_failure_refuses_without_insertion(self):
        with mock.patch.object(lnp, '_run', return_value=SimpleNamespace(returncode=2)):
            with self.assertRaises(RuntimeError):self.policy.block_ipv6()
        self.assertEqual(self.policy._owned, [])


if __name__ == '__main__':unittest.main()
