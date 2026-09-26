import socket
import unittest
from unittest import mock

from dnslib import (A, CNAME, CLASS, DNSHeader, DNSQuestion, DNSRecord,
                    NS, QTYPE, RCODE, RR)

from fakenet.listeners import DNSListener as dns_module
from fakenet.listeners.DNSListener import DNSHandler


class Callbacks(object):
    def __init__(self):
        self.leases = None
        self.alias = None
        self.events = []
        self.takeover = {
            'enabled': True,
            'available': True,
            'ipv4': '192.168.204.1',
            'dns_ttl': 60,
            'suspend_reason': None,
        }

    def isProcessBlackListed(self, proto, sport):
        return False, None, None

    def egressPolicyEnabled(self):
        return True

    def isLocalAddress(self, address):
        return address == '10.0.0.5'

    def resolveDnsRule(self, qname):
        normalized = str(qname).rstrip('.').lower()
        return ('api.deepseek.com' if normalized ==
                'api.deepseek.com' else None)

    def getTakeoverSettings(self):
        return dict(self.takeover)

    def getEgressSettings(self):
        return {
            'dns_server': '10.0.0.1',
            'dns_timeout': 3,
            'reviewed_ipv4_rule_ids': {},
        }

    def replaceDnsLeases(self, domain, records):
        self.leases = (domain, tuple(records))
        return tuple(ip for ip, ttl in records if ttl > 0)

    def registerDnsAlias(self, domain, alias, ttl):
        self.alias = (domain, alias, ttl)

    def logEgressEvent(self, event, **fields):
        self.events.append((event, fields))


class DnsPolicyTests(unittest.TestCase):
    def setUp(self):
        self.handler = DNSHandler()
        self.callbacks = Callbacks()
        self.settings = self.callbacks.getEgressSettings()
        self.request = DNSRecord(
            DNSHeader(id=7, rd=1),
            q=DNSQuestion('api.deepseek.com', QTYPE.A))

    def test_cname_chain_minimum_ttl_and_client_id(self):
        upstream = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.CNAME, ttl=20,
                               rdata=CNAME('edge.example.net')))
        upstream.add_answer(RR('edge.example.net', QTYPE.A, ttl=10,
                               rdata=A('93.184.216.34')))
        packed = self.handler._validate_and_synthesize(
            self.request, upstream, 'api.deepseek.com',
            'api.deepseek.com', self.callbacks, self.settings)
        response = DNSRecord.parse(packed)
        self.assertEqual(7, response.header.id)
        self.assertEqual(
            ('api.deepseek.com', (('93.184.216.34', 10),)),
            self.callbacks.leases)
        self.assertEqual([20, 10], [rr.ttl for rr in response.rr])

    def test_related_nameserver_glue_is_stripped_without_changing_lease(self):
        # Constructed from the later R05 resolver observation, not the P7 wire.
        upstream = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.CNAME, ttl=20,
                               rdata=CNAME('api.deepseek.com.eo.dnse1.com')))
        upstream.add_answer(RR('api.deepseek.com.eo.dnse1.com', QTYPE.A,
                               ttl=30, rdata=A('93.184.216.34')))
        upstream.add_auth(RR('com', QTYPE.NS, ttl=100,
                             rdata=NS('a.gtld-servers.net')))
        upstream.add_ar(RR('a.gtld-servers.net', QTYPE.A, ttl=1,
                           rdata=A('8.8.4.4')))

        packed = self.handler._validate_and_synthesize(
            self.request, upstream, 'api.deepseek.com',
            'api.deepseek.com', self.callbacks, self.settings)

        response = DNSRecord.parse(packed)
        self.assertEqual(7, response.header.id)
        self.assertEqual([QTYPE.CNAME, QTYPE.A],
                         [rr.rtype for rr in response.rr])
        self.assertEqual([20, 20], [rr.ttl for rr in response.rr])
        self.assertEqual([], response.auth)
        self.assertEqual([], response.ar)
        self.assertEqual(('api.deepseek.com',
                          (('93.184.216.34', 20),)), self.callbacks.leases)
        self.assertIsNone(self.callbacks.alias)
        self.assertEqual(['DNS_LEASE_ADD'],
                         [event for event, _ in self.callbacks.events])

    def test_root_nameserver_glue_is_stripped(self):
        upstream = DNSRecord(DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=30,
                               rdata=A('93.184.216.34')))
        upstream.add_auth(RR('.', QTYPE.NS, ttl=100,
                             rdata=NS('a.root-servers.net')))
        upstream.add_ar(RR('a.root-servers.net', QTYPE.A, ttl=1,
                           rdata=A('8.8.4.4')))

        response = DNSRecord.parse(self.handler._validate_and_synthesize(
            self.request, upstream, 'api.deepseek.com',
            'api.deepseek.com', self.callbacks, self.settings))

        self.assertEqual(['93.184.216.34'],
                         [str(rr.rdata) for rr in response.rr])
        self.assertEqual([], response.auth)
        self.assertEqual([], response.ar)
        self.assertEqual(('api.deepseek.com',
                          (('93.184.216.34', 30),)), self.callbacks.leases)

    def test_related_cname_ancestor_glue_does_not_change_multiple_a_ttls(self):
        upstream = DNSRecord(DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.CNAME, ttl=25,
                               rdata=CNAME('edge.example.net')))
        upstream.add_answer(RR('edge.example.net', QTYPE.A, ttl=30,
                               rdata=A('93.184.216.34')))
        upstream.add_answer(RR('edge.example.net', QTYPE.A, ttl=10,
                               rdata=A('8.8.8.8')))
        upstream.add_auth(RR('example.net', QTYPE.NS, ttl=1,
                             rdata=NS('ns.example.net')))
        upstream.add_ar(RR('ns.example.net', QTYPE.A, ttl=1,
                           rdata=A('8.8.4.4')))

        response = DNSRecord.parse(self.handler._validate_and_synthesize(
            self.request, upstream, 'api.deepseek.com',
            'api.deepseek.com', self.callbacks, self.settings))

        self.assertEqual([25, 25, 10], [rr.ttl for rr in response.rr])
        self.assertEqual([], response.auth)
        self.assertEqual([], response.ar)
        self.assertEqual(('api.deepseek.com',
                          (('93.184.216.34', 25), ('8.8.8.8', 10))),
                         self.callbacks.leases)
        self.assertEqual(2, len(self.callbacks.events))

    def test_unrelated_section_addresses_and_cnames_have_no_side_effects(self):
        for section, rr in (
                ('auth', RR('attacker.example', QTYPE.A, ttl=10,
                            rdata=A('8.8.4.4'))),
                ('auth', RR('attacker.example', QTYPE.CNAME, ttl=10,
                            rdata=CNAME('edge.example.net'))),
                ('ar', RR('attacker.example', QTYPE.A, ttl=10,
                          rdata=A('8.8.4.4'))),
                ('ar', RR('attacker.example', QTYPE.CNAME, ttl=10,
                          rdata=CNAME('edge.example.net')))):
            with self.subTest(section=section, rtype=rr.rtype):
                upstream = DNSRecord(
                    DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
                upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=10,
                                       rdata=A('93.184.216.34')))
                getattr(upstream, 'add_' + section)(rr)
                callbacks = Callbacks()
                with self.assertRaises(ValueError):
                    self.handler._validate_and_synthesize(
                        self.request, upstream, 'api.deepseek.com',
                        'api.deepseek.com', callbacks, self.settings)
                self.assertIsNone(callbacks.leases)
                self.assertIsNone(callbacks.alias)
                self.assertEqual([], callbacks.events)

    def test_only_exact_glue_of_strict_label_ancestor_can_be_stripped(self):
        for ns_owner, ns_target, additional_owner, additional_ip in (
                ('evil.com', 'ns.example.net', 'ns.example.net', '8.8.4.4'),
                ('seek.com', 'ns.example.net', 'ns.example.net', '8.8.4.4'),
                ('api.deepseek.com', 'ns.example.net', 'ns.example.net',
                 '8.8.4.4'),
                ('com', 'ns.example.net', 'other.example.net', '8.8.4.4'),
                ('com', 'api.deepseek.com', 'api.deepseek.com', '8.8.4.4'),
                ('com', 'ns.example.net', 'ns.example.net', '10.0.0.1')):
            with self.subTest(ns_owner=ns_owner, ns_target=ns_target,
                              additional_owner=additional_owner,
                              additional_ip=additional_ip):
                upstream = DNSRecord(
                    DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
                upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=10,
                                       rdata=A('93.184.216.34')))
                upstream.add_auth(RR(ns_owner, QTYPE.NS, ttl=10,
                                     rdata=NS(ns_target)))
                upstream.add_ar(RR(additional_owner, QTYPE.A, ttl=10,
                                   rdata=A(additional_ip)))
                callbacks = Callbacks()
                with self.assertRaises(ValueError):
                    self.handler._validate_and_synthesize(
                        self.request, upstream, 'api.deepseek.com',
                        'api.deepseek.com', callbacks, self.settings)
                self.assertIsNone(callbacks.leases)
                self.assertIsNone(callbacks.alias)
                self.assertEqual([], callbacks.events)

    def test_structurally_forged_nameserver_glue_is_discarded_not_authorized(self):
        upstream = DNSRecord(DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=20,
                               rdata=A('93.184.216.34')))
        upstream.add_auth(RR('com', QTYPE.NS, ttl=10,
                             rdata=NS('forged.example.net')))
        upstream.add_ar(RR('forged.example.net', QTYPE.A, ttl=10,
                           rdata=A('8.8.4.4')))

        response = DNSRecord.parse(self.handler._validate_and_synthesize(
            self.request, upstream, 'api.deepseek.com',
            'api.deepseek.com', self.callbacks, self.settings))

        self.assertEqual(['93.184.216.34'],
                         [str(rr.rdata) for rr in response.rr])
        self.assertEqual([], response.auth)
        self.assertEqual([], response.ar)
        self.assertEqual(('api.deepseek.com',
                          (('93.184.216.34', 20),)), self.callbacks.leases)
        self.assertIsNone(self.callbacks.alias)
        self.assertEqual(['DNS_LEASE_ADD'],
                         [event for event, _ in self.callbacks.events])

    def test_glue_cannot_shadow_terminal_cname_owner(self):
        upstream = DNSRecord(DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.CNAME, ttl=20,
                               rdata=CNAME('edge.example.net')))
        upstream.add_answer(RR('edge.example.net', QTYPE.A, ttl=20,
                               rdata=A('93.184.216.34')))
        upstream.add_auth(RR('com', QTYPE.NS, ttl=10,
                             rdata=NS('edge.example.net')))
        upstream.add_ar(RR('edge.example.net', QTYPE.A, ttl=10,
                           rdata=A('8.8.4.4')))

        with self.assertRaises(ValueError):
            self.handler._validate_and_synthesize(
                self.request, upstream, 'api.deepseek.com',
                'api.deepseek.com', self.callbacks, self.settings)
        self.assertIsNone(self.callbacks.leases)
        self.assertIsNone(self.callbacks.alias)
        self.assertEqual([], self.callbacks.events)

    def test_unrelated_additional_after_glue_rejects_entire_response(self):
        upstream = DNSRecord(DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=20,
                               rdata=A('93.184.216.34')))
        upstream.add_auth(RR('com', QTYPE.NS, ttl=10,
                             rdata=NS('ns.example.net')))
        upstream.add_ar(RR('ns.example.net', QTYPE.A, ttl=10,
                           rdata=A('8.8.4.4')))
        upstream.add_ar(RR('attacker.example', QTYPE.A, ttl=10,
                           rdata=A('8.8.8.8')))

        with self.assertRaises(ValueError):
            self.handler._validate_and_synthesize(
                self.request, upstream, 'api.deepseek.com',
                'api.deepseek.com', self.callbacks, self.settings)
        self.assertIsNone(self.callbacks.leases)
        self.assertIsNone(self.callbacks.alias)
        self.assertEqual([], self.callbacks.events)

    def test_glue_cannot_fill_missing_answer_or_change_cname_only_alias(self):
        upstream = DNSRecord(DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_auth(RR('com', QTYPE.NS, ttl=10,
                             rdata=NS('ns.example.net')))
        upstream.add_ar(RR('ns.example.net', QTYPE.A, ttl=10,
                           rdata=A('8.8.4.4')))
        with self.assertRaises(ValueError):
            self.handler._validate_and_synthesize(
                self.request, upstream, 'api.deepseek.com',
                'api.deepseek.com', self.callbacks, self.settings)
        self.assertIsNone(self.callbacks.leases)
        self.assertIsNone(self.callbacks.alias)
        self.assertEqual([], self.callbacks.events)

        upstream.add_answer(RR('api.deepseek.com', QTYPE.CNAME, ttl=20,
                               rdata=CNAME('edge.example.net')))
        response = DNSRecord.parse(self.handler._validate_and_synthesize(
            self.request, upstream, 'api.deepseek.com',
            'api.deepseek.com', self.callbacks, self.settings))
        self.assertEqual([QTYPE.CNAME], [rr.rtype for rr in response.rr])
        self.assertEqual([], response.auth)
        self.assertEqual([], response.ar)
        self.assertIsNone(self.callbacks.leases)
        self.assertEqual(('api.deepseek.com', 'edge.example.net', 20),
                         self.callbacks.alias)
        self.assertEqual([], self.callbacks.events)

    def test_invalid_answer_chain_with_glue_has_no_side_effects(self):
        for extra_rr in (
                RR('api.deepseek.com', QTYPE.CNAME, ttl=10,
                   rdata=CNAME('other.example.net')),
                RR('unrelated.example.net', QTYPE.A, ttl=10,
                   rdata=A('8.8.8.8'))):
            with self.subTest(extra_owner=str(extra_rr.rname),
                              extra_type=extra_rr.rtype):
                upstream = DNSRecord(
                    DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
                upstream.add_answer(RR('api.deepseek.com', QTYPE.CNAME,
                                       ttl=20,
                                       rdata=CNAME('edge.example.net')))
                upstream.add_answer(RR('edge.example.net', QTYPE.A,
                                       ttl=20, rdata=A('93.184.216.34')))
                upstream.add_answer(extra_rr)
                upstream.add_auth(RR('com', QTYPE.NS, ttl=10,
                                     rdata=NS('ns.example.net')))
                upstream.add_ar(RR('ns.example.net', QTYPE.A, ttl=10,
                                   rdata=A('8.8.4.4')))
                callbacks = Callbacks()
                with self.assertRaises(ValueError):
                    self.handler._validate_and_synthesize(
                        self.request, upstream, 'api.deepseek.com',
                        'api.deepseek.com', callbacks, self.settings)
                self.assertIsNone(callbacks.leases)
                self.assertIsNone(callbacks.alias)
                self.assertEqual([], callbacks.events)

    def test_additional_address_injection_is_rejected(self):
        upstream = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=10,
                               rdata=A('93.184.216.34')))
        upstream.add_ar(RR('attacker.example', QTYPE.A, ttl=10,
                           rdata=A('93.184.216.35')))
        with self.assertRaises(ValueError):
            self.handler._validate_and_synthesize(
                self.request, upstream, 'api.deepseek.com',
                'api.deepseek.com', self.callbacks, self.settings)

    def test_wrong_upstream_transaction_is_rejected(self):
        upstream = DNSRecord(
            DNSHeader(id=100, qr=1, ra=1), q=self.request.q)
        with self.assertRaises(ValueError):
            self.handler._validate_upstream_header(
                upstream, self.request, upstream_id=99)

    def test_zero_ttl_address_is_rejected(self):
        upstream = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=0,
                               rdata=A('93.184.216.34')))
        with self.assertRaises(ValueError):
            self.handler._validate_and_synthesize(
                self.request, upstream, 'api.deepseek.com',
                'api.deepseek.com', self.callbacks, self.settings)

    def test_multiple_global_addresses_are_installed(self):
        upstream = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=20,
                               rdata=A('93.184.216.34')))
        upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=10,
                               rdata=A('8.8.4.4')))
        packed = self.handler._validate_and_synthesize(
            self.request, upstream, 'api.deepseek.com',
            'api.deepseek.com', self.callbacks, self.settings)
        response = DNSRecord.parse(packed)
        self.assertEqual(
            ('api.deepseek.com',
             (('93.184.216.34', 20), ('8.8.4.4', 10))),
            self.callbacks.leases)
        self.assertEqual(2, len(response.rr))

    def test_reviewed_ip_overlap_is_audited_without_changing_dns(self):
        upstream = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=10,
                               rdata=A('93.184.216.34')))
        settings = dict(self.settings)
        settings['reviewed_ipv4_rule_ids'] = {
            '93.184.216.34': ('rule-a', 'rule-b')}

        packed = self.handler._validate_and_synthesize(
            self.request, upstream, 'api.deepseek.com',
            'api.deepseek.com', self.callbacks, settings)

        response = DNSRecord.parse(packed)
        self.assertEqual('93.184.216.34', str(response.rr[0].rdata))
        self.assertIn(
            ('IP_ALLOW_DOMAIN_OVERLAP', {
                'domain': 'api.deepseek.com',
                'ip': '93.184.216.34',
                'rule_ids': 'rule-a;rule-b',
            }), self.callbacks.events)

    def test_reviewed_ip_overlap_log_failure_does_not_change_dns_or_lease(self):
        upstream = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=10,
                               rdata=A('93.184.216.34')))
        settings = dict(self.settings)
        settings['reviewed_ipv4_rule_ids'] = {
            '93.184.216.34': ('rule-a',)}
        original_logger = self.callbacks.logEgressEvent

        def fail_overlap(event, **fields):
            if event == 'IP_ALLOW_DOMAIN_OVERLAP':
                raise OSError('log unavailable')
            return original_logger(event, **fields)

        self.callbacks.logEgressEvent = fail_overlap
        self.handler.server = mock.Mock()
        packed = self.handler._validate_and_synthesize(
            self.request, upstream, 'api.deepseek.com',
            'api.deepseek.com', self.callbacks, settings)

        response = DNSRecord.parse(packed)
        self.assertEqual('93.184.216.34', str(response.rr[0].rdata))
        self.assertEqual(
            ('api.deepseek.com', (('93.184.216.34', 10),)),
            self.callbacks.leases)
        self.handler.server.logger.warning.assert_called_once()

    def test_private_address_and_cname_loop_are_rejected(self):
        private = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        private.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=10,
                              rdata=A('10.0.0.1')))
        with self.assertRaises(ValueError):
            self.handler._validate_and_synthesize(
                self.request, private, 'api.deepseek.com',
                'api.deepseek.com', self.callbacks, self.settings)

        loop = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        loop.add_answer(RR('api.deepseek.com', QTYPE.CNAME, ttl=10,
                           rdata=CNAME('edge.example.net')))
        loop.add_answer(RR('edge.example.net', QTYPE.CNAME, ttl=10,
                           rdata=CNAME('api.deepseek.com')))
        with self.assertRaises(ValueError):
            self.handler._validate_and_synthesize(
                self.request, loop, 'api.deepseek.com',
                'api.deepseek.com', self.callbacks, self.settings)

    def test_wrong_upstream_question_name_and_type_are_rejected(self):
        wrong_name = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1),
            q=DNSQuestion('example.com', QTYPE.A))
        with self.assertRaises(ValueError):
            self.handler._validate_upstream_header(
                wrong_name, self.request, upstream_id=99)
        wrong_type = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1),
            q=DNSQuestion('api.deepseek.com', QTYPE.AAAA))
        with self.assertRaises(ValueError):
            self.handler._validate_upstream_header(
                wrong_type, self.request, upstream_id=99)

    def test_udp_truncation_retries_tcp_with_same_random_query(self):
        truncated = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1, tc=1), q=self.request.q).pack()
        complete = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        complete.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=10,
                               rdata=A('93.184.216.34')))
        self.handler._query_upstream_udp = mock.Mock(
            return_value=truncated)
        self.handler._query_upstream_tcp = mock.Mock(
            return_value=complete.pack())

        with mock.patch.object(dns_module.secrets, 'randbelow',
                               return_value=99):
            response = self.handler._query_upstream(
                self.request, 'UDP', self.callbacks,
                {'dns_server': '10.0.0.1', 'dns_timeout': 3})

        udp_query = self.handler._query_upstream_udp.call_args.args[0]
        tcp_query = self.handler._query_upstream_tcp.call_args.args[0]
        self.assertEqual(udp_query, tcp_query)
        parsed_query = DNSRecord.parse(udp_query)
        self.assertEqual(99, parsed_query.header.id)
        self.assertEqual(str(self.request.q.qname),
                         str(parsed_query.q.qname))
        self.assertEqual(self.request.q.qtype, parsed_query.q.qtype)
        self.assertEqual('93.184.216.34', str(response.rr[0].rdata))

    def test_independent_queries_receive_distinct_upstream_ids(self):
        seen = []

        def answer(query, callbacks, settings):
            parsed = DNSRecord.parse(query)
            seen.append(parsed.header.id)
            return DNSRecord(
                DNSHeader(id=parsed.header.id, qr=1, ra=1),
                q=parsed.q).pack()

        self.handler._query_upstream_udp = mock.Mock(side_effect=answer)
        with mock.patch.object(dns_module.secrets, 'randbelow',
                               side_effect=[100, 101]):
            first = self.handler._query_upstream(
                self.request, 'UDP', self.callbacks, {})
            second = self.handler._query_upstream(
                self.request, 'UDP', self.callbacks, {})

        self.assertEqual([100, 101], seen)
        self.assertEqual([100, 101], [first.header.id, second.header.id])

    def _parse_with_takeover(self, request, socket_type=socket.SOCK_DGRAM):
        handler = DNSHandler()
        callbacks = Callbacks()
        server = mock.Mock()
        server.socket_type = socket_type
        server.diverterListenerCallbacks = callbacks
        server.config = {'responsea': '192.168.204.1'}
        server.nxdomains = 0
        handler.server = server
        handler.client_address = ('10.0.0.5', 53000)
        handler._query_upstream = mock.Mock(
            side_effect=AssertionError('takeover queried upstream DNS'))
        packed = handler.parse(request.pack())
        return handler, callbacks, DNSRecord.parse(packed)

    def test_takeover_a_is_authoritative_and_never_queries_upstream(self):
        request = DNSRecord(
            DNSHeader(id=321, rd=1),
            q=DNSQuestion('example.test', QTYPE.A))
        handler, callbacks, response = self._parse_with_takeover(request)
        handler._query_upstream.assert_not_called()
        self.assertEqual(321, response.header.id)
        self.assertEqual(1, response.header.qr)
        self.assertEqual(1, response.header.aa)
        self.assertEqual(1, response.header.ra)
        self.assertEqual(1, response.header.rd)
        self.assertEqual(RCODE.NOERROR, response.header.rcode)
        self.assertEqual(str(request.q.qname), str(response.q.qname))
        self.assertEqual('192.168.204.1', str(response.rr[0].rdata))
        self.assertEqual(60, response.rr[0].ttl)
        self.assertIn(('TAKEOVER_DNS_ANSWER', {
            'domain': 'example.test', 'ip': '192.168.204.1',
            'ttl': 60, 'proto': 'UDP'}), callbacks.events)

    def test_takeover_udp_and_tcp_share_the_same_answer(self):
        request = DNSRecord(
            DNSHeader(id=11, rd=1),
            q=DNSQuestion('other.test', QTYPE.A))
        _, udp_callbacks, udp = self._parse_with_takeover(
            request, socket.SOCK_DGRAM)
        _, tcp_callbacks, tcp = self._parse_with_takeover(
            request, socket.SOCK_STREAM)
        self.assertEqual(udp.pack(), tcp.pack())
        self.assertEqual('UDP', udp_callbacks.events[-1][1]['proto'])
        self.assertEqual('TCP', tcp_callbacks.events[-1][1]['proto'])

    def test_msftncsi_special_case_is_disabled_in_takeover_mode(self):
        request = DNSRecord(
            DNSHeader(id=12, rd=1),
            q=DNSQuestion('dns.msftncsi.com', QTYPE.A))
        _, _, response = self._parse_with_takeover(request)
        self.assertEqual('192.168.204.1', str(response.rr[0].rdata))

    def test_takeover_suspend_returns_servfail_without_fallback(self):
        handler = DNSHandler()
        callbacks = Callbacks()
        callbacks.takeover['available'] = False
        callbacks.takeover['suspend_reason'] = 'route_snapshot_changed'
        server = mock.Mock()
        server.socket_type = socket.SOCK_DGRAM
        server.diverterListenerCallbacks = callbacks
        handler.server = server
        handler.client_address = ('10.0.0.5', 53000)
        request = DNSRecord(
            DNSHeader(id=13, rd=1),
            q=DNSQuestion('blocked.test', QTYPE.A))
        response = DNSRecord.parse(handler.parse(request.pack()))
        self.assertEqual(RCODE.SERVFAIL, response.header.rcode)
        self.assertEqual(0, len(response.rr))
        self.assertEqual('TAKEOVER_DNS_DENY', callbacks.events[-1][0])

    def test_allowed_domain_never_uses_takeover_answer(self):
        handler = DNSHandler()
        callbacks = Callbacks()
        server = mock.Mock()
        server.socket_type = socket.SOCK_DGRAM
        server.diverterListenerCallbacks = callbacks
        handler.server = server
        handler.client_address = ('10.0.0.5', 53000)
        handler._resolve_allowed_a = mock.Mock(return_value=b'allowed')
        request = DNSRecord(
            DNSHeader(id=14, rd=1),
            q=DNSQuestion('api.deepseek.com', QTYPE.A))
        self.assertEqual(b'allowed', handler.parse(request.pack()))
        handler._resolve_allowed_a.assert_called_once()
        self.assertFalse(any(event == 'TAKEOVER_DNS_ANSWER'
                             for event, fields in callbacks.events))

    def test_takeover_aaaa_is_nodata_and_invalid_questions_fail(self):
        aaaa = DNSRecord(
            DNSHeader(id=15, rd=1),
            q=DNSQuestion('other.test', QTYPE.AAAA))
        _, callbacks, response = self._parse_with_takeover(aaaa)
        self.assertEqual(RCODE.NOERROR, response.header.rcode)
        self.assertEqual(0, len(response.rr))
        self.assertEqual([], callbacks.events)

        non_in = DNSRecord(
            DNSHeader(id=16, rd=1),
            q=DNSQuestion('other.test', QTYPE.A, qclass=CLASS.CH))
        _, _, refused = self._parse_with_takeover(non_in)
        self.assertEqual(RCODE.REFUSED, refused.header.rcode)

        multiple = DNSRecord(
            DNSHeader(id=17, rd=1),
            q=DNSQuestion('one.test', QTYPE.A))
        multiple.add_question(DNSQuestion('two.test', QTYPE.A))
        _, _, malformed = self._parse_with_takeover(multiple)
        self.assertEqual(RCODE.FORMERR, malformed.header.rcode)


if __name__ == '__main__':
    unittest.main()
