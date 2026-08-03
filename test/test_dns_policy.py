import unittest
from unittest import mock

from dnslib import A, CNAME, DNSHeader, DNSQuestion, DNSRecord, QTYPE, RR

from fakenet.listeners import DNSListener as dns_module
from fakenet.listeners.DNSListener import DNSHandler


class Callbacks(object):
    def __init__(self):
        self.leases = None
        self.alias = None
        self.events = []

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
            'api.deepseek.com', self.callbacks)
        response = DNSRecord.parse(packed)
        self.assertEqual(7, response.header.id)
        self.assertEqual(
            ('api.deepseek.com', (('93.184.216.34', 10),)),
            self.callbacks.leases)
        self.assertEqual([20, 10], [rr.ttl for rr in response.rr])

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
                'api.deepseek.com', self.callbacks)

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
                'api.deepseek.com', self.callbacks)

    def test_multiple_global_addresses_are_installed(self):
        upstream = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=20,
                               rdata=A('93.184.216.34')))
        upstream.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=10,
                               rdata=A('8.8.4.4')))
        packed = self.handler._validate_and_synthesize(
            self.request, upstream, 'api.deepseek.com',
            'api.deepseek.com', self.callbacks)
        response = DNSRecord.parse(packed)
        self.assertEqual(
            ('api.deepseek.com',
             (('93.184.216.34', 20), ('8.8.4.4', 10))),
            self.callbacks.leases)
        self.assertEqual(2, len(response.rr))

    def test_private_address_and_cname_loop_are_rejected(self):
        private = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        private.add_answer(RR('api.deepseek.com', QTYPE.A, ttl=10,
                              rdata=A('10.0.0.1')))
        with self.assertRaises(ValueError):
            self.handler._validate_and_synthesize(
                self.request, private, 'api.deepseek.com',
                'api.deepseek.com', self.callbacks)

        loop = DNSRecord(
            DNSHeader(id=99, qr=1, ra=1), q=self.request.q)
        loop.add_answer(RR('api.deepseek.com', QTYPE.CNAME, ttl=10,
                           rdata=CNAME('edge.example.net')))
        loop.add_answer(RR('edge.example.net', QTYPE.CNAME, ttl=10,
                           rdata=CNAME('api.deepseek.com')))
        with self.assertRaises(ValueError):
            self.handler._validate_and_synthesize(
                self.request, loop, 'api.deepseek.com',
                'api.deepseek.com', self.callbacks)

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


if __name__ == '__main__':
    unittest.main()
