import unittest

from dnslib import A, CNAME, DNSHeader, DNSQuestion, DNSRecord, QTYPE, RR

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


if __name__ == '__main__':
    unittest.main()
