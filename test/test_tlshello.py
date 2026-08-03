import unittest

from fakenet.listeners.DomainEgressRelay import (
    ClientHelloError, parse_client_hello)


def extension(ext_type, payload):
    return ext_type.to_bytes(2, 'big') + len(payload).to_bytes(2, 'big') + payload


def client_hello(host='api.deepseek.com', extra_extensions=b'', trailing=b''):
    encoded = host.encode('ascii')
    server_name = (len(encoded) + 3).to_bytes(2, 'big') + b'\x00' + \
        len(encoded).to_bytes(2, 'big') + encoded
    extensions = extension(0, server_name) + extra_extensions
    body = (b'\x03\x03' + b'R' * 32 + b'\x00' + b'\x00\x02' +
            b'\x13\x01' + b'\x01\x00' +
            len(extensions).to_bytes(2, 'big') + extensions)
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    record = b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake
    return record + trailing


class ClientHelloTests(unittest.TestCase):
    def test_sni_and_trailing_zero_rtt_are_preserved_by_boundary(self):
        payload = client_hello(trailing=b'\x17\x03\x03\x00\x01X')
        status, sni = parse_client_hello(payload)
        self.assertEqual('ok', status)
        self.assertEqual('api.deepseek.com', sni)

    def test_fragmented_input_requests_more(self):
        payload = client_hello()
        self.assertEqual(('need_more', None), parse_client_hello(payload[:8]))
        self.assertEqual('ok', parse_client_hello(payload)[0])

    def test_ech_is_rejected(self):
        payload = client_hello(extra_extensions=extension(0xfe0d, b'\x00'))
        with self.assertRaises(ClientHelloError):
            parse_client_hello(payload)

    def test_plaintext_and_missing_sni_are_rejected(self):
        with self.assertRaises(ClientHelloError):
            parse_client_hello(b'GET / HTTP/1.1\r\n')
        extensions = extension(43, b'\x02\x03\x04')
        body = (b'\x03\x03' + b'R' * 32 + b'\x00' + b'\x00\x02' +
                b'\x13\x01' + b'\x01\x00' +
                len(extensions).to_bytes(2, 'big') + extensions)
        handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
        payload = b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake
        with self.assertRaises(ClientHelloError):
            parse_client_hello(payload)


if __name__ == '__main__':
    unittest.main()
