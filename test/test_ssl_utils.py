import logging
import tempfile
import unittest

from cryptography import x509
from cryptography.x509.oid import NameOID

from fakenet.listeners.ssl_utils import SSLWrapper


class SSLWrapperCertificateTests(unittest.TestCase):
    def setUp(self):
        self.wrapper = SSLWrapper.__new__(SSLWrapper)
        self.wrapper.logger = logging.getLogger('SSLWrapperCertificateTests')

    def test_generates_root_crl_and_sni_leaf_with_cryptography(self):
        with tempfile.TemporaryDirectory() as cert_dir:
            self.wrapper.config = {
                'cert_dir': cert_dir,
                'static_ca': 'yes',
            }
            root_cert, root_key, root_crl = self.wrapper.create_cert(
                'fakenet.flare', cert_dir=cert_dir)
            self.assertTrue(root_cert and root_key and root_crl)

            with open(root_cert, 'rb') as cert_input:
                root = x509.load_pem_x509_certificate(cert_input.read())
            self.assertTrue(
                root.extensions.get_extension_for_class(
                    x509.BasicConstraints).value.ca)
            with open(root_crl, 'rb') as crl_input:
                crl = x509.load_der_x509_crl(crl_input.read())
            self.assertEqual(root.subject, crl.issuer)

            leaf_cert, leaf_key, _ = self.wrapper.create_cert(
                'api.deepseek.com', root_cert, root_key, cert_dir)
            self.assertTrue(leaf_cert and leaf_key)
            with open(leaf_cert, 'rb') as cert_input:
                leaf = x509.load_pem_x509_certificate(cert_input.read())
            self.assertEqual(root.subject, leaf.issuer)
            self.assertEqual(
                'api.deepseek.com',
                leaf.subject.get_attributes_for_oid(
                    NameOID.COMMON_NAME)[0].value)
            self.assertEqual(
                ['api.deepseek.com'],
                leaf.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value.get_values_for_type(
                        x509.DNSName))


if __name__ == '__main__':
    unittest.main()
