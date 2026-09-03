# Copyright 2026 Google LLC

import os
import traceback
import subprocess
import logging
import shutil
import sys
import ssl
import datetime
from pathlib import Path
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from fakenet import listeners
from fakenet.listeners import ListenerBase

class SSLWrapper(object):
    NOT_AFTER_DELTA_SECONDS = 300  * 24 * 60 * 60
    CN="fakenet.flare"

    def __init__(self, config):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = config
        self.ca_cert = None
        self.ca_key = None
        self.ca_crl = None
        self.ca_cn = self.CN

        cert_dir = self.abs_config_path(self.config.get('cert_dir', None))
        if cert_dir is None:
            raise RuntimeError("cert_dir key is not specified in config")

        if not os.path.isdir(cert_dir):
            os.makedirs(cert_dir)

        # generate and add root CA, which is used to sign for other certs:
        if self.config.get('static_ca').lower() == 'yes':
            self.ca_cert = self.abs_config_path(self.config.get('ca_cert', None))
            self.ca_key = self.abs_config_path(self.config.get('ca_key', None))
            self.ca_cn = self._load_cert(self.ca_cert).get_subject().CN
        else:
            self.ca_cert, self.ca_key, self.ca_crl = self.create_cert(self.CN)
        if ( not self.config.get('networkmode', None) == 'multihost' and
             not self.config.get('static_ca').lower() == 'yes'):
            self.logger.debug('adding root cert: %s', self.ca_cert)
            self._add_root_ca(self.ca_cert, self.ca_crl)

    def wrap_socket(self, s):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            ctx.options |= ssl.OP_NO_TLSv1
            ctx.options |= ssl.OP_NO_TLSv1_1
        except AttributeError as e:
            self.logger.error('Exception calling ssl.SSLContext: %s', str(e))
        else:
            ctx.sni_callback = self.sni_callback
            ctx.load_cert_chain(certfile=self.ca_cert, keyfile=self.ca_key)
            # Register accepted TLS transports with the HTTP server before
            # the handshake begins so graceful stop can interrupt a stalled
            # client without changing normal TLS negotiation semantics.
            return ctx.wrap_socket(
                s, server_side=True, do_handshake_on_connect=False)

    def create_cert(self, cn, ca_cert=None, ca_key=None, cert_dir=None):
        """
        Create a cert given the common name, a signing CA, CA private key and
        the directory output.

        return: tuple(None, None) on error
                tuple(cert_file_path, key_file_path) on success
        """

        f_selfsign = ca_cert is None or ca_key is None
        if not cert_dir:
            cert_dir = self.abs_config_path(self.config.get('cert_dir'))
        else:
            cert_dir = os.path.abspath(cert_dir)

        cert_file = os.path.join(cert_dir, "%s.crt" % (cn))
        key_file = os.path.join(cert_dir, "%s.key" % (cn))
        crl_file = os.path.join(cert_dir, "ca.crl")
        if os.path.exists(cert_file) and os.path.exists(key_file) and os.path.exists(crl_file):
            webroot = self.config.get("webroot")
            if webroot and os.path.exists(webroot):
                web_crl_path = os.path.join(webroot, "ca.crl")
                if not os.path.exists(web_crl_path):
                    shutil.copyfile(crl_file, web_crl_path)
            return cert_file, key_file, crl_file

        try:
            key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048)
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
            ])
            if f_selfsign:
                issuer = subject
                signing_key = key
            else:
                with open(ca_cert, 'rb') as ca_cert_input:
                    ca_cert_data = x509.load_pem_x509_certificate(
                        ca_cert_input.read())
                with open(ca_key, 'rb') as ca_key_input:
                    signing_key = serialization.load_pem_private_key(
                        ca_key_input.read(), password=None)
                issuer = ca_cert_data.subject

            now = datetime.datetime.now(datetime.timezone.utc)
            builder = (x509.CertificateBuilder()
                       .subject_name(subject)
                       .issuer_name(issuer)
                       .public_key(key.public_key())
                       .serial_number(x509.random_serial_number())
                       .not_valid_before(now - datetime.timedelta(minutes=1))
                       .not_valid_after(
                           now + datetime.timedelta(
                               seconds=self.NOT_AFTER_DELTA_SECONDS)))
            builder = builder.add_extension(
                x509.BasicConstraints(ca=f_selfsign, path_length=None),
                critical=True)
            if f_selfsign:
                builder = builder.add_extension(
                    x509.KeyUsage(
                        digital_signature=False,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False),
                    critical=True)
            else:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(cn)]),
                    critical=False)
            builder = builder.add_extension(
                x509.CRLDistributionPoints([
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(
                            'http://fakenet.mandiant.com/ca.crl')],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None)
                ]),
                critical=False)
            cert = builder.sign(private_key=signing_key,
                                algorithm=hashes.SHA256())
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption())

            if f_selfsign:
                crl = (x509.CertificateRevocationListBuilder()
                       .issuer_name(cert.subject)
                       .last_update(now)
                       .next_update(now + datetime.timedelta(days=30))
                       .sign(private_key=key, algorithm=hashes.SHA256()))
                crl_der = crl.public_bytes(serialization.Encoding.DER)
                with open(crl_file, "wb") as crl_file_output:
                    crl_file_output.write(crl_der)
                webroot = self.config.get("webroot")
                if webroot and os.path.exists(webroot):
                    with open(os.path.join(webroot, "ca.crl"), "wb") as web_crl:
                        web_crl.write(crl_der)

            with open(cert_file, "wb") as cert_file_input:
                cert_file_input.write(cert_pem)
            with open(key_file, "wb") as key_file_output:
                key_file_output.write(key_pem)
        except (IOError, OSError, ValueError, TypeError):
            traceback.print_exc()
            return None, None, None
        return cert_file, key_file, crl_file

    def sni_callback(self, sslsock, servername, sslctx):
        if servername is None:
            servername = self.CN
        newctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
        newctx.options |= ssl.OP_NO_TLSv1
        newctx.options |= ssl.OP_NO_TLSv1_1
        cert_file, key_file, _ = self.create_cert(servername, self.ca_cert, self.ca_key)
        if cert_file is None or key_file is None:
            return

        newctx.check_hostname = False
        newctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        sslsock.context = newctx
        return

    def _load_cert(self, certpath):
        ca_cert = None
        try:
            with open(certpath, 'rb') as cert_file_input:
                data = cert_file_input.read()
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        except crypto.Error as e:
            self.logger.error("Failed to load certficate: %s", str(e))
        return ca_cert

    def _load_private_key(self, keypath):
        try:
            with open(keypath, 'rb') as key_file_input:
                data = key_file_input.read()
            privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, data)
        except Exception:
            traceback.print_exc()
            privkey = None
        return privkey

    def _run_process(self, argv):
        rc = True
        if sys.platform.startswith('win'):
            try:
                self.logger.debug(f"Running cmd: {argv}")
                subprocess.check_call(argv, shell=True, stdout=None)
                rc = True
            except subprocess.CalledProcessError:
                self.logger.error('Failed to add root CA')
                rc = False
        return rc

    def _add_root_ca(self, ca_cert_file, ca_crl_file):
        argv = ['certutil', '-addstore', 'Root', ca_cert_file]
        installed_cert = self._run_process(argv)
        if not installed_cert:
            return False
        argv = ['certutil', '-addstore', 'CA', ca_crl_file]
        return self._run_process(argv)

    def _remove_root_ca(self, cn):
        argv = ['certutil', '-delstore', 'Root', cn]
        removed = self._run_process(argv)
        if not removed:
            return False
        argv = ['certutil', '-delstore', 'CA', cn]
        return self._run_process(argv)

    def __del__(self):
        # Historically this GC-time destructor removed the generated root CA
        # from the OS trust stores and rmtree'd cert_dir. In the in-process
        # model one process hosts MANY wrappers across runs, and a stale
        # wrapper's GC fires at arbitrary times — the rmtree raced a fresh
        # wrapper's makedirs/cert writes mid-startup (r40 gate round 23:
        # ENOENT on port 443). Cleanup must be lifecycle-owned, not GC-owned;
        # on-disk certs are tiny and overwritten per run.
        try:
            self.logger.debug('SSLWrapper collected; deferred cleanup '
                              'skipped (lifecycle-owned)')
        except Exception:  # noqa: BLE001 - destructor must never raise
            pass

    def abs_config_path(self, path):
        """
        Attempts to return the absolute path of a path from a configuration
        setting.
        """

        # Try absolute path first
        abspath = os.path.abspath(path)
        if os.path.exists(abspath):
            return abspath

        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            abspath = os.path.join(os.getcwd(), path)
        else:
            abspath = os.path.join(os.fspath(Path(__file__).parents[2]), path)

        return abspath
