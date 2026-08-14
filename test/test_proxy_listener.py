import logging
import socket
import ssl
import unittest
from unittest import mock

from fakenet.listeners import ProxyListener


class RawSocket(object):
    def __init__(self):
        self.setblocking_called = False

    def recv(self, count, flags=0):
        if flags == socket.MSG_PEEK:
            return b'\x16\x03\x03\x00\x01X'
        raise AssertionError('the detached raw socket must not be read')

    def setblocking(self, value):
        self.setblocking_called = True
        raise AssertionError('the detached raw socket must not be configured')


class WrappedSocket(object):
    def __init__(self):
        self.reads = [b'client hello', b'']
        self.blocking_values = []

    def recv(self, count):
        return self.reads.pop(0)

    def setblocking(self, value):
        self.blocking_values.append(value)


class SSLWrapper(object):
    def __init__(self, wrapped):
        self.wrapped = wrapped

    def wrap_socket(self, raw):
        return self.wrapped


class Callbacks(object):
    def __init__(self):
        self.mapping = None

    def mapProxySportToOrigSport(self, proto, original, proxy, encrypted):
        self.mapping = (proto, original, proxy, encrypted)


class ListenerClient(object):
    def __init__(self, *args, **kwargs):
        self.daemon = False

    def connect(self):
        return 51000

    def start(self):
        return None


class ProxySocketLifecycleTests(unittest.TestCase):
    def test_tls_wrapper_replaces_detached_raw_socket(self):
        raw = RawSocket()
        wrapped = WrappedSocket()
        callbacks = Callbacks()
        server = type('Server', (), {
            'logger': logging.getLogger('proxy-socket-test'),
            'sslwrapper': SSLWrapper(wrapped),
            'config': {},
            'listeners': [],
            'diverter': object(),
            'local_ip': '127.0.0.1',
            'diverterListenerCallbacks': callbacks,
        })()
        top_listener = type('Listener', (), {
            'name': 'RawTCPListener',
            'port': 1337,
        })()
        handler = ProxyListener.ThreadedTCPRequestHandler.__new__(
            ProxyListener.ThreadedTCPRequestHandler)
        handler.request = raw
        handler.server = server
        handler.client_address = ('192.0.2.10', 50000)

        with mock.patch.object(ProxyListener.ssl_detector,
                               'looks_like_ssl', return_value=True), \
                mock.patch.object(ProxyListener, 'get_top_listener',
                                  return_value=top_listener), \
                mock.patch.object(ProxyListener, 'ThreadedTCPClientSocket',
                                  ListenerClient), \
                mock.patch.object(ProxyListener.select, 'select',
                                  return_value=([wrapped], [], [])) as select_mock:
            handler.handle()

        self.assertFalse(raw.setblocking_called)
        self.assertEqual([0], wrapped.blocking_values)
        select_mock.assert_called_once_with([wrapped], [], [], .001)
        self.assertEqual(('TCP', 50000, 51000, 'Yes'), callbacks.mapping)


class FailingWrappedSocket(object):
    def recv(self, count):
        raise ssl.SSLError('ambient telemetry handshake failure')

    def setblocking(self, value):
        return None


class CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record.getMessage())


class ProxyTlsFailureTests(unittest.TestCase):
    def _build_handler(self, wrapped):
        logger = logging.getLogger('proxy-tls-fail-test')
        logger.handlers[:] = []
        capture = CaptureHandler()
        logger.addHandler(capture)
        logger.setLevel(logging.WARNING)
        server = type('Server', (), {
            'logger': logger,
            'sslwrapper': SSLWrapper(wrapped),
            'config': {},
            'listeners': [],
            'diverter': object(),
            'local_ip': '127.0.0.1',
            'diverterListenerCallbacks': Callbacks(),
        })()
        handler = ProxyListener.ThreadedTCPRequestHandler.__new__(
            ProxyListener.ThreadedTCPRequestHandler)
        handler.request = RawSocket()
        handler.server = server
        handler.client_address = ('192.0.2.10', 50000)
        return handler, capture

    def test_tls_proxy_recv_failure_returns_without_raising(self):
        handler, capture = self._build_handler(FailingWrappedSocket())

        with mock.patch.object(ProxyListener.ssl_detector,
                               'looks_like_ssl', return_value=True):
            handler.handle()  # must not raise

        self.assertTrue(
            any('TLS proxy' in message for message in capture.records),
            'expected a TLS proxy warning, got: %r' % capture.records)


if __name__ == '__main__':
    unittest.main()
