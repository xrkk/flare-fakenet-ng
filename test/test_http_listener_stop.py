import logging
import socket
import ssl
import threading
import time
from pathlib import Path

from fakenet.listeners.HTTPListener import (
    HTTPListener,
    ThreadedHTTPServer,
    ThreadedHTTPRequestHandler,
)


ROOT = Path(__file__).resolve().parents[1]
SSL_ROOT = ROOT / 'fakenet' / 'listeners' / 'ssl_utils'


class MatrixHandler(ThreadedHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    requests = []

    def log_message(self, *args):
        pass

    def _reply(self, body):
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        type(self).requests.append(('GET', self.path))
        self._reply(b'get-ok')

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        type(self).requests.append(('POST', body))
        self._reply(b'post-ok')


class ExplodingHandler(MatrixHandler):
    def do_GET(self):
        raise RuntimeError('request boom')


class RecordingHandler(logging.Handler):
    def __init__(self):
        super(RecordingHandler, self).__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


def _start_server(handler=MatrixHandler, tls=False, timeout=2):
    server = ThreadedHTTPServer(('127.0.0.1', 0), handler)
    server.config = {'timeout': str(timeout), 'version': 'test'}
    server.logger = logging.getLogger(
        'test.http.stop.%s.%s' % (handler.__name__, id(server)))
    server.logger.handlers = []
    server.logger.propagate = False
    server.logger.setLevel(logging.DEBUG)
    server.custom_responses = []
    server.diverterListenerCallbacks = None
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            str(SSL_ROOT / 'server.pem'), str(SSL_ROOT / 'privkey.pem'))
        server.socket = context.wrap_socket(
            server.socket, server_side=True, do_handshake_on_connect=False)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    listener = HTTPListener.__new__(HTTPListener)
    listener.logger = server.logger
    listener.server = server
    listener.server_thread = thread
    return listener, server, thread


def _connect(server):
    return socket.create_connection(server.server_address, timeout=2)


def _wait_active(server, timeout=1.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with server._transport_lock:
            if server._active_transport is not None:
                return True
        time.sleep(0.005)
    return False


def _stop_with_deadline(listener, thread, timeout=1.0):
    started = time.monotonic()
    listener.stop()
    assert time.monotonic() - started <= timeout
    assert not thread.is_alive()


def _request(server, payload, tls=False):
    raw = _connect(server)
    client = raw
    if tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        client = context.wrap_socket(raw, server_hostname='localhost')
    client.settimeout(2)
    try:
        client.sendall(payload)
        chunks = []
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b''.join(chunks)
    finally:
        client.close()


def test_stop_without_active_connection_is_bounded_and_idempotent():
    listener, unused_server, thread = _start_server()

    _stop_with_deadline(listener, thread)
    listener.stop()


def test_complete_get_post_and_serial_order_are_unchanged():
    MatrixHandler.requests = []
    listener, server, thread = _start_server()
    try:
        get_response = _request(
            server, b'GET /one HTTP/1.0\r\nHost: localhost\r\n\r\n')
        post_response = _request(
            server,
            b'POST /two HTTP/1.0\r\nHost: localhost\r\n'
            b'Content-Length: 4\r\n\r\ndata')
        assert b'200 OK' in get_response and get_response.endswith(b'get-ok')
        assert b'200 OK' in post_response and post_response.endswith(b'post-ok')
        assert MatrixHandler.requests == [('GET', '/one'), ('POST', b'data')]
        assert server.config['timeout'] == '2'
    finally:
        _stop_with_deadline(listener, thread)


def test_stop_interrupts_incomplete_header_without_error_or_thread_leak():
    listener, server, thread = _start_server(timeout=2)
    recorder = RecordingHandler()
    server.logger.addHandler(recorder)
    client = _connect(server)
    try:
        client.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\n')
        assert _wait_active(server)
        _stop_with_deadline(listener, thread)
    finally:
        client.close()
    assert not [record for record in recorder.records
                if record.levelno >= logging.ERROR]


def test_stop_interrupts_incomplete_post_body():
    listener, server, thread = _start_server(timeout=2)
    client = _connect(server)
    try:
        client.sendall(
            b'POST / HTTP/1.1\r\nHost: localhost\r\n'
            b'Content-Length: 20\r\n\r\nshort')
        assert _wait_active(server)
        _stop_with_deadline(listener, thread)
    finally:
        client.close()


def test_stop_interrupts_stalled_tls_handshake():
    listener, server, thread = _start_server(tls=True, timeout=2)
    client = _connect(server)
    try:
        assert _wait_active(server)
        _stop_with_deadline(listener, thread)
    finally:
        client.close()


def test_complete_tls_request_is_unchanged():
    listener, server, thread = _start_server(tls=True)
    try:
        response = _request(
            server, b'GET /tls HTTP/1.0\r\nHost: localhost\r\n\r\n',
            tls=True)
        assert b'200 OK' in response and response.endswith(b'get-ok')
    finally:
        _stop_with_deadline(listener, thread)


def test_peer_close_and_stop_accept_race_are_idempotent():
    listener, server, thread = _start_server(timeout=2)
    client = _connect(server)
    client.close()
    _stop_with_deadline(listener, thread)
    listener.stop()


def test_non_stop_handler_exception_remains_an_error():
    listener, server, thread = _start_server(handler=ExplodingHandler)
    recorder = RecordingHandler()
    server.logger.addHandler(recorder)
    try:
        _request(server, b'GET /boom HTTP/1.0\r\nHost: localhost\r\n\r\n')
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and not recorder.records:
            time.sleep(0.005)
        errors = [record for record in recorder.records
                  if record.levelno >= logging.ERROR]
        assert errors
        assert errors[-1].exc_info
    finally:
        _stop_with_deadline(listener, thread)
