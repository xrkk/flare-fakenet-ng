#!/usr/bin/env python3
"""Bounded FNPR/1 acceptance sentinel for the reviewed host-only adapter."""

import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import re
import socket
import socketserver
import sys
import threading
import time


BIND_IPV4 = '192.168.204.1'
LISTEN_PORT = 443
MAX_REQUEST_BYTES = 512
SOCKET_TIMEOUT_SECONDS = 5
NONCE_PATTERN = re.compile(r'^[A-Za-z0-9_.:-]{1,192}$')
ALLOWED_ROLES = frozenset(('preflight', 'target', 'non-target'))


def parse_request(data):
    """Return ``(nonce, role)`` for one exact, bounded FNPR/1 line."""
    if not isinstance(data, bytes):
        raise ValueError('request must be bytes')
    if not data.endswith(b'\n') or len(data) > MAX_REQUEST_BYTES:
        raise ValueError('request must be one bounded newline-terminated line')
    if b'\r' in data or data.count(b'\n') != 1:
        raise ValueError('request contains unsupported line framing')
    try:
        text = data[:-1].decode('ascii')
    except UnicodeDecodeError as exc:
        raise ValueError('request must be ASCII') from exc
    fields = text.split('|')
    if len(fields) != 3 or fields[0] != 'FNPR/1':
        raise ValueError('request protocol mismatch')
    nonce, role = fields[1], fields[2]
    if not NONCE_PATTERN.fullmatch(nonce):
        raise ValueError('nonce contains unsupported characters')
    if role not in ALLOWED_ROLES:
        raise ValueError('request role is not allowed')
    return nonce, role


def build_response(nonce):
    if not NONCE_PATTERN.fullmatch(nonce):
        raise ValueError('response nonce is invalid')
    return ('FNPR/1|%s|OK\n' % nonce).encode('ascii')


def log_event(logger, event, **fields):
    row = {'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
           'event': event}
    row.update(fields)
    logger.info(json.dumps(row, sort_keys=True, separators=(',', ':')))


class FnprRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        peer = '%s:%s' % self.client_address
        self.request.settimeout(SOCKET_TIMEOUT_SECONDS)
        data = bytearray()
        try:
            while len(data) < MAX_REQUEST_BYTES:
                chunk = self.request.recv(min(128, MAX_REQUEST_BYTES - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if b'\n' in chunk:
                    break
            nonce, role = parse_request(bytes(data))
            self.request.sendall(build_response(nonce))
            log_event(self.server.logger, 'probe_ok', peer=peer,
                      role=role, nonce=nonce, bytes=len(data),
                      transport='tcp')
        except Exception as exc:
            log_event(self.server.logger, 'probe_rejected', peer=peer,
                      reason=type(exc).__name__, detail=str(exc)[:160],
                      bytes=len(data), transport='tcp')


class FnprUdpRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, response_socket = self.request
        peer = '%s:%s' % self.client_address
        try:
            nonce, role = parse_request(data)
            response_socket.sendto(build_response(nonce), self.client_address)
            log_event(self.server.logger, 'probe_ok', peer=peer,
                      role=role, nonce=nonce, bytes=len(data),
                      transport='udp')
        except Exception as exc:
            log_event(self.server.logger, 'probe_rejected', peer=peer,
                      reason=type(exc).__name__, detail=str(exc)[:160],
                      bytes=len(data), transport='udp')


class FnprTcpServer(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64


class FnprUdpServer(socketserver.ThreadingUDPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def configure_logger(path):
    logger = logging.getLogger('fnpr-sentinel')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    formatter = logging.Formatter('%(message)s')
    file_handler = RotatingFileHandler(
        path, maxBytes=5 * 1024 * 1024, backupCount=4, encoding='utf-8')
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.handlers[:] = [file_handler, stream_handler]
    return logger


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--log', required=True)
    args = parser.parse_args(argv)
    logger = configure_logger(args.log)
    tcp_server = None
    udp_server = None
    try:
        tcp_server = FnprTcpServer(
            (BIND_IPV4, LISTEN_PORT), FnprRequestHandler)
        udp_server = FnprUdpServer(
            (BIND_IPV4, LISTEN_PORT), FnprUdpRequestHandler)
    except OSError as exc:
        if tcp_server is not None:
            tcp_server.server_close()
        log_event(logger, 'start_failed', bind=BIND_IPV4, port=LISTEN_PORT,
                  reason=type(exc).__name__, detail=str(exc)[:160])
        return 1
    tcp_server.logger = logger
    udp_server.logger = logger
    log_event(logger, 'ready', bind=BIND_IPV4, port=LISTEN_PORT,
              protocol='FNPR/1', transports='tcp,udp',
              max_request_bytes=MAX_REQUEST_BYTES)
    servers = (tcp_server, udp_server)
    threads = []
    for transport, server in zip(('tcp', 'udp'), servers):
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={'poll_interval': 0.25},
            name='fnpr-%s' % transport)
        thread.daemon = True
        thread.start()
        threads.append(thread)
    failed = False
    try:
        while all(thread.is_alive() for thread in threads):
            time.sleep(0.25)
        failed = True
        log_event(logger, 'server_thread_stopped_unexpectedly')
    except KeyboardInterrupt:
        log_event(logger, 'stop_requested', reason='KeyboardInterrupt')
    finally:
        for server in servers:
            server.shutdown()
        for thread in threads:
            thread.join(SOCKET_TIMEOUT_SECONDS)
        for server in servers:
            server.server_close()
        log_event(logger, 'stopped')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
