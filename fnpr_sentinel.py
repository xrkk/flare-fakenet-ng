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
                      role=role, nonce=nonce, bytes=len(data))
        except Exception as exc:
            log_event(self.server.logger, 'probe_rejected', peer=peer,
                      reason=type(exc).__name__, detail=str(exc)[:160],
                      bytes=len(data))


class FnprServer(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64


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
    try:
        server = FnprServer((BIND_IPV4, LISTEN_PORT), FnprRequestHandler)
    except OSError as exc:
        log_event(logger, 'start_failed', bind=BIND_IPV4, port=LISTEN_PORT,
                  reason=type(exc).__name__, detail=str(exc)[:160])
        return 1
    server.logger = logger
    log_event(logger, 'ready', bind=BIND_IPV4, port=LISTEN_PORT,
              protocol='FNPR/1', max_request_bytes=MAX_REQUEST_BYTES)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        log_event(logger, 'stop_requested', reason='KeyboardInterrupt')
    finally:
        server.server_close()
        log_event(logger, 'stopped')
    return 0


if __name__ == '__main__':
    sys.exit(main())
