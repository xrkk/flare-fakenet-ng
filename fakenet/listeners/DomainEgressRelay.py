# Copyright 2026 Google LLC

"""Local transparent TLS relay for reviewed DomainAllowList mode."""

from collections import Counter, defaultdict, deque
import logging
import select
import socket
import threading
import time

from fakenet.diverters.egresspolicy import normalize_hostname


class ClientHelloError(ValueError):
    pass


def _take(data, offset, count):
    end = offset + count
    if end > len(data):
        raise ClientHelloError('truncated ClientHello')
    return data[offset:end], end


def parse_client_hello(data):
    """Return ("need_more", None), ("ok", sni), or raise.

    TLS handshake bytes may span records. Bytes following the ClientHello are
    intentionally ignored by the parser and retained by the relay for exact
    forwarding.
    """
    offset = 0
    handshake = bytearray()
    required = None
    while True:
        if required is not None and len(handshake) >= required:
            return 'ok', _parse_client_hello_body(bytes(handshake[4:required]))
        if len(data) - offset < 5:
            return 'need_more', None
        content_type = data[offset]
        major = data[offset + 1]
        record_length = int.from_bytes(data[offset + 3:offset + 5], 'big')
        if content_type != 22 or major != 3:
            raise ClientHelloError('not a TLS handshake record')
        if record_length > 18432:
            raise ClientHelloError('TLS record exceeds protocol limit')
        if len(data) - offset - 5 < record_length:
            return 'need_more', None
        payload = data[offset + 5:offset + 5 + record_length]
        handshake.extend(payload)
        offset += 5 + record_length
        if len(handshake) >= 4 and required is None:
            if handshake[0] != 1:
                raise ClientHelloError('first handshake message is not ClientHello')
            required = 4 + int.from_bytes(handshake[1:4], 'big')
            if required > 65536:
                raise ClientHelloError('ClientHello exceeds reviewed limit')


def _parse_client_hello_body(body):
    offset = 0
    _, offset = _take(body, offset, 2 + 32)
    session_length = body[offset] if offset < len(body) else None
    if session_length is None:
        raise ClientHelloError('missing session id')
    offset += 1
    _, offset = _take(body, offset, session_length)
    cipher_len_raw, offset = _take(body, offset, 2)
    cipher_len = int.from_bytes(cipher_len_raw, 'big')
    if cipher_len < 2 or cipher_len % 2:
        raise ClientHelloError('invalid cipher suite vector')
    _, offset = _take(body, offset, cipher_len)
    compression_len_raw, offset = _take(body, offset, 1)
    compression_len = compression_len_raw[0]
    _, offset = _take(body, offset, compression_len)
    extensions_len_raw, offset = _take(body, offset, 2)
    extensions_len = int.from_bytes(extensions_len_raw, 'big')
    extensions, offset = _take(body, offset, extensions_len)
    if offset != len(body):
        raise ClientHelloError('trailing ClientHello bytes')

    names = []
    ext_offset = 0
    while ext_offset < len(extensions):
        header, ext_offset = _take(extensions, ext_offset, 4)
        ext_type = int.from_bytes(header[:2], 'big')
        ext_len = int.from_bytes(header[2:], 'big')
        ext_data, ext_offset = _take(extensions, ext_offset, ext_len)
        if ext_type in (0xfe0d, 0xffce):
            raise ClientHelloError('ECH extension is not allowed')
        if ext_type == 0:
            if len(ext_data) < 2 or int.from_bytes(ext_data[:2], 'big') != len(ext_data) - 2:
                raise ClientHelloError('invalid server_name extension')
            name_offset = 2
            while name_offset < len(ext_data):
                name_type = ext_data[name_offset]
                name_offset += 1
                length_raw, name_offset = _take(ext_data, name_offset, 2)
                name_len = int.from_bytes(length_raw, 'big')
                name_raw, name_offset = _take(ext_data, name_offset, name_len)
                if name_type == 0:
                    try:
                        names.append(normalize_hostname(name_raw.decode('ascii')))
                    except (UnicodeDecodeError, ValueError) as exc:
                        raise ClientHelloError('invalid SNI hostname') from exc
    if len(names) != 1:
        raise ClientHelloError('exactly one cleartext SNI hostname is required')
    return names[0]


class DomainEgressRelay(object):
    def __init__(self, config=None, name='DomainEgressRelay',
                 logging_level=logging.INFO):
        self.config = config or {}
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)
        self.name = name
        self.port = int(self.config.get('port', 38927))
        self.callbacks = None
        self._listener = None
        self._accept_thread = None
        self._stop = threading.Event()
        self._quota_lock = threading.Lock()
        self._pending = 0
        self._pending_by_source = Counter()
        self._active = 0
        self._active_by_source = Counter()
        self._new_flow_rate = defaultdict(deque)
        self._connections_lock = threading.Lock()
        self._connections = set()
        self._workers_lock = threading.Lock()
        self._workers = set()

    def taste(self, data, dport):
        return 0

    def configure_dependencies(self, listeners, diverter,
                               diverterListenerCallbacks):
        self.callbacks = diverterListenerCallbacks

    def acceptDiverterListenerCallbacks(self, callbacks):
        self.callbacks = callbacks

    def start(self):
        if not self.callbacks or not self.callbacks.egressPolicyEnabled():
            raise RuntimeError('DomainEgressRelay requires DomainAllowList callbacks')
        settings = self.callbacks.getEgressSettings()
        if self.port != settings['relay_port']:
            raise RuntimeError('DomainEgressRelay port does not match policy')
        self._settings = settings
        self._stop.clear()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('0.0.0.0', self.port))
            listener.listen(settings['max_pending'])
            listener.settimeout(1)
        except Exception:
            listener.close()
            raise
        self._listener = listener
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name='DomainEgressRelayAccept',
            daemon=True)
        self._accept_thread.start()

    def stop(self):
        self._stop.set()
        if self._listener:
            try:
                self._listener.close()
            except OSError:
                pass
        with self._connections_lock:
            for connection in list(self._connections):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    connection.close()
                except OSError:
                    pass
        if self._accept_thread:
            self._accept_thread.join(5)
        with self._workers_lock:
            workers = list(self._workers)
        deadline = time.monotonic() + 5
        for worker in workers:
            worker.join(max(0, deadline - time.monotonic()))

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                client, address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                self.logger.exception('TLS relay accept failed')
                continue
            if self._stop.is_set():
                client.close()
                return
            source = address[0]
            mapping = None
            if (self.callbacks.isLocalAddress(source) and
                    self._allow_new_flow_rate(source)):
                mapping = self.callbacks.consumeRelayTarget(source, address[1])
            if mapping is None or not self._acquire_pending(source):
                if mapping is not None:
                    self.callbacks.closeRelayMapping(mapping.generation)
                client.close()
                self.callbacks.logEgressEvent(
                    'TLS_SNI_DENY', reason='mapping_or_pending_quota',
                    source=source)
                continue
            worker = threading.Thread(
                target=self._handle_client,
                args=(client, address, mapping),
                name='DomainEgressRelay-%s' % mapping.generation,
                daemon=True)
            with self._workers_lock:
                self._workers.add(worker)
            worker.start()

    def _allow_new_flow_rate(self, source):
        now = time.monotonic()
        with self._quota_lock:
            samples = self._new_flow_rate[source]
            while samples and now - samples[0] >= 10:
                samples.popleft()
            if len(samples) >= 64:
                return False
            samples.append(now)
            if len(self._new_flow_rate) > 1024:
                self._new_flow_rate = defaultdict(
                    deque,
                    ((key, value) for key, value in self._new_flow_rate.items()
                     if value and now - value[-1] < 60))
            return True

    def _acquire_pending(self, source):
        with self._quota_lock:
            if (self._pending >= self._settings['max_pending'] or
                    self._pending_by_source[source] >=
                    self._settings['max_pending_per_source']):
                return False
            self._pending += 1
            self._pending_by_source[source] += 1
            return True

    def _promote_active(self, source):
        with self._quota_lock:
            if (self._active >= self._settings['max_active'] or
                    self._active_by_source[source] >=
                    self._settings['max_active_per_source']):
                self._release_pending_locked(source)
                return False
            self._release_pending_locked(source)
            self._active += 1
            self._active_by_source[source] += 1
            return True

    def _release_pending_locked(self, source):
        if self._pending_by_source[source]:
            self._pending -= 1
            self._pending_by_source[source] -= 1
            if not self._pending_by_source[source]:
                del self._pending_by_source[source]

    def _release_pending(self, source):
        with self._quota_lock:
            self._release_pending_locked(source)

    def _release_active(self, source):
        with self._quota_lock:
            if self._active_by_source[source]:
                self._active -= 1
                self._active_by_source[source] -= 1
                if not self._active_by_source[source]:
                    del self._active_by_source[source]

    def _handle_client(self, client, address, mapping):
        source = address[0]
        upstream = None
        token = None
        pending = True
        active = False
        with self._connections_lock:
            self._connections.add(client)
        try:
            if self._stop.is_set():
                raise RuntimeError('relay is stopping')
            client.settimeout(self._settings['hello_timeout'])
            buffered, sni = self._read_client_hello(client)
            if sni != mapping.domain:
                raise ClientHelloError('SNI does not match mapped domain')
            if self._stop.is_set():
                raise RuntimeError('relay is stopping')
            if not self._promote_active(source):
                pending = False
                raise RuntimeError('active relay quota exceeded')
            pending = False
            active = True

            source_ip = self.callbacks.selectSourceIPv4(
                mapping.server_ip, mapping.server_port)
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with self._connections_lock:
                self._connections.add(upstream)
            upstream.settimeout(self._settings['hello_timeout'])
            upstream.bind((source_ip, 0))
            if self._stop.is_set():
                raise RuntimeError('relay is stopping')
            source_port = upstream.getsockname()[1]
            token = self.callbacks.registerControlFlow(
                'tls_relay', 'TCP', source_ip, source_port,
                mapping.server_ip, mapping.server_port,
                domain=mapping.domain,
                ttl=self._settings['idle_timeout'] + 30,
                generation=mapping.generation)
            upstream.connect((mapping.server_ip, mapping.server_port))
            if not self.callbacks.activateRelayMapping(mapping.generation):
                raise RuntimeError('relay NAT mapping expired before activation')
            self.callbacks.logEgressEvent(
                'TLS_SNI_ALLOW', domain=mapping.domain,
                original_ip=mapping.server_ip, sni=sni)
            self.callbacks.logEgressEvent(
                'ALLOW_INTERNAL_UPSTREAM', kind='tls_relay',
                ip=mapping.server_ip, port=mapping.server_port,
                sport=source_port)
            self._relay(client, upstream, buffered)
        except Exception as exc:
            self.callbacks.logEgressEvent(
                'TLS_SNI_DENY', domain=mapping.domain,
                reason=type(exc).__name__)
            self.logger.debug('TLS relay denied/closed: %s', exc)
        finally:
            if pending:
                self._release_pending(source)
            if active:
                self._release_active(source)
            if token:
                self.callbacks.revokeControlFlow(token)
            self.callbacks.closeRelayMapping(mapping.generation)
            for connection in (client, upstream):
                if connection:
                    with self._connections_lock:
                        self._connections.discard(connection)
                    try:
                        connection.close()
                    except OSError:
                        pass
            with self._workers_lock:
                self._workers.discard(threading.current_thread())

    def _read_client_hello(self, client):
        deadline = time.monotonic() + self._settings['hello_timeout']
        data = bytearray()
        while len(data) < self._settings['hello_max_bytes']:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ClientHelloError('ClientHello timeout')
            client.settimeout(remaining)
            chunk = client.recv(min(16384,
                                    self._settings['hello_max_bytes'] - len(data)))
            if not chunk:
                raise ClientHelloError('EOF before ClientHello')
            data.extend(chunk)
            status, sni = parse_client_hello(bytes(data))
            if status == 'ok':
                return bytes(data), sni
        raise ClientHelloError('ClientHello size limit exceeded')

    def _relay(self, client, upstream, initial_to_upstream):
        client.setblocking(False)
        upstream.setblocking(False)
        to_upstream = bytearray(initial_to_upstream)
        to_client = bytearray()
        client_open = True
        upstream_open = True
        last_activity = time.monotonic()
        limit = self._settings['buffer_bytes']
        idle = self._settings['idle_timeout']
        while not self._stop.is_set():
            if time.monotonic() - last_activity >= idle:
                return
            reads = []
            writes = []
            if client_open and len(to_upstream) < limit:
                reads.append(client)
            if upstream_open and len(to_client) < limit:
                reads.append(upstream)
            if to_upstream:
                writes.append(upstream)
            if to_client:
                writes.append(client)
            if not reads and not writes:
                return
            readable, writable, _ = select.select(reads, writes, [], 1)
            for sock in readable:
                destination = to_upstream if sock is client else to_client
                chunk = sock.recv(min(65536, limit - len(destination)))
                if chunk:
                    last_activity = time.monotonic()
                    destination.extend(chunk)
                elif sock is client:
                    client_open = False
                    try:
                        upstream.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                else:
                    upstream_open = False
                    try:
                        client.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
            for sock in writable:
                buffer = to_upstream if sock is upstream else to_client
                sent = sock.send(buffer)
                if sent:
                    del buffer[:sent]
                    last_activity = time.monotonic()
