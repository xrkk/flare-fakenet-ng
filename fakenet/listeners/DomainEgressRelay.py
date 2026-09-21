# Copyright 2026 Google LLC

"""Local transparent TLS relay for reviewed EgressControl mode."""

from collections import Counter, defaultdict, deque
import json
import logging
import os
import select
import socket
import struct
import threading
import time
from pathlib import Path

from fakenet.diverters.egresspolicy import normalize_hostname


class ClientHelloError(ValueError):
    pass


_LINGER_ABORT = struct.pack('ii', 1, 0)


def _abortive_close(connection):
    """Close one socket so the kernel emits RST while a rewrite can translate.

    A graceful shutdown leaves the peer TCB free to retransmit unacknowledged
    data after the diverter filter closes (candidate10 sst-004: the probe's
    141-byte request retransmitted onto the physical NIC 108ms after Job
    termination because the relay socket abort happened after the WinDivert
    handle was gone).  SO_LINGER(1, 0) makes close() abortive; callers must
    invoke it only while the diverter mapping still holds its teardown grace.
    """
    setsockopt = getattr(connection, 'setsockopt', None)
    if setsockopt is not None:
        try:
            setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _LINGER_ABORT)
        except OSError:
            pass
    try:
        connection.close()
    except OSError:
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
        self._quiesce = threading.Event()
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
            raise RuntimeError('DomainEgressRelay requires EgressControl callbacks')
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

    def health_snapshot(self):
        from fakenet.listeners.ListenerBase import health_snapshot
        return health_snapshot(self._listener, self._accept_thread)

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

    def quiesce(self, reason='unspecified'):
        """Fail-safe teardown of relayed client flows after a failed stop.

        Called from the managed child when the orderly stop sequence failed
        (e.g. an injected cleanup fault): the child stays alive until the
        supervisor terminates its Job, and at that point kernel handle
        cleanup aborts these sockets when the diverter filter can no longer
        translate the abort RST.  Aborting here, while the mapping rewrite
        is still in place, closes the client TCBs first so no original-tuple
        retransmission can later bypass redirection.  New arrivals are
        aborted the same way; the relay otherwise keeps serving its socket
        so the supervisor's diagnostics and termination flow are unchanged.
        """
        self._quiesce.set()
        with self._connections_lock:
            connections = list(self._connections)
        for connection in connections:
            _abortive_close(connection)
        if self.callbacks is not None:
            self.callbacks.logEgressEvent(
                'RELAY_QUIESCE', reason=reason, aborted_connections=len(connections))

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
            if self._quiesce.is_set():
                # A stop that failed must not leave a fresh redirected TCB
                # alive past the supervisor's Job termination: abort the
                # accepted socket (kernel RST, translated by the mapping's
                # teardown grace) and retire the mapping the diverter
                # created for this SYN.
                source, sport = address[0], address[1]
                mapping = None
                if (self.callbacks.isLocalAddress(source) and
                        self._allow_new_flow_rate(source)):
                    mapping = self.callbacks.consumeRelayTarget(source, sport)
                _abortive_close(client)
                deny_fields = {
                    'reason': 'relay_quiesced', 'reason_code': 'relay_quiesced',
                    'source': source, 'src': source, 'sport': sport}
                if mapping is not None:
                    deny_fields.update(generation=mapping.generation,
                                       original_ip=mapping.server_ip,
                                       original_port=mapping.server_port)
                    self.callbacks.closeRelayMapping(mapping.generation)
                self.callbacks.logEgressEvent('RELAY_QUIESCE_RST', **deny_fields)
                continue
            source = address[0]
            mapping = None
            if (self.callbacks.isLocalAddress(source) and
                    self._allow_new_flow_rate(source)):
                mapping = self.callbacks.consumeRelayTarget(source, address[1])
            if mapping is None or not self._acquire_pending(source):
                if mapping is not None:
                    self.callbacks.closeRelayMapping(mapping.generation)
                client.close()
                # Bind the rejection to the client identity actually seen;
                # target fields appear only when a mapping was really held
                # (a quota rejection after consumeRelayTarget) and are never
                # fabricated for a mapping-less arrival.
                deny_fields = {
                    'reason': 'mapping_or_pending_quota',
                    'reason_code': 'mapping_or_pending_quota',
                    'source': source, 'src': source, 'sport': address[1]}
                if mapping is not None:
                    deny_fields.update(generation=mapping.generation,
                                       original_ip=mapping.server_ip,
                                       original_port=mapping.server_port)
                self.callbacks.logEgressEvent('TLS_SNI_DENY', **deny_fields)
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

    @staticmethod
    def _deny_reason_code(exc, hello_sni):
        """Stable deny category for structured log binding.

        The legacy ``reason`` field keeps the exception class.  ``sni_mismatch``
        requires a successfully parsed ClientHello whose SNI differed from the
        mapped domain; parse/read failures stay ``clienthello_error`` and can
        never carry a fabricated ``sni``.  Everything else is one stable
        ``relay_error`` bucket — no arbitrary exception text is structured.
        """
        if not isinstance(exc, ClientHelloError):
            return 'relay_error'
        return 'sni_mismatch' if hello_sni is not None else 'clienthello_error'

    def _record_native_terminal(self, outcome, reason_code, mapping, source,
                                sport, sni):
        """Append one native-clocked connection-terminal record.

        The acceptance adjudication compares this instant with kernel trace
        events natively (no guest wall-timer uncertainty) and uses the
        abortive client close it accompanies as the deny delivery proof.
        Diagnostic only: a failed record never disturbs the connection path.
        """
        try:
            if not (Path.cwd() / 'creation.jsonl').exists():
                return  # not a managed run directory
            from fakenet.mcp.native_clock import native_clock_sample
            record = {
                'schema': 'fakenetng.relay-native-terminal.v1',
                'pid': os.getpid(),
                'outcome': outcome,
                'reason_code': reason_code,
                'src': source, 'sport': sport,
                'domain': mapping.domain,
                'original_ip': mapping.server_ip,
                'original_port': mapping.server_port,
                'generation': mapping.generation,
                'sni': sni,
                'clock': native_clock_sample(),
            }
            path = Path.cwd() / 'relay-native-events.jsonl'
            with path.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(record, ensure_ascii=False) + '\n')
        except Exception:
            self.logger.debug('relay native terminal record failed',
                              exc_info=True)

    def _handle_client(self, client, address, mapping):
        source = address[0]
        upstream = None
        token = None
        pending = True
        active = False
        hello_sni = None
        deny_reason_code = None
        with self._connections_lock:
            self._connections.add(client)
        try:
            if self._stop.is_set():
                raise RuntimeError('relay is stopping')
            client.settimeout(self._settings['hello_timeout'])
            buffered, sni = self._read_client_hello(client)
            hello_sni = sni
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
            # stop() deliberately closes every active socket.  A worker can
            # observe that close between select() and recv()/send(); it is an
            # expected shutdown path, not a failed SNI decision.  The same
            # holds for quiesce(): the abortive close is the product's own
            # teardown decision, not a deny verdict on this client.
            if not self._stop.is_set() and not self._quiesce.is_set():
                reason_code = self._deny_reason_code(exc, hello_sni)
                deny_reason_code = reason_code
                deny_fields = {
                    'domain': mapping.domain, 'reason': type(exc).__name__,
                    'reason_code': reason_code, 'src': source,
                    'sport': address[1], 'generation': mapping.generation,
                    'original_ip': mapping.server_ip,
                    'original_port': mapping.server_port}
                if reason_code == 'sni_mismatch':
                    deny_fields['sni'] = hello_sni
                self.callbacks.logEgressEvent(
                    'TLS_SNI_DENY', **deny_fields)
                self.logger.debug('TLS relay denied/closed: %s', exc)
        finally:
            if pending:
                self._release_pending(source)
            if active:
                self._release_active(source)
            if token:
                self.callbacks.revokeControlFlow(token)
            # Close both sockets before revoking the diverter mapping: the
            # client's FIN/RST must be emitted while the packet rewrite is
            # still in place, and close_relay_mapping() additionally retains
            # the rewrite for a short teardown grace so the client's final
            # ACK exchange stays translated. Revoking first leaves the peer
            # TCB half-open until its read timeout.
            infrastructure_failure = deny_reason_code == 'relay_error'
            if (infrastructure_failure and not self._stop.is_set()
                    and not self._quiesce.is_set()):
                # An upstream/infrastructure failure is not a policy deny:
                # resetting the client turns it into one and ends the
                # session within milliseconds (candidate17 sst-002: upstream
                # ConnectionResetError 7ms after the injected handle close
                # bounded the session inside the action's own conservative
                # margin pair).  Hold the client socket for one bounded
                # hello timeout so the session ends by its own lifecycle;
                # policy denies below still reset immediately.
                try:
                    time.sleep(self._settings.get('hello_timeout', 5))
                except Exception:  # noqa: BLE001 - teardown must continue
                    pass
            for connection in (client, upstream):
                if connection:
                    with self._connections_lock:
                        self._connections.discard(connection)
                    if connection is client and deny_reason_code and not infrastructure_failure:
                        # A denied client must receive its reset while the
                        # mapping rewrite still translates it: the graceful
                        # FIN leaves the client TCB half-open until its own
                        # retransmission timeout (candidate10 sst-004 case-2:
                        # RexmitCount 1..5 then a bare RST on the original
                        # tuple after the filter closed).
                        _abortive_close(connection)
                        continue
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except (OSError, AttributeError):
                        pass
                    try:
                        connection.close()
                    except OSError:
                        pass
            self._record_native_terminal(
                'deny' if deny_reason_code else 'closed',
                deny_reason_code or 'session_closed', mapping,
                source, address[1], hello_sni)
            self.callbacks.closeRelayMapping(mapping.generation)
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
