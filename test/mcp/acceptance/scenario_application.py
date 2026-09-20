"""Pure wire-byte constructors and verifiers for default-bucket application cases.

Four real application flows against the taken-over default sink (198.51.100.77):
TCP echo on 1337, UDP echo on 1337, HTTP GET on TCP/80 and a DNS A query on
UDP/53.  Every verifier consumes the actual wire bytes recorded by the probe
(``request_b64``/``response_b64``); no self-reported parsed field or success
label from the probe side is trusted.  The request must byte-equal the frozen
construction for the nonce, so a cross-nonce or cross-case recording never
verifies.  ``FakeNet.html`` is the candidate-source file
``fakenet/defaultFiles/FakeNet.html``; its SHA-256 is the expected body
identity (dynamic headers such as Date are not part of the identity).
"""

from __future__ import annotations

import base64
import hashlib

MAX_RESPONSE_BYTES = 64 * 1024
EXCHANGE_BUDGET_SECONDS = 10
APPLICATION_KINDS = ('tcp-echo', 'udp-echo', 'http-tcp', 'dns-udp')
APPLICATION_PORTS = {'tcp-echo': 1337, 'udp-echo': 1337, 'http-tcp': 80, 'dns-udp': 53}
APPLICATION_PROTOCOLS = {'tcp-echo': 'tcp', 'udp-echo': 'udp', 'http-tcp': 'tcp', 'dns-udp': 'udp'}
DEFAULT_SINK = '198.51.100.77'
DNS_EXPECTED_IPV4 = '192.0.2.123'


class ApplicationError(ValueError):
    """Raised when recorded application bytes do not meet the frozen contract."""


def echo_payload(nonce: str, case_index: int) -> bytes:
    return ('SSTAPP-%s-case-%d' % (nonce, int(case_index))).encode('ascii')


def http_request(nonce: str) -> bytes:
    return ('GET /sst-%s.html HTTP/1.1\r\n'
            'Host: %s.invalid\r\n'
            'Connection: close\r\n'
            '\r\n' % (nonce, nonce)).encode('ascii')


def _dns_transaction_id(nonce: str, case_index: int) -> int:
    digest = hashlib.sha256(('dns-%s-case-%d' % (nonce, int(case_index))).encode('ascii')).digest()
    return (digest[0] << 8) | digest[1]


def dns_query(nonce: str, case_index: int) -> bytes:
    """A minimal recursion-desired A query for ``<nonce>.invalid``."""
    qname = ('%s.invalid' % nonce).encode('ascii')
    if any(not 1 <= len(label) <= 63 for label in qname.split(b'.')):
        raise ApplicationError('dns case label length out of range')
    body = bytearray()
    body += _dns_transaction_id(nonce, case_index).to_bytes(2, 'big')
    body += b'\x01\x00'          # flags: recursion desired
    body += b'\x00\x01'          # qdcount
    body += b'\x00\x00' * 3      # an/ns/ar counts
    for label in qname.split(b'.'):
        body.append(len(label))
        body += label
    body += b'\x00'              # root label
    body += b'\x00\x01'          # qtype A
    body += b'\x00\x01'          # qclass IN
    return bytes(body)


def build_request(kind: str, nonce: str, case_index: int) -> bytes:
    if kind in ('tcp-echo', 'udp-echo'):
        return echo_payload(nonce, case_index)
    if kind == 'http-tcp':
        return http_request(nonce)
    if kind == 'dns-udp':
        return dns_query(nonce, case_index)
    raise ApplicationError('unknown application kind: %r' % (kind,))


def fakenet_html_sha256(path) -> str:
    with open(path, 'rb') as stream:
        return hashlib.sha256(stream.read()).hexdigest()


def verify_echo(request: bytes, response: bytes) -> dict:
    if not response:
        raise ApplicationError('echo response is empty')
    if response != request:
        raise ApplicationError('echo bytes differ (request %d octets, response %d octets)'
                               % (len(request), len(response)))
    return {'kind': 'echo', 'octets': len(response)}


def verify_http(request: bytes, response: bytes, body_sha256: str) -> dict:
    if not response:
        raise ApplicationError('http response is empty')
    split = response.find(b'\r\n\r\n')
    if split < 0:
        raise ApplicationError('http response head is not terminated')
    head = response[:split].decode('iso-8859-1')
    body = response[split + 4:]
    lines = head.split('\r\n')
    status = lines[0].split(' ')
    if (len(status) < 2 or status[0] not in ('HTTP/1.0', 'HTTP/1.1')
            or status[1] != '200'):
        raise ApplicationError('http status line is not HTTP/1.0|1.1 200: %r' % lines[0])
    seen: dict[str, int] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(':')
        if not sep or not name.strip() or not value.strip():
            raise ApplicationError('malformed http header line: %r' % line)
        key = name.strip().lower()
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            # a repeated header is an ambiguous frame; a later value must not
            # silently override the earlier one.
            raise ApplicationError('duplicate http header rejected: %r' % key)
    if 'transfer-encoding' in seen:
        raise ApplicationError('http transfer-encoding frame is ambiguous and rejected')
    if 'content-length' not in seen:
        raise ApplicationError('http response lacks content-length')
    declared_text = [line.split(':', 1)[1].strip() for line in lines[1:]
                     if line.split(':', 1)[0].strip().lower() == 'content-length'][0]
    if not declared_text.isdigit():
        raise ApplicationError('http content-length is not an integer')
    declared = int(declared_text)
    if declared != len(body):
        raise ApplicationError('http body length %d does not match content-length %d'
                               % (len(body), declared))
    actual = hashlib.sha256(body).hexdigest()
    if actual != body_sha256:
        raise ApplicationError('http body sha256 %s does not match FakeNet.html %s'
                               % (actual, body_sha256[:16]))
    return {'kind': 'http', 'status': 200, 'body_octets': len(body),
            'body_sha256': actual}


def verify_dns(request: bytes, response: bytes) -> dict:
    from dnslib import DNSRecord
    if not response:
        raise ApplicationError('dns response is empty')
    try:
        query = DNSRecord.parse(request)
        answer = DNSRecord.parse(response)
    except Exception as exc:  # dnslib raises assorted parse errors
        raise ApplicationError('dns wire bytes do not parse: %s' % exc) from exc
    if answer.header.id != query.header.id:
        raise ApplicationError('dns transaction id mismatch')
    if not answer.header.qr:
        raise ApplicationError('dns response is not a response (QR=0)')
    if answer.header.rcode != 0:
        raise ApplicationError('dns response rcode is %d' % answer.header.rcode)
    if answer.header.tc:
        raise ApplicationError('dns response is truncated (TC=1)')
    if [str(q.qname) for q in answer.questions] != [str(q.qname) for q in query.questions]:
        raise ApplicationError('dns question qname mismatch')
    if [q.qtype for q in answer.questions] != [q.qtype for q in query.questions]:
        raise ApplicationError('dns question qtype mismatch')
    if [q.qclass for q in answer.questions] != [q.qclass for q in query.questions]:
        raise ApplicationError('dns question qclass mismatch')
    wanted_owner = str(query.questions[0].qname)
    owners = {str(rr.rname) for rr in answer.rr}
    if any(owner != wanted_owner for owner in owners):
        # An A record for an unrelated owner does not answer the question.
        raise ApplicationError('dns answer owner does not match the query name')
    addresses = [str(rr.rdata) for rr in answer.rr
                 if rr.rtype == 1 and rr.rclass == 1]
    if not addresses:
        raise ApplicationError('dns response has no A answer')
    for address in addresses:
        if address != DNS_EXPECTED_IPV4:
            raise ApplicationError('dns A answer is %s, expected %s'
                                   % (address, DNS_EXPECTED_IPV4))
    return {'kind': 'dns', 'transaction_id': answer.header.id,
            'answers': addresses}


def verify_exchange(kind: str, request: bytes, response: bytes, nonce: str,
                    case_index: int, fakenet_html_path) -> dict:
    """Verify one recorded application exchange against the frozen contract.

    The request must equal the frozen construction for this nonce and case,
    so a recording from another nonce or case index never verifies even when
    its response is individually well formed.
    """
    if kind not in APPLICATION_KINDS:
        raise ApplicationError('unknown application kind: %r' % (kind,))
    if len(response) > MAX_RESPONSE_BYTES:
        raise ApplicationError('application response exceeds %d octets' % MAX_RESPONSE_BYTES)
    expected_request = build_request(kind, nonce, case_index)
    if request != expected_request:
        raise ApplicationError('application request bytes do not match the frozen input')
    if kind in ('tcp-echo', 'udp-echo'):
        return verify_echo(request, response)
    if kind == 'http-tcp':
        return verify_http(request, response, fakenet_html_sha256(fakenet_html_path))
    return verify_dns(request, response)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode('ascii')


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode('ascii'), validate=True)


def validate_exchange_record(row, first, payload_row, close_row, planned,
                             nonce, case_index) -> dict:
    """Validate the exchange event's own fields against this run's facts.

    Nothing is trusted because the row was selected by connection_id: the
    PID, nonce, case index, application, protocol and tuples must match the
    run's first/send/close rows and the frozen planned input, the response
    must belong to this run's send/close window, the recorded octets must
    equal the decoded bytes, timeout/truncation must be explicit false, a
    native monotonic budget of at most ten seconds must be present, and a
    UDP peer must be the expected original-target tuple.
    """
    def fail(message):
        raise ApplicationError('exchange record rejected: ' + message)

    if row.get('nonce') != nonce:
        fail('nonce mismatch')
    if row.get('case_index') != case_index:
        fail('case index mismatch')
    if row.get('connection_id') != first.get('connection_id'):
        fail('connection id does not match the first case fact')
    if row.get('pid') != first.get('pid'):
        fail('pid does not match the first case fact')
    if row.get('application') != planned.get('application'):
        fail('application kind does not match the frozen planned input')
    if str(row.get('protocol', '')).lower() != str(planned.get('protocol', '')).lower():
        fail('protocol does not match the frozen planned input')
    if row.get('src') != first.get('src') or row.get('dst') != first.get('dst'):
        fail('source/destination tuple does not match the first case fact')
    if row.get('actual_dst') != first.get('actual_dst'):
        fail('actual destination does not match the first case fact')
    if planned.get('protocol') == 'udp':
        expected_peer = '%s:%s' % (planned.get('host'), planned.get('port'))
        if row.get('peer') != expected_peer:
            fail('udp peer %r is not the expected original target %r'
                 % (row.get('peer'), expected_peer))
    if row.get('timed_out') is not False or row.get('truncated') is not False:
        fail('timeout/truncation flags must be explicit false')
    if not isinstance(row.get('eof'), bool):
        fail('eof terminal must be an explicit boolean')
    request = unb64(row.get('request_b64', ''))
    response = unb64(row.get('response_b64', ''))
    if row.get('response_octets') != len(response):
        fail('response_octets %r does not equal %d decoded bytes'
             % (row.get('response_octets'), len(response)))
    window_start = payload_row.get('send_before_ticks')
    window_end = close_row.get('utc_ticks')
    if not (isinstance(window_start, int) and isinstance(window_end, int)):
        fail('case send/close window facts are missing')
    for name in ('utc_ticks', 'receive_after_ticks'):
        value = row.get(name)
        if not isinstance(value, int) or not window_start <= value <= window_end:
            fail('%s %r is outside this run send/close window' % (name, value))
    started = row.get('exchange_started_mono')
    finished = row.get('exchange_finished_mono')
    frequency = row.get('stopwatch_frequency')
    if not (isinstance(started, int) and isinstance(finished, int)
            and isinstance(frequency, int) and frequency > 0):
        fail('native monotonic exchange bounds are missing')
    if not 0 <= finished - started <= EXCHANGE_BUDGET_SECONDS * frequency:
        fail('native monotonic exchange budget of %d seconds exceeded'
             % ((finished - started) / frequency))
    return {'octets': len(response), 'request_octets': len(request),
            'budget_seconds': (finished - started) / frequency}
