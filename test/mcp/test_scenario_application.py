"""Wire-byte contract tests for scenario_application (A02).

Every fixture is actual wire bytes: the echo payloads are the frozen
constructions, the HTTP responses are real status/head/body octets around
the candidate-source FakeNet.html, and the DNS responses are dnslib-packed
records.  Rejections are checked byte-wise, never by trusting a parsed
self-report.
"""

import hashlib
import importlib.util
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('scenario_application_test', HERE / 'acceptance/scenario_application.py')
apps = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = apps
SPEC.loader.exec_module(apps)

REPO = HERE.parents[1]
HTML = REPO / 'fakenet/defaultFiles/FakeNet.html'
NONCE = 'wire-42'


def http_response(body, status='200 OK', length=None, extra=''):
    declared = len(body) if length is None else length
    return (('HTTP/1.1 %s\r\nContent-Type: text/html\r\nDate: Mon, 07 Sep 2026 '
             '01:48:56 GMT\r\nContent-Length: %d\r\nConnection: close\r\n%s\r\n'
             % (status, declared, extra)).encode('ascii') + body)


def dns_response(nonce, txn=None, qname=None, address=apps.DNS_EXPECTED_IPV4,
                 answers=1, tc=False):
    from dnslib import A, DNSHeader, DNSQuestion, DNSRecord, RR, QTYPE
    txn = apps._dns_transaction_id(nonce, 1) if txn is None else txn
    record = DNSRecord(DNSHeader(id=txn, qr=1, aa=1, ra=1, rc=0, tc=1 if tc else 0))
    record.add_question(DNSQuestion(qname or ('%s.invalid' % nonce), QTYPE.A))
    for _ in range(answers):
        record.add_answer(RR(qname or ('%s.invalid' % nonce), ttl=60, rdata=A(address)))
    return record.pack()


@pytest.mark.parametrize('kind', apps.APPLICATION_KINDS)
def test_frozen_construction_round_trips(kind):
    request = apps.build_request(kind, NONCE, 1)
    assert request == apps.build_request(kind, NONCE, 1)
    assert request != apps.build_request(kind, NONCE + 'x', 1)


def test_echo_verifies_complete_byte_equality():
    request = apps.build_request('tcp-echo', NONCE, 1)
    assert apps.verify_echo(request, request)['octets'] == len(request)


def test_same_length_wrong_echo_is_rejected():
    request = apps.build_request('tcp-echo', NONCE, 1)
    wrong = request[:-1] + bytes([request[-1] ^ 0x20])
    assert len(wrong) == len(request)
    with pytest.raises(apps.ApplicationError, match='echo bytes differ'):
        apps.verify_echo(request, wrong)


def test_truncated_tcp_response_is_rejected():
    request = apps.build_request('tcp-echo', NONCE, 1)
    with pytest.raises(apps.ApplicationError, match='echo bytes differ'):
        apps.verify_echo(request, request[:-3])


def test_empty_echo_response_is_rejected():
    request = apps.build_request('udp-echo', NONCE, 1)
    with pytest.raises(apps.ApplicationError, match='empty'):
        apps.verify_echo(request, b'')


def test_http_real_body_with_dynamic_date_passes():
    request = apps.build_request('http-tcp', NONCE, 1)
    body = HTML.read_bytes()
    response = http_response(body)
    verdict = apps.verify_http(request, response, apps.fakenet_html_sha256(HTML))
    assert verdict['body_octets'] == len(body)
    assert verdict['body_sha256'] == hashlib.sha256(body).hexdigest()


def test_http_wrong_body_is_rejected():
    request = apps.build_request('http-tcp', NONCE, 1)
    response = http_response(HTML.read_bytes() + b'<div>extra</div>')
    with pytest.raises(apps.ApplicationError, match='does not match FakeNet.html'):
        apps.verify_http(request, response, apps.fakenet_html_sha256(HTML))


def test_http_non_200_is_rejected():
    request = apps.build_request('http-tcp', NONCE, 1)
    response = http_response(HTML.read_bytes(), status='404 Not Found')
    with pytest.raises(apps.ApplicationError, match='200'):
        apps.verify_http(request, response, apps.fakenet_html_sha256(HTML))


def test_http_missing_or_wrong_content_length_is_rejected():
    request = apps.build_request('http-tcp', NONCE, 1)
    body = HTML.read_bytes()
    short = http_response(body, length=len(body) - 1)
    with pytest.raises(apps.ApplicationError, match='does not match content-length'):
        apps.verify_http(request, short, apps.fakenet_html_sha256(HTML))
    head_only = ('HTTP/1.1 200 OK\r\nDate: Mon, 07 Sep 2026 01:48:56 GMT\r\n'
                 'Connection: close\r\n\r\n').encode() + body
    with pytest.raises(apps.ApplicationError, match='lacks content-length'):
        apps.verify_http(request, head_only, apps.fakenet_html_sha256(HTML))


def test_http_truncated_body_is_rejected():
    request = apps.build_request('http-tcp', NONCE, 1)
    body = HTML.read_bytes()
    response = http_response(body)[:-10]
    with pytest.raises(apps.ApplicationError, match='does not match content-length'):
        apps.verify_http(request, response, apps.fakenet_html_sha256(HTML))


def test_dns_real_wire_response_passes():
    request = apps.build_request('dns-udp', NONCE, 1)
    response = dns_response(NONCE)
    verdict = apps.verify_dns(request, response)
    assert verdict['answers'] == [apps.DNS_EXPECTED_IPV4]


def test_dns_wrong_transaction_id_is_rejected():
    request = apps.build_request('dns-udp', NONCE, 1)
    response = dns_response(NONCE, txn=apps._dns_transaction_id(NONCE, 1) ^ 0xFFFF)
    with pytest.raises(apps.ApplicationError, match='transaction id'):
        apps.verify_dns(request, response)


def test_dns_wrong_qname_is_rejected():
    request = apps.build_request('dns-udp', NONCE, 1)
    response = dns_response(NONCE, qname='other.invalid')
    with pytest.raises(apps.ApplicationError, match='qname'):
        apps.verify_dns(request, response)


def test_dns_wrong_answer_address_is_rejected():
    request = apps.build_request('dns-udp', NONCE, 1)
    response = dns_response(NONCE, address='192.0.2.124')
    with pytest.raises(apps.ApplicationError, match='expected 192.0.2.123'):
        apps.verify_dns(request, response)


def test_dns_no_answer_is_rejected():
    request = apps.build_request('dns-udp', NONCE, 1)
    response = dns_response(NONCE, answers=0)
    with pytest.raises(apps.ApplicationError, match='no A answer'):
        apps.verify_dns(request, response)


def test_dns_truncated_flag_is_rejected():
    request = apps.build_request('dns-udp', NONCE, 1)
    response = dns_response(NONCE, tc=True)
    with pytest.raises(apps.ApplicationError, match='truncated'):
        apps.verify_dns(request, response)


@pytest.mark.parametrize('kind', apps.APPLICATION_KINDS)
def test_verify_exchange_binds_the_frozen_request(kind):
    request = apps.build_request(kind, NONCE, 1)
    if kind in ('tcp-echo', 'udp-echo'):
        response = request
    elif kind == 'http-tcp':
        response = http_response(HTML.read_bytes())
    else:
        response = dns_response(NONCE)
    other_nonce = apps.build_request(kind, 'borrowed-nonce', 1)
    with pytest.raises(apps.ApplicationError, match='frozen input'):
        apps.verify_exchange(kind, other_nonce, response, NONCE, 1, HTML)
    assert apps.verify_exchange(kind, request, response, NONCE, 1, HTML)


def test_verify_exchange_caps_response_size():
    request = apps.build_request('tcp-echo', NONCE, 1)
    with pytest.raises(apps.ApplicationError, match='exceeds'):
        apps.verify_exchange('tcp-echo', request, b'x' * (apps.MAX_RESPONSE_BYTES + 1),
                             NONCE, 1, HTML)


# --------------------------------------------------------------------------- R02
def dns_response_foreign_owner():
    from dnslib import A, DNSHeader, DNSQuestion, DNSRecord, RR, QTYPE
    txn = apps._dns_transaction_id(NONCE, 1)
    record = DNSRecord(DNSHeader(id=txn, qr=1, aa=1, ra=1, rc=0))
    record.add_question(DNSQuestion('%s.invalid' % NONCE, QTYPE.A))
    record.add_answer(RR('unrelated.invalid', ttl=60, rdata=A(apps.DNS_EXPECTED_IPV4)))
    return record.pack()


def test_r02_dns_answer_owner_mismatch_is_rejected():
    request = apps.build_request('dns-udp', NONCE, 1)
    with pytest.raises(apps.ApplicationError, match='owner'):
        apps.verify_dns(request, dns_response_foreign_owner())


def test_r02_http_duplicate_content_length_is_rejected():
    request = apps.build_request('http-tcp', NONCE, 1)
    body = HTML.read_bytes()
    response = (('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Length: %d\r\n'
                 'Connection: close\r\n\r\n' % (len(body), len(body))).encode() + body)
    with pytest.raises(apps.ApplicationError, match='duplicate http header'):
        apps.verify_http(request, response, apps.fakenet_html_sha256(HTML))


def test_r02_http_conflicting_content_length_is_rejected():
    request = apps.build_request('http-tcp', NONCE, 1)
    body = HTML.read_bytes()
    response = (('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Length: 0\r\n'
                 'Connection: close\r\n\r\n' % len(body)).encode() + body)
    with pytest.raises(apps.ApplicationError, match='duplicate http header'):
        apps.verify_http(request, response, apps.fakenet_html_sha256(HTML))


def test_r02_http_transfer_encoding_is_rejected():
    request = apps.build_request('http-tcp', NONCE, 1)
    body = HTML.read_bytes()
    response = (('HTTP/1.1 200 OK\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\n'
                 'Connection: close\r\n\r\n' % len(body)).encode() + body)
    with pytest.raises(apps.ApplicationError, match='transfer-encoding'):
        apps.verify_http(request, response, apps.fakenet_html_sha256(HTML))


def test_r02_http_unknown_protocol_version_is_rejected():
    request = apps.build_request('http-tcp', NONCE, 1)
    body = HTML.read_bytes()
    head = ('HTTP/2.0 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n'
            % len(body)).encode()
    with pytest.raises(apps.ApplicationError, match=r'HTTP/1\.0[|]1\.1'):
        apps.verify_http(request, head + body, apps.fakenet_html_sha256(HTML))


def test_r02_echo_extra_bytes_are_rejected_not_trimmed():
    request = apps.build_request('tcp-echo', NONCE, 1)
    with pytest.raises(apps.ApplicationError, match='echo bytes differ'):
        apps.verify_echo(request, request + b'EXTRA')


def test_r02_max_budget_is_shared_constant():
    assert apps.EXCHANGE_BUDGET_SECONDS == 10
    assert apps.MAX_RESPONSE_BYTES == 64 * 1024
