"""Default-bucket application cases through the real _traffic_oracle.

The fixtures below are complete con008 originals: the probe JSONL, the
traditional ``requested`` lines, full TCPIP lifecycles for TCP cases and
real Kernel-Network EventId42 rows for UDP cases, plus the hash-bound
capture metadata.  Only the pktmon packet/NIC listing boundary is stubbed
(the same boundary the existing oracle tests stub); the case adjudication,
application byte verification and application observation chains run for
real.  Offline fixtures never stand in for a real Windows probe run.
"""

import base64
import copy
import hashlib
import importlib.util
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location('suite_default_app', HERE / 'acceptance/scenario_suite.py')
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)
ASPEC = importlib.util.spec_from_file_location('scenario_application_direct', HERE / 'acceptance/scenario_application.py')
apps = importlib.util.module_from_spec(ASPEC)
sys.modules[ASPEC.name] = apps
ASPEC.loader.exec_module(apps)

sys.path.insert(0, str(HERE))
import test_sst_tcpip_events as tcpip_fixtures  # noqa: E402  (same test dir)

REPO = HERE.parents[1]
NONCE = 'oracle-app'
LAUNCHER_PID = 777
MANAGED_PID = 404
EPOCH_TICKS = 621355968000000000


def net_ticks(moment):
    return EPOCH_TICKS + int(moment.timestamp() * 10 ** 7)


BASE = datetime(2026, 9, 11, 1, 48, 54, tzinfo=timezone.utc)
T_READY = net_ticks(datetime(2026, 9, 11, 1, 48, 55, tzinfo=timezone.utc))
T_CONNECT = '55.200000000'
KIND_INDEX = {'tcp-echo': 0, 'udp-echo': 1, 'http-tcp': 2, 'dns-udp': 3}


def pktmon_line(seconds, body):
    return '[00]0001.0002::2026-09-11 09:48:%s [Microsoft-Windows-TCPIP] TCP: %s\r\n' % (seconds, body)


def _lifecycle(tcb_main, tcb_peer, sink_port, src, sport, dst, dport):
    return [
        pktmon_line('55.100000000', 'connection 0x%s transition from ClosedState  to SynSentState , SndNxt = 0.' % tcb_main),
        pktmon_line('55.150000000', 'connection 0x%s transition from SynSentState  to EstablishedState , SndNxt = 1.' % tcb_main),
        pktmon_line(T_CONNECT, 'connection 0x%s (local=%s:%d remote=%s:%d) connect completed. PID = %d.' % (tcb_main, src, sport, dst, dport, LAUNCHER_PID)),
        pktmon_line('55.150000100', 'connection 0x%s transition from ListenState to SynRcvdState , SndNxt = 0.' % tcb_peer),
        pktmon_line('55.150000200', 'listener (local=%s:%d remote=%s:%d) accept completed. TCB = 0x%s. PID = %d.' % (src, sink_port, src, sport, tcb_peer, MANAGED_PID)),
        pktmon_line('56.000000000', 'connection 0x%s transition from EstablishedState  to FinWait1State , SndNxt = 3.' % tcb_peer),
        pktmon_line('56.100000000', 'connection 0x%s transition from EstablishedState  to CloseWaitState , SndNxt = 3.' % tcb_main),
        pktmon_line('57.000000000', 'connection 0x%s (local=%s:%d remote=%s:%d) close issued.' % (tcb_main, src, sport, dst, dport)),
    ]


def tcpip_capture_text(src, sport, dst, dport):
    lines = (_lifecycle('AAA', 'BBB', 38928, src, 5000, dst, 1337) +
             _lifecycle('CCC', 'DDD', 38929, src, sport, dst, dport))
    base = int(BASE.timestamp() * 10 ** 7)
    header = ('[00]0000.0000::2026-09-11 09:48:54.000000000 [MSNT_SystemTrace] Header, EndTime: %d, '
              'StartTime: %d, EventsLost: 0, BuffersLost: 0, LogFileNameString: C:\\run\\pktmon.etl\r\n'
              % (base + 116444736000000000 + 50000000, base + 116444736000000000))
    text = '\ufeff' + header + ''.join(lines)
    return text.encode('utf-16-le')


def pktmon_metadata(raw):
    return {
        'capture_mode': 'all-components-tcpip',
        'clock_before': dict(utc_ticks=621355968000000000 + int(BASE.timestamp() * 10 ** 7),
                             mono=0, stopwatch_frequency=10000000, offset_minutes=480),
        'clock_after': dict(utc_ticks=621355968000000000 + int(BASE.timestamp() * 10 ** 7) + 50000000,
                            mono=50000000, stopwatch_frequency=10000000, offset_minutes=480),
        'conversion': dict(argv=['pktmon', 'etl2txt', 'C:\\run\\pktmon.etl', '--out', 'C:\\run\\pktmon.txt'],
                           exit_code=0, etl_sha256=hashlib.sha256(b'fixture ETL').hexdigest(),
                           text_sha256=hashlib.sha256(raw).hexdigest()),
    }


def ipc_rows():
    return [dict(event='request', frame=dict(run_id='r', seq=1, kind='ready')),
            dict(event='response', frame=dict(run_id='r', seq=1, result={'identity': {
                'pid': MANAGED_PID,
                'creation_time': str(116444736000000000 + net_ticks(
                    datetime(2026, 9, 11, 1, 48, 0, tzinfo=timezone.utc)))}})),
            dict(event='request', frame=dict(run_id='r', seq=2, kind='start')),
            dict(event='response', frame=dict(run_id='r', seq=2, result={'probe': True}))]


def kernel_udp_events(send_before_ticks, send_after_ticks, dst_port, size, src='192.168.204.233', dst='198.51.100.77'):
    def endpoint_u32(ip):
        return int.from_bytes(ipaddress.IPv4Address(ip).packed, 'little')
    moment = datetime(2026, 9, 11, 4, 45, 14, 244775, tzinfo=timezone.utc)
    ticks = net_ticks(moment)
    assert send_before_ticks <= ticks <= send_after_ticks
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
           "<System><Provider Name='Microsoft-Windows-Kernel-Network' "
           "Guid='{7dd42a49-5329-4832-8dfd-43d979153a88}'/>"
           "<EventID>42</EventID><Version>0</Version><Level>4</Level><Task>11</Task>"
           "<Opcode>42</Opcode><Keywords>0x8000000000000010</Keywords>"
           "<TimeCreated SystemTime='2026-09-11T04:45:14.2447750Z'/>"
           "<EventRecordID>22</EventRecordID><Correlation/>"
           "<Execution ProcessID='%d' ThreadID='1128'/><Channel></Channel>"
           "<Computer>DESKTOP-3FI41GR</Computer><Security/></System>"
           "<EventData><Data Name='PID'>%d</Data><Data Name='size'>%d</Data>"
           "<Data Name='daddr'>%d</Data><Data Name='saddr'>%d</Data>"
           "<Data Name='dport'>%d</Data><Data Name='sport'>%d</Data>"
           "<Data Name='seqnum'>0</Data><Data Name='connid'>0</Data></EventData></Event>"
           % (LAUNCHER_PID, LAUNCHER_PID, size, endpoint_u32(dst), endpoint_u32(src),
              int.from_bytes(dst_port.to_bytes(2, 'big'), 'little'),
              int.from_bytes((5001).to_bytes(2, 'big'), 'little')))
    row = json.dumps({'ordinal': 1, 'xml': xml}).encode() + b'\r\n'
    # One leading PartitionInfoExtensionV2 context row, as in the real export.
    context = (b'{"xml":"<Event xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'>'
               b'<System><Provider Name=\'\'/><EventID>0</EventID></System>'
               b'<ProcessingErrorData><ErrorCode>15003</ErrorCode></ProcessingErrorData></Event>","ordinal":0}\r\n')
    return context + row


def kernel_metadata(events_raw, etl):
    import hashlib as _h
    meta = copy.deepcopy(tcpip_fixtures.KERNEL_META)
    meta['conversion']['events_sha256'] = _h.sha256(events_raw).hexdigest()
    meta['conversion']['etl_sha256'] = _h.sha256(etl).hexdigest()
    meta['conversion']['header_sha256'] = _h.sha256(tcpip_fixtures.KERNEL_HEADER).hexdigest()
    meta['conversion']['summary_sha256'] = _h.sha256(tcpip_fixtures.KERNEL_SUMMARY).hexdigest()
    return meta


def probe_rows(profile, kind, request, response, send_before, send_after):
    case = profile['probe_cases'][0]
    target = '%s:%d' % (case['host'], case['port'])
    cadence = profile['cadence_ms']
    rows = [
        dict(event='ready', utc_ticks=T_READY, mono=0, pid=LAUNCHER_PID, worker=1, seq=0,
             nonce=NONCE, profile=profile['bucket'], variant=profile['variant'],
             tempo=profile['tempo'], interleave=profile['interleave'], cadence_ms=cadence,
             target_host=profile['probe_target']['host'], target_port=profile['probe_target']['port'],
             target_protocol=profile['probe_target']['protocol'],
             process_mode=profile['probe_target']['process_mode'], fnpr_role='',
             startup_retry_seconds=profile['startup_retry_seconds'],
             additional_targets=list(profile['probe_cases']), creation_ticks=T_READY,
             stopwatch_frequency=10000000),
        dict(event='released', utc_ticks=T_READY, mono=0, nonce=NONCE,
             interleave=profile['interleave']),
        dict(event='established', utc_ticks=T_READY + 1000000, mono=100000, nonce=NONCE,
             connection_id='main', pid=LAUNCHER_PID, worker=1, seq=1,
             src='192.168.204.233:5000', dst='198.51.100.77:1337',
             actual_dst='198.51.100.77:1337'),
        dict(event='send', utc_ticks=T_READY + 2000000, mono=200000, nonce=NONCE,
             connection_id='main', pid=LAUNCHER_PID, cadence_ms=cadence),
        dict(event='send', utc_ticks=T_READY + 2000000 + cadence * 10000, mono=300000,
             nonce=NONCE, connection_id='main', pid=LAUNCHER_PID, cadence_ms=cadence),
        dict(event='close', utc_ticks=T_READY + 20000000, mono=2000000, nonce=NONCE,
             connection_id='main', pid=LAUNCHER_PID, worker=1, seq=2),
        dict(event='cases_released', utc_ticks=T_READY + 30000000, mono=3000000, nonce=NONCE,
             worker=1, seq=0, phase='after-healthy', count=1),
    ]
    connection = '%s-case-1' % NONCE
    protocol = case['protocol']
    if protocol == 'udp':
        rows.append(dict(event='case_udp_sent', utc_ticks=send_before, mono=4000000, nonce=NONCE,
                         connection_id=connection, case_index=1, expectation='local_fake',
                         src='192.168.204.233:5001', dst=target, actual_dst=target,
                         protocol='udp', bytes=len(request), byte_count=len(request),
                         send_before_ticks=send_before, send_after_ticks=send_after,
                         application=kind, pid=LAUNCHER_PID, worker=1, seq=0, cadence_ms=cadence))
    else:
        rows.append(dict(event='case_established', utc_ticks=T_READY + 5000000, mono=500000,
                         nonce=NONCE, connection_id=connection, case_index=1,
                         expectation='local_fake', src='192.168.204.233:5001', dst=target,
                         actual_dst=target, protocol='tcp', application=kind,
                         pid=LAUNCHER_PID, worker=1, seq=0))
        rows.append(dict(event='case_request_sent' if kind == 'http-tcp' else 'case_send',
                         utc_ticks=send_before, mono=600000, nonce=NONCE, connection_id=connection,
                         case_index=1, expectation='local_fake', bytes=len(request),
                         byte_count=len(request), cadence_ms=0, application=kind,
                         send_before_ticks=send_before, send_after_ticks=send_after,
                         pid=LAUNCHER_PID, worker=1, seq=0))
    rows.append(dict(event='case_application_exchange', utc_ticks=send_after, mono=700000,
                     nonce=NONCE, connection_id=connection, case_index=1,
                     expectation='local_fake', application=kind,
                     protocol=protocol, src='192.168.204.233:5001', dst=target,
                     actual_dst=target, peer=target, pid=LAUNCHER_PID,
                     request_b64=base64.b64encode(request).decode(),
                     response_b64=base64.b64encode(response).decode(),
                     response_octets=len(response), eof=True, timed_out=False,
                     truncated=False, exchange_budget_seconds=10,
                     send_before_ticks=send_before, send_after_ticks=send_after,
                     receive_after_ticks=send_after, worker=1, seq=0,
                     exchange_started_mono=600000, exchange_finished_mono=700000,
                     stopwatch_frequency=10000000))
    rows.append(dict(event='case_close', utc_ticks=send_after + 1000000, mono=800000, nonce=NONCE,
                     connection_id=connection, case_index=1, expectation='local_fake',
                     protocol=protocol, application=kind, pid=LAUNCHER_PID, worker=1, seq=0))
    return rows


def application_response(kind, request):
    if kind in ('tcp-echo', 'udp-echo'):
        return request
    if kind == 'http-tcp':
        body = (REPO / 'fakenet/defaultFiles/FakeNet.html').read_bytes()
        head = ('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n'
                'Date: Mon, 07 Sep 2026 01:48:56 GMT\r\n'
                'Content-Length: %d\r\nConnection: close\r\n\r\n' % len(body))
        return head.encode('ascii') + body
    from dnslib import A, DNSHeader, DNSQuestion, DNSRecord, RR
    txn = apps._dns_transaction_id(NONCE, 1)
    answer = DNSRecord(DNSHeader(id=txn, qr=1, aa=1, ra=1, rc=0))
    answer.add_question(DNSQuestion('%s.invalid' % NONCE, getattr(__import__('dnslib').QTYPE, 'A')))
    answer.add_answer(RR('%s.invalid' % NONCE, ttl=60, rdata=A(apps.DNS_EXPECTED_IPV4)))
    assert DNSQuestion('%s.invalid' % NONCE)  # qname builds
    return answer.pack()


def build_fixture(tmp_path, kind, *, mutate=None, nic_leak=False):
    root = Path(tmp_path)
    profile = suite.materialize_probe_profile(
        suite.profile_for_bucket('default', 0, in_bucket=KIND_INDEX[kind]), '60.28.220.199')
    case = profile['probe_cases'][0]
    request = apps.build_request(kind, NONCE, 1)
    response = application_response(kind, request)
    send_before = net_ticks(datetime(2026, 9, 11, 1, 48, 56, tzinfo=timezone.utc))
    send_after = send_before + 10000
    if kind in ('dns-udp', 'udp-echo'):
        # the kernel fixture event sits at 04:45:14.2447750Z; place the send
        # window around it so match_send's conservative interval intersects.
        send_before = net_ticks(datetime(2026, 9, 11, 4, 45, 14, 244770, tzinfo=timezone.utc))
        send_after = net_ticks(datetime(2026, 9, 11, 4, 45, 14, 244780, tzinfo=timezone.utc))
    rows = probe_rows(profile, kind, request, response, send_before, send_after)
    if mutate:
        rows = mutate(rows)
    files = []

    def put(name, raw):
        (root / name).write_bytes(raw)
        files.append(dict(path=name, size=len(raw), sha256=hashlib.sha256(raw).hexdigest()))

    put('probe.jsonl', ('\n'.join(json.dumps(row) for row in rows) + '\n').encode())
    log_lines = ['2026-09-11 09:48:55,300 INFO Diverter FakeNet (777) requested TCP 198.51.100.77:1337']
    log_lines.append('2026-09-11 09:48:56,400 INFO Diverter FakeNet (777) requested %s 198.51.100.77:%d'
                     % (case['protocol'].upper(), case['port']))
    put('run.log', ('\n'.join(log_lines) + '\n').encode())
    # Every run keeps the pktmon all-components capture (plan 7d): the TCP
    # primary's con008 observation always reads it, even when the one case is
    # a UDP application flow with its own Kernel-Network originals.
    put('pktmon.txt', tcpip_capture_text('192.168.204.233', 5001, '198.51.100.77', case['port']))
    put('pktmon.etl', b'fixture ETL')
    put('pktmon-nic.json', json.dumps(pktmon_metadata(
        (root / 'pktmon.txt').read_bytes())).encode())
    put('ipc-parent.jsonl', ('\n'.join(json.dumps(row) for row in ipc_rows()) + '\n').encode())
    if case['protocol'] == 'udp':
        events = kernel_udp_events(send_before, send_after, case['port'], len(request))
        etl = b'synthetic ETL payload, never runtime qualification'
        put('kernel-network.events.jsonl', events)
        put('kernel-network.etl', etl)
        put('kernel-network.header.xml', tcpip_fixtures.KERNEL_HEADER)
        put('kernel-network.summary.txt', tcpip_fixtures.KERNEL_SUMMARY)
        put('kernel-network.metadata.json', json.dumps(kernel_metadata(events, etl)).encode())

    class Identity:
        candidate_id = 'mcp-test-default-application'

    runner = object.__new__(suite.Suite)
    runner.root = root
    runner.identity = Identity()

    def packets(capture, src, dst, protocol, not_after_local=None, not_before_local=None):
        nic = [{'component': 9}] if (nic_leak and src.endswith(':5001')) else []
        return ([{'src': src, 'dst': dst, 'protocol': protocol}] if not nic else []), nic, {'component_ids': [9]}

    runner._pktmon_observations = packets
    originals = [dict(record) for record in files if record['path'] == 'run.log']
    capture_files = [dict(record) for record in files if record['path'] != 'run.log']
    run = {'run_id': 'r',
           'capture': {'probe_path': 'probe.jsonl', 'pktmon_path': 'pktmon.txt',
                       'observation_contract': 'con008', 'files': capture_files},
           'originals': {'files': originals}}
    return runner, run, profile


def oracle(runner, run, profile):
    return runner._traffic_oracle(run, profile, NONCE, {'rows': []})


ALL_KINDS = ['tcp-echo', 'udp-echo', 'http-tcp', 'dns-udp']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_default_application_case_complete_facts_pass(tmp_path, kind):
    runner, run, profile = build_fixture(tmp_path, kind)
    result = oracle(runner, run, profile)
    assert result['passed'], result


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_default_application_missing_exchange_fails(tmp_path, kind):
    def drop_exchange(rows):
        return [row for row in rows if row.get('event') != 'case_application_exchange']
    runner, run, profile = build_fixture(tmp_path, kind, mutate=drop_exchange)
    assert not oracle(runner, run, profile)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_default_application_missing_request_fails(tmp_path, kind):
    request_events = ('case_send', 'case_request_sent', 'case_udp_sent')

    def drop_request(rows):
        return [row for row in rows if row.get('event') not in request_events]
    runner, run, profile = build_fixture(tmp_path, kind, mutate=drop_request)
    assert not oracle(runner, run, profile)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_default_application_wrong_nonce_bytes_fail(tmp_path, kind):
    runner, run, profile = build_fixture(tmp_path, kind)
    run2 = copy.deepcopy(run)
    text = (Path(runner.root) / 'probe.jsonl').read_text()
    other = apps.b64(apps.build_request(kind, 'other-nonce', 1))
    rows = [json.loads(line) for line in text.splitlines()]
    for row in rows:
        if row.get('event') == 'case_application_exchange':
            row['request_b64'] = other
    (Path(runner.root) / 'probe.jsonl').write_text(
        '\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
    for record in run2['capture']['files']:
        if record['path'] == 'probe.jsonl':
            raw = (Path(runner.root) / 'probe.jsonl').read_bytes()
            record.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    run2['originals']['files'] = [dict(r) for r in run2['capture']['files'] if r['path'] == 'pktmon.txt']
    assert not oracle(runner, run2, profile)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_default_application_wrong_case_binding_fails(tmp_path, kind):
    def rebind(rows):
        return [dict(row, connection_id='other-case-9') if row.get('event') == 'case_application_exchange'
                else row for row in rows]
    runner, run, profile = build_fixture(tmp_path, kind, mutate=rebind)
    assert not oracle(runner, run, profile)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_default_application_pid_binding_missing_fails(tmp_path, kind):
    def repid(rows):
        return [dict(row, pid=888) if str(row.get('event', '')).startswith('case_') else row
                for row in rows]
    runner, run, profile = build_fixture(tmp_path, kind, mutate=repid)
    assert not oracle(runner, run, profile)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_default_application_original_target_nic_packet_fails(tmp_path, kind):
    runner, run, profile = build_fixture(tmp_path, kind, nic_leak=True)
    assert not oracle(runner, run, profile)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_default_application_native_observation_missing_fails(tmp_path, kind):
    runner, run, profile = build_fixture(tmp_path, kind)
    name = ('pktmon-nic.json' if profile['probe_cases'][0]['protocol'] == 'tcp'
            else 'kernel-network.events.jsonl')
    broken = Path(runner.root) / name
    broken.write_bytes(broken.read_bytes() + b'x')
    run2 = copy.deepcopy(run)
    for record in run2['capture']['files']:
        if record['path'] == name:
            raw = broken.read_bytes()
            record.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    run2['originals']['files'] = [dict(r) for r in run2['capture']['files'] if r['path'] == 'pktmon.txt']
    assert not oracle(runner, run2, profile)['passed']


def test_default_application_restart_rows_carry_independent_cases():
    """Restart rows run the case per run; the fixture builder's exchange is
    per-run by construction (case_index 1 per run label), and no run may
    borrow another run's recording - enforced by the nonce/case binding the
    verifier applies to the raw bytes."""
    for kind in ALL_KINDS:
        request = apps.build_request(kind, NONCE, 1)
        assert request == apps.build_request(kind, NONCE, 1)
        assert request != apps.build_request(kind, NONCE + '-run2', 1)
        if kind != 'http-tcp':
            # echo payloads and DNS transactions also bind the case index;
            # the frozen HTTP request carries the nonce only.
            assert request != apps.build_request(kind, NONCE, 2)


# --------------------------------------------------------------------------- R02
def _tamper_exchange(tmp_path, kind, **fields):
    runner, run, profile = build_fixture(tmp_path, kind)
    text = (Path(runner.root) / 'probe.jsonl').read_text()
    rows = [json.loads(line) for line in text.splitlines()]
    hit = 0
    for row in rows:
        if row.get('event') == 'case_application_exchange':
            row.update(fields)
            hit += 1
    assert hit == 1
    (Path(runner.root) / 'probe.jsonl').write_text(
        '\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
    raw = (Path(runner.root) / 'probe.jsonl').read_bytes()
    for record in run['capture']['files']:
        if record['path'] == 'probe.jsonl':
            record.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    return oracle(runner, run, profile)


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_r02_exchange_pid_tamper_rejected(tmp_path, kind):
    assert not _tamper_exchange(tmp_path, kind, pid=888)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_r02_exchange_timeout_flag_rejected(tmp_path, kind):
    assert not _tamper_exchange(tmp_path, kind, timed_out=True)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_r02_exchange_truncated_flag_rejected(tmp_path, kind):
    assert not _tamper_exchange(tmp_path, kind, truncated=True)['passed']


@pytest.mark.parametrize('kind', ['udp-echo', 'dns-udp'])
def test_r02_exchange_foreign_peer_rejected(tmp_path, kind):
    assert not _tamper_exchange(tmp_path, kind, peer='203.0.113.9:53')['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_r02_exchange_octets_mismatch_rejected(tmp_path, kind):
    assert not _tamper_exchange(tmp_path, kind, response_octets=1)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_r02_exchange_missing_time_fields_rejected(tmp_path, kind):
    runner, run, profile = build_fixture(tmp_path, kind)
    text = (Path(runner.root) / 'probe.jsonl').read_text()
    rows = [json.loads(line) for line in text.splitlines()]
    for row in rows:
        if row.get('event') == 'case_application_exchange':
            del row['exchange_started_mono']
            del row['exchange_finished_mono']
    (Path(runner.root) / 'probe.jsonl').write_text(
        '\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
    raw = (Path(runner.root) / 'probe.jsonl').read_bytes()
    for record in run['capture']['files']:
        if record['path'] == 'probe.jsonl':
            record.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    assert not oracle(runner, run, profile)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_r02_exchange_budget_exceeded_rejected(tmp_path, kind):
    assert not _tamper_exchange(
        tmp_path, kind, exchange_started_mono=0,
        exchange_finished_mono=11 * 10000000)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_r02_exchange_outside_run_window_rejected(tmp_path, kind):
    late = T_READY + 400_000_000  # far beyond this run's case window
    assert not _tamper_exchange(tmp_path, kind, utc_ticks=late,
                                receive_after_ticks=late,
                                send_before_ticks=late,
                                send_after_ticks=late + 1000)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_r02_case_error_alongside_bytes_rejected(tmp_path, kind):
    runner, run, profile = build_fixture(tmp_path, kind)
    text = (Path(runner.root) / 'probe.jsonl').read_text()
    rows = [json.loads(line) for line in text.splitlines()]
    connection = '%s-case-1' % NONCE
    rows.append(dict(event='case_error', utc_ticks=T_READY + 6000000, mono=650000,
                     nonce=NONCE, connection_id=connection, case_index=1,
                     expectation='local_fake', protocol='tcp',
                     application=kind, pid=LAUNCHER_PID, worker=1, seq=0,
                     error_type='TimeoutException', message='late error'))
    (Path(runner.root) / 'probe.jsonl').write_text(
        '\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
    raw = (Path(runner.root) / 'probe.jsonl').read_bytes()
    for record in run['capture']['files']:
        if record['path'] == 'probe.jsonl':
            record.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    assert not oracle(runner, run, profile)['passed']


def _run_two_runs(tmp_path, kind):
    """Two independent run fixtures sharing nonce and case_index."""
    run1_root = Path(tmp_path) / 'run1'
    run2_root = Path(tmp_path) / 'run2'
    run1_root.mkdir(parents=True, exist_ok=True)
    run2_root.mkdir(parents=True, exist_ok=True)
    one = build_fixture(run1_root, kind)
    two = build_fixture(run2_root, kind)
    return one, two


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_r02_two_runs_same_nonce_each_passes(tmp_path, kind):
    one, two = _run_two_runs(tmp_path, kind)
    assert oracle(*one)['passed']
    assert oracle(*two)['passed']


@pytest.mark.parametrize('kind', ALL_KINDS)
def test_r02_run1_response_transplanted_into_run2_rejected(tmp_path, kind):
    one, two = _run_two_runs(tmp_path, kind)
    runner2, run2, profile2 = two
    source = [json.loads(line) for line in (Path(one[0].root) / 'probe.jsonl').read_text().splitlines()]
    donor = next(row for row in source if row.get('event') == 'case_application_exchange')
    # Shift run2's timeline one hour later at build time is not available here,
    # so shift the donor one hour EARLIER instead: still a foreign run window.
    donor = dict(donor)
    donor['utc_ticks'] -= 3600 * 10_000_000
    donor['receive_after_ticks'] -= 3600 * 10_000_000
    donor['send_before_ticks'] -= 3600 * 10_000_000
    donor['send_after_ticks'] -= 3600 * 10_000_000
    rows = [json.loads(line) for line in (Path(runner2.root) / 'probe.jsonl').read_text().splitlines()]
    out = []
    for row in rows:
        if row.get('event') == 'case_application_exchange':
            out.append(donor)
        else:
            out.append(row)
    (Path(runner2.root) / 'probe.jsonl').write_text(
        '\n'.join(json.dumps(row) for row in out) + '\n', encoding='utf-8')
    raw = (Path(runner2.root) / 'probe.jsonl').read_bytes()
    for record in run2['capture']['files']:
        if record['path'] == 'probe.jsonl':
            record.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    assert not oracle(runner2, run2, profile2)['passed']
