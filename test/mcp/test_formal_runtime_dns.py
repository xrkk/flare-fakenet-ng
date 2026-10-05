"""Real PCAP/log/native-byte binding; no manufactured live DNS lease credit."""
import copy
import json
import socket
from pathlib import Path

import dpkt
from dnslib import DNSRecord, RR, QTYPE, A, CNAME
import pytest

from test_formal_runtime_context import materials, load, git, record, write_json
from formal_runtime import dns_evidence as dns


SOURCE, RESOLVER, API = '192.168.204.233', '8.8.8.8', '1.1.1.1'


def dns_packet(payload, response=False):
    udp = dpkt.udp.UDP(sport=53 if response else 52345, dport=52345 if response else 53, data=payload)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=socket.inet_aton(RESOLVER if response else SOURCE),
                    dst=socket.inet_aton(SOURCE if response else RESOLVER),
                    p=dpkt.ip.IP_PROTO_UDP, data=udp)
    ip.len = len(ip)
    return bytes(ip)


def originals(root, failure=None):
    root.mkdir()
    pcap, log, native = (root / name for name in ('runtime-DNS.pcap', 'run.log', 'relay-native-events.jsonl'))
    question = DNSRecord.question(dns.DOMAIN)
    answer = question.reply()
    answer.add_answer(RR(dns.DOMAIN, QTYPE.CNAME, ttl=60, rdata=CNAME('runtime-api.example')))
    answer.add_answer(RR('runtime-api.example', QTYPE.A, ttl=30, rdata=A(API)))
    if failure == 'wrong-answer-id': answer.header.id += 1
    if failure == 'zero-ttl': answer.rr[-1].ttl = 0
    if failure == 'private-answer': answer.rr[-1].rdata = A('192.168.204.234')
    with pcap.open('xb') as stream:
        writer = dpkt.pcap.Writer(stream, linktype=dpkt.pcap.DLT_RAW)
        if failure != 'missing-query':
            writer.writepkt(dns_packet(question.pack()), ts=100)
        writer.writepkt(dns_packet(answer.pack(), response=True), ts=101)
        if failure == 'unrelated-query':
            writer.writepkt(dns_packet(DNSRecord.question('unrelated.example').pack()), ts=102)
    ttl = 31 if failure == 'lease-ttl' else 30
    flow_time = '00:00:31,000' if failure == 'expired-lease' else '00:00:02,000'
    lines = [
        f'2026-10-05 00:00:01,000 DNS_LEASE_ADD domain={dns.DOMAIN} ip={API} ttl={ttl}\n',
        f'2026-10-05 {flow_time} PROCESS_FLOW disposition=REDIRECT_TLS_RELAY domain={dns.DOMAIN} src={SOURCE} dst={API} proto=TCP dport=443 sport=52345\n',
        f'2026-10-05 00:00:02,100 TLS_SNI_ALLOW domain={dns.DOMAIN} sni={dns.DOMAIN} original_ip={API}\n',
        f'2026-10-05 00:00:02,101 ALLOW_INTERNAL_UPSTREAM kind=tls_relay port=443 ip={API}\n']
    if failure == 'missing-lease': lines = lines[1:]
    if failure == 'wrong-sni': lines[2] = lines[2].replace('sni=' + dns.DOMAIN, 'sni=wrong.example')
    log.write_bytes(b'\xef\xbb\xbf' + ''.join(lines).encode())
    event = {'schema': 'fakenetng.relay-native-terminal.v1', 'domain': dns.DOMAIN, 'sni': dns.DOMAIN,
             'original_ip': API, 'original_port': 443, 'src': SOURCE, 'sport': 52345, 'generation': 1,
             'clock': {'supported': True, 'qpc_frequency': 1000, 'qpc_before': 100,
                       'qpc_after': 101, 'filetime_100ns': 134355888888888888}}
    if failure == 'native-source': event['src'] = '192.168.204.234'
    if failure == 'native-sport': event['sport'] = 12345
    if failure == 'native-qpc': event['clock']['qpc_before'] = 102
    native.write_text(json.dumps(event) + '\n')
    probe = {'actual_curl_exit': 0, 'exit_code': 0, 'nonce': 'preflight-controlled',
             'url': 'https://' + dns.DOMAIN + '/preflight-controlled'}
    if failure == 'curl-error': probe['actual_curl_exit'] = 28
    p4 = {'external_dns_server': RESOLVER, 'api_ipv4': '8.8.4.4', 'routes': [{'InterfaceAlias': 'controlled-route'}]}
    return pcap, log, native, probe, 'controlled-stopped-run', p4


def test_original_runtime_query_answer_cname_lease_and_native_binding_use_exact_bytes(tmp_path):
    args = originals(tmp_path / 'originals')
    verdict = dns.bind_dns_native(*args, source=SOURCE)
    assert verdict['passed'] and verdict['P4_IP_need_not_equal_runtime_API']
    binding = verdict['bindings'][0]
    assert binding['runtime_IP'] == API and binding['DNS'][0]['ttl'] == 30
    assert binding['DNS'][0]['request_packet'] == 1 and binding['DNS'][0]['response_packet'] == 2
    assert binding['same_guest_log_TTL_guard'][0]['elapsed_guest_log_seconds'] == 1
    log = args[1].read_bytes()
    lease = binding['lease_log'][0]
    assert b'DNS_LEASE_ADD' in log[lease['byte_start']:lease['byte_end']]
    assert verdict['native_terminal_not_a_new_TLS_pass_oracle']
    assert verdict['DNS_capture_original'] == record(args[0])


@pytest.mark.parametrize('failure', ['wrong-answer-id', 'zero-ttl', 'private-answer', 'missing-query',
    'unrelated-query', 'lease-ttl', 'expired-lease', 'missing-lease', 'wrong-sni', 'native-source',
    'native-sport', 'native-qpc', 'curl-error'])
def test_original_dns_native_binding_rejects_missing_or_conflicting_original_proof(tmp_path, failure):
    args = originals(tmp_path / failure, failure)
    with pytest.raises(AssertionError):
        dns.bind_dns_native(*args, source=SOURCE)


def test_exact_domain_endpoint_filter_has_no_TLS_or_fixed_remote_API_capture():
    capture = dns.dns_filter(SOURCE, RESOLVER)
    assert capture == 'udp and port 53 and host ' + SOURCE + ' and host ' + RESOLVER + ' and ' + dns.DNS_QNAME_BPF
    assert API not in capture and '443' not in capture
    with pytest.raises(ValueError):
        dns.dns_filter('not-ip', RESOLVER)


def pinned_probe(materials):
    repo, path, _, data = materials
    original = Path(__file__).parent / 'acceptance/scenario_probes.ps1'
    probe = repo / 'test/mcp/acceptance/scenario_probes.ps1'
    probe.write_bytes(original.read_bytes())
    git(repo, 'add', str(probe))
    git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
        '-c', 'commit.gpgsign=false', 'commit', '-qm', 'explicit original probe fixture')
    data['tool_source']['commit'] = git(repo, 'rev-parse', 'HEAD')
    data['tool_source']['files'].append(record(probe))
    from formal_runtime.context import load_context
    return load_context(path, write_json(path, data)['sha256'], repository_root=repo)


def test_original_registered_probe_is_unchanged_and_must_be_pinned(materials):
    command = '$p="original-registered-probe";& $p -Action preflight-b1 -Nonce $n'
    context = pinned_probe(materials)
    binding = {'capture_root': str(context.evidence_root / 'P7-capture'), 'api_ipv4': '8.8.4.4'}
    actual, intent = dns.selected_p7_command(command, binding, context)
    assert actual == command and intent['runtime_DNS_required'] and intent['no_added_pre_start_DNS']
    assert intent['registered_probe_sha256'] == context.tool_source['files'][-1]['sha256']
    for altered in (command + ' --resolve api.deepseek.com:443:1.1.1.1', command + ' -TargetHost 1.1.1.1',
                    command.replace('preflight-b1', 'traffic')):
        with pytest.raises(AssertionError):
            dns.selected_p7_command(altered, binding, context)
    with pytest.raises(AssertionError):
        dns.selected_p7_command(command, dict(binding, capture_root=str(context.repository_root)), context)


def test_probe_missing_from_explicit_dependencies_never_acquires_P7_authority(materials):
    context = load(materials)
    with pytest.raises(AssertionError, match='pinned tool dependencies'):
        dns.selected_p7_command('& $p -Action preflight-b1 -Nonce $n',
                                {'capture_root': str(context.evidence_root / 'P7')}, context)
