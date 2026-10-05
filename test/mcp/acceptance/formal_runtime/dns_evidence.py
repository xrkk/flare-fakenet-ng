"""Bind only the original stopped P7 run's DNS/lease/TLS packets and log bytes.
No network, host capture, probe rewriting, fabricated lease, or product changes.
"""
import hashlib, ipaddress, re, socket, datetime
from pathlib import Path
import dpkt
from dnslib import DNSRecord, QTYPE, RCODE
DOMAIN = 'api.deepseek.com'


def api_ipv4(value):
    ip = ipaddress.IPv4Address(value)
    assert ip.is_global and not ip.is_multicast and not ip.is_reserved, 'P4 API target must be a public IPv4'
    return str(ip)


def route_binding(preflight):
    checks = [row for row in preflight['checks'] if row['id'] == 'P4-route-dns' and row['passed']]
    assert len(checks) == 1
    result = checks[0]['result']
    result = result[0] if isinstance(result, (list, tuple)) else result
    return {'external_dns_server': result['external_dns_server'], 'routes': result['routes']}


def selected_p7_command(original, binding, context):
    context.revalidate()
    assert original.count('& $p -Action preflight-b1 -Nonce $n') == 1
    assert '--resolve' not in original and '-TargetHost' not in original
    assert len(original) < 10000
    probe = context.source_root / 'test/mcp/acceptance/scenario_probes.ps1'
    records = [row for row in context.tool_source['files'] if row['path'] == str(probe)]
    assert len(records) == 1, 'original registered P7 probe must be in pinned tool dependencies'
    capture = Path(binding['capture_root'])
    from .context import exact_path
    assert exact_path(str(capture)).is_relative_to(context.evidence_root)
    return original, {'original_command': original, 'registered_probe_sha256': records[0]['sha256'],
                      'original_domain_probe_unmodified': True, 'runtime_DNS_required': True,
                      'P4_route_only': binding, 'no_added_pre_start_DNS': True,
                      'command_chars': len(original)}

def record(p):
    p = Path(p)
    with p.open('rb') as f:
        h = hashlib.file_digest(f, 'sha256').hexdigest()
    return {'path': str(p), 'size': p.stat().st_size, 'sha256': h}

def packets(path):
    rows = []
    with Path(path).open('rb') as f:
        reader = dpkt.pcap.Reader(f)
        link = reader.datalink()
        assert link in (dpkt.pcap.DLT_RAW, dpkt.pcap.DLT_EN10MB), 'unsupported original PCAP link type'
        for n, (ts, raw) in enumerate(reader, 1):
            try:
                ip = dpkt.ip.IP(raw) if link == dpkt.pcap.DLT_RAW else dpkt.ethernet.Ethernet(raw).data
            except (dpkt.UnpackError, ValueError):
                continue
            if not isinstance(ip, dpkt.ip.IP):
                continue
            transport = ip.data
            if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                continue
            rows.append({'index': n, 'time': float(ts), 'src': socket.inet_ntoa(ip.src), 'dst': socket.inet_ntoa(ip.dst), 'sport': transport.sport, 'dport': transport.dport, 'proto': 'TCP' if isinstance(transport, dpkt.tcp.TCP) else 'UDP', 'seq': getattr(transport, 'seq', None), 'flags': getattr(transport, 'flags', 0), 'payload': bytes(transport.data)})
    return rows

def fields(line):
    return dict(re.findall('([A-Za-z_]+)=([^\\s]+)', line))
DNS_QNAME_BPF = 'udp[20:4] = 0x03617069 and udp[24:4] = 0x08646565 and udp[28:4] = 0x70736565 and udp[32:4] = 0x6b03636f and udp[36:2] = 0x6d00'

def dns_filter(source, resolver):
    for value in (source, resolver):
        ipaddress.IPv4Address(value)
    return 'udp and port 53 and host ' + source + ' and host ' + resolver + ' and ' + DNS_QNAME_BPF

def bind_dns_native(pcap, log, native, probe, run_id, p4, source):
    """DNS-only wire capture + stopped-run product lease/flow/SNI/native originals.
This is not external TLS PCAP or a substitute for formal traffic/fault oracles.
"""
    assert probe and probe.get('actual_curl_exit') == 0 and (probe.get('exit_code') == 0) and (not probe.get('native_error'))
    assert probe['url'] == 'https://' + DOMAIN + '/' + probe['nonce'] and probe['nonce'].startswith('preflight-')
    rows = packets(pcap)
    dns = []
    resolver = p4['external_dns_server']
    for r in rows:
        assert r['proto'] == 'UDP' and 53 in (r['sport'], r['dport']) and ({r['src'], r['dst']} == {source, resolver}), 'DNS-only capture escaped endpoint filter'
        q = DNSRecord.parse(r['payload'])
        assert len(q.questions) == 1 and str(q.q.qname).rstrip('.').lower() == DOMAIN, 'DNS-only capture contains unrelated domain'
        if q.q.qtype != QTYPE.A:
            continue
        dns.append((r, q))
    answers = []
    for r, q in dns:
        if not q.header.qr or q.header.tc or q.header.rcode != RCODE.NOERROR or (r['src'] != resolver):
            continue
        request = [(a, z) for a, z in dns if not z.header.qr and z.header.id == q.header.id and ((a['src'], a['sport'], a['dst'], a['dport']) == (r['dst'], r['dport'], r['src'], r['sport'])) and (a['time'] <= r['time'])]
        if not request:
            continue
        cnames = {str(rr.rname).rstrip('.').lower(): (str(rr.rdata.label).rstrip('.').lower(), rr.ttl) for rr in q.rr if rr.rtype == QTYPE.CNAME}
        current = DOMAIN
        ttls = []
        seen = set()
        while current in cnames:
            assert current not in seen and len(seen) < 16
            seen.add(current)
            current, ttl = cnames[current]
            ttls.append(ttl)
        for rr in q.rr:
            if rr.rtype == QTYPE.A and str(rr.rname).rstrip('.').lower() == current:
                ip = str(rr.rdata)
                ttl = min(ttls + [rr.ttl])
                address = ipaddress.IPv4Address(ip)
                if ttl > 0 and address.is_global and (not address.is_multicast):
                    answers.append({'ip': ip, 'ttl': ttl, 'time': r['time'], 'request_packet': request[-1][0]['index'], 'response_packet': r['index']})
    assert answers, 'no complete same-capture runtime UDP A query/answer; TCP/fragmented/empty answers unproved'
    raw = Path(log).read_bytes()
    offset = 3 if raw.startswith(b'\xef\xbb\xbf') else 0
    leases = []
    allows = []
    flows = []
    upstreams = []
    for line in raw.decode('utf-8-sig').splitlines(keepends=True):
        f = fields(line)
        ref = {'byte_start': offset, 'byte_end': offset + len(line.encode()), 'fields': f}
        offset = ref['byte_end']
        try:
            ref['guest_log_time'] = datetime.datetime.strptime(line[:23], '%Y-%m-%d %H:%M:%S,%f').isoformat()
        except ValueError:
            ref['guest_log_time'] = None
        if 'DNS_LEASE_ADD ' in line and f.get('domain') == DOMAIN:
            leases.append(ref)
        if 'TLS_SNI_ALLOW ' in line and f.get('domain') == DOMAIN and (f.get('sni') == DOMAIN):
            allows.append(ref)
        if 'PROCESS_FLOW ' in line and f.get('disposition') == 'REDIRECT_TLS_RELAY' and (f.get('domain') == DOMAIN) and (f.get('src') == source) and (f.get('proto') == 'TCP') and (f.get('dport') == '443'):
            flows.append(ref)
        if 'ALLOW_INTERNAL_UPSTREAM ' in line and f.get('kind') == 'tls_relay' and (f.get('port') == '443'):
            upstreams.append(ref)
    native_rows = []
    for line in Path(native).read_text().splitlines():
        if line.strip():
            import json
            native_rows.append(json.loads(line))
    bindings = []
    for a in allows:
        ip = a['fields'].get('original_ip')
        dns_answers = [x for x in answers if x['ip'] == ip]
        lease = [x for x in leases if x['fields'].get('ip') == ip and any((int(x['fields'].get('ttl', '0')) == y['ttl'] for y in dns_answers)) and (x['byte_start'] < a['byte_start'])]
        flow = [x for x in flows if x['fields'].get('dst') == ip]
        relay = [x for x in upstreams if x['fields'].get('ip') == ip]
        native_match = [x for x in native_rows if x.get('schema') == 'fakenetng.relay-native-terminal.v1' and x.get('domain') == DOMAIN and (x.get('sni') == DOMAIN) and (x.get('original_ip') == ip) and (x.get('original_port') == 443) and (x.get('src') == source) and isinstance(x.get('generation'), int) and (x['generation'] > 0) and any((str(x.get('sport')) == f['fields'].get('sport') for f in flow)) and (x.get('clock', {}).get('supported') is True) and (x.get('clock', {}).get('qpc_frequency', 0) > 0) and (0 < x.get('clock', {}).get('qpc_before', 0) <= x.get('clock', {}).get('qpc_after', 0)) and (x.get('clock', {}).get('filetime_100ns', 0) > 0)]
        live = []
        for l in lease:
            for f in flow:
                if not l.get('guest_log_time') or not f.get('guest_log_time'):
                    continue
                elapsed = (datetime.datetime.fromisoformat(f['guest_log_time']) - datetime.datetime.fromisoformat(l['guest_log_time'])).total_seconds()
                if 0 <= elapsed < int(l['fields']['ttl']) and l['byte_start'] < f['byte_start']:
                    live.append({'lease_log_byte_start': l['byte_start'], 'redirect_log_byte_start': f['byte_start'], 'elapsed_guest_log_seconds': elapsed, 'ttl_seconds': int(l['fields']['ttl'])})
        if dns_answers and lease and flow and relay and native_match and live:
            bindings.append({'runtime_IP': ip, 'DNS': dns_answers, 'lease_log': lease, 'SNI_allow_log': a, 'client_redirect_log': flow, 'relay_upstream_log': relay, 'native_original_records': native_match, 'same_guest_log_TTL_guard': live})
    assert bindings and len(bindings) == len(allows), 'same-run DNS lease / original redirect / SNI / native mapping proof incomplete'
    return {'passed': True, 'run_id': run_id, 'probe_nonce': probe['nonce'], 'probe_url': probe['url'], 'P4_route_only': p4, 'P4_IP_need_not_equal_runtime_API': True, 'capture_contract': 'domain-filtered runtime DNS only + same-run original product native relay and log; no external TLS wire verdict', 'DNS_capture_original': record(pcap), 'run_log_original': record(log), 'relay_native_original': record(native), 'bindings': bindings, 'unsupported_DNS_transport': 'TCP fallback/fragmentation stays unproved and fails local binding; no retry', 'formal_traffic_oracles_unchanged': True, 'native_terminal_not_a_new_TLS_pass_oracle': True}
