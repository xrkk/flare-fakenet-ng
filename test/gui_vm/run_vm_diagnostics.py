# -*- coding: utf-8 -*-
"""One-click, human-in-the-loop VM diagnostic evidence collector.

The runner never changes adapter, route, firewall, or DNS state itself.  It
preflights the Ubuntu FNPR/1 endpoint, launches the diagnostic GUI, creates a
bounded TEST-NET TCP connection after the core is ready, observes the stop
request, and invokes Export-Logs.ps1.  A hung core is deliberately not killed:
its unfinished stop boundary is the evidence this runner exists to collect.
"""

import datetime
import glob
import hashlib
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import uuid


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(SCRIPT_DIR))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from fakenet.gui import launcher  # noqa: E402


EXIT_CAPTURED = 0
EXIT_FAILED = 1
EXIT_REFUSED = 2
SENTINEL_IPV4 = '192.168.204.1'
SENTINEL_PORT = 443
SENTINEL_WAIT_SECONDS = 120
SENTINEL_RETRY_SECONDS = 10
SESSION_WAIT_SECONDS = 20 * 60
STOP_OBSERVE_SECONDS = 45
TEST_TCP_IPV4 = '198.51.100.10'
TEST_TCP_PORT = 80
DIAGNOSTIC_DNS_SUFFIX = 'invalid'
GUI_STOP_OBSERVE_SECONDS = 30


def utc_now_text():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        '+00:00', 'Z')


def _tsv_value(value):
    return str(value).replace('\t', ' ').replace('\r', ' ').replace('\n', ' ')


def write_tsv(path, headers, rows):
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        handle.write('\t'.join(_tsv_value(item) for item in headers) + '\n')
        for row in rows:
            handle.write('\t'.join(_tsv_value(item) for item in row) + '\n')


def create_evidence_paths(log_root, stamp=None):
    stamp = stamp or datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    return {
        'results': os.path.join(
            log_root, 'diagnostic-results-%s.tsv' % stamp),
        'timeline': os.path.join(
            log_root, 'diagnostic-timeline-%s.tsv' % stamp),
        'network_before': os.path.join(
            log_root, 'diagnostic-network-before-%s.txt' % stamp),
        'network_after': os.path.join(
            log_root, 'diagnostic-network-after-%s.txt' % stamp),
        'session': os.path.join(
            log_root, 'diagnostic-session-%s.json' % stamp),
        'anomalies': os.path.join(
            log_root, 'diagnostic-core-anomalies-%s.txt' % stamp),
    }


def write_json(path, value):
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write('\n')


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def package_identity():
    manifest_path = os.path.join(REPO, 'gui-vm-manifest.json')
    identity = {'manifest_path': manifest_path}
    if not os.path.isfile(manifest_path):
        identity['manifest_status'] = 'missing'
        return identity
    try:
        with open(manifest_path, 'r', encoding='utf-8') as handle:
            manifest = json.load(handle)
        identity.update({
            'manifest_status': 'loaded',
            'manifest_sha256': file_sha256(manifest_path),
            'package_version': manifest.get('package_version'),
            'package_mode': manifest.get('package_mode'),
            'source_commit': manifest.get('source_commit'),
            'fakenet_exe_sha256': manifest.get('fakenet_exe_sha256'),
            'fakenet_gui_exe_sha256': manifest.get(
                'fakenet_gui_exe_sha256'),
        })
    except (OSError, ValueError) as exc:
        identity['manifest_status'] = 'invalid: %s' % exc
    return identity


def is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:  # noqa: BLE001 - fail closed outside Windows
        return False


def _read_bounded_line(sock, limit=512):
    data = bytearray()
    while len(data) < limit:
        chunk = sock.recv(min(128, limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b'\n' in chunk:
            break
    return bytes(data)


def probe_fnpr_transports(nonce, role, timeout=3.0, tcp_connect=None,
                          udp_socket_factory=None, target_ipv4=None,
                          target_port=None):
    """Probe both FNPR/1 transports without hiding a partial failure."""
    request = ('FNPR/1|%s|%s\n' % (nonce, role)).encode('ascii')
    expected = ('FNPR/1|%s|OK\n' % nonce).encode('ascii')
    target_ipv4 = target_ipv4 or SENTINEL_IPV4
    target_port = target_port or SENTINEL_PORT
    tcp_connect = tcp_connect or socket.create_connection
    udp_socket_factory = udp_socket_factory or (
        lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    results = {
        'tcp': {'ok': False, 'detail': 'not attempted'},
        'udp': {'ok': False, 'detail': 'not attempted'},
    }
    try:
        tcp = tcp_connect((target_ipv4, target_port), timeout)
        try:
            tcp.settimeout(timeout)
            tcp.sendall(request)
            tcp_response = _read_bounded_line(tcp)
        finally:
            tcp.close()
        results['tcp'] = {
            'ok': tcp_response == expected,
            'detail': ('same-nonce response' if tcp_response == expected else
                       'nonce response mismatch (%d bytes)' % len(tcp_response)),
        }
    except OSError as exc:
        results['tcp'] = {'ok': False, 'detail': 'unreachable: %s' % exc}

    try:
        udp = udp_socket_factory()
        try:
            udp.settimeout(timeout)
            udp.sendto(request, (target_ipv4, target_port))
            udp_response, peer = udp.recvfrom(512)
        finally:
            udp.close()
        peer_matches = peer[0] == target_ipv4
        response_matches = udp_response == expected
        results['udp'] = {
            'ok': peer_matches and response_matches,
            'detail': ('same-nonce response' if peer_matches and response_matches
                       else 'peer/nonce response mismatch (%d bytes)' %
                       len(udp_response)),
        }
    except OSError as exc:
        results['udp'] = {'ok': False, 'detail': 'unreachable: %s' % exc}
    return all(item['ok'] for item in results.values()), results


def probe_sentinel_once(nonce, timeout=3.0, tcp_connect=None,
                        udp_socket_factory=None):
    """Return ``(ok, detail)`` after same-nonce TCP and UDP preflight."""
    ok, transports = probe_fnpr_transports(
        nonce, 'preflight', timeout=timeout, tcp_connect=tcp_connect,
        udp_socket_factory=udp_socket_factory)
    if ok:
        return True, 'TCP/UDP 同 nonce 前置通过'
    detail = '; '.join('%s: %s' % (name.upper(), result['detail'])
                       for name, result in sorted(transports.items())
                       if not result['ok'])
    return False, detail


def _format_transport_failures(transports):
    failures = [
        '%s: %s' % (name.upper(), result['detail'])
        for name, result in sorted(transports.items()) if not result['ok']]
    return '; '.join(failures) if failures else 'TCP/UDP 同 nonce 前置通过'


def wait_for_sentinel():
    nonce = 'diag-%s' % uuid.uuid4().hex
    ok, transports = probe_fnpr_transports(nonce, 'preflight')
    detail = _format_transport_failures(transports)
    if ok:
        print('[PASS] Ubuntu Sentinel: %s' % detail, flush=True)
        return True, nonce, transports

    print('', flush=True)
    print('[ACTION REQUIRED 1/1]', flush=True)
    print('在 Ubuntu 运行仓库根目录的 Start-FNPR-Sentinel.sh，'
          '并保持窗口打开。', flush=True)
    print('Windows 端正在等待 %s:%s 的 TCP+UDP，同一窗口无需输入其他命令。'
          % (SENTINEL_IPV4, SENTINEL_PORT), flush=True)
    deadline = time.monotonic() + SENTINEL_WAIT_SECONDS
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        remaining = max(0, int(deadline - time.monotonic()))
        print('[WAIT] Ubuntu Sentinel 尚未就绪，剩余约 %d 秒；上次结果: %s'
              % (remaining, detail), flush=True)
        time.sleep(min(SENTINEL_RETRY_SECONDS,
                       max(0, deadline - time.monotonic())))
        ok, transports = probe_fnpr_transports(nonce, 'preflight')
        detail = _format_transport_failures(transports)
        if ok:
            print('[PASS] Ubuntu Sentinel: %s; nonce=%s' % (detail, nonce),
                  flush=True)
            return True, nonce, transports
    print('[REFUSED] Ubuntu Sentinel 前置失败: %s' % detail, flush=True)
    print('未启动 GUI，未修改 Windows 网络。', flush=True)
    return False, nonce, transports


def _encode_dns_name(name):
    labels = name.rstrip('.').split('.')
    encoded = bytearray()
    for label in labels:
        raw = label.encode('ascii')
        if not raw or len(raw) > 63:
            raise ValueError('invalid DNS label')
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def build_dns_a_query(name, query_id=None):
    query_id = query_id if query_id is not None else int(
        uuid.uuid4().hex[:4], 16)
    header = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(name) + struct.pack('!HH', 1, 1)
    return query_id, header + question


def _decode_dns_name(data, offset, depth=0):
    if depth > 16:
        raise ValueError('DNS compression pointer recursion')
    labels = []
    next_offset = None
    while True:
        if offset >= len(data):
            raise ValueError('truncated DNS name')
        length = data[offset]
        if length == 0:
            offset += 1
            if next_offset is None:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError('truncated DNS compression pointer')
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            suffix, unused = _decode_dns_name(data, pointer, depth + 1)
            if suffix:
                labels.extend(suffix.split('.'))
            if next_offset is None:
                next_offset = offset + 2
            break
        if length & 0xC0 or offset + 1 + length > len(data):
            raise ValueError('invalid DNS label')
        offset += 1
        labels.append(data[offset:offset + length].decode('ascii'))
        offset += length
    return '.'.join(labels), next_offset


def parse_dns_a_response(data, query_id, expected_name):
    if len(data) < 12:
        raise ValueError('truncated DNS response')
    response_id, flags, questions, answers, unused_ns, unused_ar = \
        struct.unpack('!HHHHHH', data[:12])
    if response_id != query_id:
        raise ValueError('DNS transaction ID mismatch')
    if not (flags & 0x8000) or flags & 0x000F:
        raise ValueError('DNS response flag/rcode mismatch')
    if questions != 1:
        raise ValueError('DNS response must repeat one question')
    offset = 12
    question_name, offset = _decode_dns_name(data, offset)
    if question_name.lower() != expected_name.rstrip('.').lower():
        raise ValueError('DNS response question mismatch')
    if offset + 4 > len(data):
        raise ValueError('truncated DNS question')
    offset += 4
    ipv4_answers = []
    for unused in range(answers):
        unused_name, offset = _decode_dns_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError('truncated DNS answer')
        record_type, record_class, unused_ttl, length = struct.unpack(
            '!HHIH', data[offset:offset + 10])
        offset += 10
        if offset + length > len(data):
            raise ValueError('truncated DNS record data')
        record_data = data[offset:offset + length]
        offset += length
        if record_type == 1 and record_class == 1 and length == 4:
            ipv4_answers.append(socket.inet_ntoa(record_data))
    return ipv4_answers


def probe_direct_dns(name, timeout=5.0, socket_factory=None):
    query_id, request = build_dns_a_query(name)
    socket_factory = socket_factory or (
        lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    dns_socket = socket_factory()
    try:
        dns_socket.settimeout(timeout)
        dns_socket.sendto(request, ('127.0.0.1', 53))
        response, peer = dns_socket.recvfrom(4096)
    except OSError as exc:
        return False, [], '127.0.0.1:53 unreachable: %s' % exc
    finally:
        dns_socket.close()
    try:
        answers = parse_dns_a_response(response, query_id, name)
    except (ValueError, UnicodeError, OSError) as exc:
        return False, [], 'invalid response from %s:%s: %s' % (
            peer[0], peer[1], exc)
    return bool(answers), answers, 'A=%s via %s:%s' % (
        ','.join(answers) if answers else '-', peer[0], peer[1])


def probe_system_dns(name):
    try:
        unused_host, unused_aliases, addresses = socket.gethostbyname_ex(name)
    except OSError as exc:
        return False, [], 'Windows resolver failed: %s' % exc
    unique = sorted(set(addresses))
    return bool(unique), unique, 'A=%s' % (','.join(unique) if unique else '-')


def _first_allowed_domain(content):
    match = re.search(
        r'DOMAIN_TAKEOVER_READY\s+allowed_domains=(\S+)', content)
    if not match:
        return None
    for domain in match.group(1).split(','):
        domain = domain.strip().lower()
        if domain and not domain.startswith('*.'):
            return domain
    return None


def probe_takeover_path(nonce, core_content):
    """Exercise DNS plus post-start TCP/UDP delivery to the Ubuntu sink."""
    rows = []
    query_name = 'diag-%s.%s' % (nonce[-12:], DIAGNOSTIC_DNS_SUFFIX)
    direct_ok, direct_answers, direct_detail = probe_direct_dns(query_name)
    direct_exact = direct_ok and direct_answers == [SENTINEL_IPV4]
    rows.append(('dns_direct_takeover', 'PASS' if direct_exact else 'FAIL',
                 '%s query=%s' % (direct_detail, query_name)))
    system_ok, system_answers, system_detail = probe_system_dns(query_name)
    system_exact = system_ok and system_answers == [SENTINEL_IPV4]
    rows.append(('dns_system_takeover', 'PASS' if system_exact else 'FAIL',
                 '%s query=%s' % (system_detail, query_name)))

    allowed_domain = _first_allowed_domain(core_content)
    if allowed_domain:
        allowed_ok, allowed_answers, allowed_detail = probe_direct_dns(
            allowed_domain)
        allowed_status = 'OBSERVED' if allowed_ok else 'UNAVAILABLE'
        if allowed_answers == [SENTINEL_IPV4]:
            allowed_status = 'FAIL'
        rows.append(('dns_allowed_domain_control', allowed_status,
                     '%s query=%s' % (allowed_detail, allowed_domain)))
    else:
        rows.append(('dns_allowed_domain_control', 'SKIP',
                     'no exact allowed domain in ready marker'))

    target_ok, transports = probe_fnpr_transports(nonce, 'target', timeout=5.0)
    for transport in ('tcp', 'udp'):
        item = transports[transport]
        rows.append(('takeover_target_%s' % transport,
                     'PASS' if item['ok'] else 'FAIL',
                     '%s:%s nonce=%s role=target %s' % (
                         SENTINEL_IPV4, SENTINEL_PORT, nonce,
                         item['detail'])))
    return direct_exact and system_exact and target_ok, rows


def capture_network_snapshot(path, label):
    commands = (
        ('ipconfig-all', ['ipconfig.exe', '/all']),
        ('route-ipv4', ['route.exe', 'print', '-4']),
        ('dns-client', [
            'powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
            '-Command',
            'Get-DnsClientServerAddress -AddressFamily IPv4 | '
            'Sort-Object InterfaceIndex | Select-Object '
            'InterfaceAlias,InterfaceIndex,ServerAddresses | '
            'ConvertTo-Json -Compress']),
        ('windivert-service', ['sc.exe', 'query', 'WinDivert1.3']),
        ('fakenet-processes', [
            'tasklist.exe', '/FI', 'IMAGENAME eq fakenet.exe', '/V']),
    )
    sections = ['label=%s' % label, 'captured_utc=%s' % utc_now_text()]
    captured = {}
    for name, command in commands:
        sections.append('\n===== %s =====' % name)
        sections.append('command=' + ' '.join(command))
        try:
            completed = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors='replace', timeout=20)
            sections.append('exit_code=%d' % completed.returncode)
            sections.append(completed.stdout.rstrip())
            captured[name] = (completed.returncode, completed.stdout.rstrip())
        except (OSError, subprocess.SubprocessError) as exc:
            error = 'capture_error=%s: %s' % (type(exc).__name__, exc)
            sections.append(error)
            captured[name] = (None, error)
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        handle.write('\n'.join(sections) + '\n')
    return captured


def write_core_anomaly_summary(path, core_path, gui_path=None):
    selected = []
    markers = (
        '[ERROR', '[CRITICAL', 'Traceback', 'DOMAIN_TAKEOVER_READY',
        'TAKEOVER_DNS_ANSWER', 'ALLOW_TAKEOVER_SINK', 'DIVERT_FAKE',
        'Stop flag found at ', 'STOP_PHASE_', 'STOP_PROVIDER_',
        'FakeNet-NG exiting:', 'PCAP_DUAL_SUMMARY')
    for source in (core_path, gui_path):
        if not source:
            continue
        selected.append('===== %s =====' % source)
        for line in read_text(source).splitlines():
            if any(marker in line for marker in markers):
                selected.append(line)
    with open(path, 'w', encoding='utf-8', newline='') as handle:
        handle.write('\n'.join(selected) + '\n')


def snapshot_logs(log_root):
    snapshot = {}
    for path in glob.glob(os.path.join(log_root, '*.log')):
        try:
            stat = os.stat(path)
            snapshot[os.path.abspath(path)] = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            pass
    return snapshot


def changed_core_logs(log_root, before):
    changed = []
    for path in glob.glob(os.path.join(log_root, 'fakenet-*.log')):
        if os.path.basename(path).lower().startswith('fakenet-gui-'):
            continue
        try:
            stat = os.stat(path)
        except OSError:
            continue
        identity = (stat.st_mtime_ns, stat.st_size)
        if before.get(os.path.abspath(path)) != identity:
            changed.append((stat.st_mtime_ns, os.path.abspath(path)))
    return [path for unused, path in sorted(changed, reverse=True)]


def changed_gui_logs(log_root, before):
    changed = []
    for path in glob.glob(os.path.join(log_root, 'fakenet-GUI-*.log')):
        try:
            stat = os.stat(path)
        except OSError:
            continue
        identity = (stat.st_mtime_ns, stat.st_size)
        if before.get(os.path.abspath(path)) != identity:
            changed.append((stat.st_mtime_ns, os.path.abspath(path)))
    return [path for unused, path in sorted(changed, reverse=True)]


def read_text(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as handle:
            return handle.read()
    except OSError:
        return ''


def _parse_gui_log_time(line):
    match = re.match(r'^(\d\d/\d\d/\d\d \d\d:\d\d:\d\d [AP]M)', line)
    if not match:
        return None
    try:
        return datetime.datetime.strptime(
            match.group(1), '%m/%d/%y %I:%M:%S %p')
    except ValueError:
        return None


def evaluate_gui_stop_log(content):
    requested = None
    exited = None
    exit_code = None
    for line in content.splitlines():
        if 'Stop requested via flag:' in line:
            requested = _parse_gui_log_time(line)
        if 'FakeNet session exited: code=' in line:
            exited = _parse_gui_log_time(line)
            match = re.search(r'FakeNet session exited: code=(-?\d+)', line)
            if match:
                exit_code = int(match.group(1))
    if requested and exited:
        elapsed = max(0.0, (exited - requested).total_seconds())
        return True, 'request_to_gui_exit_seconds=%.0f exit_code=%s' % (
            elapsed, exit_code if exit_code is not None else 'unknown')
    if requested:
        return False, 'stop request logged but GUI did not observe session exit'
    return False, 'GUI stop request marker missing'


def wait_for_gui_stop_observation(log_root, before, timeout=None):
    timeout = GUI_STOP_OBSERVE_SECONDS if timeout is None else timeout
    deadline = time.monotonic() + timeout
    last_detail = 'GUI log not found'
    last_path = None
    while time.monotonic() <= deadline:
        candidates = changed_gui_logs(log_root, before)
        if candidates:
            last_path = candidates[0]
            ok, last_detail = evaluate_gui_stop_log(read_text(last_path))
            if ok:
                return True, last_detail, last_path
        time.sleep(0.5)
    return False, last_detail, last_path


def evaluate_core_log(content):
    """Return ``(state, detail)`` for the exact diagnostic decision."""
    takeover = 'DOMAIN_TAKEOVER_READY' in content
    ordinary = 'EGRESS_CONTROL_READY' in content and not takeover
    stop_requested = 'Stop flag found at ' in content
    stop_complete = (
        'STOP_PHASE_END phase=complete' in content and
        'FakeNet-NG exiting: rc=0' in content)
    if stop_complete and takeover:
        return 'complete', '接管已启用，停止完整结束'
    if stop_complete and ordinary:
        return 'config-missing', '停止完整结束，但核心未进入 takeover'
    if stop_requested:
        return 'observing-stop', '停止请求已进入核心'
    if takeover:
        return 'takeover-ready', '核心已进入 takeover'
    if ordinary:
        return 'ordinary-ready', '核心仅进入普通出站策略'
    return 'waiting', '等待核心启动证据'


def open_bounded_test_connection():
    """Create one safe TEST-NET connection and retain it through stop."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(8)
    try:
        sock.connect((TEST_TCP_IPV4, TEST_TCP_PORT))
        sock.sendall(b'GET /diagnostic HTTP/1.1\r\nHost: diagnostic.invalid\r\n')
        return sock, 'TEST-NET TCP 连接已建立并保留'
    except OSError as exc:
        sock.close()
        return None, 'TEST-NET TCP 探针未建立: %s' % exc


def run_export(started_utc):
    exporter = os.path.join(SCRIPT_DIR, 'Export-Logs.ps1')
    command = [
        'powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
        '-ExecutionPolicy', 'Bypass', '-File', exporter,
        '-SinceUtc', started_utc,
        '-SessionLabel', 'diagnostic',
    ]
    completed = subprocess.run(command, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True,
                               errors='replace', timeout=120)
    print(completed.stdout, end='' if completed.stdout.endswith('\n') else '\n',
          flush=True)
    if completed.returncode != 0:
        return False, '证据导出失败，退出码 %d' % completed.returncode
    for line in completed.stdout.splitlines():
        if line.startswith('EVIDENCE_PATH='):
            return True, line.split('=', 1)[1]
    return False, '导出器未返回 EVIDENCE_PATH'


def main():
    if os.name != 'nt':
        print('[REFUSED] 诊断入口只允许在隔离 Windows VM 运行。')
        return EXIT_REFUSED
    if not is_admin():
        print('[REFUSED] 请双击 Run-Diagnostics.cmd；它会自动请求一次 UAC。')
        return EXIT_REFUSED
    vm = launcher.query_vm_state()
    if vm.verdict != launcher.VERDICT_VM:
        print('[REFUSED] VM 判定未通过: %s' % vm.detail)
        return EXIT_REFUSED
    if launcher.is_fakenet_running():
        print('[REFUSED] 已有 fakenet.exe 运行。请回滚/重启 VM 后再诊断；'
              '本工具不会强杀并掩盖恢复状态。')
        return EXIT_REFUSED

    gui_exe = os.path.join(REPO, 'fakenet-GUI.exe')
    if not os.path.isfile(gui_exe):
        print('[REFUSED] 诊断包根目录缺少 fakenet-GUI.exe: %s' % gui_exe)
        return EXIT_REFUSED

    log_root = os.path.join(REPO, 'Logs')
    os.makedirs(log_root, exist_ok=True)
    before = snapshot_logs(log_root)
    started = datetime.datetime.now(datetime.timezone.utc)
    started_utc = started.isoformat().replace('+00:00', 'Z')
    evidence_paths = create_evidence_paths(log_root)
    results = []
    timeline = []

    def record_timeline(event, detail):
        timeline.append((event, utc_now_text(), detail))
        write_tsv(evidence_paths['timeline'], ('event', 'utc', 'detail'),
                  timeline)

    def record_result(check, status, detail):
        results.append((check, status, detail))
        write_tsv(evidence_paths['results'],
                  ('check', 'status', 'detail'), results)

    record_timeline('diagnostic_started', 'package_root=%s' % REPO)
    network_before = capture_network_snapshot(
        evidence_paths['network_before'], 'before-core')
    record_result('network_snapshot_before', 'CAPTURED',
                  evidence_paths['network_before'])

    ok, nonce, preflight_transports = wait_for_sentinel()
    session_identity = package_identity()
    session_identity.update({
        'diagnostic_started_utc': started_utc,
        'nonce': nonce,
        'sentinel_ipv4': SENTINEL_IPV4,
        'sentinel_port': SENTINEL_PORT,
        'python': sys.version,
        'platform': sys.platform,
        'package_root': REPO,
        'gui_executable': gui_exe,
        'runner_argv': sys.argv,
    })
    write_json(evidence_paths['session'], session_identity)
    for transport in ('tcp', 'udp'):
        item = preflight_transports[transport]
        record_result(
            'sentinel_preflight_%s' % transport,
            'PASS' if item['ok'] else 'FAIL',
            'nonce=%s role=preflight target=%s:%s %s' %
            (nonce, SENTINEL_IPV4, SENTINEL_PORT, item['detail']))
    if not ok:
        record_timeline('diagnostic_refused', 'sentinel preflight failed')
        network_after = capture_network_snapshot(
            evidence_paths['network_after'], 'after-refused-preflight')
        record_result('network_snapshot_after', 'CAPTURED',
                      evidence_paths['network_after'])
        record_result('dns_state_restored',
                      'PASS' if network_before.get('dns-client') ==
                      network_after.get('dns-client') else 'FAIL',
                      'before/after DNS client state comparison')
        exported, export_detail = run_export(started_utc)
        if exported:
            print('[EVIDENCE] %s' % export_detail, flush=True)
        return EXIT_REFUSED

    print('', flush=True)
    print('[GUI DIAGNOSTIC]', flush=True)
    print('GUI 即将打开。请只在 GUI 中完成以下操作，无需输入 Windows 命令:',
          flush=True)
    print('  1. 启用“将其他域名导向私网分析主机”，确认地址为 '
          '192.168.204.1。', flush=True)
    print('  2. 保存到一个非默认 INI，然后点击“启动 FakeNet-NG”。',
          flush=True)
    print('  3. 等待本控制台显示“现在点击停止”后，点击 GUI 的“停止”。',
          flush=True)
    print('之后本工具会自动等待 45 秒并导出证据。不要使用任务管理器强杀。',
          flush=True)
    gui_process = subprocess.Popen([gui_exe], cwd=REPO)
    record_timeline('gui_launched', 'pid=%s' % gui_process.pid)
    print('[WAIT] GUI 已打开；等待本次核心日志。sentinel nonce=%s' % nonce,
          flush=True)

    active_socket = None
    probe_attempted = False
    takeover_path_ok = False
    core_path = None
    stop_seen_at = None
    stop_seen_monotonic = None
    action_prompt_monotonic = None
    last_state = None
    outcome = 'timeout'
    deadline = time.monotonic() + SESSION_WAIT_SECONDS
    try:
        while time.monotonic() < deadline:
            candidates = changed_core_logs(log_root, before)
            if candidates:
                core_path = candidates[0]
                content = read_text(core_path)
                state, detail = evaluate_core_log(content)
                if state != last_state:
                    print('[STATE] %s: %s' % (state, detail), flush=True)
                    record_timeline('core_state', '%s: %s' % (state, detail))
                    last_state = state
                if state in ('takeover-ready', 'ordinary-ready') and \
                        not probe_attempted:
                    probe_attempted = True
                    if state == 'takeover-ready':
                        takeover_path_ok, path_rows = probe_takeover_path(
                            nonce, content)
                        for check, status, path_detail in path_rows:
                            record_result(check, status, path_detail)
                            print('[%s] %s: %s' %
                                  (status, check, path_detail), flush=True)
                        record_timeline(
                            'takeover_path_probe',
                            'PASS' if takeover_path_ok else 'FAIL')
                    else:
                        record_result(
                            'takeover_ready', 'FAIL',
                            'core entered ordinary egress policy')
                        for check in (
                                'dns_direct_takeover',
                                'dns_system_takeover',
                                'takeover_target_tcp',
                                'takeover_target_udp'):
                            record_result(check, 'SKIP',
                                          'takeover was not enabled')
                    active_socket, probe_detail = open_bounded_test_connection()
                    record_result('active_testnet_connection',
                                  'PASS' if active_socket else 'FAIL',
                                  probe_detail)
                    print('[PROBE] %s' % probe_detail, flush=True)
                    print('[ACTION REQUIRED] 现在点击 GUI 的“停止”按钮。',
                          flush=True)
                    action_prompt_monotonic = time.monotonic()
                    record_timeline('stop_action_prompt',
                                    '现在点击 GUI 的“停止”按钮')
                if state == 'complete':
                    outcome = 'complete'
                    record_result('core_stop_complete', 'PASS', detail)
                    record_timeline('core_stop_complete', detail)
                    break
                if state == 'config-missing':
                    outcome = 'config-missing'
                    record_result('core_stop_complete', 'PASS', detail)
                    record_timeline('core_stop_complete', detail)
                    break
                if state == 'observing-stop' and stop_seen_at is None:
                    stop_seen_at = time.monotonic()
                    stop_seen_monotonic = stop_seen_at
                    prompt_delay = (
                        stop_seen_at - action_prompt_monotonic
                        if action_prompt_monotonic is not None else -1)
                    record_result(
                        'core_stop_request', 'PASS',
                        'prompt_to_core_stop_seconds=%.3f' % prompt_delay)
                    record_timeline('core_stop_request_seen', detail)
                    print('[WAIT] 停止请求已进入核心；观察 45 秒，随后自动导出。',
                          flush=True)
                if stop_seen_at is not None and \
                        time.monotonic() - stop_seen_at >= STOP_OBSERVE_SECONDS:
                    outcome = 'stop-incomplete'
                    record_result(
                        'core_stop_complete', 'FAIL',
                        'no complete stop after %.0f seconds' %
                        STOP_OBSERVE_SECONDS)
                    record_timeline('core_stop_timeout', outcome)
                    break
            if gui_process.poll() is not None and core_path is None:
                outcome = 'gui-exited-before-core'
                break
            time.sleep(1)
    finally:
        if active_socket is not None:
            try:
                active_socket.close()
            except OSError:
                pass

    gui_log_path = None
    if outcome in ('complete', 'config-missing'):
        gui_stop_ok, gui_stop_detail, gui_log_path = \
            wait_for_gui_stop_observation(log_root, before)
        record_result('gui_stop_observation',
                      'PASS' if gui_stop_ok else 'FAIL', gui_stop_detail)
        record_timeline('gui_stop_observation', gui_stop_detail)
    else:
        gui_candidates = changed_gui_logs(log_root, before)
        if gui_candidates:
            gui_log_path = gui_candidates[0]
        record_result('gui_stop_observation', 'INCOMPLETE',
                      'core session did not complete')

    if stop_seen_monotonic is None:
        final_core_content = read_text(core_path) if core_path else ''
        if 'Stop flag found at ' in final_core_content:
            record_result(
                'core_stop_request', 'PASS',
                'present in final core log; live prompt latency unavailable')
        else:
            record_result('core_stop_request', 'FAIL',
                          'core did not log the stop flag')
    if not probe_attempted:
        record_result('takeover_probe_sequence', 'FAIL',
                      'core never reached a probe-ready state')
    else:
        record_result('takeover_probe_sequence',
                      'PASS' if takeover_path_ok else 'FAIL',
                      'DNS plus post-start TCP/UDP target evidence captured')

    if core_path:
        write_core_anomaly_summary(
            evidence_paths['anomalies'], core_path, gui_log_path)
        record_result('core_anomaly_summary', 'CAPTURED',
                      evidence_paths['anomalies'])
    network_after = capture_network_snapshot(
        evidence_paths['network_after'], 'after-core-session')
    record_result('network_snapshot_after', 'CAPTURED',
                  evidence_paths['network_after'])
    for check, section in (
            ('dns_state_restored', 'dns-client'),
            ('ipv4_route_state_restored', 'route-ipv4')):
        same = network_before.get(section) == network_after.get(section)
        record_result(check, 'PASS' if same else 'FAIL',
                      'before/after %s exact comparison' % section)
    record_result(
        'fakenet_process_absent_after',
        'PASS' if not launcher.is_fakenet_running() else 'FAIL',
        'checked by executable image name after core session')
    record_timeline('evidence_export_started', outcome)

    exported, export_detail = run_export(started_utc)
    if exported:
        print('[EVIDENCE] %s' % export_detail, flush=True)
    else:
        print('[FAIL] %s' % export_detail, flush=True)
        return EXIT_FAILED

    if outcome == 'complete':
        print('[CAPTURED] 本次 takeover 配置与完整停止均有证据。',
              flush=True)
        if takeover_path_ok:
            print('[PASS] 启动后域名应答及 TCP/UDP 已真实到达 Ubuntu。',
                  flush=True)
        else:
            print('[FAIL] 启动后的域名/Ubuntu TCP+UDP 端到端链未通过；'
                  '请同时回传 Windows 证据与 Ubuntu Sentinel 日志。',
                  flush=True)
    elif outcome == 'config-missing':
        print('[CAPTURED] 已捕获 GUI 会话未进入 takeover；请回传证据目录。',
              flush=True)
    elif outcome == 'stop-incomplete':
        print('[CAPTURED] 已捕获停止未在 45 秒内完成；不要强杀后继续验收。',
              flush=True)
        print('请回传证据目录，然后回滚隔离 VM 快照。', flush=True)
    else:
        print('[CAPTURED] 诊断流程未完成: %s；请回传证据目录。' % outcome,
              flush=True)
    print('现在可以关闭 GUI，并在 Ubuntu Sentinel 窗口按 Ctrl+C。', flush=True)
    return EXIT_CAPTURED


if __name__ == '__main__':
    sys.exit(main())
