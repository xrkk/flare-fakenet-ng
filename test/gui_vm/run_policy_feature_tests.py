# -*- coding: utf-8 -*-
"""One-click policy feature tests for the VM package (plan v1.28 12.31.4).

Exercises the user-authorized v1.28 core changes end to end with the real
fakenet.exe and the real DNS data path:

  Phase 1 (EgressControl, multi-domain + wildcard):
    P1 exact domain resolves and leases a global IP
    P2 wildcard-covered subdomain resolves and leases a global IP
    P3 wildcard does not cover the apex (no lease for deepseek.com)
    P4 default deny: a non-allowed domain never leases

  Phase 2 (private-network takeover, multi-domain):
    P5 DOMAIN_TAKEOVER_READY lists every configured domain/wildcard
    P6 apex (not allowed) is answered with the takeover sink IPv4
    P7 wildcard-covered subdomain stays allowlisted under takeover
    P16-P20 exercise adjacent-private/ICMP/IPv6 fail-closed behavior and
            a temporary interface-metric route drift with exact restoration

  Phase 3 (unknown-IPv4 fallback, plan v1.29 12.32.1):
    P11 direct TCP to an unreviewed global IPv4 is DIVERT_FAKE'd (the
        sample never reaches the real host; it talks to a fake listener)
    P12 a bare DNS query sent to 8.8.8.8 (not the configured upstream)
        is intercepted and answered with the takeover sink IPv4

Start via Run-Policy-Tests.cmd (self-elevates). The runner refuses on
physical machines and unknown VM state, launches the core with generated
configs (GUI writer + validator agreement), triggers nslookup queries
against the local DNS listener and evaluates the core log. Exit codes:
0 = all PASS, 1 = any FAIL, 2 = REFUSED (precondition).
"""

import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
import uuid

REPO = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
HERE = os.path.dirname(os.path.abspath(__file__))
for path in (REPO, HERE):
    if path not in sys.path:
        sys.path.insert(0, path)

from fakenet.gui import configmodel, launcher, validator  # noqa: E402
import run_gui_vm_acceptance as acceptance  # noqa: E402

EXIT_PASS, EXIT_FAIL, EXIT_REFUSED = 0, 1, 2
RESULTS = []
LOG_DIR = None
FNPR_NONCE = None

EXACT_DOMAIN = 'api.deepseek.com'
WILDCARD_ENTRY = '*.deepseek.com'
WILDCARD_NAME = 'www.deepseek.com'
APEX_DOMAIN = 'deepseek.com'
DENY_DOMAIN = 'example.com'
TAKEOVER_SINK = '192.168.204.1'
BARE_RESOLVER = '8.8.8.8'
UNREVIEWED_IPV4 = '93.184.216.34'
UNREVIEWED_PORT = 80
# P16 only needs an adjacent-private policy classification.  Do not target
# an active listener port: ProxyUDP would otherwise forward the probe to the
# TCP-only HTTP listener and Windows would report an unrelated UDP reset.
ADJACENT_PRIVATE_PROBE_PORT = 65000


def result(name, status, detail, level='实测'):
    RESULTS.append((status, name, detail, level))
    print('  [%s] %-28s %s' % (status, name, detail))


def build_policy_config(path, domains, takeover_ip=None, dump_packets=False):
    """GUI writer + validator agreement for a full egress-policy config."""
    model = configmodel.ConfigModel.new_config()
    model.fakenet().set('DivertTraffic', 'Yes')
    diverter = model.diverter()
    diverter.set('ExternalAccessPolicy', 'EgressControl')
    diverter.set('ExternalAllowedDomains', domains)
    diverter.set('ExternalDnsServer', 'Auto')
    diverter.set('DumpPackets', 'Yes' if dump_packets else 'No')
    if dump_packets:
        # P14 (plan 2026.08.21-01 §5.2) parses this phase's dual pcap to
        # prove both directions are recorded.
        diverter.set('DumpPacketsFilePrefix', 'packets')
    # the GUI writes these enforced values on policy activation; the
    # validator requires them to be explicit in a generated config too
    for key, value in validator.schema.LOCKED_FIELD_VALUES.items():
        diverter.set(key, value)
    if takeover_ip:
        # A VMware host-only gateway can also be selected by Auto DNS.  When
        # the Ubuntu takeover sink uses that address, the core correctly
        # rejects the ambiguous topology.  Freeze the existing bare-resolver
        # test address for takeover phases so the two roles stay distinct.
        diverter.set('ExternalDnsServer', BARE_RESOLVER)
        diverter.set('ExternalTakeoverIPv4', takeover_ip)
        diverter.set('ExternalTakeoverDnsTTL', '60')
        diverter.set('ExternalTakeoverProbeTCPPorts', '')
        diverter.set('ExternalNonAllowedAction', 'Divert')
    validator.ensure_egress_control_topology(model)
    for section in model.listener_sections():
        if (section.get('Listener') or '') == 'DNSListener' and takeover_ip:
            section.set('ResponseA', takeover_ip)
    errors = [i for i in validator.validate(model)
              if i.level == validator.ERROR]
    if errors:
        return model, errors
    model.mtime = None
    model.save(path)
    return model, errors


def leased_global_ips(log_text, domain):
    """Global IPs leased for `domain` per DNS_LEASE_ADD lines."""
    ips = set()
    for match in re.finditer(
            r'DNS_LEASE_ADD domain=%s ip=(\S+)' % re.escape(domain), log_text):
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        if address.version == 4 and address.is_global:
            ips.add(str(address))
    return ips


def takeover_ready_domains(log_text):
    match = re.search(r'DOMAIN_TAKEOVER_READY allowed_domains=(\S+)', log_text)
    if not match:
        return None
    return match.group(1)


def _addresses_from_text(text, exclude):
    found = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text))
    found.discard(exclude)
    return found


def received_request_logged(log_text, name):
    """True when an A request for `name` (or its suffix-search mangled
    form) reached the DNS listener. The v28 field run showed nslookup
    may append the connection-specific suffix (e.g. *.localdomain) or a
    trailing dot, so match on the name prefix, not the closing quote."""
    return ("Received A request for domain '%s" % name) in log_text


def nslookup_addresses(name, server='127.0.0.1', timeout=15):
    # trailing dot = fully-qualified query: prevents the connection
    # specific DNS suffix search from mangling the name (v28 field fix)
    query = name if name.endswith('.') else name + '.'
    try:
        proc = subprocess.run(
            ['nslookup', query, server], capture_output=True, text=True,
            timeout=timeout,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except (subprocess.TimeoutExpired, OSError):
        return set()
    text = (proc.stdout or '') + (proc.stderr or '')
    return _addresses_from_text(text, server)


def divert_fake_logged(log_text, original_ip):
    """True when the diverter logged DIVERT_FAKE for this original IP."""
    return ('DIVERT_FAKE original_ip=%s ' % original_ip in log_text or
            log_text.rstrip().endswith(
                'DIVERT_FAKE original_ip=%s' % original_ip))


def reviewed_allow_logged(log_text, original_ip):
    marker = 'ip=%s' % original_ip
    return any('ALLOW_REVIEWED_IP' in line and marker in line
               for line in log_text.splitlines())


def answers_only_sink(addresses, sink):
    """True when every returned address is the takeover sink."""
    return bool(addresses) and addresses == {sink}


def takeover_route_identity(log_text):
    """Parse the frozen route identity emitted by the real Windows core."""
    lines = [line for line in log_text.splitlines()
             if 'TAKEOVER_ROUTE_OK ' in line]
    if not lines:
        return None
    fields = dict(re.findall(r'(\w+)=([^\s]+)', lines[-1]))
    try:
        return {
            'interface_index': int(fields['interface_index']),
            'interface_metric': int(fields['interface_metric']),
            'destination_prefix': fields['destination_prefix'],
            'next_hop': fields['next_hop'],
            'source_ipv4': fields['source_ipv4'],
        }
    except (KeyError, TypeError, ValueError):
        return None


def _powershell_json(script, timeout=20):
    completed = subprocess.run(
        ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
         '-ExecutionPolicy', 'Bypass', '-Command', script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=timeout,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout).strip() or
                           'PowerShell returned no diagnostic')
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError('PowerShell returned no JSON')
    return json.loads(lines[-1])


def read_interface_metric(interface_index):
    index = int(interface_index)
    script = (
        "$i=Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex %d "
        "-ErrorAction Stop | Select-Object -First 1;"
        "[PSCustomObject]@{interface_index=[int]$i.InterfaceIndex;"
        "automatic_metric=[string]$i.AutomaticMetric;"
        "interface_metric=[int]$i.InterfaceMetric}|"
        "ConvertTo-Json -Compress" % index)
    value = _powershell_json(script)
    return {
        'interface_index': int(value['interface_index']),
        'automatic_metric': str(value['automatic_metric']),
        'interface_metric': int(value['interface_metric']),
    }


def set_interface_metric(interface_index, metric):
    index = int(interface_index)
    value = int(metric)
    script = (
        "Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex %d "
        "-AutomaticMetric Disabled -InterfaceMetric %d -ErrorAction Stop;"
        "[PSCustomObject]@{ok=$true}|ConvertTo-Json -Compress"
        % (index, value))
    _powershell_json(script)


def restore_interface_metric(original):
    index = int(original['interface_index'])
    automatic = str(original['automatic_metric']).lower() == 'enabled'
    if automatic:
        command = (
            "Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex %d "
            "-AutomaticMetric Enabled -ErrorAction Stop;" % index)
    else:
        command = (
            "Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex %d "
            "-AutomaticMetric Disabled -InterfaceMetric %d "
            "-ErrorAction Stop;" % (index, int(original['interface_metric'])))
    _powershell_json(
        command + "[PSCustomObject]@{ok=$true}|ConvertTo-Json -Compress")


def _run_ping(arguments):
    try:
        completed = subprocess.run(
            ['ping.exe'] + list(arguments), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, timeout=10,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        detail = 'rc=%d' % completed.returncode
        if completed.stdout:
            detail += ';' + completed.stdout.splitlines()[-1].strip()
        return detail
    except (OSError, subprocess.SubprocessError) as exc:
        return '%s: %s' % (type(exc).__name__, exc)


def _send_adjacent_private_probe(nonce):
    adjacent = str(ipaddress.ip_address(TAKEOVER_SINK) + 1)
    payload = ('FNPR/1|%s|target\n' % nonce).encode('ascii')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(1)
        sock.sendto(payload, (adjacent, ADJACENT_PRIVATE_PROBE_PORT))
        detail = 'bounded UDP sent'
    except OSError as exc:
        detail = 'send result: %s' % exc
    finally:
        sock.close()
    return adjacent, detail


def exercise_acc008_negative_matrix(core_log, nonce):
    """Exercise the reviewed real-VM negative matrix and restore route state."""
    import run_vm_diagnostics as diagnostic

    initial = acceptance.read_core_log(core_log)
    route = takeover_route_identity(initial)
    adjacent, adjacent_detail = _send_adjacent_private_probe(nonce)
    time.sleep(1)
    after_adjacent = acceptance.read_core_log(core_log)
    adjacent_allowed = (
        'ALLOW_TAKEOVER_SINK ip=%s ' % adjacent in after_adjacent)
    result('P16 邻接私网不扩散', 'PASS' if not adjacent_allowed else 'FAIL',
           '%s;%s;ALLOW_TAKEOVER_SINK=%s' % (
               adjacent, adjacent_detail, adjacent_allowed))

    icmp_before = after_adjacent.count(
        'ALLOW_TAKEOVER_SINK ip=%s proto=ICMP' % TAKEOVER_SINK)
    icmp_detail = _run_ping(['-n', '1', '-w', '1000', TAKEOVER_SINK])
    time.sleep(1)
    after_icmp = acceptance.read_core_log(core_log)
    icmp_after = after_icmp.count(
        'ALLOW_TAKEOVER_SINK ip=%s proto=ICMP' % TAKEOVER_SINK)
    result('P17 ICMP 不得命中 sink',
           'PASS' if icmp_after == icmp_before else 'FAIL',
           '%s;ALLOW_TAKEOVER_SINK before=%d after=%d' % (
               icmp_detail, icmp_before, icmp_after))

    ipv6_drop_marker = 'DROP_EXTERNAL reason=external_ipv6'
    ipv6_before = after_icmp.count(ipv6_drop_marker)
    interface_index = route['interface_index'] if route else 0
    ipv6_target = 'ff02::1%%%d' % interface_index if interface_index else '::1'
    ipv6_detail = _run_ping(
        ['-6', '-n', '1', '-w', '1000', ipv6_target])
    ipv6_seen = acceptance.wait_for(
        lambda: acceptance.read_core_log(core_log).count(
            ipv6_drop_marker) > ipv6_before, 10)
    result('P18 IPv6 fail-closed', 'PASS' if ipv6_seen else 'FAIL',
           '%s;target=%s;external_ipv6_drop=%s' % (
               ipv6_detail, ipv6_target, ipv6_seen))

    evidence = {
        'route_marker': route,
        'original_interface': None,
        'drifted_interface': None,
        'restored_interface': None,
        'restore_matches_original': False,
        'takeover_suspended': False,
        'negative_target_tcp': None,
        'negative_target_udp': None,
        'errors': [],
    }
    original = None
    drift_applied = False
    try:
        if not route:
            raise RuntimeError('TAKEOVER_ROUTE_OK identity missing')
        original = read_interface_metric(route['interface_index'])
        evidence['original_interface'] = original
        drift_metric = original['interface_metric'] + 17
        drift_applied = True
        set_interface_metric(route['interface_index'], drift_metric)
        evidence['drifted_interface'] = read_interface_metric(
            route['interface_index'])
        suspended = acceptance.wait_for(
            lambda: ('TAKEOVER_SUSPEND' in
                     acceptance.read_core_log(core_log) and
                     'reason=route_snapshot_changed' in
                     acceptance.read_core_log(core_log)), 20)
        evidence['takeover_suspended'] = suspended
        allow_before = acceptance.read_core_log(core_log).count(
            'ALLOW_TAKEOVER_SINK')
        negative_ok, negative = diagnostic.probe_fnpr_transports(
            'negative-%s' % uuid.uuid4().hex, 'target', timeout=3.0)
        evidence['negative_target_tcp'] = negative['tcp']['ok']
        evidence['negative_target_udp'] = negative['udp']['ok']
        time.sleep(1)
        allow_after = acceptance.read_core_log(core_log).count(
            'ALLOW_TAKEOVER_SINK')
        drift_ok = (suspended and not negative_ok and
                    not negative['tcp']['ok'] and
                    not negative['udp']['ok'] and
                    allow_after == allow_before)
        result('P19 route drift 挂起 sink',
               'PASS' if drift_ok else 'FAIL',
               'suspended=%s;TCP=%s;UDP=%s;allow_before=%d;allow_after=%d'
               % (suspended, negative['tcp']['ok'], negative['udp']['ok'],
                  allow_before, allow_after))
    except Exception as exc:  # evidence failure is an explicit FAIL
        evidence['errors'].append('%s: %s' % (type(exc).__name__, exc))
        result('P19 route drift 挂起 sink', 'FAIL', evidence['errors'][-1])
    finally:
        if drift_applied and original is not None:
            try:
                restore_interface_metric(original)
                time.sleep(1)
                restored = read_interface_metric(original['interface_index'])
                evidence['restored_interface'] = restored
                evidence['restore_matches_original'] = restored == original
            except Exception as exc:  # restoration failure stays visible
                evidence['errors'].append(
                    'restore %s: %s' % (type(exc).__name__, exc))

    result('P20 route drift 精确恢复',
           'PASS' if evidence['restore_matches_original'] else 'FAIL',
           'original=%s;restored=%s;errors=%s' % (
               evidence['original_interface'],
               evidence['restored_interface'],
               evidence['errors'] or '-'))
    evidence_path = os.path.join(LOG_DIR, 'route-drift-evidence.json')
    with open(evidence_path, 'w', encoding='utf-8', newline='') as handle:
        json.dump(evidence, handle, ensure_ascii=False, indent=2,
                  sort_keys=True)
        handle.write('\n')
    return evidence


def probe_direct_ipv4(ip, port, timeout=10):
    """TCP-connect to an unreviewed global IPv4 and read any response.

    Returns (connected, received). Under a working divert fallback the
    three-way handshake completes against the fake listener and the
    listener usually answers an HTTP request with bytes.
    """
    connected, _sport, received = probe_direct_ipv4_sport(ip, port, timeout)
    return connected, received


def probe_direct_ipv4_sport(ip, port, timeout=10):
    """Same probe, also returning the local source port used (P14)."""
    import socket as _socket
    try:
        sock = _socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return False, None, 0
    sport = sock.getsockname()[1]
    received = 0
    try:
        sock.settimeout(timeout)
        try:
            sock.sendall(b'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' %
                         ip.encode('ascii'))
        except OSError:
            pass
        try:
            data = sock.recv(4096)
            received = len(data)
        except OSError:
            received = 0
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return True, sport, received


def parse_pcap_direction_counts(pcap_path, target_ip, sport):
    """Count outbound packets to target_ip and inbound TCP packets to
    sport in a DLT_RAW pcap (plan 2026.08.21-01 P14)."""
    import socket as _socket
    import dpkt
    target_bytes = _socket.inet_aton(target_ip)
    outbound = 0
    inbound = 0
    with open(pcap_path, 'rb') as handle:
        reader = dpkt.pcap.Reader(handle)
        for _ts, buf in reader:
            try:
                ip = dpkt.ip.IP(buf)
            except (dpkt.UnpackError, ValueError):
                continue
            if bytes(ip.dst) == target_bytes:
                outbound += 1
            if (ip.p == dpkt.ip.IP_PROTO_TCP and
                    getattr(ip.data, 'dport', None) == sport):
                inbound += 1
    return outbound, inbound


def run_core_phase(label, config_path, ready_marker, stop_flag):
    """Launch the core, wait for `ready_marker`, yield, stop cleanly."""
    fakenet_exe = acceptance.find_file('fakenet.exe')
    core_log = os.path.join(LOG_DIR, '%s.log' % label)
    params = '-c "%s" -l "%s" -f "%s" -p -v' % (config_path, core_log, stop_flag)
    ok, detail = launcher.launch_elevated(
        fakenet_exe, params, os.path.dirname(config_path))
    if not ok:
        result(label, 'FAIL', 'ShellExecute 结果: %s' % detail)
        return None, None
    acceptance.wait_for(launcher.is_fakenet_running, 40)
    ready = acceptance.wait_for(
        lambda: ready_marker in acceptance.read_core_log(core_log)
        if os.path.isfile(core_log) else False, 60)
    return core_log, ready


def stop_core(stop_flag, core_log):
    with open(stop_flag, 'w') as handle:
        handle.write('stop\n')
    acceptance.wait_for(lambda: not launcher.is_fakenet_running(), 40)
    acceptance.wait_for(
        lambda: 'FakeNet-NG exiting: rc=0' in
        (acceptance.read_core_log(core_log) if
         os.path.isfile(core_log) else ''), 15)


def finish():
    failed = [r for r in RESULTS if r[0] == 'FAIL']
    leftovers = acceptance.active_fakenet_images()
    if leftovers:
        result('P 组结束后进程残留', 'FAIL',
               '%s；未强杀，请导出证据并回滚快照' % ','.join(leftovers))
        failed = [r for r in RESULTS if r[0] == 'FAIL']
    if LOG_DIR is not None:
        tsv = os.path.join(LOG_DIR, 'policy-results.tsv')
        with open(tsv, 'w', encoding='utf-8') as handle:
            for status, name, detail, level in RESULTS:
                handle.write('%s\t%s\t%s\t[%s]\n' % (status, name, detail,
                                                     level))
        print('明细: %s' % tsv)
    print('\n===== 策略功能汇总: %d 项,失败 %d 项 ====='
          % (len(RESULTS), len(failed)))
    return EXIT_FAIL if failed else EXIT_PASS


def refuse(detail):
    print('拒绝: %s' % detail)
    return EXIT_REFUSED


def main():
    global LOG_DIR, FNPR_NONCE

    if os.name != 'nt':
        return refuse('仅支持 Windows')
    if not acceptance.is_admin():
        return refuse('未提权:请通过 Run-Policy-Tests.cmd 启动')
    if not acceptance.find_file('fakenet.exe'):
        return refuse('需要 fakenet.exe(放在脚本同目录/仓库根/dist 下)')
    vm = launcher.query_vm_state()
    if vm.verdict != launcher.VERDICT_VM:
        return refuse('本机不是确定的 VM(状态 %s)——策略测试会启用真实'
                      '流量劫持,只允许在隔离 VM 内运行' % vm.verdict)

    session_path = acceptance.fnpr_session_path()
    try:
        with open(session_path, 'r', encoding='utf-8') as handle:
            fnpr_session = json.load(handle)
        FNPR_NONCE = fnpr_session['nonce']
        if not fnpr_session.get('ok'):
            raise ValueError('preflight did not pass')
        if time.time() - float(fnpr_session['created_epoch']) > 3600:
            raise ValueError('preflight session is older than one hour')
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return refuse('缺少当前 Run-Tests.cmd 生成的 Sentinel 前置会话: %s'
                      % exc)

    stamp = time.strftime('%Y%m%d-%H%M%S')
    LOG_DIR = os.path.join(HERE, 'Logs', 'policy-%s' % stamp)
    os.makedirs(LOG_DIR, exist_ok=True)
    print('日志目录: %s' % LOG_DIR)

    domains = '%s, %s' % (EXACT_DOMAIN, WILDCARD_ENTRY)

    # -- Phase 1: EgressControl with multiple domains + wildcard -----------
    print('\n== 阶段 1:域名放行(多域名 + 通配符)==')
    config1 = os.path.join(LOG_DIR, 'policy1.ini')
    model, errors = build_policy_config(config1, domains)
    if errors:
        result('P1 阶段1配置', 'FAIL', '校验错误: %s' % errors[0].message)
        return finish()
    stop1 = os.path.join(LOG_DIR, 'stop1.flag')
    core_log, ready = run_core_phase('phase1', config1,
                                     'EGRESS_CONTROL_READY', stop1)
    if core_log is None:
        return finish()
    if not ready:
        result('P1 阶段1就绪', 'FAIL', '60 秒内未见 EGRESS_CONTROL_READY')
        stop_core(stop1, core_log)
        return finish()
    result('P1 阶段1就绪', 'PASS', 'EGRESS_CONTROL_READY 已出现')

    for name in (EXACT_DOMAIN, WILDCARD_NAME, APEX_DOMAIN, DENY_DOMAIN):
        nslookup_addresses(name)
    acceptance.wait_for(
        lambda: (leased_global_ips(
            acceptance.read_core_log(core_log), EXACT_DOMAIN) and
            leased_global_ips(
                acceptance.read_core_log(core_log), WILDCARD_NAME)), 30)
    time.sleep(3)
    log_text = acceptance.read_core_log(core_log)

    exact_ips = leased_global_ips(log_text, EXACT_DOMAIN)
    wildcard_ips = leased_global_ips(log_text, WILDCARD_NAME)
    apex_ips = leased_global_ips(log_text, APEX_DOMAIN)
    deny_ips = leased_global_ips(log_text, DENY_DOMAIN)
    queried = all(received_request_logged(log_text, name)
                  for name in (EXACT_DOMAIN, WILDCARD_NAME, APEX_DOMAIN,
                               DENY_DOMAIN))

    result('P2 精确域名放行', 'PASS' if exact_ips else 'FAIL',
           '%s 租约 %s' % (EXACT_DOMAIN, sorted(exact_ips) or '无'))
    result('P3 通配子域名放行', 'PASS' if wildcard_ips else 'FAIL',
           '%s 由 %s 覆盖,租约 %s' % (WILDCARD_NAME, WILDCARD_ENTRY,
                                        sorted(wildcard_ips) or '无'))
    result('P4 通配不含裸域', 'PASS' if not apex_ips else 'FAIL',
           '%s 未租约真实 IP(%s)' % (APEX_DOMAIN, sorted(apex_ips) or '空'))
    result('P5 默认拒绝', 'PASS' if not deny_ips and queried else 'FAIL',
           '%s 未租约真实 IP(%s);查询覆盖 %s'
           % (DENY_DOMAIN, sorted(deny_ips) or '空',
              '完整' if queried else '不完整'))
    stop_core(stop1, core_log)
    result('P6 阶段1干净退出', 'PASS'
           if 'FakeNet-NG exiting: rc=0' in
           acceptance.read_core_log(core_log) else 'FAIL', 'rc=0 停止旗标')

    # -- Phase 2: takeover with multiple domains -----------------------------
    print('\n== 阶段 2:私网接管(多域名)==')
    config2 = os.path.join(LOG_DIR, 'policy2.ini')
    model2, errors2 = build_policy_config(config2, domains,
                                          takeover_ip=TAKEOVER_SINK)
    if errors2:
        result('P7 阶段2配置', 'FAIL', '校验错误: %s' % errors2[0].message)
        return finish()
    stop2 = os.path.join(LOG_DIR, 'stop2.flag')
    core_log2, ready2 = run_core_phase('phase2', config2,
                                       'DOMAIN_TAKEOVER_READY', stop2)
    if core_log2 is None:
        return finish()
    if not ready2:
        result('P7 接管就绪', 'FAIL', '60 秒内未见 DOMAIN_TAKEOVER_READY')
        stop_core(stop2, core_log2)
        return finish()

    log2 = acceptance.read_core_log(core_log2)
    ready_domains = takeover_ready_domains(log2) or ''
    both = (EXACT_DOMAIN in ready_domains and
            WILDCARD_ENTRY in ready_domains)
    result('P7 接管就绪', 'PASS' if both else 'FAIL',
           'DOMAIN_TAKEOVER_READY 清单: %s' % (ready_domains or '缺失'))

    apex_answers = set()
    for _ in range(3):
        apex_answers = nslookup_addresses(APEX_DOMAIN)
        if apex_answers:
            break
        time.sleep(2)
    nslookup_addresses(WILDCARD_NAME)
    acceptance.wait_for(
        lambda: leased_global_ips(
            acceptance.read_core_log(core_log2), WILDCARD_NAME), 30)
    time.sleep(3)
    log2 = acceptance.read_core_log(core_log2)

    sink_answered = TAKEOVER_SINK in apex_answers
    no_real_apex = not leased_global_ips(log2, APEX_DOMAIN)
    result('P8 接管裸域导向 sink', 'PASS' if sink_answered and no_real_apex
           else 'FAIL',
           '%s 应答 %s(含 sink %s: %s)' % (
               APEX_DOMAIN, sorted(apex_answers) or '无', TAKEOVER_SINK,
               sink_answered))
    wildcard2 = leased_global_ips(log2, WILDCARD_NAME)
    result('P9 接管通配放行', 'PASS' if wildcard2 else 'FAIL',
           '%s 租约 %s' % (WILDCARD_NAME, sorted(wildcard2) or '无'))

    import run_vm_diagnostics as diagnostic
    target_ok, target = diagnostic.probe_fnpr_transports(
        FNPR_NONCE, 'target', timeout=5.0)
    acceptance.wait_for(
        lambda: 'ALLOW_TAKEOVER_SINK' in
        acceptance.read_core_log(core_log2), 10)
    log2b = acceptance.read_core_log(core_log2)
    sink_allowed = ('ALLOW_TAKEOVER_SINK' in log2b and
                    'ip=%s' % TAKEOVER_SINK in log2b)
    sink_diverted = divert_fake_logged(log2b, TAKEOVER_SINK)
    result('P15 接管 sink 连通',
           'PASS' if target_ok and sink_allowed and not sink_diverted
           else 'FAIL',
           'nonce=%s;TCP=%s;UDP=%s;ALLOW_TAKEOVER_SINK=%s;'
           '本地DIVERT_FAKE=%s' % (
               FNPR_NONCE, target['tcp']['ok'], target['udp']['ok'],
               sink_allowed, sink_diverted))
    exercise_acc008_negative_matrix(core_log2, FNPR_NONCE)
    stop_core(stop2, core_log2)
    result('P10 阶段2干净退出', 'PASS'
           if 'FakeNet-NG exiting: rc=0' in
           acceptance.read_core_log(core_log2) else 'FAIL', 'rc=0 停止旗标')

    # -- Phase 3: unknown-IPv4 fallback (v1.29 12.32.1) ----------------------
    print('\n== 阶段 3:未知公网 IPv4 直连兜底 + 裸解析器 DNS ==')
    config3 = os.path.join(LOG_DIR, 'policy3.ini')
    model3, errors3 = build_policy_config(
        config3, domains, takeover_ip=TAKEOVER_SINK, dump_packets=True)
    if errors3:
        result('P11 阶段3配置', 'FAIL', '校验错误: %s' % errors3[0].message)
        return finish()
    stop3 = os.path.join(LOG_DIR, 'stop3.flag')
    core_log3, ready3 = run_core_phase('phase3', config3,
                                       'DOMAIN_TAKEOVER_READY', stop3)
    if core_log3 is None:
        return finish()
    if not ready3:
        result('P11 接管就绪', 'FAIL', '60 秒内未见 DOMAIN_TAKEOVER_READY')
        stop_core(stop3, core_log3)
        return finish()

    connected, probe_sport, received = probe_direct_ipv4_sport(
        UNREVIEWED_IPV4, UNREVIEWED_PORT)
    bare_answers = set()
    for _ in range(3):
        bare_answers = nslookup_addresses(DENY_DOMAIN, BARE_RESOLVER)
        if bare_answers:
            break
        time.sleep(2)
    time.sleep(3)
    log3 = acceptance.read_core_log(core_log3)

    diverted = divert_fake_logged(log3, UNREVIEWED_IPV4)
    not_reviewed = not reviewed_allow_logged(log3, UNREVIEWED_IPV4)
    result('P11 未知IPv4直连兜底', 'PASS'
           if connected and diverted and not_reviewed else 'FAIL',
           '%s:%d 连接=%s 收到%d字节;DIVERT_FAKE=%s;误放行=%s'
           % (UNREVIEWED_IPV4, UNREVIEWED_PORT, connected, received,
              diverted, not not_reviewed))
    only_sink = answers_only_sink(bare_answers, TAKEOVER_SINK)
    bare_logged = received_request_logged(log3, DENY_DOMAIN)
    result('P12 裸解析器DNS拦截', 'PASS' if only_sink and bare_logged
           else 'FAIL',
           'nslookup %s %s 应答 %s(仅 sink=%s);查询到达本机监听=%s'
           % (DENY_DOMAIN, BARE_RESOLVER, sorted(bare_answers) or '无',
              only_sink, bare_logged))
    stop_core(stop3, core_log3)
    result('P13 阶段3干净退出', 'PASS'
           if 'FakeNet-NG exiting: rc=0' in
           acceptance.read_core_log(core_log3) else 'FAIL', 'rc=0 停止旗标')

    # P14 (plan 2026.08.21-01 §5.2): the phase-3 dual pcap must contain
    # BOTH directions — outbound packets to the probe target (sample->C2)
    # and inbound TCP packets to the probe's source port (C2->sample).
    import glob as _glob
    pcaps = [path for path in _glob.glob(
        os.path.join(LOG_DIR, 'packets_*.pcap'))
        if not path.endswith('-converted.pcap')]
    p14_detail = '未找到 pcap'
    p14_ok = False
    if pcaps and probe_sport:
        newest = max(pcaps, key=os.path.getmtime)
        try:
            outbound, inbound = parse_pcap_direction_counts(
                newest, UNREVIEWED_IPV4, probe_sport)
            p14_ok = outbound > 0 and inbound > 0
            p14_detail = ('%s 出站(dst=%s)=%d 入站(dport=%d)=%d'
                          % (os.path.basename(newest), UNREVIEWED_IPV4,
                             outbound, probe_sport, inbound))
        except Exception as exc:  # dpkt 解析失败按 FAIL 处理,不静默
            p14_detail = 'pcap 解析失败: %s' % exc
    result('P14 PCAP 双向捕获', 'PASS' if p14_ok else 'FAIL', p14_detail)

    return finish()


if __name__ == '__main__':
    sys.exit(main())
