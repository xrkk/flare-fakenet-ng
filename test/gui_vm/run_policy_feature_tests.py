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

Start via Run-Policy-Tests.cmd (self-elevates). The runner refuses on
physical machines and unknown VM state, launches the core with generated
configs (GUI writer + validator agreement), triggers nslookup queries
against the local DNS listener and evaluates the core log. Exit codes:
0 = all PASS, 1 = any FAIL, 2 = REFUSED (precondition).
"""

import ipaddress
import os
import re
import subprocess
import sys
import time

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

EXACT_DOMAIN = 'api.deepseek.com'
WILDCARD_ENTRY = '*.deepseek.com'
WILDCARD_NAME = 'www.deepseek.com'
APEX_DOMAIN = 'deepseek.com'
DENY_DOMAIN = 'example.com'
TAKEOVER_SINK = '192.168.204.1'


def result(name, status, detail, level='实测'):
    RESULTS.append((status, name, detail, level))
    print('  [%s] %-28s %s' % (status, name, detail))


def build_policy_config(path, domains, takeover_ip=None):
    """GUI writer + validator agreement for a full egress-policy config."""
    model = configmodel.ConfigModel.new_config()
    model.fakenet().set('DivertTraffic', 'Yes')
    diverter = model.diverter()
    diverter.set('ExternalAccessPolicy', 'EgressControl')
    diverter.set('ExternalAllowedDomains', domains)
    diverter.set('ExternalDnsServer', 'Auto')
    diverter.set('DumpPackets', 'No')
    # the GUI writes these enforced values on policy activation; the
    # validator requires them to be explicit in a generated config too
    for key, value in validator.schema.LOCKED_FIELD_VALUES.items():
        diverter.set(key, value)
    if takeover_ip:
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
    acceptance.kill_leftover_processes()
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
    global LOG_DIR

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
    stop_core(stop2, core_log2)
    result('P10 阶段2干净退出', 'PASS'
           if 'FakeNet-NG exiting: rc=0' in
           acceptance.read_core_log(core_log2) else 'FAIL', 'rc=0 停止旗标')

    return finish()


if __name__ == '__main__':
    sys.exit(main())
