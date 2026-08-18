# -*- coding: utf-8 -*-
"""Validation rule engine (plan v0.2 §5.3).

Consumes a ConfigModel and returns Issue objects; non-empty error list
disables the launch button in the GUI. fakenet itself remains the final
authority at startup — this engine only front-loads the checks that the
diverter / listeners / egresspolicy perform (dual-source design, anchored
by test_gui_schema.py and the end-to-end profile test there).
"""

import ipaddress
import os
import re

from fakenet.gui import configmodel
from fakenet.gui import schema

ERROR = 'error'
WARNING = 'warning'

PLACEHOLDER_RE = re.compile(r'^__[A-Z0-9_]+__$')
EXECUTE_CMD_TOKEN_RE = re.compile(r'\{([a-z_]+)\}')
EXECUTE_CMD_ALLOWED = frozenset((
    'pid', 'procname', 'src_addr', 'src_port', 'dst_addr', 'dst_port'))
ABSOLUTE_WINDOWS_PATH_RE = re.compile(r'^[A-Za-z]:\\.+$')
SHA256_RE = re.compile(r'^[0-9a-fA-F]{64}$')

GETBOOLEAN_TRUE = frozenset(('1', 'yes', 'true', 'on'))
GETBOOLEAN_FALSE = frozenset(('0', 'no', 'false', 'off'))
FUZZY_TRUE = frozenset(('yes', 'on', 'true', 'enable', 'enabled'))

DIVERTER_RESERVED = ('FakeNet', 'Diverter')


class Issue(object):
    def __init__(self, level, section, key, message):
        self.level = level
        self.section = section
        self.key = key
        self.message = message

    @property
    def location(self):
        if self.section and self.key:
            return '[%s] %s' % (self.section, self.key)
        return '[%s]' % self.section if self.section else '-'

    def __repr__(self):
        return '<%s %s: %s>' % (self.level, self.location, self.message)


def _is_enabled(sec):
    value = (sec.get('Enabled') or '').strip().lower()
    return value in GETBOOLEAN_TRUE


def _is_yes(value):
    return (value or '').strip().lower() in FUZZY_TRUE


def _policy_active(model):
    diverter = model.diverter()
    return schema.egress_policy_enabled(
        diverter.get('ExternalAccessPolicy') or 'Disabled')


def _takeover_ip(model):
    return (model.diverter().get('ExternalTakeoverIPv4') or '').strip()


def _enabled_listeners(model):
    return [sec for sec in model.listener_sections() if _is_enabled(sec)]


def _expanded_bindings(sec):
    """[(protocol, port)] after fakenet-style port expansion."""
    protocol = (sec.get('Protocol') or '').strip().upper()
    ports = configmodel.expand_ports(sec.get('Port') or '')
    return [(protocol, port) for port in ports]


# ---------------------------------------------------------------------------
# Rule 1: section naming
# ---------------------------------------------------------------------------

def _check_section_names(model, issues):
    for name in model.sections:
        if name in DIVERTER_RESERVED:
            continue
        if name.lower() in ('fakenet', 'diverter'):
            issues.append(Issue(
                ERROR, name, '',
                '段名大小写错误:必须精确为 [%s](fakenet 将本段当作监听器段,'
                '会因缺少 Enabled 键崩溃)' % name.title()))


# ---------------------------------------------------------------------------
# Rule 2: listener section structure
# ---------------------------------------------------------------------------

def _check_listener_structure(model, issues):
    expanded_names = {}
    bindings = {}
    for sec in model.listener_sections():
        issues.extend(_check_listener_section(sec))
        for name in model.expanded_listener_names(sec):
            prior = expanded_names.get(name.lower())
            if prior and prior != sec.name:
                issues.append(Issue(
                    ERROR, sec.name, 'Port',
                    '端口展开实例 %r 与段 [%s] 冲突' % (name, prior)))
            expanded_names[name.lower()] = sec.name
        if _is_enabled(sec):
            for protocol, port in _expanded_bindings(sec):
                prior = bindings.get((protocol, port))
                if prior and prior != sec.name:
                    issues.append(Issue(
                        ERROR, sec.name, 'Port',
                        '已启用监听器与 [%s] 重复绑定 %s/%d(fakenet 运行时 '
                        'bind 失败即整体退出,fakenet.py:266-274)'
                        % (prior, protocol, port)))
                bindings[(protocol, port)] = sec.name
    return bindings


def _check_listener_section(sec):
    issues = []
    enabled = sec.get('Enabled')
    if enabled is None:
        issues.append(Issue(
            ERROR, sec.name, 'Enabled',
            '缺少 Enabled 键(fakenet.py:108 读取时直接抛 NoOptionError)'))
    elif enabled.strip().lower() not in (GETBOOLEAN_TRUE | GETBOOLEAN_FALSE):
        issues.append(Issue(
            ERROR, sec.name, 'Enabled',
            'Enabled 值 %r 不被 configparser.getboolean 接受'
            '(仅 1/yes/true/on/0/no/false/off)' % enabled))

    port = sec.get('Port')
    if port is None or str(port).strip() == '':
        issues.append(Issue(ERROR, sec.name, 'Port', '缺少 Port 键'))
    else:
        try:
            ports = configmodel.expand_ports(port)
            if not ports:
                raise ValueError('empty')
            bad = [p for p in ports if not 1 <= p <= 65535]
            if bad:
                issues.append(Issue(
                    ERROR, sec.name, 'Port',
                    '端口 %r 超出 1-65535' % bad))
        except ValueError:
            issues.append(Issue(
                ERROR, sec.name, 'Port', '端口 %r 无法解析(支持 80 / 80,81 '
                '/ 60000-60010)' % port))

    protocol = (sec.get('Protocol') or '').strip()
    if not protocol:
        issues.append(Issue(ERROR, sec.name, 'Protocol', '缺少 Protocol 键'))
    elif protocol.upper() not in ('TCP', 'UDP'):
        issues.append(Issue(
            ERROR, sec.name, 'Protocol',
            'Protocol 必须为 TCP 或 UDP(当前 %r)' % protocol))

    listener = (sec.get('Listener') or '').strip()
    if listener and listener not in schema.LISTENER_CLASSES:
        issues.append(Issue(
            ERROR, sec.name, 'Listener',
            '监听器类型 %r 不存在(大小写敏感,可用: %s)'
            % (listener, ', '.join(schema.LISTENER_CLASSES))))
    return issues


# ---------------------------------------------------------------------------
# Rule 3: exclusivity, redirect defaults, [FakeNet]
# ---------------------------------------------------------------------------

def _check_exclusivity(model, issues):
    def check_list_pairs(holder, label):
        white = (holder.get('ProcessWhiteList') or '').strip()
        black = (holder.get('ProcessBlackList') or '').strip()
        if white and black:
            issues.append(Issue(
                ERROR, label, 'ProcessWhiteList/ProcessBlackList',
                '进程白/黑名单互斥(同时存在时 fakenet 启动即退出)'))
        white = (holder.get('HostWhiteList') or '').strip()
        black = (holder.get('HostBlackList') or '').strip()
        if white and black:
            issues.append(Issue(
                ERROR, label, 'HostWhiteList/HostBlackList',
                '主机白/黑名单互斥(同时存在时 fakenet 启动即退出)'))

    check_list_pairs(model.diverter(), 'Diverter')
    for sec in model.listener_sections():
        check_list_pairs(sec, sec.name)


def _check_redirect_defaults(model, issues):
    diverter = model.diverter()
    if not _is_yes(diverter.get('RedirectAllTraffic')):
        return
    expanded = set()
    for sec in model.listener_sections():
        for name in model.expanded_listener_names(sec):
            expanded.add(name.lower())
    for key in ('DefaultTCPListener', 'DefaultUDPListener'):
        value = (diverter.get(key) or '').strip()
        if not value:
            issues.append(Issue(
                ERROR, 'Diverter', key,
                'RedirectAllTraffic 开启时必须填写(值为监听器段名)'))
        elif value.lower() not in expanded:
            issues.append(Issue(
                ERROR, 'Diverter', key,
                '值 %r 不是已存在的监听器段名(端口区间段会展开为 '
                '"段名_端口" 实例名)' % value))


def _check_fakenet(model, issues):
    value = (model.fakenet().get('DivertTraffic') or 'No').strip()
    if value.lower() == 'yes':
        mode = (model.diverter().get('NetworkMode') or '').strip().lower()
        if mode not in ('singlehost', 'multihost', 'auto'):
            issues.append(Issue(
                ERROR, 'Diverter', 'NetworkMode',
                'DivertTraffic=Yes 时必须为 SingleHost/MultiHost/Auto'))


# ---------------------------------------------------------------------------
# Rule 4: EgressControl policy core
# ---------------------------------------------------------------------------

def _usable_unicast_ipv4(text):
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.version != 4:
        return None
    if (address.is_loopback or address.is_link_local or
            address.is_multicast or address.is_unspecified or
            address.is_reserved):
        return None
    return address


def _is_rfc1918(address):
    return address.is_private and not (
        address.is_loopback or address.is_link_local)


def _is_global_unicast(address):
    return (not address.is_private and not address.is_loopback and
            not address.is_link_local and not address.is_multicast and
            not address.is_reserved and not address.is_unspecified)


def _valid_hostname(domain):
    try:
        domain.encode('idna')
    except UnicodeError:
        return False
    if not domain or len(domain) > 253:
        return False
    if re.search(r'[:/@*?\\]', domain):
        return False
    labels = domain.rstrip('.').split('.')
    return all(0 < len(label) <= 63 for label in labels)


def _check_policy_core(model, issues):
    diverter = model.diverter()
    divert = (model.fakenet().get('DivertTraffic') or 'No').strip()
    if divert.lower() != 'yes':
        issues.append(Issue(
            ERROR, 'FakeNet', 'DivertTraffic',
            '出站策略启用时要求 DivertTraffic=Yes(代码只认小写比较 '
            "'yes')"))

    for key, expected in schema.LOCKED_FIELD_VALUES.items():
        value = diverter.get(key)
        if value is None or not str(value).strip():
            # egresspolicy applies its own defaults when a key is absent,
            # and those defaults equal the reviewed values — except
            # ExternalAllowedTCPPorts, whose source default is empty and
            # therefore must be present with 443 while the policy is on.
            if key == 'ExternalAllowedTCPPorts':
                issues.append(Issue(
                    ERROR, 'Diverter', key,
                    '出站策略启用时要求显式为 %r(缺省即被 '
                    'egresspolicy 拒绝)' % expected))
                continue
            field = schema.diverter_field(key)
            value = field.default
        value = str(value).strip()
        field = schema.diverter_field(key)
        if field.wtype == schema.T_INT:
            try:
                ok = int(value) == int(expected)
            except ValueError:
                ok = False
        else:
            ok = value.lower() == expected.lower()
        if not ok:
            issues.append(Issue(
                ERROR, 'Diverter', key,
                '代码强制值 %r(当前 %r),启动时 egresspolicy 将直接拒绝'
                % (expected, value)))

    domains = [d.strip() for d in
               (diverter.get('ExternalAllowedDomains') or '').split(',')
               if d.strip()]
    if not domains:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalAllowedDomains',
            '出站策略启用时必填'))
    for domain in domains:
        candidate = domain[2:] if domain.startswith('*.') else domain
        if not _valid_hostname(candidate) or (
                domain.startswith('*.') and not candidate):
            issues.append(Issue(
                ERROR, 'Diverter', 'ExternalAllowedDomains',
                '域名 %r 不合法(须为不带 scheme/端口/路径的主机名,'
                '或 *.域名 形式的前导通配)' % domain))

    dns_server = (diverter.get('ExternalDnsServer') or 'Auto').strip()
    if dns_server.lower() != 'auto':
        if _usable_unicast_ipv4(dns_server) is None:
            issues.append(Issue(
                ERROR, 'Diverter', 'ExternalDnsServer',
                '必须为 Auto 或可用的单播 IPv4(当前 %r)' % dns_server))

    timeout = (diverter.get('ExternalDnsTimeout') or '3').strip()
    try:
        if not 1 <= int(timeout) <= 30:
            raise ValueError
    except ValueError:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalDnsTimeout',
            '须为 1-30 之间的整数秒'))

    try:
        relay_port = int((diverter.get('ExternalRelayPort') or
                          '38927').strip())
        if not 1 <= relay_port <= 65535:
            raise ValueError
    except ValueError:
        relay_port = None
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalRelayPort', '须为 1-65535'))

    issues.extend(_check_policy_topology(model, relay_port))
    return relay_port


def _check_policy_topology(model, relay_port):
    issues = []
    enabled = _enabled_listeners(model)
    relays = [sec for sec in enabled
              if (sec.get('Listener') or '') == 'DomainEgressRelay']
    if len(relays) != 1:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalAccessPolicy',
            '拓扑要求恰好 1 个已启用的 DomainEgressRelay 监听器段'
            '(当前 %d 个)' % len(relays)))
    else:
        relay = relays[0]
        if (relay.get('Protocol') or '').upper() != 'TCP':
            issues.append(Issue(
                ERROR, relay.name, 'Protocol',
                'DomainEgressRelay 监听器必须为 TCP'))
        try:
            port = int(str(relay.get('Port')).strip())
            if relay_port is not None and port != relay_port:
                issues.append(Issue(
                    ERROR, relay.name, 'Port',
                    '必须等于 ExternalRelayPort=%d(当前 %d)'
                    % (relay_port, port)))
        except ValueError:
            pass  # already reported by structure rules

    dns_udp = dns_tcp = 0
    for sec in enabled:
        if (sec.get('Listener') or '') != 'DNSListener':
            continue
        try:
            ports = configmodel.expand_ports(sec.get('Port') or '')
        except ValueError:
            continue
        if 53 not in ports:
            continue
        if (sec.get('Protocol') or '').upper() == 'UDP':
            dns_udp += 1
        elif (sec.get('Protocol') or '').upper() == 'TCP':
            dns_tcp += 1
    if dns_udp != 1 or dns_tcp != 1:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalAccessPolicy',
            '拓扑要求恰好 2 个已启用、端口 53 的 DNSListener 监听器'
            '(一个 UDP 一个 TCP;当前 UDP=%d TCP=%d)' % (dns_udp, dns_tcp)))

    if relay_port is not None:
        for sec in enabled:
            if (sec.get('Listener') or '') == 'DomainEgressRelay':
                continue
            try:
                bindings = _expanded_bindings(sec)
            except ValueError:
                continue
            if any(port == relay_port for _, port in bindings):
                issues.append(Issue(
                    ERROR, sec.name, 'Port',
                    '不得占用 TLS 中继端口 %d(ExternalRelayPort)'
                    % relay_port))
    return issues


# ---------------------------------------------------------------------------
# Rule 5: takeover sub-policy
# ---------------------------------------------------------------------------

def _check_takeover(model, issues):
    diverter = model.diverter()
    takeover_keys = (
        'ExternalTakeoverIPv4', 'ExternalTakeoverDnsTTL',
        'ExternalTakeoverProbeTCPPorts',
        'ExternalTakeoverProbeTimeoutMs')
    requested = 'ExternalTakeoverIPv4' in diverter
    orphaned = [key for key in takeover_keys[1:] if key in diverter]
    if not requested:
        for key in orphaned:
            issues.append(Issue(
                ERROR, 'Diverter', key,
                '须先启用“将其他域名导向私网分析主机”'))
        return None
    sink_text = _takeover_ip(model)
    if not sink_text:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalTakeoverIPv4',
            '启用后必须填写私网分析主机 IPv4'))
        return None
    try:
        sink = ipaddress.ip_address(sink_text)
    except ValueError:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalTakeoverIPv4',
            '须为一个点分十进制 IPv4 地址(当前 %r)' % sink_text))
        return None
    if sink.version != 4 or not _is_rfc1918(sink):
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalTakeoverIPv4',
            '须为 RFC1918 私网 IPv4(当前 %r)' % sink_text))
        return None

    dns_server = (diverter.get('ExternalDnsServer') or '').strip()
    if dns_server.lower() != 'auto' and dns_server == sink_text:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalTakeoverIPv4',
            '不得等于 ExternalDnsServer'))

    ttl = (diverter.get('ExternalTakeoverDnsTTL') or '').strip()
    try:
        if not 1 <= int(ttl) <= 300:
            raise ValueError
    except ValueError:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalTakeoverDnsTTL',
            '接管启用时必填,且为 1-300 秒'))

    probe_ports = (diverter.get('ExternalTakeoverProbeTCPPorts') or '').strip()
    if probe_ports:
        try:
            ports = configmodel.expand_ports(probe_ports)
            if len(ports) > 64 or any(not 1 <= p <= 65535 for p in ports):
                raise ValueError
        except ValueError:
            issues.append(Issue(
                ERROR, 'Diverter', 'ExternalTakeoverProbeTCPPorts',
                '须为最多 64 个 1-65535 的端口(可留空)'))

    timeout = (diverter.get('ExternalTakeoverProbeTimeoutMs') or
               '500').strip()
    try:
        if not 100 <= int(timeout) <= 5000:
            raise ValueError
    except ValueError:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalTakeoverProbeTimeoutMs',
            '须为 100-5000 毫秒'))

    action = (diverter.get('ExternalNonAllowedAction') or
              'Divert').strip().lower()
    if action != 'divert':
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalNonAllowedAction',
            '接管模式要求 Divert'))

    for sec in _enabled_listeners(model):
        if (sec.get('Listener') or '') != 'DNSListener':
            continue
        try:
            if 53 not in configmodel.expand_ports(sec.get('Port') or ''):
                continue
        except ValueError:
            continue
        response = (sec.get('ResponseA') or '').strip()
        if response and response != sink_text:
            issues.append(Issue(
                ERROR, sec.name, 'ResponseA',
                '接管模式要求等于 ExternalTakeoverIPv4=%s(当前 %r)'
                % (sink_text, response)))
    return sink


# ---------------------------------------------------------------------------
# Rule 6: reviewed public IPv4 rules
# ---------------------------------------------------------------------------

def _check_reviewed_rules(model, issues):
    diverter = model.diverter()
    raw = diverter.get('ExternalAllowedIPv4Rules')
    if raw is None:
        return
    rules = [r.strip() for r in raw.split(',') if r.strip()]
    if not rules:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalAllowedIPv4Rules',
            '键存在但为空即配置错误——不使用时请整行删除'))
        return
    if len(rules) > 32:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalAllowedIPv4Rules',
            '最多 32 条(当前 %d)' % len(rules)))
    seen_rules = set()
    seen_ips = set()
    for rule in rules:
        if rule in seen_rules:
            issues.append(Issue(
                ERROR, 'Diverter', 'ExternalAllowedIPv4Rules',
                '重复规则 %r' % rule))
            continue
        seen_rules.add(rule)
        parts = rule.split('/')
        if len(parts) != 3:
            issues.append(Issue(
                ERROR, 'Diverter', 'ExternalAllowedIPv4Rules',
                '规则 %r 须为 协议/IPv4/端口 三段式' % rule))
            continue
        proto, raw_ip, port = (part.strip() for part in parts)
        if proto.upper() not in ('TCP', 'UDP'):
            issues.append(Issue(
                ERROR, 'Diverter', 'ExternalAllowedIPv4Rules',
                '规则 %r 协议须为 TCP 或 UDP' % rule))
        try:
            address = ipaddress.ip_address(raw_ip)
        except ValueError:
            issues.append(Issue(
                ERROR, 'Diverter', 'ExternalAllowedIPv4Rules',
                '规则 %r 的 IPv4 不合法' % rule))
            continue
        if address.version != 4 or not _is_global_unicast(address):
            issues.append(Issue(
                ERROR, 'Diverter', 'ExternalAllowedIPv4Rules',
                '规则 %r 须为全球单播 IPv4(RFC1918/环回等不允许)' % rule))
        if port != '*':
            try:
                if not 1 <= int(port) <= 65535:
                    raise ValueError
            except ValueError:
                issues.append(Issue(
                    ERROR, 'Diverter', 'ExternalAllowedIPv4Rules',
                    '规则 %r 端口须为 * 或 1-65535' % rule))
        seen_ips.add(raw_ip)
    if len(seen_ips) > 16:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalAllowedIPv4Rules',
            '最多 16 个不同 IPv4(当前 %d)' % len(seen_ips)))


# ---------------------------------------------------------------------------
# Rule 7: process redirect
# ---------------------------------------------------------------------------

def _check_process_redirect(model, issues, takeover_sink):
    diverter = model.diverter()
    if not _is_yes(diverter.get('ExternalProcessRedirectEnabled')):
        return
    required = (
        'ExternalProcessRedirectProtocol',
        'ExternalProcessRedirectImagePath',
        'ExternalProcessRedirectImageSHA256',
        'ExternalProcessRedirectOriginalIPv4',
        'ExternalProcessRedirectTargetIPv4',
    )
    for key in required:
        if not (diverter.get(key) or '').strip():
            issues.append(Issue(
                ERROR, 'Diverter', key,
                '进程重定向启用时必填(fail-closed)'))

    image_path = (diverter.get('ExternalProcessRedirectImagePath') or
                  '').strip()
    if image_path:
        if not ABSOLUTE_WINDOWS_PATH_RE.match(image_path):
            issues.append(Issue(
                ERROR, 'Diverter', 'ExternalProcessRedirectImagePath',
                '须为绝对盘符路径(禁 UNC/ADS/通配)'))
        elif not os.path.isfile(image_path):
            issues.append(Issue(
                ERROR, 'Diverter', 'ExternalProcessRedirectImagePath',
                '文件不存在: %s' % image_path))

    sha256 = (diverter.get('ExternalProcessRedirectImageSHA256') or
              '').strip()
    if sha256 and not SHA256_RE.match(sha256):
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalProcessRedirectImageSHA256',
            '须为 64 位十六进制 SHA-256'))

    original = (diverter.get('ExternalProcessRedirectOriginalIPv4') or
                '').strip()
    target = (diverter.get('ExternalProcessRedirectTargetIPv4') or
              '').strip()
    addr_a = _usable_unicast_ipv4(original) if original else None
    if original and (addr_a is None or addr_a.is_private):
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalProcessRedirectOriginalIPv4',
            'A 须为全球单播 IPv4(当前 %r)' % original))
    addr_b = _usable_unicast_ipv4(target) if target else None
    if target and (addr_b is None or not _is_rfc1918(addr_b)):
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalProcessRedirectTargetIPv4',
            'B 须为可用 RFC1918 IPv4(当前 %r)' % target))
    if original and target and original == target:
        issues.append(Issue(
            ERROR, 'Diverter', 'ExternalProcessRedirectTargetIPv4',
            'B 不得等于 A'))

    dns_server = (diverter.get('ExternalDnsServer') or '').strip()
    for key_name, value in (('ExternalProcessRedirectOriginalIPv4', original),
                            ('ExternalProcessRedirectTargetIPv4', target)):
        if value and dns_server.lower() != 'auto' and value == dns_server:
            issues.append(Issue(
                ERROR, 'Diverter', key_name,
                '不得等于 ExternalDnsServer'))
        if value and takeover_sink is not None and value == str(takeover_sink):
            issues.append(Issue(
                ERROR, 'Diverter', key_name,
                '不得等于接管 sink IPv4'))


# ---------------------------------------------------------------------------
# Rule 8: general values (placeholders, escapes, ExecuteCmd, paths)
# ---------------------------------------------------------------------------

def _check_values(model, issues):
    sections = ([model.fakenet(), model.diverter()] +
                model.listener_sections())
    for sec in sections:
        for key, value in sec.items():
            value = value or ''
            if PLACEHOLDER_RE.match(value.strip()):
                issues.append(Issue(
                    ERROR, sec.name, key,
                    '模板占位符 %r —— 请填入实际值' % value.strip()))
            if PLACEHOLDER_RE.match(key):
                issues.append(Issue(
                    ERROR, sec.name, key, '键名为模板占位符,请重命名'))
            if '%' in value:
                issues.append(Issue(
                    WARNING, sec.name, key,
                    '值包含 % 字符:本工具保存时将转义为 %%;若当前文件'
                    '未经本工具保存,fakenet 读取时可能插值崩溃'))
            try:
                value.encode('ascii')
            except UnicodeEncodeError:
                issues.append(Issue(
                    WARNING, sec.name, key,
                    '值含非 ASCII 字符:fakenet 按系统区域编码读取,可能乱码'))
            if key.lower() == 'executecmd':
                for token in EXECUTE_CMD_TOKEN_RE.findall(value):
                    if token not in EXECUTE_CMD_ALLOWED:
                        issues.append(Issue(
                            ERROR, sec.name, key,
                            '占位符 {%s} 不合法(可用: %s)'
                            % (token, ', '.join(sorted(EXECUTE_CMD_ALLOWED)))))

    if model.bom:
        issues.append(Issue(
            WARNING, '', '',
            '文件带 UTF-8 BOM:中文系统上 fakenet 以 GBK 读取时 BOM 会混入'
            '首段名导致解析错乱'))

    diverter = model.diverter()
    if _is_yes(diverter.get('DumpPackets')) and not \
            (diverter.get('DumpPacketsFilePrefix') or '').strip():
        issues.append(Issue(
            WARNING, 'Diverter', 'DumpPacketsFilePrefix',
            'DumpPackets 开启但未设置前缀,运行时将使用默认值 packets'))

    for sec in model.listener_sections():
        for key in ('Webroot', 'FTProot', 'TFTPRoot', 'Custom', 'CA_Cert',
                    'CA_Key'):
            value = (sec.get(key) or '').strip()
            if not value:
                continue
            if os.path.isabs(value):
                candidates = [value]
            else:
                candidates = [value]
                if model.path:
                    candidates.append(
                        os.path.join(os.path.dirname(model.path), value))
            if not any(os.path.exists(c) for c in candidates):
                issues.append(Issue(
                    WARNING, sec.name, key,
                    '路径不存在: %s(相对路径相对 fakenet 工作目录或配置目录'
                    '解析,请确认部署布局)' % value))


# ---------------------------------------------------------------------------
# Custom-response file validation (§5.1 custom response schema)
# ---------------------------------------------------------------------------

def validate_custom(model):
    issues = []
    http_body_keys = ('HttpRawFile', 'HttpStaticString', 'HttpDynamic')
    prefixes = {'TCP': ('TcpStaticString', 'TcpStaticBase64', 'TcpRawFile',
                        'TcpDynamic'),
                'UDP': ('UdpStaticString', 'UdpStaticBase64', 'UdpRawFile',
                        'UdpDynamic')}
    for sec in model.sections.values():
        instance = (sec.get('InstanceName') or '').strip()
        listener_type = (sec.get('ListenerType') or '').strip().upper()
        if not instance and not listener_type:
            issues.append(Issue(
                ERROR, sec.name, 'InstanceName',
                '须提供 InstanceName 或 ListenerType 之一'))
        if listener_type and listener_type not in ('HTTP', 'TCP', 'UDP'):
            issues.append(Issue(
                ERROR, sec.name, 'ListenerType', '须为 HTTP/TCP/UDP'))
            continue
        if listener_type == 'HTTP':
            if not ((sec.get('HttpURIs') or '').strip() or
                    (sec.get('HttpHosts') or '').strip()):
                issues.append(Issue(
                    ERROR, sec.name, 'HttpURIs',
                    'HttpURIs 与 HttpHosts 至少其一'))
            chosen = [k for k in http_body_keys if (sec.get(k) or '').strip()]
            if len(chosen) != 1:
                issues.append(Issue(
                    ERROR, sec.name, 'HttpRawFile',
                    '响应体 HttpRawFile/HttpStaticString/HttpDynamic 恰好选一'
                    '(当前 %d 个)' % len(chosen)))
            if (sec.get('ContentType') or '').strip() and \
                    'HttpStaticString' not in chosen:
                issues.append(Issue(
                    ERROR, sec.name, 'ContentType',
                    'ContentType 仅可搭配 HttpStaticString'))
        elif listener_type in prefixes:
            keys = prefixes[listener_type]
            chosen = [k for k in keys if (sec.get(k) or '').strip()]
            if len(chosen) != 1:
                issues.append(Issue(
                    ERROR, sec.name, keys[0],
                    '%s 响应体四选一恰好选一(当前 %d 个)'
                    % (listener_type, len(chosen))))
    return issues


# ---------------------------------------------------------------------------
# Top-level entry points
# ---------------------------------------------------------------------------

def validate(model):
    if model.kind == 'custom':
        return validate_custom(model)
    issues = []
    _check_section_names(model, issues)
    _check_listener_structure(model, issues)
    _check_exclusivity(model, issues)
    _check_redirect_defaults(model, issues)
    _check_fakenet(model, issues)
    takeover_sink = None
    if _policy_active(model):
        _check_policy_core(model, issues)
        takeover_sink = _check_takeover(model, issues)
        _check_reviewed_rules(model, issues)
    else:
        # Sub-policies only take effect under EgressControl, but a
        # configured-but-invalid takeover sink still deserves an error.
        sink_text = _takeover_ip(model)
        if sink_text:
            try:
                sink = ipaddress.ip_address(sink_text)
                if sink.version != 4 or not _is_rfc1918(sink):
                    raise ValueError
            except ValueError:
                issues.append(Issue(
                    ERROR, 'Diverter', 'ExternalTakeoverIPv4',
                    '须为 RFC1918 私网 IPv4(当前 %r)' % sink_text))
    _check_process_redirect(model, issues, takeover_sink)
    _check_values(model, issues)
    return issues


def ensure_egress_control_topology(model):
    """Idempotent automatic provisioning (§12.15): relay + 2x DNS."""
    changes = []
    diverter = model.diverter()
    relay_port = (diverter.get('ExternalRelayPort') or '38927').strip() \
        or '38927'

    relays = [sec for sec in _enabled_listeners(model)
              if (sec.get('Listener') or '') == 'DomainEgressRelay']
    if not relays:
        existing = [sec for sec in model.listener_sections()
                    if (sec.get('Listener') or '') == 'DomainEgressRelay']
        if existing:
            sec = existing[0]
        else:
            sec = model.ensure_section('Domain Egress Relay')
            sec.set('Listener', 'DomainEgressRelay')
            sec.set('Protocol', 'TCP')
            sec.set('Hidden', 'True')
        sec.set('Enabled', 'True')
        sec.set('Port', relay_port)
        changes.append('[%s] 已配置 DomainEgressRelay(TCP/%s)'
                       % (sec.name, relay_port))
    else:
        relay = relays[0]
        if str(relay.get('Port')).strip() != relay_port:
            relay.set('Port', relay_port)
            changes.append('[%s] Port 已同步为 %s' % (relay.name, relay_port))

    sink_text = _takeover_ip(model)
    for protocol, name in (('UDP', 'DNS Server'), ('TCP', 'DNS TCP Server')):
        match = [sec for sec in _enabled_listeners(model)
                 if (sec.get('Listener') or '') == 'DNSListener' and
                 (sec.get('Protocol') or '').upper() == protocol and
                 _port_is(sec, 53)]
        if match:
            sec = match[0]
        else:
            existing = [sec for sec in model.listener_sections()
                        if (sec.get('Listener') or '') == 'DNSListener' and
                        (sec.get('Protocol') or '').upper() == protocol]
            if existing:
                sec = existing[0]
            else:
                sec = model.ensure_section(name)
                sec.set('Listener', 'DNSListener')
                sec.set('Protocol', protocol)
                sec.set('Port', '53')
                sec.set('ResponseMX', 'mail.evil2.com')
                sec.set('ResponseTXT', 'FAKENET')
                sec.set('NXDomains', '0')
                sec.set('Hidden', 'False')
                if protocol == 'TCP':
                    sec.set('Timeout', '5')
                changes.append('[%s] 已创建(%s/53 DNSListener)'
                               % (sec.name, protocol))
            sec.set('Enabled', 'True')
            if not _port_is(sec, 53):
                sec.set('Port', '53')
                changes.append('[%s] Port 已设为 53' % sec.name)
        if sink_text and not (sec.get('ResponseA') or '').strip():
            sec.set('ResponseA', sink_text)
            changes.append('[%s] ResponseA 已填为接管 sink %s'
                           % (sec.name, sink_text))
    return changes


def _port_is(sec, port):
    try:
        return port in configmodel.expand_ports(sec.get('Port') or '')
    except ValueError:
        return False
