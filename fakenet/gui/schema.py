# -*- coding: utf-8 -*-
"""Declarative field catalog for the fakenet-config GUI.

Pure data module: no tkinter and no fakenet core imports (plan v0.2 §4).
Constraint values are anchored to source code and re-verified by
test/test_gui_schema.py:

- resource-limit tuple  == egresspolicy.py:472 ``expected``
- debug labels          == diverters/debuglevels.py DLABELS + 'Off'
- listener class list   == class-bearing modules under fakenet/listeners/
- validation ranges     == egresspolicy.py / processredirect.py / windows.py
"""

# ---------------------------------------------------------------------------
# Widget types (§5.1)
# ---------------------------------------------------------------------------

T_BOOL_YESNO = 'bool_yesno'          # canonical literal Yes/No
T_BOOL_TRUEFALSE = 'bool_truefalse'  # canonical literal True/False
T_INT = 'int'
T_STRING = 'string'
T_ENUM = 'enum'
T_STRINGLIST = 'stringlist'          # comma separated strings
T_INTLIST = 'intlist'                # comma separated ints (BlackListIDsICMP)
T_PORTLIST = 'portlist'              # ints and a-b ranges, comma separated
T_PORTSPEC = 'portspec'              # single port, comma list or a-b range
T_IPV4 = 'ipv4'
T_IPV4_OR_ENUM = 'ipv4_or_enum'      # literal IPv4 or a special token
T_PATH_FILE = 'path_file'
T_PATH_DIR = 'path_dir'
T_HEX64 = 'hex64'
T_TEXT = 'text'

# ---------------------------------------------------------------------------
# Lock rule ids (§5.1).  LOCK_* are unconditional while the DomainAllowList
# policy is active; COND_* activate on an additional condition.
# ---------------------------------------------------------------------------

LOCK_TCP_PORTS_443 = 'LOCK_TCP_PORTS_443'
LOCK_BOOL_YES = 'LOCK_BOOL_YES'      # must be Yes (SNI verify / IPv6 / QUIC)
LOCK_RESOURCE_TUPLE = 'LOCK_RESOURCE_TUPLE'  # 8-tuple pinned by egresspolicy
LOCK_PR_PROTOCOL_TCP = 'LOCK_PR_PROTOCOL_TCP'
COND_TAKEOVER_DOMAINS = 'COND_TAKEOVER_DOMAINS'  # only api.deepseek.com
COND_TAKEOVER_ACTION = 'COND_TAKEOVER_ACTION'    # NonAllowedAction=Divert
COND_TAKEOVER_RESPONSEA = 'COND_TAKEOVER_RESPONSEA'  # DNS ResponseA==sink

# The reviewed resource limits, verbatim from egresspolicy.py:472.
EXPECTED_RESOURCE_TUPLE = (5, 65536, 256, 32, 128, 16, 300, 1048576)
EXPECTED_RESOURCE_KEYS = (
    'ExternalTLSHelloTimeout', 'ExternalTLSHelloMaxBytes',
    'ExternalMaxPendingFlows', 'ExternalMaxPendingPerSource',
    'ExternalMaxActiveRelays', 'ExternalMaxActivePerSource',
    'ExternalRelayIdleTimeout', 'ExternalRelayBufferBytes',
)

# Values hard-pinned while ExternalAccessPolicy=DomainAllowList (§3.3).
LOCKED_FIELD_VALUES = {
    'ExternalAllowedTCPPorts': '443',
    'ExternalVerifyTLSSNI': 'Yes',
    'ExternalBlockExternalIPv6': 'Yes',
    'ExternalBlockQUIC': 'Yes',
    'ExternalProcessRedirectProtocol': 'TCP',
}
for _k in EXPECTED_RESOURCE_KEYS:
    LOCKED_FIELD_VALUES[_k] = str(
        EXPECTED_RESOURCE_TUPLE[EXPECTED_RESOURCE_KEYS.index(_k)])

# DebugLevel vocabulary: debuglevels.py DLABELS (16 tags) plus 'Off'.
DEBUG_LABELS = (
    'Off', 'GENPKT', 'GENPKTV', 'CB', 'NONLOC', 'DPF', 'DPFV', 'IPNAT',
    'MANGLE', 'PCAP', 'IGN', 'FTP', 'IGN-FTP', 'MISC', 'NFQUEUE', 'PROCFS',
    'IPTABLES',
)

LISTENER_CLASSES = (
    'DNSListener', 'DomainEgressRelay', 'FTPListener', 'HTTPListener',
    'IRCListener', 'POPListener', 'ProxyListener', 'RawListener',
    'SMTPListener', 'TFTPListener',
)

# Keys injected by fakenet at runtime; never written to INI (§3.5).
SYSTEM_INJECTED_KEYS = frozenset(('ipaddr', 'configdir', 'networkmode'))

FAKENET_SECTION = 'FakeNet'
DIVERTER_SECTION = 'Diverter'

# RespawnIPv4ResponseA special tokens (DNSListener.py:224,232).
RESPONSEA_TOKENS = ('GetFirstNonLoopback', 'GetHostByName')


class Field(object):
    """One editable configuration key."""

    def __init__(self, key, label, wtype=T_STRING, default='', group='',
                 enum=None, minimum=None, maximum=None, lock=None,
                 cond_lock=None, hint='', dead=False, advanced=False):
        self.key = key
        self.label = label
        self.wtype = wtype
        self.default = default
        self.group = group
        self.enum = tuple(enum) if enum else None
        self.minimum = minimum
        self.maximum = maximum
        self.lock = lock
        self.cond_lock = cond_lock
        self.hint = hint
        self.dead = dead        # documented-but-unread key, editable for fidelity
        self.advanced = advanced  # rarely used, shown in advanced areas

    def __repr__(self):
        return '<Field %s %s>' % (self.key, self.wtype)


# ---------------------------------------------------------------------------
# [FakeNet] section
# ---------------------------------------------------------------------------

FAKENET_FIELDS = (
    Field('DivertTraffic', '劫持流量 (DivertTraffic)', T_BOOL_YESNO,
          default='Yes', group='全局',
          hint='Yes 时 NetworkMode 必填;DomainAllowList 模式强制 Yes'),
)

# ---------------------------------------------------------------------------
# [Diverter] section, six groups (§5.1)
# ---------------------------------------------------------------------------

DIVERTER_FIELDS = (
    # -- 基础 --------------------------------------------------------------
    Field('NetworkMode', '网络模式', T_ENUM, default='SingleHost',
          group='基础', enum=('SingleHost', 'MultiHost', 'Auto'),
          hint='Auto: Windows→SingleHost, Linux→MultiHost'),
    Field('DebugLevel', '调试级别', T_STRINGLIST, default='Off', group='基础',
          enum=DEBUG_LABELS,
          hint='逗号分隔;合法标签: ' + ', '.join(DEBUG_LABELS)),
    # -- 抓包 --------------------------------------------------------------
    Field('DumpPackets', '双 PCAP 抓包', T_BOOL_YESNO, default='Yes',
          group='抓包',
          hint='同步输出 raw-IP 与合成以太网两份 PCAP'),
    Field('DumpPacketsFilePrefix', 'PCAP 文件前缀', T_STRING,
          default='packets', group='抓包'),
    # -- DNS 与网关修复 ----------------------------------------------------
    Field('FixGateway', '自动修复网关', T_BOOL_YESNO, default='Yes',
          group='DNS与网关'),
    Field('FixDNS', '自动修复 DNS', T_BOOL_YESNO, default='Yes',
          group='DNS与网关'),
    Field('ModifyLocalDNS', '修改本地 DNS', T_BOOL_YESNO, default='Yes',
          group='DNS与网关',
          hint='Windows 改注册表;Linux 临时改 /etc/resolv.conf'),
    Field('StopDNSService', '停止 DNS 客户端服务', T_BOOL_YESNO,
          default='Yes', group='DNS与网关', hint='仅 Windows'),
    # -- 重定向与黑名单 ----------------------------------------------------
    Field('RedirectAllTraffic', '重定向全部流量', T_BOOL_YESNO, default='Yes',
          group='重定向与黑名单',
          hint='开启时 DefaultTCP/UDPListener 必填且须为已存在段名'),
    Field('DefaultTCPListener', '默认 TCP 监听器段名', T_STRING,
          default='ProxyTCPListener', group='重定向与黑名单'),
    Field('DefaultUDPListener', '默认 UDP 监听器段名', T_STRING,
          default='ProxyUDPListener', group='重定向与黑名单'),
    Field('BlackListPortsTCP', 'TCP 端口黑名单', T_PORTLIST, default='139',
          group='重定向与黑名单',
          hint='仅 RedirectAllTraffic 开启时生效;支持 67, 68 与 60000-60010'),
    Field('BlackListPortsUDP', 'UDP 端口黑名单', T_PORTLIST,
          default='67, 68, 137, 138, 443, 1900, 5355',
          group='重定向与黑名单'),
    Field('BlackListIDsICMP', 'ICMP ID 黑名单', T_INTLIST, default='',
          group='重定向与黑名单', advanced=True,
          hint='仅 Windows;模板中仅注释样例,v0.2 审计 P5 补'),
    Field('ProcessWhiteList', '进程白名单(Diverter 级)', T_STRINGLIST,
          default='', group='重定向与黑名单',
          hint='与 ProcessBlackList 互斥(同时存在即启动失败)'),
    Field('ProcessBlackList', '进程黑名单(Diverter 级)', T_STRINGLIST,
          default='', group='重定向与黑名单'),
    Field('HostBlackList', '主机黑名单(Diverter 级)', T_STRINGLIST,
          default='', group='重定向与黑名单', hint='逗号分隔 IPv4'),
    # -- Linux 专用 --------------------------------------------------------
    Field('LinuxRestrictInterface', 'Linux 限定的网卡名', T_STRING,
          default='Off', group='Linux',
          hint='Off 或网卡名(如 eth0);仅 MultiHost 生效'),
    Field('LinuxFlushIptables', 'Linux 启动时清空 iptables', T_BOOL_YESNO,
          default='Yes', group='Linux'),
    Field('LinuxFlushDNSCommand', 'Linux 刷新 DNS 命令', T_STRING,
          default='service dns-clean restart', group='Linux'),
    # -- 出站策略: 域名放行 -------------------------------------------------
    Field('ExternalAccessPolicy', '出站策略', T_ENUM, default='Disabled',
          group='域名放行', enum=('Disabled', 'DomainAllowList'),
          hint='DomainAllowList 仅 Windows 且要求 DivertTraffic=Yes'),
    Field('ExternalAllowedDomains', '放行域名', T_STRINGLIST,
          default='api.deepseek.com', group='域名放行',
          hint='接管模式下代码仅允许 api.deepseek.com'),
    Field('ExternalAllowedTCPPorts', '放行 TCP 端口', T_PORTLIST,
          default='443', group='域名放行', lock=LOCK_TCP_PORTS_443,
          hint='代码强制仅 443'),
    Field('ExternalDnsServer', '上游 DNS', T_STRING, default='Auto',
          group='域名放行',
          hint='Auto 或可用单播 IPv4;不能是本机地址'),
    Field('ExternalDnsTimeout', '上游 DNS 超时(秒)', T_INT, default='3',
          group='域名放行', minimum=1, maximum=30),
    Field('ExternalVerifyTLSSNI', 'TLS SNI 精确校验', T_BOOL_YESNO,
          default='Yes', group='域名放行', lock=LOCK_BOOL_YES,
          hint='代码强制 Yes'),
    Field('ExternalRelayPort', 'TLS 中继端口', T_INT, default='38927',
          group='域名放行', minimum=1, maximum=65535,
          hint='必须等于 DomainEgressRelay 监听器的 Port'),
    Field('ExternalTLSHelloTimeout', 'TLS Hello 超时(秒)', T_INT, default='5',
          group='域名放行', lock=LOCK_RESOURCE_TUPLE,
          minimum=5, maximum=5, hint='代码强制 5'),
    Field('ExternalTLSHelloMaxBytes', 'TLS Hello 最大字节', T_INT,
          default='65536', group='域名放行', lock=LOCK_RESOURCE_TUPLE,
          minimum=65536, maximum=65536, hint='代码强制 65536'),
    Field('ExternalMaxPendingFlows', '最大挂起流', T_INT, default='256',
          group='域名放行', lock=LOCK_RESOURCE_TUPLE,
          minimum=256, maximum=256, hint='代码强制 256'),
    Field('ExternalMaxPendingPerSource', '每源最大挂起流', T_INT,
          default='32', group='域名放行', lock=LOCK_RESOURCE_TUPLE,
          minimum=32, maximum=32, hint='代码强制 32'),
    Field('ExternalMaxActiveRelays', '最大活动中继', T_INT, default='128',
          group='域名放行', lock=LOCK_RESOURCE_TUPLE,
          minimum=128, maximum=128, hint='代码强制 128'),
    Field('ExternalMaxActivePerSource', '每源最大活动中继', T_INT,
          default='16', group='域名放行', lock=LOCK_RESOURCE_TUPLE,
          minimum=16, maximum=16, hint='代码强制 16'),
    Field('ExternalRelayIdleTimeout', '中继空闲超时(秒)', T_INT,
          default='300', group='域名放行', lock=LOCK_RESOURCE_TUPLE,
          minimum=300, maximum=300, hint='代码强制 300'),
    Field('ExternalRelayBufferBytes', '中继缓冲字节', T_INT,
          default='1048576', group='域名放行', lock=LOCK_RESOURCE_TUPLE,
          minimum=1048576, maximum=1048576, hint='代码强制 1048576'),
    Field('ExternalNonAllowedAction', '非放行流量动作', T_ENUM,
          default='Divert', group='域名放行', enum=('Divert', 'Drop'),
          cond_lock=COND_TAKEOVER_ACTION,
          hint='接管模式下代码强制 Divert'),
    Field('ExternalBlockExternalIPv6', '拒绝 IPv6 公网出站', T_BOOL_YESNO,
          default='Yes', group='域名放行', lock=LOCK_BOOL_YES,
          hint='代码强制 Yes'),
    Field('ExternalBlockQUIC', '拒绝 QUIC', T_BOOL_YESNO, default='Yes',
          group='域名放行', lock=LOCK_BOOL_YES, hint='代码强制 Yes'),
    # -- 出站策略: 私网接管 -------------------------------------------------
    Field('ExternalTakeoverIPv4', '接管 sink IPv4', T_IPV4, default='',
          group='私网接管',
          hint='RFC1918 单播;非本机、≠上游 DNS;填写即启用接管(其余 3 键须同时配置)'),
    Field('ExternalTakeoverDnsTTL', '接管 DNS TTL(秒)', T_INT, default='',
          group='私网接管', minimum=1, maximum=300),
    Field('ExternalTakeoverProbeTCPPorts', '接管探测 TCP 端口', T_PORTLIST,
          default='', group='私网接管',
          hint='可空;最多 64 个;只读探测'),
    Field('ExternalTakeoverProbeTimeoutMs', '探测超时(毫秒)', T_INT,
          default='500', group='私网接管', minimum=100, maximum=5000),
    # -- 出站策略: 公网 IPv4 放行 -------------------------------------------
    Field('ExternalAllowedIPv4Rules', '公网 IPv4 直连规则', T_STRINGLIST,
          default='', group='公网IPv4放行',
          hint='格式 协议/IPv4/端口,如 TCP/110.242.69.21/443;端口可用 *;'
               '最多 32 条、16 个 IP;存在但为空=配置错误'),
    # -- 出站策略: 进程重定向 -----------------------------------------------
    Field('ExternalProcessRedirectEnabled', '启用按进程重定向', T_BOOL_YESNO,
          default='No', group='进程重定向', hint='仅 Windows;fail-closed'),
    Field('ExternalProcessRedirectProtocol', '重定向协议', T_ENUM,
          default='TCP', group='进程重定向', enum=('TCP',),
          lock=LOCK_PR_PROTOCOL_TCP, hint='代码强制 TCP'),
    Field('ExternalProcessRedirectImagePath', '目标 PE 绝对路径',
          T_PATH_FILE, default='', group='进程重定向',
          hint='绝对盘符路径;禁 UNC/ADS/通配'),
    Field('ExternalProcessRedirectImageSHA256', 'PE SHA-256', T_HEX64,
          default='', group='进程重定向',
          hint='64 位十六进制;须与实际文件一致'),
    Field('ExternalProcessRedirectOriginalIPv4', '原公网 IPv4 (A)', T_IPV4,
          default='', group='进程重定向', hint='全球单播 IPv4'),
    Field('ExternalProcessRedirectTargetIPv4', '目标私网 IPv4 (B)', T_IPV4,
          default='', group='进程重定向', hint='可用 RFC1918'),
)

# ---------------------------------------------------------------------------
# Listener common fields (all listener sections, §5.1)
# ---------------------------------------------------------------------------

LISTENER_COMMON_FIELDS = (
    Field('Enabled', '启用', T_BOOL_TRUEFALSE, default='True'),
    Field('Port', '端口', T_PORTSPEC, default='',
          hint='单端口、逗号列表或区间(如 60000-60010,将展开为多实例)'),
    Field('Protocol', '协议', T_ENUM, default='TCP', enum=('TCP', 'UDP')),
    Field('Listener', '监听器类型', T_ENUM, default='', enum=LISTENER_CLASSES,
          hint='留空 = 匿名监听器(仅重定向,不启服务)'),
    Field('Hidden', '隐藏日志', T_BOOL_TRUEFALSE, default='False',
          hint='仅认字面 True'),
    Field('ProcessWhiteList', '进程白名单', T_STRINGLIST, default=''),
    Field('ProcessBlackList', '进程黑名单', T_STRINGLIST, default=''),
    Field('HostWhiteList', '主机白名单', T_STRINGLIST, default=''),
    Field('HostBlackList', '主机黑名单', T_STRINGLIST, default=''),
    Field('ExecuteCmd', '首包执行命令', T_TEXT, default='',
          hint='占位符: {pid} {procname} {src_addr} {src_port} '
               '{dst_addr} {dst_port}'),
)

# Per-listener-type fields.  Trap annotations from source review (§5.1).
LISTENER_TYPE_FIELDS = {
    'DNSListener': (
        Field('ResponseA', 'A 记录应答', T_IPV4_OR_ENUM, default='',
              enum=RESPONSEA_TOKENS,
              hint='字面 IPv4 或 GetFirstNonLoopback/GetHostByName;'
                   '接管模式须等于接管 sink IPv4'),
        Field('ResponseMX', 'MX 记录应答', T_STRING, default='mail.evil.com'),
        Field('ResponseTXT', 'TXT 记录应答', T_STRING, default='FAKENET'),
        Field('NXDomains', '前 N 次不答 A 查询', T_INT, default='0'),
        Field('Timeout', '连接超时(秒)', T_INT, default='5',
              hint='仅 TCP DNS'),
        Field('DNSResponse', '已废弃键(代码不读取)', T_STRING, default='',
              dead=True,
              hint='历史拼写残留(burp.ini);代码实际读取 ResponseA,'
                   '仅为保真可编辑'),
    ),
    'HTTPListener': (
        Field('UseSSL', '启用 SSL', T_BOOL_YESNO, default='No',
              hint='代码精确匹配字面 Yes'),
        Field('Webroot', 'Web 根目录', T_PATH_DIR, default='defaultFiles/'),
        Field('Timeout', '连接超时(秒)', T_INT, default='10'),
        Field('DumpHTTPPosts', '保存 HTTP POST', T_BOOL_YESNO, default='Yes'),
        Field('DumpHTTPPostsFilePrefix', 'POST 文件前缀', T_STRING,
              default='http'),
        Field('Custom', '自定义响应 INI', T_PATH_FILE, default=''),
        Field('Version', 'HTTP Server 头', T_STRING, default='FakeNet/1.3',
              advanced=True),
        Field('Static_CA', '使用用户 CA', T_BOOL_YESNO, default='No'),
        Field('CA_Cert', 'CA 证书(PEM)', T_PATH_FILE, default=''),
        Field('CA_Key', 'CA 私钥(PEM)', T_PATH_FILE, default=''),
        Field('cert_dir', '动态证书目录', T_PATH_DIR,
              default='configs/temp_certs', advanced=True),
    ),
    'FTPListener': (
        Field('UseSSL', '启用 SSL', T_BOOL_YESNO, default='No'),
        Field('FTProot', 'FTP 根目录', T_PATH_DIR, default='defaultFiles/'),
        Field('PasvPorts', '被动端口段', T_PORTSPEC, default='60000-60010'),
        Field('Banner', '欢迎横幅', T_STRING, default='!generic',
              hint='字面串或 !key(!generic/!random 等);支持 {servername} '
                   '{tz};\\n \\t 按字面保真'),
        Field('ServerName', '服务器名', T_STRING, default='localhost',
              hint='字面串、!gethostname 或 !random'),
    ),
    'IRCListener': (
        Field('UseSSL', '启用 SSL(代码未实现)', T_BOOL_YESNO, default='No',
              dead=True, hint='IRC 监听器不读取此键,仅保真'),
        Field('Banner', '欢迎横幅', T_STRING, default='!generic',
              hint='IRC BANNERS 仅 generic 与 debian-ircd-irc2'),
        Field('ServerName', '服务器名', T_STRING, default='localhost'),
        Field('Timeout', '连接超时(秒)', T_INT, default='30'),
    ),
    'RawListener': (
        Field('UseSSL', '启用 SSL', T_BOOL_YESNO, default='No'),
        Field('Timeout', '连接超时(秒)', T_INT, default='10'),
        Field('Custom', '自定义响应 INI', T_PATH_FILE, default=''),
    ),
    'SMTPListener': (
        Field('UseSSL', '启用 SSL', T_BOOL_YESNO, default='No'),
        Field('Banner', '欢迎横幅(字面串)', T_STRING,
              default='220 FakeNet SMTP Service Ready',
              hint='不走 BANNERS 字典'),
        Field('Timeout', '连接超时(秒)', T_INT, default='5'),
    ),
    'POPListener': (
        Field('UseSSL', '启用 SSL', T_BOOL_YESNO, default='No'),
        Field('Timeout', '连接超时(秒)', T_INT, default='10'),
    ),
    'TFTPListener': (
        Field('TFTPRoot', 'TFTP 根目录', T_PATH_DIR, default='defaultFiles/'),
        Field('TFTPFilePrefix', '上传文件前缀', T_STRING, default='tftp'),
    ),
    'ProxyListener': (
        Field('Listeners', '子监听器清单(仅文档)', T_STRINGLIST, default='',
              dead=True,
              hint='代码不读取此键:ProxyListener 嗅探全部运行中监听器'),
        Field('Static_CA', '使用用户 CA', T_BOOL_YESNO, default='No'),
        Field('CA_Cert', 'CA 证书(PEM)', T_PATH_FILE, default=''),
        Field('CA_Key', 'CA 私钥(PEM)', T_PATH_FILE, default=''),
    ),
    'DomainEgressRelay': (
        Field('Port', '端口(须等于 ExternalRelayPort)', T_PORTSPEC,
              default='38927'),
    ),
}

# ---------------------------------------------------------------------------
# Custom response sections (§5.1, separate INI referenced via Custom:)
# ---------------------------------------------------------------------------

CUSTOM_RESPONSE_COMMON_FIELDS = (
    Field('InstanceName', '匹配监听器实例段名', T_STRING, default='',
          hint='与 ListenerType 二选一(至少其一)'),
    Field('ListenerType', '匹配监听器类型', T_ENUM, default='',
          enum=('HTTP', 'TCP', 'UDP'), hint='与 InstanceName 二选一'),
)

CUSTOM_RESPONSE_HTTP_FIELDS = (
    Field('HttpURIs', '匹配 URI(后缀)', T_STRINGLIST, default='',
          hint='与 HttpHosts 至少其一;两者都给取逻辑与'),
    Field('HttpHosts', '匹配 Host', T_STRINGLIST, default='',
          hint='支持 host:port'),
    Field('HttpRawFile', '响应体文件', T_PATH_FILE, default='',
          hint='响应体三选一;支持 <RAW-DATE>'),
    Field('HttpStaticString', '响应体字符串', T_TEXT, default='',
          hint='三选一;\\r\\n 按字面保真;支持 <RAW-DATE>'),
    Field('HttpDynamic', '响应体动态模块', T_PATH_FILE, default='',
          hint='三选一;py 模块须导出 HandleHttp'),
    Field('ContentType', 'Content-Type(仅配 HttpStaticString)', T_STRING,
          default=''),
)

CUSTOM_RESPONSE_RAW_FIELDS = (
    Field('TcpStaticString', 'TCP 响应字符串', T_TEXT, default=''),
    Field('TcpStaticBase64', 'TCP 响应 Base64', T_TEXT, default=''),
    Field('TcpRawFile', 'TCP 响应文件', T_PATH_FILE, default=''),
    Field('TcpDynamic', 'TCP 动态模块', T_PATH_FILE, default=''),
    Field('UdpStaticString', 'UDP 响应字符串', T_TEXT, default=''),
    Field('UdpStaticBase64', 'UDP 响应 Base64', T_TEXT, default=''),
    Field('UdpRawFile', 'UDP 响应文件', T_PATH_FILE, default=''),
    Field('UdpDynamic', 'UDP 动态模块', T_PATH_FILE, default='',
          hint='四选一(每协议);动态模块须导出 HandleTcp/HandleUdp'),
)

CUSTOM_RESPONSE_FIELDS = (CUSTOM_RESPONSE_COMMON_FIELDS +
                          CUSTOM_RESPONSE_HTTP_FIELDS +
                          CUSTOM_RESPONSE_RAW_FIELDS)

# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

_DIVERTER_BY_KEY = {f.key.lower(): f for f in DIVERTER_FIELDS}
_LISTENER_COMMON_BY_KEY = {f.key.lower(): f for f in LISTENER_COMMON_FIELDS}
_LISTENER_TYPE_BY_KEY = {
    cls: {f.key.lower(): f for f in fields}
    for cls, fields in LISTENER_TYPE_FIELDS.items()
}
_CUSTOM_BY_KEY = {f.key.lower(): f for f in CUSTOM_RESPONSE_FIELDS}


def diverter_field(key):
    return _DIVERTER_BY_KEY.get(key.lower())


def fakenet_field(key):
    lowered = key.lower()
    for field in FAKENET_FIELDS:
        if field.key.lower() == lowered:
            return field
    return None


def listener_fields(listener_class):
    """Common fields plus the per-type fields for one listener class."""
    common = list(LISTENER_COMMON_FIELDS)
    specific = LISTENER_TYPE_FIELDS.get(listener_class, ())
    # Only DomainEgressRelay redefines Port (with a special label/hint).
    return common + [f for f in specific
                     if f.key != 'Port' or listener_class == 'DomainEgressRelay']


def listener_known_keys(listener_class):
    keys = set(_LISTENER_COMMON_BY_KEY)
    keys.update(_LISTENER_TYPE_BY_KEY.get(listener_class, ()))
    return keys


def custom_response_field(key):
    return _CUSTOM_BY_KEY.get(key.lower())


def egress_group_names():
    """Egress policy sub-groups shown on the 出站策略 tab."""
    return ('域名放行', '私网接管', '公网IPv4放行', '进程重定向')


def is_egress_field(field):
    return field.group in egress_group_names()
