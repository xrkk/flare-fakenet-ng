## 目录

- Linux 运行/部署 2 case
- 手工功能 11 case
- 输入、动作、原件、判据、恢复
- 中央集成边界

## Linux 运行/部署

| Case | 原来源/接口 | 固定输入 | 动作/原件 | 判据/恢复 |
| --- | --- | --- | --- | --- |
| LINUX-SINGLEHOST (NOT_IMPLEMENTED) | fakenet/mcp/linuxrunner.py, fakenet/diverters/linux.py, linuxnetpolicy.py | mode=singlehost\|multihost, interface, NFQUEUE, control endpoint, config | INI、owned rule argv、IPv4/IPv6 PCAP、启动/停止记录 | SingleHost 分流、MultiHost 接口限制、IPv6 默认 DROP 与精确控制例外、规则无人残留 |
| LINUX-DEPLOY-UPDATE (NOT_IMPLEMENTED) | deploy/linux/deploy.sh, update-idle.py, build-offline.py | package/manifest SHA、source/base identity、token、operation、idle status | install/update receipt、backup、published files、token mode、failure phase | 首次部署/manifest/hash、idle 事务、失败保留/回滚、token/unit 身份、恢复 |

## 手工功能

当前已接入 `GAP-NCSI`, `GAP-RAW-DATE`, `GAP-LIST-MUTEX`, `GAP-EXECUTECMD`, `GAP-DIVERTER-SWITCH`, `GAP-SYSLOG-ICMP-LOG`, `GAP-DUMPPACKETS`, `GAP-CTRLC-IPC`, `GAP-LINUX-FLUSH-INTERFACE`, `GAP-NETWORK-FIX` 和 `GAP-STANDALONE-LISTENERS`; 其余 2 个 Linux case 的完整链仍未实现, 不返回 pass. 历史 T007/R02 仅交付前两项.

| Case | 原来源 | 关键正反判据 |
| --- | --- | --- |
| GAP-EXECUTECMD | 原 parse/build/PacketCtx/maybe_redir_port/execute_detached | 首次一次/重复与负场景零次; 本轮 token/六字段输出原字节; 独立缺失/错内容/重复拒绝 |
| GAP-NCSI | fakenet/listeners/DNSListener.py DNSHandler.parse | 真实 query/response UDP/TCP；dns.msftncsi.com=131.107.255.225；其它域 responsea |
| GAP-STANDALONE-LISTENERS | 9 个 listener 脚本的 main/start/handler/stop, ProxyListener 实际转发 | 本机 127.0.0.1 临时端口与良性原协议字节; DNS/HTTP/FTP/IRC/POP/SMTP/Raw/TFTP/Proxy 的原 main, 构造, 启停及实际请求响应. 保留原 main 调用的内嵌 test (Raw/TFTP 原本注释, Proxy 无 test); sys.profile 采原函数调用, 独立 calls/resources 原件判定, 临时钩子逐轮恢复. FTP 保留 pyftpdlib 原 serve_forever, 每轮独立 IOLoop/Event; POP/SMTP 以既有证书和 SSLContext 兼容旧 wrap_socket; HTTP 优先正常 Requests, 缺失时复用 pip 已安装的真实 Requests. 不生成或安装证书/依赖. 9 协议篡改、缺入口/内嵌test、假关闭/owner/source 拒绝, 同中央 plan/execute/judge 正反通过. 仅受控回环 fixture, 原生 Windows/Linux/系统网络恢复未验 |
| GAP-CTRLC-IPC | fakenet.fakenet main wait_for_shutdown/stop | 原 main -f 文件 IPC 与进程内 Ctrl-C, 原 parse/start/wait/stop 和 backend start/stop 实际调用/返回观测, 不依赖测试计数器; owned watcher 仅在 wait 进入后触发并 join, 无关 flag 不触发, finally 移除正确 flag/恢复 argv/profile/logger; 系统 console/信号/native 恢复未验 |
| GAP-DIVERTER-SWITCH | 原 Fakenet.parse_config/start/stop | 两值原 core 分支/调用与日志; owned 停止及幂等; 系统网络恢复单独未验 |
| GAP-SYSLOG-ICMP-LOG | fakenet.fakenet main -s, PacketCtx/check_log_icmp | 原 main -s/无-s/formatter 与原 PacketCtx ICMP 正反字节; PID/token 从原 LogRecord/主日志/owned stop flag 绑定, 不捏造 syslog 字段; finally 关闭本轮 handler 并恢复原 logger/argv/profile. 本机 OS sink fixture, 真实 syslog/EventLog/live ICMP 未验 |
| GAP-DUMPPACKETS | DumpPackets/DumpPacketsFilePrefix, DualPcapWriter | 原 INI parser、enabled/disabled、custom prefix、TCP/UDP 固定原字节、真实 raw+converted/observation/seal parser 及 finally close; 独立文件/字节判据. 本机为保留原件的离线重放, 不授真实 wire/native/full, 系统网络恢复未运行 |
| GAP-LINUX-FLUSH-INTERFACE | fakenet/diverters/linux.py start/stopCallback, linutil.py | 原 INI/字段解析、四表 flush 与独立采集的原 iptables-save/restore 字节、DNS argv/rc/原日志, 按原占用队列分配, MultiHost/SingleHost restrict 的 NFQUEUE 与规则 iface. producer 委托原系统调用并记录, 不依赖测试记录器/假快照; 本机 OS 边界 fixture, 真实系统效果/native 未验 |
| GAP-NETWORK-FIX | winutil.WinUtilMixin/Windows._restore_network_settings, linutil.LinUtilMixin | 原 Windows/Linux 构造、INI 和 start/stop 实际驱动网关/DNS及服务开关; producer 透明采原命令、registry/resolver/service 初中末值并独立重判, 测试仅替 OS/driver. Linux TODO/服务不支持及原 stop 不删除新增默认路由明确保留; 真实系统恢复与 native/full 仍未验 |
| GAP-RAW-DATE | fakenet/listeners/HTTPListener.py CustomResponse | 真实 raw/static respond；日期替换、逐字节保留、非匹配拒绝 |
| GAP-LIST-MUTEX | DiverterBase.parse_listeners_config, ListenerMeta, ListenerPorts | 四类名单的 16 项允许/拒绝/错协议/错端口; 两类明确互斥异常和三类 parser 冲突; 原配置/源码身份与独立重判 |

## 组合场景

`GAP-COMBO-SCENARIO` 已从 `manual-headless` 接到 `policy-combo`; 精确 12 checks 为 exact_domain/wildcard_domain/tls_application/reviewed_ip_tls/sink_tcp/sink_udp/port_80_denied/port_444_denied/udp443_denied/other_ip_denied/adjacent_denied/route_restore. sink 探针消费 denied_domain 的实际 DNS sink 回答, 失败不回退固定地址. combo-context 及同轮 DNS 原包/消费时序/固定停止态端点对照已接入; 原子用例不变. 当前只取得代码与 fixture 自验信用, 临时自测原件未保留为归档重判材料. 真实主机核心/网络仍未验.

## 中央集成

本轮新模块不修改 `tools/acceptance.py`、`acceptance_native.py`、`catalog.json` 或 README。未来主控按 `T007-R01-evidence/central-integration.patch` 接入 driver/check filter/dispatch/source pin；本结果不声明中央 catalog/native/full 已验。


## Current NCSI and RAW-DATE execution

The two stable cases use fixed `manual-ncsi` and `manual-raw-date` drivers. The
producer starts the original product listeners on owned loopback ephemeral
ports, retains DNS payloads and TCP length frames, HTTP requests/responses,
configuration and original lifecycle observations, then stops and joins the
owned resources. The oracle checks four exact DNS name/transport pairs, full
HTTP bytes and real response dates against each request window.

Use the existing `tools/acceptance.py plan`, `execute` and independent `judge`
commands. Set `environment.manual` to
`{"schema":"fakenet.manual-options.v1","responsea":"192.0.2.55"}` and include
the candidate source commit, package SHA-256 and exact deployed identity.
Production execution requires the installed source and explicit `local-target`
VM authority. Remote automatic deployment is not implemented for these cases;
missing transport/identity is reported as blocked before execution.

For source-local development only, `candidate.offline_fixture=true`,
`native_runtime.transport=manual-loopback-fixture` and the **actual** local host
identity enable the same production CLI with real loopback listeners. The
existing `native` action must be explicit. Catalog platforms remain unchanged.
This grants fixture/code credit only, never Windows VM or full functional credit.
All runtime evidence stays in the selected run directory under `Logs/`.

Six other manual cases remain unimplemented. A missing default HTTP web file
currently exposes an existing product TypeError; preserve that failure instead
of treating it as a prerequisite to repair product behavior during facility work.

## Current list mutual-exclusion execution

`GAP-LIST-MUTEX` uses `manual-list-mutex` through the same central
`plan`, `execute`, and independent `judge` commands. It retains
`config/list-mutex.ini`, the production parser/predicate observations, precise
mutual-exclusion errors and source hashes. The oracle independently parses the
configuration, checks semantic expected values and rejects altered identity,
queries, ports, errors, fixture status or lifecycle records. This is a pure
in-memory list/parser case; it opens no listener, driver or network socket.

T022/R01 verified the local offline fixture, including the central CLI with
only its OS process boundary substituted by in-process execution of the original
manual entry. Actual child transport and Windows native execution remain untested;
these results do not grant native or full functional credit. Existing NCSI and
RAW-DATE evidence is inherited without rerunning those cases.

## Current ExecuteCmd and DivertTraffic switch

The `manual-executecmd` producer uses the original configuration parser,
PacketCtx and first-session caller. It binds the exact fixed command separately
from its six-field/execution-token output bytes; missing, altered and duplicate
output fails. The local regression intercepts only the OS process boundary and
retains simulated output explicitly as fixture evidence. Actual Windows command
execution and child exit have not been verified.

The `manual-diverter-switch` producer calls original Fakenet parse/start/stop
for Yes and No, retains original method-call observations and core logs, and
stops owned components even when startup fails. The oracle requires the exact
configurations, normal/negative branches and observed idempotent stop. Its local
regression uses only test-side OS backend/interface fixtures; system network
restoration remains explicitly unverified. Both drivers use the central
plan/execute/independent-judge path; code/fixture passes grant no native or full
functional credit. Existing case evidence remains valid in its recorded scope.
