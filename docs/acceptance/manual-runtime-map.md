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

T007/R02 只实现 `GAP-NCSI` 与 `GAP-RAW-DATE`; 其余 9 个手工 case 和 2 个 Linux case 在默认入口明确 `not_implemented`, 不返回 pass.

| Case | 原来源 | 关键正反判据 |
| --- | --- | --- |
| GAP-EXECUTECMD (NOT_IMPLEMENTED) | docs/testing.md, ExecuteCmd | 本轮不返回 pass |
| GAP-NCSI | fakenet/listeners/DNSListener.py DNSHandler.parse | 真实 query/response UDP/TCP；dns.msftncsi.com=131.107.255.225；其它域 responsea |
| GAP-STANDALONE-LISTENERS (NOT_IMPLEMENTED) | 原 listener 入口 | 每个 standalone listener 的真实请求/响应与关闭 |
| GAP-CTRLC-IPC (NOT_IMPLEMENTED) | 原控制入口 | Ctrl-C 与 IPC halt 的实际关闭/退出 |
| GAP-DIVERTER-SWITCH (NOT_IMPLEMENTED) | default.ini, diverter | DivertTraffic 两值及规则恢复 |
| GAP-SYSLOG-ICMP-LOG (NOT_IMPLEMENTED) | syslog/ICMP 日志 | 标记、ICMP 实际记录、PID owner |
| GAP-DUMPPACKETS (NOT_IMPLEMENTED) | DumpPackets | 开/关、前缀、真实包内容 |
| GAP-LINUX-FLUSH-INTERFACE (NOT_IMPLEMENTED) | LinuxFlushIptables/LinuxFlushDNSCommand/LinuxRestrictInterface | 三个独立字段及实际清理/接口 |
| GAP-NETWORK-FIX (NOT_IMPLEMENTED) | FixGateway/FixDNS/ModifyLocalDNS/StopDNSService | 逐平台实际语义及前后恢复 |
| GAP-RAW-DATE | fakenet/listeners/HTTPListener.py CustomResponse | 真实 raw/static respond；日期替换、逐字节保留、非匹配拒绝 |
| GAP-LIST-MUTEX (NOT_IMPLEMENTED) | black/white list | 互斥配置与允许/拒绝对照 |

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

The other manual cases remain unimplemented. A missing default HTTP web file
currently exposes an existing product TypeError; preserve that failure instead
of treating it as a prerequisite to repair product behavior during facility work.
