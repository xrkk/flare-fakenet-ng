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

## 中央集成

本轮新模块不修改 `tools/acceptance.py`、`acceptance_native.py`、`catalog.json` 或 README。未来主控按 `T007-R01-evidence/central-integration.patch` 接入 driver/check filter/dispatch/source pin；本结果不声明中央 catalog/native/full 已验。
