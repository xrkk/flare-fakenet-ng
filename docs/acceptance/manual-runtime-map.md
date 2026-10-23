## 目录

- Linux 运行/部署 2 case
- 手工功能 11 case
- 输入、动作、原件、判据、恢复
- 中央集成边界

## Linux 运行/部署

| Case | 原来源/接口 | 固定输入 | 动作/原件 | 判据/恢复 |
| --- | --- | --- | --- | --- |
| LINUX-SINGLEHOST | fakenet/mcp/linuxrunner.py, fakenet/diverters/linux.py, linuxnetpolicy.py | mode=singlehost\|multihost, interface, NFQUEUE, control endpoint, config | INI、owned rule argv、IPv4/IPv6 PCAP、启动/停止记录 | SingleHost 分流、MultiHost 接口限制、IPv6 默认 DROP 与精确控制例外、规则无人残留 |
| LINUX-DEPLOY-UPDATE | deploy/linux/deploy.sh, update-idle.py, build-offline.py | package/manifest SHA、source/base identity、token、operation、idle status | install/update receipt、backup、published files、token mode、failure phase | 首次部署/manifest/hash、idle 事务、失败保留/回滚、token/unit 身份、恢复 |

## 手工功能

| Case | 原来源 | 关键正反判据 |
| --- | --- | --- |
| GAP-EXECUTECMD | docs/testing.md, ExecuteCmd | 首次连接命令/非连接负例 |
| GAP-NCSI | docs/testing.md, NCSI | dns.msftncsi.com=131.107.255.225，其它域对照 |
| GAP-STANDALONE-LISTENERS | 原 listener 入口 | 每个 standalone listener 的真实请求/响应与关闭 |
| GAP-CTRLC-IPC | 原控制入口 | Ctrl-C 与 IPC halt 的实际关闭/退出 |
| GAP-DIVERTER-SWITCH | default.ini, diverter | DivertTraffic 两值及规则恢复 |
| GAP-SYSLOG-ICMP-LOG | syslog/ICMP 日志 | 标记、ICMP 实际记录、PID owner |
| GAP-DUMPPACKETS | DumpPackets | 开/关、前缀、真实包内容 |
| GAP-LINUX-FLUSH-INTERFACE | LinuxFlushIptables/LinuxFlushDNSCommand/LinuxRestrictInterface | 三个独立字段及实际清理/接口 |
| GAP-NETWORK-FIX | FixGateway/FixDNS/ModifyLocalDNS/StopDNSService | 逐平台实际语义及前后恢复 |
| GAP-RAW-DATE | CustomResponse.md | 日期替换且保留字节一致 |
| GAP-LIST-MUTEX | black/white list | 互斥配置与允许/拒绝对照 |

## 中央集成

本轮新模块不修改 `tools/acceptance.py`、`acceptance_native.py`、`catalog.json` 或 README。未来主控按 `T007-R01-evidence/central-integration.patch` 接入 driver/check filter/dispatch/source pin；本结果不声明中央 catalog/native/full 已验。
