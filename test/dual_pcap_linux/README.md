# Linux 双 PCAP 一键验收

该验收包只允许在**已拍快照、隔离的 Linux 虚拟机**中运行。runner 会拒绝
物理机、容器、非 Linux 和非 root 环境；不会下载、安装或升级任何依赖，也不会
询问 DNS、路径或故障模式。

## 一键执行

先把整个版本化 ZIP 解压到 Linux VM，然后在解压目录执行：

```bash
sudo bash test/dual_pcap_linux/Run-Tests.sh
```

脚本会自动运行，不需要参数或人工输入。验收期间不要同时运行恶意样本、另一个
FakeNet-NG 实例或会修改防火墙/DNS/route 的程序。

## 运行前依赖

- Linux VM；项目测试基线为 Ubuntu 24.04.2 LTS；
- Python 3.10 或更高版本；
- `iptables`、`iptables-save`、`iptables-restore`、`ip6tables-save`、
  `ip6tables-restore`、`ip`；
- Python 模块：`dpkt==1.9.8`、`dnslib`、`netifaces`、`pyftpdlib`、
  `cryptography`、`pyOpenSSL`、`jinja2`、`netfilterqueue`；
- `netfilterqueue` 所需的系统 `libnetfilter_queue` 支持。

缺少任何依赖时，runner 会在修改网络前失败并给出明文原因。安装依赖属于 VM
准备工作，不是一键脚本的隐式联网 fallback。

## 自动验收内容

1. 包 manifest、VM 身份、root、命令和 Python 依赖身份；
2. Linux/共用核心单元测试；
3. IPv4、IPv6、截断已知版本及正常 EOF 的 writer 文件合同；
4. 100000 条 64/1500 字节、三次中位数、双写不超过单写 2.5 倍；
5. Linux NFQUEUE 真实 IPv4 原始包及重定向后包的同步双 PCAP；
6. RAW write、Ethernet write、close 三种故障的非零退出和受控停止；
7. 当前故障 NFQUEUE 包的显式 drop 证据；
8. 每个用例前后的 iptables、ip6tables、IPv4/IPv6 route、DNS 完整比较；
9. 无残留子进程或仍打开验收文件的文件描述符。

Linux 现有生产 NFQUEUE 只接入 IPv4。runner 会如实把 IPv4 标记为真实动态覆盖，
把 IPv6 标记为同一 Linux 环境中的真实 writer 文件合同，二者不会混报。

## 日志

日志不压缩，直接保存在：

```text
Logs/dual-pcap-linux-v1-YYYYMMDD-HHMMSS/
```

回传整个明文目录即可。`results.tsv` 和 `summary.json` 是汇总；每个用例保留
FakeNet 日志、控制台输出、退出码、PCAP、解析结果及网络前后快照。

如果生产清理已经失败，runner 会在保持 FAIL 的前提下尝试用用例前快照紧急恢复
iptables/ip6tables和未改变链接身份的 DNS 内容，以避免 VM 留在断网状态。这只是
测试安全回滚，不是运行时成功 fallback；route 差异只报告、不擅自修复。
