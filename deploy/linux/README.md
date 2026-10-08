# LNX-FN Linux 部署（MalTrace 总纲前置）

在固定 REMnux guest（IP 192.168.204.230, SSH maltrace-admin:2222）上部署
FakeNet-NG Linux MCP 服务。2026-10-06 曾按本目录流程完成部署并通过
MalTrace 7.1 硬验收主链；guest 回滚到可信基线后按此重建。

## 文件

- `lnxfn-serve.py` — guest 服务入口：Bearer 门（token 于
  `/etc/fakenet-ng-linux/token`, 0600 root）包在 TransportGuard 外层，
  `FAKENETNG_MCP_LINUX_RUNNER=1` 启用 LinuxRunner 生命周期, 监听
  127.0.0.1:28788。
- `fakenet-ng-linux.service` — systemd unit（root, NoNewPrivileges）。
- `deploy.sh` — 一键部署：guest venv（/opt/fakenet-ng/venv）+ 冻结依赖
  wheel + 源码 tar + token provision + unit 安装。
- `netfilterqueue-upstream-master.tar.gz` — 上游 python-netfilterqueue
  源码快照（PyPI 1.1.0 与 py3.12 不兼容；guest 需 venv 内先装 cython
  与 setuptools, 再由本安装器离线 `pip install --no-deps --no-build-isolation`）。

## 冻结离线配送

`offline-lock.json` 固定 Python 3.12/Linux x86_64 的 38 个 wheel 和三个
源码包的版本、SHA-256 与来源. NetfilterQueue 使用已封存快照的内容指纹,
不在线解析 master. 所有依赖须事先通过官方索引或已验收封存取得.

```bash
python3 deploy/linux/build-offline.py --inputs /absolute/verified-inputs \
  --output "$PWD/dist/exclusive-release" \
  --source-commit 3ed8592df4c326331000a7ec6d2abda84bac948b
```

打包器验证完整输入, 从不可变提交导出源码并保留 build_identity.py.
仅将产物与独立记录的 manifest SHA-256 运输到固定 guest 的 root 私有目录;
传输后先核全包指纹. 不从宿主 venv 复制依赖. 安装不联网、不运行 apt:

```bash
sudo bash /private/package/deploy.sh --package /private/package \
  --manifest-sha256 <verified-sha256> --operation <exclusive-operation-id>
```

安装器在任何修改前校验完整包、父链、目标与 token, 拒绝未知服务/规则.
既有安装只能在无进程引用且全清单校验后同卷移动到独占 preserved 目录,
不删除原件. 固定私有事务目录记录阶段; 完成重入校验已安装身份且不重复激活;
中断或失败重入明确拒绝, 保留原件供显式续作. 合法 root 0600 token 保留,
非法 token 拒绝. 依赖安装、pip check、导入成功才 provision token/激活 unit.
临时构建目录在子命令结束且记录精确身份清单后清理; 包和正式结果保留.

安装配置关闭全表 flush/restore、自动网关/DNS/缓存命令. 管理端点配置固定为
已核实的 192.168.204.1:2222, 不适用于任意 VM/管理地址. unit 的正常
PROGRAMDATA 指向 /opt/fakenet-ng/runtime; 未使用测试路径覆盖开关.

部署测试: `python3 -B -m unittest discover -s test -p test_linux_deploy.py -v`.
fixture 只使用隔离文件与替身命令, 不调用真实服务或处理真实凭据.

## 部署时必须的三处环境调整（曾现场发现）

1. 保存原配置、resolv.conf 链接与服务状态后, `systemd-resolved`：`/etc/systemd/resolved.conf.d/fakenet-analysis.conf`
   写入 `[Resolve]` + `DNSStubListener=no` 并重启, 释放 53 端口。
   仅在原件不存在且无未知冲突时创建该文件; 临时验证 stop 后恢复本轮原状态
   并复核 stub 监听. 不改变上游 DNS 或路由; idle MCP 服务不提供 DNS.
2. `default.ini` 的 `[Diverter]` 节追加
   `LinuxControlEndpoints: <管理主机IP>:2222`（管理通道放行；值会被
   fnconfig 炸成字符列表, diverter 侧已做归一化）。
3. fakenet 源码 tar 打包时不要用 `--exclude='build*'` 通配——会把
   `fakenet/mcp/build_identity.py` 一起排除（曾踩坑）。

## 验收基线

MalTrace 7.1 硬验收主链（start 真实接管/良性 IPv4 拦截/IPv6 阻断/
stop 零残留/Bearer 401/崩溃收养）证据:
MalTrace `.tmp/linux-master-20260930/lnxfn-deploy-20261006/seal-lnxfn.json`。

## 2026-10-08 原生复验的限制

本轮离线配送、IPv4 DNS 拦截、隔离期 P01/SSH 管理存活和 stop 清理已取得
原件 (`Logs/linux-master-20260930-S0048/`). 此结果不是分析资格或整体隔离通过:
既有 LinuxRunner 在活动运行返回 controller=null; NetPolicy 入站例外仅限源 IP,
未限 TCP/2222; IPv6 的头插 DROP 位于 loopback ACCEPT 前, 实测 ::1 被拒绝.
这些业务缺陷未在部署改动中修复, 需独立授权的核心修复与复验.
stop 后规则条目为零, nft 保留无规则的 ACCEPT 表/链壳; 未执行全表 flush.
DNS stub 已恢复, idle MCP 保留, 下次拦截仍须按上述规则准备并恢复 DNS.
历史验收记录不能替代本次缺陷核定; P04 生产 provider 尚未接线.

上游冻结快照的实际构建版本为 `NetfilterQueue 1.1.0+dev`; 锁表按此记录,
不能与 PyPI 的 `1.1.0` sdist 混同. 已使用的 S0048-v2 包保留原字节,
其版本标签少了 `+dev`; v3 只修正该锁元数据, 源码包哈希与部署脚本未变.
