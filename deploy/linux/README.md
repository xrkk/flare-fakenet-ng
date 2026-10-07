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
  与 setuptools, 再 `python setup.py build_ext --inplace && pip install .`）。

## 冻结依赖 wheel 来源

29 个 wheel 与版本清单见
MalTrace `.tmp/linux-master-20260930/independent-glm-handoff-20261006/maintenance-deploy/build/wheelhouse/`
（git 忽略, 不提交）。重建方式：在能出网的 host 上

```bash
pip download -d wheels --python-version 312 --only-binary=:all: \
  --platform manylinux2014_x86_64 --platform manylinux_2_28_x86_64 --platform any \
  mcp==2.1.1 uvicorn==0.52.4 starlette==1.6.0 pydantic==2.13.5 \
  dpkt==1.9.8 dnslib==0.9.26
pip download -d wheels --no-deps pyopenssl netifaces pyftpdlib capstone \
  jinja2 markupsafe pyasynchat pyasyncore   # 部分为源码包, guest 上构建
```

源码包部署时需 `--no-build-isolation`（venv 先装 setuptools/cython）。

## 部署时必须的三处环境调整（曾现场发现）

1. `systemd-resolved`：`/etc/systemd/resolved.conf.d/fakenet-analysis.conf`
   写入 `[Resolve]` + `DNSStubListener=no` 并重启, 释放 53 端口。
2. `default.ini` 的 `[Diverter]` 节追加
   `LinuxControlEndpoints: <管理主机IP>:2222`（管理通道放行；值会被
   fnconfig 炸成字符列表, diverter 侧已做归一化）。
3. fakenet 源码 tar 打包时不要用 `--exclude='build*'` 通配——会把
   `fakenet/mcp/build_identity.py` 一起排除（曾踩坑）。

## 验收基线

MalTrace 7.1 硬验收主链（start 真实接管/良性 IPv4 拦截/IPv6 阻断/
stop 零残留/Bearer 401/崩溃收养）证据:
MalTrace `.tmp/linux-master-20260930/lnxfn-deploy-20261006/seal-lnxfn.json`。
