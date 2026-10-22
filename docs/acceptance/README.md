# FakeNet 集中验收

本目录集中现有 Windows/Linux 核心、策略、GUI、PCAP、载荷报告、MCP、发布和辅助验收. 目标是修改产品或接口后, 能明确选择并执行同一份回归清单, 对照原始结果判断是否破坏已有功能.

当前状态: **盘点 + S1 离线闭环**. `catalog.json` 已升级为 v2, `tools/acceptance.py` 已具备候选/环境绑定的 `plan --mode`、`execute` 和严格 `judge --results`; 原 `test.py` 的退出、Host 名单夹具和 SMTP SSL 测试已修, 并有离线合同自测. S2 原生适配、S3 资源调度、S4 完整验收尚未完成. 当前没有任何新的原生实机通过, 不能把本目录或 S1 自测当作完整设施验收.

排除范围保持用户裁决: GUI 窗口/点击/UAC/三轮停止、旧 100 场景、150 轮发布和新出口验证接口不进入 full; 它们的共享核心已按断言/调用用途抽取为独立 case, 没有因目录名删除.

## 文件

- `catalog.json`: 唯一手工定义来源. v2 含 25 个 suite、64 个 case、显式 `exclusions`、平台/模式/输入/步骤/正反预期/oracle/资源/就绪/超时/清理/依赖. `disposition` 记录 keep/extract/exclude.
- `清单.md`: 由 `tools/acceptance.py inventory --format markdown` 程序派生, 不手改.
- `tools/acceptance.py`: 兼容入口. v1 的 `inventory`/`check`/`plan --output`/`run --suite`/`judge --result` 保持原语义; v2 新增模式化 plan、离线 execute 和严格 judge.
- `test/test_acceptance_regression.py`: 真实 CLI 的 plan/execute/judge 闭环与负例自测.
- `test/test_upstream_runner_contract.py`: 原 `test.py` 退出/重试/名单夹具/SMTP SSL 的离线合同自测.

## 使用顺序

以下命令从仓库根执行, `python` 替换为所在平台已有项目 Python. S1 只在主机运行离线 pytest; 不连接 VM、不启动核心、不构建、不发送网络探针.

```text
python tools/acceptance.py check
python tools/acceptance.py inventory --format json
python tools/acceptance.py inventory --format markdown --output <未占用路径>
python tools/acceptance.py plan --mode full --candidate candidate.json --environment environment.json --output Logs/acceptance/<run>/plan.json
python tools/acceptance.py execute --plan Logs/acceptance/<run>/plan.json
python tools/acceptance.py judge --plan Logs/acceptance/<run>/plan.json --results Logs/acceptance/<run>/results --output Logs/acceptance/<run>/summary.json
```

- `check`: 校验 catalog schema、suite/case 唯一性、依赖无环、来源存在和未归类入口. 不执行测试.
- `plan --mode full`: 展开完整必需集合. 未接入的 native case 记 `blocked`, 不假 ready.
- `plan --mode selected --suite <id>` 或 `--case <id>`: 明确子集. 成功也只会得到 `coverage=selected`, 不会 `full_functional_pass=true`.
- `plan --mode stress`: 只选 `stress=true` 的性能/大负载 case. 不把 stress 计数抄回 full.
- 不带 `--mode` 的 `plan --output`: 仍是旧 v1 计划, 只读兼容.
- `execute`: 按计划中的精确 collection 节点执行注册适配器, 自动收集 stdout/stderr、返回码、JUnit、耗时和 adapter 派生 cleanup; 正常结束时自动调用同一 judge.
- `judge --results`: 从本轮 results 索引读取收据, 重验原件 SHA, 重算终态. 不遍历历史结果猜选.
- `run --suite`: 保留旧语义, 只转交一个已注册原生入口, 不自动批量运行.

### candidate.json

```json
{
  "schema": "fakenet.acceptance-candidate.v2",
  "source_commit": "<当前产品提交>",
  "package_manifest": null,
  "package_sha256": null,
  "deployed_identity": null
}
```

纯源码离线组只要求真实 `source_commit`; 原生组才需要实际包/部署身份. 候选与实际 HEAD 不一致时 `plan` 拒绝; 不自动重建或换候选.

### environment.json

```json
{
  "schema": "fakenet.acceptance-environment.v2",
  "targets": ["host-linux"],
  "interpreters": {"python": "<项目解释器绝对路径>"},
  "endpoints": [],
  "auth_refs": [],
  "work_root": "<本轮 Logs/acceptance 绝对路径>",
  "allowed_actions": ["offline-pytest", "collection"]
}
```

禁止嵌入密码、token、私钥等秘密. `allowed_actions` 决定本轮实际允许的副作用; 未列出的动作在 plan 阶段拒绝, 不静默降级.

### 退出码

- `0`: 声明范围全部实际通过且恢复完成.
- `1`: 真实检查失败 (包括 rc0 但 JUnit 失败、失败被重试掩盖).
- `2`: 输入/环境/未验/blocked 导致不能完整判定.
- `3`: 设施自身异常 (collection/适配器/原件格式).
- 多项并存按 3、1、2、0 取最高优先级.

`full_functional_pass=true` 只在 full 模式、所有必需 case 通过、无 blocked/unverified 时成立. S1 的 full 一定因 native adapters 未实现而为 false.

## 结果如何集中

每次运行使用全新 run 目录, 碰撞拒绝覆盖. 目录结构:

```text
Logs/acceptance/<run>/
  plan.json
  collection/<case>-collection.log
  results/
    results.json
    <case>/receipt.json
    <case>/junit.xml
    <case>/stdout.log
    <case>/stderr.log
  summary.json
```

- plan v2: `execution_id/mode/candidate/environment/catalog_sha256/source_hashes/required_checks/blocked/exclusions`.
- receipt v2: `execution_id/case_id/attempt/candidate/config_sha256/evidence_level/command/returncode/artifacts/cleanup/时间/耗时`.
- summary v2: `candidate/execution_id/coverage/checks/cleanup/verdict/full_functional_pass/unverified/failures/timings`.
- `artifacts` 只保存 path/SHA-256/format 和原验证器输出; 手写 `checks`/`verdict`/`cleanup=true` 不是信用.
- judge 对 planned case 要求有且仅有一个终态. 失败、缺项、重复、skip、OBSERVED、not_run、unknown、blocked 均不能计入通过.
- `cleanup_complete` 由 adapter 的实际动作与后置观察派生; judge 拒绝调用方手填.

## S1 已实现

1. catalog v2: 25 旧 suite 全部有 disposition, 64 case 覆盖核心/MCP/上游协议/域名与 IP/进程改址/双 PCAP/载荷/MCP/构建/Linux/手工/组合; GUI/100/150/新出口显式排除, 共享核心保留.
2. 离线闭环: 真实 CLI 在 `test/test_tlshello.py`、`test/test_dual_pcap_writer.py` 和三个自测模块上完成 collection → execute → 自动收证 → 严格重判; 2026-10-22 本轮证据中 selected 5/5 pass, 但 `full_functional_pass=false`.
3. 严格判定负例: 错候选、错 execution_id、配置漂移、源漂移、缺项、重复、skip、OBSERVED、假 cleanup、rc0 失败、输出碰撞、未知 schema/命令/case/suite 全部在对应入口被拒, 原失败保留.
4. 原 `test.py`: 失败汇总进入非零退出和结构化 TSV; 首次失败后重试成功记为 FLAKY, 不抹首次失败; MultiHost 支持 `--non-interactive`; Host 名单夹具改为真正命中 listener 级黑/白名单; SMTP SSL 修构造 API、实际 `sendmail` 调用、成功返回和错误传播.
5. 文档: 本 README、派生 `清单.md` 和 `docs/testing.md` 导航.

## 尚未完成 (S2..S4)

- 原生适配器: DOMAIN-EGRESS/DOMAIN-IP/PROCESS-REDIRECT/PCAP/PAYLOAD/MCP/LINUX-RUNTIME/GAP-MANUAL/GAP-APPLICATION 仍为 `blocked`, 需要真实 VM、受控端点、Sentinel/Sink 和逐 case 的原 oracle 解析.
- `judge` 目前只解析 JUnit/TSV; 原生 `result.json`、PCAP、HTML 报告适配器尚未接入. 原生 case 不能因文件存在或包成功签通过.
- 资源调度/并行/恢复 (IMP-008) 和完整原生集成 (IMP-009/ACC-014) 未开始.
- 100/150/新出口保持排除; 历史原生失败 (SMTP SSL、Windows IRC、Linux 进程黑名单) 保留原记录, 只有当前真实运行才能重判.

## 限制

- 静态 inventory 的文件数/声明数不是运行覆盖; 参数化节点的真实集合由 collection 决定.
- `check`/`inventory` 不执行驱动; `plan --mode` 的 collection 是代码执行, 只对 `collection_safe` 且 environment 允许的模块进行.
- S1 的成功只证明离线能力, 不代表任何 Windows/Linux 原生功能通过.
- 共享资源 (VM/驱动/捕获/路由/DNS) 仍由原驱动持有停止与恢复责任; 外层不新增竞争状态机.
