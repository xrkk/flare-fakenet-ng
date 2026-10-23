# FakeNet 集中验收

本目录集中现有 Windows/Linux 核心、策略、GUI、PCAP、载荷报告、MCP、发布和辅助验收. 目标是修改产品或接口后, 能明确选择并执行同一份回归清单, 对照原始结果判断是否破坏已有功能.

当前状态: **盘点 + S1/R02 离线闭环 + S2 native 判定骨架 + 无GUI策略单元(T004/R01 部分)**. `catalog.json` 已升级为 v2, `tools/acceptance.py` 已具备候选/环境绑定的 `plan --mode`、`execute` 和严格 `judge --results`; R02 增加了注册表/模式/源/环境动作校验、JUnit 精确节点集合判定、receipt 身份与 oracle 类型校验、adapter 派生 cleanup, 并接通 12 个安全离线 case. 原 `test.py` 的退出、Host 名单夹具、SMTP SSL 拒收/错误、stop 失败和 MultiHost 就绪也已修, 并有离线合同自测. S2 已完成策略配置/生命周期/独立judge的离线合同和 fixture, 但真实策略探针、真实原生运行、S3 资源调度、S4 完整验收尚未完成. 当前没有任何新的原生实机通过, 不能把本目录或 S1/S2 fixture 当作完整设施验收.

排除范围保持用户裁决: GUI 窗口/点击/UAC/三轮停止、旧 100 场景、150 轮发布和新出口验证接口不进入 full; 它们的共享核心已按断言/调用用途抽取为独立 case, 没有因目录名删除.

## 文件

- `catalog.json`: 唯一手工定义来源. v2 含 25 个 suite、64 个 case、显式 `exclusions`、平台/模式/输入/步骤/正反预期/oracle/资源/就绪/超时/清理/依赖. `disposition` 记录 keep/extract/exclude.
- `清单.md`: 由 `tools/acceptance.py inventory --format markdown` 程序派生, 不手改.
- `tools/acceptance.py`: 兼容入口. v1 的 `inventory`/`check`/`plan --output`/`run --suite`/`judge --result` 保持原语义; v2 新增模式化 plan、离线 execute 和严格 judge.
- `tools/acceptance_native.py`: native driver 注册表, 固定 argv/子检查/oracle, 不执行未授权 native.
- `tools/acceptance_policy.py`: 无GUI策略配置/固定生命周期/结果入口; `tools/acceptance_policy_oracles.py`: 重读配置/日志/PCAP并独立判定.
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
- `execute`: 在任何子进程前重新校验 plan 注册表、mode、case 集合、adapter/oracle、源 hash、environment 动作和 blocked 状态; 通过后按精确 collection 节点执行注册适配器, 自动收集 stdout/stderr、返回码、JUnit、耗时和 adapter 派生 cleanup; 正常结束时自动调用同一 judge. `allowed_actions` 没有 `offline-pytest` 时在执行前拒绝, 只有 `collection` 时 plan 可完成合法收集但 case 记 blocked.
- `judge --results`: 从本轮 results 索引读取收据, 重验原件 SHA, 重算终态. 不信任 plan 自报 mode/局部集合: full 必须等于 catalog 完整必需集合; index/receipt 必须与计划 case/suite/adapter/oracle/environment/config 一一对应; JUnit 的额外节点、缺失、重复、skip、OBSERVED、unknown/timeout 及非零返回码都不能升级为 pass. 不遍历历史结果猜选.
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
2. 离线闭环: 真实 CLI 在 12 个安全离线 case 上完成 collection → execute → 自动收证 → 严格重判 (tlshello、dual-pcap writer、三个设施自测、diverter、listeners、DNS、PCAP、Linux 规则、payload report/integrity). 2026-10-22 R02 证据中 selected 12/12 pass, full 12 pass + 49 blocked, `full_functional_pass=false`.
3. 严格判定负例: MAIN-001 把 selected 改名 full、MAIN-002 额外 skip/unknown、MAIN-003 错 case/environment、MAIN-004 collection-only 执行, 以及错候选、错 execution_id、配置/源漂移、缺项、重复、skip、OBSERVED、非法 adapter/node、假 cleanup、rc0 失败、输出碰撞、未知 schema/命令/case/suite 全部在对应入口被拒, 原失败保留.
4. 原 `test.py`: 失败汇总进入非零退出和结构化 TSV; 首次失败后重试成功记为 FLAKY, 不抹首次失败; stop 失败/异常进入失败结论; MultiHost 的 `--non-interactive` 必须配合显式 `--multihost-ready`, 缺就绪停止该 suite; Host 名单夹具改为真正命中 listener 级黑/白名单; SMTP/SMTP SSL 用当前 API 实际发送, 全/部分拒收和异常不返回成功.
5. 文档: 本 README、派生 `清单.md` 和 `docs/testing.md` 导航.


## S2 native adapter 代码状态

`tools/acceptance_native.py` 是本套 native 的固定注册表. 每个 driver 声明平台/模式、固定 argv 数组、固定子检查表、单一 oracle、候选包要求和收尾责任; 不接受调用方传入 shell/cmd 字符串. `environment.allowed_actions` 必须包含 `native` 才会解除 native 的 blocked 状态; 本轮所有实际 native 运行预算为 0, 因此真实运行仍为 NOT_RUN.

本轮停用未适配的生产包装: `upstream-singlehost` 仍会整跑 test.py, `egress-windows`/`reviewed-ipv4-windows`/`process-redirect-windows` 仍有固定路径、占位、依赖安装或压力步骤; 它们不再标为可用, 原 case 与功能保留待改.

已注册但明确 blocked (代码未接入, 不缺项静默丢弃): `upstream-multihost`, `pcap-windows-functional`, `pcap-linux-functional`, `policy-headless`, `payload-headless`, `mcp-p01`..`mcp-p04`, `mcp-special`, `linux-runtime`, `manual-headless`, `build-identity`.
本轮新增 `policy-domain`/`policy-ipv4`/`policy-takeover`/`policy-combined` 四个 Windows singlehost driver: 固定配置来自仓库内已审 INI 模板, 生命周期有真实就绪/停止/退出观察, oracle 重读原配置/日志/PCAP并核对 attempt/nonce/五元组/双向服务. 当前只完成离线 fixture 和结构合同, 真实探针未实现, 生产结果一律 `not_run`; 不产生 native 或 full 信用.

native 的 plan 只展开固定子检查; execute 只在 action/平台/候选包身份齐全时按固定 argv 运行; judge 核 argv/子检查/全部原件/必需 stdout-stderr/退出与 cleanup 一致性. T003/R02 修复了重复/缺失/额外/矛盾超时/缺日志/假 resources 的误判; fixture 通过只给 `fixture_contract_pass`, 不授 `full_functional_pass` 或当前 native 信用.

## 尚未完成 (S2..S4)

- 原生适配器: DOMAIN-EGRESS/DOMAIN-IP/PROCESS-REDIRECT/PCAP/PAYLOAD/MCP/LINUX-RUNTIME/GAP-MANUAL/GAP-APPLICATION 仍为 `blocked`, 需要真实 VM、受控端点、Sentinel/Sink 和逐 case 的原 oracle 解析.
- `judge` 已解析 JUnit/TSV 和策略 `policy-result`; 上游/PCAP/HTML 报告适配器仍按各自 oracle 接入. 原生 case 不能因文件存在或包成功签通过.
- 资源调度/并行/恢复 (IMP-008) 和完整原生集成 (IMP-009/ACC-014) 未开始.
- 100/150/新出口保持排除; 历史原生失败 (SMTP SSL、Windows IRC、Linux 进程黑名单) 保留原记录, 只有当前真实运行才能重判.

## 限制

- 静态 inventory 的文件数/声明数不是运行覆盖; 参数化节点的真实集合由 collection 决定.
- `check`/`inventory` 不执行驱动; `plan --mode` 的 collection 是代码执行, 只对 `collection_safe` 且 environment 允许的模块进行.
- S1 的成功只证明离线能力, 不代表任何 Windows/Linux 原生功能通过.
- 共享资源 (VM/驱动/捕获/路由/DNS) 仍由原驱动持有停止与恢复责任; 外层不新增竞争状态机.

### Exact upstream execution

The original `test/test.py here [regex ...]` interface is retained. The new
`python test/test.py --mechanical-spec SPEC.json` accepts schema
`fakenet.upstream-selection.v1` with exactly `schema`, `checks`, `target`, and
`work_root`. `checks` contains unique `suite::test name` IDs from the original
platform-specific callback definitions, for example `General::DNS listener test`.
Unknown, duplicate and platform-inapplicable selections fail before target
operations. `target` is the exact local `{platform, hostname}` identity and
`work_root` must be a fresh absolute directory on the selected VM. MultiHost
requires a separate observed remote channel and is refused by this entry.

Each selected configuration starts one owned core using a fixed argv, waits for
the actual successful-start marker, executes only selected original callbacks
without automatic retries, requests stop, reaps the process and compares network
state. Original TSV plus `upstream.json`, core lifecycle and before/after network
snapshots remain in the run directory. Failure to stop or restore prevents later
suites from using the same resource. Forced termination never earns cleanup
credit. This implementation has offline process/channel contract tests; native
platform acceptance remains required.

### Noninteractive dual-PCAP functionality

Linux: `python test/dual_pcap_linux/run_tests.py --functional --case normal
--case raw-write --case ethernet-write --case close --output-directory ABSENT_ABSOLUTE_DIR`.
Windows: `powershell.exe -NoProfile -NonInteractive -File
test/dual_pcap_vm/Run-DualPcapTests.ps1 -Functional -CaseSet
normal,raw-write,ethernet-write,close -OutputDirectory ABSENT_ABSOLUTE_DIR
-PythonPath PYTHON`. These run only the explicit functional modes and installed
dependency checks, with no dependency installation, broad unit discovery,
benchmark, UAC prompt or keypress requirement. Historical entry behavior remains
available without the new switch.

Normal Windows execution uses the stop flag. Both platforms retain original
packet generation and original pair verifiers; Linux also verifies original and
mangled marker destinations. Each mode retains process exit evidence, capture
logs and before/after network snapshots. Faults must hit their own fatal path;
Linux write faults additionally require its NFQUEUE current-packet-drop marker,
which is not a Windows contract. Network differences and forced termination
remain failures, including when emergency rollback subsequently succeeds.

Offline tests replace native processes/network but execute the original PCAP
oracles on benign packets. They do not certify Windows/WinDivert or
Linux/NFQUEUE runtime behavior.

### Native target and original evidence binding

The unified production adapters now support `upstream-singlehost`,
`pcap-linux-functional` and `pcap-windows-functional`. Native execution requires
`allowed_actions` to contain `native` and an explicit environment field:

```json
"native_runtime": {
  "transport": "local-target",
  "identity": {"platform": "linux", "hostname": "EXACT_VM_HOSTNAME"}
}
```

Run the unified entry on this selected VM with its project interpreter.
`candidate.deployed_identity` must equal the observed target identity. The
runner checks administrator/root and actual VM identity before starting a core;
a host platform label alone cannot authorize local native execution. No remote
VM is silently substituted and this channel performs no deployment or snapshot
reset. Existing-channel Host-to-guest and MultiHost code paths are described below; actual native acceptance remains pending.

Plans freeze platform-specific exact upstream IDs without importing client
libraries or contacting the target. Native results retain all indexed original
files, both execution logs, request and observed target. Independent `judge`
reopens the original driver outputs, compares lifecycle/network observations
and invokes original PCAP content verifiers; a status-only JSON is insufficient.
A timeout never treats a killed outer process as proof of network restoration.
Unresolved native cleanup prevents following native cases; independent offline
cases can continue. `offline_fixture` candidates retain only fixture credit even
when their tests exercise production adapter code. Native/full acceptance is
still pending and cannot be inferred from these offline tests.

### Existing host-to-VM channels (code, native acceptance pending)

`windows-mcp-velo` extends `native_runtime` with `mcp_config_ref` and
`mcp_server` referencing the existing URL-only Windows MCP configuration,
plus the guest `python`, `source_root`, and an E/D `work_root`. The existing
`transfer` deployment reference supplies `python/python_sha256`,
`origin/origin_sha256`, `connection_profile`, `expected_vm_identity`
(`vm_uuid/boot_identity/vm_epoch`) and the original Velo `budget`.
`allowed_actions` must explicitly include `native`, `vm-execute`, `vm-transfer`.
Credentials stay inside the existing client/coordinator; this adapter creates
no profiles, bearer tokens, SSH installation or transfer service. Authenticated
Windows configurations unsupported by the original Win10VmChannel are rejected.

The host pins the original source set in the plan, pushes only a closed request
through `python -I -B -m velo_transfer --spec`, verifies MCP and transfer VM
identity, then invokes the pinned `tools/acceptance_guest.py` once. The target
verifies request/source/catalog/check identities before starting the registered
driver. Only after the original producer has exited does the host pull that
exact output directory through the same coordinator. It preserves the guest
receipt bytes, maps artifacts by relative paths and independently invokes the
original content oracles. Transfer completion requires publication, both cleanup
results, the expected VM and local hashes. Unknown submission is retained with
its original intent and is never silently replayed or moved to another channel.

`remnux-sdk` executes registered Linux upstream/PCAP cases through
`acceptance_linux.ExistingRemnuxChannel`, reusing the deployed REMnux SDK,
Host-authoritative health/epoch, mutation UUIDs and original put/get. Required
runtime references are `connection_ref/module_root`, `expected_vm_uuid`, the
existing `workspace_id/workspace_root`, absolute `python/source_root/work_root`
and exact `identity={platform: linux, hostname: ...}`. `work_root` is inside that
workspace's `work/` directory; a fixed read-only command observes the actual
workspace cwd and VM hostname, and pins the target entry before execution.
The adapter does not create a workspace, install SSH or deploy a candidate.

The SDK starts the fixed guest entry once. Read-only process queries follow
that original job ID and kernel birth until `state=exited`; `unknown`, `stopped`,
birth changes or timeout never enable collection/replay. The last guest producer
writes a closed, hash-bound export index. After observing its exit, the Host
uses existing SDK file downloads for precisely those originals, preserving their
remote-to-local relative mapping and then invoking the original Linux byte
oracle. No AI performs chunk transfer or fills individual result fields.

`UPSTREAM-MULTIHOST` is a separate original functional case, covering General
and No Redirect configurations and every original platform/mode callback.
Use a `native_runtime` with `transport=remnux-multihost`, `server_ipv4`, `server`
(the existing Linux REMnux runtime above), and a distinct `client`. The client
uses either `windows-mcp-velo` (the original supported client platform) or
`remnux-sdk` (the original optional Linux client). `allowed_actions` additionally
includes `multihost`; `candidate.deployed_identity` names both exact `server`
and `client` identities. The original documented client gateway and DNS must
already point to the server; probes observe that topology, without changing it.

For each original configuration the Host transfers the original INI and its
ancillary files, starts one bounded owned server, obtains an actual Observe
(owner/core PID birth, config/source hashes and successful-start log), passes
that observation to the fixed client entry, runs exact original callbacks,
then observes the same live server again. Negative connection probes cannot
pass because the server died. Finally it requests only that owner's stop flag,
observes producer exit and collects both sides' originals. Unknown submission
retains the original intent/ID and never silently creates another job. A failed
or unresolved configuration prevents the next configuration from starting.
Independent judge rechecks configuration derivation, source/target identities,
both exact original indexes, observations, callback set and network/core
recovery. It does not treat a supplied ready boolean or status-only JSON as proof.

These paths have only safe SDK/process/Windows-channel substitute tests. The
original PCAP content validators remain real in those tests. Actual Windows
PowerShell syntax/execution, authenticated/deployed channel operation, Linux
NFQUEUE, Windows WinDivert and complete native acceptance are still unverified.
All other planned policy, payload, MCP, Linux deployment/manual, package identity,
scheduling/reuse/recovery and final full regression work remains required.
