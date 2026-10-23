# FakeNet 集中验收

本目录集中现有 Windows/Linux 核心、策略、GUI、PCAP、载荷报告、MCP、发布和辅助验收. 目标是修改产品或接口后, 能明确选择并执行同一份回归清单, 对照原始结果判断是否破坏已有功能.

当前状态: **集中盘点、S1 离线闭环和部分 S2 生产代码; 原生与完整验收未完成**. `catalog.json` 已升级为 v2, `tools/acceptance.py` 已具备候选/环境绑定的 `plan --mode`、`execute` 和严格 `judge --results`; R02 增加了注册表/模式/源/环境动作校验、JUnit 精确节点集合判定、receipt 身份与 oracle 类型校验、adapter 派生 cleanup, 并接通 12 个安全离线 case. 原 `test.py` 的退出、Host 名单夹具、SMTP SSL 拒收/错误、stop 失败和 MultiHost 就绪也已修, 并有离线合同自测. S2 已完成策略及进程改址/双向载荷的配置、探针、原verifier和独立judge代码; 进程改址/载荷四case可用纯内存边界执行同CLI的plan/execute/judge. 真实Windows原生运行、S3资源调度、S4完整验收尚未完成. 当前没有任何新的原生实机通过, 不能把本目录或 S1/S2 fixture 当作完整设施验收.

排除范围保持用户裁决: GUI 窗口/点击/UAC/三轮停止、旧 100 场景、150 轮发布和新出口验证接口不进入 full; 它们的共享核心已按断言/调用用途抽取为独立 case, 没有因目录名删除.

## 文件

- `catalog.json`: 唯一手工定义来源. v2 含 25 个 suite、64 个 case、显式 `exclusions`、平台/模式/输入/步骤/正反预期/oracle/资源/就绪/超时/清理/依赖. `disposition` 记录 keep/extract/exclude.
- `清单.md`: 由 `tools/acceptance.py inventory --format markdown` 程序派生, 不手改.
- `tools/acceptance.py`: 兼容入口. v1 的 `inventory`/`check`/`plan --output`/`run --suite`/`judge --result` 保持原语义; v2 新增模式化 plan、离线 execute 和严格 judge.
- `tools/acceptance_native.py`: native driver 注册表, 固定 argv/子检查/oracle, 不执行未授权 native.
- `tools/acceptance_policy.py`: 无GUI策略配置/固定生命周期/结果入口; `tools/acceptance_policy_oracles.py`: 重读配置/日志/PCAP并独立判定.
- `tools/acceptance_headless.py`: EXE改址/双向载荷的固定输入、生命周期和纯内存边界; `tools/acceptance_headless_oracles.py`: 调用原verifier重判PE/client/PCAP/raw/converted/HTML.
- `tools/acceptance_mcp.py`: MCP六case固定输入、HTTP/process/channel/clock内存边界; `tools/acceptance_mcp_oracles.py`: 复用原MCP result/round/incident/IPC validator.
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

纯源码离线组只要求真实 `source_commit`; 原生组才需要实际包/部署身份. 源码、运行及混合集合仍保留当前产品 HEAD 约束. 包执行身份按实际注册分两层: `BUILD-PACKAGE-IDENTITY` 与六个 `MCP-P01-FULL/P02/P03/P04/SPECIAL-IPC/SPECIAL-FAULT-RECOVERY` 形成唯一包层集合, 只有该完整集合允许 candidate/plan 的 source_commit 保持旧包 manifest 来源, 当前 harness 仍由 source_hashes/native_source_hashes 及原 ZIP/`mcp-input.v2` 验证器固定. ACC019 依赖先展开为 P03/ACC008 再分类; 源码、运行、混合集合及任何未核包/目标仍保留原 HEAD 或拒绝条件. 不写当前 HEAD 冒充包来源, 不改旧包/旧候选/旧计划, 不证明旧包等于当前产品或满足新的构建资格/运行要求. 已有 source/mixed 计划在 execute/judge 时只在冻结路径集合的 Git 对象逐项相同且工作树 pins 完整通过时接受无关 HEAD 漂移, 缺失或变化拒绝; 不新增调用方豁免开关.

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

历史 T003/R01 的整跑 test.py 问题已由精确选择修复; 仍停用的旧包装为 `egress-windows`/`reviewed-ipv4-windows`/`process-redirect-windows` 仍有固定路径、占位、依赖安装或压力步骤; 它们不再标为可用, 原 case 与功能保留待改.

upstream singlehost/MultiHost、Windows/Linux 双 PCAP 和四个策略 driver 的代码已接入, 真实环境未验. 仍未接入: `policy-headless`, `payload-headless`, `mcp-p01`..`mcp-p04`, `mcp-special`, `linux-runtime`, `manual-headless`, `build-identity`.
本轮新增 `policy-domain`/`policy-ipv4`/`policy-takeover`/`policy-combined`/`policy-combo` 五个 Windows singlehost driver: 固定配置来自仓库内已审 INI 模板, 生产路径发送真实 DNS/TCP/UDP/TLS FNPR/1 请求, oracle 重读实际 INI/日志/PCAP 帧并核对 attempt/nonce/五元组/双向服务. 另有 `policy-substitute-*` 仅用于本机安全替身: 同 CLI 的 plan/execute/judge 覆盖策略/组合 case, 结果为 `fixture_contract_pass` 且 `full_functional_pass=false`, 不产生 native 信用. 新 `policy-combo` 以单个最终 INI/核心/捕获窗口覆盖 12 项组合检查; `sink_tcp`/`sink_udp` 先消费 denied_domain 的实际 DNS sink 回答, 不回落固定地址.

`policy-combo` 现在另外保存 `combo-context.json`, 把本轮配置指纹、核心出生身份、起止窗口、捕获和各探针绑定在一起. DNS 后的应用探针必须使用同轮实际 DNS 发送/应答原字节, sink 的停止态探针保持固定端点对照. 新 oracle 拒绝跨配置/轮次拼接、未发送/错误入口/无原包/晚到 DNS 和虚假恢复. 这些新增要求只适用于 combo, 原四个原子策略合同保持.

当前离线自验为 9 tests/4 subtests 通过; 真实注册的三个父策略和 combo 经正式 plan/execute/judge 及 4 个真实纯 substitute 子进程执行, 仍为 fixture 信用. 测试使用的 TemporaryDirectory 已清理临时探针/CLI原件, 留存测试 stdout/退出/进程/旧新 oracle 对比记录; 这批临时路径不作为可离线重放的归档验收原件. 实际用户执行目录的原件保留机制未改变, 原生集成及其归档重判仍未验.

## 有界离线调度

`tools/acceptance_scheduler.py` 对已核 `CORE-TLSHELLO` 与 `CORE-DUALPCAP-WRITER` 使用最多 2 个工作者, 还受可用 CPU/内存约束; 未知容量及嵌套调用保守取 1. 其它组串行, 同一显式互斥资源不重叠. 所有 adapter 走同一前驱队列, 不再提前执行全部离线组. 子进程独占 `results/<case>/tmp`, 禁止共享 pytest 缓存; 子环境递增嵌套深度并保持产品导入根, 主线程按原计划顺序关闭唯一 `results.json`.

前驱/资源状态由原件 judge 重判后推进, 不信 `cleanup.recovered` 字段单独授予恢复. 未恢复只阻断实际目标/资源与其依赖, 物理身份不明按相关目标保守处理; 已知独立目标和只读包校验可继续. 主控独立 judge 重建阻断原因, 错原因、缺过程原件或重hash谎报不能过关. 工作者设施异常保留原始错误和完整索引, 退出 3, 独立项继续; 产品失败和超时原件保留.

离线 Python 启动记录本次进程出生及独占进程组/Job, 超时只回收本次拥有的子树, 原件 `process.json` 包含清理前后观察, 不能只取消 Future 或声明 cleanup=true. 无法确认退出时保留 unknown/受影响资源不可复用. Linux 使用保留 leader 身份的 WNOWAIT 观察、按出生身份/pidfd 跟踪的后代(含新 session)及后置检查; Windows Job 分支未做原生验证. native 的停止/恢复仍由原驱动负责, 调度不重发 stop/recover. 这些设施代码/良性 fixture 检查不代表 Windows/Linux 原生产品或完整方案验收通过.

native 的 plan 只展开固定子检查; execute 只在 action/平台/候选包身份齐全时按固定 argv 运行; judge 核 argv/子检查/全部原件/必需 stdout-stderr/退出与 cleanup 一致性. T003/R02 修复了重复/缺失/额外/矛盾超时/缺日志/假 resources 的误判; fixture 通过只给 `fixture_contract_pass`, 不授 `full_functional_pass` 或当前 native 信用.

### EXE改址与双向载荷

四个正式case保持原ID: PR-REDIRECT-POSITIVE、PR-OWNER-BOUNDED、PR-PCAP-RESTORE、PAYLOAD-THREE-WAY. 生产适配器为process-redirect-headless/payload-headless, 使用同一tools/acceptance_headless.py编排. 外部任意commands和事后artifacts不再是输入. 程序生成固定INI、核心和原生客户端argv, 观察就绪、NIC捕获/转换、受控停止, 保留映像副本、客户端属主/出生身份、网络前后和原字节, 独立judge调用原EXE及三个payload验证器.

环境headless对象schema=fakenet.headless-input.v2, 必需source_ip(被选VM)、target_ip(同接口子网的RFC1918宿主B)、original_ip(原A, 沿core认可的公网/文档IPv4)、port、upstream_dns. EXE组另需target_path/non_target_path为已部署的两份原良性native PE绝对路径, target_sha256/non_target_sha256为其完整内容身份; 名单、映像路径/字节和进程出生/流不能相互替代. payload组不需要这四个PE字段. 不自动编译、部署或选择实际目标.

正常Windows host-to-VM使用现有windows-mcp-velo通道, 仍要求native/vm-execute/vm-transfer动作; 响应端额外使用已授权policy-services动作及headless_service={bind_ipv4: 与target_ip同值, allowed_peer_ipv4: 与source_ip同值, max_seconds: 1..300}. 复用原有界FNPR宿主响应端, 闭合原始字节/nonce/五元组/属主生命周期与来宾证据相互核对. 远程未知不拉活动原件或重放, finally只停本端服务. 所有生产字段必须显式, 缺项/未知选择在进程前拒绝; 原生验证当前未执行.

EXE功能有界owner流的并发量从实际core token bucket源码和hash派生, 保留真实已审预算拒绝事件及成功回包, 不要求最终每个TCP重试都失败. 原10000/64压力定义保留为可选stress, 不作为日常功能门槛. NIC窗口位于非目标对照之后, A线上包不能与core的A/B观察视图混计. 配置关闭、映像/owner不符、错nonce/回包、无关单向包、双PCAP错字节、载荷缺方向/gap/conflict/多PID均不能通过; 无观测/端点故障保持未验, 网络前后或属主停止不成立不获恢复信用.

纯内存边界与生产使用同一编排和正式catalog; candidate.offline_fixture=true才由统一适配器加--memory. socket/process/capture/channel边界模拟OS返回, 原协议字节及内容验证器真实执行, 不改catalog换成fixture驱动. 历史process-substitute/payload-substitute仅兼容设施测试入口, 不给原生信用.

```text
python tools/acceptance_headless.py --mode process --memory --output <未占用目录>
python tools/acceptance_headless.py --mode payload --memory --output <未占用目录>
```

原件根Logs/acceptance-regression-20261022/main-headless-r16包含正式CLI本机/Windows通道内存正常链及三种已知坏原件独立重判. 相关回归129 passed、31 subtests passed, 只证明实现和离线设施行为; 实际Windows PE/WinDivert/物理NIC/pktmon语法与完整恢复仍NOT_RUN. 之前T005/R01的COMPLETED自报未获主控接受, 原错误原件/结果保留.

### MCP P01-P04 与 SPECIAL

MCP原入口是宿主控制器, 通过既有Windows MCP通道操作已核来宾, 不把控制器复制进VM运行. 正式六case现统一绑定`mcp-headless`固定驱动. `environment.mcp`的`fakenet.mcp-input.v2`输入包括原候选/包与manifest完整身份、VM UUID、配置SHA、显式私网端点/允许源、原通道配置引用、具体actions、宿主证据根、已安装路径及来宾E/D工作根. 不支持操作者任意`commands`或自填产物补全. 原候选ZIP逐文件验证器保留; 包外SHA与内嵌manifest分别核验, manifest不要求不可能自引用的ZIP哈希.

每个原ACC按固定映射直接调用原业务函数. 记录原HTTP/PowerShell/进程与必要socket边界的完整输入输出, 原EvidenceWriter保存断言与原件; 独立judge在禁止真实副作用的回放边界上重新执行同一原业务函数及原validator, 不依据成功摘要或文件存在授予通过. 记录改变但引用hash同步正确的业务失败仍须失败. 输出原件与回放工作根分开, 新回放不污染已关闭原件索引. 只有`candidate.offline_fixture=true`可使用测试边界; 内存结果不授native/full信用.

动作前验证实际VM/已安装映像SHA与出生身份、ping的构建manifest/source、服务空闲及当前配置. 仅回收有本轮成功回执的run/临时配置, 按SHA恢复原配置并核原故障模式与独立前后网络; 未知属主/未恢复状态保留, 不重试或杀同名进程. 每组全功能检查是原ACC集合, full模式不允许用`mcp_checks`缩为一项. selected模式可定点运行, 结果只代表选中断言.

当前MCP实现仍在实施中: P02原四组配置/控制者/并发幂等及管理断言已经在实际工具域(ConfigStore/Coordinator/原tools)和纯内存OS边界验证; 同正式catalog公共CLI的ACC005正常与重hash坏响应判别已验证. 后续已接原P01协议/SDK调用接口、安装服务身份和当前声明工具面的原函数, 五类原故障/incident字节和六类原IPC父子记录/receipt/恢复函数及三旧坏内容拒绝. 这些只在HTTP/PS/process/socket/clock边界替身下验证, 原业务和validator未替换. SDK传输实际未运行: 异步事件循环需要socketpair而零socket guard拒绝, 测试只验证SDK返回结构和接口后的业务判断. SDK认证接入改动被自动审批拒绝, 未执行; 当前不修改认证, 不要求无用途客户端认证参数.

P03正常接管和P02同一工具域整组已验证. 现有LifecycleDouble缺进程唯一性门禁, 因而无GUI重复启动用例被保留为正确失败反例; 真实Supervisor已有进程的拒绝分支单独离线核对, 不拿生命周期替身当唯一实例正常通过. P01访问源/防火墙完整闭环, P03其余异常/恢复/锁, P04全部产物和受控退出, SPECIAL初始化/控制/loopback等仍未完整验证, 真实MCP/native全未验. 原GUI/100/150和旧硬编码历史候选资料链排除, 原产品断言保留. 既有IPv6网络loopback用例没有移除, 缺环境须未验, 不新增IPv6产品支持.

来源证据: `Logs/acceptance-regression-20261022/main-mcp-r18/`. package01夹具时间戳失败、public01候选身份夹具错误、public02缺具体失败摘要、public03最小非MCP夹具被全闭包读取影响、domain01/02原runner过期版本复用失败均保留. 对应定点修复后的package02、public04、domain04和transport01通过. 真实VM/MCP/HTTP网络/监听/核心/构建安装操作均未执行.

### 策略生产与安全替身

生产 driver 必须在 environment.policy 中显式提供全部输入, 不默认填公网或历史地址:

- 域名: allowed_domain, wildcard_domain, apex_domain, denied_domain. 拒绝域名不得被允许通配覆盖.
- DNS 和 VM 源: upstream_dns, dns_address, dns_port, local_source.
- 审核目标: reviewed_ip, reviewed_port, denied_http_port, denied_alt_port, denied_udp_port, other_ip, other_port.
- 宿主端和非目标对照: sink_ip, sink_port, adjacent_ip, adjacent_port.

输入只服务于集中策略回归, 不要求恶意软件分析使用同一配置. 缺项在 core 启动前拒绝; 不自动改变 VM 网络. 选择在动作前应用, 只选 route_restore 不发送 DNS/TCP/UDP/ping. ExternalAllowedIPv4Rules 使用实际 core 的 TCP/IPv4/PORT 语法.

应用测试复用良性 FNPR/1 nonce 请求/响应协议. 目标须具备对应响应能力; 任意公共 HTTPS 站点不会仅凭连接成功得到应用信用. TLS 正常验证证书, 可通过 tls_ca_file 引用已有 CA、tls_peer_sha256 固定已有证书 DER 身份, 不创建或传递私钥. IPv6 只有显式 ipv6_target 与 local_source_ipv6 才能运行, 缺少时保持未验, 不修改 VM IPv6.

Windows 远程宿主 TCP/UDP 项由原 MCP/Velo 通道编排, 额外要求已授权 policy-services 动作和 host_service 对象: bind_ipv4 等于 sink_ip, allowed_peer_ipv4 等于 local_source, max_seconds 为 1..300 的整数. 程序先核 VM 身份, 然后只在选定本机接口/端口启动有界属主响应端, 记录源端口、nonce、原始收发字节及属主出生/结束身份. 正常、失败和远程状态未知都停止自己的服务; 未观察远程生产者退出时不拉取活动证据、不重放, 保持 unknown. 最终 judge 关联独立宿主原件与来宾流和字节.

oracle 重读实际 INI、日志范围、probe JSON、PCAP/PCAPNG 完整五元组/时窗/方向和应用内容. 禁止端口有成功响应会失败, 超时不能单独证明拒绝, 还须匹配当前策略决定及停止态可达对照. 恢复来自独立前后网络快照和本轮 core 属主退出原件; 无观察不能填相同伪值冒通过.

纯内存自测不改正式 catalog 或 driver: candidate 显式 offline_fixture=true 才选择内存 socket/process 边界. 同 plan/execute/独立 judge 覆盖八个原策略 case; 不绑定端口、不发送网络包、不执行 ping/core. fixture_contract_pass 不给予 native/full 信用. 旧 policy-substitute 入口仅保留兼容.

```text
python tools/acceptance_policy.py --scenario domain --substitute --output <未占用目录>
python tools/acceptance_policy_oracles.py --original <目录> --scenario domain --checks exact_domain,wildcard_domain,apex_denied,default_deny,tls_application,route_restore --allow-fixture
```

fixture 空捕获不能通过内容判定, 默认 oracle 拒绝 fixture. allow-fixture 只用于设施自测. 本次相关离线回归 115 passed、19 subtests passed; 原件在 Logs/acceptance-regression-20261022/main-policy-r14/. 原 R02 的 loopback 服务/ping 超出当轮零网络预算事实及失败原件保留, 后续修复不抹除历史. 当前没有新的实机通过.

## 尚未完成 (S2..S4)

- S2 其余 EXE/载荷、MCP P01..P04/SPECIAL、Linux 部署/手工功能、未支持格式的包身份仍有未实现项; MCP ZIP 只读身份已接入, 见下文; 已接入 upstream/PCAP/策略的真实环境验收也未执行, 未实现与未验分别保留.
- `judge` 已解析 JUnit/TSV 和策略 `policy-result`; 策略内容 oracle 需要实际非空 PCAP 帧、配置选中值、attempt 时间窗和日志策略事件. 上游/PCAP/HTML 报告适配器仍按各自 oracle 接入.
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

本轮补充原件: `main-mcp-r18/fault-01`五fault原函数通过; `ipc-01`单次timeout并发回放未消费完整记录失败, 将原线程存活观察纳入OS记录后`ipc-02`通过且未缩时间窗口. `content-01`相关41tests/27subtests通过, 五类错误hook/nonce和IPC错receipt/缺child/跨candidate不再通过. `protocol-01`发现原P01对嵌套JSON字符串直接匹配误拒, 改按协议解析service后`protocol-02`通过. `sdk-01`被零socket guard拒绝事件循环socketpair, 原失败保留; 后续只SDK边界结构替身, 不授实际SDK信用. `groups-01`生命周期替身缺重复启动保护保留为反例, 正常接管另验; `resume-02`相关45tests/28subtests通过. `no-auth-change-01`当前20tests/28subtests通过. 无真实VM/网络/监听/核心/构建安装.


MCP恢复判定与业务结果独立: 业务断言失败但配置SHA、服务模式和独立前后环境均恢复时, 保留业务失败并单独记录clean=true. 恢复未观察到或恢复失败时, 不执行该组剩余单元, 记录not_run及未决原因. 来源索引递归绑定固定原模块的本地传递依赖和静态脚本引用; 不从结果提供的任意路径加载代码.

P01非允许源探针现在记录源地址HTTP边界供独立回放. 绑定/路由失败、连接超时或无关HTTP错误只能判未知/blocked, 不作为远端阻断通过; 实际端点拒绝与正常协议响应分别判定. 默认探针来源仍须现场可用, 当前未证明实际防火墙全链. firewall-attribution-02正常/反例及firewall-impacted-02相关49tests/31subtests仅为guard下的内存边界信用, 不授真实网络或整体验收通过.

P04功能与信用映射见[mcp-capability-map.md](mcp-capability-map.md). 新`INCIDENT-INTEGRITY`仅供selected定点检查原机械断言, full不为此重复触发故障, 原`ACC-014`完整包内根因定位与terminal/条件转储要求仍在full集合; 未完成项不能以切片通过替代.


控制/初始化接入增量: 原CONTROL-DEFAULT、四CONTROL-EXTRA与既有LOOPBACK-V4/V6使用当前冻结VM/source/端口和来宾工作根, 不再向旧VM地址发socket探针. 中央驱动自动临时加入本用例需要的额外控制端口, 保留其它service配置; 受控停启后只按已核SHA恢复本轮仍未变化的原字节. 并发配置变化保留且恢复不确认, 后续单元not_run; 外层另核完整service配置语义前后相同. 原runner独立CLI缺该新参数时保留原配置约定, 当前中央接口显式管理配置.

LOOPBACK原PCAP检查现仅使用完整UDP载荷的准确标记; 管理TCP命令文字或子串不能证明捕获活跃, 重定向环回标记必须失败. PCAP原字节大小/SHA与解析和原恢复断言均保留, 既有IPv6用例只保留原适用范围, 不扩大IPv6产品支持. CONTROL-INVALID从本次启动前记录的日志偏移读新增错误, 历史尾部拒绝文字不能证明本次非法值被拒绝. 初始化用例仍检查有效配置、真实初始化调用栈/nonce/child失败/从未健康及incident与恢复原函数; 内存边界不是实机证据.

原件位于`main-mcp-r18/control-03`、`control-config-01`、`control-foreign-01`、`control-invalid-01`、`initialization-01`和`special-public-02`. 同正式catalog的plan/execute/独立judge已走控制/非法配置/双栈环回正常链及正确更新引用hash后的坏PCAP拒绝, 没用替代catalog. 实机和整个SPECIAL/P03/P04仍未验/未完成, 未声明MCP完整通过.

P03原S2初始化、S3监听线程异常、S6精确受管子进程退出已补OS内存边界正常及错child身份回放; S3原内外层重复写独占证据名导致FileExistsError, 已将外层改为scenario-checks而保留原判断. lifecycle-additional-01失败保留, additional-02两tests三subtests通过; lifecycle-impacted-01相关63tests44subtests/29.08s通过. 原生线程/进程/恢复仍未验, P03其余能力未完成.


ACC019前序引用现在由中央控制器从同一次run的`results/MCP-P03-FULL/driver/units/ACC-008/result.json`生成, 不读旧cwd或最新目录. 引用冻结result SHA, 先核同候选/部署VM/配置/manifest和来源闭包, 再对ACC008原业务函数与直接字节单独重判; 与被依赖能力无关的其它P03失败不代替该项判定. 缺失、失败、变更或跨身份在本轮服务动作前拒绝, fixture不授native引用信用. 输入首次配置不需要每轮人工填写前序路径. 原ACC008损坏快照拒启只支持启动恢复子能力, 明确不授ACC019预停审计失败或完整定位信用; ACC019新受控停服与完整能力引用其余接线仍未完成.

`predecessor-01/02`使用实际StateSnapshot/BaselineStore字节及原ACC008函数/原validator的OS内存边界, 包括快照损坏、写失败、监听残留和先备份再精确清理原路径. 仅证明编排/原判据接通, 不证明真实Windows ACL/SCM/原子写或故障恢复. 前序单项回放只读取明确本次目录, 不枚举历史结果.


ACC019当前生产链已改接现有安装CLI的两阶段stop与install升级预停, 中央执行前须显式授权`deploy`动作(仅代码测试不会安装). plan在选中ACC019时自动加入同次ACC008单项前序并固定先后, 原完整P03若已选不缩减其集合; 被依赖能力单独重判, 不使用旧目录布尔. 原CLI停服和升级分别要求: 预停前标准STOP得到1061且原PID/出生仍在线; 本次instance/attempt进入draining窗口时发起两种变更, 必须立即得到not_allowed_in_state; 查询在安全关闭前保持, 只读本次run.log新增顺序完成阶段, 当前预停成功/无子进程与恢复责任才接受SCM停止/升级文件可替换. 实际升级分支使用固定当前部署参数和原产品install入口, 不构造任意命令或覆盖产品为另一候选.

预停审计失败另做本run baseline受控扰动, 先保存原字节并绑定run/SHA, 验证stop与upgrade均非零、同PID/出生/instance保持Running且状态failed/原因可读、标准STOP仍拒绝、映像/配置未替换. 只恢复本轮仍未变baseline原字节, 再走现有受控退出与重启恢复. 它不是用ACC008启动恢复布尔代替. CLI与wrapper都须有匹配nonce/argv/出生和实际退出观察; 提交后结果未知/未退出时保留现场及基线恢复责任、不与其并行重启清理，后续单元not_run.

正常/三种错误实现和未知回执的direct原件在controlled-exit-01/02、exit-wrapper-01与exit-planned-dependency-01. 同正式catalog public CLI自动串跑ACC008→ACC019并独立重判, 更新正确引用hash后的错误attempt不得通过. exit-public-01因夹具预建结果不满足空run目录而失败且保留, public-02改为实际同plan生产链后通过. exit-impacted-01误写不存在测试文件导致零测试, 正确exit-impacted-02相关126tests54subtests通过、1项Windows分享句柄测试在Linux跳过. 这些都在零网络guard和OS边界替身下, 实际Windows PowerShell/SCM/升级/ACL/Job/审计恢复仍未验证, 不授完整P04/MCP/native信用; 根因定位/terminal三条件取证及其它未完保持.

ACC015已补原ArtifactRegistry元数据/incident原ZIP/PCAP字节导出及unknown-download-tool负向完整OS边界链, 当前programdata_root显式绑定, 原默认保留. 正常、跨run、传输字节变化和D盘根在artifact01/02验证; 都只良性内存VM边界/本地原字节, 实际导出仍未验. 新selected-only INCIDENT-INTEGRITY已进入正式driver过滤器, 默认full仍只原完整检查名单; incident-public01经正式catalog plan/execute/judge通过且不授full信用. artifact-impacted01相关124tests56subtests/59.30s通过, 局部编译/diff通过; 这些不替代完整P04/native验收.


ACC014闭合原件复用入口已接通, 输入及信用边界见
[mcp-capability-map.md](mcp-capability-map.md). 首次在实际environment.mcp.references中
固定原task/接收配置/result/received/报告/作者接受原件的路径与完整SHA,
用JSON pointer只定位原件已有字段, 不要求改写已关闭报告. 程序核独立身份、
产品对象和接受结论、当前适用身份/相关产品依赖, 再跑原完整ACC014判据;
单独选引用时不创建认证/VM通道. 无当前真实独立产品原件仍未验,
fixture通过不授native/full信用, 不替代本次运行的机械检查或三类producer.


P03 selected可用`HEALTH-NO-LISTENER`和`HEALTH-ACTIVE-PROBE`定点复验原ACC006
子能力; full仍执行原完整ACC006一次, 子能力通过不代替全项通过.
无监听配置按实际解析全部关闭监听段, 不漏被动FTP; 创建/加载失败不启动旧配置,
接受的start及整个原观察窗口都保留, 结束后核受控停止与default恢复.
主动探测沿原pipe/当前child/时间/nonce/incident/恢复判据重判.
当前仅离线判别验证, 实机结果未验.

### 只读候选包身份检查

`BUILD-PACKAGE-IDENTITY` 已接入同一 `plan/execute/judge` 入口. 当前明确支持
`fakenet.mcp-candidate-manifest.v1` 的 MCP ZIP, 不执行包内文件、不重建或部署,
也不要求 VM 通道. 其它包格式仍未验, 不因这个适配完成而删除其必要范围.

candidate 除现有 `source_commit` 外, 填写 `package_path`, `package_manifest`
的规范绝对路径及 `package_sha256`. `plan` 自动冻结 manifest 原字节的
`package_manifest_sha256`, 不要求逐轮手抄它. 源提交仍按既有规则与当前仓库
HEAD 相符. 缺少/不支持的包输入只使该 case blocked, 不替其它独立组增加门禁.
环境可仅授权 `allowed_actions: ["offline-artifacts"]`; 原 `native` 授权兼容,
但此 case 本身只读本地原件.

```bash
python tools/acceptance.py plan --mode selected --case BUILD-PACKAGE-IDENTITY --candidate /absolute/candidate.json --environment /absolute/environment.json --output /absolute/Logs/acceptance/package-check/plan.json
python tools/acceptance.py execute --plan /absolute/Logs/acceptance/package-check/plan.json
python tools/acceptance.py judge --plan /absolute/Logs/acceptance/package-check/plan.json --results /absolute/Logs/acceptance/package-check/results --output /absolute/Logs/acceptance/package-check/independent.json
```

独立 judge 重新读取已冻结的包/manifest 原件, 复用原构建器的
`verify_package_zip`, 保留成员集合/大小/SHA/固定时间及嵌入 manifest 断言.
额外拒绝重复及大小写/Unicode 别名、越界或文件/目录冲突路径、链接、重复
JSON 键与缺失身份字段. 不解压到调用方路径. 有界读取限制为 manifest 16 MiB,
单成员 512 MiB, 全包解压总量 4 GiB, 成员数 50000; 超界明确拒绝, 不跳过成员.

证据保留本次执行/candidate 请求、manifest 原字节副本及原验证结果, 引用的
原包继续只读保存. 结果或外层 receipt/index 重新计算哈希后, 错源/错成员及
篡改判定仍不能通过. 原 manifest 的 `qualification_status` 和 `native_gaps`
原样输出, `PARTIAL` 不会升格; 包自洽不证明可复现构建、当前部署或任何 VM 功能.
良性小包自测只授 fixture 信用, selected 通过不授 full.
