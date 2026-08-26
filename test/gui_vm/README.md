# GUI 配置工具 VM 一键验收

对应方案 `PLAN/2026.08.14/2026.08.14-01-GUI配置界面方案.md` §6 验收环境 / §12.18。

## 用法

1. 在**隔离分析 VM** 内放置(任一布局):
   - VM 验收包(`Windows-GUI配置工具-VM验收-v*.zip`,已含 `fakenet.exe`/`fakenet-GUI.exe` 于包根),或
   - 仓库检出 + 已 `pip install .`(GUI 以 `python -m` 运行;A6–A8 需要 `fakenet.exe`,建议放到本目录/仓库根/`dist\`)。
   - **验收驱动脚本本身需要 VM 内有 Python ≥3.8(仅标准库依赖;两个 exe 已自带各自运行时)。**
2. 在 Ubuntu 仓库根目录运行一次 `./Start-FNPR-Sentinel.sh` 并保持窗口；然后在 Windows VM 双击唯一正式入口 `Run-Tests.cmd`，同意一次 UAC。若尚未启动 Sentinel，控制台会打印这条完整命令并等待，无需猜测。
3. A/P 自动检查通过后，控制台会引导三轮 GUI 启动/停止；每轮只按提示在 GUI 点击启动和停止，不需要输入 Windows 命令。脚本自动记录同 nonce TCP/UDP、停止反馈、顶层句柄、残留、DNS/路由恢复和 onedir 身份。
4. 结果:控制台汇总 + `Logs\<时间戳>\results.tsv`，并自动导出 `formal-v34-export-<时间戳>`；只需回传控制台打印的 `EVIDENCE_PATH` 整个目录。

退出码:`0` 全部通过 / `1` 存在失败 / `2` REFUSED(前置条件不满足:物理机、VM 检测不确定、未提权)。

## 验收项与证据级别

| 项 | 内容 | 证据级别 |
|---|---|---|
| 前置 | 仅 VM 运行;物理机/检测不确定即拒绝(与 Start-*.ps1 同一约束) | 实测 |
| A1 | VM 判定放行(CIM 厂商/型号) | 实测 |
| A2 | 物理机拒绝分类(真实物理机样本) | 等效(VM 内无法真机实测) |
| A3 | 不确定态 fail-closed(剥离 PATH 子进程实测 powershell 不可达 → unknown) | 实测 |
| A4 | UAC 取消/失败分支(SE_ERR_ACCESSDENIED=5 与 >32 的解释) | 等效(真实点击"No"无法免交互自动化) |
| A5 | GUI 写出最小配置 + 校验 0 错(写入器/校验器一致性) | 实测 |
| A6 | 提权启动真实 fakenet.exe(最小非侵入配置:不劫持流量、不抓包)+ 稳定存活 + 成功启动日志标记 | 实测 |
| A7 | 双实例门(真实实例运行中被检出) | 实测 |
| A8 | `-f` 停止旗标命中 + `Stopping...` + `rc=0` 优雅退出 | 实测 |
| A9 | fakenet-GUI GUI 启动冒烟(存活 ≥6 秒;窗口会短暂出现,无需操作) | 实测 |

A6–A8 依赖 `fakenet.exe` 镜像名和同次核心日志做生命周期断言;缺失时明确 SKIP 并在结果中说明放置方式(dev 模式的 python.exe 无独立镜像名,不做脆弱断言)。判定 fail-closed:进程短暂出现或消失均不足以 PASS;日志存在 traceback、异常终止、停止失败或非零退出时,A6/A8 必须 FAIL。

## 安全说明

A6 启动的 fakenet 使用**最小非侵入配置**(`DivertTraffic: No`、`DumpPackets: No`、单一 Raw 监听器):不加载 WinDivert、不改 DNS/网关,停止走 fakenet 自带的 stop-flag 机制。这仍要求在 VM 内运行——脚本在物理机上会自我拒绝。

## 手动测试证据一键导出(v1.27 §12.30)

`Run-Tests.cmd` 的证据收集发生在验收结束时;此后若继续用 GUI 手动启动核心做测试,
新产生的日志/PCAP/报告不会进入验收目录。此时双击 **`Export-Logs.cmd`**(免提权):
包根 `Logs\` 日志、`packets_*.pcap`、`report_*.html`, 以及日志中记录的实际启动 INI
会集中拷贝到 `test\gui_vm\Logs\manual-export-<时间戳>\`.导出目录还包含
`config-sources.tsv`、`stop-diagnosis.txt` 和 `evidence-sha256.tsv`.

导出完成后控制台会直接打印:

- 是否找到并复制了当次 INI;
- 最新核心日志中最深的未闭合 `STOP_PHASE/STOP_PROVIDER` 边界;
- 缺少 INI 或诊断标记时的明确失败原因.

用户不需要自己猜测卡住位置;将整个新生成的
`manual-export-<时间戳>` 目录回传即可。

## v33 诊断包一键入口

当前停止专项诊断包使用独立名称 `Windows-GUI配置工具-VM诊断-v33-diagnostic-03.zip`,
不覆盖或冒充 v33/v34 交付包。解压到隔离 Windows VM 后双击
`test\gui_vm\Run-Diagnostics.cmd`。该入口自动请求一次 UAC、验证 Ubuntu
Sentinel 的同 nonce TCP/UDP、打开 GUI、等待启动、建立一条有界 TEST-NET
活动连接、观察 GUI 停止请求，并调用导出器生成
`diagnostic-export-<时间戳>`。

diagnostic-03 的核心使用 PyInstaller debug bootloader，并仅在诊断构建中注入
`stop_trace_runtime_hook.py`。runner 会自动绑定冻结 Python 子进程、one-file
父进程和 `_MEIPASS`，以 50ms 周期记录子进程退出、父进程退出及 `_MEI`
目录删除时刻；独立 console helper 会自动保存 bootloader 的删除失败、等待、
重试和最终删除消息。GUI 另记录停止回调、反馈可见、顶层进程句柄返回及 UI
完成回调的同一单调时钟。Windows 侧仍不要求输入任何命令。

增强后的诊断器不再把“启动前能直连 Ubuntu”当成接管成功：核心进入
takeover 后，它会使用本轮同一 nonce 先查询一个唯一未放行域名，
分别记录本地 DNS 直查和 Windows 系统解析结果，再对应答的
`192.168.204.1:443` 发送 TCP/UDP `role=target` 请求。Ubuntu Sentinel 必须
出现相同 nonce 的两种传输记录，才会输出端到端 PASS；任一传输失败
不会阻止另一传输继续取证。

导出目录额外包含 `diagnostic-results-*.tsv`、`diagnostic-timeline-*.tsv`、
`diagnostic-network-before/after-*.txt`、`diagnostic-session-*.json` 和
`diagnostic-core-anomalies-*.txt`，以及 `diagnostic-stop-process-*.tsv`、
`diagnostic-stop-runtime-*.jsonl`、`diagnostic-stop-bootloader-*.txt`。它们分别固定每个检查的 PASS/FAIL、
人工点击提示到核心停止的时序、启动前后 DNS/路由/进程快照、包与
nonce 身份，以及所有错误和关键接管/停止标记。核心完成停止后，诊断器
还会最多等待 30 秒，确认 GUI 何时显示会话已退出，避免再把显示延迟
误判为核心没有停止。

控制台会在需要人工操作时逐项打印。Windows 侧无需输入命令；用户只需按
提示在 GUI 中启用接管、保存到非默认 INI、启动和点击停止。若 Ubuntu
Sentinel 尚未启动，控制台只要求在 Ubuntu 运行一次
`Start-FNPR-Sentinel.sh`。诊断器不会强杀挂起核心；捕获后应回传打印的
`EVIDENCE_PATH` 目录并回滚 VM 快照。

诊断 runner 不强杀进程；挂起或残留本身属于证据，应导出后回滚 VM 快照。

## 进程网络视图与 A10 进程归因(v1.32 12.32.2)

GUI 实时日志页工具栏新增 **"进程网络视图"** 按钮:独立窗口按"进程 (PID) -> 流"两级
分组显示 `PROCESS_FLOW` 事件(每条出站流一条,含 pid/进程名/协议/目标/处置/关联域名),
支持进程名子串、精确 PID、处置类型过滤与暂停/清空;未启动核心时也可"打开日志文件"
离线分析。数据面在策略模式下对每条新 TCP 流的 SYN 做一次进程归因(owner 查询失败
降级为 unknown,持续失败自动挂起,绝不影响包路径)。验收脚本新增 **A10**:以接管
配置启动核心,由验收进程自身直连未审核公网 IPv4,断言 `PROCESS_FLOW` 携带本进程
pid/映像名且处置为 `DIVERT_FAKE`。

## 策略功能一键测试(v1.28 §12.31.4)

正式 v34 由唯一 **`Run-Tests.cmd`** 自动串联以下策略检查；`Run-Policy-Tests.cmd`
仅保留为开发期单组入口，不能替代正式验收，也必须读取同次正式 Sentinel 前置会话:
阶段 1 以 `api.deepseek.com,*.deepseek.com` 启动域名放行,断言精确域名与通配子域名
(`www.deepseek.com`)获得真实公网租约、裸域 `deepseek.com` 与未放行的 `example.com`
不产生真实租约;阶段 2 以同一域名列表启用私网接管,断言 `DOMAIN_TAKEOVER_READY`
清单完整、裸域应答为接管 sink `192.168.204.1`、通配子域名照常放行;阶段 3(v1.29
§12.32.1)验证未知公网 IPv4 直连兜底(对未审核 `93.184.216.34:80` 的 TCP 连接被
`DIVERT_FAKE` 改道假监听器)与裸解析器 DNS 拦截(`nslookup example.com 8.8.8.8`
应答仅为接管 sink,查询实际到达本机监听器)。P15/A11 在
`DOMAIN_TAKEOVER_READY` 后复用前置 nonce，要求 Ubuntu Sentinel 同时回显 TCP/UDP，
核心记录 `ALLOW_TAKEOVER_SINK`，且 sink 不得出现本地 `DIVERT_FAKE`。证据(核心日志、
各阶段配置、`policy-results.tsv`)写入 `test\gui_vm\Logs\policy-<时间戳>\`。
物理机/非确定 VM 状态直接拒绝(会启用真实流量劫持)。
