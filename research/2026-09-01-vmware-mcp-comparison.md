# Ubuntu 主机上的 VMware Workstation MCP 对比

调研日期：2026-09-01（Asia/Shanghai）

范围：只比较以下三个公开仓库在 Ubuntu 主机上控制 VMware Workstation 测试 VM 的适用性，重点是列快照、恢复指定快照、运行态处理、`vmrun`/REST 依赖、MCP transport、Linux 支持、风险与维护状态。本次阅读了 README、源码、包元数据和提交历史，并对首选候选的底层执行器做了只读调用验证；未安装 MCP、未恢复快照、未改变 VM 状态。

- [Dyspel/vmware_workstation_mcp](https://github.com/Dyspel/vmware_workstation_mcp)，审阅提交 [`9501247`](https://github.com/Dyspel/vmware_workstation_mcp/commit/9501247a613d91b9291b3a925817732147fff59f)
- [slupro/vmware-mcp](https://github.com/slupro/vmware-mcp)，审阅提交 [`b6cf9d0`](https://github.com/slupro/vmware-mcp/commit/b6cf9d0a30f55d5f1798a333602f3c715e7b0653)
- [ZacharyZcR/vmware-mcp](https://github.com/ZacharyZcR/vmware-mcp)，审阅提交 [`5b4f4c2`](https://github.com/ZacharyZcR/vmware-mcp/commit/5b4f4c2119445f05ae28d34075424d32c56cc66c)

## 结论

**首选 `slupro/vmware-mcp`，但应把它视为一个需要小幅加固的基础实现，而不是可直接无监督恢复快照的成品。** 对当前目标而言，它的优势是：只依赖 `vmrun`、MCP 使用本地 `stdio`、VM 必须先以配置中的短名称登记，工具面最小（源码中 19 个工具），快照调用有 300 秒超时。Ubuntu 上应把 `vmrun_path` 配成绝对路径（通常是 `/usr/bin/vmrun`），不要只写 `vmrun`。

排序建议：

1. **`slupro/vmware-mcp`：最合适。** 配置式 VM 白名单最适合固定的验收 VM，依赖少、权限面相对小、代码结构也比另两者容易审计。
2. **`Dyspel/vmware_workstation_mcp`：可作为纯 Linux 快速验证的第二选择。** 它对 Linux 最直接，`vmrun` 自动从 `PATH` 定位，并且快照列表固定使用树形输出；但只有一次提交、单文件、无打包元数据、无许可证声明、任意 `.vmx` 路径均可作为工具参数，长期托管和权限控制较弱。
3. **`ZacharyZcR/vmware-mcp`：不建议用于“只恢复测试 VM 快照”的窄任务。** 它实际暴露的工具面远大于需要，混合 REST、`vmrun`、`vmcli` 三条控制路径，默认可执行文件路径是 Windows 路径，子进程无超时，而且 REST 实现至少有一处与官方 API 契约直接不符。虽然它的 `vmrun_snapshot_*` 在传入直接 `.vmx` 路径并正确设置 `VMRUN_PATH` 时理论上可绕过 REST 使用，但复杂度和误操作半径没有收益。

三者共同的关键缺口是：**都没有“安全恢复并回到可测试状态”的复合操作**。它们的恢复工具只是把目标交给 `vmrun revertToSnapshot`（Zachary 还提供一条 `vmcli` 路径），不会自动执行“检查运行态 → 停机 → 核对快照 → 恢复 → 启动 → 等待 Tools/IP → 验证”的完整流程。VMware 明确提示快照恢复不能撤销，恢复点之后的工作会丢失，因此不宜对恢复工具启用无条件自动批准。[Broadcom KB 315595](https://knowledge.broadcom.com/external/article/315595/cannot-undo-revert-snapshot.html)

## 当前主机只读验证

- Ubuntu 主机存在 `/usr/bin/vmrun`。以 slupro 的 `vmrun_exec` 执行器调用 `/usr/bin/vmrun listSnapshots <目标.vmx>` 已成功返回 7 个快照，证明其执行器和当前原生 Ubuntu `vmrun` 能走通只读快照路径；这不等于恢复路径已经验收。
- 通过当前 Win10VM MCP 读取到的 guest MAC `00-0C-29-4C-FD-C0` 和 BIOS UUID，与主机文件 `/home/adminn/vmware-machines/win10h2-MalBox-20241110/win10h2-MalBox-20241110.vmx` 中的 MAC/UUID 精确匹配。该 `.vmx` 可作为唯一允许的测试 VM 目标，避免靠文件名猜测。
- 已读出的快照树为 `快照 17-安装逆向技能 → Snapshot 4-更新VMTools → Snapshot 16-Win10VM.MCP → Snapshot 17-打开中 → Snapshot 181-准备分析 → Snapshot 182-dnspy.mcp 可用 → Snapshot 18-bbd53`。恢复前仍须由用户或生效测试契约明确指定其中哪个节点是基线；工具不得自行选“最新”或按模糊名称匹配。
- 当前隔离命令环境中的 `vmrun list` 返回 0 个运行中 VM，而 Win10VM MCP 与 `.lck` 证据表明 VM 正在运行。这说明最终 MCP 必须运行在拥有 VMware 用户会话可见性的 Ubuntu 进程环境中；正式放行恢复前要再做一次 `list`/`listSnapshots` 的只读在线核对。

## 总表

| 维度 | Dyspel | slupro | ZacharyZcR |
|---|---|---|---|
| 推荐级别 | 第二 | **第一** | 第三 |
| 快照列表 | `vmrun listSnapshots ... showTree` | `vmrun listSnapshots ...`，无树形选项 | `vmrun` 可选 `showTree`；另有 `vmcli Snapshot query` |
| 指定快照恢复 | `revert_to_snapshot(vmx, name)` | `vm_snapshot_restore(vm_alias, name)` | `vmrun_snapshot_revert(vm_id_or_vmx, name)`；另有 `snapshot_revert` |
| 运行态处理 | 有独立 list/start/stop，但恢复前后不编排 | 有独立 list/start/stop，但恢复前后不编排 | 有 REST/vmrun/vmcli 电源工具，但恢复前后不编排 |
| 快照主依赖 | `vmrun` | `vmrun` | 快照可走 `vmrun` 或 `vmcli`；REST API 本身没有快照接口 |
| REST/`vmrest` | 无 | 无 | REST 工具及把 VM ID 解析成 `.vmx` 时需要；直接传 `.vmx` 可绕过 |
| MCP transport | `stdio` | `stdio` | `stdio` |
| Ubuntu 适配 | **明确面向 Linux**，自动找 `vmrun` | 可用，但必须给 `vmrun` 绝对路径 | 无开箱即用 Linux 默认值，须设置 `VMRUN_PATH`；`vmcli` 也须另配 |
| 超时 | 普通 60 秒；启动/停止 120 秒；快照 300 秒 | 默认 120 秒；快照 300 秒 | **无子进程超时** |
| VM 目标约束 | 任意存在的 `.vmx` 路径 | **配置文件中的 VM 名称白名单** | 任意 VM ID 或任意直接 `.vmx` 路径 |
| 工具面 | README 称 34，源码实际 33 个装饰器 | 源码 19 个 | README 称 117，源码工具清单实际 130 项 |
| 测试/CI | 未见 | 未见 | 未见 |
| 历史/发布 | 1 次提交；无 tag/release | 9 次提交；无 tag/release | 9 次提交，集中在两天；无 tag/release |

## VMware 官方能力边界

1. Workstation Pro 官方手册包含 `vmrun`，并给出 `listSnapshots`、`snapshot`、`deleteSnapshot` 和 `revertToSnapshot` 的调用方式；因此三者使用 `vmrun` 完成快照工作的方向是合理的。[VMware Workstation Pro 17 官方手册（PDF）](https://techdocs2-prod.adobecqms.net/content/dam/broadcom/techdocs/us/en/pdf/vmware/desktop-hypervisors/workstation/vmware-workstation-pro-17-0.pdf)
2. Workstation REST API 1.2.1 的官方操作索引只有 VM、Power、NIC、Shared Folder 和 Host Network 等类别，没有快照操作。因此 Zachary 项目的快照能力不是由 REST 提供，启动 `vmrest` 也不能替代 `vmrun`/`vmcli` 的快照路径。[官方 Workstation API 操作索引](https://developer.broadcom.com/xapis/vmware-workstation-pro-api/latest/operation-index/)
3. 官方手册说明，恢复会把 VM 设置到快照时的状态；如果快照是在 VM 开机时拍摄，恢复后的 VM 会处于挂起状态而不会自动继续运行。因此验收编排必须显式检查恢复后的电源状态并按需启动，不能把 `revertToSnapshot` 成功等同于“VM 已可测试”。[VMware Workstation Pro 17 官方手册（PDF）](https://techdocs2-prod.adobecqms.net/content/dam/broadcom/techdocs/us/en/pdf/vmware/desktop-hypervisors/workstation/vmware-workstation-pro-17-0.pdf)

## 逐项分析

### 1. Dyspel/vmware_workstation_mcp

适配亮点：

- README 直接声明面向 Linux，依赖 Workstation Pro、`vmrun` 位于 `PATH` 和 Python 3.10+；源码用 `shutil.which("vmrun")`，失败后退到 `/usr/bin/vmrun`。这在当前 Ubuntu 主机上最接近开箱即用。[README 要求](https://github.com/Dyspel/vmware_workstation_mcp/blob/9501247a613d91b9291b3a925817732147fff59f/README.md#L98-L104)；[`vmrun` 定位代码](https://github.com/Dyspel/vmware_workstation_mcp/blob/9501247a613d91b9291b3a925817732147fff59f/vmware_mcp.py#L18-L30)
- `list_snapshots` 固定加 `showTree`，对存在同名子快照的 VM 更容易确认层级；恢复接收快照名称/路径并直接调用 `revertToSnapshot`，两者都会先解析并检查 `.vmx` 文件存在。[快照实现](https://github.com/Dyspel/vmware_workstation_mcp/blob/9501247a613d91b9291b3a925817732147fff59f/vmware_mcp.py#L323-L376)；[路径检查](https://github.com/Dyspel/vmware_workstation_mcp/blob/9501247a613d91b9291b3a925817732147fff59f/vmware_mcp.py#L75-L80)
- 子进程使用参数数组而不是 shell 字符串，非零退出码会抛异常，快照操作有 300 秒超时；这比把错误包装成普通成功文本更利于 MCP 客户端识别失败。[命令执行器](https://github.com/Dyspel/vmware_workstation_mcp/blob/9501247a613d91b9291b3a925817732147fff59f/vmware_mcp.py#L37-L72)
- MCP 明确运行在 `stdio` transport，没有额外监听端口。[入口](https://github.com/Dyspel/vmware_workstation_mcp/blob/9501247a613d91b9291b3a925817732147fff59f/vmware_mcp.py#L952-L957)

不足和风险：

- 恢复函数不查询当前运行态、不停机、不在恢复后启动或做就绪检查；这些能力只是分散的独立工具。[电源工具](https://github.com/Dyspel/vmware_workstation_mcp/blob/9501247a613d91b9291b3a925817732147fff59f/vmware_mcp.py#L240-L320)；[恢复函数](https://github.com/Dyspel/vmware_workstation_mcp/blob/9501247a613d91b9291b3a925817732147fff59f/vmware_mcp.py#L353-L363)
- 工具接受任意可访问的 `.vmx` 路径，没有 VM 白名单；同时暴露删除快照、克隆、写变量等修改能力。对自动批准策略而言，误操作范围比 slupro 大。
- README 称 34 个工具，但审阅提交中实际只有 33 个 `@mcp.tool()`；仓库还提交了 `__pycache__`，没有 `pyproject.toml`、测试或 CI，且 GitHub 未识别许可证。仓库历史只有一个 initial commit。[README 工具数](https://github.com/Dyspel/vmware_workstation_mcp/blob/9501247a613d91b9291b3a925817732147fff59f/README.md#L37-L37)；[提交历史](https://github.com/Dyspel/vmware_workstation_mcp/commits/master/)；[仓库元数据 API](https://api.github.com/repos/Dyspel/vmware_workstation_mcp)

### 2. slupro/vmware-mcp

适配亮点：

- 控制面只基于 `vmrun`，没有 `vmrest` 或 `vmcli` 依赖；README/包元数据要求 Python 3.10+，唯一运行依赖是 `mcp>=1.2.0`。[README](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/README.md#L1-L18)；[`pyproject.toml`](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/pyproject.toml#L5-L17)
- 配置文件必须包含 `vmrun_path` 和至少一个 VM；工具只接收配置中的 VM 名称，再映射到固定 `.vmx`，这是三者中最适合固定验收 VM 的最小权限设计。[配置校验和 VM 查找](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/src/vmware_mcp/config.py#L32-L57)
- 快照 list/create/restore/delete 都是明确的窄工具，恢复有 300 秒超时；生命周期工具可另行 start/stop。[快照实现](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/src/vmware_mcp/server.py#L88-L147)；[生命周期实现](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/src/vmware_mcp/server.py#L21-L86)
- 明确使用 `stdio` transport；README 也给出了 `--transport stdio` 配置。[入口](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/src/vmware_mcp/server.py#L372-L376)；[README 启动方式](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/README.md#L19-L34)
- 9 次提交中包含专门修复 Windows 与 WSL 路径判断的提交，相比另两者显示出更清晰的迭代痕迹。[提交历史](https://github.com/slupro/vmware-mcp/commits/master/)

不足和需要加固之处：

- README 说 `vmrun` 可在 `PATH` 中或配置路径，但执行器先用 `os.path.isfile(exe_path)` 检查；在原生 Ubuntu 配置裸命令 `vmrun` 会失败。因此实际应配置绝对路径 `/usr/bin/vmrun`。WSL 的 Windows路径转换不会在原生 Linux 启用。[路径和执行逻辑](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/src/vmware_mcp/vmrun.py#L13-L108)
- `vm_snapshot_list` 没有 `showTree` 参数；当快照树中出现同名节点时，不如另两者容易选择完整层级路径。[列表和恢复实现](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/src/vmware_mcp/server.py#L90-L132)
- 示例配置中的 `snapshot: "clean"` 没有被服务器使用；恢复仍必须每次显式传 `name`，不能把该字段当成安全默认快照。[README 示例](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/README.md#L36-L54)；[配置模块](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/src/vmware_mcp/config.py#L32-L57)
- 捕获 `VmrunError` 后返回 `"Error ..."` 普通字符串，而不是让 MCP tool call 失败。调用者必须检查文本，或在部署前改成协议层错误，否则存在把恢复失败误认为工具调用成功的风险。[恢复错误处理](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/src/vmware_mcp/server.py#L119-L132)
- 执行器把完整命令写到 stderr；需要 guest 凭据的其他工具会把 `-gp` 密码带入该日志。仅快照命令不需要 guest 凭据，但若保留整套 MCP，应去除敏感参数日志。[命令日志与凭据拼接](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/src/vmware_mcp/vmrun.py#L68-L70)；[guest 参数构造](https://github.com/slupro/vmware-mcp/blob/b6cf9d0a30f55d5f1798a333602f3c715e7b0653/src/vmware_mcp/vmrun.py#L111-L125)
- 未见测试、CI 或 release/tag；README 和 `pyproject.toml` 声明 MIT，但仓库没有独立 LICENSE 文件，GitHub API 也未识别许可证。[提交历史](https://github.com/slupro/vmware-mcp/commits/master/)；[仓库元数据 API](https://api.github.com/repos/slupro/vmware-mcp)

### 3. ZacharyZcR/vmware-mcp

可以完成快照工作的部分：

- 同时提供 `vmrun_snapshot_list/take/delete/revert` 和 `vmcli` 的 snapshot 工具；`vmrun` 列表支持可选 `showTree`。[`vmrun` 快照包装](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/src/vmware_mcp/vmrun.py#L77-L94)；[`vmcli` 快照包装](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/src/vmware_mcp/vmcli.py#L38-L55)
- `get_vmx_path` 对包含路径分隔符或以 `.vmx` 结尾的参数直接返回；因此调用 `vmrun_snapshot_*` 时传 Ubuntu 本机 `.vmx` 绝对路径，可以不访问 REST。只有传短 VM ID 时才会调用 REST 枚举并解析路径。[路径解析](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/src/vmware_mcp/server.py#L34-L45)
- MCP transport 仍只是本地 `stdio`；`vmrest` 是它访问 Workstation REST API 的后端，不是 MCP 网络 transport。[MCP 入口](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/src/vmware_mcp/server.py#L517-L528)

不适合作为本任务首选的原因：

- README 和默认值明显按 Windows 部署：`vmrun.exe`、`vmcli.exe` 和 `vmrest.exe` 都是 Windows 路径。Ubuntu 必须至少设置 `VMRUN_PATH`；若要用 `vmcli`，还必须设置 `VMCLI_PATH`；若用 REST 或短 VM ID，还要启动并配置 `vmrest`。[README 环境与配置](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/README.md#L15-L46)；[`vmrun` 默认路径](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/src/vmware_mcp/vmrun.py#L7-L17)；[`vmcli` 默认路径](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/src/vmware_mcp/vmcli.py#L9-L18)
- README 宣称 117 个工具，而对 `list_tools()` 返回项静态计数为 130；其中包含删除 VM、删除快照、修改磁盘、网卡和端口转发等高影响工具。对只需要恢复测试 VM 的代理而言，权限面过宽且文档与实现不一致。[README 规模声明](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/README.md#L5-L13)；[源码工具清单](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/src/vmware_mcp/server.py#L56-L224)
- `vmrun` 和 `vmcli` 子进程都没有超时；若 Workstation 在锁、弹窗或长操作上阻塞，MCP 调用可能无限挂住。[`vmrun` 执行器](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/src/vmware_mcp/vmrun.py#L16-L38)；[`vmcli` 执行器](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/src/vmware_mcp/vmcli.py#L18-L36)
- REST 客户端至少有一个可直接验证的契约错误：源码用 `POST /api/vms/{vm_id}` 且只发送 `name`；官方 Workstation API 的“Create VM”要求 `POST /api/vms`，请求体为 `name` 和 `parentId`。这降低了对未实机覆盖的其余 130 项工具的可信度。[仓库 REST 实现](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/src/vmware_mcp/client.py#L22-L36)；[官方 Create VM API](https://developer.broadcom.com/xapis/vmware-workstation-pro-api/latest/api/vms/post/)
- 源码没有在恢复前后编排运行态，也没有验证恢复后的状态。[调用分派](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/src/vmware_mcp/server.py#L286-L314)
- 9 次提交集中在 2026-01-15 至 2026-01-16，之后没有代码提交，也没有测试、CI、tag 或 release；虽有更多 stars/forks，但这不能替代维护和验证证据。README 声明 MIT，`pyproject.toml` 没有 license 字段，仓库也无 LICENSE 文件。[提交历史](https://github.com/ZacharyZcR/vmware-mcp/commits/master/)；[`pyproject.toml`](https://github.com/ZacharyZcR/vmware-mcp/blob/5b4f4c2119445f05ae28d34075424d32c56cc66c/pyproject.toml)；[仓库元数据 API](https://api.github.com/repos/ZacharyZcR/vmware-mcp)

## 推荐的安全恢复契约

无论最终采用哪个仓库，都不应直接把单个 `revert` 调用当成完成。建议对外只暴露一个受控的复合操作，输入是预配置的 VM 别名和预配置的快照别名，内部按以下顺序执行：

1. 用 `vmrun list` 确认目标 VM 当前是否运行，并核对 `.vmx` 规范化路径、VM UUID/MAC 与白名单完全一致。
2. 用 `listSnapshots ... showTree` 获取快照树；必须找到唯一目标。若出现重名，使用完整层级路径，不做模糊匹配。
3. 若 VM 正在运行，先尝试 `stop ... soft`，设置明确超时；超时后是否允许 `hard` 必须由策略或用户确认，不能静默升级。
4. 再次 `vmrun list`，确认 VM 已停止或处于允许恢复的状态。
5. 执行 `revertToSnapshot`，检查进程退出码和 stderr；失败必须作为 MCP error 返回，而不是普通文本。
6. 再列一次快照/读取状态，确认命令完成。随后根据契约显式恢复到目标运行状态；不要假定 `revertToSnapshot` 成功就代表 VM 已经运行并可测试。包含内存状态的快照可能恢复成挂起态。
7. 等待 VMware Tools/IP 或一个只读 guest 健康检查成功，再把 VM 标记为“可测试”。整个流程要有总超时和步骤级日志。
8. `deleteSnapshot`、`deleteVM`、磁盘/网络修改等工具不应出现在该 MCP 的自动批准集合中。恢复操作本身也应保留目标 VM、目标快照和不可撤销警告的审批边界。恢复前先把需要保留的 VM 日志和验收证据导出到 Ubuntu 仓库的 `Logs/`，因为恢复会丢弃快照之后留在 guest 内的状态。

如果不改上游代码而直接选一个使用，建议用 slupro 并采取最低限度配置：只登记 Win10 测试 VM；`vmrun_path` 使用 Ubuntu 绝对路径；guest 密码不放入配置文件；恢复前由调用者显式完成 list/stop/listSnapshots/revert/start/health-check；每一步检查返回文本是否以 `Error` 开头。更稳妥的长期方案是基于它保留最少的 inventory/power/snapshot 工具，并修复协议错误、树形快照列表、敏感日志和复合恢复事务。

## 维护状态快照

以下数字取自 2026-09-01 的 GitHub 仓库元数据和完整 Git 历史；“updated_at”可能受 stars 等非代码活动影响，因此这里以 `pushed_at`/提交历史为维护判断依据。

| 仓库 | 提交数 | 最后提交 | stars / forks | tag / release | GitHub 检测许可证 |
|---|---:|---|---:|---|---|
| Dyspel | 1 | 2026-03-16，initial commit | 3 / 0 | 无 / 无 | 无 |
| slupro | 9 | 2026-04-25，本机 Windows/WSL 路径判断修复 | 0 / 0 | 无 / 无 | 无（项目文件声明 MIT） |
| ZacharyZcR | 9 | 2026-01-16，README 中文化 | 47 / 8 | 无 / 无 | 无（README 声明 MIT） |

一手元数据入口：[Dyspel API](https://api.github.com/repos/Dyspel/vmware_workstation_mcp)、[slupro API](https://api.github.com/repos/slupro/vmware-mcp)、[ZacharyZcR API](https://api.github.com/repos/ZacharyZcR/vmware-mcp)。
