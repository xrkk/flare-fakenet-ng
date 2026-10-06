# MCP 查询工作流（只读）

三个只读查询工具让 AI 用一次调用完成"看某个 run 的进度、事件和产物"，
不需要逐项轮询。它们不改变任何状态：不启动/停止/重放采集，不修改
state_version、controller 或命令缓存，产物枚举始终在固定的诊断任务里
按每次请求重新校验字节。

## list_artifacts(run_id=None, artifact_type=None)

- 不带参数：原全集语义不变（`artifacts`/`error` 字段），不强制分页。
- `run_id`：必须是规范 UUID（小写、连字符标准形式）。非法值、路径穿越
  是结构化拒绝（`invalid_request`），不会退回全集；未知但合法的 run
  返回空匹配。过滤在真实诊断任务内执行：只锚定该 run 的注册产物目录
  （`artifacts/<run_id>/`），未选中的 run 不会被打开或哈希。
- `artifact_type`：精确匹配既有 metadata `type`（`pcap`/`log`/`report`/
  `userdump`/`config`/其他后缀名）。非空字符串；未知类型为空匹配。
- 返回额外带 `query`（回显过滤条件）和 `matched_count`。零匹配只表示
  没有匹配产物，不代表 run 成功或完成。
- 完整性语义不变：每个选中产物每次请求都重算 SHA-256，`complete=false`
  表示发布声明与当前字节不一致（篡改或未完成）；deadline 到期以
  TimeoutError 结构化失败，绝不返回半截清单——**筛选阶段同样受预算
  约束**：类型过滤进行中预算耗尽会结构化失败，不会被伪装成零匹配的
  空清单。

## get_events(limit=100, cursor=None, run_id=None)

- 每条事件自带 `epoch`（事件日志实例唯一）和严格递增 `seq`；`seq=0`
  是每个 epoch 的合法起点（日志仍为空时的游标位置）。
- 不带 `cursor`：返回最近 `limit`（1..500 钳制）条事件的旧语义，另给
  当前末端 cursor——**空日志也返回非空的 epoch/0 起点 cursor**，
  `latest_seq=0`、`oldest_seq=null`；拿这个起点 cursor 之后新增的事件
  可以从 1 开始逐页续读，空页的 cursor 也不会退回 null。游标只向前
  走，更早的事件通过 `oldest_seq` 观察，不提供往回翻页。
- 带 `cursor`：返回该位置之后按 `seq` 升序的最多 `limit` 条事件；
  `next_cursor` 指向本次扫描到的末端（未匹配满一页时推进到当前末端，
  匹配被截断时指向最后一条返回事件且 `has_more=true`）。被 `run_id`
  过滤跳过的事件同样推进游标，所以"没有新匹配事件"的空页不会死循环
  ——下一次调用只扫真正的新事件。
- `gap` 只在保留窗口**确证丢失**时为 true：同 epoch 且
  `cursor_seq < oldest_seq - 1`。cursor 恰在保留窗口前一项
  （`cursor_seq = oldest_seq - 1`）是连续的，不算 gap；例：保留
  16..20、cursor 15 → 返回 [16,17]、gap=false、has_more=true，续页
  [18,19]、[20] 覆盖全部保留项。
- 真实 gap 与 epoch 重建（`reset_required=true`）都**从保留窗口最早的
  匹配开始分页恢复**，逐页覆盖全部保留项，不直接跳到最新尾部；恢复
  返回的 cursor 之后按同 epoch 正常续读。
- 非法 cursor、伪造格式或超过当前末端的 seq（空日志时即 ≥1）都是
  结构化拒绝，不会被当作初始查询。
- `run_id` 用同一规范 UUID 规则，只匹配事件自身的 `run_id` 字段；没有
  `run_id` 字段的事件（如 command/health 事件）不猜归属，不匹配任何
  具体过滤。
- 事件读取不改变 state_version、controller 或 commands。

## get_run_overview(run_id=None, event_limit=100, event_cursor=None,
                   artifact_type=None)

一次聚合：当前 `service_status` + 所选 run 的事件页 + 过滤后的产物清单。

- 省略 `run_id`：使用首次状态快照里的当前 run（`selection=current`）；
  当前没有 run 时 `selected_run_id=null`、`selection=no_current_run`，
  events/artifacts 为空并注明，不枚举历史全部产物。
- 显式 `run_id`：`selection=explicit`，可查历史 run；`service_status`
  始终是**当前服务**快照，历史 run 不继承当前健康/恢复字段。
- 聚合不是原子事务：响应带 `status_before_version`/
  `status_after_version`，两者不同则 `consistent=false`。
- 单个子查询失败（例如非法 cursor 或诊断任务不可用）保留其他子结果，
  顶层 `partial=true` 并在 `error` 里点名失败的子查询；失败产生的空
  列表不会被当作完整成功。

## get_command_status(command_id)

一次只读对账：这条命令在**本进程**的命令缓存里是什么状态，避免为确认
提交结果而重复执行命令。

- 需要有效的 `X-FakeNet-Controller-ID`；当前有 run 时必须是该 run 的
  controller，且缓存记录必须属于同一 controller——他人查不到你的
  response、describe 或异常。
- 返回 `status`：`in_progress`（命令已接受仍在执行，附接受时的原始
  响应）、`completed`（保存的最终响应）、`failed`（命令自身的错误：
  `McpError` 按原结构，其他异常只给安全的 `internal_error` 概要，不带
  堆栈）、`unknown`。`cache_scope='process'`、`cache_epoch` 每个
  Coordinator 实例唯一、`persistent=false`。
- **`unknown` 只说明当前进程缓存没有这条记录**（从未提交、被更新的
  命令淘汰、或服务重启）——不能推断命令没执行过，也不能推断重放安全；
  重放前按命令语义自行评估副作用。
- 查询本身零副作用：不调用 submit/execute、不增长 state_version、
  不刷新 LRU、不改重放语义；返回内容是与缓存隔离的深拷贝。

## wait_status(states, after_state_version, timeout_seconds)

一次有界等待：等到 state 属于 `states` 和/或 `state_version` 超过
`after_state_version`，最多等 `timeout_seconds`（0..30 秒，必须有限；
非法值直接拒绝，不会悄悄无限等）。两个条件都给时是 AND。

- 至少给一个条件；`states` 必须是状态机已知状态的非空列表。
- 只给 `states` 时能观察到**不增长版本号的健康变化**（如
  healthy→degraded）；注意 `state_version` 是"已接受变更"的版本，
  不是健康转移计数，`after_state_version` 不会因健康变化而满足。
- `timeout_seconds=0` 表示只立即观察一次。超时是正常的有界结果
  （`timed_out=true`），绝不冒充条件达成；`matched=true` 时返回的
  `status` 就是判定所用的同一次末次观察，不会混入更新状态。
- 单次 RPC 内部以约 100ms 间隔异步轮询：不阻塞服务循环（等待期间
  get_status 和真实变更照常完成），不持有协调器/监管锁跨等待，返回
  后没有残留线程；请求被取消立即停止观察，且绝不取消任何在途命令。
- 只读：不生成事件、不增长版本、不取得所有权、不自动恢复。

## 边界

- 三个工具都是只读，可被任何可达连接调用；不触发 FakeNet、WinDivert
  或任何网络流量。
- 产物路径永远不逃出注册根：run 锚定不跟随符号链接，枚举不下降符号
  目录。
- 下载产物内容仍走既有受保护流程；`list`/`overview` 的文件清单不是
  下载证明。
