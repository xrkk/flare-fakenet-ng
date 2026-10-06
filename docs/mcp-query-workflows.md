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
  TimeoutError 结构化失败，绝不返回半截清单。

## get_events(limit=100, cursor=None, run_id=None)

- 每条事件自带 `epoch`（事件日志实例唯一）和严格递增 `seq`。
- 不带 `cursor`：返回最近 `limit`（1..500 钳制）条事件的旧语义，另给
  当前末端 cursor。游标只向前走，更早的事件通过 `oldest_seq` 观察，
  不提供往回翻页。
- 带 `cursor`：返回该位置之后按 `seq` 升序的最多 `limit` 条事件；
  `next_cursor` 指向本次扫描到的末端。被 `run_id` 过滤跳过的事件同样
  推进游标，所以"没有新匹配事件"的空页不会死循环——下一次调用只扫
  真正的新事件。
- `gap=true`：cursor 早于保留窗口（日志只留最近 500 条），返回现存
  部分并明确缺口；`reset_required=true`：事件日志重建（epoch 变化），
  返回当前保留部分，不宣称连续。
- 非法 cursor、伪造格式或超过当前末端的 seq 都是结构化拒绝，不会被
  当作初始查询。
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

## 边界

- 三个工具都是只读，可被任何可达连接调用；不触发 FakeNet、WinDivert
  或任何网络流量。
- 产物路径永远不逃出注册根：run 锚定不跟随符号链接，枚举不下降符号
  目录。
- 下载产物内容仍走既有受保护流程；`list`/`overview` 的文件清单不是
  下载证明。
