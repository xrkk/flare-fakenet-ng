# MCP 接口合同（T003 落地面）

本轮固化三个接口面：配置变更回执、全工具类型化元数据、ping 构建身份。

## 配置变更回执（config_result / config_identity）

- `create_config`/`import_config`/`edit_config`/`rename_config` 成功响应
  携带 `config_result = {name, sha256, builtin:false, deleted:false}`；
  `delete_config` 成功为 `{name, sha256:null, builtin:false, deleted:true}`。
- `sha256` 是**本次已完成的提交**实际写入磁盘字节的哈希（来自
  ConfigStore 同一次调用返回值），不是调用方输入串的哈希，也不是提交
  后另读的新版本；no-op edit 返回同一实际身份。
- `load_config` 成功响应保留 `config_identity`（name/sha256/builtin）。
- 回执进入命令缓存的最终响应：同 `command_id` 重放在文件后续变化后
  仍返回**原**回执；`get_command_status` 返回同一回执的隔离副本。
  失败（CAS/身份/在途）不伪造回执。调用方无需再发一次 `read_config`
  对账——下一写直接链用上一响应的 `config_result.sha256`。

## 工具元数据

- 全部 19 个公开工具带一行紧凑 description（动作/前提/关键返回）与
  真实 ToolAnnotations：只读工具 `readOnlyHint=true`；变更工具
  `readOnlyHint=false/destructiveHint=true/idempotentHint=false`（进程
  内命令缓存去重不是持久幂等）；生命周期 `start/stop/restart` 另带
  `openWorldHint=true`（可能影响网络）。
- 输出 schema 由 Pydantic 返回模型生成（`fakenet/mcp/schemas.py`，
  `extra='allow'`）：稳定顶层字段与已知嵌套结构（事件页/产物行/
  配置身份/命令缓存视图）有类型与可空性，真正开放的字段（health、
  detail）保持开放 dict；错误形状（含 `error` 键）与成功形状同样通过
  验证，字段不被丢弃或改写。`structuredContent` 与 text 内容同语义。
- 注意：类型化 schema **增加**发现字节（本轮实测 7952 → 49999
  canonical bytes）；其价值是客户端侧校验与缓存失效依据，不是 token
  节省。`interface_revision`（见下）变更时应视为发现缓存失效。

## ping 构建身份（build_identity）

`ping` 追加 `build_identity = {interface_revision, source_commit, source,
manifest_sha256, error}`：

- `interface_revision` 是固定合同常量 `'2026-10-06.1'`，代表本轮稳定
  接口；接口变更时必须更新它，客户端以此做接口缓存失效。
- 其余字段来自正式 exe 同目录（源码模式为项目包根）的
  `mcp-candidate-manifest.json` 白名单读取：`source_commit` 仅接受
  40/64 位十六进制；`manifest_sha256` 是 manifest 文件自身哈希；
  只读、上限 4 MiB（单次 `read(MAX+1)` 有界请求，stat 后增长到超界
  即拒绝、不缓存可信身份）、拒绝符号链接与非普通文件；不运行
  git、不联网、不回显 files 数组/路径/凭据。
- 缺失 → `source:'unknown'`、`error:null`（不失败 ping）；损坏 →
  `unknown` + 一句简短原因，绝不冒充可信版本。unknown 时不得宣称
  缓存匹配。
- **该值每进程最多读取一次并缓存**：部署替换 manifest 后必须重启服务，
  ping 才会报告新身份——避免把热变化当成新运行二进制身份。构建身份
  不是认证，也不代替实际工具发现或包哈希验签。
