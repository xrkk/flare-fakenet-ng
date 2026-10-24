## 目录

- [目标](#目标)
- [产品闭包](#产品闭包)
- [计划分层](#计划分层)
- [限制](#限制)

## 目标

同产品、同构建/运行数据且仅 harness/文档变化时，已有候选的
`source_commit` 可在显式 `source_reuse` opt-in 下继续用于新 source plan。
没有该字段的旧 candidate/plan 仍执行原来的 HEAD 精确校验；package/MCP
的独立旧包身份和部署身份不因本能力放宽。

## 产品闭包

`acceptance_source_identity` 使用封闭规则建立产品/构建/运行闭包：
`fakenet/**`、`deploy/**`、`wheelhouse/**`、`tools/docker/**`、
`.github/workflows/**`、根 `setup`/`pyproject`/`requirements*`/`*.spec`/`Test-*`/
`Build-*`/`build-*`、`tools/build*`，以及 case sources 和当前 harness 之外的
`test/` 运行资料。调用者不能缩小或伪造路径集合。闭包逐文件要求候选与当前
Git blob 的内容及 Git 执行模式一致，并要求当前工作树字节一致；新增、删除、
dirty、symlink、Git 执行位变化或路径逃逸均拒绝。纯 harness 测试和文档不
作为产品闭包，由当前 harness pins 单独冻结；harness 排除项来自本模块固定文件清单, 不接受调用方 pins 改写.
产品模块即使同时由当前测试器绑定, 仍必须参与产品比较; 新增或 rename 文件
不因名称前缀自动成为排除项。

## 计划分层

新 plan 同时保存旧 `candidate.source_commit`/`source_commit`、当前
`harness_commit` 和 `source_reuse` closure proof。execute/judge 重核当前
HEAD 必须等于 harness_commit、当前 harness pins 精确匹配、产品闭包与旧
candidate 逐字相同；harness 变更后旧 plan 失效。中央 plan/execute/judge
仍使用原 catalog、case、检查集合、package/MCP 部署校验和 oracle。

## 限制

本能力只证明源码身份可复用，不证明候选已构建、已部署、已运行或网络
可执行；真实 VM/SDK/服务、缓存 PASS 和 native/full 均未授权。
