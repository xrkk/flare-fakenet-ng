# 修复 FakeNet 长时间运行后的恢复审计死锁

2026-11-06 已完成源码修复. VM 内两份历史失败样本经只读重放, 旧代码均拒绝 owner 身份, 补丁均通过. 本次没有部署或重启现用服务, 没有修改 state.json 或旧 baseline. 部署后的新 run 停止与 SCM 退出仍需验证.

用户问题来源: `/home/adminn/projects/样本分析/样本分析/-分析中/2026.10.14-中心-刘玲/样本/f07c6/.f07c6-c2-fake-c2-xbx-analysis/FakeNet恢复审计死锁-修复说明-20261105.md`.

## 现场核对与根因修正

原说明将 TCP 15101 的消失列为确定性根因. 本次读取保留的原件后, 该结论不能用于解释这份失败审计: baseline 中 15101 的 PID 是 4, 协调器 PID 是 2908, 实际 MCP 监听端口是 28788. 留存审计最后两份采样的 before/after 都有 15101. 当前 HTTP.sys 请求队列也显示由另一个进程注册 15101. `ControlLinkExcludePort` 是过滤器保护参数, 不证明端口归协调器所有, 因此补丁没有按端口号忽略 TCP 差异.

留存归因文件的 `foreign_owner_samples` 已经为 true, 但总 `accepted` 仍为 false. 实际拒绝发生在 `same_boot_owner_proof`: trace-start 通过 Win32_Process CreationDate 读取的创建时间只有微秒精度, 原生 GetProcessTimes FILETIME 为 100 ns 精度, 旧代码对二者做字符串全等比较.

具体观测: PID 1740 的原生 FILETIME 为 `134380710533160753`, trace 为 `134380710533160750`; PID 2096 分别为 `134380710318692894` 和 `134380710318692890`. 两者表示同一个微秒内的创建时刻, 旧代码却判断为 PID 复用, 令正常 UDP 轮换无法闭环.

另一个相关缺陷是共享 UDP 端口只取首个匹配 PID. 现场 5353 同时存在多个 owner, 首行通过会漏查后续 owner. 只取消 mixed owners 限制会保留这个漏洞.

## 实际修改

- `fakenet/mcp/reboot_recovery.py`: 新增 `cim_creation_matches`, 保留完整精度证据的精确比较; 对微秒对齐的 CIM 时间, 仅接受对应十个 100 ns tick 的区间, 不扩大到相邻微秒. 同 boot, 活进程, 映像可见性和错误标记等原门禁继续生效.
- `fakenet/mcp/endpoint_attribution.py`: 外部 UDP 归因遍历共享端口的全部 owner. 每个 owner 都必须早于 run 存在, 不能属于 managed 进程, 且后续原生身份核对必须通过. 重复原始行, 未知 owner 和新建 owner 继续拒绝.
- `test/mcp/test_recovery_audit_deadlock.py`: 使用经简化的现场数据形态验证精度差异, 共享 owner, 拒绝边界及管理员受控停止到 marker 释放的链路. 这是受控夹具, 不冒充整包 VM 原始证据.

五节审计, TCP 差异, 原始证据字节和 controller 永久持有语义保持原契约. 本次未增加降级审计, TTL, 接管 token 或清除 marker 的后门.

## 管理员恢复与 SCM 停止

现有本地管理员入口已经能够处理旧会话遗留责任: 以管理员身份执行安装目录下的 `fakenetng-mcp.exe stop`. 它发起 SCM 自定义预停控制, 服务内部沿旧 controller 执行审计恢复; 审计通过且 run/controller 释放后, 才允许标准 SCM STOP 并等待 SERVICE_STOPPED. 必须等命令退出并核 `logs/service-stop-result.json` 的当前实例与 attempt, 失败时保留恢复责任.

直接 `Stop-Service` 或 `Restart-Service` 在预停尚未成功时不被接受, 是 `winservice.py` 的既有两阶段设计, 不是 exit-monitor 保活. 已有 `test_winservice_state.py` 覆盖预停前拒绝标准 STOP, 预停后允许 STOP_PENDING 的行为. 服务重启使用上述 CLI 成功停止后再执行 `Start-Service fakenetng-mcp`; 本次未在现用 VM 执行这组变更.

## 验证与证据边界

旧源码对照重放: 2 failed, 1 passed. 新补丁定向回归: 267 passed, 2 skipped. 原始失败复现和完整命令见本地 `Logs/recovery-audit-deadlock-20261106/red-original-source.txt` 与 `targeted-regression.txt`.

VM 内只读历史重放读取原 baseline, trace-start 和留存审计末两条采样. 原实现两次均 `attributed=true, identity_verified=false`, 补丁两次均 `attributed=true, identity_verified=true`; 归因 owner 行由 7 增至 8, 因为共享端口的第二个 owner 也得到检查. 只向宿主返回判定摘要, 未修改安装文件, 服务或恢复状态. 摘要见本地 `Logs/recovery-audit-deadlock-20261106/historical-replay-summary.txt`.

VM 原件位置保持为 `C:\ProgramData\FakeNet-NG-MCP\baselines\7dd27b43-6242-41d0-9df1-6eb7b9951c00.json`, 对应 run 的 `artifacts\runs\<run_id>\endpoint-trace-start.json`, 以及 `logs\recovery-audit-7dd27b43-6242-41d0-9df1-6eb7b9951c00-60a8984d-8435-49a6-ae2c-48ea8cc3c62f.jsonl` 和 `.attribution.json`.

完整 MCP 测试包含创建 socket 的用例, 当前宿主沙箱以 `PermissionError: Operation not permitted` 拒绝, 不能报告全套通过. 已检查仓库指定 Docker/Wine builder, 但当前会话无 Docker socket 权限. Windows 安装包构建, 部署和新 run 原生停止验收尚未执行; 历史只读重放不替代这些步骤.

原始 VM 证据整包导出被自动审批拒绝, 理由是可能包含敏感内容. 因此没有导出原件, 后续验证改在 VM 内执行, 仅返回非敏感判定摘要.
