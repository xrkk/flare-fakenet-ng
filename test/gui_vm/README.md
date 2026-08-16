# GUI 配置工具 VM 一键验收

对应方案 `PLAN/2026.08.14/2026.08.14-01-GUI配置界面方案.md` §6 验收环境 / §12.18。

## 用法

1. 在**隔离分析 VM** 内放置(任一布局):
   - VM 验收包(`Windows-GUI配置工具-VM验收-v*.zip`,已含 `fakenet.exe`/`fakenet-GUI.exe` 于包根),或
   - 仓库检出 + 已 `pip install .`(GUI 以 `python -m` 运行;A6–A8 需要 `fakenet.exe`,建议放到本目录/仓库根/`dist\`)。
   - **验收驱动脚本本身需要 VM 内有 Python ≥3.8(仅标准库依赖;两个 exe 已自带各自运行时)。**
2. 双击 `Run-Tests.cmd`。**仅开头一次 UAC 同意**,之后全程免操作;脚本自提权后,对 fakenet 的提权启动不再弹窗。
3. 结果:控制台汇总 + `Logs\<时间戳>\results.tsv`(及 fakenet 运行日志)。

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
