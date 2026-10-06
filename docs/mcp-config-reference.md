# FakeNet-NG MCP 配置参考

> 适用于候选 `mcp-c94e7abdb-57b2ee8a7dde`（r58c）。两套配置：服务自身的 `service.json`，与受管 FakeNet INI。

## 1. 服务配置 service.json

路径：`C:\ProgramData\FakeNet-NG-MCP\configs\service.json`。修改后通过安装目录下的 `fakenetng-mcp.exe stop` 受控退出服务，再运行 `fakenetng-mcp.exe start` 生效。字段校验 fail-closed：任何非法值拒绝启动。

| 字段 | 必填 | 类型/范围 | 默认 | 说明 |
| --- | --- | --- | --- | --- |
| `listen_ip` | 是 | 具体单播 IP | — | MCP 端点绑定地址。**禁止 `0.0.0.0`/`::`**（必须是专用地址，通常取与控制端同网的 host-only/内网 IP） |
| `listen_port` | 是 | 1–65535 | — | MCP HTTP 端点端口（部署示例用 28788） |
| `allowed_host_ips` | 是 | 非空字符串数组 | — | 防火墙规则放行的控制端源 IP（安装脚本据此建规则） |
| `log_level` | 否 | DEBUG/INFO/WARNING/ERROR | INFO | 服务日志级别 |
| `extra_control_ports` | 否 | 端口数组 | [] | 除 `listen_port` 外同样受主 WinDivert filter 排除保护的端口（如并存的 Win10VM 管理通道 28787/28790）。不得等于 `listen_port`，重复自动去重 |
| `stop_grace_seconds` | 否 | 5–600 | 60 | 停止宽限：FakeNet 停止超过该时长按"宽限超限"收敛（保留恢复标记，下次启动先审计） |
| `allow_legacy_protocol` | 否 | JSON 布尔值 | false | 显式启用旧式 initialize 客户端兼容；支持 2024-11-05、2025-03-26、2025-06-18、2025-11-25。现代协议仍严格校验。修改后重启服务。 |
| `allow_legacy_protocol` | 否 | JSON 布尔值 | true | 默认兼容 initialize 客户端（如 Codex）；支持 2024-11-05、2025-03-26、2025-06-18、2025-11-25。现代协议仍严格校验。显式 false 仅允许现代协议；修改后重启服务。 |

示例：

```json
{
  "listen_ip": "192.168.204.149",
  "listen_port": 28788,
  "allowed_host_ips": ["192.168.204.1"],
  "log_level": "INFO",
  "extra_control_ports": [28787, 28790],
  "stop_grace_seconds": 60
  "stop_grace_seconds": 60,
  "allow_legacy_protocol": true
}
```

安装时的对应参数：`install-fakenetng-mcp.ps1 -ListenIp <ip> -Port <port> -AllowedHost <ip> [-ExtraExcludePort @(28787,28790)]`。

2026-10-06 起，新安装及未声明该字段的配置默认
`allow_legacy_protocol=true`；已有配置中显式的 `false` 保持有效，需手动修改。
host-only 绑定、防火墙和恢复门禁不变。显式 `false` 可关闭旧式兼容。

### Windows 服务自动启动和故障恢复

安装器将 `fakenetng-mcp` 注册为自动启动的 Windows 服务，并配置进程崩溃后
延迟 30 秒重启。管理员 PowerShell 可查看或重新设置：

```powershell
sc.exe config fakenetng-mcp start= auto
sc.exe failure fakenetng-mcp reset= 0 actions= restart/30000
sc.exe qc fakenetng-mcp
sc.exe qfailure fakenetng-mcp
sc.exe qfailureflag fakenetng-mcp
```

若还需在服务报告非零退出错误时触发恢复，可另行设置
`sc.exe failureflag fakenetng-mcp 1`；Microsoft 文档注明此标志更改在下次系统启动时生效。
正常受控停止或管理员停止服务不会触发该故障恢复，
MCP 工具 `stop` 停止的是受管 FakeNet 核心，主管服务仍运行。
恢复规则及标志语义见 [sc failure](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742019(v=ws.11))
和 [SERVICE_FAILURE_ACTIONS_FLAG](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actions_flag)。

## 2. 受管 FakeNet INI

- 内置：`configs\default.ini`（只读，`delete_config`/`edit_config` 均拒绝）。
- 自定义：`configs\custom\*.ini`，经 MCP 工具管理（`create_config`/`import_config`/`edit_config`/`rename_config`/`delete_config`），每次变更（含被拒尝试）写审计日志 `configs\audit.jsonl`。路径穿越/符号链接逃逸被阻断。
- 语法/语义校验通过 `validate_config` 或 `load_config` 完成；**start 只会用已 load 的配置**。
- 运行期活动配置被 OS 级锁定：外部写/删/改名被拒，服务自身仍可读；停止后解锁。
- 每个 INI 段的逐项含义见 `default.ini` 内嵌注释。常用段：

| 段 | 作用 | 常用项 |
| --- | --- | --- |
| `[FakeNet]` | 总开关 | `DivertTraffic`（No=只开监听器不改路由） |
| `[Diverter]` | 流量接管 | `NetworkMode: SingleHost`（实机单主机模式）；`DebugLevel`（GENPKT/GENPKTV/… 细粒度调试）；`DumpPackets`/`DumpPacketsFilePrefix`（原始+以太网双格式 PCAP）；`DumpHTTPWebRoot`；`ControlLinkExcludeIp/Port`（控制链路排除——服务启动时自动注入自身端点，配置自带值会被校验，非法则拒绝启动） |
| `[DNS Server]` / `[DNS TCP Server]` | DNS 劫持应答 | 默认通配应答指向本机；黑名单进程隐藏日志 |
| `[ProxyTCPListener]`/`[ProxyUDPListener]` | 端口代理 | `Enabled`、`Port`、`ProxyIP`/`ProxyPort` |
| `[RawTCPListener]`/`[RawUDPListener]` | 裸监听 | `Enabled`、`Port` |
| `[HTTPListener80]`/`[HTTPListener443]` | HTTP(S) | `Enabled`、`Port`、webroot、自定义响应（见 docs/CustomResponse.md） |
| `[SMTPListener]`/`[FTPListener21]`/`[FTPListenerPASV]`/`[IRCServer]`/`[TFTPListener]`/`[POPServer]` | 协议仿真 | 各自 `Enabled`/端口 |
| `[Forwarder]`/`[FilteredListener]`/`[Domain Egress Relay]` | 转发/过滤/域名出口 | 见内嵌注释 |

要点：

- **不要关闭 `DivertTraffic` 以外的安全相关默认值**除非你明确知道后果；`NetworkMode` 保持 `SingleHost`。
- PCAP/报告输出：相对路径相对进程工作目录（r58c 上为程序根；后续版本改为 ProgramData 每运行目录）。
- 修改自定义配置的推荐流：`read_config default.ini` 取基础 → 本地改 → `create_config`/`edit_config` → `load_config` → `start`。
