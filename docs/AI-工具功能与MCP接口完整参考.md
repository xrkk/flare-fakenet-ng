# FakeNet-NG：AI工具功能与MCP接口完整参考

本文可单独提供给AI，说明本仓库产品功能、配置入口和全部MCP调用合同。以2026-09-23读取的源码 `e22a60d74adc088a6e8221194baf6bbe2f21d037` 为基线；描述实现能力，不代表全部场景已经验收通过。运行中的安装包可能落后于源码，连接后先用 `tools/list` 核对实际schema，不能仅凭版本号认定包内容一致。

## 1. 产品是什么，选哪个入口

FakeNet-NG用于隔离实验环境中的网络行为分析：截获并重定向流量、模拟网络服务、记录请求响应、生成抓包和HTML报告。本仓库还增加Windows出站策略、域名接管、公网IPv4放行、按进程透明重定向、GUI和MCP主管服务。

| 入口 | 用途 | 边界 |
| --- | --- | --- |
| `fakenet.exe` / `python -m fakenet.fakenet` | 直接运行FakeNet核心与监听器 | 根据INI接管网络或只运行监听器 |
| `fakenet-GUI.exe` / `python -m fakenet.gui.main` | 编辑配置、校验、启动核心、看实时日志 | GUI不是MCP客户端，也不是MCP工具 |
| `fakenetng-mcp.exe` / `python -m fakenet.mcp` | 安装和运行Windows主管服务 | 通过MCP控制受管子进程、配置、状态、产物元数据 |
| `Start-*.cmd`、验收runner | 预设模式启动和受控验收 | 本地命令，不是远程MCP接口 |

MCP服务启动不代表FakeNet已经接管网络；需要 `load_config` 后 `start`。工具 `stop` 停止受管FakeNet及恢复网络，**不会卸载/停止MCP服务本身**。服务CLI的 `stop` 则是服务级受控停止，两者不同。

## 2. 全部主要功能与使用边界

### 2.1 原有核心与协议服务

- `DivertTraffic=Yes`启用Diverter；Windows使用WinDivert，Linux有独立netfilter实现。Windows专属External策略不应搬到Linux启用。
- 可按配置重定向指定协议/端口或全部适用流量至监听器；响应改写为原请求目标，供分析程序观察仿真服务。
- `DivertTraffic=No`可仅启动监听器，通常绑定`0.0.0.0`，不加载Diverter；并不等于服务只对本机可见。
- 通过端口、进程及其它配置过滤流量；过滤与策略字段详附录，不把未知配置键当作有效能力。
- 支持以下10种监听器类，可在INI中建立多个命名实例：

| 类 | 功能 |
| --- | --- |
| `DNSListener` | DNS请求处理、配置A/MX/TXT等响应及策略相关DNS行为，TCP/UDP实例按配置建立 |
| `HTTPListener` | HTTP服务、文件响应和自定义响应；可配置TLS |
| `FTPListener` | FTP仿真服务 |
| `SMTPListener` | SMTP邮件协议仿真 |
| `POPListener` | POP协议仿真 |
| `IRCListener` | IRC协议仿真 |
| `TFTPListener` | TFTP仿真 |
| `RawListener` | 原始TCP/UDP收发与静态/动态自定义响应 |
| `ProxyListener` | 嗅探并分派给运行中的监听器；历史Listeners键不参与选择，非通用公网代理授权 |
| `DomainEgressRelay` | 出站策略内部TLS中继及ClientHello/SNI核对，不是任意CONNECT代理 |

监听器是否启用、协议、端口、响应行为均取决于实际INI；不要将默认例子的端口理解为不可修改的接口。

### 2.2 域名白名单出站（Windows新增）

`ExternalAccessPolicy=EgressControl`启用；`Disabled`关闭该扩展。域名集合由`ExternalAllowedDomains`指定，核心强制允许TCP端口443、SNI验证、外部IPv6/QUIC阻断和固定资源限制。当前示例常用`api.deepseek.com`，一般域名策略与下述私网接管模式的固定域名约束须区分。

策略通过外部DNS解析及TLS中继允许符合域名/SNI合同的连接，其余按`ExternalNonAllowedAction`处理。这是域名/SNI层控制，不是URL、HTTP方法或内容白名单。直接IP访问不能自动取得域名授权，DNS变化也不自动授权所有IP。ECH等无法验证SNI的情形不得假定可用。

### 2.3 私网域名接管（Windows新增）

`ExternalTakeoverIPv4`把非允许目标导向指定私网分析主机，示例配置 `domain_takeover_windows.ini`。此模式受更严格安全合同约束：唯一真实域名固定为`api.deepseek.com`，非允许动作固定Divert，相关DNS ResponseA与sink一致；目标路由及地址合法性由启动检查判断。可选TCP端口探测是无应用载荷的前置检查，不是业务可用性证明。不要把它解释成任意目标公网代理。

### 2.4 公网IPv4精确放行（Windows新增）

`ExternalAllowedIPv4Rules`格式为 `协议/IPv4/端口`，例如 `TCP/110.242.69.21/443`；此处数字仅为格式说明，不是当前授权。支持的通配及集合限制见附录和实际校验。它是网络层授权，不额外保证SNI、证书、HTTP内容或进程身份。

规则需要合法公网IPv4、端口和协议，受重复/通配冲突、条数/地址数量、受保护地址和运行路由检查约束。32/33规则、16/17地址为应关注的边界；GUI和核心共用严格解析。示例/交付包中经审定的IP、配置hash、manifest不可被客户端随意替换成DNS新地址。

### 2.5 按进程透明IPv4重定向（Windows新增）

`ExternalProcessRedirectEnabled=Yes`：对一个确切可执行文件，将它发往公网IPv4 A的TCP目的地址改为同链路RFC1918私网IPv4 B，端口不变；回包反向改写。绑定完整映像路径、SHA256和实际文件/进程身份，不按basename、不默认继承给子进程。

配置包含Protocol=TCP、ImagePath、ImageSHA256、OriginalIPv4和TargetIPv4。单规则，不支持UDP、IPv6、端口映射或任意多规则。新流使用完整TCP owner tuple与身份复核，未知/歧义/路由漂移等拒绝。它不启动或管理B上的服务。

历史README记录特定WinDivert版本下关闭后的无载荷FIN/RST限制；该说明不是所有策略/场景的全局豁免，也不能据此忽略带载荷原目标包。正常功能边界、运行结果和验收状态应分别报告。

### 2.6 抓包、日志、报告和自定义响应

- `DumpPackets=Yes`生成同步raw-IP PCAP与`-converted.pcap`（合成以太网头）两份观察记录，snaplen262144。重定向前后可能多次记录同一包，不能当物理线速包数；要证明实际NIC行为，使用独立抓包。
- HTML报告展示网络行为指标、进程/协议分类、请求响应及分析信息。具体产物依配置及运行是否完成；读取前核完成状态和哈希。
- HTTP/Raw的`Custom`指向自定义响应INI，选择器可用`ListenerType`或`InstanceName`，同时提供时为OR。HTTP按Host/URI等选择返回内容，Raw支持静态文件或Python动态处理；完整字段见附录。Python动态响应是本地可执行代码能力，不是MCP提供的任意代码执行接口。
- 核心/GUI有各自日志；冻结GUI发布通常在exe旁`Logs`，MCP服务的数据在ProgramData，每run有独立证据目录，不能混用路径规则。

### 2.7 GUI新增功能

五个标签：基础配置、出站策略、监听器、自定义响应、实时日志。支持实时校验、字段提示、导入/保存/恢复默认、监听器增删复制重命名、域名/IPv4规则表编辑、映像SHA自动计算、启动核心和跟踪实际日志。

保留未知键、禁用节、顺序、编码/BOM、换行等原文本信息；代码固定字段只读，策略依赖的DNS/relay自动管理。启用策略可能在内存补齐依赖并标记修改，保存才落原文件。恢复默认对已绑定文件会在确认后覆盖。启动检查VM、重复进程和UAC；运行期间编辑锁定。未知扩展键仅保留，不承诺核心支持。

### 2.8 MCP主管新增功能

Windows无头服务管理独立Job中的FakeNet子进程，维护控制者、状态版本、配置身份、健康详情和事件。启动前保存恢复基线，失败/停止执行有界收尾与恢复审计，必要时生成incident/dump/退出诊断。`healthy`要求真实初始化与资源健康，不等于TCP端口可连接。

MCP不提供：任意shell/PowerShell、任意路径文件读写、PCAP正文下载、远程修改service.json、快照恢复、清空恢复标记、强制启动、任意进程结束。需要文件传输/VM操作时属于另行授权的外部通道。

## 3. 连接协议与请求格式

### 3.1 地址和身份

- HTTP POST `/mcp`，默认端口28788；具体IP由安装`listen_ip`确定，禁止监听`0.0.0.0`或`::`。
- 项目历史测试端点为`http://192.168.204.233:28788/mcp`；28787是另一套VM管理服务，不是本产品。地址示例不是当前操作授权，使用用户指定机器。
- 服务名`fakenetng-mcp`，软件版本`0.1.0`；协议版本为仓库当前常量`2026-07-28`。这里描述仓库实现，不宣称其它MCP服务也采用该协议。
- 默认现代模式无持久MCP session、无GET SSE端点，不先发传统`initialize`。GET/DELETE `/mcp`返回405。
- `X-FakeNet-Controller-ID`为标准带连字符UUID字符串；只读接口可以缺省，所有变更必须携带。它是合作身份，不是认证密码；权限边界还依赖host-only地址、防火墙和允许宿主IP。此实现不校验Origin。

### 3.2 现代请求

每次发送`Content-Type: application/json`、`Accept: application/json, text/event-stream`、`MCP-Protocol-Version: 2026-07-28`、`Mcp-Method`。`tools/call`还需`Mcp-Name`，必须与body名称一致。body `params._meta`中的协议版本若提供必须与header一致。

只读示例（UUID在变更调用中固定为同一个控制者）：

```http
POST /mcp
Content-Type: application/json
Accept: application/json, text/event-stream
MCP-Protocol-Version: 2026-07-28
Mcp-Method: tools/call
Mcp-Name: get_status
X-FakeNet-Controller-ID: 550e8400-e29b-41d4-a716-446655440000
```

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_status","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"fakenet-ai-client","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}
```

获取实际工具schema：同一地址将header `Mcp-Method`和body `method`改为`tools/list`，移除`Mcp-Name`，params仅保留必要meta。SDK还提供`server/discover`，它们是协议方法，不计入16个业务工具。

默认返回JSON-RPC外层`result`中的MCP工具结果；常见为`content:[{type:"text",text:"{...业务JSON...}"}]`。优先遵循客户端SDK解包；手写客户端解析text中的JSON，并同时检查JSON-RPC error、MCP isError及业务error/state，不因HTTP200或error=null就认定业务成功。若响应为SSE，解析data帧并按请求id关联，不能直接把整段当JSON。

### 3.3 可选旧协议模式

仅当service.json显式`allow_legacy_protocol=true`，才允许SDK处理旧协议initialize及后续调用。支持的旧版本为2024-11-05、2025-03-26、2025-06-18、2025-11-25。initialize的params.protocolVersion必须受支持；后续请求携带一致版本header。仍是stateless HTTP，没有额外GET SSE端点。不要遇协议错误就猜测降级或远程修改服务配置。

## 4. 所有变更工具共用的合同

`command_id: string`和`expected_state_version: integer`为必填；控制者UUID在HTTP header，不放arguments。推荐每个新意图使用新UUID作command_id，但源码未要求command_id必须UUID。

1. 先读get_status，取当前state_version；发变更前后都检查状态。接受的变更会推进版本，即使后续执行失败；健康自主变化不必推进版本。
2. 同进程内同控制者重复command_id重放原结果，可能有`replayed:true`；执行中重放可能返回`in_progress:true`。缓存为内存中最近256个完成命令，重启不保留。**不得复用同一ID表达不同方法/参数**：当前重放按ID，不重新核对参数等价。
3. 身份检查在重放之前；不能用他人command_id接管。活动run有控制者且不超时过期，冲突控制者只能读状态。
4. 生命周期冲突立即operation_busy、不排队。干净stopped且无控制者时，不相交配置名的变更可并行；客户端默认串行，避免版本竞争。
5. recovering、受控退出/draining或待保护恢复期间拒绝客户端新变更；failed态能否stop取决于实际责任与当前门，不能盲目重试start。
6. 配置编辑/重命名/删除还要携带read_config所得expected_sha256；state_version与文件SHA解决不同冲突，不能互相代替。

### 通用变更返回

正常完成通常为：

```json
{"state":"stopped","state_version":3,"run_id":null,"changed":true,"error":null,"command_id":"cmd-002","last_run_outcome":null}
```

`state`可能为stopped/starting/healthy/degraded/stopping/failed/recovering；状态查询应保留未来扩展值。`run_id`为当前实例或null，`changed`表示本次行为是否变化，`last_run_outcome`可为ok/failed/null。restart可额外返回`bound_run_id`表示旧实例。`stopped + last_run_outcome=failed`表示已收尾但上次运行失败，不能改称成功。

当前Coordinator会收敛内部返回：**配置创建/编辑等不会在公开变更结果中自动返回name/sha256/content；load_config也不直接返回config_identity**。用read_config或get_status再读。业务异常常见：

```json
{"state":"failed","state_version":8,"run_id":"run-uuid","changed":false,"error":{"code":"state_conflict","message":"expected_state_version does not match current state","detail":{"expected":7,"current":8}},"command_id":null}
```

错误路径字段可能少于成功路径；内部非McpError也可能成为SDK工具错误，不能假设所有异常均为同一个业务结构。

## 5. 全部16个MCP工具

下表参数类型取自当前注册函数签名。未标可选的一律必填；不发送无关参数。可选字符串推荐省略而非显式null，以部署的tools/list inputSchema为准。

| 工具 | arguments | 用途与专属返回/限制 |
| --- | --- | --- |
| `ping` | `{}` | 无副作用探活。返回service/version/protocol/controller_header，后者为valid_uuid/missing/invalid_format；不证明核心已healthy |
| `get_status` | `{}` | 完整当前状态，字段见§6 |
| `get_events` | `limit: integer=100`（可选） | 返回events数组与error:null；源码将值夹到1..500，仅近期内存事件，无分页/持久化保证 |
| `list_configs` | `{}` | 返回configs数组与error:null；每项name/builtin/size/sha256/active |
| `validate_config` | `name: string`（可选），`content: string`（可选） | 至少一个；两者同时给时content优先。成功valid:true、sections、error:null；失败error，不能假定有valid:false |
| `read_config` | `name: string` | 返回name/builtin/sha256/size/content/error。原始INI正文，仅配置域，不读任意路径 |
| `list_artifacts` | `{}` | 返回artifacts数组与error，元数据见§6；无正文、无run过滤参数；固定诊断任务60秒预算 |
| `load_config` | `name: string, command_id: string, expected_state_version: integer` | 读取并校验现有配置，登记name/SHA/builtin；活动run时拒绝。不会启动FakeNet |
| `start` | `command_id: string, expected_state_version: integer` | 使用已load配置启动，未load拒绝；实际主管核Windows/防火墙/身份/恢复等条件。开始运行绑定控制者 |
| `stop` | `command_id: string, expected_state_version: integer` | 停止当前run并恢复；无run且无恢复责任时changed:false并释放配置活动锁。只检查stopped还不足，应读恢复/历史失败详情 |
| `restart` | `command_id: string, expected_state_version: integer` | 必须有活动run；受控stop后start，响应run_id是新实例，bound_run_id为原实例。不是配置热更新工具 |
| `create_config` | `name: string, content: string, command_id: string, expected_state_version: integer` | 校验正文并在自定义根创建；存在/内置名冲突拒绝；成功返回通用变更结构 |
| `import_config` | `name: string, content: string, command_id: string, expected_state_version: integer` | 按正文导入，存储行为同create；**没有源文件路径或URL参数** |
| `edit_config` | `name: string, content: string, expected_sha256: string, command_id: string, expected_state_version: integer` | 全文替换自定义INI，非局部patch；SHA防并发覆盖，活动或受恢复责任保护的配置不能编辑 |
| `rename_config` | `name: string, new_name: string, expected_sha256: string, command_id: string, expected_state_version: integer` | 自定义配置重命名，保护源/目标两个名字；目标冲突、内置或正在使用时拒绝 |
| `delete_config` | `name: string, expected_sha256: string, command_id: string, expected_state_version: integer` | 删除自定义配置；内置/使用中/SHA冲突拒绝。调用前确认用户有删除意图 |

所有读操作错误也可能只有`error`，其余成功字段缺失。多数业务工具当前无docstring，部署tools/list的description可能为空；本文提供语义说明，签名仍以部署schema为准。

## 6. 返回对象细节

### 状态与事件

get_status包含`service`、`state`、`state_version`、`run_id`、`controller`、`failure_reason`、`config_identity`、`last_run_outcome`、`health`、`error`。

- config_identity为null或`{name,sha256,builtin}`；不要把配置名当固定内容版本。
- health为主管缓存的详情字典，具体字段随阶段/实现变化，不是固定布尔。可包含process_alive、init_evidence、probe、listener/driver或恢复诊断；字段缺失不能等价通过。
- 状态快照与健康缓存不是跨进程完全原子观测；遇运行变化应继续核事件和最终响应。
- events每项至少有`timestamp`（服务所在guest的Unix秒浮点）和`kind`，其余按事件类型变化。典型kind为command.accepted/completed/failed、health、recovery、terminal_failure、draining.begin/failed，可带command_id/controller/operation/state/state_version/reason。不是永久审计日志。

### 配置正文

自定义名字匹配`^[A-Za-z0-9._-]+\.ini$`，不接受路径分隔符、绝对路径或Windows设备名CON/PRN/AUX/NUL/COM1..9/LPT1..9；符号链接、硬链接及目录逃逸拒绝。正文UTF-8编码后≤1MiB。内置配置只读，自定义不能覆盖它；read_config优先识别内置名。

validate_config调用核心解析得到`sections:{fakenet:{...},diverter:{...},listeners:{节名:{...}}}`。它证明语法/基础语义，不证明当前VM路由、DNS、端口、证书、外网或运行依赖可用；start仍可能拒绝。INI正文按全文传入，JSON中换行写`\n`，不要发送反斜杠字面串代替真实换行。

### 产物

每项`{path,type,size,complete,sha256}`；path是guest受管路径而非宿主可读路径；type通常pcap/log/report/userdump/config，其它后缀可作为类型。只有生产者已发布且当前内容与发布大小/哈希一致才complete:true；未完成时sha256可为null。`.part/.partial`不是完成产物。仅文件存在或有大小不足以读取为最终证据。

list_artifacts包含多个run产物，调用者按真实路径/run身份筛选，不能把不同run的同名run.log借来补证。诊断超时可返回`{"artifacts":[],"error":"..."}`，这里error是字符串例外，不能当成“没有产物”。正文传输须另行授权通道及SHA校验。

## 7. 错误处理表

| 业务error.code | 含义 / 正确后续 |
| --- | --- |
| controller_identity_missing | 变更缺有效UUID header；修正本客户端身份 |
| controller_conflict | 当前run或command_id属于另一控制者；读取状态并协调，不抢占 |
| state_conflict | 版本旧；重新get_status，核原意图是否仍适用后以新命令提交 |
| operation_busy | 冲突操作执行中；观察原命令状态，不重复创建并行操作 |
| config_not_found | 名字不存在；先list_configs核名 |
| name_conflict | 创建/重命名目标冲突；选择新名字或明确编辑现有文件 |
| version_conflict | 配置SHA不匹配；重新读取、合并意图，不能盲覆盖 |
| path_escape_blocked | 名字/链接/路径非法；只用合法自定义文件名 |
| config_in_use | 配置被活动run/恢复责任保护；先闭合对应责任 |
| validation_failed | INI解析或启动边界校验失败；读message/detail修正原因 |
| invalid_request | 参数、正文类型/大小或调用前置不满足 |
| builtin_readonly | 内置不可改；复制正文至新自定义名 |
| audit_write_failed | 配置审计无法安全落盘；保存现场，解决存储问题 |
| not_allowed_in_state | 当前生命周期或退出/恢复阶段拒绝此操作 |
| internal_error | 内部错误；保留状态、事件及服务日志定位 |

传输层另有JSON-RPC错误：缺版本header/方法或名称不匹配通常HTTP400、code=-32020；不支持版本/默认模式legacy initialize为-32022；params不是对象为-32600；SDK还可能报告未知方法/工具、schema不匹配等。错误码层次必须区分。

**响应超时处理：** 超时不是停止事实。保存原command_id，用同控制者重试原ID或读状态/事件确认；in_progress继续等待实际终态。服务重启后缓存已失效，先核当前run/恢复状态再决定，不能机械重发start。不得清needs_recovery或把failed改成stopped来绕过恢复。

## 8. 推荐完整调用流程

1. `tools/list`核实际16工具/参数；`ping`核服务与协议；`get_status`确认没有他人run、未闭合恢复或正在变更。
2. `list_configs`选择现有配置，或`read_config("default.ini")`取基础，在本地修改后`validate_config(content=...)`。需要新增时`create_config`，需要编辑时先read SHA再`edit_config`。
3. 每个新变更前get_status取新state_version。`load_config(name,command_id,expected_state_version)`；再get_status核config_identity SHA。
4. `start`；确认最终healthy及health具体事实。degraded/failed、SDK错误或超时均不能算启动成功。保存run_id与控制者。
5. 通过get_events和get_status观察；需要重启同一配置时用restart并核旧bound_run_id/新run_id。要换配置，先stop责任闭合再load/start。
6. `stop`后核stopped、run_id=null、controller释放和恢复诊断；last_run_outcome=failed仍须如实报告。
7. `list_artifacts`等待生产者封存，按本run筛选complete及hash；另行传输并核SHA。必要配置清理只能删除确认不再使用的自定义文件。

变更arguments示例（版本3必须换成刚读取的实际值，command_id仅示例）：

```json
{"name":"default.ini","command_id":"load-001","expected_state_version":3}
```

以上给load_config；随后start arguments仅`command_id`和新读取的`expected_state_version`。无需也不能给start传exe路径、shell、config正文或run_id。

## 9. 本地部署CLI与服务配置

CLI子命令：install、uninstall、start、stop、run、debug（前台运行，无SCM）；`--version`查询版本。install参数`--listen-ip`必填，`--port`默认28788，`--allowed-host`必填可重复，`--extra-exclude-port`可重复。管理员在目标Windows安装，普通AI不得把本地CLI伪装成远程MCP工具。

service.json位于`%ProgramData%\FakeNet-NG-MCP\configs\service.json`。字段：

| 字段 | 类型/默认 | 说明 |
| --- | --- | --- |
| listen_ip | string，必填 | 具体host-only地址，不接受通配绑定 |
| listen_port | integer，必填 | 1..65535；CLI默认28788 |
| allowed_host_ips | 非空string数组，必填 | 防火墙允许宿主地址；单string也会归一数组 |
| log_level | string，INFO | 日志等级配置 |
| extra_control_ports | integer数组，[] | 1..65535，去重并排除自身端口；控制链豁免 |
| stop_grace_seconds | 5..600，60 | 优雅停止阶段预算，不等于完整恢复总耗时 |
| allow_legacy_protocol | boolean，false | 显式开启旧协议兼容 |

MCP数据根下包括configs、configs/custom、state、baselines、logs、artifacts；部署内置INI在安装目录configs。服务日志、配置审计、恢复状态和退出诊断用途不同；不要把用户分析数据路径作为可任意删除缓存。

## 10. 配置字段完整目录（当前GUI声明目录）

以下由当前`fakenet/gui/schema.py`机械提取，列出原有和新增字段，供AI编写INI时查阅；这是声明目录，不是另一个MCP工具列表。GUI默认值不保证等于每个现有INI或核心缺省值；运行以read_config实际内容及validate/start结果为准。`dead`标记为仅保真保留、运行不读取。第三方未知监听器扩展可能不在表内，不应编造语义。

类型：bool_yesno=Yes/No；bool_truefalse=True/False；bool_policy=Disabled/EgressControl；int=整数；enum=列举值；stringlist=逗号字符串列表；portlist/portspec=端口或范围表达；ipv4=IPv4；hex64=64位十六进制SHA；path_*为目标机器路径。被锁定字段在EgressControl启用时按核心要求设置，不靠编辑INI绕过。

### [FakeNet]

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `DivertTraffic` | 劫持流量 (DivertTraffic) | bool_yesno / `Yes` | Yes 时 NetworkMode 必填;出站策略启用时强制 Yes |

### [Diverter]

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `NetworkMode` | 网络模式 | enum / `SingleHost` | Auto: Windows→SingleHost, Linux→MultiHost；枚举=SingleHost, MultiHost, Auto |
| `DebugLevel` | 调试级别 | stringlist / `Off` | 逗号分隔;合法标签: Off, GENPKT, GENPKTV, CB, NONLOC, DPF, DPFV, IPNAT, MANGLE, PCAP, IGN, FTP, IGN-FTP, MISC, NFQUEUE, PROCFS, IPTABLES；枚举=Off, GENPKT, GENPKTV, CB, NONLOC, DPF, DPFV, IPNAT, MANGLE, PCAP, IGN, FTP, IGN-FTP, MISC, NFQUEUE, PROCFS, IPTABLES |
| `DumpPackets` | 双 PCAP 抓包 | bool_yesno / `Yes` | 同步输出 raw-IP 与合成以太网两份 PCAP |
| `DumpPacketsFilePrefix` | PCAP 文件前缀 | string / `packets` | 同步生成的 raw-IP 与合成以太网 PCAP 共用此前缀 |
| `FixGateway` | 自动修复网关 | bool_yesno / `Yes` | 为 VMware Host-Only 等未提供网关的环境自动设置合适网关 |
| `FixDNS` | 自动修复 DNS | bool_yesno / `Yes` | 自动设置 FakeNet 拦截所需的 DNS 地址;退出时按核心流程恢复 |
| `ModifyLocalDNS` | 修改本地 DNS | bool_yesno / `Yes` | Windows 改注册表;Linux 临时改 /etc/resolv.conf |
| `StopDNSService` | 停止 DNS 客户端服务 | bool_yesno / `Yes` | 仅 Windows |
| `RedirectAllTraffic` | 重定向全部流量 | bool_yesno / `Yes` | 开启时 DefaultTCP/UDPListener 必填且须为已存在段名 |
| `DefaultTCPListener` | 默认 TCP 监听器段名 | string / `ProxyTCPListener` | 未命中显式端口的 TCP 流量交给此已存在监听器段;区间段使用展开后的实例名 |
| `DefaultUDPListener` | 默认 UDP 监听器段名 | string / `ProxyUDPListener` | 未命中显式端口的 UDP 流量交给此已存在监听器段;注意默认接管 DNS 流量 |
| `BlackListPortsTCP` | TCP 端口黑名单 | portlist / `139` | 仅 RedirectAllTraffic 开启时生效;支持 67, 68 与 60000-60010 |
| `BlackListPortsUDP` | UDP 端口黑名单 | portlist / `67, 68, 137, 138, 443, 1900, 5355` | RedirectAllTraffic 开启时不重定向这些 UDP 端口;支持逗号与端口区间 |
| `BlackListIDsICMP` | ICMP ID 黑名单 | intlist / `` | 仅 Windows;模板中仅注释样例,v0.2 审计 P5 补 |
| `ProcessWhiteList` | 进程白名单(Diverter 级) | stringlist / `` | 全局过滤:仅接管列表内进程的出站流量,其他进程直接转发;与 ProcessBlackList 互斥(同时存在即启动失败) |
| `ProcessBlackList` | 进程黑名单(Diverter 级) | stringlist / `` | 全局过滤:列表内进程的流量直接放行转发、不进任何监听器;与 ProcessWhiteList 同时配置会启动失败 |
| `HostBlackList` | 主机黑名单(Diverter 级) | stringlist / `` | 全局过滤:发往列表内 IPv4 的流量直接放行转发,不进监听器;逗号分隔 |
| `LinuxRestrictInterface` | Linux 限定的网卡名 | string / `Off` | Off 或网卡名(如 eth0);仅 MultiHost 生效 |
| `LinuxFlushIptables` | Linux 启动时清空 iptables | bool_yesno / `Yes` | 加入 FakeNet 规则前清空 iptables;正常退出时用 iptables-restore 恢复 |
| `LinuxFlushDNSCommand` | Linux 刷新 DNS 命令 | string / `service dns-clean restart` | Linux 修改 DNS 后执行的发行版相关刷新命令;如 service dns-clean restart |
| `ExternalAccessPolicy` | 出站策略总开关 | bool_policy / `Disabled` | 勾选后启用域名放行、私网接管、公网 IPv4 放行和进程重定向的统一出站策略,并自动补齐必需监听器；枚举=Disabled, EgressControl |
| `ExternalAllowedDomains` | 真实联网域名 | stringlist / `` | 需先手动勾选“启用真实域名联网”;英文逗号分隔;支持精确主机名与 *.example.com 通配(匹配其任意层级子域名,不含裸域本身);私网接管下同样支持多域名 |
| `ExternalAllowedTCPPorts` | 放行 TCP 端口 | portlist / `443` | 代码强制仅 443；策略固定=443 |
| `ExternalDnsServer` | 上游 DNS | string / `Auto` | Auto 或可用单播 IPv4;不能是本机地址 |
| `ExternalDnsTimeout` | 上游 DNS 超时(秒) | int / `3` | 查询上游 DNS 的等待时间;范围 1–30 秒；范围=1..30 |
| `ExternalVerifyTLSSNI` | TLS SNI 精确校验 | bool_yesno / `Yes` | 代码强制 Yes；策略固定=Yes |
| `ExternalRelayPort` | TLS 中继端口 | int / `38927` | 必须等于 DomainEgressRelay 监听器的 Port；范围=1..65535 |
| `ExternalTLSHelloTimeout` | TLS Hello 超时(秒) | int / `5` | 代码强制 5；范围=5..5；策略固定=5 |
| `ExternalTLSHelloMaxBytes` | TLS Hello 最大字节 | int / `65536` | 代码强制 65536；范围=65536..65536；策略固定=65536 |
| `ExternalMaxPendingFlows` | 最大挂起流 | int / `256` | 代码强制 256；范围=256..256；策略固定=256 |
| `ExternalMaxPendingPerSource` | 每源最大挂起流 | int / `32` | 代码强制 32；范围=32..32；策略固定=32 |
| `ExternalMaxActiveRelays` | 最大活动中继 | int / `128` | 代码强制 128；范围=128..128；策略固定=128 |
| `ExternalMaxActivePerSource` | 每源最大活动中继 | int / `16` | 代码强制 16；范围=16..16；策略固定=16 |
| `ExternalRelayIdleTimeout` | 中继空闲超时(秒) | int / `300` | 代码强制 300；范围=300..300；策略固定=300 |
| `ExternalRelayBufferBytes` | 中继缓冲字节 | int / `1048576` | 代码强制 1048576；范围=1048576..1048576；策略固定=1048576 |
| `ExternalNonAllowedAction` | 非放行流量动作 | enum / `Divert` | 接管模式下代码强制 Divert；枚举=Divert, Drop；条件锁=COND_TAKEOVER_ACTION |
| `ExternalBlockExternalIPv6` | 拒绝 IPv6 公网出站 | bool_yesno / `Yes` | 代码强制 Yes；策略固定=Yes |
| `ExternalBlockQUIC` | 拒绝 QUIC | bool_yesno / `Yes` | 代码强制 Yes；策略固定=Yes |
| `ExternalTakeoverIPv4` | 私网分析主机 IPv4 | ipv4 / `` | 其余域名的 A 查询将解析到此 RFC1918 单播地址;必须非本机且不等于上游 DNS |
| `ExternalTakeoverDnsTTL` | 接管 DNS TTL(秒) | int / `` | 接管模式返回 sink IPv4 时使用的 DNS TTL;启用接管时必填,范围 1–300；范围=1..300 |
| `ExternalTakeoverProbeTCPPorts` | 接管探测 TCP 端口 | portlist / `` | 可空;最多 64 个;只读探测 |
| `ExternalTakeoverProbeTimeoutMs` | 探测超时(毫秒) | int / `500` | 仅启用私网导向后写入;接管前只读 TCP 探测的单次超时;范围 100–5000 毫秒；范围=100..5000 |
| `ExternalAllowedIPv4Rules` | 公网 IPv4 放行规则 | stringlist / `` | 格式 协议/IPv4/端口,如 TCP/110.242.69.21/443;端口可用 *;最多 32 条、16 个 IP;存在但为空=配置错误 |
| `ExternalProcessRedirectEnabled` | 按程序与原 IP 重定向 | bool_yesno / `No` | 仅 Windows;fail-closed |
| `ExternalProcessRedirectProtocol` | 重定向协议 | enum / `TCP` | 代码强制 TCP；枚举=TCP；策略固定=TCP |
| `ExternalProcessRedirectImagePath` | 目标 PE 绝对路径 | path_file / `` | 绝对盘符路径;禁 UNC/ADS/通配 |
| `ExternalProcessRedirectImageSHA256` | PE SHA-256 | hex64 / `` | 64 位十六进制;须与实际文件一致 |
| `ExternalProcessRedirectOriginalIPv4` | 原公网 IPv4 (A) | ipv4 / `` | 全球单播 IPv4 |
| `ExternalProcessRedirectTargetIPv4` | 目标私网 IPv4 (B) | ipv4 / `192.168.204.1` | 可用 RFC1918;默认 192.168.204.1,仅在启用本功能后生效 |

### 监听器公共字段

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `Enabled` | 启用 | bool_truefalse / `True` | 是否创建此监听器;INI 使用 True/False,禁用段仍会原样保留 |
| `Port` | 端口 | portspec / `` | 单端口、逗号列表或区间(如 60000-60010,将展开为多实例) |
| `Protocol` | 协议 | enum / `TCP` | 监听与重定向使用的传输协议:TCP 或 UDP；枚举=TCP, UDP |
| `Listener` | 监听器类型 | enum / `` | 留空 = 匿名监听器(仅重定向,不启服务)；枚举=DNSListener, DomainEgressRelay, FTPListener, HTTPListener, IRCListener, POPListener, ProxyListener, RawListener, SMTPListener, TFTPListener |
| `Hidden` | 隐藏日志 | bool_truefalse / `False` | 仅认字面 True |
| `ProcessWhiteList` | 进程白名单 | stringlist / `` | 仅修改逗号列表内进程的流量,其他进程直接转发 |
| `ProcessBlackList` | 进程黑名单 | stringlist / `` | 逗号列表内进程的流量直接转发,其他进程按监听器规则处理 |
| `HostWhiteList` | 主机白名单 | stringlist / `` | 仅修改发往逗号列表内主机的流量,其他目标直接转发 |
| `HostBlackList` | 主机黑名单 | stringlist / `` | 发往逗号列表内主机的流量直接转发,其他目标按监听器规则处理 |
| `ExecuteCmd` | 首包执行命令 | text / `` | 占位符: {pid} {procname} {src_addr} {src_port} {dst_addr} {dst_port} |

### DNSListener

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `ResponseA` | A 记录应答 | ipv4_or_enum / `` | 字面 IPv4 或 GetFirstNonLoopback/GetHostByName;接管模式须等于接管 sink IPv4；枚举=GetFirstNonLoopback, GetHostByName |
| `ResponseMX` | MX 记录应答 | string / `mail.evil.com` | DNS MX 查询返回的邮件服务器主机名 |
| `ResponseTXT` | TXT 记录应答 | string / `FAKENET` | DNS TXT 查询返回的文本内容 |
| `NXDomains` | 前 N 次不答 A 查询 | int / `0` | 忽略最初 N 次 A 查询,让样本轮询备用 C2;0 表示不忽略 |
| `Timeout` | 连接超时(秒) | int / `5` | 仅 TCP DNS |
| `DNSResponse` | 已废弃键(代码不读取) | string / `` | 历史拼写残留(burp.ini);代码实际读取 ResponseA,仅为保真可编辑；dead：仅保留，运行不读取 |

### HTTPListener

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `UseSSL` | 启用 SSL | bool_yesno / `No` | 代码精确匹配字面 Yes |
| `Webroot` | Web 根目录 | path_dir / `defaultFiles/` | HTTP 静态文件与动态响应模块的根目录;相对路径按配置目录解析 |
| `Timeout` | 连接超时(秒) | int / `10` | HTTP TCP 连接的套接字超时时间,单位秒 |
| `DumpHTTPPosts` | 保存 HTTP POST | bool_yesno / `Yes` | 是否把收到的 HTTP POST 请求体保存到日志输出目录 |
| `DumpHTTPPostsFilePrefix` | POST 文件前缀 | string / `http` | 保存 HTTP POST 请求体时使用的文件名前缀 |
| `Custom` | 自定义响应 INI | path_file / `` | 自定义响应规则 INI 路径;相对路径按主配置目录解析 |
| `Version` | HTTP Server 头 | string / `FakeNet/1.3` | HTTP Server 响应头中报告的服务器版本字符串 |
| `Static_CA` | 使用用户 CA | bool_yesno / `No` | Yes 时使用 CA_Cert/CA_Key 签发动态站点证书;证书需预先加入信任库 |
| `CA_Cert` | CA 证书(PEM) | path_file / `` | Static_CA=Yes 时使用的 PEM CA 证书文件 |
| `CA_Key` | CA 私钥(PEM) | path_file / `` | Static_CA=Yes 时使用的 PEM CA 私钥文件;请妥善保护 |
| `cert_dir` | 动态证书目录 | path_dir / `configs/temp_certs` | 运行时生成的站点证书、私钥与 CRL 缓存目录 |

### FTPListener

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `UseSSL` | 启用 SSL | bool_yesno / `No` | 仅字面 Yes 启用 FTP TLS/SSL |
| `FTProot` | FTP 根目录 | path_dir / `defaultFiles/` | FTP 下载文件与上传落盘使用的根目录 |
| `PasvPorts` | 被动端口段 | portspec / `60000-60010` | FTP 被动模式数据连接使用的端口或区间 |
| `Banner` | 欢迎横幅 | string / `!generic` | 字面串或 !key(!generic/!random 等);支持 {servername} {tz};\n \t 按字面保真 |
| `ServerName` | 服务器名 | string / `localhost` | 字面串、!gethostname 或 !random |

### IRCListener

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `UseSSL` | 启用 SSL(代码未实现) | bool_yesno / `No` | IRC 监听器不读取此键,仅保真；dead：仅保留，运行不读取 |
| `Banner` | 欢迎横幅 | string / `!generic` | IRC BANNERS 仅 generic 与 debian-ircd-irc2 |
| `ServerName` | 服务器名 | string / `localhost` | 插入 IRC banner 的服务器名;支持字面值、!gethostname、!random |
| `Timeout` | 连接超时(秒) | int / `30` | IRC TCP 连接的套接字超时时间,单位秒 |

### RawListener

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `UseSSL` | 启用 SSL | bool_yesno / `No` | 仅字面 Yes 启用 RawListener TLS/SSL |
| `Timeout` | 连接超时(秒) | int / `10` | RawListener TCP 连接的套接字超时时间,单位秒 |
| `Custom` | 自定义响应 INI | path_file / `` | TCP/UDP 自定义响应规则 INI;相对路径按主配置目录解析 |

### SMTPListener

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `UseSSL` | 启用 SSL | bool_yesno / `No` | 仅字面 Yes 启用 SMTP TLS/SSL |
| `Banner` | 欢迎横幅(字面串) | string / `220 FakeNet SMTP Service Ready` | 不走 BANNERS 字典 |
| `Timeout` | 连接超时(秒) | int / `5` | SMTP TCP 连接的套接字超时时间,单位秒 |

### POPListener

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `UseSSL` | 启用 SSL | bool_yesno / `No` | 仅字面 Yes 启用 POP TLS/SSL |
| `Timeout` | 连接超时(秒) | int / `10` | POP TCP 连接的套接字超时时间,单位秒 |

### TFTPListener

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `TFTPRoot` | TFTP 根目录 | path_dir / `defaultFiles/` | TFTP 下载文件与上传落盘使用的根目录 |
| `TFTPFilePrefix` | 上传文件前缀 | string / `tftp` | 保存 TFTP 上传文件时使用的文件名前缀 |

### ProxyListener

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `Listeners` | 子监听器清单(仅文档) | stringlist / `` | 代码不读取此键:ProxyListener 嗅探全部运行中监听器；dead：仅保留，运行不读取 |
| `Static_CA` | 使用用户 CA | bool_yesno / `No` | Yes 时代理子监听器使用 CA_Cert/CA_Key 签发动态证书 |
| `CA_Cert` | CA 证书(PEM) | path_file / `` | Static_CA=Yes 时代理监听器使用的 PEM CA 证书 |
| `CA_Key` | CA 私钥(PEM) | path_file / `` | Static_CA=Yes 时代理监听器使用的 PEM CA 私钥 |

### DomainEgressRelay

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `Port` | 端口(须等于 ExternalRelayPort) | portspec / `38927` | 出站策略 TLS 中继监听端口;必须等于 Diverter.ExternalRelayPort |

### 自定义响应公共字段

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `InstanceName` | 匹配监听器实例段名 | string / `` | 与 ListenerType 二选一(至少其一) |
| `ListenerType` | 匹配监听器类型 | enum / `` | 与 InstanceName 二选一；枚举=HTTP, TCP, UDP |

### 自定义HTTP响应

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `HttpURIs` | 匹配 URI(后缀) | stringlist / `` | 与 HttpHosts 至少其一;两者都给取逻辑与 |
| `HttpHosts` | 匹配 Host | stringlist / `` | 支持 host:port |
| `HttpRawFile` | 响应体文件 | path_file / `` | 响应体三选一;支持 <RAW-DATE> |
| `HttpStaticString` | 响应体字符串 | text / `` | 三选一;\r\n 按字面保真;支持 <RAW-DATE> |
| `HttpDynamic` | 响应体动态模块 | path_file / `` | 三选一;py 模块须导出 HandleHttp |
| `ContentType` | Content-Type(仅配 HttpStaticString) | string / `` | 仅与 HttpStaticString 同用的 HTTP Content-Type 头;其他响应类型禁止配置 |

### 自定义Raw响应

| 字段 | 用途 | 类型 / GUI默认 | 限制与说明 |
| --- | --- | --- | --- |
| `TcpStaticString` | TCP 响应字符串 | text / `` | TCP 四种响应体之一;按原字符串发送 |
| `TcpStaticBase64` | TCP 响应 Base64 | text / `` | TCP 四种响应体之一;Base64 解码后按原始字节发送 |
| `TcpRawFile` | TCP 响应文件 | path_file / `` | TCP 四种响应体之一;发送配置根目录下文件的原始内容 |
| `TcpDynamic` | TCP 动态模块 | path_file / `` | TCP 四种响应体之一;加载 Python 模块并调用 HandleTcp |
| `UdpStaticString` | UDP 响应字符串 | text / `` | UDP 四种响应体之一;按原字符串发送 |
| `UdpStaticBase64` | UDP 响应 Base64 | text / `` | UDP 四种响应体之一;Base64 解码后按原始字节发送 |
| `UdpRawFile` | UDP 响应文件 | path_file / `` | UDP 四种响应体之一;发送配置根目录下文件的原始内容 |
| `UdpDynamic` | UDP 动态模块 | path_file / `` | 四选一(每协议);动态模块须导出 HandleTcp/HandleUdp |

## 11. 维护与事实边界

本文工具全集按当前源码注册函数提取：server.py的ping及tools.py的15项，共16项。功能描述核对README、配置样例、GUI schema与MCP实现；字段约束以实际核心解析为最终执行依据。新增工具、签名、返回字段或策略时应同步本文，并重新核对部署tools/list；不能只更新PLAN。

主要实现定位：`fakenet/mcp/{server,tools,coordination,configstore,errors,transportguard,config,artifacts,supervisor}.py`；配置目录`fakenet/configs`；GUI字段`fakenet/gui/schema.py`；协议监听器`fakenet/listeners`；核心策略`fakenet/diverters`。这些定位用于源码维护，正常调用所需合同已在本文列明。

本文件不授予任何VM写入、网络测试、删除文件或部署权限；按当前用户任务执行。功能存在、单元测试通过、构建成功和正式实机验收是不同事实；对运行限制与未通过项按实际证据报告，不把本文当成功证明。
