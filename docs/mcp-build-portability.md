# MCP 构建资格边界 (Docker/Wine 门禁)

本文记录 FakeNet-NG MCP 正式 Docker/Wine 构建门禁的平台资格边界: 哪些验证在
该环境内真实执行, 哪些平台差异必须显式声明, 以及镜像依赖的固定身份。它面向
`./Build-FakeNetNgMcpPackage.sh` 产出的候选包验收, 不替代实机 Windows 验收。

## 构建镜像身份

- 基底镜像 `flare-fakenet-ng/gui-vm-diagnostic-builder:py3119-pyi6220`
  (内容 ID `sha256:1b33b518a7c71ecd13264f0d1c41faf254e301b8702e2da8ca11376cff700a5e`)
  在 Wine 上提供 Windows Python 3.11.9 + PyInstaller 6.22.0 + pytest 8.3.5。
- 增量门禁镜像 `...:py3119-pyi6220-mingit` 由 `./Build-GuiVmDiagnosticPackage.sh
  --image-mingit` 从上述基底增量构建: 校验安装 MinGit 2.47.1 并加入 Wine 系统
  PATH, 设置 `core.autocrlf=false`, 构建期以 Windows Python `subprocess` 调用
  原生 git 并对 `Z:` 盘临时仓库 `cat-file` 自检。正式构建经
  `BUILDER_IMAGE=...:py3119-pyi6220-mingit ./Build-FakeNetNgMcpPackage.sh ...`
  显式选择并在日志中记录实际镜像内容 ID。
- MinGit 分发件固定哈希: `MinGit-2.47.1-64-bit.zip` SHA-256
  `50b04b55425b5c465d076cdb184f63a0cd0f86f6ec8bb4d5860114a713d2c29a`,
  来源 `git-for-windows/git` 官方 release `v2.47.1.windows.1`。
- formal_runtime 验收测试通过真实 `git cat-file` 子进程读取原始字节; 宿主
  Unix git 不能替代 (Unix ELF 经 `CreateProcess` 以 `git.exe` 名义启动得
  `WinError 6`, 且不解析 `Z:\` 路径)。

## Wine 平台差异与门禁语义

- **autocrlf**: MinGit 默认 `core.autocrlf=true` 会把 LF 转 CRLF 入库, 使
  materials fixture 的工作树哈希与 pinned blob 不一致; 增量镜像设置系统级
  `core.autocrlf=false` 与 Unix git 行为对齐。
- **subprocess audit 参数形态**: Windows Python 在 `sys.audit('subprocess.Popen')`
  前已将 argv 列表经 `list2cmdline` 转为命令行字符串; formal_runtime 的独立
  审计 hook 对字符串按同函数渲染逐条匹配 git 白名单 (`audit.py`), 列表形式
  保持原比较。
- **symlink 负例**: Wine 可能无法创建真实符号链接, 或把 `os.symlink` 静默物化
  为副本。拒绝 symlink 的安全负例只在能真实创建链接 (创建后 `os.path.islink`
  为真) 的环境执行, 否则按 `symlink creation unavailable` 跳过
  (`test_build_identity.py`, `test_formal_runtime_preparation_receipt.py`,
  `test_formal_runtime_context.py`, `test_configstore_links.py` 同模式)。
  这些跳过是**原生 Windows 资格缺口**而非已验证的拒绝; 原生 Windows 验收仍需
  另行取得, 未取得时整体资格如实 PARTIAL。
- **IPC 失败假设**: 依赖"本机诊断 IPC 必然失败"触发 partial 路径的测试改为
  确定性注入 (真实 HTTP 工具路径中对 `list-artifacts` 子查询注入
  `DiagnosticError`), 不依赖平台特定行为 (`test_run_overview_query.py`)。
- **宿主 `ip` 路由检查**: formal_runtime DNS 捕获的 host-only 路由证据
  (`ip -j route get`) 属宿主 POSIX 协议, 测试路径中均以受控 stub 提供, 不在
  Wine 内声明为真实宿主证据。

## skip 台账合同

`tools/build_fakenetng_mcp_wine.py` 的 `WINE_ALLOWED_SKIPS` 是按测试节点
(nodeid) 的有限白名单: 门禁观察到的**每一个**跳过都必须在其中且附理由,
任何未知身份或未知理由的跳过使门禁失败, 不存在模块级整体放行。门禁结果保留
全部跳过的 nodeid、原始 pytest 消息与白名单理由。Wine symlink 三项的
`native Windows gap` 标注即上述原生资格缺口。场景原件类跳过
(`test_scenario_r02_regressions`, `test_scenario_suite` 个别用例) 依赖本
checkout 不存在的密封历史原件, 按原件可用性跳过并保持原断言。

门禁 PASS 仅表示已明确合同的 Wine 构建检查通过; 不据此声明整体发布资格,
原生缺口在候选验证材料中显式记录。

## 编码合同

配置解析优先 `utf-8-sig`, `UnicodeDecodeError` 后回退 locale 编码并重建 parser
(与 GUI 编码策略一致, 提交 `385e90e`)。中文 UTF-8 与旧 locale 配置都必须在
Windows Python 门禁中通过真实 HTTP 回执链验证 (`test_config_receipts_http.py`,
`test/test_config_encoding.py`), 不以 Linux 通过替代。

## 历史更正

2026-10-07 R02 期间 13 次 Docker 构建失败的直接原因是 `unzip` 解出的
`git.exe` 无 Unix 执行位而 `test -x` 恒败; 安装器 burn 日志的阶段差异造成了
"非确定失败"的误判。当时的完整实验证据归档于
`Logs/vmmalbox-build-20261006-924d0d5a/r02-experiment-evidence/`。

## 实机验收边界

本门禁通过不等于实机验收。WinDivert、Windows GUI/进程句柄行为、路由恢复、
端到端 Windows-to-Ubuntu 交付仍需真实 Windows VM 证据; Wine-only 结果不作为
上述运行时条件的替代。

## 2026-10-07 分层执行和凭证绑定

`LAYER=core SHARDS=0` 与分片入口均把确定的产品测试文件列表传给实际
Windows Python pytest。完整 `test_formal_runtime_*` 宿主证据编排回归转到
现有 `.venv-mcp-runners` 的 Linux Python；该层也执行构建门禁正反例。
Linux 专属 `test/test_linuxnetpolicy.py` 七项迁至同一 Linux host receipt：
其幂等证据查询实际调用宿主 `ip6tables`，Windows 无此命令；Linux 原断言
完整执行，产品和测试源码保持原样。测试文件和节点统一使用 POSIX 相对路径
绑定，使凭证逻辑在 Windows Python 自身的回归中也保持相同身份。
独立审计入口在激活写入守卫前完成标准库 `tempfile.gettempdir()` 初始化；
否则首次只读容量查询会先创建默认临时目录探测文件，被守卫拒绝，掩盖
真正的原始 verifier 拒绝。初始化后仍使用原守卫、原容量阈值和每次源
重校验，未放行审计作用域内的外部写入。
其余原全库用例全部留在 Wine，包括 GUI、diverter、SDK 真实 HTTP、配置
编码和路径、构建身份、服务边界及 HTTP listener 隔离组。它们的运行性质
仍由原测试决定：受控 VM/网络替身的通过不增加原生业务验收信用。

| 原门禁 | 本轮环境和证据 | 保留的断言及限制 |
| --- | --- | --- |
| 每个 `test_formal_runtime_*` 节点 | Linux host receipt 的收集清单、JUnit、原始日志 | 全部宿主编排、封存、篡改、独立子进程、恢复断言；VM/SCM 替身保持原性质 |
| Linux NetPolicy 七项 | Linux host receipt | 原始 Linux 防火墙策略/幂等证据断言，真实只读宿主命令；受控规则修改仍为替身 |
| formal context 源码绑定 | Wine sentinel receipt | 真实 Windows Python + MinGit 对 pinned blob 的读取、重校验、工作树篡改拒绝 |
| formal audit argv | Wine sentinel receipt | 列表和 Windows 命令行字符串匹配；真实 `sys.addaudithook` 放行 pinned git、拒绝未列举 git 子进程 |
| 原全库其余节点 | Wine main receipt，HTTP 独立 receipt | 产品相关断言与已知 skip 的精确节点和原因保留 |
| 冻结 EXE | package manifest 的 frozen_smoke、原始 smoke-exe 日志 | 实际冻结程序的协议、控制器、角色边界；不启动 FakeNet 引擎 |
| WinDivert、真实 symlink、SCM 安装/重启/恢复 | 后续原生 Windows `.149` 验收 | 本轮候选和资格凭证显式 PARTIAL，未取得原生信用 |

每组先真实 `--collect-only`，再执行同一选择；JUnit 必须与收集节点一一
对应。每次运行保存独立目录，旧 XML、失败包和合并目录均保留。
`gate-receipt.json` 绑定源 commit、镜像内容 ID、层、分片 index/count、
测试选择、全部收集节点、原始 XML/收集输出/日志 SHA-256。合并要求所有
分片恰好一次、HTTP 组恰好在 shard 0、core 的 Wine 哨兵和完整 Linux receipt
齐全，并重新核对 XML 的失败/错误及精确 skip 台账。任意 XML 拼合不产生资格。

`--package-only` 必须显式提供 `--qualification` 与
`--qualification-sha256`，并在任何 Wine 安装/冻结动作之前验证凭证。
验证重读全部 receipt 和原始证据，按归档源码重新推导测试文件选择，拒绝
缺片、重复、异 commit/镜像/层、修改的哈希、失败及未知 skip。凭证是本地
构建证据绑定，不是跨信任域签名；主控仍需审核证据来源。
包 manifest 保留 `build_gate=PASS` 与 `qualification_status=PARTIAL`、原生
缺口和各构建阶段真实用时。普通及分片 shell 入口都先取得绑定凭证再打包。

独立执行示例：`--host-only --layer core --builder-image-id sha256:...` 产生
Linux receipt；`--gate-only --layer core` 产生 Wine receipt；`--gate-merge`
需要显式 `--receipt`、`--host-receipt`、`--shard-count`、源 commit 和镜像
内容 ID，输出到全新 `--qualification` 文件。合并时工作树必须干净且 HEAD
等于指定源码；文档提交后已有固定源码候选无需重复技术验证。
