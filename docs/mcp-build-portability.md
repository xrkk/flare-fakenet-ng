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
