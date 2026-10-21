# FakeNet 集中验收

本目录集中现有 Windows/Linux 核心、策略、GUI、PCAP、载荷报告、MCP、发布和辅助验收. 目标是修改产品或接口后, 能明确选择并执行同一份回归清单, 对照原始结果判断是否破坏已有功能. 当前是**盘点、统一入口与结果核对的第一阶段**, 尚未完成全部判据补齐或完整实机回归, 不得标为完整设施已验收.

`catalog.json` 是分组、验收内容、前置条件、原执行过程、结果判断、输出和已知缺口的唯一手工来源. `清单.md` 是程序派生阅读版. `tools/acceptance.py inventory --format json` 展开每个源文件的 SHA-256、测试函数/类、源码位置、断言及原生结果声明. 参数化测试仍以真正 runtime collection 为准, 静态条目数不是通过数.

## 使用顺序

以下命令从仓库根执行, `python` 替换为所在平台已有项目 Python.

```text
python tools/acceptance.py check
python tools/acceptance.py inventory --format markdown
python tools/acceptance.py inventory --output Logs/acceptance/<本次目录>/inventory.json
python tools/acceptance.py plan --output Logs/acceptance/<本次目录>/plan.json
```

以上均不连接 VM、不构建、不启停服务、不发送网络探针. 输出路径必须未占用; 生成计划保留 candidate 和 required_checks 未填写, 不把一个待填计划当作已取得执行或验收资格.

计划中的 candidate 填本次真实源/包/部署身份, 每组 required_checks 填原 collect 产生的精确测试 ID, 或经过核对的原生/人工逐项计划. 不从本轮实际结果倒推应验项. 先确定适用平台与完整范围, 缩减/定向回归必须标 selected, 不冒充全功能回归. 不能把源码声明数量直接当成运行节点数.

只有明确选择某个原执行入口时才使用 run:

```text
python tools/acceptance.py run --suite DOMAIN-IP --output Logs/acceptance/<本次目录>/execution
python tools/acceptance.py run --suite MCP-P02 --args-json <原CLI参数数组.json> --output Logs/acceptance/<本次目录>/execution
```

Windows 原生入口必须在 Windows VM 内运行, 原脚本的管理员/VM/清单/Sentinel/恢复约束继续生效. Linux 原生入口只在隔离 Linux VM 使用. MCP host-controller 入口复用现有通道和原CLI必填身份/材料, 不新建服务或改认证. 统一入口不自动部署、恢复快照、开启 IPv6、重跑旧任务或更换失败公网目标. 原始输出写磁盘, 不让 AI 逐步操作各字段. 本轮不处理新出口验证接口.

run 记录执行意图、源码哈希、stdout/stderr、原退出码及执行后源码漂移. 它不擅自给功能 pass, 不用新的超时强杀/重试覆盖原生 driver 的停止与恢复责任. 原 driver 继续保存自己的完整证据. 某些旧入口本身有强杀/快照回退等动作, 必须按分组原约束单独选择, 不隐式批量运行.

## 结果如何集中

每个分组一份 receipt, 引用本轮原始结果文件, 示例:

```json
{
  "suite_id": "DOMAIN-IP",
  "execution_id": "与计划完全相同",
  "candidate": {"source_commit": "本轮真实提交", "package_sha256": "本轮真实包身份"},
  "source_hashes": {"原源路径": "计划中相同完整SHA-256"},
  "evidence_level": "native",
  "returncode": 0,
  "cleanup_complete": true,
  "artifacts": [
    {"path": "/本轮原始/results.tsv", "sha256": "完整SHA-256", "format": "tsv"}
  ]
}
```

```text
python tools/acceptance.py judge --plan <plan.json> --result <receipt1.json> --result <receipt2.json> --output Logs/acceptance/<本次目录>/summary.json
```

当前解析器直接读取原 TSV 或 JUnit XML, 不相信 receipt 内手写的 checks/verdict. 已有两种 TSV 列顺序均支持. 其它原生 JSON/PCAP 必须沿原验证器判断; 它们的自动适配和完整来源闭包仍是待办, 不通过通用 `status=pass` 猜测. 原件哈希只证明读到相同字节, 不能独立证明来源声明或测试语义正确.

- 同一完整计划、候选、execution、当前测试源码和原件身份必须一致.
- required 检查缺项、重复、not_run、unknown、blocked、skip、OBSERVED 均不算通过.
- 任一真实失败, 即使不在 required 子集里, 仍保留为失败; 原脚本退出0不能覆盖.
- 非零退出或恢复未确认不能签通过.
- required 分组未齐全只得到 selected 或 not_run, 不给全功能通过.
- catalog 中判据尚不完整或尚未核准的分组使 `full_catalog_pass=false`. `existing` 表示原设施存在, 不是 `ready` 或已通过. 不得只改这个标记绕过待补工作.

目前 judge 是**原始结果与计划的一致性核对器**, 不是独立的网络包 oracle. 它不证明调用方手工填写的候选/恢复声明真实, 不自动给任何历史结果当前资格. 需继续接入原 runner 的真实身份/恢复记录与独立 PCAP 验证器, 才能完成统一实机总判定.

## 要补齐什么才算完整

1. 修原版 Listener HostWhitelist 错测及失败不反映退出码的问题; 对 SMTP SSL/Windows IRC 保留真实已知结果, 不静默排除.
2. 给域名出站负例补逐条实际发送、路径/五元组与线侧判定. 旧脚本已有 DoH/DoT 探针, 但 OBSERVED 不等于“阻断已验收”; 不再表述为“完全没有DoH测试”.
3. 为组合策略建立良性共同场景: 允许的真实域名、公网IP、私网 fake-c2 与不允许目标同时存在; 保留指定 EXE A->B 的独立覆盖, 不用 PowerShell 代替.
4. 逐个补 docs/testing.md 的手工功能的触发、正反期望、观测和恢复; 明确 Windows/Linux 实际适用性及现有单测复用. 不凭功能名声明全覆盖.
5. 统一 native JSON/原始 PCAP/GUI 等效与实测级别、候选/运行/恢复原件的适配和记录; 将手工填 receipt 改成对应原 runner 正常收尾产生.
6. 给良性载荷三方验证、Linux运行/部署/更新补统一原生适配. Windows/Linux分开执行并汇总, 不把 writer IPv6文件测试说成网络IPv6支持.
7. 实机运行受影响的必要组, 再汇总当前完整范围; 保留所有未测、失败、已知限制和历史. 不为集中目录重建未变产品、不重启旧100/150轮、不把它们当日常每次分析的前置.

上述尚未完成; 当前没有一次新的实机通过, 没有修改产品逻辑、VM或网络. 只有原设施 inventory/check 和集中核对器自身的离线测试可以单独报告通过.
