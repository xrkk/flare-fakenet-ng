## 目录

- [范围](#范围)
- [远程 SingleHost](#远程-singlehost)
- [独立 MultiHost](#独立-multihost)
- [身份与恢复](#身份与恢复)
- [信用边界](#信用边界)

## 范围

`LINUX-SINGLEHOST` 的 composite 入口位于
`tools/acceptance_linux_composite.py`。Host controller 不直接启动本地
LinuxRunner；它通过既有 `ExistingRemnuxChannel` 和原
`acceptance_orchestration.run_linux` 在绑定的 server 上执行原
`acceptance_guest.py`/`acceptance_linux_runtime` SingleHost，然后调用原
`run_multihost` 的 server/client 直接链。

## 远程 SingleHost

SingleHost 使用显式 `singlehost.target`、配置、配置哈希和 probe，并绑定
到原 REMnux server runtime。它的原 start/health/UDP 双向 PCAP/stop、
原 guest request/case/catalog/source pins 和原 oracle 保持只读。只有
SingleHost 原始五检查中的 singlehost、nfqueue、ipv6-block、restore 及
实际 stop/网络恢复通过，且 producer 退出明确后，才允许进入 MultiHost；
预期缺失的 multihost 不能通过本阶段，也不能由布尔字段补证。

## 独立 MultiHost

MultiHost 使用原 `General`/`No Redirect` 配置、两个不同原生身份/VM UUID、
原 server birth/owner、fresh Observe、client 原 probe、after Observe、Stop
和两端退出/网络恢复原件。组合 oracle 调用原 MultiHost evaluator，只有原
callback 集合和两端恢复全部通过才把 `multihost` 记为 pass。

## 身份与恢复

输入和候选必须精确绑定 SingleHost/server/client 三角色；SingleHost 与
server 可为同一目标，但 client 必须独立；缺任一角色、重复目标或 UUID
不符在创建 owned 输出/远程动作前拒绝。非组合 deployment 保持原严格
`candidate.deployed_identity == expected_target` 校验，不再接受单 server
弱化。失败/未知只保留原请求、原件和恢复入口，不重放远程 mutation。

## 信用边界

真实 VM/root/systemd、外部网络/DNS、真实 SDK MultiHost 和完整
62/9/14 native/full 仍需另行验收；本轮源码 fixture 不等于 native。
