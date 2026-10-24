## 目录

- [范围](#范围)
- [输入与两棵树](#输入与两棵树)
- [production 与 fixture](#production-与-fixture)
- [失败与恢复](#失败与恢复)
- [限制](#限制)

## 范围

`LINUX-DEPLOY-UPDATE` 由 `tools/acceptance_linux_runtime.py` 和
`tools/acceptance_linux_runtime_oracles.py` 驱动。正常路径调用原
`deploy/linux/deploy.sh` 内嵌的 `install()` 与
`deploy/linux/update-idle.py` 的 `update()`，不重写这两个产品的成功状态机。

## 输入与两棵树

`fresh_root` 是本轮新建的 fresh 目标，同时作为案例证据根；
`accepted_update_root` 是独立的已有 accepted S0048 根。二者必须非
symlink、非交叠，且 accepted 根的所有者必须符合原 update 的 OWNER 边界。
`install_package` 与 `update_package` 各自绑定 manifest SHA-256；缺少
任一树或包身份时在创建输出/服务副作用前拒绝。

## production 与 fixture

production 默认把 `run`、`idle`、`preflight`、`status` 和 OWNER 留给
原产品函数，不内置成功模型。测试 fixture 只通过 `run(..., os_boundary=...)`
提供进程、服务、凭据和 OWNER 边界，并显式标记 fixture；fixture 结果不能
取得 native/full 信用。

## 失败与恢复

oracle 直接读取原始 transaction receipt、backup、token inode/mode、源文件
和无关文件的前后状态。原 updater 没有自动 rollback：start 失败后仍保留
`phase=failed` receipt 和已发布状态；只有从本轮原 receipt 指向的 backup
实际恢复原 bytes/mode、并记录服务后态时，才报 `rollback` 的受控恢复证据。
缺少原件、路径逃逸或自报 summary 不得通过。

## 限制

本轮只验证源码/受控文件与 OS 边界 fixture。真实 Linux VM、root 安装、
systemd、网络/DNS、driver/服务和完整 62 required/9 IMP/14 ACC 仍未验证。
