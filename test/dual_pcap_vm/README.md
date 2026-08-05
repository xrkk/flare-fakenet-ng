# Windows 双 PCAP v2 虚拟机验收

在已拍快照的 Windows 虚拟机中双击 `Run-Tests.cmd`。脚本不要求填写 DNS、路径或故障参数；若权限不足会触发一次 Windows UAC。正常运行阶段会持续显示 FakeNet-NG 明文日志，按 `Ctrl+C` 或 Enter 请求安全停止。

脚本离线校验并安装包内锁定依赖，执行单元/故障合同、100000 包正式性能门禁、真实 FakeNet-NG 双 PCAP 运行，以及 RAW 写、Ethernet 写、close 三种进程内故障注入。它不会下载依赖，不会压缩日志，也不会生成 `.sha256` 文件。

完成后请把本目录 `Logs` 下最新的整个明文目录复制回项目 `dist\Logs`。真实网络拦截只能在该虚拟机中运行，禁止在宿主机执行此脚本。
