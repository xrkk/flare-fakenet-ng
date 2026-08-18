# Windows EgressControl VM test bundle

Run this package only inside a disposable Windows virtual machine with a
snapshot. The runner refuses to start FakeNet-NG unless Windows reports a
recognized virtual-machine manufacturer/model.

1. Extract the ZIP inside the VM to a local path, preferably on `C:`.
2. Ensure Python and the project dependencies are installed. The runner never
   downloads dependencies automatically.
3. Keep IPv6 enabled. Disable HTTP/HTTPS proxy settings and remove credentials,
   API keys, writable host shares and sensitive clipboard contents from the VM.
4. Double-click `Run-Tests.cmd` and accept the administrator prompt. The runner
   automatically selects the IPv4 DNS server from the connected interface with
   the preferred default route before FakeNet changes any network setting.
5. Wait for the test matrix and graceful cleanup to finish.
6. Return the generated plain-text directory `Logs\domain-allowlist-*` for
   analysis. The runner does not compress the logs.

The runner records DNS/IP state before and after, policy logs, stdout/stderr,
unit-test logs, all positive/negative command output, and an independent
`pktmon` PCAPNG. It uses no DeepSeek API key. HTTP status such as 401/403/404 is
acceptable for the positive connectivity test.

The runner never invents a public-DNS fallback. If the VM has no usable IPv4
DNS server on a connected default-route interface, it fails and leaves the
plain diagnostic log directory without starting FakeNet.

If the runner exits early, return the plain log directory anyway. Do not work around a
failure by disabling IPv6, using `curl -k` for the positive case, changing the
allowed domain, adding public-DNS fallback, or broadening firewall rules.

## Abnormal-stop recovery

The VM unit suite exercises the WinDivert receiver-exit watchdog and verifies
this order: suspend all policy permits, stop policy listeners, restore network
settings, then close the WinDivert handle. A hard process or VM termination
cannot run in-process cleanup. If that happens:

1. Disconnect the VM's virtual network adapter before any further activity.
2. Preserve the latest plain `Logs\domain-allowlist-*` directory.
3. Compare `dns-before.txt` and the current IPv4 DNS configuration.
4. If they differ, restore the disposable VM snapshot before reconnecting it.

Do not invent a DNS value or add a temporary outbound exception as recovery.
