# Windows public reviewed-IPv4 v14 VM acceptance

Run only inside the reviewed, snapshotted Windows VM. Double-click
`Run-Tests.cmd`; there are no DNS, IP, port, sample, Python-package, or
dependency prompts. The runner elevates itself, uses the VM's existing
default-route DNS, creates a package-local virtual environment, and installs
only the hash-locked bundled wheels.

The runner refuses a physical host, an unexpected Windows/Python build, an
altered package, a DNS result that no longer contains `110.242.69.21`, or a
missing/ambiguous route. It never downloads a dependency, changes a route, or
selects an alternate IP/DNS server.

The automated matrix covers:

- the single reviewed rule `TCP/110.242.69.21/443`;
- a positive TLS connection fixed to that IP with SNI `www.baidu.com`, system
  certificate-chain validation, the reviewed allow event, and physical PCAPNG;
- zero matching physical IPv4 packets for TCP/80, TCP/444, UDP/443, and the
  unreviewed current Baidu address `110.242.70.57:443`;
- public default/gateway/on-link best-route acceptance and fail-closed route
  query/refresh behavior;
- all reviewed Python and PowerShell contract tests;
- a separate takeover regression for `192.168.204.1` and the existing
  `api.deepseek.com` DNS/TCP-443/exact-SNI relay;
- graceful stop, log drain, DNS/IP/route restoration, and independent pktmon
  capture conversion and automatic tuple counting.

The IP rule is network-layer authorization for every VM process. Runtime SNI
is not restricted by this rule; SNI and certificate checks in the runner prove
only that the pinned address still serves `www.baidu.com`. The pinned address
may rotate because its DNS TTL is short. A missing address or failed TLS check
stops acceptance; no second address is used as fallback.

After the run, copy the newest directory under `Logs` back to `dist\Logs`
without compression. Preserve the `.pcapng` file alongside the plain-text
logs.
