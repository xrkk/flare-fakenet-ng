# Windows private reviewed-IPv4 v12 VM acceptance

Run only inside the reviewed, snapshotted Windows VM. Double-click
`Run-Tests.cmd`; there are no DNS, IP, port, Python-package, or dependency
prompts. The runner elevates itself, uses the VM's existing default-route DNS
for the one reviewed real domain, creates a package-local virtual environment,
and installs only the hash-locked bundled wheels.

The runner refuses a machine that does not identify as a VM, Windows builds
other than `10.0.19045`, Python other than CPython `3.13.7` x64, an invalid
manifest, an altered package file, or a missing/ambiguous/gateway route to
`192.168.204.1`. It never downloads a dependency and never changes a route.

The automated matrix covers:

- all reviewed Python unit-test files;
- PowerShell launcher probe cases (open/refused/timeout/error/skip) and route
  preflight cases (unique on-link/default/gateway/missing/ambiguous/read-only);
- real `api.deepseek.com` DNS/TLS relay behavior;
- synthesized UDP/TCP A answers and AAAA NODATA for other domains;
- `dns.msftncsi.com` returning `192.168.204.1`;
- domain-derived and direct sink TCP/UDP traffic with original ports;
- two isolated reviewed-private-IPv4 profiles for `192.168.204.1`: TCP/UDP
  all ports and TCP/443 plus UDP/5000 exact ports;
- exact negative tuples on `192.168.204.1` and the unreviewed
  `192.168.204.2`, with zero matching outbound IPv4 packets required;
- reviewed-IP route/source snapshots, the fixed no-payload UDP/9 selection
  probe contract, and bounded `IP_ALLOW_*` audit events;
- a separate takeover regression profile proving the existing sink and
  DeepSeek relay without contributing reviewed-IP evidence;
- required/forbidden policy events, graceful stop, DNS snapshot comparison,
  and an independent `pktmon` PCAPNG.

The sink listener does not have to return a successful application response.
The evidence proves only that the VM sent matching traffic unchanged to the
reviewed sink and interface. It does not claim that a host listener handled the
traffic safely. Inbound return traffic is outside the new sink verdict.

Reviewed private-IP results use the same evidence rule: a successful FakeNet
send verdict and a matching packet in the independent physical-interface PCAP
prove egress authorization, not service availability. Negative matrix entries
must have zero matching physical-interface packets. Reviewed-IP fragments are
expected to be dropped, and all-port authorization applies to every VM process.

After the run, copy the newest directory under `Logs` back to
`dist\Logs` without compression. Preserve the `.pcapng` file alongside the
plain-text logs.
