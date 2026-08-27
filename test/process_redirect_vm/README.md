# Windows process-redirection VM acceptance

This directory is packaged only after a reviewer binds one target PE, its
SHA-256, one public IPv4 A, one on-link RFC1918 IPv4 B, and one FNPR/1 sentinel
port into the manifest. Run it only in the reviewed snapshotted Windows VM.
Double-click `Run-Tests.cmd`; the runner accepts no DNS, process, address, port,
dependency, fallback, or safety-bypass input.

Before DNS or WinDivert changes, it verifies every manifest file, refuses a
physical host or unexpected Windows/Python build, freezes A/B routes, binds the
B probe to the frozen VM source address, and requires an exact `FNPR/1` nonce
response. FakeNet does not start or manage that external sentinel.

The matrix uses two separately compiled native Windows PE clients. It checks a
target positive flow, a same-protocol non-target negative flow, 10,000 paced
new target connections, a synchronized 64-thread pressure burst, graceful
stop-flag shutdown, DNS restoration, structured owner/NAT evidence, and
independent pktmon proof
that target-process wire traffic reached B while no packet reached A. Pktmon
starts after the non-target compatibility check and captures NIC components only,
so the zero-A verdict cannot mix allowed non-target traffic or upper-stack
pre-rewrite snapshots into the target evidence window. Built-in PCAP files show
policy observation views (A then B, or B then A), not wire packet counts.
The 64-thread check requires at least one completed target flow plus an audited
owner-budget denial. TCP retries may legitimately let every connection finish
successfully after one or more initial SYNs were denied.

The 10,000-flow owner gate is intentionally sequential and starts no faster
than one connection every 40 ms. On the reviewed 4 GB VM it is expected to take
about 16-22 minutes and has a fixed 25-minute fail-closed timeout. The console
prints completed JSONL connection rows, percentage, elapsed time, and estimated
remaining time once per minute. Changing or wrapping local ephemeral port
numbers is normal Windows behavior and is not the progress indicator. The
runner also announces the later stop/capture-conversion/verification phase,
which commonly takes another 1-5 minutes depending on capture size.

After execution, copy the newest plain directory under package-root
the repository-root `Logs` directory to the review machine without compression. Include `wire.pcapng`,
`fakenet.log`, `fakenet.err.log`, the client
JSONL files, route/driver evidence, DNS snapshots, and `results.tsv`.
