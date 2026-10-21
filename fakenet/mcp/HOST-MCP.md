# fakenetng-host-mcp (host stdio facade)

`fakenetng-host-mcp` is the single AI-facing entry for the egress isolation
verification capability. It is a stdio MCP server; it does not open a TCP
listener, daemon, reverse callback or HTTP endpoint. The existing Windows
`fakenetng-mcp` service and its tools remain unchanged.

## Launch

Use the console script installed with the fakeNet package:

```text
fakenetng-host-mcp --config /absolute/path/to/host-config.json
```

The MCP client owns the process lifetime. The config path is fixed by the
launcher; the AI-facing tool accepts only a canonical `command_id`.

## Tool

`verify_egress_isolation(command_id)` returns one typed `VerificationResult`:
lifecycle, verdict, bindings, every planned step, the eight checks, helper
input, coverage, manifest/hash, invalidation conditions and `authorized=false`.
A retry with the same command_id and fixed configuration reconciles the
original ledger record; it does not start a second probe sequence. A different
configuration/scope is rejected.

## Fixed inputs and trust boundary

- The config declares the FakeNet endpoint/controller, Windows-MCP endpoint,
  Velo control tool, VMX path/UUID/computer, guest IP, VMware network files,
  sample launcher context, probe authorization source/hash/scope, fixed
  control ports and output/state roots.
- `probe_authorization.authorized` must be true and the source file SHA-256
  must match. The source is a versioned operator-controlled JSON scope
  (`fakenetng.probe-scope.v1`), not a free-text approval. The facade validates
  its schema/version, VM/VMX/guest/config/path/tool coverage, control ports,
  probe destinations/script, budget, valid time window and `revoked:false`;
  it re-reads the scope before active actions and at the final consistency
  check. A correct hash or a caller-supplied boolean is not a trust root.
  `probe-scope.example.json` ships withheld/revoked on purpose.
- The sample context must contain real launcher path/SHA-256, account/SID/
  session, token integrity level and protocol class. The probe reads its own
  token IL. FakeNet global/listener `ProcessWhiteList`/`ProcessBlackList`
  rules from the live config are parsed; sample and probe must be covered by
  the same rules. No process rule means both are captured. AppLocker is an
  optional additional fact, not a normal dependency and not a substitute for
  FakeNet process rules. The sample and probe binaries need not have the same
  image hash.
- The AI cannot pass a URL, shell, executable, arbitrary path, nonce, matrix,
  port list, host evidence or `isolated=true`.
- The Windows PowerShell payload is transported as one gzip-compressed UTF-8
  in-memory base64 value. The fixed wrapper decompresses it in PowerShell
  memory, verifies the original UTF-8 SHA-256, then uses the original
  `ScriptBlock`; it creates no file, daemon or extra tool round trip. The
  wrapper rejects an oversized command before constructing a client. This is
  an internal transport detail, not a public MCP argument.
- The Windows PowerShell probe is a fixed v3 profile template with a pinned template
  hash, explicit IPv4/IPv6 sockets, per-step nonce/transaction/status checks,
  a separate positive and an instance PID/creation/script identity. It records
  the real Windows identity/firewall and runs the fixed 30-row TEST-NET matrix
  after the positive under the already-approved probe scope. NAT, bridging,
  forwarding or a missing second blocker do not skip the matrix. The
  identity preflight and final consistency read disable the positive; only the
  one matrix process sends the positive, and its PID/creation/source IP/port/
  protocol/full tuple/window/nonce are used for producer matching. The
  DIVERT_FAKE probe event is emitted only after a successful send and only
  when the fixed benign marker is present. It does not start a sample. The
  guest FakeNet tool returns only its observable subset; host-only checks
  remain unknown unless the host provider proves them.
- Qualification contract version 3 uses `running_egress_contained` in place of
  `independent_egress_blocked`. Both the host config policy and finite scope
  explicitly declare `qualification_profile: ipv4-v1`. Historical contract 2
  evidence is not a current proof. The running check is named
  `running_egress_contained`. Old results cannot be replayed as this contract.
  FakeNet stopped permits normal connectivity; running must intercept/contain
  the declared traffic; stopping must restore connectivity. No permanent
  independent blocker, NAT suspension, host-only conversion or extra firewall
  is a prerequisite or a substitute for FakeNet.
- A normal pass retains all 30 rows, requires the fixed 15 IPv4 rows to pass,
  and requires a strict IPv6 scope guard derived from complete OS facts. Only
  an OS-confirmed loopback-only IPv6 stack qualifies; link-local/on-link
  configurations remain unknown, without automatically changing IPv6. The
  IPv6 diagnostic rows retain their actual outcomes and any leak fails.
  A pass also needs a real nonce/producer positive and stable
  final facts, plus a complete passive VM-edge observation. UDP/DNS require
  the actual Send return; TCP blocked rows require a concrete routed source,
  a real asynchronous connect attempt and timed wait, not a local error.
  An observed outbound matrix packet fails even if a later host rule drops it.
  ICMP emission without sufficient proof stays unknown; it is not silently
  removed from the matrix. Missing IPv6 or unsupported topology stays unknown.
- `passive_observation.enabled` additionally requires `passive_observe` in the
  pinned scope. The bounded `/usr/bin/dumpcap` child never installs or elevates
  permissions, changes network policy or creates a daemon. It only supports a
  single mapped VMware NIC initially, with Ethernet pcapng, complete drop
  statistics and a post-probe control heartbeat. A fresh, hash-checked stopped
  calibration must prove visibility of each required IPv4 next-hop path.
  Per-family diagnostic facts do not bypass common capture completeness.
  A heartbeat alone cannot prove visibility. Missing capability returns an
  explicit unknown while already-authorized benign matrix probes still run.
  Default capture remains non-promiscuous (`-p`). A deployment may explicitly
  opt in with `passive_observation.promiscuous: true` only when the finite
  pinned scope also contains `passive_capture` with `mode: process-promiscuous`,
  the snapshot's exact `vm_uuid`, `mac`, `interface`, and `dumpcap_sha256`.
  This requests reception through the owned capture process, never `ip link`
  or a global mode reset. It keeps the VM-only BPF and 35-second/4-MiB limits,
  waits two seconds after readiness, drains for up to three seconds before
  closing, and records interface flags/promiscuity before, during and after.
  An unconfirmed mode or restoration cannot qualify any family. Capture mode
  and timing are part of the calibration identity; recalibrate after changing
  them. Concurrent interface changes are reported; the verifier never undoes
  another process's settings.
- Deployment acceptance is separate from each running MCP call. The operator
  helper `tools/verify_egress_lifecycle.py` records stopped `before`/`after`
  connectivity to the same explicitly authorized public IP/port, generates
  `calibrate` evidence with two fixed TEST-NET UDP nonce probes, and evaluates
  all phases using the real running MCP result. `lifecycle_connectivity` and
  `visibility_calibration` are separate scope actions; the public endpoint and
  connectivity template hash must be explicitly covered. The helper never
  starts/stops FakeNet. Use existing lifecycle tools and reconcile their IDs.
  TEST-NET calibration is not public-connectivity evidence. Calibration is
  valid for at most one hour and invalidates on relevant context/network change.
- The old local nft/NAT-stop fixture is historical recovery material only.
  No normal verifier path requires it. The old guest subset remains accepted
  for health/filter/producer facts only; it cannot supply the host contract-v3
  passive check. Host probe/merge corrections do not require deploying another
  guest binary. The installed guest build identity must still be reported.

Validate the actual analysis configuration after configuration preparation.
Read its name/hash and compare them with the engine's loaded config identity
before calling the verifier. Each changed configuration, run, sample context
or scope requires its own verification intent. A dedicated EgressControl test
profile does not prove another configuration. Reusing the same command ID
rechecks current facts, calibration lifetime and originals, probe template and
capture binary; it does not rerun the matrix or guest verification. These
checks do not require repeating deployment acceptance for every sample.

## Output and evidence

Host raw evidence is written under the configured `output_root`; guest raw
evidence stays in the FakeNet run lifecycle. The returned result carries
path/SHA-256 references; no raw credentials, tokens or sample bytes are
returned. When native provenance exceeds the compact budget, repeated step
references use `{"id": "evidence-N"}` pointing to one manifest entry with the
exact path and SHA-256. Step identities, expectations, outcomes, reasons,
times, qualification inputs and the actual fail/unknown verdict remain in
line. Large observations retain a hash-checked unabridged JSON pointer.
The guest evidence transfer remains a separate authorized VM
transfer; this facade adds no transport service.

## Offline tests

Run with the FakeNet test environment:

```text
.venv-mcp-runners/bin/python -m pytest test/mcp/test_egress_contract.py \
  test/mcp/test_egress_verification.py test/mcp/test_host_provider.py \
  test/mcp/test_host_stdio.py -q
```

The host stdio tool test uses a local fake facade and exits without a VM or
network. The real Windows/WinDivert acceptance is a separate dedicated-VM
runner and is not claimed by these tests.
