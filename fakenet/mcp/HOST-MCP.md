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
- The Windows PowerShell probe is a fixed v2 template with a pinned template
  hash, explicit IPv4/IPv6 sockets, per-step nonce/transaction/status checks,
  a separate positive and an instance PID/creation/script identity. It records
  the real Windows identity/firewall and runs the fixed 30-row TEST-NET matrix
  only after the positive and a complete independent host boundary. The
  identity preflight and final consistency read disable the positive; only the
  one matrix process sends the positive, and its PID/creation/source IP/port/
  protocol/full tuple/window/nonce are used for producer matching. The
  DIVERT_FAKE probe event is emitted only after a successful send and only
  when the fixed benign marker is present. It does not start a sample. The
  guest FakeNet tool returns only its observable subset; host-only checks
  remain unknown unless the host provider proves them.
- NAT with unreadable host firewall/NAT rules is an honest `unknown`, not a
  pass. TEST-NET timeouts are not egress-block evidence. A normal pass needs a
  readable independent boundary (or a pure host-only/no-forwarding deployment
  with all NICs, both families, per-interface forwarding and route facts) plus
  all 30 matrix rows, the separate sample-context positive, a real guest
  producer tuple match, and a stable final host/guest/VM/config re-read.
  Missing/unknown/not_run rows or an unreviewed final check never produce a
  pass, even if the eight helper checks are otherwise complete.

## Output and evidence

Host raw evidence is written under the configured `output_root`; guest raw
evidence stays in the FakeNet run lifecycle. The returned result carries
path/SHA-256 references; no raw credentials, tokens or sample bytes are
returned. The guest evidence transfer remains a separate authorized VM
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
