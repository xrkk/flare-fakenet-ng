# Local egress fixture: implementation checkpoint

The optional observer remains fail closed. The host MCP still accepts only a
command_id, never starts the fixture, never asks for sudo, and never installs a
service. The default provider is unchanged when observer is absent.

The current code has offline coverage. It is **not a completed native fixture
release**: an exact ordinary-user lifecycle runner/configuration, actual nft
syntax/output compatibility, native normal/five-case acceptance and recovery
must be completed before approving or executing a network window. Do not use
the historical prepare/apply/serve commands; that incomplete implementation was
replaced. No root or network actions were used to develop this checkpoint.

## Interfaces

`tools/fakenet_egress_fixture.py plan --config <reviewed-v2-config>` is read only.
The root-only `run` owns one foreground window, one `/run/fakenet-egress-*`
directory, the table and the NAT pidfd. `recover` requires its original root
state and exact config. Mutation also requires `--confirm local-fixture-only`;
that flag does not grant user authorization. The frozen original deadline is
2026-10-20T19:29:33.527152+08:00 and is not extended by retries or recovery.
Choose an interpreter with real pidfd support; capability failure precedes
network changes. Do not use a different interpreter for MalTrace development.

The strict `fakenetng.local-fixture.config.v2` requires commands, target,
vmx_path, natd_pid/birth_ticks, window_start/end, runner and quiescence_checker.
Each ordinary script specifies fixed python/script/hash/args/uid/gid. Root
never imports project business code; subprocess UID/GID/groups and descriptors
are dropped before the ordinary interpreter reads that code. No arbitrary
command is accepted over the FIFO. The directory is supplied to the ordinary
runner as FAKENET_EGRESS_FIXTURE_DIR; the runner must bind a local host config
to it without weakening the original scope/hash/intent gates.

The host observer configuration has directory, producer_script and optional
bounded timeout_seconds. It trusts kernel UID 0, secure ancestors, live
PID/birth/boot/script, a finite lease, a fresh challenge and collection time.
Response facts include the complete nft ruleset, current process/NIC facts and
observer_identity. Policy is evaluated structurally. Normal counters, elements
and challenges are not policy changes. An expired/dead observer invalidates
current reuse and never restarts a probe.

## Guest and recovery boundaries

`tools/fakenet_egress_guest.ps1` defaults to a plan. Apply/Restore require an
explicit identity and state path on E or D, exact VM UUID/MAC/boot, and an
exclusive creation ledger. Only a new documentation-prefix IPv6 address and
the two test-target host routes are allowed. Preexisting items are refused;
restore requires the original ledger and checks exact current identities.

`tools/fakenet_egress_guest_control.py` runs as the ordinary user and performs
actual read-only process/service/route/engine queries. It does not terminate
processes, stop services or restore routes. The lifecycle runner must finish
those explicitly authorized owned actions first. Missing intent/completion,
a live/reused PID, changed service, guest entries or an active engine refuses
release. The root recovery controller retains the boundary on unknown state,
checks the same NAT birth/boot and table semantics, resumes that instance,
rechecks control, and deletes only its own table last. SIGKILL cannot rely on
finally: keep the root state and use the same identity-checked recovery entry.

A pass inside the window is historical after recovery; it does not authorize
sample execution on the restored network. The original 30 rows, eight checks,
50-second/64-KiB bounds and authorized=false remain mandatory. Native
PowerShell parse-only success is syntax evidence, not execution or driver
acceptance. No token/cost reduction percentage has been measured.

## Protected existing MCP endpoints

Connection specifications may use `bearer_token_env` or `auth_headers_env`
for Authorization/X-API-Key. These are environment variable names, never
credential literals. Missing/invalid references refuse IO; MCP protocol,
controller and Host headers cannot be replaced through this interface.
Both existing SDK versions use the public streamable HTTP transport with a
configured HTTP client; redirects and ambient proxy credentials are disabled.
No provider/agent/global MCP setting is modified. A 401 is an authentication
gap, not proof that a protocol downgrade or a new endpoint is needed.

The ordinary user's runner environment must explicitly contain the selected
reference. The root controller clears its environment on privilege drop, so
production credentials must not be copied into its config/state or displayed
in approval material. The current bootstrap needs the existing reference
location before authenticated native acceptance can be prepared.

A deployment may instead set `mcp_auth_ref` to the exact `path` and `server`
from its existing user-owned Codex TOML configuration. The ordinary process
bounded-reads that one regular file, verifies its owner/write permissions and
exact endpoint match, and resolves only authentication headers. The reference
is recorded, the header values are not. Protocol/controller headers cannot be
imported as authentication. This permits the root coordinator to clear its
environment: only the ordinary uid reads the existing user configuration.
No global MCP configuration is changed and no credential is copied into the
root state, approval document or tool result.
