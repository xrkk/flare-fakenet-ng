# Formal runtime materials

`context.load_context(materials_json, materials_sha256, repository_root=...)`
reads explicitly pinned `fakenetng.formal-runtime.materials.v1` inputs. The
expected SHA-256 is supplied independently by the caller. Loading creates no
output and grants no business, instance-admission, recovery, or pass authority.

The top-level fields are `schema`, `candidate_identity`, `tool_source`,
`suite_argv`, `plan`, `credited_selection`, `spike_source`, `source_indices`,
`evidence_root`, `audit_root`, `physical_namespace`, `resource_plan`, and
`protected_sources`. File records contain exactly absolute `path`, integer
`size`, and lowercase `sha256`. Both suite argv records use the existing formal
batch argv schema. The plan's identity, root, and physical namespace must agree
with the material and argv bindings.

Product identity remains the original six-field candidate identity. Tool source
is a separate `{commit, files}` binding: each listed dependency must match both
its file fingerprint and the blob in that Git commit, under `test/mcp` of the
explicit source root. The eventual entry must also verify completeness of its
actual dependency set; an arbitrary list of valid files is insufficient.

Paths must be absolute without aliases or symlink components. Business and
audit outputs must be separate children of repository `Logs/`, disjoint from
inputs, protected sources, and tool source. Contexts recursively freeze their
inputs and can `revalidate()` before an action.

This module is the input-binding component. Full offline preparation, resource
admission, trusted historical selections, original package checks, orchestration,
and independent source auditing are subsequent components; this module alone
does not validate those conditions or constitute a runnable acceptance entry.

`runner.check_preparation_inputs(context)` checks the original P2 local identity
gate, actual 199-member archive, original deterministic 100-row manifest,
indexed/protected selected-source metadata, exact remaining one-to-five-row
batches, and fresh host/tmp capacity. Its plan needs explicit `candidate_files`
records named `manifest`, `verification`, `deployment`, and `archive`, plus the
`original_manifest` record and original batch policy. No archive name is inferred.
The returned input report explicitly grants no business authority. Metadata
checks are followed by independent original raw-source/Spike adjudication and
the configuration/instance gates when the full runner is assembled.

`command_transport.StageFileVm(client, context, responsibility)` keeps short
commands on the original client and stages long commands under the explicit
physical namespace. The caller supplies `refuse()` and `unknown(error)` for its
current mutation responsibility; a loaded context alone grants no mutation
authority. Staging retains the original 32767 UTF16-unit projection, 2048-unit
wrapper reserve, 1024-byte chunks and 4 MiB script limit. All calls share the
original deadline, and exact UTF8-BOM script bytes are SHA-verified before
dot-sourcing in the original remote executor. File-location automatic variables
are refused for staged scripts. Unknown results retain a command fingerprint
under the current output root and cannot be replayed by a new adapter there.
This is an offline-verified component; full runner, source-export, instance and
Windows acceptance gates remain necessary.

`source.resolve_source(context, protected_source_root)` reads the explicitly
pinned source index, frozen original execution, and actual capture/ETW witness
bytes. Historical driver files are only fingerprinted data. The returned
immutable `SourceBinding` preserves the original namespace, nonce and run-01
producer even when the new context has a different output namespace. Set this
binding as the original Suite's `physical_source_binding` before reading that
source. Suite transfer and export inventory share `source.transfer_limit`;
ordinary 192 MiB, owned shared text 512 MiB, and original E-root auxiliary ZIP
256 MiB budgets remain separate. An incorrect owner or namespace is refused.
The source-read/classification component does not run an independent raw-proof
audit or grant existing pass credit.

`source.export_source(suite, context, protected_source_root, destination)` uses
a fresh child of the context's output root. It requires the original exact
capture/ETW stopped gate, derives native UUIDs only from indexed run responses
or exact supervisor PID/FILETIME lineage, checks all required files and the
original 4 GiB total export budget, copies via Suite's original transfer method,
and compares complete pre/post size and double-SHA inventories. Read commands
are bounded to 30 seconds and never fall back to remote script staging. A
failure retains its raw inventory, partial copies and terminal; existing output
is never retried. The original Suite client and source binding are restored on
every terminal path. These environment-boundary tests provide component
coverage; actual guest export and independent original-proof adjudication
remain separate acceptance gates.

`config_ownership.prestart_gate(suite, context)` keeps the original Suite's
planned names and default restoration. It compares the product list against a
complete native physical inventory before wrapping the service; conflicts are
retained and never pruned. `ConfigOwnedService` records only successful changed
mutations with exact request names and UTF8-byte hashes. Identical edits retain
existing ownership. Builtins and other executions' files cannot be edited or
cleaned. An unknown response, inflight mutation, or failed local audit prevents
further writes while preserving read access and the actual known response.
Tests exercise the actual ConfigStore through the RPC boundary; they grant no
new Windows instance admission or formal scene credit.

`dns_evidence.bind_dns_native(pcap, run_log, native_records, probe, run_id, p4,
source=guest_address)` retains the original same-capture UDP request/answer,
CNAME/A TTL, stopped-run lease/redirect/SNI/native mapping checks. It reads
explicit original bytes and preserves byte offsets; the P4 route IP is not a
runtime lease. `selected_p7_command` returns the registered original command
unchanged and requires its PowerShell probe in the independently pinned tool
dependencies. Fixed remote-IP/resolve substitutions are refused. The binding
is supplementary evidence and cannot replace formal traffic/fault oracles.
Live capture, closed-run export and complete runner integration remain separate
implementation and Windows acceptance steps.

`instance.FirstSpikeInstanceGate(context, responsibility)` runs the original
current-SCM identity/environment, native-six original transfers and checks,
then the original Suite P1-P7 preflight. Each PID/FILETIME is admitted once;
the candidate manifest and default SHA come from the pinned context. It does
not enable business by itself. `ProtectedService` refuses unadmitted business
and unresolved mutation replay; `ProtectedVm` preserves the original single
SCM command and reconciles only its exact completed receipt. A transaction
completion always invalidates instance admission.

`instance.bind_namespace(suite, context)` maps the original E-root producer
before capture creation and binds the transfer budget only after its original
validated response. `recovery.bind_recovery` keeps the original snapshot and
cooperative stop validators, granting only exact capture recovery while general
responsibility remains unknown. Exact recovery writes an immutable command
intent and cannot replay it through a new adapter. Controlled native-six bytes,
the actual original P1-P7 methods and real ConfigStore lifecycle are exercised
offline; SCM cycle orchestration, live DNS capture/export and full Windows
acceptance remain necessary.

`coordinator.Coordinator(...).installed()` scopes the original Suite/Batch SCM,
fault-instance profile freeze, precise fault restoration and continuation
seams to one context. Each completed original SCM command revokes admission;
only that new instance's original native-six and P1-P7 gate enables business.
Fresh host/tmp and original C/E floors, complete candidate members and exact
PID/FILETIME are checked. The original Batch stops after its first nonpass;
unknown SCM is not replayed or blindly restored. All seams are revoked on exit.

`dns_capture.Captures(...).probe_hooks()` scopes capture to the actual original
P7 command after its healthy start. Host-only routing is required; dumpcap is
bounded to exact-domain UDP DNS, 180 seconds and 16 MiB. Owned host writers
must exit before closed-run export and original DNS/native binding. Failures
retain originals, unresolved writer handles and the primary exception even
when terminal cleanup/audit fails. An absent original stopped/owner-free status
cannot be recorded as a closed managed capture. These composed tests exercise
the actual original SCM bodies, native/preflight, copy, ConfigStore and Batch
functions with environment boundaries controlled. They grant no real Windows
credit; the full formal entry, independent source audit and final prepare are
still pending.

`source.export_closed_run(suite, context, run_id, original_P7_cleanup, output)`
reads the exact UUID's original artifact/native/recovery directories only after
the original P7 cleanup reaches default, stopped and owner-free. It preserves
the original Suite byte-copy path and ordinary/total budgets, requires run-log
and relay-native originals, and compares complete pre/post size and double-SHA
inventories. Its bounded read adapter never stages or mutates guest files;
failures retain partial copies and revoke the adapter without retry. This
current-run path does not extend historical source-index authority.

`audit.Mapper(context, authority_path, independent_authority_sha256)` accepts
only a source-index-authorized independent view and the pinned credited or
Spike selection. Actual selected result, attempt, nonce, candidate, run and
parser dependency keys are checked against the source bytes. Copies must have
independent inodes. Projection changes only `inputs_before/after` keys;
all values and every other proof field stay intact, including incomplete status.
`installed(output)` temporarily wraps the actual original derive, records raw
and projected proofs, confines writes and temporary files to the audit root,
refuses source fallback during derive, and restores the original on every exit.
Import installs no hook. Scoped auditing permits only the exact pinned read-only
Git blob subprocesses needed for context revalidation and denies network and
business subprocesses. Minimal source-copy construction, independent CLI and
actual old-five/Spike proof rebuilding remain separate pending steps.

`audit_view.plan_view(context, scope)` inventories only the exact indexed
selected attempts, results, canonical manifest and (for Spike) original report.
Every relative nested result/report reference must match that source graph;
unindexed temporary files stay untouched in the source and are not copied.
`build_view` requires unused audit output, the original fresh host/tmp floors
plus measured copy bytes and the frozen derivation reserve. It copies actual
bytes to independent inodes, checks pre/post source and target SHA, freezes a
validated Mapper authority, and retains partial files and terminal on failure.
Unclosed transport writers prevent authority publication. A completed copy
grants no proof or formal-scene credit. Independent entry and actual original
five/Spike rejudging are still required.

`run_formal_source_audit.py --materials-json ABS --materials-sha256 SHA
--selection-json ABS [--scope credited-selection|spike-only]` is the separate
audit CLI. It qualifies its static local import closure, three original
file-loaded audit scripts and actual module paths against the pinned Git tool
commit. Product helpers must match the separate candidate source commit.
Code from Logs, unpinned dependencies, network and business subprocesses are
refused. The credited selection must be the pinned selection file; Spike
selection must exactly match the indexed original report.

The CLI builds a fresh independent view, calls original verify and each
selected replay, then original summary; missing unselected coverage is kept
explicit and the full-100 gate stays false until complete. Spike uses the
original complete five-class gate in a distinct matrix root. Raw verdicts,
proofs, provenance and failed terminal paths are retained. CLI help/import
start no audit or output. Separate-interpreter regressions preserve real
original verify/Spike failures. Actual historical five/Spike rejudging through
this CLI remains blocked until its fresh capacity gate is satisfied.

`clients.FreshClient(original_client, context, responsibility)` creates an
original MCP session for each call, retaining the same controller and the
earliest original absolute deadline across initialization and tool dispatch.
Original status and mutation timeout caps remain 30 and 480 seconds.
Each actual bounded transport child supplies its own completion evidence;
missing or unreadable completion never counts as a terminated writer.
Terminal audit failures block subsequent mutations but preserve a received
original response, allowing configuration ownership to retain its exact SHA.
Unknown calls are never replayed. This transport component grants no business
admission and still requires wiring into the complete single-batch entry.

`producer.register_execution(context)` records the explicit material SHA,
separate tool commit and candidate, original output and frozen physical nonce
and scope. Its namespace scope must match the original output's SHA prefix;
the record is write-once and grants no admission or sealed source authority.
`ProtectedVm.journal` pairs each exact mapped final command with its actual
short or staged response and terminal. Unknown capture/ETW intents stay visible;
SCM receipt reconciliation has a separate actual read response. Local witness
failure retains known responses in memory and blocks subsequent mutations,
including after a completed SCM receipt. Successful payloads and large command
texts remain in evidence files rather than accumulating in the memory ledger.
Current-source reading/export and independent sealed-index qualification still
remain necessary before this identity record can support a full batch.

`source.resolve_source` also accepts an independently indexed versioned
execution binding. `producer_source` checks its original material/plan SHA,
candidate, nonce and output scope, then checks the historical producer's
dependency blobs against its own immutable Git commit as data. Later consumer
worktree changes do not redefine the original producer. Historical code is
never imported. The shared capture parser retains original owner/namespace,
PID/creation and ordinary/shared transfer rules. Each known response must match
its paired intent and indexed terminal fingerprint; known ETW responses must
match the exact session intent. Unknown ETW stays in the closure query, and an
unresolved capture start prevents export until exact recovery is established.
This sealed historical path does not grant current-run source authority.

`current_source.resolve_current(context, protected_vm, service_fresh_client)`
hands off only the actual same-context VM journal and Fresh transports. Their
terminal and bounded-completion bytes are re-read, and disk dispatches must
exactly match the in-memory owner ledger. Active or unresolved host writers,
caller-supplied stopped flags and changed witnesses are refused. The metadata
snapshot checks every read and never admits later files. It has no historical
source index and grants neither business admission nor guest business-writer
closure; current export must still pass the original capture/inventory gates.

`source.export_current_source(suite, context, service_fresh_client, output)`
uses that exact handoff and the same backend as historical export. Original
capture/ETW closure, native UUIDs from actual service responses, file budgets,
Suite byte copies and complete pre/post double-SHA inventories remain active.
Original metadata witnesses are checked again; actual host transport/journal
closure is required before publishing the guest-original index. A received
last response with failed local audit cannot publish it. Failures retain partial
copies, preserve the primary exception and restore adapters without replay.
The terminal distinguishes synchronous file closure from actual Fresh closure;
neither export grants guest business closure or formal-scene credit.

`runner.single_batch_request(context, explicit_batch_id)` resolves exactly one
original planned group of one to five rows. It checks the complete remaining
matrix, credited exclusions, filter and first-nonpass stop, and uses the pinned
original argv. Its immutable request rechecks inputs before producing a fresh
args object. It creates no Suite/client/output and grants no prepare or business
permission. The full entry must retain original Batch validation with the
owned evidence parent, followed by complete preparation and instance gates.

`runtime_sources.qualify(context, entry)` records the original runtime's static
imports, explicitly loaded QPC/capture scripts and staged PowerShell bytes.
The original FNPR subprocess is pinned by the plan's exact
`additional_tool_files` record for repository-root `fnpr_sentinel.py`; all
host tools must match the tool Git commit, while copied/imported product
helpers match the separate candidate source commit. `loaded_sources` checks
actual module origins against those qualified bytes and refuses Logs code.
The shared AST graph does not import or execute inspected sources, and the
independent audit entry retains its narrower three-script map. Qualification
creates no clients or output and grants no preparation or scene credit.

`run_formal_completion.py --materials-json ABS --materials-sha256 SHA prepare`
is the offline preparation entry. The pinned plan supplies an exact
`configuration_plan` file record and two ordered `preparation_audits` jobs
(`credited-selection`, then `spike-only`), each with independent material and
selection file records. Config planning calls the original lifecycle selector
without constructing Suite/clients and preserves all 401 names plus default
restoration. Audit jobs preserve candidate/tool/source/resource and original
argv bindings, differing only in owned unused roots. Each qualified audit CLI
runs in its own interpreter; its first failure prevents the second dispatch.
Raw stdout/stderr, waited process completion and preparation terminal remain.
Sources and fresh capacity are checked again after audits before a preparation
result can be written. Preparation grants no live instance admission or formal
credit. Actual complete old-five/Spike audits remain capacity blocked, and
successful full preparation is still unverified.

Preparation also checks the original producer's clean-r/date/32-hex nonce/
output-SHA scope namespace and exact SCM cycle upper bound of 70, before
capacity or audit dispatch. A generic E-drive path is insufficient to bind
a future execution, even when material and plan fingerprints are consistent.

`preparation_receipt.load_preparation(context, result_path, independently_frozen_sha,
entry)` consumes the exact owned preparation result with the same main material
SHA. Its expected SHA comes from the caller, never a neighbouring file. It
rechecks original inputs and fresh capacity, complete source/config/execution
plans, each original audit argv/completion and all indexed output/proof bytes.
Both producer and consumer recheck the original authority's indexed source
bytes, copy bytes and independent inodes without importing/installing Mapper.
Unknown, failed, altered, self-reported or differently bound preparation is
refused before clients or business output; an existing business root always
prevents retry. The resulting frozen handle grants no live instance admission.
Successful real full-preparation consumption and the normal chain remain
unverified while actual original audits are blocked.

`run_formal_completion.py ... run-batch --batch-id ID` assembles exactly one
original Suite/Batch with Fresh/Protected clients, configuration inventory,
scoped Coordinator and physical namespace. It either prepares new materials
in this invocation or consumes the explicitly supplied pair
`--preparation-json ABS --preparation-sha256 SHA`. Construction sends no RPC
and grants no admission; original live gates still precede every instance.
Original Batch stops at its first nonpass. Exact owned capture shutdown,
configuration/default and actual transport closure precede current-source
export; unknown closure withholds export and retains the primary error and
partial originals. The handoff always records zero new formal credit. After
actual current transport/journal/capture closure, `sealing` hashes the complete
owned host tree into a write-once index and rechecks its exact file set and
bytes. No later business-root writes occur. `batch_rejudge` freezes a different
audit material SHA with the exact parent material/index/batch and original
argv, then invokes the qualified original audit CLI in a separate interpreter
with `--scope batch-selection`. Original verify/replay/summary gates remain.
Incomplete or nonpass originals cannot acquire credit. Copies and all indexed
proof outputs are rechecked; failures retain sealed originals and raw process
outputs. Successful real full preparation, positive sealing and the complete
normal/failure chain remain unverified while required original audits and VM
acceptance are capacity blocked.

`run_formal_completion.py ... export-source --source-root ABS` reads one
explicitly indexed/protected producer. Source/package qualification and fresh
original host/tmp capacity precede Suite/output/RPC creation. The original
VM/candidate/native/default/worker/drive gates run before and after export;
only status and read-only PowerShell are dispatched through actual Fresh
bounded sessions. Source closure, inventory, transfer classes, sizes and
double SHA use the original backend. Capacity is rechecked before each source
RPC. Actual transport closure precedes index publication; received responses
survive local audit failure, with writer completion and audit safety recorded
separately. Failed/unknown exports retain partials and cannot retry that output.
This action grants no instance admission or formal credit.

`test_formal_runtime_chain.py` covers public preparation failure before all
business, actual original first-nonpass stopping, and unknown SCM withholding
blind restoration, with actual native/P1/P7/DNS and owned-writer restoration.
These failure slices complement the original transport/export/audit tests;
they do not establish successful complete preparation or the positive full
Windows chain, which still needs the original sources and resource gate.

`row_audit.RowAudits` wraps the original `_traffic_recheck_issues` seam.
After the original traffic recheck accepts a stored pass, actual same-context
native, owned capture, journal and bounded transport closure are required.
A read-only original guest capture query must show stopped capture sessions
and no probe writers. A write-once index pins the closed batch prefix and its
actual closure witnesses while the batch is paused. Original frozen credits
stay selected so cross-scenario checks retain the cumulative scope. A separate original
audit CLI performs verify/replay/summary with `--scope row-selection`; its
independent copies and outputs are rechecked before the seam returns success.
Failure joins the original traffic issues so Original Batch stops before the
next row; no retry or business Mapper is installed. Batch sealing additionally
requires all requested rows audited and all owned audit processes ended.
The incomplete-metadata negative test reaches the actual original verifier;
positive real row auditing and the complete Windows chain remain unverified.

`spike_gate.SpikeAudits` keeps the original business `_require_fault_spike`
seam isolated. Each invocation freezes a new parent-bound child context and
executes the full original five-class Spike validator in its own interpreter;
no preparation summary or inline business Mapper substitutes for that gate.
Original source/copy/output bytes and process completion are rechecked.
Failure retains the original child output and only its owned process may be
terminated. The test's incomplete five-case claim reaches and fails the actual
original Spike validator; positive real rejudging remains capacity blocked.

`historical_capture` reads actual capture ownership and inherited session
names from independently indexed original baselines. Initial, final and
post-export read-only queries require all those sessions and pktmon stopped;
there is no hard-coded historical session. The initial physical guest namespace
must be absent. Original scene gates bind VM/package/native/default ownership
and service configuration bytes before business and after restoration; after
export the native PID/FILETIME must still match the final gate. These checks
grant no live instance admission or new formal credit.
