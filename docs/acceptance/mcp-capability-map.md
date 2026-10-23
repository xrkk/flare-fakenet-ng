# MCP P04 capability and evidence mapping

This is an implementation map for the current regression plan, not a new
product contract or an acceptance result. The original `run_acc014` contract
and its full credit remain required. No GUI, 100-scenario or 150-round driver
is brought into the regression set.

| Capability | Fixed execution or check | Credit and current limit |
| --- | --- | --- |
| Five original fault hooks | `FAULT-POINTS` and five `MCP-SPECIAL-FAULT-RECOVERY` units | Original action, nonce/run receipt, incident bytes and recovery assertions remain; no publication-loop credit. |
| Incident mechanical integrity | `INCIDENT-INTEGRITY`, calling `collect_acc014_incident_integrity` | Original round validator, all exported incident ZIPs, member manifests/hashes/run attribution and required dump checks. A pass explicitly leaves root-cause localization not evaluated. |
| Package-only component and failure-chain localization | Original `ACC-014` / `run_acc014` | Still mandatory for complete P04 capability credit. Actual package references and localization plus original terminal coverage must pass; missing localization remains blocked. No generated or fabricated localization. |
| Terminal IPC timeout/EOF/wrong-run/repeat/reverse | Original six `MCP-SPECIAL-IPC` units; `ACC-014` terminal coverage | Keep original parent/child action, nonce, run, health revocation, recovery, incident and timeout dump assertions. IPC success alone does not supply package-only semantic localization or all full ACC-014 records. |
| Initialization failure | `INITIALIZATION-FAILURE` and original P03 assertions | Keep actual failed initialization, evidence and recovery checks; native execution not yet verified. |
| Stacks unavailable | Original `ACC-014` required class and conditional dump requirement | Retained as required product capability. Dedicated minimal action/record integration not implemented yet; not excluded because a historical matrix covered it. |
| Native crash | Original `ACC-014` required class and conditional dump requirement | Retained as required product capability. Dedicated minimal action/record integration not implemented yet; no native credit. |
| Unknown cause | Original `ACC-014` required class and conditional dump requirement | Retained as required product capability. Required diagnosis/escalation evidence is not replaced by file existence or hashes; integration remains unfinished. |
| Artifact metadata/export and content-tool negative | Original `ACC-015` | Same-run incident/PCAP, actual bytes and no-download-tool assertions remain. |
| Controlled stop/upgrade and failed recovery | Original `ACC-019` | Original drain/query/mutation/stop/recovery assertions remain. |

The centralized P04 full check set still includes `ACC-014`. The explicit
mechanical slice is selected-only: full already executes these assertions in
`ACC-014`, so the slice adds no duplicate fault runs to full. A selected slice
pass cannot make the full group pass.
`INCIDENT-INTEGRITY` adds observable mechanical progress; it does not remove
any original condition from `run_acc014`.

Evidence reuse is not an automatic waiver. Root-cause capability may reuse
only actual accepted evidence whose candidate, source/dependency slice,
configuration, fault and requirement identities remain applicable and whose
original bytes and localization references still validate. A changed or
unverified dependency invalidates its affected credit. The source of semantic
localization is an independent capability acceptance, not a human template
that every unchanged daily run must refill. The read-only reuse interface is now connected through
`mcp.references.ACC-014` in the frozen environment inputs. The minimal additional
fault producers and actual independent native originals remain unfinished;
full P04/MCP remains incomplete.

Current extraction tests use benign in-memory channel/process bytes and the
unchanged original business functions/validators under the zero-network
guard. No actual VM, MCP service, fault injection, dump or recovery ran.

The reference has schema `fakenet.mcp-capability-reference.v1`, `files` and
`mapping`. `files` explicitly pins six immutable originals (`task`,
`receive_config`, `result`, `receipt`, `report`, `acceptance`) by absolute `path`
and full `sha256`. Each mapping contains only `{file, pointer}` and locates an
existing JSON field or a field in the sole JSON block of a Markdown original.
It supplies no new reviewer, verdict or capability facts. Report fields are
`capability`, `verdict`, `evidence_level`, `implementers`, `identity`, `target`,
`config_identity`, `manifest_sha256`, `dependencies`, `fault_records` and
`localization`. Result fields locate `reviewer`, `controller`, `report_path`
and `report_sha256`; acceptance locates `accepted_verdict`,
`accepted_result_sha256` and `accepting_controller`. `fault_records` and
`localization` themselves pin their original files by path and SHA-256.

The loader checks matching original event/task/result/receive, closed work,
independence from controller/implementers, product ACC014 object and accepted
conclusion, current candidate/target/config/manifest and relevant product source
closure. It reexports only pinned original ZIP bytes into a new judgment root
and calls the unchanged full `run_acc014` assertions over original round and
localization records. Missing terminal classes/dumps or invalid package quotes
still fail. Selection containing only this reference constructs no authentication
or target channel. This rejudges historical capability; it does not observe the
current deployment or replace current-run mechanical checks. The native path
requires native originals; explicit synthetic fixtures are rejected there.
No actual matching independent product originals are currently available.

The bounded synthetic fixture tests cover parsing, matching links, semantic
identity/object/acceptance rejection, unchanged originals and rehashed bad
quotes through the production catalog's `plan/execute/judge`. Synthetic rounds,
ZIP bytes and reviewer names prove interface discrimination only, not actual
independence, the three missing producers, dump generation or native capability.


P03 protection-parameter regression uses the actual `Fakenet.parse_config`,
configuration store, tools and `RealSupervisor._inject_exclusion`, with benign
lifecycle/process edges. The current product lowercases parsed keys but the
injection validator reads mixed-case keys. A configured `not-an-ip` is therefore
accepted at that layer and overwritten; the original S4 assertion correctly
reports a product failure. This is a code-level finding, not a native observation.
Product core is outside this implementation's write scope and remains unchanged.
The S4 runner now binds load to the original accepted create request name,
not a nonexistent top-level `MutationResponse.name`; create/load failure stops
before start and never retries an accepted mutation or tests the stale default.
The production catalog's selected `plan/execute/judge` retains this failure.
A successful facility discrimination test does not mark the product unit passed.


ACC006 keeps the complete IPC, healthy control, listener/capture exception,
active handle loss and no-initialization-evidence checks. `HEALTH-NO-LISTENER`
and `HEALTH-ACTIVE-PROBE` expose those same original functions as selected-only
slices; full does not repeat them or treat a slice as complete ACC006 credit.
The no-listener configuration now disables every parsed listener section,
including passive FTP, and loads the accepted request name. It records the
accepted start and the complete original observation window, then checks
controlled stop/default restoration. A rejected mutation or transient healthy
sample cannot count as the intended no-initialization test. Active-probe loss
keeps original same-run pipe request/response, live listeners, same child,
four-second revocation, nonce, incident bytes and recovery predicates.
All current slice evidence remains guarded, benign process/HTTP/clock fixtures;
actual health revocation, WinDivert and native recovery remain unverified.

Three conditional diagnostic producers were checked against the actual source
before adding any action. They remain mandatory and unimplemented as complete
stimulus-to-classification chains:

| Class | Existing mechanism | Missing part and current disposition |
| --- | --- | --- |
| `stacks_unavailable` | `managed_stacks.read_stacks` validates run/process/time; `incident_task.prepare` escalates missing live/snapshot stacks for a pinned managed dump target. | No verified fixed action selectively makes the live stack reply and fallback observations unavailable while preserving the intended live child. IPC health-drop hooks do not establish that condition. Keep the gap; do not arm an unsupported hook or erase stack evidence to manufacture it. |
| `native_crash` | Managed exit evidence can supply a precollected dump; P03 has handle-pinned termination and supervisor restart tests. | Those termination tests do not establish a native exception. No pinned benign native-exception stimulus with its complete exit/dump/recovery chain is integrated here. Keep the gap; a collected dump alone is not a native-crash producer. |
| `unknown_cause` | Existing incident preparation and conditional dumps collect observations for a pinned run/process. | No verified stimulus plus observed unclassified cause and independent package-only localization is connected. Writing this class into a record or supplying a reason string is not an observed unknown cause. Keep the gap. |

These findings do not declare the whole product incapable of the conditions;
they identify the missing mechanical acceptance chains. Product hooks and
validators remain unchanged. No real fault or dump was executed.

The independent P03 `ACC-004-S5` path now requires a healthy current run and
the exact `policy_pause` nonce consumed by the real hook into that run's
`fault-triggered.json`, in addition to the existing entire-stop control-link
probes and bounded stop/recovery checks. Arming a hook and observing a normal
stop no longer count as a triggered hang. A failed receipt read cannot supply
successful recovery credit. The source, replay judge and unchanged production
catalog are exercised with process/HTTP/clock boundaries only: wrong nonce,
class, run and channel exit code fail; rehashing the outer receipts does not
make bad content pass. This is limited offline integration credit, not a native
hang, complete P03/MCP acceptance, or any of the three missing classes above.

P03 `ACC-009` now verifies the accepted create/load/start receipts before using
the current healthy run's exact custom-config name, bytes, SHA and version.
It does not continue from a rejection or missing receipt into the old default.
The fixed `acc009_config_probe.ps1` records actual file identity, attempted
write/delete, native error codes and unchanged hashes. Only sharing/lock
violations (32/33), with the same readable bytes, satisfy the running lock
predicate. Access-denied labels or other OS failures do not. After controlled
stop, it actually writes/deletes and exclusively recreates only its own file
with the original bytes, then observes restoration before MCP cleanup.

The real ConfigStore and coordinator still own runtime `config_in_use`, path
rejection, versions and stopped CRUD assertions. Failed accepted mutations may
reserve a version; that is recorded without treating lifecycle/byte mutation as
acceptable. Import/edit/rename failure stops dependent mutations: a preexisting
same-name object is neither edited nor deleted to make the test continue.

Reparse tests use a fresh nonce name and a benign target under the selected E/D
work root. They record creation, real configuration-domain rejection and exact
link/target cleanup, and leave any old `junction.ini` untouched. Unsupported
construction is not evaluated; unknown cleanup or an unconfirmed mutation
receipt preserves the scene and cannot supply cleanup credit. The new-run
restart response is checked against its observed current run, while
`bound_run_id` must identify the request's original run; a new run is not
mistakenly required to retain the old run ID.

Current tests run original P03 functions and actual configuration/coordination
domain code, replacing only Windows file/process/HTTP/clock edges. Real benign
host symlinks exercise the path guard. Same-catalog CLI tests reject bad attempt
content even after outer hashes are updated. Windows sharing/PowerShell/SCM
execution remains unverified; these results provide offline integration credit,
not complete P03/MCP or native/full acceptance. The centralized facility selftest
now includes `test/test_acceptance_mcp.py`, and source identity includes the
fixed PowerShell probe. No GUI, historical scenario/release driver or T007 test
is added by this registration.


### Atomic creation windows and process recovery (ACC007)

The fixed original ACC007 runner retains all six creation stages and the healthy
run case. Load/start receipts and the consumed creation nonce, stage, command,
run, current marker and SCM birth must match before termination. Early creation
windows require no child; later windows require the actual child in the Job and
the exact allowed creation prefix, without a start frame or PCAP.

The fixed PowerShell helpers hold process handles, verify FILETIME, executable,
run and parent ancestry, and terminate only the pinned supervisor. The managed
image is `fakenetng-mcp-managed.exe`, as used by the current product. A separate
fixed PowerShell sleep process uses CreateNoWindow and proves unrelated process
survival; cleanup targets only that invocation's canary. Descendants are observed
through their retained handles, with explicit surviving/escaped process results.

Recovery uses the actual new SCM PID/birth and endpoint owner. The real product's
per-instance EventLog supplies the ordered recovering/stopped audit, with a new
epoch and timestamps inside that instance's lifetime. The old runner searched
for a `startup recovery outcome` log string that the current product does not
emit. A RESTART configuration label alone cannot establish recovery. The entire
read-only no-replay window is bracketed by the same SCM/endpoint identity and
requires the old marker to be retained with only needs_recovery cleared, no
command replay and no automatic FakeNet continuation.

Tests invoke the unmodified creation evidence producer and EventLog with benign
file, process-identity and clock boundaries, then run the original acceptance
functions and independent replay through the same catalog CLI. Bad birth,
ancestry, stage, takeover, canary, SCM, epoch, recovery marker and run observations
are rejected; updating outer hashes cannot make wrong tree content pass. These
are offline integration and predicate checks. PowerShell parsing/execution,
Windows Job/handle/SCM behavior, native crash exceptions/dumps/root-cause
localization and full P03/MCP remain unverified. No real VM/service/kill/network
operation or T007 check is performed by these offline tests.
