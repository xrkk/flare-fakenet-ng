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
