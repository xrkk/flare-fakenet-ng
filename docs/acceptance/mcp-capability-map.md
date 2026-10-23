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
that every unchanged daily run must refill. The reuse interface and required
minimal additional fault producers are not implemented by this extraction.
Until they are integrated and accepted, full P04/MCP remains incomplete.

Current extraction tests use benign in-memory channel/process bytes and the
unchanged original business functions/validators under the zero-network
guard. No actual VM, MCP service, fault injection, dump or recovery ran.
