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
