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
