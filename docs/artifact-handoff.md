# Completed FakeNet artifact handoff

`tools/Export-VeloArtifacts.ps1` exports only registered `complete=true` rows
from a selected stopped run, using the deployed Velo repository's
`export_transfer_artifacts.ps1`. It starts/stops no process and makes no network
call. FakeNet remains responsible for capture/network lifecycle; Velo handles
cross-host transfer after publication.

Wait for the managed run's owned writers and stop operation to finish. Save the
fresh, successful **structured result** of `get_run_overview(run_id=<RunId>)` as
UTF-8 JSON at `$OverviewPath` (not the outer MCP response or text rendering).
Select the explicit canonical run UUID and omit `artifact_type` to request the
whole run's registered artifact list. Keep the producer quiescent throughout
export. The wrapper requires `consistent=true`, `partial=false`, current service
state `stopped`, `health.process_alive=false`, matching selected/query run IDs
and matching status-after/service state versions. These observations describe
that query, not a lock preventing a later capture start.

Use absolute deployment paths for `$FakeNetRepository`, `$VeloRepository`,
`$PolicyPath`, `$OutputRoot`, `$ArtifactsRoot`, `$OverviewPath` and
`$EvidenceDirectory`. `$ArtifactsRoot` is the existing registered `artifacts`
directory, not protected `exit-evidence` or a package working directory.
`$OutputRoot` is an existing dedicated exact Velo policy `read_roots` entry,
disjoint from source originals, work state and private configuration; prepare
administrator/SYSTEM directory creation rights and service Read/traverse.
Use a new `$BatchId` (1–64 ASCII letters/digits/underscore/hyphen/dot, first
character alphanumeric). Store host runtime/acceptance evidence under `Logs/`;
do not use repository-root `dist/` for it.

```powershell
& (Join-Path $FakeNetRepository 'tools/Export-VeloArtifacts.ps1') `
  -VeloRepository $VeloRepository -PolicyPath $PolicyPath -OutputRoot $OutputRoot `
  -ArtifactsRoot $ArtifactsRoot -OverviewPath $OverviewPath -BatchId $BatchId `
  -EvidenceDirectory $EvidenceDirectory
```

The wrapper retains `<BatchId>.export.json`, selecting only complete rows below
`artifacts/<RunId>/`; it never marks unpublished files complete. The shared
exporter rechecks current source size/SHA-256 without writer/delete sharing,
creates independent copies with a bound `handoff-receipt.json`, configures and
verifies scoped Velo service Read, and publishes a new batch directory. A changed
source, sharing conflict, policy violation or existing destination is a failure.
Keep the original overview, manifest, receipt and failure JSON.

Only outputs the FakeNet producer actually publishes can be exported. PCAP,
log, HTML report and registered incident members are supported by the registry.
HTTP observations embedded in published log/report files can travel with them;
raw `DumpHTTPPosts` `.txt` records require their own producer-side publication.
The registrar now selects enabled HTTP listeners' relative basename prefixes
from the retained `active-config.ini`, matching only timestamped POST `.txt`
names. Disabled producers, arbitrary text, staging suffixes and absolute/path
prefixes are outside this run-scoped registrar. Configure a basename prefix so
the output stays in its isolated run directory; do not scan private directories.
Only call registration after the producer has stopped.

For a frozen deployment awaiting an upgrade, the explicit compatibility entry
`tools/publish_closed_run_artifacts.py` runs from a verified source bundle with
`fakenet/mcp/artifacts.py` and package initializers, using a supplied Python.
It validates a stopped consistent overview and retained config hash, then calls
the same registrar. Run with `--overview $OverviewPath --artifacts-root
$ArtifactsRoot`, save a **new** `get_run_overview(run_id=...)`, then export from
that fresh overview. It does not change service/network lifecycle or ACLs.

Listener-only (`DivertTraffic=No`) health now checks real live listener handles;
interception-enabled health still requires its native engine and capture
threads. NBI callbacks skip attaching data when there is no diverter. HTTP
requests still log and produce raw POST records. This mode does not provide
PCAP capture or intercepted-session HTML reports. A permission acceptance
fixture for those formats is not network capture qualification.

For an incident dump, use FakeNet's existing controlled incident publication:
it verifies the retained exit dump and publishes a copied `userdump.dmp` under
the run's registered incident subtree. Do not recursively grant the Velo service
access to protected `exit-evidence`; that source requires exactly SYSTEM and
Administrators FullControl ACEs. The shared export reads only the published
incident copy, leaving the protected original intact.

Submit the returned `output_directory` to the existing Velo host pull coordinator
using the configured connection profile and new transfer identity. Export success
is not transfer COMPLETE: retain destination content/SHA-256 verification, the
durable coordinator result and both owned cleanup results. Audit retention and
cleanup against an exact reviewed manifest only after all capture, transfer and
derived-evidence writers have exited; preserve formal success/failure originals
and dependencies. This wrapper does not perform retention cleanup.

See `docs/artifact-export-handoff.md`, `docs/service-file-updates.md`,
`docs/cross-account-permission-implementation.md` and
`docs/cross-account-handoff-source-audit.md` in the deployed Velo repository for
the shared contract, separate private-file updates and implementation/acceptance
status. No VM reboot or snapshot restore is needed for this workflow.

For a service candidate built in the existing Docker/Wine workflow, use the
MinGit image when the Windows qualification sentinels need native Git. The
`core` gate retains the complete formal-runtime Linux host regression and
Windows sentinels; Linux-only deploy/update tests also belong to that mandatory
host receipt. Do not turn an environment failure into an allowlisted skip or
package without the pinned qualification. Keep the resulting PARTIAL build
qualification separate from native handoff acceptance.
