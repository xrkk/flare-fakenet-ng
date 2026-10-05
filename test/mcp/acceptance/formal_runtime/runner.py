"""Offline input checks for the versioned formal runner.

These checks never create a Suite instance, invoke a client, or award credit.
Independent raw-source adjudication and instance admission remain separate.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
import re
import shutil
from typing import Any
import zipfile

import formal_batch_v3 as batch
import scenario_suite as suite

from .context import MaterialError, RunContext, checked_record, exact_path, read_json, _freeze


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MaterialError(message)


def _record(value: Any) -> Path:
    require(isinstance(value, dict), "explicit file record required")
    return checked_record(value)


def _package(context: RunContext, plan: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    records = plan.get("candidate_files")
    require(isinstance(records, dict) and set(records) ==
            {"manifest", "verification", "deployment", "archive"}, "candidate_files records missing")
    paths = {name: _record(row) for name, row in records.items()}
    require(all(not any(output == path or output in path.parents
                        for output in (context.evidence_root, context.audit_root))
                for path in paths.values()), "candidate input overlaps output root")
    for name, value in (("manifest", args.package_manifest),
                        ("verification", args.package_verification),
                        ("deployment", args.deployment_record)):
        require(value == str(paths[name]), "candidate argv record mismatch: " + name)
    # Call the original P2 local identity gate without constructing clients or
    # reserving a root. New code supplements it with actual archive bytes.
    view = suite.Suite.__new__(suite.Suite)
    view.args = args
    view.identity = suite.Identity(args.candidate_id, args.source_commit, args.package_sha256)
    original = view._identity_material()
    identity = context.candidate_identity
    require(records["manifest"]["sha256"] == identity["manifest_sha256"] and
            records["archive"]["sha256"] == identity["zip_sha256"], "candidate manifest/archive SHA mismatch")
    manifest = read_json(paths["manifest"])
    verification = read_json(paths["verification"])
    rows = manifest.get("files")
    require(isinstance(rows, list) and len(rows) == 199, "candidate must contain original 199 members")
    names = [row.get("path") for row in rows if isinstance(row, dict)]
    require(len(names) == 199 and all(isinstance(name, str) for name in names) and
            len(set(names)) == 199, "candidate member names invalid/duplicate")
    for name in names:
        member = PurePosixPath(name)
        require(not member.is_absolute() and member.as_posix() == name and
                ".." not in member.parts and "\\" not in name, "unsafe candidate member: " + name)
    require(verification.get("verified_files") == 199 and verification.get("manifest_match") is True
            and verification.get("size_hash_match") is True, "package verification inconsistent")
    with zipfile.ZipFile(paths["archive"]) as archive:
        entries = [entry for entry in archive.infolist() if not entry.is_dir()]
        # The builder's verify_package_zip includes the manifest envelope in addition
        # to the 199 payload members; it is deliberately absent from its own
        # files list. Bind that envelope byte-for-byte rather than ignoring it.
        expected_entries = set(names) | {"mcp-candidate-manifest.json"}
        require(len(entries) == len(expected_entries) and
                {entry.filename for entry in entries} == expected_entries,
                "archive members differ from manifest")
        require(archive.read("mcp-candidate-manifest.json") == paths["manifest"].read_bytes(),
                "embedded candidate manifest differs from pinned manifest")
        for row in rows:
            require(type(row.get("size")) is int and row["size"] >= 0 and
                    isinstance(row.get("sha256"), str) and
                    re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is not None,
                    "candidate member fingerprint invalid")
            info = archive.getinfo(row["path"])
            require(info.file_size == row["size"], "archive member size mismatch: " + row["path"])
            digest = hashlib.sha256()
            with archive.open(info) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            require(digest.hexdigest() == row["sha256"], "archive member SHA mismatch: " + row["path"])
    member_map = {row["path"]: row for row in rows}
    require(member_map.get("fakenetng-mcp.exe", {}).get("sha256") == identity["exe_sha256"]
            and member_map.get("configs/default.ini", {}).get("sha256") == identity["default_sha256"],
            "candidate EXE/default member identity mismatch")
    return dict(original, verified_members=199, archive=records["archive"])


def _sources(context: RunContext, selection: dict[str, str], manifest: dict[str, Any]) -> dict[str, Any]:
    seals: dict[Path, dict[str, Any]] = {}
    for record in context.materials["source_indices"]:
        path = checked_record(dict(record))
        index = read_json(path)
        require(isinstance(index, dict) and isinstance(index.get("rows"), list), "source index rows missing")
        require(path.parent not in seals, "duplicate source root authority")
        rows = {}
        for row in index["rows"]:
            require(isinstance(row, dict) and isinstance(row.get("path"), str), "source row invalid")
            relative = PurePosixPath(row["path"])
            require(not relative.is_absolute() and relative.as_posix() == row["path"]
                    and ".." not in relative.parts and "\\" not in row["path"], "source row path unsafe")
            require(row["path"] not in rows, "source index contains duplicate path")
            rows[row["path"]] = row
        seals[path.parent] = rows

    def source_file(path: Path) -> dict[str, Any]:
        matches = [root for root in seals if path.is_relative_to(root)]
        require(len(matches) == 1, "source file lacks unique pinned index: " + str(path))
        root = matches[0]
        row = seals[root].get(path.relative_to(root).as_posix())
        require(row is not None, "source file absent from pinned index: " + str(path))
        checked_record({"path": str(path), "size": row.get("size"), "sha256": row.get("sha256")})
        return read_json(path)

    require(isinstance(selection, dict), "credited selection must be an explicit object")
    rows = {row["scenario_id"]: row for row in manifest["scenarios"]}
    product = context.candidate_identity
    expected = {"candidate_id": product["candidate"], "source_commit": product["source"],
                "package_sha256": product["zip_sha256"]}
    selected = {}
    protected = [exact_path(item) for item in context.materials["protected_sources"]]
    for sid, location in selection.items():
        require(sid in rows, "credited scenario absent from manifest")
        root = exact_path(location)
        require(root in seals and any(root == item or root.is_relative_to(item) for item in protected),
                "credited source root must be explicitly pinned and protected")
        original = source_file(root / "scenario-manifest.json")
        require(not suite.manifest_issues(original) and original["scenarios"] == manifest["scenarios"],
                "credited source manifest differs")
        result_path = root / "results" / ("scenario-" + sid + ".json")
        result = source_file(result_path)
        require(result.get("scenario_id") == sid and result.get("state") == "pass" and
                result.get("identity") == expected and result.get("scenario") == rows[sid],
                "credited result identity/state/scenario mismatch")
        require(type(result.get("attempt")) is int and result["attempt"] > 0 and
                isinstance(result.get("traffic_evidence"), dict) and
                isinstance(result["traffic_evidence"].get("nonce"), str) and
                re.fullmatch(re.escape(sid) + r"-a%d-[0-9a-f]{32}" % result["attempt"],
                             result["traffic_evidence"]["nonce"]) is not None,
                "credited result attempt/nonce invalid")
        runs = result.get("run_chain")
        require(isinstance(runs, list) and bool(runs) and all(isinstance(row, dict) and
                isinstance(row.get("run_id"), str) and bool(row["run_id"]) for row in runs)
                and len({row["run_id"] for row in runs}) == len(runs), "credited run identities invalid")
        selected[sid] = {"root": str(root), "attempt": result["attempt"],
                         "nonce": result["traffic_evidence"]["nonce"],
                         "run_ids": [row["run_id"] for row in runs]}
    spike_path = exact_path(context.materials["spike_source"]["path"])
    spike = source_file(spike_path)
    require(spike.get("schema") == "sst.fault-spike.v1" and spike.get("identity") == expected,
            "Spike source identity/schema mismatch")
    return {"selected_source_identities": selected, "spike_source_indexed": True,
            "independent_raw_rejudge_required": True}


def _batches(plan: dict[str, Any], manifest: dict[str, Any], credited: dict[str, str]) -> list[dict[str, Any]]:
    rows = {row["scenario_id"]: row for row in manifest["scenarios"]}
    batches = plan.get("batches")
    require(isinstance(batches, list) and bool(batches), "explicit batches missing")
    require(plan.get("first_nonpass_stop") is True, "first_nonpass_stop must remain true")
    seen_ids: set[str] = set()
    seen_batches: set[str] = set()
    for item in batches:
        require(isinstance(item, dict) and set(item) == {"batch_id", "kind", "scenario_ids"}, "batch fields invalid")
        batch_id, kind, ids = item["batch_id"], item["kind"], item["scenario_ids"]
        require(isinstance(batch_id, str) and batch.BATCH_ID_RE.fullmatch(batch_id) is not None
                and batch_id not in seen_batches, "batch ID invalid/duplicate")
        require(kind in ("benign", "fault") and isinstance(ids, list) and 1 <= len(ids) <= 5
                and all(isinstance(sid, str) for sid in ids) and len(set(ids)) == len(ids), "batch must select one to five unique IDs")
        require(not seen_ids.intersection(ids) and not set(credited).intersection(ids), "batch repeats selected/credited scenario")
        for sid in ids:
            require(sid in rows and (rows[sid]["fault_class"] is not None) == (kind == "fault"),
                    "batch scenario/filter mismatch")
        seen_batches.add(batch_id)
        seen_ids.update(ids)
    require(seen_ids == set(rows) - set(credited) and plan.get("remaining") == len(seen_ids),
            "batches do not cover the exact uncredited manifest IDs")
    return batches


def _capacity(context: RunContext, largest_batch: int) -> dict[str, Any]:
    resource = context.materials["resource_plan"]
    fixed = {"host_reserve_bytes": 24 * 2 ** 30, "tmp_reserve_bytes": 768 * 2 ** 20,
             "export_total_bytes": 4 * 2 ** 30, "ordinary_bytes": suite.MAX_GUEST_TRANSFER,
             "shared_bytes": suite.MAX_SHARED_PKTMON_TEXT_TRANSFER, "auxiliary_bytes": suite.MAX_AUX_V2_ZIP_TRANSFER}
    for name, expected in fixed.items():
        require(type(resource.get(name)) is int and resource[name] == expected,
                "original resource bound differs: " + name)
    forecast = ("per_scenario_host_source_bytes", "per_scenario_audit_copy_bytes",
                "transfer_temporary_reserve_bytes", "instance_gate_reserve_bytes")
    for name in forecast:
        require(type(resource.get(name)) is int and resource[name] >= 0, "capacity forecast invalid: " + name)
    need = (resource[forecast[0]] + resource[forecast[1]]) * largest_batch + resource[forecast[2]] + resource[forecast[3]]
    host = shutil.disk_usage(context.repository_root).free
    temporary = shutil.disk_usage(Path("/tmp")).free
    require(host >= fixed["host_reserve_bytes"] + need and temporary >= fixed["tmp_reserve_bytes"],
            "fresh offline host/tmp capacity insufficient")
    return {"host_free_bytes": host, "tmp_free_bytes": temporary, "forecast_increment_bytes": need,
            "guest_capacity_not_checked": True}


def check_preparation_inputs(context: RunContext, *, prepared_audit=False) -> dict[str, Any]:
    """Validate local inputs only; complete prepare still needs the audit lane."""
    context = context.revalidate()
    plan = read_json(checked_record(dict(context.materials["plan"])))
    args = {kind: batch.load_suite_args(checked_record(dict(row)))
            for kind, row in context.materials["suite_argv"].items()}
    require(vars(args["benign"]) | {"filter": "fault"} == vars(args["fault"]),
            "benign/fault argv differ beyond the filter")
    require(args["benign"].fault_spike_result == context.materials["spike_source"]["path"],
            "suite argv Spike source differs from pinned material")
    package = _package(context, plan, args["benign"])
    manifest = read_json(_record(plan.get("original_manifest")))
    require(not suite.manifest_issues(manifest) and suite.canonical_bytes(manifest) ==
            suite.canonical_bytes(suite.build_manifest(args["benign"].seed, args["benign"].count)),
            "original manifest differs from original generator/contract")
    if args["benign"].regen_check:
        require(Path(plan["original_manifest"]["path"]).read_bytes() == suite.canonical_bytes(manifest),
                "original manifest regeneration is not byte-identical")
    selection = read_json(checked_record(dict(context.materials["credited_selection"])))
    sources = _sources(context, selection, manifest)
    batches = _batches(plan, manifest, selection)
    capacity = _capacity(context, max(len(item["scenario_ids"]) for item in batches))
    require(not context.evidence_root.exists() and (prepared_audit or not context.audit_root.exists()),
            "offline preparation requires unused output roots")
    return {"schema": "fakenetng.formal-runtime.input-check.v1", "materials_sha256": context.materials_sha256,
            "package": package, "manifest_count": len(manifest["scenarios"]),
            "benign_count": sum(row["fault_class"] is None for row in manifest["scenarios"]),
            "fault_count": sum(row["fault_class"] is not None for row in manifest["scenarios"]),
            "remaining": plan["remaining"], "batches": batches, "sources": sources, "capacity": capacity,
            "VM_calls": 0, "business_authorized": False,
            "pending": ["complete tool dependency/entry binding", "independent original credited/Spike rejudge",
                        "configuration plan integration", "instance and fresh guest admission before execution"]}


@dataclass(frozen=True)
class BatchRequest:
    context: RunContext
    batch_id: str
    kind: str
    scenario_ids: tuple[str, ...]
    argv_record: object
    manifest_record: object
    original_manifest: object

    def suite_args(self):
        self.context.revalidate()
        checked_record(dict(self.manifest_record))
        return batch.load_suite_args(checked_record(dict(self.argv_record)))


def single_batch_request(context: RunContext, batch_id: str) -> BatchRequest:
    """Select one frozen original batch only; this does not prepare or run it."""
    context = context.revalidate()
    require(isinstance(batch_id,str) and batch.BATCH_ID_RE.fullmatch(batch_id) is not None,
            'one explicit original batch ID is required; no default all-scenes execution')
    plan = read_json(checked_record(dict(context.materials['plan'])))
    manifest_record = plan.get('original_manifest')
    manifest = read_json(_record(manifest_record))
    args = {kind: batch.load_suite_args(checked_record(dict(row)))
            for kind,row in context.materials['suite_argv'].items()}
    require(vars(args['benign']) | {'filter':'fault'} == vars(args['fault']),
            'benign/fault argv differ beyond the filter')
    require(not suite.manifest_issues(manifest) and suite.canonical_bytes(manifest) ==
            suite.canonical_bytes(suite.build_manifest(args['benign'].seed,args['benign'].count)),
            'original manifest differs from original generator/contract')
    credited = read_json(checked_record(dict(context.materials['credited_selection'])))
    require(isinstance(credited,dict), 'credited selection must be an explicit object')
    planned = _batches(plan,manifest,credited)
    chosen = [item for item in planned if item['batch_id'] == batch_id]
    require(len(chosen) == 1, 'explicit batch ID is absent from the frozen remaining plan')
    item = chosen[0]
    require(args[item['kind']].stop_on_first_failure is True,
            'original selected argv must stop after the first nonpass')
    # formal_batch_v3 requires runner.root to be a new *child* of its allowed
    # evidence root. The full entry must pass this owned parent, retaining the
    # original validator rather than rewriting its scheduling contract.
    parent = context.evidence_root.parent
    require(parent.is_relative_to(context.repository_root/'Logs'),
            'formal batch allowed parent must remain repository Logs')
    return BatchRequest(context,batch_id,item['kind'],tuple(item['scenario_ids']),
                        _freeze(dict(context.materials['suite_argv'][item['kind']])),
                        _freeze(manifest_record),_freeze(manifest))
