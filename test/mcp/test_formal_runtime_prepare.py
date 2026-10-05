"""Original package, manifest and exact-source input gates are kept intact."""

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from test_formal_runtime_context import materials, record, write_json
from formal_runtime.context import MaterialError, load_context
from formal_runtime import runner


@pytest.fixture
def prepared(materials, monkeypatch):
    root, path, _, data = materials
    inputs = path.parent
    payloads = {"fakenetng-mcp.exe": b"MZfixture", "configs/default.ini": b"[FakeNet]\n"}
    payloads.update({"dependencies/file-%03d.bin" % n: ("fixture-%03d" % n).encode()
                     for n in range(197)})
    archive = inputs / "package.zip"
    identity = data["candidate_identity"]
    identity.update(exe_sha256=hashlib.sha256(payloads["fakenetng-mcp.exe"]).hexdigest(),
                    default_sha256=hashlib.sha256(payloads["configs/default.ini"]).hexdigest())
    package = {"schema": "fakenet.mcp-candidate-manifest.v1", "source_commit": identity["source"],
               "files": [{"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                         for name, body in payloads.items()]}
    package_record = write_json(inputs / "package-manifest.json", package)
    identity["manifest_sha256"] = package_record["sha256"]
    with zipfile.ZipFile(archive, "w") as bundle:
        for name, body in payloads.items():
            bundle.writestr(name, body)
        bundle.writestr("mcp-candidate-manifest.json", Path(package_record["path"]).read_bytes())
    identity["zip_sha256"] = record(archive)["sha256"]
    verification = write_json(inputs / "verification.json", {"zip_sha256": identity["zip_sha256"],
        "verdict": "PASS", "verified_files": 199, "manifest_match": True, "size_hash_match": True})
    deployment = write_json(inputs / "deployment.json", {"source": identity["source"],
        "candidate": identity["candidate"], "zip_sha256": identity["zip_sha256"], "verified_members": 199})
    generated = runner.suite.build_manifest(20260912, 100)
    manifest_path = inputs / "scenario-manifest.json"
    manifest_path.write_bytes(runner.suite.canonical_bytes(generated))
    history = inputs / "history"
    history.mkdir()
    (history / "scenario-manifest.json").write_bytes(manifest_path.read_bytes())
    result_dir = history / "results"
    result_dir.mkdir()
    credited = {"sst-%03d" % n: str(history) for n in range(5, 10)}
    product_identity = {"candidate_id": identity["candidate"], "source_commit": identity["source"],
                        "package_sha256": identity["zip_sha256"]}
    for sid in credited:
        write_json(result_dir / ("scenario-" + sid + ".json"), {
            "scenario_id": sid, "state": "pass", "identity": product_identity,
            "scenario": next(row for row in generated["scenarios"] if row["scenario_id"] == sid),
            "attempt": 1, "traffic_evidence": {"nonce": sid + "-a1-" + "d" * 32},
            "run_chain": [{"run_id": sid + "-one"}]})
    spike = history / "fault-spike-result.json"
    data["spike_source"] = write_json(spike, {"schema": "sst.fault-spike.v1", "identity": product_identity})
    index = history / "full-SHA-index.json"
    write_json(index, {"rows": [{**record(item), "path": item.relative_to(history).as_posix()}
                               for item in sorted(history.rglob("*.json"))]})
    data["source_indices"] = [record(index)]
    data["credited_selection"] = write_json(Path(data["credited_selection"]["path"]), credited)
    batches = []
    for kind in ("benign", "fault"):
        ids = [row["scenario_id"] for row in generated["scenarios"] if row["scenario_id"] not in credited
               and (row["fault_class"] is not None) == (kind == "fault")]
        for start in range(0, len(ids), 5):
            batches.append({"batch_id": "%s-%02d" % (kind, start // 5), "kind": kind,
                            "scenario_ids": ids[start:start + 5]})
    plan = {"identity": identity, "root": data["evidence_root"],
            "physical_namespace": data["physical_namespace"], "original_manifest": record(manifest_path),
            "candidate_files": {"manifest": package_record, "verification": verification,
                                "deployment": deployment, "archive": record(archive)},
            "batches": batches, "remaining": 95, "first_nonpass_stop": True}
    for kind, row in data["suite_argv"].items():
        invocation = {"schema": "fakenetng.final100.suite-argv.v1", "argv": [
            "run", "--candidate-id", identity["candidate"], "--source-commit", identity["source"],
            "--package-sha256", identity["zip_sha256"], "--suite-root", data["evidence_root"],
            "--filter", kind, "--stop-on-first-failure", "--regen-check",
            "--package-manifest", package_record["path"], "--package-verification", verification["path"],
            "--deployment-record", deployment["path"], "--fault-spike-result", str(spike)]}
        row.update(write_json(Path(row["path"]), invocation))
    data["plan"] = write_json(Path(data["plan"]["path"]), plan)
    data["resource_plan"] = {"host_reserve_bytes": 24 * 2 ** 30, "tmp_reserve_bytes": 768 * 2 ** 20,
        "export_total_bytes": 4 * 2 ** 30, "ordinary_bytes": 192 * 2 ** 20,
        "shared_bytes": 512 * 2 ** 20, "auxiliary_bytes": 256 * 2 ** 20,
        "per_scenario_host_source_bytes": 2 ** 20, "per_scenario_audit_copy_bytes": 2 ** 20,
        "transfer_temporary_reserve_bytes": 2 ** 20, "instance_gate_reserve_bytes": 2 ** 20}
    pin = write_json(path, data)["sha256"]
    monkeypatch.setattr(runner.shutil, "disk_usage", lambda path: SimpleNamespace(free=50 * 2 ** 30))
    return root, path, pin, data, plan


def check(prepared):
    root, path, pin, _, _ = prepared
    return runner.check_preparation_inputs(load_context(path, pin, repository_root=root))


def repin(prepared):
    root, path, _, data, plan = prepared
    data["plan"] = write_json(Path(data["plan"]["path"]), plan)
    return root, path, write_json(path, data)["sha256"], data, plan


def reseal_history(prepared):
    data = prepared[3]
    index = Path(data["source_indices"][0]["path"])
    rows = json.loads(index.read_text())["rows"]
    for row in rows:
        source = index.parent / row["path"]
        row.update({key: value for key, value in record(source).items() if key != "path"})
    data["source_indices"] = [write_json(index, {"rows": rows})]


def test_checks_call_original_gates_without_clients_or_output(prepared, monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("offline material check cannot construct Suite or clients")
    monkeypatch.setattr(runner.suite.Suite, "__init__", deny)
    monkeypatch.setattr(runner.suite.RawMcp, "__init__", deny)
    monkeypatch.setattr(runner.suite.VmMcp, "__init__", deny)
    verdict = check(prepared)
    assert (verdict["manifest_count"], verdict["benign_count"], verdict["fault_count"], verdict["remaining"]) == (100, 85, 15, 95)
    assert verdict["package"]["verified_members"] == 199 and verdict["VM_calls"] == 0
    assert verdict["business_authorized"] is False
    assert verdict["sources"]["independent_raw_rejudge_required"] is True
    assert not Path(prepared[3]["evidence_root"]).exists()
    assert not Path(prepared[3]["audit_root"]).exists()


def test_original_p2_rejects_wrong_deployment(prepared):
    plan = prepared[4]
    path = Path(plan["candidate_files"]["deployment"]["path"])
    value = json.loads(path.read_text())
    value["candidate"] = "wrong"
    plan["candidate_files"]["deployment"] = write_json(path, value)
    with pytest.raises(runner.suite.Blocked, match="candidate material does not bind"):
        check(repin(prepared))


@pytest.mark.parametrize("change,reason", [
    (lambda bodies: bodies.update({"dependencies/file-001.bin": b"altered"}), "archive member (size|SHA) mismatch"),
    (lambda bodies: bodies.pop("mcp-candidate-manifest.json"), "archive members differ"),
    (lambda bodies: bodies.update({"mcp-candidate-manifest.json": b"{}"}), "embedded candidate manifest differs"),
    (lambda bodies: bodies.update({"extra.bin": b"unexpected"}), "archive members differ"),
])
def test_zip_bytes_are_checked_beyond_selfreported_verification(prepared, change, reason):
    plan = prepared[4]
    path = Path(plan["candidate_files"]["archive"]["path"])
    with zipfile.ZipFile(path) as old:
        bodies = {name: old.read(name) for name in old.namelist()}
    change(bodies)
    with zipfile.ZipFile(path, "w") as altered:
        for name, body in bodies.items():
            altered.writestr(name, body)
    record_now = record(path)
    # Keep every outer binding consistent to exercise the member check itself.
    identity = prepared[3]["candidate_identity"]
    identity["zip_sha256"] = record_now["sha256"]
    plan["candidate_files"]["archive"] = record_now
    for key in ("verification", "deployment"):
        source = Path(plan["candidate_files"][key]["path"])
        value = json.loads(source.read_text())
        value["zip_sha256"] = identity["zip_sha256"]
        plan["candidate_files"][key] = write_json(source, value)
    for row in prepared[3]["suite_argv"].values():
        source = Path(row["path"])
        value = json.loads(source.read_text())
        value["argv"][value["argv"].index("--package-sha256") + 1] = identity["zip_sha256"]
        row.update(write_json(source, value))
    with pytest.raises(MaterialError, match=reason):
        check(repin(prepared))


@pytest.mark.parametrize("mutation,reason", [
    (lambda p: p["batches"][0]["scenario_ids"].append(p["batches"][0]["scenario_ids"][0]), "one to five unique"),
    (lambda p: p["batches"][1].update(batch_id=p["batches"][0]["batch_id"]), "batch ID invalid/duplicate"),
    (lambda p: p["batches"][0]["scenario_ids"].__setitem__(0, "sst-005"), "selected/credited"),
    (lambda p: p["batches"].pop(), "exact uncredited"),
    (lambda p: p.update(first_nonpass_stop=False), "first_nonpass_stop"),
    (lambda p: p["batches"][0].update(kind="fault"), "scenario/filter mismatch"),
])
def test_exact_batch_selection_rejects_wrong_plans(prepared, mutation, reason):
    mutation(prepared[4])
    with pytest.raises(MaterialError, match=reason):
        check(repin(prepared))


def test_sealed_failure_cannot_be_claimed_as_credited_pass(prepared):
    root = Path(next(iter(json.loads(Path(prepared[3]["credited_selection"]["path"]).read_text()).values())))
    path = root / "results/scenario-sst-005.json"
    value = json.loads(path.read_text())
    value["state"] = "fail"
    write_json(path, value)
    reseal_history(prepared)
    with pytest.raises(MaterialError, match="credited result identity/state/scenario mismatch"):
        check(repin(prepared))


def test_source_manifest_and_generated_contract_must_agree(prepared):
    source = Path(prepared[4]["original_manifest"]["path"])
    value = json.loads(source.read_text())
    value["scenarios"][0]["scenario_id"] = "made-up"
    prepared[4]["original_manifest"] = write_json(source, value)
    with pytest.raises(MaterialError, match="original manifest differs"):
        check(repin(prepared))


def test_credited_nonce_belongs_to_exact_scenario_and_attempt(prepared):
    history = Path(prepared[3]["source_indices"][0]["path"]).parent
    source = history / "results/scenario-sst-005.json"
    result = json.loads(source.read_text())
    result["traffic_evidence"]["nonce"] = "sst-006-a1-" + "d" * 32
    write_json(source, result)
    reseal_history(prepared)
    with pytest.raises(MaterialError, match="credited result attempt/nonce invalid"):
        check(repin(prepared))


def test_source_row_must_be_in_the_pinned_index(prepared):
    data = prepared[3]
    index = Path(data["source_indices"][0]["path"])
    value = json.loads(index.read_text())
    value["rows"] = [row for row in value["rows"] if row["path"] != "results/scenario-sst-005.json"]
    data["source_indices"] = [write_json(index, value)]
    with pytest.raises(MaterialError, match="absent from pinned index"):
        check(repin(prepared))


def test_fresh_capacity_does_not_use_historical_free_space(prepared, monkeypatch):
    monkeypatch.setattr(runner.shutil, "disk_usage", lambda path: SimpleNamespace(free=23 * 2 ** 30))
    with pytest.raises(MaterialError, match="fresh offline host/tmp capacity insufficient"):
        check(prepared)


def test_resource_limits_are_not_relaxed_during_migration(prepared):
    prepared[3]["resource_plan"]["ordinary_bytes"] = 512 * 2 ** 20
    with pytest.raises(MaterialError, match="original resource bound differs: ordinary_bytes"):
        check(repin(prepared))


def test_existing_execution_root_is_not_a_preparation_retry(prepared):
    Path(prepared[3]["evidence_root"]).mkdir()
    with pytest.raises(MaterialError, match="unused output roots"):
        check(prepared)
