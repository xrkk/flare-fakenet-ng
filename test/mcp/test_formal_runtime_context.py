"""Material pins and Git source bindings are independent trust anchors."""

import hashlib
import json
import os
import tempfile
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / "acceptance"))
from formal_runtime.context import MaterialError, SCHEMA, load_context


def write_json(path, data):
    # newline="\n" keeps the JSON bytes platform-identical: the default
    # text mode would translate LF to CRLF on Windows Python and desync
    # recorded sizes/hashes from the pinned material fingerprints.
    path.write_text(json.dumps(data), encoding="utf-8", newline="\n")
    return record(path)


def record(path):
    raw = path.read_bytes()
    return {"path": str(path), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE,
                                   text=True).strip()


@pytest.fixture
def materials(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    source = root / "test/mcp/acceptance/helper.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n")
    git(root, "init", "-q")
    git(root, "add", "test/mcp/acceptance/helper.py")
    git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-qm", "isolated fixture")
    commit = git(root, "rev-parse", "HEAD")
    inputs = root / "Logs/inputs"
    inputs.mkdir(parents=True)
    identity = {"candidate": "test-candidate", "source": "c" * 40,
                **{key: "a" * 64 for key in
                   ("zip_sha256", "exe_sha256", "manifest_sha256", "default_sha256")}}
    evidence = root / "Logs/business"
    plan = {"identity": identity, "root": str(evidence), "physical_namespace": r"E:\evidence\test-run"}
    argv = {}
    for kind in ("benign", "fault"):
        argv[kind] = write_json(inputs / (kind + ".json"), {
            "schema": "fakenetng.final100.suite-argv.v1", "argv": [
                "run", "--candidate-id", identity["candidate"], "--source-commit", identity["source"],
                "--package-sha256", identity["zip_sha256"], "--suite-root", str(evidence),
                "--filter", kind, "--stop-on-first-failure"]})
    data = {"schema": SCHEMA, "candidate_identity": identity,
            "tool_source": {"commit": commit, "files": [record(source)]}, "suite_argv": argv,
            "plan": write_json(inputs / "plan.json", plan),
            "credited_selection": write_json(inputs / "selection.json", {}),
            "spike_source": write_json(inputs / "spike.json", {}),
            "source_indices": [write_json(inputs / "index.json", {"rows": []})],
            "evidence_root": str(evidence), "audit_root": str(root / "Logs/audit"),
            "physical_namespace": plan["physical_namespace"],
            "resource_plan": {"host_reserve_bytes": 24 * 2 ** 30}, "protected_sources": [str(inputs)]}
    path = inputs / "materials.json"
    pin = write_json(path, data)["sha256"]
    return root, path, pin, data


def load(values):
    root, path, pin, _ = values
    return load_context(path, pin, repository_root=root)


def test_explicit_context_is_readonly_and_does_not_create_output(materials):
    context = load(materials)
    assert context.tool_source["commit"] != context.candidate_identity["source"]
    assert not context.evidence_root.exists() and not context.audit_root.exists()
    with pytest.raises(TypeError):
        context.materials["resource_plan"]["host_reserve_bytes"] = 0
    assert context.revalidate().materials_sha256 == context.materials_sha256


def test_material_and_internal_fingerprint_tamper_cannot_change_external_pin(materials):
    _, path, _, data = materials
    referenced = Path(data["credited_selection"]["path"])
    data["credited_selection"] = write_json(referenced, {"sst-010": "forged"})
    write_json(path, data)
    with pytest.raises(MaterialError, match="independent materials SHA256 mismatch"):
        load(materials)


def test_changed_referenced_file_rejected_before_action(materials):
    Path(materials[3]["spike_source"]["path"]).write_text("changed")
    with pytest.raises(MaterialError, match="input fingerprint mismatch"):
        load(materials)


def test_worktree_fingerprint_cannot_replace_pinned_git_blob(materials):
    root, path, _, data = materials
    helper = Path(data["tool_source"]["files"][0]["path"])
    helper.write_text("VALUE = 2\n")
    data["tool_source"]["files"] = [record(helper)]
    pin = write_json(path, data)["sha256"]
    with pytest.raises(MaterialError, match="differs from pinned commit"):
        load_context(path, pin, repository_root=root)


@pytest.mark.parametrize("change,reason", [
    (lambda d: d.pop("source_indices"), "schema/fields"),
    (lambda d: d["plan"].update(size=True), "invalid record size"),
    (lambda d: d.update(audit_root=d["evidence_root"]), "roots overlap"),
    (lambda d: d.update(evidence_root=d["protected_sources"][0]), "plan candidate/root"),
    (lambda d: d["candidate_identity"].update(candidate="other"), "plan candidate/root"),
    (lambda d: d.update(physical_namespace=r"C:\Program Files\FakeNet"), "plan candidate/root"),
])
def test_invalid_material_contract_refused(materials, change, reason):
    root, path, _, data = materials
    change(data)
    pin = write_json(path, data)["sha256"]
    with pytest.raises(MaterialError, match=reason):
        load_context(path, pin, repository_root=root)


def _can_symlink():
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, 't')
            link = os.path.join(tmp, 'l')
            os.mkdir(target)
            os.symlink(target, link, target_is_directory=True)
            # Some Wine configurations silently materialize a copy instead
            # of a real link; refusing a symlink requires a true link.
            return os.path.islink(link)
    except OSError:
        return False


@pytest.mark.skipif(not _can_symlink(), reason='symlink creation unavailable')
def test_output_symlink_refused(materials):
    root, path, _, data = materials
    outside = root.parent / "outside"
    outside.mkdir()
    (root / "Logs/link").symlink_to(outside, target_is_directory=True)
    assert (root / "Logs/link").is_symlink()
    data["audit_root"] = str(root / "Logs/link/new")
    pin = write_json(path, data)["sha256"]
    with pytest.raises(MaterialError, match="symlink path refused"):
        load_context(path, pin, repository_root=root)


def test_argv_wrong_filter_is_not_a_valid_bound_run(materials):
    root, path, _, data = materials
    argv_path = Path(data["suite_argv"]["benign"]["path"])
    argv = json.loads(argv_path.read_text())
    argv["argv"][argv["argv"].index("--filter") + 1] = "fault"
    data["suite_argv"]["benign"] = write_json(argv_path, argv)
    pin = write_json(path, data)["sha256"]
    with pytest.raises(MaterialError, match="suite argv binding mismatch: --filter"):
        load_context(path, pin, repository_root=root)


def test_two_contexts_have_no_mutable_shared_input(materials):
    first = load(materials)
    _, path, _, data = materials
    data["resource_plan"]["host_reserve_bytes"] = 48 * 2 ** 30
    new_pin = write_json(path, data)["sha256"]
    second = load_context(path, new_pin, repository_root=materials[0])
    assert first.materials["resource_plan"]["host_reserve_bytes"] == 24 * 2 ** 30
    assert second.materials["resource_plan"]["host_reserve_bytes"] == 48 * 2 ** 30
    with pytest.raises(MaterialError, match="independent materials SHA256 mismatch"):
        first.revalidate()


def test_output_overlapping_input_refused_even_with_consistent_plan(materials):
    root, path, _, data = materials
    data["evidence_root"] = str(Path(data["plan"]["path"]).parent)
    plan = json.loads(Path(data["plan"]["path"]).read_text())
    plan["root"] = data["evidence_root"]
    data["plan"] = write_json(Path(data["plan"]["path"]), plan)
    for row in data["suite_argv"].values():
        argv_path = Path(row["path"])
        argv = json.loads(argv_path.read_text())
        argv["argv"][argv["argv"].index("--suite-root") + 1] = data["evidence_root"]
        row.update(write_json(argv_path, argv))
    pin = write_json(path, data)["sha256"]
    with pytest.raises(MaterialError, match="output overlaps input/protected source"):
        load_context(path, pin, repository_root=root)


def test_import_has_no_business_or_write_side_effects(tmp_path):
    acceptance = Path(__file__).parent / "acceptance"
    command = '''
import sys, socket, subprocess
def deny(*args, **kwargs):
    raise AssertionError("business action during import")
socket.socket = deny
socket.create_connection = deny
subprocess.Popen = deny
def audit(event, args):
    if event == "open":
        mode, flags = args[1], args[2]
        if (isinstance(mode, str) and any(x in mode for x in "wax+")) or flags & 3:
            raise AssertionError("write during import")
sys.addaudithook(audit)
import formal_runtime
import formal_runtime.context
assert not any(name in sys.modules for name in ("relocation", "audit_child", "spike_driver"))
'''
    response = subprocess.run([sys.executable, "-B", "-c",
                               "import sys;sys.path.insert(0," + repr(str(acceptance)) + ");" + command],
                              cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert response.returncode == 0, response.stderr
    assert not list(tmp_path.iterdir())
