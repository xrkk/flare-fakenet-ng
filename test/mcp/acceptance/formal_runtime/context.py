"""Read explicitly pinned materials without historical-directory defaults.

Loading establishes input identities only. It grants no instance admission,
mutation, recovery, or formal-pass credit. The runner must apply those gates.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import subprocess
from types import MappingProxyType
from typing import Any, Mapping


SCHEMA = "fakenetng.formal-runtime.materials.v1"
ARGV_SCHEMA = "fakenetng.final100.suite-argv.v1"
IDENTITY_KEYS = frozenset(("candidate", "source", "zip_sha256", "exe_sha256",
                           "manifest_sha256", "default_sha256"))
MATERIAL_KEYS = frozenset(("schema", "candidate_identity", "tool_source", "suite_argv",
                           "plan", "credited_selection", "spike_source", "source_indices",
                           "evidence_root", "audit_root", "physical_namespace", "resource_plan",
                           "protected_sources"))


class MaterialError(ValueError):
    """An explicit material binding is missing, unsafe, or inconsistent."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise MaterialError(reason)


def _digest(value: Any, length: int, label: str) -> str:
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value)
             is not None, label + " must be a lowercase digest")
    return value


def exact_path(value: Any) -> Path:
    """Refuse aliases and symlinks, including existing output ancestors."""
    _require(isinstance(value, str) and bool(value), "path must be an explicit string")
    path = Path(value)
    _require(path.is_absolute() and str(path) == value and ".." not in path.parts,
             "path must be canonical and absolute: " + value)
    for part in (path, *path.parents):
        _require(not part.is_symlink(), "symlink path refused: " + str(part))
    _require(path.resolve() == path, "path alias refused: " + value)
    return path


def _overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checked_record(value: Any) -> Path:
    _require(isinstance(value, dict) and set(value) == {"path", "size", "sha256"},
             "file record requires exactly path, size, sha256")
    path = exact_path(value["path"])
    _require(type(value["size"]) is int and value["size"] >= 0, "invalid record size")
    _digest(value["sha256"], 64, "record SHA256")
    _require(path.is_file(), "missing regular input: " + str(path))
    _require(path.stat().st_size == value["size"] and
             file_sha256(path) == value["sha256"], "input fingerprint mismatch: " + str(path))
    return path


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=_object)
    except (OSError, ValueError) as exc:
        raise MaterialError("invalid JSON input: " + str(path) + ": " + str(exc)) from exc


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _check_tool_source(value: Any, source_root: Path) -> None:
    _require(isinstance(value, dict) and set(value) == {"commit", "files"},
             "tool_source requires commit and files")
    commit = _digest(value["commit"], 40, "tool source commit")
    files = value["files"]
    _require(isinstance(files, list) and bool(files), "tool source files must be nonempty")
    seen: set[Path] = set()
    for row in files:
        path = checked_record(row)
        _require(path.is_relative_to(source_root / "test" / "mcp"),
                 "tool dependency must be in formal test/mcp source: " + str(path))
        _require(path not in seen, "duplicate tool dependency")
        seen.add(path)
        relative = path.relative_to(source_root).as_posix()
        try:
            original = subprocess.run(
                ["git", "-C", str(source_root), "cat-file", "blob", commit + ":" + relative],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            raise MaterialError("tool dependency absent from pinned commit: " + relative) from exc
        _require(len(original) == row["size"] and hashlib.sha256(original).hexdigest()
                 == row["sha256"], "tool dependency differs from pinned commit: " + relative)


@dataclass(frozen=True)
class RunContext:
    repository_root: Path
    source_root: Path
    evidence_root: Path
    audit_root: Path
    materials_path: Path
    materials_sha256: str
    candidate_identity: Mapping[str, str]
    tool_source: Mapping[str, Any]
    physical_namespace: str
    materials: Mapping[str, Any]

    def revalidate(self) -> "RunContext":
        """Recheck immediately before an action; never accept a changed pin."""
        return load_context(self.materials_path, self.materials_sha256,
                            repository_root=self.repository_root, source_root=self.source_root)


def load_context(materials_json: Path, materials_sha256: str, *,
                 repository_root: Path, source_root: Path | None = None) -> RunContext:
    expected = _digest(materials_sha256, 64, "independent materials SHA256")
    path = exact_path(str(materials_json))
    repo = exact_path(str(repository_root))
    source = exact_path(str(source_root if source_root is not None else repo))
    _require(repo.is_dir() and source.is_dir(), "repository/source root missing")
    _require(path.is_file() and path.stat().st_size <= 4 * 1024 * 1024,
             "materials must be a regular file of at most 4 MiB")
    raw = path.read_bytes()
    _require(hashlib.sha256(raw).hexdigest() == expected, "independent materials SHA256 mismatch")
    try:
        data = json.loads(raw, object_pairs_hook=_object)
    except (ValueError, UnicodeError) as exc:
        raise MaterialError("invalid materials JSON: " + str(exc)) from exc
    _require(isinstance(data, dict) and set(data) == MATERIAL_KEYS and data["schema"] == SCHEMA,
             "materials schema/fields mismatch")
    identity = data["candidate_identity"]
    _require(isinstance(identity, dict) and set(identity) == IDENTITY_KEYS, "candidate identity fields mismatch")
    _require(isinstance(identity["candidate"], str) and bool(identity["candidate"]), "candidate ID missing")
    for key in IDENTITY_KEYS - {"candidate"}:
        _digest(identity[key], 40 if key == "source" else 64, "candidate " + key)
    _check_tool_source(data["tool_source"], source)
    inputs = [path]
    argv = data["suite_argv"]
    _require(isinstance(argv, dict) and set(argv) == {"benign", "fault"}, "both suite argv records required")
    for row in argv.values():
        inputs.append(checked_record(row))
    for name in ("plan", "credited_selection", "spike_source"):
        inputs.append(checked_record(data[name]))
    indices = data["source_indices"]
    _require(isinstance(indices, list) and bool(indices), "explicit source indices required")
    for row in indices:
        inputs.append(checked_record(row))
    inputs.extend(exact_path(row["path"]) for row in data["tool_source"]["files"])
    protection = data["protected_sources"]
    _require(isinstance(protection, list), "protected_sources must be a path list")
    protected = [exact_path(item) for item in protection]
    _require(all(item.exists() for item in protected), "protected source missing")
    evidence = exact_path(data["evidence_root"])
    audit = exact_path(data["audit_root"])
    plan = read_json(exact_path(data["plan"]["path"]))
    _require(isinstance(plan, dict) and plan.get("identity") == identity
             and plan.get("root") == str(evidence)
             and plan.get("physical_namespace") == data["physical_namespace"],
             "plan candidate/root/namespace differs from materials")
    for kind, row in argv.items():
        invocation = read_json(exact_path(row["path"]))
        _require(isinstance(invocation, dict) and invocation.get("schema") == ARGV_SCHEMA,
                 "suite argv schema mismatch")
        values = invocation.get("argv")
        _require(isinstance(values, list) and bool(values)
                 and all(isinstance(item, str) for item in values)
                 and values[0] == "run" and values.count("--stop-on-first-failure") == 1,
                 "suite argv must be an explicit stop-on-first-failure run")
        for flag, wanted in (("--candidate-id", identity["candidate"]),
                             ("--source-commit", identity["source"]),
                             ("--package-sha256", identity["zip_sha256"]),
                             ("--suite-root", str(evidence)), ("--filter", kind)):
            _require(values.count(flag) == 1 and values.index(flag) + 1 < len(values)
                     and values[values.index(flag) + 1] == wanted,
                     "suite argv binding mismatch: " + flag)
    logs = repo / "Logs"
    for output in (evidence, audit):
        _require(output != logs and output.is_relative_to(logs), "outputs must be children of repository Logs")
        _require(not _overlap(output, source / "test") and
                 not any(_overlap(output, item) for item in inputs + protected),
                 "output overlaps input/protected source")
        _require(not output.exists() or output.is_dir(), "output root must be a directory")
    _require(not _overlap(evidence, audit), "business and audit roots overlap")
    namespace = data["physical_namespace"]
    _require(isinstance(namespace, str) and PureWindowsPath(namespace).is_absolute()
             and PureWindowsPath(namespace).drive.upper() == "E:"
             and ".." not in PureWindowsPath(namespace).parts,
             "physical namespace must be an explicit absolute E-drive path")
    resource = data["resource_plan"]
    _require(isinstance(resource, dict) and bool(resource), "explicit resource plan required")
    return RunContext(repo, source, evidence, audit, path, expected, _freeze(identity),
                      _freeze(data["tool_source"]), namespace, _freeze(data))
