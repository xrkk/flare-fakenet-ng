#!/usr/bin/env python3
"""Execute one immutable formal FakeNet100 batch of one to five manifest rows.

V3 (T014/R02): retain V2's IPC recovery and re-adjudicate each immutable
online pass from raw traffic before scheduling the next scenario. V2 and the
original formal_batch.py remain frozen.

This is a versioned host adapter around ``scenario_suite.Suite``.  It does
not generate or alter a manifest, alter an acceptance rule, translate a
failure to pass, retry an existing result, or provide a new fault gate.  Its
only scheduling policy is: execute the explicitly selected one-to-five rows
in their supplied explicit order, record both continuation gates, and stop scheduling after
the first non-pass or gate/tool failure.

The standard Suite argv is supplied as a JSON object so the exact candidate,
deployment, endpoint, and fault-spike inputs are freezeable before the batch.
The object is deliberately small and explicit::

  {"schema":"fakenetng.final100.suite-argv.v1", "argv":["run", ...]}

``argv`` contains the arguments that follow ``scenario_suite.py``.  It must
be a valid ``run`` invocation, including ``--filter``.  A benign batch may
contain only benign manifest rows; a fault batch may contain only fault rows
and relies on Suite's existing ``_require_fault_spike`` check.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import traceback
from typing import Any


REPO = Path(__file__).resolve().parents[3]
FINAL_ROOT = REPO / "Logs" / "fakenetng-mcp" / "final100-20260920"
ACCEPTANCE = REPO / "test" / "mcp" / "acceptance"
ARGV_SCHEMA = "fakenetng.final100.suite-argv.v1"
START_SCHEMA = "fakenetng.final100.formal-batch.start.v1"
TERMINAL_SCHEMA = "fakenetng.final100.formal-batch.terminal.v1"
BATCH_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")

sys.path.insert(0, str(REPO))
sys.path.insert(0, str(ACCEPTANCE))
import scenario_suite as suite_mod  # noqa: E402


def record(path: Path, relative_to: Path | None = None) -> dict[str, Any]:
    raw = path.read_bytes()
    try:
        shown = str(path.relative_to(relative_to)) if relative_to else str(path)
    except ValueError:
        shown = str(path)
    return {"path": shown, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        stream.write("\n")


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        stream.write("\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite-argv-json", required=True, type=Path,
                        help="frozen fakenetng.final100.suite-argv.v1 JSON")
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--scenario-id", action="append", dest="scenario_ids", required=True,
                        help="explicit manifest scenario ID; repeat one to five times")
    return parser.parse_args(argv)


def load_suite_args(path: Path) -> argparse.Namespace:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit("suite argv JSON is unreadable: %r" % (exc,)) from exc
    if not isinstance(raw, dict) or raw.get("schema") != ARGV_SCHEMA:
        raise SystemExit("suite argv JSON schema must be " + ARGV_SCHEMA)
    values = raw.get("argv")
    if (not isinstance(values, list) or not values or
            any(not isinstance(value, str) for value in values)):
        raise SystemExit("suite argv JSON argv must be a non-empty string list")
    try:
        parsed = suite_mod.parse_args(values)
    except SystemExit as exc:
        raise SystemExit("suite argv JSON is not a valid scenario_suite command") from exc
    if parsed.command != "run" or parsed.filter not in ("benign", "fault"):
        raise SystemExit("suite argv JSON must be a scenario_suite run with --filter benign|fault")
    if not parsed.stop_on_first_failure:
        raise SystemExit("suite argv JSON must include --stop-on-first-failure")
    return parsed


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def validate_inputs(runner: Any, args: argparse.Namespace, batch_id: str,
                    scenario_ids: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    if not BATCH_ID_RE.fullmatch(batch_id):
        raise SystemExit("batch-id must match " + BATCH_ID_RE.pattern)
    if not 1 <= len(scenario_ids) <= 5:
        raise SystemExit("a formal batch contains one to five explicit scenario IDs")
    if len(set(scenario_ids)) != len(scenario_ids):
        raise SystemExit("scenario IDs must be unique within a formal batch")
    if runner.root.resolve() == FINAL_ROOT.resolve() or not _inside(runner.root, FINAL_ROOT):
        raise SystemExit("suite-root must be a new child directory under " + str(FINAL_ROOT))
    manifest = runner.manifest()
    rows = {str(row.get("scenario_id")): row for row in manifest.get("scenarios", [])}
    selected: list[dict[str, Any]] = []
    for scenario_id in scenario_ids:
        row = rows.get(scenario_id)
        if not isinstance(row, dict):
            raise SystemExit("scenario is absent from this manifest: " + scenario_id)
        is_fault = row.get("fault_class") is not None
        if (args.filter == "fault") != is_fault:
            raise SystemExit("scenario filter does not match manifest fault class: " + scenario_id)
        result_path = runner._result_path(scenario_id)
        state_path = runner._state_path(scenario_id)
        if result_path.exists() or state_path.exists():
            raise SystemExit("scenario already has immutable state/result in this root: " + scenario_id)
        selected.append(row)
    batch_root = runner.root / "formal-batches" / batch_id
    if batch_root.exists():
        raise SystemExit("formal batch ID already exists; do not resume or overwrite it: " + batch_id)
    # Use Suite's actual gates.  The fault gate is intentionally not reimplemented
    # here; this preserves candidate/manifest/hash validation in scenario_suite.
    runner.require_clients()
    preflight = runner._require_preflight()
    if args.filter == "fault":
        runner._require_fault_spike()
    return selected, manifest, preflight


def run_batch(runner: Any, suite_args: argparse.Namespace, suite_argv_path: Path,
              batch_id: str, selected: list[dict[str, Any]], manifest: dict[str, Any],
              preflight: dict[str, Any]) -> dict[str, Any]:
    """Run selected rows, returning only a record of their stored outcomes.

    This function is intentionally independent from VM construction so the
    self-check can prove the scheduler's first-failure boundary with a stub.
    """
    batch_root = runner.root / "formal-batches" / batch_id
    ledger = batch_root / "ledger.jsonl"
    manifest_before = record(runner.manifest_path, runner.root)
    driver_record = record(Path(__file__).resolve(), REPO)
    start = {
        "schema": START_SCHEMA,
        "mode": "formal-acceptance",
        "batch_id": batch_id,
        "scenario_ids": [row["scenario_id"] for row in selected],
        "identity": runner.identity.as_dict(),
        "suite_argv": record(suite_argv_path, REPO),
        "manifest": manifest_before,
        "preflight": record(runner.preflight_path, runner.root),
        "preflight_passed": bool(preflight.get("passed")),
        "driver": driver_record,
        "fault_spike_result": (record(Path(suite_args.fault_spike_result), REPO)
                               if suite_args.filter == "fault" else None),
    }
    write_new_json(batch_root / "start.json", start)
    events: list[dict[str, Any]] = []
    status = "complete"
    stop_reason: str | None = None
    not_executed: list[str] = []
    ipc_evidence: dict[str, Any] = {}
    ipc_attempted = False
    active_index: int | None = None
    active_scenario_id: str | None = None
    run_started = False
    batch_error: dict[str, Any] | None = None

    try:
        # This is the same batch-level environment arm/restore used by
        # Suite.run.  It is required for every exported run's ipc-parent
        # evidence, including benign rows; a formal adapter must not silently
        # omit it merely because it schedules a subset of the manifest.
        # The recovery responsibility starts before the arming call itself:
        # a partially applied arming that raises must still be disabled once.
        ipc_attempted = True
        ipc_evidence["attempted"] = True
        ipc_evidence["enabled"] = runner._ipc_evidence_mode(True)
        write_new_json(batch_root / "ipc-evidence-enabled.json", ipc_evidence["enabled"])
    except BaseException as exc:
        event = {"event": "not-executed", "classification": "tool_error",
                 "reason": "IPC evidence enable failed: " + repr(exc),
                 "traceback": traceback.format_exc(limit=8)}
        try:
            append_jsonl(ledger, event)
        except BaseException as write_exc:
            event["ledger_error"] = repr(write_exc)
        events.append(event)
        status, stop_reason = "failed", event["reason"]
        not_executed = [str(row["scenario_id"]) for row in selected]

    try:
        if status == "complete":
            for index, scenario in enumerate(selected):
                active_index = index
                active_scenario_id = str(scenario["scenario_id"])
                run_started = False
                result_path = runner._result_path(active_scenario_id)
                try:
                    pre_gate = runner._continuation_gate()
                except BaseException as exc:  # gate evidence is part of the failure record
                    event = {"event": "not-executed", "scenario_id": active_scenario_id,
                             "ordinal": index + 1, "classification": "environment_blocked",
                             "reason": "pre-scenario continuation gate: " + repr(exc),
                             "traceback": traceback.format_exc(limit=8)}
                    append_jsonl(ledger, event)
                    events.append(event)
                    status, stop_reason = "blocked", event["reason"]
                    not_executed = [str(row["scenario_id"]) for row in selected[index:]]
                    break

                run_started = True
                try:
                    returned = runner._run_one(scenario, 1)
                except BaseException as exc:
                    event = {"event": "executed-without-result", "scenario_id": active_scenario_id,
                             "ordinal": index + 1, "classification": "tool_error",
                             "reason": "_run_one escaped: " + repr(exc), "pre_gate": pre_gate,
                             "result": record(result_path, runner.root) if result_path.is_file() else None,
                             "traceback": traceback.format_exc(limit=8)}
                    append_jsonl(ledger, event)
                    events.append(event)
                    status, stop_reason = "failed", event["reason"]
                    not_executed = [str(row["scenario_id"]) for row in selected[index + 1:]]
                    break

                if not isinstance(returned, dict) or not result_path.is_file():
                    event = {"event": "executed-without-immutable-result", "scenario_id": active_scenario_id,
                             "ordinal": index + 1, "classification": "tool_error",
                             "reason": "_run_one returned without the required immutable result file",
                             "pre_gate": pre_gate,
                             "result": record(result_path, runner.root) if result_path.is_file() else None}
                    append_jsonl(ledger, event)
                    events.append(event)
                    status, stop_reason = "failed", event["reason"]
                    not_executed = [str(row["scenario_id"]) for row in selected[index + 1:]]
                    break

                # The stored original, not the return value, is the outcome
                # bound into the batch ledger.  A malformed original is an
                # adapter failure; the outer finally still restores IPC mode.
                stored = json.loads(result_path.read_text(encoding="utf-8"))
                result_state = stored.get("state")
                traffic_issues = (runner._traffic_recheck_issues(stored, scenario)
                                  if result_state == "pass" else [])
                post_gate: dict[str, Any] | None = None
                post_error: str | None = None
                try:
                    post_gate = runner._continuation_gate()
                except BaseException as exc:
                    post_error = "post-scenario continuation gate: " + repr(exc)
                event = {"event": "executed", "scenario_id": active_scenario_id, "ordinal": index + 1,
                         "state": result_state, "traffic_recheck_issues": traffic_issues,
                         "classification": "pass" if result_state == "pass" and not traffic_issues and not post_error else
                         ("environment_blocked" if post_error else "scenario_fail"),
                         "pre_gate": pre_gate, "post_gate": post_gate, "post_gate_error": post_error,
                         "result": record(result_path, runner.root)}
                append_jsonl(ledger, event)
                events.append(event)
                if result_state != "pass" or traffic_issues or post_error:
                    status = "blocked" if post_error else "failed"
                    stop_reason = (post_error or
                                   ("raw traffic recheck rejected: " + repr(traffic_issues)
                                    if traffic_issues else
                                    "stored result state is " + repr(result_state)))
                    not_executed = [str(row["scenario_id"]) for row in selected[index + 1:]]
                    break
            else:
                not_executed = []
    except BaseException as exc:
        result_path = (runner._result_path(active_scenario_id)
                       if active_scenario_id is not None else None)
        batch_error = {"event": "adapter_error", "scenario_id": active_scenario_id,
                       "ordinal": active_index + 1 if active_index is not None else None,
                       "reason": repr(exc), "traceback": traceback.format_exc(limit=12),
                       "result": (record(result_path, runner.root)
                                  if result_path is not None and result_path.is_file() else None)}
        try:
            append_jsonl(ledger, batch_error)
        except BaseException as write_exc:
            batch_error["ledger_error"] = repr(write_exc)
        events.append(batch_error)
        status, stop_reason = "failed", "formal batch adapter error: " + repr(exc)
        if active_index is None:
            not_executed = [str(row["scenario_id"]) for row in selected]
        elif run_started:
            not_executed = [str(row["scenario_id"]) for row in selected[active_index + 1:]]
        else:
            not_executed = [str(row["scenario_id"]) for row in selected[active_index:]]
    finally:
        # This must run after every parser, ledger, hash, or result exception
        # once the IPC arming was attempted.  A partially applied arming that
        # raised never set "enabled", but the responsibility still stands;
        # the original failure remains in ``batch_error``/``stop_reason``
        # even when restore also fails.
        if ipc_attempted:
            try:
                ipc_evidence["disabled"] = runner._ipc_evidence_mode(False)
            except BaseException as exc:
                ipc_evidence["disabled"] = {"error": repr(exc),
                                             "traceback": traceback.format_exc(limit=8)}
                status = "failed"
                if stop_reason is None:
                    stop_reason = "IPC evidence restore failed: " + repr(exc)
                else:
                    ipc_evidence["restore_error_after"] = repr(exc)
            try:
                write_new_json(batch_root / "ipc-evidence-disabled.json", ipc_evidence["disabled"])
            except BaseException as exc:
                ipc_evidence["disabled_record_error"] = repr(exc)
                status = "failed"
                if stop_reason is None:
                    stop_reason = "IPC evidence restore record failed: " + repr(exc)
        recovery_record = {"schema": "fakenetng.final100.formal-batch.recovery.v1",
                           "batch_id": batch_id, "status": status,
                           "stop_reason": stop_reason, "adapter_error": batch_error,
                           "ipc_evidence": ipc_evidence}
        try:
            write_new_json(batch_root / "recovery.json", recovery_record)
        except BaseException as exc:
            ipc_evidence["recovery_record_error"] = repr(exc)
            status = "failed"
            if stop_reason is None:
                stop_reason = "formal batch recovery record failed: " + repr(exc)

    try:
        manifest_after = record(runner.manifest_path, runner.root)
    except BaseException as exc:
        manifest_after = {"error": repr(exc), "traceback": traceback.format_exc(limit=8)}
        status = "failed"
        if stop_reason is None:
            stop_reason = "manifest final record failed: " + repr(exc)
    if manifest_after.get("sha256") != manifest_before["sha256"]:
        status = "failed"
        if stop_reason is None:
            stop_reason = "scenario manifest changed during formal batch"
        else:
            ipc_evidence["manifest_error_after"] = "scenario manifest changed during formal batch"
    terminal = {
        "schema": TERMINAL_SCHEMA,
        "mode": "formal-acceptance",
        "batch_id": batch_id,
        "identity": runner.identity.as_dict(),
        "status": status,
        "passed": status == "complete",
        "stop_reason": stop_reason,
        "events": events,
        "not_executed": not_executed,
        "manifest_before": manifest_before,
        "manifest_after": manifest_after,
        "ledger": record(ledger, runner.root) if ledger.is_file() else None,
        "ipc_evidence": ipc_evidence,
        "recovery": record(batch_root / "recovery.json", runner.root)
        if (batch_root / "recovery.json").is_file() else None,
    }
    try:
        write_new_json(batch_root / "terminal.json", terminal)
    except BaseException as exc:
        # recovery.json is deliberately written before terminal.json so an
        # evidence-volume failure still leaves a distinct attempted-restore
        # record rather than masking the original batch error.
        terminal["terminal_record_error"] = repr(exc)
        status = "failed"
        terminal["status"] = status
        terminal["passed"] = False
    return terminal


def main(argv: list[str] | None = None) -> int:
    options = parse_args(argv)
    suite_args = load_suite_args(options.suite_argv_json.resolve())
    runner = suite_mod.Suite(suite_args)
    selected, manifest, preflight = validate_inputs(runner, suite_args, options.batch_id,
                                                     options.scenario_ids)
    terminal = run_batch(runner, suite_args, options.suite_argv_json.resolve(), options.batch_id,
                         selected, manifest, preflight)
    print(json.dumps({"batch_id": options.batch_id, "status": terminal["status"],
                      "passed": terminal["passed"], "not_executed": terminal["not_executed"]},
                     ensure_ascii=False, sort_keys=True))
    return 0 if terminal["passed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
