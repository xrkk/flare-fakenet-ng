"""Offline contracts for the per-candidate scenario result ledger."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

import pytest


LEDGER_PATH = Path(__file__).parent / 'acceptance' / 'scenario_result_ledger.py'
SPEC = importlib.util.spec_from_file_location('scenario_result_ledger_test_module', LEDGER_PATH)
ledger = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ledger
SPEC.loader.exec_module(ledger)


IDENTITY_A = {'candidate_id': 'mcp-cand-a', 'source_commit': 'a' * 40, 'package_sha256': '1' * 64}
IDENTITY_B = {'candidate_id': 'mcp-cand-b', 'source_commit': 'b' * 40, 'package_sha256': '2' * 64}


def write_result(root: Path, batch: str, scenario_id: str, state: str, identity: dict,
                 filename: str | None = None):
    directory = root / batch / 'results'
    directory.mkdir(parents=True, exist_ok=True)
    payload = {'schema': 'fakenetng.mcp-scenario.v1', 'scenario_id': scenario_id,
               'state': state, 'identity': dict(identity)}
    path = directory / (filename or ('scenario-%s.json' % scenario_id))
    path.write_text(json.dumps(payload), encoding='utf-8')
    return path


def build_root() -> Path:
    """Two candidates over a shared id universe; sst-004 never passes."""
    root = Path(tempfile.mkdtemp())
    # Candidate A passes 001/002, fails 004; candidate B passes 004? no —
    # nobody passes 004.  B passes 002 only, so the union stays separated.
    write_result(root, 'discovery100-01', 'sst-001', 'pass', IDENTITY_A)
    write_result(root, 'discovery100-01', 'sst-002', 'fail', IDENTITY_A)
    write_result(root, 'discovery100-02', 'sst-002', 'pass', IDENTITY_A)
    write_result(root, 'discovery100-02', 'sst-004', 'fail', IDENTITY_A)
    write_result(root, 'discovery100-03', 'sst-002', 'pass', IDENTITY_B)
    write_result(root, 'discovery100-03', 'sst-004', 'fail', IDENTITY_B)
    return root


def run_main(root: Path, output: Path, *extra: str) -> tuple[int, dict | None]:
    code = ledger.main(['--evidence-root', str(root), '--output-dir', str(output), *extra])
    ledger_path = output / 'ledger.json'
    value = json.loads(ledger_path.read_text(encoding='utf-8')) if ledger_path.is_file() else None
    return code, value


def test_ledger_groups_by_candidate_and_reports_union_separately():
    with tempfile.TemporaryDirectory() as temp:
        root = build_root()
        out = Path(temp) / 'ledger-out'
        code, value = run_main(root, out)
        assert code == 0, value
        assert value['result_count'] == 6
        assert value['id_universe']['ids'] == ['sst-001', 'sst-002', 'sst-004']
        candidates = value['candidates']
        assert candidates['mcp-cand-a']['ever_pass_ids'] == ['sst-001', 'sst-002']
        assert candidates['mcp-cand-b']['ever_pass_ids'] == ['sst-002']
        # The union is labelled as a union, never as one candidate's verdict.
        union = value['ever_pass_union_across_candidates']
        assert union['ids'] == ['sst-001', 'sst-002'] and union['count'] == 2
        assert 'not a single-candidate verdict' in union['note']
        # Missing ids are per candidate against the shared universe.
        assert 'sst-004' in candidates['mcp-cand-a']['missing_ids']
        assert candidates['mcp-cand-b']['missing_ids'] == ['sst-001', 'sst-004']
        # A retry that moved from fail to pass is recorded as a state conflict.
        conflicts = {row['scenario_id']: row['states']
                     for row in candidates['mcp-cand-a']['state_conflicts']}
        assert conflicts == {'sst-002': ['fail', 'pass']}
        # Every record carries the full candidate identity and content hash.
        record = next(row for row in value['records'] if row['scenario_id'] == 'sst-001')
        assert record['identity'] == IDENTITY_A and record['batch'] == 'discovery100-01'
        raw = (root / 'discovery100-01' / 'results' / 'scenario-sst-001.json').read_bytes()
        assert record['sha256'] == hashlib.sha256(raw).hexdigest()
        # No --candidate given: nothing selected, nothing guessed.
        assert value['selected_candidate'] is None
        summary = (out / 'summary.md').read_text(encoding='utf-8')
        assert 'no candidate was selected or guessed' in summary
        assert 'not a candidate verdict' in summary


def test_ledger_selected_candidate_view_is_strictly_that_candidate():
    with tempfile.TemporaryDirectory() as temp:
        root = build_root()
        out = Path(temp) / 'ledger-out'
        code, value = run_main(root, out, '--candidate', 'mcp-cand-b')
        assert code == 0, value
        selected = value['selected_candidate']
        assert selected['candidate_id'] == 'mcp-cand-b'
        assert selected['ever_pass_ids'] == ['sst-002']
        assert selected['missing_ids'] == ['sst-001', 'sst-004']
        assert selected['covers_id_universe'] is False
        # The other candidate's pass never leaks into the selected view.
        assert 'sst-001' not in selected['ever_pass_ids']
        summary = (out / 'summary.md').read_text(encoding='utf-8')
        assert 'mcp-cand-b' in summary and 'sst-004' in summary


def test_ledger_flags_duplicate_ids_within_one_batch():
    with tempfile.TemporaryDirectory() as temp:
        root = build_root()
        write_result(root, 'discovery100-01', 'sst-001', 'fail', IDENTITY_A,
                     filename='scenario-copy.json')
        out = Path(temp) / 'ledger-out'
        code, value = run_main(root, out)
        assert code == 2
        assert any('appears in 2 result files within batch discovery100-01' in issue
                   for row in value['anomalies'] for issue in row['issues'])
        summary = (out / 'summary.md').read_text(encoding='utf-8')
        assert 'Structural anomalies' in summary


def test_ledger_records_corrupted_json_and_exits_nonzero(capsys):
    with tempfile.TemporaryDirectory() as temp:
        root = build_root()
        (root / 'discovery100-02' / 'results' / 'scenario-sst-004.json').write_text(
            '{not json', encoding='utf-8')
        out = Path(temp) / 'ledger-out'
        code, value = run_main(root, out)
        assert code == 2
        assert value['read_errors'] and value['read_errors'][0]['path'].endswith(
            'scenario-sst-004.json')
        diagnostics = capsys.readouterr().err
        assert 'unreadable result' in diagnostics and 'scenario-sst-004.json' in diagnostics
        # The parseable records are still counted; the ledger stays honest.
        assert value['result_count'] == 5


def test_ledger_rejects_output_overlapping_input():
    with tempfile.TemporaryDirectory() as temp:
        root = build_root()
        inside = root / 'discovery100-01' / 'results' / 'ledger-out'
        assert ledger.main(['--evidence-root', str(root), '--output-dir', str(inside)]) == 2
        assert not inside.exists()
        # A directory that would contain the whole evidence input is rejected
        # just the same: writing under it covers the inputs.
        covering = root.parent
        assert ledger.main(['--evidence-root', str(root), '--output-dir', str(covering)]) == 2
        missing_root = Path(temp) / 'absent'
        assert ledger.main(['--evidence-root', str(missing_root),
                            '--output-dir', str(Path(temp) / 'o')]) == 2


def test_ledger_rejects_unknown_candidate():
    with tempfile.TemporaryDirectory() as temp:
        root = build_root()
        out = Path(temp) / 'ledger-out'
        assert ledger.main(['--evidence-root', str(root), '--output-dir', str(out),
                            '--candidate', 'mcp-nobody']) == 2
        assert not (out / 'ledger.json').exists()


def test_ledger_help_documents_actual_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        ledger.parse_args(['--help'])
    assert exc.value.code == 0
    text = capsys.readouterr().out
    for flag in ('--evidence-root', '--output-dir', '--candidate'):
        assert flag in text
    with pytest.raises(SystemExit):
        ledger.parse_args([])  # required arguments are enforced


def test_ledger_matches_completion_recheck_aggregate_on_real_evidence():
    """Reconcile the real 591-record scan against the 2026-09-20 aggregate."""
    repo = Path(__file__).resolve().parents[2]
    root = repo / 'Logs/fakenetng-mcp/unified-repair-20260913/7ec8eff-loop'
    aggregate_path = repo / 'Logs/fakenetng-mcp/completion-recheck-20260920/aggregate.json'
    if not root.is_dir() or not aggregate_path.is_file():
        return  # local acceptance evidence, kept out of the repository
    with tempfile.TemporaryDirectory() as temp:
        out = Path(temp) / 'ledger-out'
        code, value = run_main(root, out)
        assert code == 0
        assert value['batch_count'] == 121 and value['result_count'] == 591
        aggregate = json.loads(aggregate_path.read_text(encoding='utf-8'))
        prefix = str(root.relative_to(repo)) + '/'
        by_path = {row['path'][len(prefix):]: row for row in aggregate['results']}
        ledger_by_path = {row['path']: row for row in value['records']}
        assert set(ledger_by_path) == set(by_path)
        for path, row in ledger_by_path.items():
            assert row['sha256'] == by_path[path]['sha256'], path
            assert row['state'] == by_path[path]['state'], path
            assert row['identity'] == by_path[path]['identity'], path
        union = value['ever_pass_union_across_candidates']
        assert union['count'] == aggregate['pass_distinct'] == 99
        assert value['id_universe']['count'] == aggregate['attempted_distinct'] == 100
        # The aggregate lists only candidates holding passes; the ledger also
        # holds candidates that only attempted — restrict the comparison.
        pass_by_candidate = {cid: sorted(group['ever_pass_ids'])
                             for cid, group in value['candidates'].items()
                             if group['ever_pass_ids']}
        assert pass_by_candidate == aggregate['pass_by_candidate']
        assert len(value['candidates']) >= len(aggregate['pass_by_candidate'])
        # sst-004 stays missing for every candidate that attempted it.
        assert all('sst-004' in group['missing_ids'] for group in value['candidates'].values())
