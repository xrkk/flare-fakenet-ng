"""Per-candidate machine ledger over stored discovery100 scenario results.

This tool is statistics over originally stored result JSONs.  It never
re-adjudicates traffic, faults or integrity, and a stored ``state`` value is
recorded fact, not a re-acceptance verdict.  Historical ever-pass per
candidate and a selected candidate's own coverage are strictly separated;
the union of ever-pass ids across candidates is reported as a union only and
is never presented as one candidate's 100-scenario verification.

Usage:
    python scenario_result_ledger.py --evidence-root <dir> \\
        --output-dir <dir> [--candidate <candidate_id>]

Exit codes: 0 on a clean ledger; 2 on input/parse errors with diagnostics
on stderr (the ledger file still records the errors for forensics).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

SCHEMA = 'fakenetng.scenario-result-ledger.v1'
LEDGER_NOTE = ('stored-result statistics; state values are recorded facts '
               'and are not re-acceptance verdicts')


class LedgerError(RuntimeError):
    """Fatal input error: the ledger cannot be built as requested."""


def _batch_sort_key(path: Path):
    suffix = path.name.rsplit('-', 1)[-1]
    return (0, int(suffix), path.name) if suffix.isdigit() else (1, 0, path.name)


def scan_evidence(evidence_root: Path) -> dict[str, object]:
    """Scan ``discovery100-*/results/scenario-*.json`` under the root."""
    batches = sorted((entry for entry in evidence_root.glob('discovery100-*') if entry.is_dir()),
                     key=_batch_sort_key)
    if not batches:
        raise LedgerError('no discovery100-* batch directories under evidence root: %s' % evidence_root)
    records: list[dict] = []
    read_errors: list[dict] = []
    anomalies: list[dict] = []
    for batch in batches:
        results_dir = batch / 'results'
        paths = sorted(results_dir.glob('scenario-*.json')) if results_dir.is_dir() else []
        seen_ids: dict[str, int] = {}
        for path in paths:
            relative = str(path.relative_to(evidence_root)).replace('\\', '/')
            record = {'path': relative, 'batch': batch.name}
            try:
                raw = path.read_bytes()
                value = json.loads(raw)
            except (OSError, ValueError) as exc:
                read_errors.append({'path': relative, 'error': str(exc)})
                continue
            record['sha256'] = hashlib.sha256(raw).hexdigest()
            issues: list[str] = []
            if not isinstance(value, dict):
                issues.append('result is not a JSON object')
                value = {}
            scenario_id = value.get('scenario_id')
            state = value.get('state')
            identity = value.get('identity')
            if not isinstance(scenario_id, str) or not scenario_id:
                issues.append('scenario_id missing or not a string')
                scenario_id = None
            if not isinstance(state, str) or not state:
                issues.append('state missing or not a string')
                state = None
            if (not isinstance(identity, dict) or
                    not isinstance(identity.get('candidate_id'), str) or
                    not identity.get('candidate_id')):
                issues.append('identity/candidate_id missing or malformed')
                identity = None
            if scenario_id is not None and path.name != 'scenario-%s.json' % scenario_id:
                issues.append('result filename %s does not match scenario_id %s'
                              % (path.name, scenario_id))
            if issues:
                anomalies.append({'path': relative, 'issues': issues})
            if scenario_id is not None:
                seen_ids[scenario_id] = seen_ids.get(scenario_id, 0) + 1
            if scenario_id is not None and state is not None and identity is not None:
                records.append({**record, 'scenario_id': scenario_id, 'state': state,
                                'identity': dict(identity)})
        for scenario_id, count in sorted(seen_ids.items()):
            if count > 1:
                anomalies.append({'path': '%s/results' % batch.name,
                                  'issues': ['scenario_id %s appears in %d result files within batch %s'
                                             % (scenario_id, count, batch.name)]})
    return {'batch_names': [batch.name for batch in batches], 'records': records,
            'read_errors': read_errors, 'anomalies': anomalies}


def build_ledger(evidence_root: Path, scan: dict, selected_candidate: str | None) -> dict:
    """Group the scanned records per candidate; never merge candidates."""
    records: list[dict] = scan['records']
    universe = sorted({record['scenario_id'] for record in records})
    universe_set = set(universe)
    grouped: dict[str, list[dict]] = {}
    for record in records:
        grouped.setdefault(record['identity']['candidate_id'], []).append(record)
    candidates: dict[str, dict] = {}
    for candidate_id in sorted(grouped):
        attempts = grouped[candidate_id]
        identities: list[dict] = []
        for record in attempts:
            if record['identity'] not in identities:
                identities.append(record['identity'])
        attempted_ids = sorted({record['scenario_id'] for record in attempts})
        pass_ids = sorted({record['scenario_id'] for record in attempts
                           if record['state'] == 'pass'})
        pass_set = set(pass_ids)
        state_counts: dict[str, int] = {}
        for record in attempts:
            state_counts[record['state']] = state_counts.get(record['state'], 0) + 1
        conflicts = []
        for scenario_id in attempted_ids:
            states = sorted({record['state'] for record in attempts
                             if record['scenario_id'] == scenario_id})
            if len(states) > 1:
                conflicts.append({'scenario_id': scenario_id, 'states': states})
        candidates[candidate_id] = {
            'identity_variants': identities,
            'identity_conflicts': identities[1:],
            'attempt_count': len(attempts),
            'distinct_attempted': len(attempted_ids),
            'attempted_ids': attempted_ids,
            'state_counts': state_counts,
            'ever_pass_ids': pass_ids,
            'ever_pass_count': len(pass_ids),
            'missing_ids': [scenario_id for scenario_id in universe
                            if scenario_id not in pass_set],
            'state_conflicts': conflicts,
        }
    union_ids = sorted(set().union(*(set(group['ever_pass_ids'])
                                     for group in candidates.values())) if candidates else set())
    selected = None
    if selected_candidate is not None:
        group = candidates[selected_candidate]
        selected = {'candidate_id': selected_candidate,
                    'identity_variants': group['identity_variants'],
                    'attempt_count': group['attempt_count'],
                    'distinct_attempted': group['distinct_attempted'],
                    'ever_pass_ids': group['ever_pass_ids'],
                    'ever_pass_count': group['ever_pass_count'],
                    'missing_ids': group['missing_ids'],
                    'missing_count': len(group['missing_ids']),
                    'state_counts': group['state_counts'],
                    'state_conflicts': group['state_conflicts'],
                    'covers_id_universe': group['ever_pass_count'] == len(universe_set)}
    return {
        'schema': SCHEMA,
        'kind': LEDGER_NOTE,
        'evidence_root': str(evidence_root),
        'batch_count': len(scan['batch_names']),
        'batch_names': scan['batch_names'],
        'result_count': len(records),
        'id_universe': {'source': 'union of scenario_id values observed in scanned results',
                        'count': len(universe), 'ids': universe},
        'read_errors': scan['read_errors'],
        'anomalies': scan['anomalies'],
        'records': records,
        'candidates': candidates,
        'ever_pass_union_across_candidates': {
            'ids': union_ids, 'count': len(union_ids),
            'note': ('union of historical ever-pass ids across all candidates; '
                     'it is not a single-candidate verdict and not an acceptance pass')},
        'selected_candidate': selected,
    }


def render_summary(ledger: dict) -> str:
    """Render summary.md from the ledger dict alone (no re-scan)."""
    lines: list[str] = []
    lines.append('# Scenario result ledger')
    lines.append('')
    lines.append('- schema: `%s`' % ledger['schema'])
    lines.append('- kind: %s.' % ledger['kind'])
    lines.append('- evidence root: `%s`' % ledger['evidence_root'])
    batches = ledger['batch_names']
    lines.append('- batches: %d (`%s`..`%s`)' % (ledger['batch_count'], batches[0], batches[-1]))
    lines.append('- result records: %d' % ledger['result_count'])
    lines.append('- id universe: %d ids (union of observed scenario ids)'
                 % ledger['id_universe']['count'])
    lines.append('- read errors: %d; structural anomalies: %d'
                 % (len(ledger['read_errors']), len(ledger['anomalies'])))
    lines.append('')
    selected = ledger['selected_candidate']
    lines.append('## Selected candidate')
    lines.append('')
    if selected is None:
        lines.append('No `--candidate` was given, so no candidate was selected or guessed. '
                     'The per-candidate sections below are the only verdict views; the '
                     'cross-candidate union is explicitly not a candidate verdict.')
    else:
        lines.append('- candidate: `%s`' % selected['candidate_id'])
        for variant in selected['identity_variants']:
            lines.append('- identity: commit `%s`, package `%s`'
                         % (variant.get('source_commit'), variant.get('package_sha256')))
        lines.append('- attempts: %d records over %d distinct ids'
                     % (selected['attempt_count'], selected['distinct_attempted']))
        lines.append('- ever-pass ids: %d' % selected['ever_pass_count'])
        lines.append('- missing ids (%d): %s' % (selected['missing_count'],
                                                 ', '.join(selected['missing_ids']) or 'none'))
        lines.append('- covers the id universe: %s' % selected['covers_id_universe'])
        lines.append('- state counts: %s'
                     % ', '.join('%s=%d' % item for item in sorted(selected['state_counts'].items())))
        conflicts = selected['state_conflicts']
        lines.append('- state conflicts across attempts: %d%s'
                     % (len(conflicts), (' (%s)' % ', '.join(
                         '%s %s' % (row['scenario_id'], '/'.join(row['states']))
                         for row in conflicts)) if conflicts else ''))
    lines.append('')
    lines.append('## Per-candidate stored results (strictly separated)')
    lines.append('')
    lines.append('| candidate | attempts | distinct attempted | ever-pass | missing | identity conflicts |')
    lines.append('| --- | --- | --- | --- | --- | --- |')
    for candidate_id, group in sorted(ledger['candidates'].items()):
        lines.append('| `%s` | %d | %d | %d | %d | %d |'
                     % (candidate_id, group['attempt_count'], group['distinct_attempted'],
                        group['ever_pass_count'], len(group['missing_ids']),
                        len(group['identity_conflicts'])))
    union = ledger['ever_pass_union_across_candidates']
    lines.append('')
    lines.append('Cross-candidate ever-pass union: %d ids. %s.'
                 % (union['count'], union['note']))
    lines.append('')
    if ledger['read_errors']:
        lines.append('## Read errors')
        lines.append('')
        for row in ledger['read_errors']:
            lines.append('- `%s`: %s' % (row['path'], row['error']))
        lines.append('')
    if ledger['anomalies']:
        lines.append('## Structural anomalies')
        lines.append('')
        for row in ledger['anomalies']:
            lines.append('- `%s`: %s' % (row['path'], '; '.join(row['issues'])))
        lines.append('')
    lines.append('This summary is derived from `ledger.json`; re-acceptance of any scenario '
                 'requires the scenario-suite verify/replay entry, not this ledger.')
    lines.append('')
    return '\n'.join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--evidence-root', required=True,
                        help='directory holding discovery100-*/results/scenario-*.json '
                             'result originals (read-only input)')
    parser.add_argument('--output-dir', required=True,
                        help='directory to write ledger.json and summary.md into; must not '
                             'overlap the evidence root')
    parser.add_argument('--candidate', default=None,
                        help='candidate_id whose stored results form the selected-candidate '
                             'view; when omitted no candidate is guessed')
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    evidence_root = Path(args.evidence_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    try:
        if not evidence_root.is_dir():
            raise LedgerError('evidence root is not a directory: %s' % evidence_root)
        if output_dir == evidence_root or evidence_root in output_dir.parents \
                or output_dir in evidence_root.parents:
            raise LedgerError('output directory must not overlap the evidence root: '
                              'output would cover inputs (%s vs %s)' % (output_dir, evidence_root))
        scan = scan_evidence(evidence_root)
        if args.candidate is not None:
            known = sorted({record['identity']['candidate_id'] for record in scan['records']})
            if args.candidate not in known:
                raise LedgerError('unknown candidate %r; available: %s'
                                  % (args.candidate, ', '.join(known) or 'none'))
        ledger = build_ledger(evidence_root, scan, args.candidate)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / 'ledger.json').write_text(
            json.dumps(ledger, ensure_ascii=False, indent=2, sort_keys=True) + '\n',
            encoding='utf-8')
        (output_dir / 'summary.md').write_text(render_summary(ledger), encoding='utf-8')
    except LedgerError as exc:
        print('scenario_result_ledger: %s' % exc, file=sys.stderr)
        return 2
    for row in scan['read_errors']:
        print('scenario_result_ledger: unreadable result %s: %s' % (row['path'], row['error']),
              file=sys.stderr)
    for row in scan['anomalies']:
        print('scenario_result_ledger: anomalous result %s: %s'
              % (row['path'], '; '.join(row['issues'])), file=sys.stderr)
    clean = not scan['read_errors'] and not scan['anomalies']
    print(json.dumps({'ledger': str(output_dir / 'ledger.json'),
                      'summary': str(output_dir / 'summary.md'),
                      'result_count': ledger['result_count'],
                      'candidate_count': len(ledger['candidates']),
                      'selected_candidate': args.candidate,
                      'clean': clean}, ensure_ascii=False))
    return 0 if clean else 2


if __name__ == '__main__':
    raise SystemExit(main())
