#!/usr/bin/env python3
"""Collect auxiliary TCP native clock and TDH originals without guessing 0x0 semantics.

The zero-TCB Receive-discarded descriptor has not yet been verified against a
Windows TDH original. An export containing it remains INCOMPLETE until that
semantic gate is implemented from real native fields.
"""
import argparse
import json
import re
from pathlib import Path
import sys
import traceback

import etl_raw_clock as raw_clock
import scenario_qpc_diagnostic as qpc
import scenario_tcpip as tcpip
import sst_fault_evidence as fault
import tdh_metadata
from scenario_qpc_identity import check_aux_provenance


def diagnostic_order(observed, targets, selectors):
    """Report raw counter gaps; this alone never validates zero-TCB semantics."""
    by_ref = {json.dumps(target['pktmon_ref'], sort_keys=True): selector['raw_qpc']
              for target, selector in zip(targets, selectors)}
    begin_refs = [observed['connect']['ref']]
    if observed['peer']:
        begin_refs.append(observed['peer']['ref'])
    if any(json.dumps(ref, sort_keys=True) not in by_ref for ref in begin_refs):
        raise raw_clock.DiagnosticError('establishment target omitted from raw order')
    begin = max(by_ref[json.dumps(ref, sort_keys=True)] for ref in begin_refs)
    zero_refs = [item['ref'] for item in observed['tuple_terminals']]
    if any(json.dumps(ref, sort_keys=True) not in by_ref for ref in zero_refs):
        raise raw_clock.DiagnosticError('zero-TCB target omitted from raw order')
    zeros = [by_ref[json.dumps(ref, sort_keys=True)] for ref in zero_refs]
    return {'status': 'UNVERIFIED_TDH_SEMANTICS', 'begin_qpc': begin,
            'zero_tcb_qpc': zeros, 'gaps_ticks': [value - begin for value in zeros],
            'all_strictly_later_than_one_tick': bool(zeros) and all(
                value - begin > 1 for value in zeros)}


def diagnostic_candidates(observed, paired_path):
    """Keep named targets strict; enumerate every possible zero-TCB TDH row.

    FILETIME and provider narrow the diagnostic search only. Duplicate
    non-time identities expand the set across converted FILETIMEs because
    raw/default pairing cannot uniquely assign their QPC values. Neither a
    single remaining row nor its order establishes the native event role.
    """
    named = dict(observed, tuple_terminals=[])
    targets, selectors = qpc.choose_targets(named, paired_path)
    zero_events = observed['tuple_terminals']
    stamps = {}
    for event in zero_events:
        match = re.search(r'::(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)', event['text'])
        if not match or event.get('tcb') != '0X0' or event.get('kind') != 'unattributed_tuple_terminal':
            raise raw_clock.DiagnosticError('zero-TCB formatted target identity invalid')
        stamp = raw_clock.pktmon_filetime(match.group(1) + '+08:00')
        stamps.setdefault(stamp, []).append(event)
    rows = {stamp: [] for stamp in stamps}
    identity_groups = {}
    with paired_path.open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if row['provider'] != qpc.TCPIP_PROVIDER:
                continue
            identity_groups.setdefault(row['identity_sha256'], []).append(row)
            if row['default_filetime_100ns'] in rows:
                rows[row['default_filetime_100ns']].append(row)
    sets = []
    candidate_selectors = {}
    for stamp, events in stamps.items():
        anchors = rows[stamp]
        if not anchors:
            raise raw_clock.DiagnosticError('zero-TCB diagnostic candidate set empty')
        options_by_seq = {}
        for anchor in anchors:
            group = identity_groups[anchor['identity_sha256']]
            if len(group) != anchor['identity_occurrences']:
                raise raw_clock.DiagnosticError('zero-TCB raw/default identity group count differs')
            for row in group:
                options_by_seq[row['seq']] = row
        options = [options_by_seq[seq] for seq in sorted(options_by_seq)]
        anchor_seqs = {row['seq'] for row in anchors}
        for event in events:
            candidates = []
            for row in options:
                candidates.append({key: row[key] for key in (
                    'seq', 'provider', 'id', 'version', 'opcode', 'task',
                    'raw_timestamp', 'default_filetime_100ns',
                    'userdata_sha256', 'identity_sha256', 'identity_occurrences',
                    'binding_status')})
                candidates[-1]['selection_reason'] = (
                    'EXACT_FORMATTED_FILETIME' if row['seq'] in anchor_seqs
                    else 'SAME_AMBIGUOUS_NON_TIME_IDENTITY')
                selector = candidate_selectors.get(row['seq'])
                if selector is None:
                    selector = {key: row[key] for key in (
                        'seq', 'provider', 'id', 'version', 'opcode', 'task',
                        'userdata_sha256', 'identity_sha256', 'binding_status')}
                    selector.update(raw_qpc=row['raw_timestamp'],
                                    target_kind='auxiliary_zero_tcb_diagnostic_candidate',
                                    tcb='0X0', diagnostic_candidate_refs=[])
                    candidate_selectors[row['seq']] = selector
                if event['ref'] not in selector['diagnostic_candidate_refs']:
                    selector['diagnostic_candidate_refs'].append(event['ref'])
            sets.append({'status': 'DIAGNOSTIC_CANDIDATES_UNRESOLVED',
                         'pktmon_ref': event['ref'], 'formatted_kind': event['kind'],
                         'formatted_tcb': event['tcb'], 'local': event.get('local'),
                         'remote': event.get('remote'), 'default_filetime_100ns': stamp,
                         'exact_filetime_anchor_seqs': sorted(anchor_seqs),
                         'candidates': candidates})
    # The named set remains exactly the old unique selection. A candidate may
    # overlap it; TDH reads that seq once while the candidate map retains it.
    return targets, selectors, sets, list(candidate_selectors.values())


def run(case_path: Path, evidence_root: Path, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    manifest = {'schema': 'sst.aux-qpc-diagnostic.v1', 'status': 'INCOMPLETE',
                'inputs_before': {}, 'inputs_after': {}, 'error': None,
                'formal_traffic_verdict': 'UNCHANGED'}
    paths = [case_path]
    try:
        manifest['inputs_before'] = {str(case_path): raw_clock.sha_file(case_path)}
        case = json.loads(case_path.read_text(encoding='utf-8'))
        if case.get('schema') != 'sst.aux-qpc-input.v1' or not case.get('cases'):
            raise raw_clock.DiagnosticError('auxiliary QPC input schema/cases missing')
        keys = [(row['case_index'], row['connection_id']) for row in case['cases']]
        if len(keys) != len(set(keys)):
            raise raw_clock.DiagnosticError('duplicate auxiliary case identity')
        evidence = fault.Evidence(evidence_root, case['files'])
        paths += [(evidence_root / item['path']).resolve() for item in case['files']]
        manifest['inputs_before'] = {str(p): raw_clock.sha_file(p) for p in paths}
        capture = case['capture']
        etl = (evidence_root / capture['etl_path']).resolve()
        text = evidence.data[capture['text_path']]
        log = evidence.data[case['run_log_path']].decode('utf-8-sig')
        tcpip.validate_capture(text, evidence.data[capture['etl_path']],
                               evidence.read(capture['metadata_ref']), 50_000_000)
        ipc = [json.loads(line) for line in evidence.data[case['ipc_path']].splitlines()]
        managed_pid, managed_created = tcpip.managed_identity(ipc, case['run_id'])
        exported = raw_clock.export(etl, output / 'raw')
        all_targets, all_selectors, all_candidate_sets, candidate_selectors, details = [], [], [], [], []
        provenance = []
        for auxiliary in case['cases']:
            origin = evidence.read(auxiliary['probe_ref'])
            if (origin.get('event') != 'case_established' or
                    origin.get('nonce') != case['nonce'] or
                    origin.get('case_index') != auxiliary['case_index'] or
                    origin.get('connection_id') != auxiliary['connection_id'] or
                    origin.get('pid') != auxiliary['pid'] or
                    origin.get('src') != auxiliary['src'] or
                    (origin.get('actual_dst') or origin.get('dst')) != auxiliary['dst']):
                raise raw_clock.DiagnosticError('auxiliary case/probe identity differs')
            probe_rows = [json.loads(line) for line in
                          evidence.data[auxiliary['probe_ref']['path']].splitlines()]
            endings = [row for row in probe_rows if row.get('nonce') == case['nonce']
                       and row.get('pid') == auxiliary['pid']
                       and row.get('connection_id') == auxiliary['connection_id']
                       and row.get('event') in ('case_error', 'case_eof', 'case_close')]
            if not endings or [evidence.read(ref) for ref in auxiliary['end_refs']] != endings:
                raise raw_clock.DiagnosticError('auxiliary probe terminal refs changed/incomplete')
            tcpip.validate_tuple_probe(probe_rows, origin, auxiliary['src'], auxiliary['dst'])
            observed = tcpip.connection_events(text, capture['text_path'], log,
                auxiliary['pid'], auxiliary['src'], auxiliary['dst'], managed_pid,
                log_path=case['run_log_path'])
            if (auxiliary['connection_refs'] != [x['ref'] for x in observed['events']] or
                    auxiliary['tuple_terminal_refs'] !=
                    [x['ref'] for x in observed['tuple_terminals']] or
                    auxiliary['generation_manifest'] != observed['generation_manifest']):
                raise raw_clock.DiagnosticError('auxiliary complete native ref set changed')
            if not observed['termination']:
                raise raw_clock.DiagnosticError('auxiliary named native terminal missing')
            targets, selectors, candidate_sets, diagnostics = diagnostic_candidates(
                observed, output / 'raw/paired.jsonl')
            for target, selector in zip(targets, selectors):
                binding = {'run_id': case['run_id'], 'case_index': auxiliary['case_index'],
                           'connection_id': auxiliary['connection_id']}
                target.update(binding)
                selector.update(binding)
            for candidate_set in candidate_sets:
                candidate_set.update(run_id=case['run_id'],
                                     case_index=auxiliary['case_index'],
                                     connection_id=auxiliary['connection_id'])
            all_targets.extend(targets)
            all_selectors.extend(selectors)
            all_candidate_sets.extend(candidate_sets)
            candidate_selectors.extend(diagnostics)
            by_ref = {json.dumps(target['pktmon_ref'], sort_keys=True): selector['raw_qpc']
                      for target, selector in zip(targets, selectors)}
            begin_refs = [observed['connect']['ref']]
            if observed['peer']:
                begin_refs.append(observed['peer']['ref'])
            begin = max(by_ref[json.dumps(ref, sort_keys=True)] for ref in begin_refs)
            order = {'status': 'UNVERIFIED_TDH_SEMANTICS', 'begin_qpc': begin,
                     'candidate_gap_sets_ticks': [
                         [{'seq': item['seq'], 'gap_ticks': item['raw_timestamp'] - begin}
                          for item in group['candidates']] for group in candidate_sets]}
            ready_rows = [item for item in probe_rows if item.get('event') == 'ready'
                          and item.get('nonce') == case['nonce']]
            child_rows = [item for item in probe_rows
                          if item.get('event') == 'process_ready' and
                          item.get('nonce') == case['nonce'] and
                          item.get('pid') == auxiliary['pid']]
            if len(ready_rows) != 1 or len(child_rows) > 1:
                raise raw_clock.DiagnosticError('auxiliary native probe ready ambiguous')
            provenance.append((ready_rows[0], child_rows[0] if child_rows else None, origin))
            details.append({'case_index': auxiliary['case_index'],
                            'connection_id': auxiliary['connection_id'],
                            'primary_tcb': observed['connect']['tcb'],
                            'peer_tcb': (observed['peer'] or {}).get('tcb'),
                            'probe_pid': auxiliary['pid'], 'managed_pid': managed_pid,
                            'target_seqs': [item['seq'] for item in targets],
                            'tuple_terminal_refs': auxiliary['tuple_terminal_refs'],
                            'diagnostic_candidate_seqs': [
                                [item['seq'] for item in group['candidates']]
                                for group in candidate_sets],
                            'raw_order_diagnostic': order})
        if len({item['seq'] for item in all_selectors}) != len(all_selectors):
            raise raw_clock.DiagnosticError('native event reused across auxiliary cases')
        selected_by_seq = {item['seq']: item for item in all_selectors}
        for item in candidate_selectors:
            existing = selected_by_seq.get(item['seq'])
            if existing is None:
                selected_by_seq[item['seq']] = item
            else:
                refs = existing.setdefault('diagnostic_candidate_refs', [])
                for ref in item['diagnostic_candidate_refs']:
                    if ref not in refs:
                        refs.append(ref)
        selected = list(selected_by_seq.values())
        manifest.update(targets=all_targets, candidate_sets=all_candidate_sets,
                        cases=details, candidate_binding_status='UNRESOLVED')
        selector_path = output / 'selectors.json'
        selector_path.write_text(json.dumps({'schema': 'fakenet.t007-r02-tdh-selectors.v1',
            'source_event_count': exported['paired_events'],
            'source_etl_sha256': exported['input_before']['sha256'],
            'selectors': selected}, indent=2) + '\n', encoding='utf-8')
        tdh = tdh_metadata.run(etl, selector_path, output / 'tdh')
        if tdh['target_count'] != len(selected):
            raise raw_clock.DiagnosticError('auxiliary TDH target set incomplete')
        identities = [check_aux_provenance(
            evidence.read(capture['metadata_ref']), ready, process_ready, origin,
            exported['passes'][0]['header'], case['candidate_id'], case['run_id'],
            managed_pid, managed_created)
            for ready, process_ready, origin in provenance]
        if any(identity != identities[0] for identity in identities[1:]):
            raise raw_clock.DiagnosticError('auxiliary cases have mixed native identity')
        manifest.update(managed_pid=managed_pid,
                        managed_creation_filetime_100ns=managed_created,
                        candidate_id=case['candidate_id'], run_id=case['run_id'],
                        identity=identities[0])
        # Do not turn formatted text's "Receive discarded" into a TDH fact.
        # The real zero-TCB descriptor, reason and process identity fields
        # must be established from this export before acceptance is enabled.
        if all_candidate_sets:
            raise raw_clock.DiagnosticError(
                'UNSUPPORTED: zero-TCB diagnostic candidates have no verified unique TDH binding/semantics')
        raise raw_clock.DiagnosticError('NO_ZERO_TCB_BRANCH: native negative branch unobserved')
    except BaseException as exc:  # preserve original raw/TDH output
        manifest['error'] = {'type': type(exc).__name__, 'message': str(exc),
                             'traceback': traceback.format_exc()}
    finally:
        manifest['inputs_after'] = {str(p): raw_clock.sha_file(p) for p in paths if p.is_file()}
        if manifest['inputs_before'] != manifest['inputs_after']:
            manifest['status'] = 'INCOMPLETE'
            manifest['error'] = {'type': 'InputChanged', 'message': 'source inputs changed'}
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2,
            ensure_ascii=False, sort_keys=True) + '\n', encoding='utf-8')
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = run(args.case.resolve(), args.evidence_root.resolve(), args.output.resolve())
    print(json.dumps({'status': result['status'], 'output': str(args.output.resolve()),
                      'error': (result['error'] or {}).get('message')}))
    return 0 if result['status'] == 'COMPLETE_DIAGNOSTIC_ONLY' else 1


if __name__ == '__main__':
    sys.exit(main())
