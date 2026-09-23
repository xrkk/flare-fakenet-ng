#!/usr/bin/env python3
"""Rebuild an auxiliary QPC proof from sealed ETL/TDH and case originals."""
import argparse
from collections import Counter
import json
from pathlib import Path

import etl_raw_clock as raw
import scenario_aux_qpc_diagnostic as aux
import scenario_qpc_offline as shared
import scenario_tcpip as tcpip
import sst_fault_evidence as fault
from scenario_qpc_identity import check_aux_provenance


def _read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def _lines(path):
    with path.open(encoding='utf-8') as stream:
        return [json.loads(line) for line in stream]


def derive(case_path, evidence_root, export, output, *, require_complete=True):
    """Never turn an old incomplete Windows diagnostic into a formal proof."""
    case_path, evidence_root, export, output = map(Path, (case_path, evidence_root, export, output))
    output.mkdir(parents=True, exist_ok=False)
    case = _read(case_path)
    if case.get('schema') != 'sst.aux-qpc-input.v1' or not case.get('cases'):
        raise raw.DiagnosticError('auxiliary input schema/cases invalid')
    paths = [case_path] + [(evidence_root / item['path']).resolve() for item in case['files']]
    paths += [export / name for name in ('manifest.json', 'raw/manifest.json',
        'raw/raw.jsonl', 'raw/default.jsonl', 'raw/paired.jsonl', 'selectors.json',
        'tdh/manifest.json', 'tdh/metadata.jsonl')]
    before = {str(path): raw.sha_file(path) for path in paths}
    evidence = fault.Evidence(evidence_root, case['files'])
    if shared.verify_case_refs(case, evidence) < 1:
        raise raw.DiagnosticError('auxiliary case has no original byte references')
    etl = (evidence_root / case['capture']['etl_path']).resolve()
    selectors_source, header = shared.verify_export(export, etl, output)
    selected = selectors_source['selectors']
    rows = _lines(export / 'tdh/metadata.jsonl')
    shared.verify_tdh_rows(rows, selected)
    by_seq = {row['selector']['seq']: row for row in rows}
    windows = _read(export / 'manifest.json')
    if (windows.get('schema') != 'sst.aux-qpc-diagnostic.v1' or
            windows.get('status') not in ('COMPLETE_DIAGNOSTIC_ONLY', 'INCOMPLETE') or
            windows.get('formal_traffic_verdict') != 'UNCHANGED' or
            windows.get('inputs_before') != windows.get('inputs_after') or
            Counter((item['bytes'], item['sha256']) for item in windows['inputs_before'].values()) !=
            Counter((before[str(path)]['bytes'], before[str(path)]['sha256'])
                    for path in paths[:1 + len(case['files'])])):
        raise raw.DiagnosticError('Windows auxiliary source manifest/identity differs')
    if require_complete and (windows['status'] != 'COMPLETE_DIAGNOSTIC_ONLY' or
                             windows.get('error') is not None):
        raise raw.DiagnosticError('original Windows auxiliary export did not complete')
    capture = case['capture']
    text = evidence.data[capture['text_path']]
    log = evidence.data[case['run_log_path']].decode('utf-8-sig')
    tcpip.validate_capture(text, evidence.data[capture['etl_path']],
                           evidence.read(capture['metadata_ref']), 50_000_000)
    ipc = [json.loads(line) for line in evidence.data[case['ipc_path']].splitlines()]
    managed_pid, managed_created = tcpip.managed_identity(ipc, case['run_id'])
    all_targets, all_selectors, groups, cases, identities = [], [], [], [], []
    keys = [(item['case_index'], item['connection_id']) for item in case['cases']]
    if len(keys) != len(set(keys)):
        raise raw.DiagnosticError('duplicate auxiliary case identity')
    for item in case['cases']:
        origin = evidence.read(item['probe_ref'])
        if (origin.get('event') != 'case_established' or origin.get('nonce') != case['nonce'] or
                origin.get('case_index') != item['case_index'] or
                origin.get('connection_id') != item['connection_id'] or
                origin.get('pid') != item['pid'] or origin.get('src') != item['src'] or
                (origin.get('actual_dst') or origin.get('dst')) != item['dst']):
            raise raw.DiagnosticError('auxiliary case/probe identity differs')
        probe_rows = [json.loads(line) for line in
                      evidence.data[item['probe_ref']['path']].splitlines()]
        endings = [row for row in probe_rows if row.get('nonce') == case['nonce'] and
                   row.get('pid') == item['pid'] and
                   row.get('connection_id') == item['connection_id'] and
                   row.get('event') in ('case_error', 'case_eof', 'case_close')]
        if not endings or [evidence.read(ref) for ref in item['end_refs']] != endings:
            raise raw.DiagnosticError('auxiliary probe terminal refs changed/incomplete')
        tcpip.validate_tuple_probe(probe_rows, origin, item['src'], item['dst'])
        observed = tcpip.connection_events(text, capture['text_path'], log,
            item['pid'], item['src'], item['dst'], managed_pid, log_path=case['run_log_path'])
        if (item['connection_refs'] != [event['ref'] for event in observed['events']] or
                item['tuple_terminal_refs'] != [event['ref'] for event in observed['tuple_terminals']] or
                item['generation_manifest'] != observed['generation_manifest'] or
                not observed['termination']):
            raise raw.DiagnosticError('auxiliary native generation/terminal changed')
        targets, selectors, candidate_sets, candidates = aux.diagnostic_candidates(
            observed, export / 'raw/paired.jsonl')
        binding = {'run_id': case['run_id'], 'case_index': item['case_index'],
                   'connection_id': item['connection_id']}
        for target, selector in zip(targets, selectors):
            target.update(binding)
            selector.update(binding)
        for group in candidate_sets:
            group.update(binding)
        all_targets.extend(targets)
        all_selectors.extend(selectors)
        groups.extend(candidate_sets)
        ready = [row for row in probe_rows if row.get('event') == 'ready' and
                 row.get('nonce') == case['nonce']]
        child = [row for row in probe_rows if row.get('event') == 'process_ready' and
                 row.get('nonce') == case['nonce'] and row.get('pid') == item['pid']]
        if len(ready) != 1 or len(child) > 1:
            raise raw.DiagnosticError('auxiliary native probe ready ambiguous')
        identities.append(check_aux_provenance(evidence.read(capture['metadata_ref']),
            ready[0], child[0] if child else None, origin, header, case['candidate_id'],
            case['run_id'], managed_pid, managed_created))
        aux.validate_named_tdh([by_seq[s['seq']] for s in selectors], targets,
            observed['connect']['tcb'], (observed['peer'] or {}).get('tcb'),
            item['pid'], managed_pid)
        cases.append((item, observed, targets, selectors, candidates))
    if any(identity != identities[0] for identity in identities[1:]):
        raise raw.DiagnosticError('auxiliary native identity differs across cases')
    identity = identities[0]
    for label, actual, expected in (
            ('identity', windows.get('identity'), identity),
            ('targets', windows.get('targets'), json.loads(json.dumps(all_targets))),
            ('candidate_sets', windows.get('candidate_sets'), json.loads(json.dumps(groups))),
            ('candidate_id', windows.get('candidate_id'), case['candidate_id']),
            ('run_id', windows.get('run_id'), case['run_id']),
            ('managed_pid', windows.get('managed_pid'), managed_pid),
            ('managed_creation', windows.get('managed_creation_filetime_100ns'), managed_created)):
        if actual != expected:
            raise raw.DiagnosticError('Windows auxiliary ' + label + ' summary differs')
    bindings = aux.unique_zero_bindings(groups)
    if not bindings:
        raise raw.DiagnosticError('NO_ZERO_TCB_BRANCH: no native negative branch')
    facts = aux.candidate_field_facts(rows, groups, selected, strict=True)
    if windows['status'] == 'COMPLETE_DIAGNOSTIC_ONLY' and (
            windows.get('candidate_binding_status') != 'UNIQUE_VERIFIED' or
            windows.get('candidate_field_facts') != facts):
        raise raw.DiagnosticError('Windows auxiliary zero-TCB semantic summary differs')
    expected_selectors = {item['seq']: item for item in all_selectors}
    if len(expected_selectors) != len(all_selectors):
        raise raw.DiagnosticError('named native target reused')
    for _, _, _, _, candidates in cases:
        for item in candidates:
            prior = expected_selectors.get(item['seq'])
            if prior is None:
                expected_selectors[item['seq']] = item
            else:
                refs = prior.setdefault('diagnostic_candidate_refs', [])
                for ref in item['diagnostic_candidate_refs']:
                    if ref not in refs:
                        refs.append(ref)
    if selected != list(expected_selectors.values()):
        raise raw.DiagnosticError('Windows auxiliary selectors changed')
    lo, hi = identity['capture_qpc']['before'][1], identity['capture_qpc']['after'][0]
    if any(not lo <= selector['raw_qpc'] <= hi for selector in selected):
        raise raw.DiagnosticError('auxiliary target outside native capture QPC window')
    proof_cases = []
    for item, observed, targets, selectors, _ in cases:
        by_ref = {json.dumps(t['pktmon_ref'], sort_keys=True): s['raw_qpc']
                  for t, s in zip(targets, selectors)}
        establish_refs = [observed['connect']['ref']]
        if observed['peer']:
            establish_refs.append(observed['peer']['ref'])
        begin = max(by_ref[json.dumps(ref, sort_keys=True)] for ref in establish_refs)
        own = [group for group in groups if group['case_index'] == item['case_index'] and
               group['connection_id'] == item['connection_id']]
        zeros = [bindings[json.dumps(group['pktmon_ref'], sort_keys=True)] for group in own]
        gaps = [row['raw_timestamp'] - begin for row in zeros]
        if any(gap <= 1 for gap in gaps):
            raise raw.DiagnosticError('zero-TCB QPC at/before establishment margin')
        proof_cases.append({'case_index': item['case_index'], 'connection_id': item['connection_id'],
            'pid': item['pid'], 'src': item['src'], 'dst': item['dst'],
            'tuple_terminal_refs': item['tuple_terminal_refs'],
            'begin_qpc': begin, 'zero_seqs': [row['seq'] for row in zeros],
            'zero_qpc': [row['raw_timestamp'] for row in zeros], 'gaps_ticks': gaps,
            'zero_constraint': 'VERIFIED' if zeros else 'NO_ZERO_TCB'})
    if windows['status'] == 'COMPLETE_DIAGNOSTIC_ONLY':
        windows_cases = windows.get('cases') or []
        if len(windows_cases) != len(proof_cases):
            raise raw.DiagnosticError('Windows auxiliary case proof count differs')
        for emitted, recomputed in zip(windows_cases, proof_cases):
            native = emitted.get('native_zero_tcb') or {}
            if (emitted.get('case_index') != recomputed['case_index'] or
                    emitted.get('connection_id') != recomputed['connection_id'] or
                    emitted.get('probe_pid') != recomputed['pid'] or
                    emitted.get('tuple_terminal_refs') != recomputed['tuple_terminal_refs'] or
                    native.get('status') != recomputed['zero_constraint'] or
                    native.get('begin_qpc') != recomputed['begin_qpc'] or
                    native.get('zero_qpc') != recomputed['zero_qpc'] or
                    native.get('zero_seqs') != recomputed['zero_seqs'] or
                    native.get('gaps_ticks') != recomputed['gaps_ticks'] or
                    native.get('passed') is not True):
                raise raw.DiagnosticError('Windows auxiliary native case proof differs')
    after = {str(path): raw.sha_file(path) for path in paths}
    if before != after:
        raise raw.DiagnosticError('auxiliary source changed during offline derivation')
    result = {'schema': 'sst.aux-qpc-offline.v1',
              'status': ('COMPLETE_FORMAL_INPUT' if windows['status'] ==
                         'COMPLETE_DIAGNOSTIC_ONLY' else 'DIAGNOSTIC_ONLY_INCOMPLETE_SOURCE'),
              'source_windows_status': windows['status'], 'candidate_id': case['candidate_id'],
              'run_id': case['run_id'], 'nonce': case['nonce'], 'identity': identity,
              'cases': proof_cases, 'reason_map_sha256': sorted({x['reason_map_sha256'] for x in facts}),
              'inputs_before': before, 'inputs_after': after}
    (output / 'derived.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n',
                                         encoding='utf-8')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--export', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = derive(args.case.resolve(), args.evidence_root.resolve(),
                    args.export.resolve(), args.output.resolve())
    print(json.dumps({'status': result['status'], 'cases': len(result['cases'])}))


if __name__ == '__main__':
    main()
