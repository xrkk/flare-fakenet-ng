#!/usr/bin/env python3
"""Collect auxiliary TCP native clock and TDH originals without guessing 0x0 semantics.

The zero-TCB Receive-discarded descriptor has not yet been verified against a
Windows TDH original. An export containing it remains INCOMPLETE until that
semantic gate is implemented from real native fields.
"""
import argparse
import json
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
        all_targets, all_selectors, details = [], [], []
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
            targets, selectors = qpc.choose_targets(observed, output / 'raw/paired.jsonl')
            for target, selector in zip(targets, selectors):
                binding = {'run_id': case['run_id'], 'case_index': auxiliary['case_index'],
                           'connection_id': auxiliary['connection_id']}
                target.update(binding)
                selector.update(binding)
            all_targets.extend(targets)
            all_selectors.extend(selectors)
            order = diagnostic_order(observed, targets, selectors)
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
                            'raw_order_diagnostic': order})
        if len({item['seq'] for item in all_selectors}) != len(all_selectors):
            raise raw_clock.DiagnosticError('native event reused across auxiliary cases')
        selector_path = output / 'selectors.json'
        selector_path.write_text(json.dumps({'schema': 'fakenet.t007-r02-tdh-selectors.v1',
            'source_event_count': exported['paired_events'],
            'source_etl_sha256': exported['input_before']['sha256'],
            'selectors': all_selectors}, indent=2) + '\n', encoding='utf-8')
        tdh = tdh_metadata.run(etl, selector_path, output / 'tdh')
        if tdh['target_count'] != len(all_targets):
            raise raw_clock.DiagnosticError('auxiliary TDH target set incomplete')
        identities = [check_aux_provenance(
            evidence.read(capture['metadata_ref']), ready, process_ready, origin,
            exported['passes'][0]['header'], case['candidate_id'], case['run_id'],
            managed_pid, managed_created)
            for ready, process_ready, origin in provenance]
        if any(identity != identities[0] for identity in identities[1:]):
            raise raw_clock.DiagnosticError('auxiliary cases have mixed native identity')
        manifest.update(targets=all_targets, cases=details, managed_pid=managed_pid,
                        managed_creation_filetime_100ns=managed_created,
                        candidate_id=case['candidate_id'], run_id=case['run_id'],
                        identity=identities[0])
        # Do not turn formatted text's "Receive discarded" into a TDH fact.
        # The real zero-TCB descriptor, reason and process identity fields
        # must be established from this export before acceptance is enabled.
        if any(target['tcb'] == '0X0' for target in all_targets):
            raise raw_clock.DiagnosticError(
                'UNSUPPORTED: zero-TCB Receive-discarded TDH descriptor/properties unverified')
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
