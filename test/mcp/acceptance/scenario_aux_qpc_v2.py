#!/usr/bin/env python3
"""Versioned auxiliary zero-TCB proof from a complete same-callback scan.

Named connection generations continue to use the strict v1 raw/default and
TDH path. The v1 diagnostic is retained as evidence, including its ambiguous
failure; only zero-TCB RST records use this scan and multiset contract.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import traceback

import etl_raw_clock as raw
import scenario_aux_qpc_diagnostic as aux
import scenario_aux_qpc_single_pass as single
import scenario_qpc_diagnostic as qpc
import scenario_qpc_offline as shared
import scenario_tcpip as tcpip
import sst_fault_evidence as fault
from scenario_qpc_identity import check_aux_provenance

SCHEMA = 'sst.aux-qpc-diagnostic.v2'
PROOF_SCHEMA = 'sst.aux-qpc-offline.v2'


def _read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def _lines(path):
    with path.open(encoding='utf-8') as stream:
        return [json.loads(line) for line in stream]


def _require(test, message):
    if not test:
        raise raw.DiagnosticError(message)


def _source_paths(case_path, evidence_root, case, export):
    return ([case_path] + [(evidence_root / item['path']).resolve() for item in case['files']] +
            [export / name for name in ('legacy/manifest.json', 'legacy/raw/manifest.json',
                'legacy/raw/raw.jsonl', 'legacy/raw/default.jsonl', 'legacy/raw/paired.jsonl',
                'legacy/selectors.json', 'legacy/tdh/manifest.json',
                'legacy/tdh/metadata.jsonl', 'single/manifest.json',
                'single/records.jsonl', 'single/index.jsonl')])


def _single_rows(export, etl, legacy_count, legacy_raw, header):
    manifest = _read(export / 'single/manifest.json')
    record_bytes = (export / 'single/records.jsonl').read_bytes()
    lines = record_bytes.splitlines(keepends=True)
    records = [json.loads(line) for line in lines]
    index = _lines(export / 'single/index.jsonl')
    _require(len(index) == len(records), 'single-pass byte index count differs')
    offset = 0
    for item, row, line in zip(index, records, lines):
        _require(item == {'seq': row['selector']['seq'], 'byte_start': offset,
                          'byte_end': offset + len(line),
                          'sha256': hashlib.sha256(line).hexdigest()} and
                 line.endswith(b'\n'), 'single-pass byte reference differs')
        row['record_ref'] = {'path': 'single/records.jsonl', **item}
        offset += len(line)
    _require(offset == len(record_bytes), 'single-pass record bytes unindexed')
    _require(manifest.get('schema') == single.SCHEMA and
             manifest.get('status') == 'COMPLETE_DIAGNOSTIC_ONLY' and
             manifest.get('error') is None and
             manifest.get('input_before') == manifest.get('input_after') == raw.sha_file(etl),
             'single-pass ETL manifest incomplete or changed')
    scan = manifest.get('scan') or {}
    same_header = {k: v for k, v in (scan.get('header') or {}).items()
                   if not k.endswith('_pointer')} == {
                       k: v for k, v in header.items() if not k.endswith('_pointer')}
    _require(scan.get('events') == legacy_count and
             scan.get('process_trace_return') == scan.get('events_lost_output') == 0 and
             same_header and
             manifest.get('rst_records') == len(records),
             'single-pass full scan count, clock or header differs')
    selectors = [row['selector'] for row in records]
    shared.verify_tdh_rows(records, selectors)
    _require(len({item['seq'] for item in selectors}) == len(selectors),
             'single-pass callback locator reused')
    native = Counter(json.dumps(row['record'], sort_keys=True) for row in records)
    historical = Counter(json.dumps({key: value for key, value in row.items()
                                     if key != 'seq'}, sort_keys=True) for row in legacy_raw
                         if row['provider'] == qpc.TCPIP_PROVIDER and row['id'] == 1479)
    _require(native == historical, 'single-pass omitted/added/changed TCPIP RST record')
    _require(all(item['record']['timestamp'] == item['selector']['raw_qpc']
                 for item in records), 'single-pass QPC/source record differs')
    return records, manifest


def _zero_semantics(row, src, dst):
    """Return a target only after reading the same callback's verified bytes."""
    tcb = qpc._property(row, 'Tcb')
    if len(tcb) != 8 or tcb != b'\0' * 8:
        return False
    local = qpc._property(row, 'LocalSockAddr')
    remote = qpc._property(row, 'RemoteSockAddr')
    if local != qpc._sockaddr(src).ljust(16, b'\0') or remote != qpc._sockaddr(dst).ljust(16, b'\0'):
        return False
    # candidate_field_facts checks provider, descriptor, all typed properties,
    # exact endpoints and the captured Reason map's value zero.
    group = {'local': src, 'remote': dst,
             'candidates': [{'seq': row['selector']['seq']}]}
    aux.candidate_field_facts([row], [group], [row['selector']], strict=True)
    return True


def adjudicate_zeros(single_rows, observed, src, dst, begin, lower, upper):
    """Count every same-callback zero record and every original text ref."""
    zeros = [row for row in single_rows if _zero_semantics(row, src, dst)]
    _require(all(lower <= row['record']['timestamp'] <= upper for row in zeros),
             'zero-TCB outside QPC capture window')
    text_multiset = Counter((qpc.TCPIP_PROVIDER, 1479, '0X0', 6, 2,
        e['local'], e['remote'], 'Receive discarded ') for e in observed['tuple_terminals'])
    native_multiset = Counter((row['record']['provider'], row['record']['id'],
        '0X0', 6, 2, src, dst, 'Receive discarded ') for row in zeros)
    _require(text_multiset == native_multiset,
             'zero-TCB native/text full semantic multiset differs')
    gaps = [row['record']['timestamp'] - begin for row in zeros]
    _require(all(gap > 1 for gap in gaps),
             'zero-TCB QPC at/before establishment margin')
    return {'zero_seqs': [row['selector']['seq'] for row in zeros],
            'native_refs': [row.get('record_ref') for row in zeros],
            'zero_qpc': [row['record']['timestamp'] for row in zeros],
            'gaps_ticks': gaps, 'zero_constraint': 'VERIFIED' if zeros else 'NO_ZERO_TCB',
            'native_count': len(zeros), 'text_count': sum(text_multiset.values())}


def rebuild(case_path, evidence_root, export, *, require_windows=True):
    case_path, evidence_root, export = map(Path, (case_path, evidence_root, export))
    case = _read(case_path)
    _require(case.get('schema') == 'sst.aux-qpc-input.v1' and bool(case.get('cases')),
             'auxiliary input schema/cases invalid')
    paths = _source_paths(case_path, evidence_root, case, export)
    before = {str(path): raw.sha_file(path) for path in paths}
    evidence = fault.Evidence(evidence_root, case['files'])
    _require(shared.verify_case_refs(case, evidence) > 0,
             'auxiliary case original byte refs absent')
    capture = case['capture']
    etl = (evidence_root / capture['etl_path']).resolve()
    legacy = export / 'legacy'
    selectors_source, header = shared.verify_export(legacy, etl, legacy)
    selected = selectors_source['selectors']
    named_rows = _lines(legacy / 'tdh/metadata.jsonl')
    shared.verify_tdh_rows(named_rows, selected)
    by_seq = {row['selector']['seq']: row for row in named_rows}
    legacy_manifest = _read(legacy / 'manifest.json')
    _require(legacy_manifest.get('schema') == 'sst.aux-qpc-diagnostic.v1' and
             (legacy_manifest.get('status') == 'COMPLETE_DIAGNOSTIC_ONLY' or
              ((legacy_manifest.get('error') or {}).get('message') or '').startswith(
                  'zero-TCB no verified unique TDH binding')),
             'legacy named proof failed for a reason other than zero-TCB ambiguity')
    legacy_raw = _lines(legacy / 'raw/raw.jsonl')
    single_rows, single_manifest = _single_rows(
        export, etl, len(legacy_raw), legacy_raw, header)
    text = evidence.data[capture['text_path']]
    log = evidence.data[case['run_log_path']].decode('utf-8-sig')
    tcpip.validate_capture(text, evidence.data[capture['etl_path']],
                           evidence.read(capture['metadata_ref']), 50_000_000)
    ipc = [json.loads(line) for line in evidence.data[case['ipc_path']].splitlines()]
    managed_pid, managed_created = tcpip.managed_identity(ipc, case['run_id'])
    cases, identities, named_targets, named_selectors, used_tuples = [], [], [], [], set()
    keys = [(item['case_index'], item['connection_id']) for item in case['cases']]
    _require(len(keys) == len(set(keys)), 'duplicate auxiliary case identity')
    for item in case['cases']:
        tuple_key = (item['src'], item['dst'])
        _require(tuple_key not in used_tuples, 'auxiliary tuple reused across cases')
        used_tuples.add(tuple_key)
        origin = evidence.read(item['probe_ref'])
        _require(origin.get('event') == 'case_established' and
                 origin.get('nonce') == case['nonce'] and
                 origin.get('case_index') == item['case_index'] and
                 origin.get('connection_id') == item['connection_id'] and
                 origin.get('pid') == item['pid'] and origin.get('src') == item['src'] and
                 (origin.get('actual_dst') or origin.get('dst')) == item['dst'],
                 'auxiliary case/probe identity differs')
        probe_rows = [json.loads(line) for line in
                      evidence.data[item['probe_ref']['path']].splitlines()]
        endings = [row for row in probe_rows if row.get('nonce') == case['nonce'] and
                   row.get('pid') == item['pid'] and
                   row.get('connection_id') == item['connection_id'] and
                   row.get('event') in ('case_error', 'case_eof', 'case_close')]
        _require(bool(endings) and [evidence.read(ref) for ref in item['end_refs']] == endings,
                 'auxiliary probe terminal refs changed/incomplete')
        tcpip.validate_tuple_probe(probe_rows, origin, item['src'], item['dst'])
        observed = tcpip.connection_events(text, capture['text_path'], log,
            item['pid'], item['src'], item['dst'], managed_pid, log_path=case['run_log_path'])
        _require(item['connection_refs'] == [e['ref'] for e in observed['events']] and
                 item['tuple_terminal_refs'] == [e['ref'] for e in observed['tuple_terminals']] and
                 item['generation_manifest'] == observed['generation_manifest'] and
                 bool(observed['termination']), 'auxiliary native lifecycle/ref set changed')
        named = dict(observed, tuple_terminals=[])
        targets, selectors = qpc.choose_targets(named, legacy / 'raw/paired.jsonl')
        binding = {'run_id': case['run_id'], 'case_index': item['case_index'],
                   'connection_id': item['connection_id']}
        for target, selector in zip(targets, selectors):
            target.update(binding)
            selector.update(binding)
        named_targets.extend(targets)
        named_selectors.extend(selectors)
        aux.validate_named_tdh([by_seq[s['seq']] for s in selectors], targets,
            observed['connect']['tcb'], (observed['peer'] or {}).get('tcb'),
            item['pid'], managed_pid)
        ready = [row for row in probe_rows if row.get('event') == 'ready' and
                 row.get('nonce') == case['nonce']]
        child = [row for row in probe_rows if row.get('event') == 'process_ready' and
                 row.get('nonce') == case['nonce'] and row.get('pid') == item['pid']]
        _require(len(ready) == 1 and len(child) <= 1,
                 'auxiliary native probe ready ambiguous')
        identity = check_aux_provenance(evidence.read(capture['metadata_ref']), ready[0],
            child[0] if child else None, origin, header, case['candidate_id'],
            case['run_id'], managed_pid, managed_created)
        identities.append(identity)
        lower, upper = identity['capture_qpc']['before'][1], identity['capture_qpc']['after'][0]
        _require(all(lower <= row['raw_qpc'] <= upper for row in selectors),
                 'named event outside QPC capture window')
        by_ref = {json.dumps(t['pktmon_ref'], sort_keys=True): s['raw_qpc']
                  for t, s in zip(targets, selectors)}
        establishes = [observed['connect']['ref']]
        if observed['peer']:
            establishes.append(observed['peer']['ref'])
        begin = max(by_ref[json.dumps(ref, sort_keys=True)] for ref in establishes)
        zero_proof = adjudicate_zeros(single_rows, observed, item['src'], item['dst'],
                                      begin, lower, upper)
        cases.append({'case_index': item['case_index'], 'connection_id': item['connection_id'],
            'pid': item['pid'], 'src': item['src'], 'dst': item['dst'],
            'tuple_terminal_refs': item['tuple_terminal_refs'],
            'begin_qpc': begin, **zero_proof,
            'legacy_utc_source': 'pktmon.txt', 'legacy_v1_binding_status':
                legacy_manifest.get('candidate_binding_status')})
    _require(all(identity == identities[0] for identity in identities[1:]),
             'auxiliary cases have mixed native identity')
    _require(len({s['seq'] for s in named_selectors}) == len(named_selectors) and
             all(s in selected for s in named_selectors) and
             all(t in legacy_manifest.get('targets', []) for t in named_targets),
             'legacy named selector/target differs')
    _require(len(cases) == len(case['cases']), 'auxiliary case proof count differs')
    after = {str(path): raw.sha_file(path) for path in paths}
    _require(before == after, 'auxiliary v2 inputs changed during rebuild')
    proof = {'schema': PROOF_SCHEMA, 'status': 'COMPLETE_FORMAL_INPUT',
             'source_windows_status': 'COMPLETE_DIAGNOSTIC_ONLY',
             'candidate_id': case['candidate_id'], 'run_id': case['run_id'],
             'nonce': case['nonce'], 'identity': identities[0], 'cases': cases,
             'single_pass': {'scan': single_manifest['scan'],
                             'rst_records': single_manifest['rst_records'],
                             'source_etl': single_manifest['input_before']},
             'legacy_v1_status': legacy_manifest['status'],
             'inputs_before': before, 'inputs_after': after}
    if require_windows:
        windows = _read(export / 'manifest.json')
        _require(windows.get('schema') == SCHEMA and
                 windows.get('status') == 'COMPLETE_DIAGNOSTIC_ONLY' and
                 windows.get('error') is None and
                 windows.get('candidate_id') == case['candidate_id'] and
                 windows.get('run_id') == case['run_id'] and
                 windows.get('nonce') == case['nonce'] and
                 windows.get('identity') == identities[0] and
                 windows.get('cases') == cases and
                 windows.get('inputs_before') == windows.get('inputs_after') and
                 Counter((item['bytes'], item['sha256']) for item in
                         windows.get('inputs_before', {}).values()) ==
                    Counter((before[str(path)]['bytes'], before[str(path)]['sha256'])
                            for path in paths[:1 + len(case['files'])]),
                 'Windows v2 export proof/identity/integrity differs')
    return proof


def run(case_path, evidence_root, output):
    case_path, evidence_root, output = map(Path, (case_path, evidence_root, output))
    output.mkdir(parents=True, exist_ok=False)
    manifest = {'schema': SCHEMA, 'status': 'INCOMPLETE', 'error': None,
                'inputs_before': {}, 'inputs_after': {}}
    paths = [case_path]
    try:
        case = _read(case_path)
        paths += [(evidence_root / item['path']).resolve() for item in case['files']]
        manifest['inputs_before'] = {str(path): raw.sha_file(path) for path in paths}
        etl = evidence_root / case['capture']['etl_path']
        single_result = single.export(etl, output / 'single')
        _require(single_result['status'] == 'COMPLETE_DIAGNOSTIC_ONLY',
                 'single-pass native scan incomplete')
        aux.run(case_path, evidence_root, output / 'legacy')
        proof = rebuild(case_path, evidence_root, output, require_windows=False)
        manifest.update(candidate_id=case['candidate_id'], run_id=case['run_id'],
                        nonce=case['nonce'], identity=proof['identity'],
                        cases=proof['cases'], single_pass=proof['single_pass'],
                        legacy_v1_status=proof['legacy_v1_status'],
                        status='COMPLETE_DIAGNOSTIC_ONLY')
    except BaseException as exc:
        manifest['error'] = {'type': type(exc).__name__, 'message': str(exc),
                             'traceback': traceback.format_exc()}
    finally:
        manifest['inputs_after'] = {str(path): raw.sha_file(path)
                                    for path in paths if path.is_file()}
        if manifest['inputs_after'] != manifest['inputs_before']:
            manifest['status'] = 'INCOMPLETE'
            manifest['error'] = {'type': 'InputChanged', 'message': 'v2 input changed'}
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2,
            ensure_ascii=False, sort_keys=True) + '\n')
    return manifest


def derive(case_path, evidence_root, export, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    proof = rebuild(case_path, evidence_root, export)
    # Bind the final Windows manifest as well as the complete raw graph.
    proof['windows_manifest'] = raw.sha_file(Path(export) / 'manifest.json')
    (output / 'derived.json').write_text(json.dumps(proof, indent=2, sort_keys=True) + '\n')
    return proof


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--evidence-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = run(args.case.resolve(), args.evidence_root.resolve(), args.output.resolve())
    print(json.dumps({'status': result['status'],
                      'error': (result['error'] or {}).get('message')}))
    return 0 if result['status'] == 'COMPLETE_DIAGNOSTIC_ONLY' else 1


if __name__ == '__main__':
    raise SystemExit(main())
