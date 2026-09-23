#!/usr/bin/env python3
"""Verify an existing Windows QPC export and derive offline-only observations."""
import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile

import etl_raw_clock as raw
import scenario_qpc_diagnostic as qpc
from scenario_qpc_identity import check_provenance
import scenario_tcpip as tcpip
import sst_fault_evidence as fault
import tdh_metadata as tdh

QPC_ORDERING_SOURCE = ('https://learn.microsoft.com/en-us/windows/win32/sysinfo/'
                       'acquiring-high-resolution-time-stamps')


def require(condition, message):
    if not condition:
        raise raw.DiagnosticError(message)


def _json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def _lines(path):
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            yield json.loads(line)


def _same_header(a, b):
    return {k: v for k, v in a.items() if not k.endswith('_pointer')} == {
        k: v for k, v in b.items() if not k.endswith('_pointer')}


def verify_case_refs(value, evidence):
    """Resolve every case byte reference through the case's hashed file list."""
    if isinstance(value, dict):
        if {'path', 'byte_start', 'byte_end', 'event_key'} <= value.keys():
            evidence.read(value)
            return 1
        return sum(verify_case_refs(item, evidence) for item in value.values())
    if isinstance(value, list):
        return sum(verify_case_refs(item, evidence) for item in value)
    return 0


def verify_export(export, etl, output):
    """Re-pair both original passes, then check their selectors and TDH ledger."""
    rm, tm = _json(export / 'raw/manifest.json'), _json(export / 'tdh/manifest.json')
    source = _json(export / 'selectors.json')
    etl_hash = raw.sha_file(etl)
    require(rm.get('schema') == raw.SCHEMA and rm.get('status') == 'COMPLETE_DIAGNOSTIC_ONLY'
            and rm.get('error') is None and rm.get('host', {}).get('system') == 'Windows'
            and rm.get('input_before') == rm.get('input_after') == etl_hash,
            'raw two-pass manifest failed or ETL identity changed')
    passes = rm.get('passes', [])
    count = rm.get('paired_events')
    require(len(passes) == 2 and [p.get('mode') for p in passes] == ['raw', 'default']
            and isinstance(count, int) and count > 0 and
            all(type(p.get('open_trace_handle')) is int and
                0 < p['open_trace_handle'] < 0xffffffffffffffff and
                p.get('events') == count and p.get('process_trace_return') == 0
                and p.get('close_trace_return') == 0 and p.get('events_lost_output') == 0
                and p.get('header', {}).get('EventsLost') == 0
                and p.get('header', {}).get('BuffersLost') == 0 for p in passes)
            and _same_header(passes[0]['header'], passes[1]['header'])
            and passes[0]['header'].get('ReservedFlags') == 1,
            'raw/default pass count, clock or native API status differs')
    with tempfile.TemporaryDirectory(dir=output) as tmp:
        rebuilt = Path(tmp) / 'paired.jsonl'
        pairing = raw.pair_streams(export / 'raw/raw.jsonl', export / 'raw/default.jsonl', rebuilt)
        require(pairing == rm.get('pairing') and pairing['events'] == count,
                'raw/default pairing differs from Windows manifest')
        # Close both handles before TemporaryDirectory cleanup, including on
        # a mismatch: Wine/Windows keeps an open JSONL file locked.
        with (export / 'raw/paired.jsonl').open(encoding='utf-8') as original, \
                rebuilt.open(encoding='utf-8') as derived:
            for index in range(count):
                a, b = original.readline(), derived.readline()
                require(bool(a) and bool(b) and json.loads(a) == json.loads(b),
                        'paired row changed at seq ' + str(index))
            require(not original.readline() and not derived.readline(),
                    'paired row count differs')
    require(source.get('schema') == 'fakenet.t007-r02-tdh-selectors.v1'
            and source.get('source_event_count') == count
            and source.get('source_etl_sha256') == etl_hash['sha256']
            and isinstance(source.get('selectors'), list), 'selector source identity invalid')
    selectors = source['selectors']
    require(len(selectors) == len({x['seq'] for x in selectors}), 'duplicate selector seq')
    require(tm.get('schema') == 'fakenet.t007-r02-tdh-metadata.v1'
            and tm.get('status') == 'COMPLETE_DIAGNOSTIC_ONLY' and tm.get('error') is None
            and tm.get('input_before') == tm.get('input_after') == {
                'etl': etl_hash, 'selectors': raw.sha_file(export / 'selectors.json')}
            and tm.get('source_event_count') == tm.get('observed_count') == count
            and tm.get('target_count') == tm.get('target_records') ==
                tm.get('tdh_success_count') == len(selectors)
            and tm.get('property_failure_count') == 0
            and type(tm.get('api', {}).get('open_trace_handle')) is int
            and 0 < tm['api']['open_trace_handle'] < 0xffffffffffffffff
            and tm.get('api', {}).get('process_trace_return') == 0
            and tm.get('api', {}).get('close_trace_return') == 0
            and _same_header(tm.get('api', {}).get('header', {}), passes[0]['header']),
            'TDH manifest failed or differs from raw source')
    return source, passes[0]['header']


def verify_tdh_rows(rows, selectors):
    """Verify exported TDH rows against original selectors and binary metadata."""
    require(len(rows) == len(selectors), 'TDH target row count incomplete')
    by_seq = {s['seq']: s for s in selectors}
    require(len(by_seq) == len(selectors), 'duplicate selector seq')
    seen = set()
    for row in rows:
        selector = row.get('selector', {})
        seq = selector.get('seq')
        require(seq in by_seq and seq not in seen and selector == by_seq[seq],
                'TDH selector missing, duplicate or changed')
        seen.add(seq)
        record = row['record']
        for field, source in (('timestamp', 'raw_qpc'), ('provider', 'provider'),
                              ('id', 'id'), ('version', 'version'), ('opcode', 'opcode'),
                              ('task', 'task'), ('userdata_sha256', 'userdata_sha256')):
            require(record[field] == selector[source], 'TDH record selector identity changed')
        require(raw.identity_digest(record) == selector['identity_sha256'],
                'TDH full non-time identity changed')
        blob = base64.b64decode(row['tdh']['buffer_base64'], validate=True)
        require(row['tdh']['second_status'] == 0
                and len(blob) == row['tdh']['required_size']
                and hashlib.sha256(blob).hexdigest() == row['tdh']['buffer_sha256']
                and tdh.parse_tei(blob) == row['tdh']['parsed'],
                'TDH binary metadata failed or changed')
        props = row['property_results']
        require(len(props) == len(row['tdh']['parsed']['properties']),
                'TDH property set incomplete')
        for prop, definition in zip(props, row['tdh']['parsed']['properties']):
            value = base64.b64decode(prop['raw_base64'], validate=True)
            require(prop['name'] == definition['name']
                    and prop['size_status'] == prop['property_status'] == 0
                    and len(value) == prop['size']
                    and hashlib.sha256(value).hexdigest() == prop['raw_sha256'],
                    'TDH property failed or changed')
    require(seen == set(by_seq), 'TDH terminal selector omitted')


def conservative_time_bounds(event, resolution_ns):
    """Mirror the formal oracle's uncertainty, not timestamp display precision."""
    require(type(resolution_ns) is int and 0 < resolution_ns <= 10**9,
            'invalid UTC resolution')
    lo, hi = fault.time_bounds(event)
    uncertainty = resolution_ns - 1
    return lo - uncertainty, hi + uncertainty


def derive(case_path, evidence_root, export, output):
    """All source reads are checked before writing a derived-only result."""
    output.mkdir(parents=True, exist_ok=False)
    case = _json(case_path)
    session = case['session']
    source_paths = [case_path] + [(evidence_root / item['path']).resolve()
                                for item in case['files']]
    source_paths += [export / item for item in ('manifest.json', 'raw/manifest.json',
        'raw/raw.jsonl', 'raw/default.jsonl', 'raw/paired.jsonl', 'selectors.json',
        'tdh/manifest.json', 'tdh/metadata.jsonl')]
    before = {str(p): raw.sha_file(p) for p in source_paths}
    evidence = fault.Evidence(evidence_root, case['files'])
    reference_count = verify_case_refs(case, evidence)
    require(reference_count > 0, 'case has no resolvable references')
    require(case['schema'] == 'sst.fault-evidence.case.v2' and case['synthetic'] is False,
            'unsupported or synthetic case')
    etl = (evidence_root / session['connection_capture']['etl_path']).resolve()
    selectors_source, header = verify_export(export, etl, output)
    capture = evidence.read(session['connection_capture']['metadata_ref'])
    action = next((evidence.read(ref) for ref in case['trigger']['success_refs']
                   if isinstance(evidence.read(ref), dict) and
                   evidence.read(ref).get('schema') == 'fakenet.fault-action.v1'), None)
    require(action is not None, 'fault action original missing')
    probe_rows = [json.loads(line) for line in
                  evidence.data[session['established_ref']['path']].splitlines()]
    ready = next((r for r in probe_rows if r.get('event') == 'ready'), None)
    process_ready = next((r for r in probe_rows if r.get('event') == 'process_ready'
                          and r.get('pid') == session['probe_pid']), None)
    established = evidence.read(session['established_ref'])
    ipc_rows = [json.loads(line) for line in
                evidence.data[case['start_response_ref']['path']].splitlines()]
    managed_pid, managed_created = tcpip.managed_identity(ipc_rows, case['run_id'])
    identity = check_provenance(capture, ready, process_ready, established, action,
        header, case['candidate_id'], case['run_id'], managed_pid, managed_created)
    text_path = session['connection_capture']['text_path']
    log_path = session['managed_ref']['path']
    observed = tcpip.connection_events(evidence.data[text_path], text_path,
        evidence.data[log_path].decode('utf-8-sig'), session['probe_pid'],
        session['src'], session['dst'], managed_pid, log_path=log_path)
    require(session['connection_event_refs'] == [e['ref'] for e in observed['events']]
            and session.get('tuple_terminal_refs', []) ==
                [e['ref'] for e in observed['tuple_terminals']]
            and session['generation_manifest'] == observed['generation_manifest'],
            'case lifecycle refs or generation changed')
    targets, selectors = qpc.choose_targets(observed, export / 'raw/paired.jsonl')
    windows = _json(export / 'manifest.json')
    expected_hashes = Counter((item['bytes'], item['sha256']) for item in
                              [before[str(p)] for p in source_paths[:1 + len(case['files'])]])
    require(windows.get('schema') == 'sst.qpc-diagnostic.v1'
            and windows.get('status') in ('INCOMPLETE', 'COMPLETE_DIAGNOSTIC_ONLY')
            and windows.get('formal_fault_verdict') == 'UNCHANGED'
            and (windows.get('status') != 'COMPLETE_DIAGNOSTIC_ONLY' or
                 (windows.get('capture_run_id') == capture['capture_run_id']
                  and windows.get('managed_run_id') == case['run_id']
                  and windows.get('candidate_id') == case['candidate_id']))
            and windows.get('inputs_before') == windows.get('inputs_after')
            and Counter((x['bytes'], x['sha256']) for x in
                        windows['inputs_before'].values()) == expected_hashes
            and windows.get('identity') == identity
            and windows.get('targets') == json.loads(json.dumps(targets)),
            'original Windows diagnostic manifest/source identity differs')
    require(selectors == selectors_source['selectors'], 'original selector set changed')
    rows = list(_lines(export / 'tdh/metadata.jsonl'))
    verify_tdh_rows(rows, selectors)
    semantics = qpc.validate_tdh_semantics(rows, targets, observed['connect']['tcb'],
        (observed['peer'] or {}).get('tcb'), session['probe_pid'], managed_pid)
    if windows['status'] == 'COMPLETE_DIAGNOSTIC_ONLY':
        require(windows.get('error') is None and windows.get('tdh_semantics') == semantics,
                'complete Windows diagnostic terminal or TDH semantics differ')
    by_seq = {s['seq']: s for s in selectors}
    details = [{**t, 'raw_qpc': by_seq[t['seq']]['raw_qpc'],
                'utc_bounds_ns': fault.time_bounds(next(e['text'] for e in
                    observed['events'] + observed['tuple_terminals'] if e['ref'] == t['pktmon_ref']))}
               for t in targets]
    frequency = identity['qpc_frequency']
    establish_qpc = max(x['raw_qpc'] for x in details if not x['terminal'])
    terminal_qpc = min(x['raw_qpc'] for x in details if x['terminal'])
    brackets = {name: {k: action['clock_observations'][name][k]
                       for k in ('qpc_before', 'qpc_after')}
                for name in ('before', 'after')}
    for name in brackets:
        require(brackets[name]['qpc_before'] <= brackets[name]['qpc_after'],
                'action QPC bracket reversed')
    bounds = lambda event: conservative_time_bounds(event, case['clock']['resolution_ns'])
    begin_utc = max(bounds(established)[1],
                    bounds(evidence.read(session['managed_ref']))[1],
                    bounds(observed['connect']['text'])[1])
    trigger_lower = bounds(evidence.read(case['trigger']['lower_ref']))[0]
    trigger_upper = bounds(evidence.read(case['trigger']['upper_ref']))[1]
    end_utc = min([bounds(evidence.read(session['end_ref']))[0]] +
                  fault.terminal_bounds(observed, bounds))
    after = {str(p): raw.sha_file(p) for p in source_paths}
    require(before == after, 'source input changed during offline derivation')
    result = {'schema': 'sst.qpc-offline-derived.v1',
              'status': 'COMPLETE_DIAGNOSTIC_ONLY', 'formal_fault_verdict': 'UNCHANGED',
              'source_windows_status': windows['status'],
              'source_windows_error': (windows.get('error') or {}).get('message'),
              'case_reference_count': reference_count,
              'identity': identity, 'semantics': semantics, 'targets': details,
              'action_qpc_brackets': brackets, 'probe_established_mono': established['mono'],
              'conservative_utc_bounds_ns': {'session_begin_upper': begin_utc,
                  'trigger_lower': trigger_lower, 'trigger_upper': trigger_upper,
                  'session_end_lower': end_utc},
              'cross_thread_ordering': {'source': QPC_ORDERING_SOURCE,
                  'ambiguous_if_difference_at_most_ticks': 1,
                  'note': 'Microsoft QPC guidance; no acceptance tolerance added'},
              'diagnostic_qpc': {'latest_establishment': establish_qpc,
                'earliest_terminal': terminal_qpc,
                'establishment_to_terminal_ticks': terminal_qpc - establish_qpc,
                'establishment_to_terminal_ns':
                    (terminal_qpc - establish_qpc) * 1_000_000_000 // frequency,
                'establishment_to_terminal_cross_thread_lower_ticks':
                    max(0, terminal_qpc - establish_qpc - 1),
                'establishment_to_terminal_cross_thread_lower_ns':
                    max(0, terminal_qpc - establish_qpc - 1) * 1_000_000_000 // frequency,
                'action_after_upper_to_earliest_terminal_ticks':
                    terminal_qpc - brackets['after']['qpc_after'],
                'action_after_upper_to_earliest_terminal_ns':
                    (terminal_qpc - brackets['after']['qpc_after']) * 1_000_000_000 // frequency,
                'action_after_upper_to_earliest_terminal_cross_thread_lower_ticks':
                    max(0, terminal_qpc - brackets['after']['qpc_after'] - 1),
                'action_after_upper_to_earliest_terminal_cross_thread_lower_ns':
                    max(0, terminal_qpc - brackets['after']['qpc_after'] - 1)
                    * 1_000_000_000 // frequency},
              'inputs_before': before, 'inputs_after': after}
    (output / 'derived.json').write_text(json.dumps(result, indent=2,
        ensure_ascii=False, sort_keys=True) + '\n', encoding='utf-8')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', required=True, type=Path)
    parser.add_argument('--evidence-root', required=True, type=Path)
    parser.add_argument('--export', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    result = derive(args.case.resolve(), args.evidence_root.resolve(),
                    args.export.resolve(), args.output.resolve())
    print(json.dumps({'status': result['status'], 'target_count':
                      result['semantics']['target_count']}))


if __name__ == '__main__':
    main()
