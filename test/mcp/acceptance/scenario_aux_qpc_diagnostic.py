#!/usr/bin/env python3
"""Collect and verify auxiliary TCP native clock and TDH originals."""
import argparse
import base64
import hashlib
import json
import re
import struct
from pathlib import Path
import sys
import traceback

import etl_raw_clock as raw_clock
import scenario_qpc_diagnostic as qpc
import scenario_tcpip as tcpip
import sst_fault_evidence as fault
import tdh_metadata
import scenario_qpc_offline as offline
from scenario_qpc_identity import check_aux_provenance

ZERO_TCB_DESCRIPTOR = 'c70500100400ba058000000080000080'
ZERO_TCB_REASON_MAP = 'TCP_RST_SEND_REASON_ValueMap'
AUX_STATES = dict(qpc._OBSERVED_STATES, FinWait2=6, CloseWait=7, LastAck=9)
AUX_EXTRA = {
    'abort issued': (1039, 1, '0f04011004000f048404000010000080', 'TcpAbortTcbRequest'),
    'abort completed': (1040, 1, '10040110040010048404000010000080', 'TcpAbortTcbComplete'),
    'sent RST': (1479, 0, ZERO_TCB_DESCRIPTOR, 'TcpRstSend'),
}


def validate_named_tdh(rows, targets, primary_tcb, peer_tcb, probe_pid, managed_pid):
    """Preserve the complete named generation, including auxiliary abort/RST roles."""
    if len(rows) != len(targets):
        raise raw_clock.DiagnosticError('auxiliary named TDH target count differs')
    ordinary = [(row, target) for row, target in zip(rows, targets)
                if target['kind'] not in AUX_EXTRA]
    named = qpc.validate_tdh_semantics([row for row, _ in ordinary],
        [target for _, target in ordinary], primary_tcb, peer_tcb,
        probe_pid, managed_pid, states=AUX_STATES)
    for row, target in zip(rows, targets):
        kind = target['kind']
        if kind not in AUX_EXTRA:
            continue
        event_id, version, descriptor, task = AUX_EXTRA[kind]
        record, parsed = row['record'], row['tdh']['parsed']
        if (not target['terminal'] or record['provider'] != qpc.TCPIP_PROVIDER or
                parsed['provider_guid'] != qpc.TCPIP_PROVIDER or
                record['id'] != event_id or record['task'] != (
                    1466 if kind == 'sent RST' else event_id) or
                record['version'] != version or record['opcode'] != 0 or
                parsed['event_descriptor_bytes'] != descriptor or
                parsed['strings'].get('task') != task or
                parsed['strings'].get('provider') != 'Microsoft-Windows-TCPIP' or
                qpc._property(row, 'Tcb') != int(target['tcb'], 16).to_bytes(8, 'little')):
            raise raw_clock.DiagnosticError('auxiliary named abort/RST TDH role differs')
        prefix = 'SockAddr' if kind == 'sent RST' else 'Address'
        for side, endpoint in (('Local', target['local']), ('Remote', target['remote'])):
            if qpc._property(row, side + prefix) != qpc._sockaddr(endpoint).ljust(16, b'\0'):
                raise raw_clock.DiagnosticError('auxiliary named abort/RST endpoint differs')
        if kind == 'sent RST':
            if (qpc._property(row, 'IPTransportProtocol') != (6).to_bytes(4, 'little') or
                    qpc._property(row, 'AddressFamily') != (2).to_bytes(4, 'little') or
                    len(qpc._property(row, 'Reason')) != 4):
                raise raw_clock.DiagnosticError('auxiliary named RST properties differ')
        else:
            pid = qpc._property(row, 'ProcessId')
            start = qpc._property(row, 'ProcessStartKey')
            expected_pid = (probe_pid if target['tcb'] == primary_tcb else
                            managed_pid if target['tcb'] == peer_tcb else None)
            expected_start = named['process_start_keys'].get(target['tcb'])
            if not ((pid == b'\0' * 4 and start == b'\0' * 8) or
                    (expected_pid is not None and expected_start is not None and
                     pid == expected_pid.to_bytes(4, 'little') and
                     start == bytes.fromhex(expected_start))):
                raise raw_clock.DiagnosticError('auxiliary named abort attribution differs')


def parse_reason_map(blob):
    """Decode the documented EVENT_MAP_INFO/ENTRY layout, with bounded strings."""
    if len(blob) < 24:
        raise raw_clock.DiagnosticError('Reason EVENT_MAP_INFO truncated')
    name_offset, flags, count, value_type = struct.unpack_from('<4I', blob)
    # Manifest value map, ULONG Value (MAP_VALUETYPE zero), 8-byte entries.
    end_entries = 16 + count * 8
    if flags != 1 or value_type != 0 or not 1 <= count <= 4096 or end_entries > len(blob):
        raise raw_clock.DiagnosticError('Reason map flags/value type/entries invalid')

    def string_at(offset):
        if offset < end_entries or offset >= len(blob) or offset % 2:
            raise raw_clock.DiagnosticError('Reason map string offset outside buffer')
        end = offset
        while end + 1 < len(blob) and blob[end:end + 2] != b'\0\0':
            end += 2
        if end + 1 >= len(blob):
            raise raw_clock.DiagnosticError('Reason map unterminated string')
        return blob[offset:end].decode('utf-16-le'), end + 2

    name, name_end = string_at(name_offset)
    if name != ZERO_TCB_REASON_MAP:
        raise raw_clock.DiagnosticError('Reason map internal name differs')
    entries, spans, values = [], [(name_offset, name_end)], set()
    for index in range(count):
        offset, value = struct.unpack_from('<2I', blob, 16 + index * 8)
        label, label_end = string_at(offset)
        if value in values or not label:
            raise raw_clock.DiagnosticError('Reason map duplicate value/empty label')
        values.add(value)
        entries.append({'value': value, 'text': label})
        spans.append((offset, label_end))
    spans.sort()
    if (any(blob[end_entries:spans[0][0]]) or spans[-1][1] != len(blob) or any(
            left[1] != right[0] for left, right in zip(spans, spans[1:]))):
        raise raw_clock.DiagnosticError('Reason map bytes contain gap/overlap/trailing data')
    match = [item for item in entries if item['value'] == 0]
    if len(match) != 1 or match[0]['text'] != 'Receive discarded ':
        raise raw_clock.DiagnosticError('Reason zero value is not Receive discarded')
    return {'name': name, 'flags': flags, 'value_type': value_type,
            'entries': entries, 'reason_zero_label': match[0]['text']}


def unique_zero_bindings(candidate_sets):
    """A formatted zero-TCB ref must bind to one full raw identity and seq."""
    by_ref, used = {}, set()
    for group in candidate_sets:
        candidates = group['candidates']
        if (group['status'] != 'DIAGNOSTIC_CANDIDATES_UNRESOLVED' or
                len(candidates) != 1 or len(group['exact_filetime_anchor_seqs']) != 1):
            raise raw_clock.DiagnosticError('zero-TCB no verified unique TDH binding: raw/default pairing')
        item = candidates[0]
        seq = item['seq']
        if (seq != group['exact_filetime_anchor_seqs'][0] or
                item['binding_status'] != 'unique' or item['identity_occurrences'] != 1 or
                item['selection_reason'] != 'EXACT_FORMATTED_FILETIME' or seq in used):
            raise raw_clock.DiagnosticError('zero-TCB no verified unique TDH binding: full non-time identity')
        key = json.dumps(group['pktmon_ref'], sort_keys=True)
        if key in by_ref:
            raise raw_clock.DiagnosticError('zero-TCB formatted reference reused')
        used.add(seq)
        by_ref[key] = item
    return by_ref


def candidate_field_facts(tdh_rows, candidate_sets, selectors, *, strict=False):
    """Check RST bytes; formal mode additionally requires the decoded map."""
    selected = {item['seq']: item for item in selectors}
    rows = {item['selector']['seq']: item for item in tdh_rows}
    if (len(selected) != len(selectors) or len(rows) != len(tdh_rows)
            or set(rows) != set(selected)):
        raise raw_clock.DiagnosticError('TDH candidate/named selector set differs')
    candidate_refs = {}
    for group in candidate_sets:
        for item in group['candidates']:
            candidate_refs.setdefault(item['seq'], []).append(group)
    facts = []
    for seq, groups in sorted(candidate_refs.items()):
        row = rows[seq]
        if row['selector'] != selected[seq]:
            raise raw_clock.DiagnosticError('TDH zero-TCB selector identity differs')
        record, parsed = row['record'], row['tdh']['parsed']
        if (record['provider'] != qpc.TCPIP_PROVIDER or
                parsed['provider_guid'] != qpc.TCPIP_PROVIDER or
                record['id'] != 1479 or record['version'] != 0 or
                record['opcode'] != 0 or record['task'] != 1466 or
                parsed['event_descriptor_bytes'] != ZERO_TCB_DESCRIPTOR or
                parsed['strings'].get('provider') != 'Microsoft-Windows-TCPIP' or
                parsed['strings'].get('task') != 'TcpRstSend'):
            raise raw_clock.DiagnosticError('TDH zero-TCB provider/descriptor/task differs')
        expected = {'Tcb': b'\0' * 8, 'IPTransportProtocol': (6).to_bytes(4, 'little'),
                    'AddressFamily': (2).to_bytes(4, 'little'),
                    'LocalSockAddrLength': (16).to_bytes(4, 'little'),
                    'RemoteSockAddrLength': (16).to_bytes(4, 'little'),
                    'Reason': b'\0' * 4}
        for group in groups:
            for name, endpoint in (('LocalSockAddr', group['local']),
                                   ('RemoteSockAddr', group['remote'])):
                value = qpc._sockaddr(endpoint).ljust(16, b'\0')
                if name in expected and expected[name] != value:
                    raise raw_clock.DiagnosticError('zero-TCB candidate tuples conflict')
                expected[name] = value
        by_name = {item['name']: item for item in row['property_results']}
        meta = {item['name']: item for item in parsed['properties']}
        if (len(by_name) != len(row['property_results']) or
                len(meta) != len(parsed['properties'])):
            raise raw_clock.DiagnosticError('TDH zero-TCB property duplicate')
        for name, value in expected.items():
            if name not in by_name or qpc._property(row, name) != value:
                raise raw_clock.DiagnosticError('TDH zero-TCB property differs: ' + name)
        for name in ('LocalSockAddr', 'RemoteSockAddr'):
            if (meta[name]['flags'] != 2 or
                    meta[name]['in_type_or_struct_start'] != 14 or
                    meta[name]['out_type_or_struct_members'] != 25):
                raise raw_clock.DiagnosticError('TDH zero-TCB SockAddr type differs')
        reason = meta['Reason']
        if (reason['flags'] != 0 or reason['in_type_or_struct_start'] != 8 or
                reason['out_type_or_struct_members'] != 8 or
                reason['length_or_index'] != 4 or
                meta['Tcb']['flags'] != 0 or meta['Tcb']['length_or_index'] != 8):
            raise raw_clock.DiagnosticError('TDH zero-TCB Reason/Tcb type differs')
        blob = base64.b64decode(row['tdh']['buffer_base64'], validate=True)
        if (reason['map_or_schema_offset'] <= 0 or
                tdh_metadata.utf16_at(blob, reason['map_or_schema_offset']) !=
                ZERO_TCB_REASON_MAP):
            raise raw_clock.DiagnosticError('TDH zero-TCB Reason map name differs')
        map_result = by_name['Reason'].get('event_map') or {}
        map_bytes = (base64.b64decode(map_result['buffer_base64'], validate=True)
                     if map_result.get('buffer_base64') else None)
        captured = (map_result.get('name') == ZERO_TCB_REASON_MAP and
                    map_result.get('first_status') == 122 and
                    map_result.get('second_status') == 0 and
                    map_bytes is not None and
                    len(map_bytes) == map_result.get('required_size', len(map_bytes) if not strict else None) and
                    hashlib.sha256(map_bytes).hexdigest() == map_result.get('buffer_sha256'))
        decoded = None
        if captured:
            try:
                decoded = parse_reason_map(map_bytes)
            except raw_clock.DiagnosticError:
                if strict:
                    raise
        if strict and decoded is None:
            raise raw_clock.DiagnosticError('Reason map original absent')
        facts.append({'seq': seq, 'candidate_ref_count': len(groups),
                      'status': ('REASON_MAP_VERIFIED' if decoded else
                                 'REASON_MAP_OPAQUE_UNVERIFIED' if captured else
                                 'REASON_MAP_NOT_CAPTURED'),
                      'reason_raw_hex': expected['Reason'].hex(),
                      'reason_map_name': ZERO_TCB_REASON_MAP,
                      'reason_map_sha256': (map_result.get('buffer_sha256') if captured else None),
                      'tdh_descriptor_hex': ZERO_TCB_DESCRIPTOR,
                      'reason_label': decoded['reason_zero_label'] if decoded else None})
    return facts


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
        observed_cases = []
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
            observed_cases.append((observed, targets, selectors, auxiliary['pid']))
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
        tdh_rows = [json.loads(line) for line in
                    (output / 'tdh/metadata.jsonl').read_text(encoding='utf-8').splitlines()]
        manifest['candidate_field_facts'] = candidate_field_facts(
            tdh_rows, all_candidate_sets, selected)
        bindings = unique_zero_bindings(all_candidate_sets)
        offline.verify_export(output, etl, output)
        offline.verify_tdh_rows(tdh_rows, selected)
        manifest['candidate_field_facts'] = candidate_field_facts(
            tdh_rows, all_candidate_sets, selected, strict=True)
        by_seq = {row['selector']['seq']: row for row in tdh_rows}
        for detail, (observed, targets, selectors, probe_pid) in zip(details, observed_cases):
            validate_named_tdh([by_seq[s['seq']] for s in selectors], targets,
                observed['connect']['tcb'], (observed['peer'] or {}).get('tcb'),
                probe_pid, managed_pid)
            groups = [group for group in all_candidate_sets
                      if group['case_index'] == detail['case_index'] and
                      group['connection_id'] == detail['connection_id']]
            by_ref = {json.dumps(target['pktmon_ref'], sort_keys=True): selector['raw_qpc']
                      for target, selector in zip(targets, selectors)}
            establish = [observed['connect']['ref']]
            if observed['peer']:
                establish.append(observed['peer']['ref'])
            begin = max(by_ref[json.dumps(ref, sort_keys=True)] for ref in establish)
            zeros = [bindings[json.dumps(group['pktmon_ref'], sort_keys=True)] for group in groups]
            gaps = [item['raw_timestamp'] - begin for item in zeros]
            if any(gap <= 1 for gap in gaps):
                raise raw_clock.DiagnosticError('zero-TCB QPC at/before establishment margin')
            detail['native_zero_tcb'] = {'status': 'VERIFIED' if zeros else 'NO_ZERO_TCB',
                'begin_qpc': begin, 'zero_qpc': [item['raw_timestamp'] for item in zeros],
                'zero_seqs': [item['seq'] for item in zeros], 'gaps_ticks': gaps,
                'passed': True}
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
        capture_window = identities[0]['capture_qpc']
        low, high = capture_window['before'][1], capture_window['after'][0]
        if any(not low <= item['raw_qpc'] <= high for item in selected):
            raise raw_clock.DiagnosticError('auxiliary native target outside capture QPC window')
        if not all_candidate_sets:
            raise raw_clock.DiagnosticError('NO_ZERO_TCB_BRANCH: native negative branch unobserved')
        manifest['candidate_binding_status'] = 'UNIQUE_VERIFIED'
        manifest['status'] = 'COMPLETE_DIAGNOSTIC_ONLY'
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
