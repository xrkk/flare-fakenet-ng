#!/usr/bin/env python3
"""One read-only diagnostic entry for a new SST case's native ETL/QPC chain.

The T007 R02 raw/default exporter and TDH decoder are reused verbatim. This
entry selects all native terminals from the current case, requires exact raw
identity and TDH semantics, and writes only into a new output directory. It
never changes the formal UTC fault verdict.
"""
import argparse
import base64
import json
from pathlib import Path
import re
import socket
import sys
import traceback

import etl_raw_clock as raw_clock
import scenario_tcpip as tcpip
import sst_fault_evidence as fault
import tdh_metadata
from scenario_qpc_identity import check_provenance, DiagnosticIdentityError

TCPIP_PROVIDER = '2f07e2ee-15db-40f1-90ef-9d7ba282188a'
# Win10 TCPIP/Diagnostic descriptors observed in the T007 TDH originals. The
# descriptor and TDH task name are checked together: a TCB is not an event role.
_DIALECT = {
    'connect completed': (1033, 1, '09040110040009048404000004000080', 'TcpConnectTcbComplete'),
    'accept completed': (1017, 1, 'f90301100400f9038604000004000080', 'TcpAcceptListenerComplete'),
    'connection terminated': (1184, 0, 'a00400100400a0048000000006000080', 'TcpConnectionTerminatedRcvdRst'),
    'shutdown initiated': (1044, 1, '14040110040014048404000010000080', 'TcpShutdownTcb'),
    'transition': (1051, 0, '1b04001004001b040404000000000080', 'TcpTcbStateChange'),
    'close issued': (1038, 1, '0e04011004000e040404000010000080', 'TcpCloseTcbRequest'),
    'disconnect completed': (1043, 1, '13040110040013048404000010000080', 'TcpDisconnectTcbComplete'),
}
_OBSERVED_STATES = {'Closed': 0, 'Established': 4, 'FinWait1': 5}
_UNATTRIBUTED_TERMINALS = {'close issued', 'disconnect completed'}


def _role(record, target, states=None):
    kind = target['kind']
    if kind not in _DIALECT:
        raise raw_clock.DiagnosticError('unverified TCPIP terminal role: ' + kind)
    event_id, version, descriptor, task_name = _DIALECT[kind]
    actual = record['record']
    parsed = record['tdh']['parsed']
    if (actual.get('provider') != TCPIP_PROVIDER or
            parsed.get('provider_guid') != TCPIP_PROVIDER or
            actual.get('id') != event_id or actual.get('task') != event_id or
            actual.get('version') != version or actual.get('opcode') != 0 or
            parsed.get('event_descriptor_bytes') != descriptor or
            parsed.get('strings', {}).get('task') != task_name or
            parsed.get('strings', {}).get('provider') != 'Microsoft-Windows-TCPIP'):
        raise raw_clock.DiagnosticError('TDH descriptor/task does not prove selected role')
    if kind == 'transition':
        pair = target.get('transition')
        states = _OBSERVED_STATES if states is None else states
        if (not pair or len(pair) != 2 or
                any(state not in states for state in pair)):
            raise raw_clock.DiagnosticError('unverified TCPIP transition state')
        for name, state in zip(('OldState', 'NewState'), pair):
            if _property(record, name) != states[state].to_bytes(4, 'little'):
                raise raw_clock.DiagnosticError('TDH transition state differs from terminal')
        if target.get('terminal') != (pair in tcpip.TERMINATE):
            raise raw_clock.DiagnosticError('TCPIP transition terminal role changed')
    elif kind in ('connect completed', 'accept completed'):
        if target.get('terminal'):
            raise raw_clock.DiagnosticError('establishment marked terminal')
        if _property(record, 'Status') != b'\0' * 4:
            raise raw_clock.DiagnosticError('TDH establishment status is not success')
    elif not target.get('terminal'):
        raise raw_clock.DiagnosticError('native terminal role changed')
    if kind == 'connection terminated' and _property(record, 'NewState') != b'\0' * 4:
        raise raw_clock.DiagnosticError('TDH RST termination did not reach Closed')


def _input_hash(path):
    return raw_clock.sha_file(path)


def _property(record, name):
    rows = [p for p in record['property_results'] if p['name'] == name]
    if len(rows) != 1 or rows[0]['size_status'] != 0 or rows[0]['property_status'] != 0:
        raise raw_clock.DiagnosticError('TDH property missing/ambiguous: ' + name)
    return base64.b64decode(rows[0]['raw_base64'], validate=True)


def _optional_property(record, name):
    rows = [p for p in record['property_results'] if p['name'] == name]
    return _property(record, name) if rows else None


def _sockaddr(value):
    host, port = value.rsplit(':', 1)
    return b'\x02\x00' + int(port).to_bytes(2, 'big') + socket.inet_aton(host)


def validate_tdh_semantics(records, targets, primary_tcb, peer_tcb, probe_pid,
                           managed_pid, *, states=None):
    """Verify TDH Tcb/endpoint/process properties for every selected target."""
    by_ref = {json.dumps(t['pktmon_ref'], sort_keys=True): t for t in targets}
    if len(by_ref) != len(targets) or len(records) != len(targets):
        raise raw_clock.DiagnosticError('missing/duplicate selected native target')
    start_keys = {}
    for record in records:
        selector = record['selector']
        key = json.dumps(selector['pktmon_ref'], sort_keys=True)
        if key not in by_ref:
            raise raw_clock.DiagnosticError('TDH returned an unselected target')
        target = by_ref.pop(key)
        if selector['tcb'] != target['tcb'] or selector['target_kind'] != target['kind']:
            raise raw_clock.DiagnosticError('TDH target role/TCB changed')
        _role(record, target, states)
        tcb = target['tcb']
        if tcb and tcb != '0X0':
            if _property(record, 'Tcb') != int(tcb, 16).to_bytes(8, 'little'):
                raise raw_clock.DiagnosticError('TDH Tcb differs from selected generation')
        elif not target.get('local') or not target.get('remote'):
            raise raw_clock.DiagnosticError('identity-less tuple terminal lacks exact endpoints')
        for name, endpoint in (('LocalAddress', target.get('local')),
                               ('RemoteAddress', target.get('remote'))):
            value = _optional_property(record, name)
            if endpoint and (value is None or len(value) != 16 or
                             value != _sockaddr(endpoint).ljust(16, b'\0')):
                raise raw_clock.DiagnosticError('TDH ' + name + ' differs from selected tuple')
            if (tcb == '0X0' and value is None):
                raise raw_clock.DiagnosticError('tuple terminal TDH endpoint missing')
        pid_raw = _optional_property(record, 'ProcessId')
        expected_pid = probe_pid if tcb == primary_tcb else managed_pid if tcb == peer_tcb else None
        if pid_raw is not None:
            if len(pid_raw) != 4:
                raise raw_clock.DiagnosticError('TDH ProcessId has wrong width')
            pid = int.from_bytes(pid_raw, 'little')
            if pid and expected_pid and pid != expected_pid:
                raise raw_clock.DiagnosticError('TDH ProcessId differs from selected connection')
        if target['kind'] in ('connect completed', 'accept completed'):
            if expected_pid is None or pid_raw is None or int.from_bytes(pid_raw, 'little') != expected_pid:
                raise raw_clock.DiagnosticError('TDH establishment process missing/mismatch')
        start_key = _optional_property(record, 'ProcessStartKey')
        if target['kind'] in ({'connect completed', 'accept completed',
                               'shutdown initiated'} | _UNATTRIBUTED_TERMINALS) and (
                pid_raw is None or start_key is None):
            raise raw_clock.DiagnosticError('TDH process identity fields missing')
        if target['kind'] in ('connect completed', 'accept completed') and (
                start_key is None or len(start_key) != 8 or not any(start_key)):
            raise raw_clock.DiagnosticError('TDH establishment ProcessStartKey missing/zero')
        if start_key is not None:
            if len(start_key) != 8:
                raise raw_clock.DiagnosticError('TDH ProcessStartKey has wrong width')
            if not any(start_key):
                # Only verified close/disconnect TDH descriptors lack attribution.
                if target['kind'] not in _UNATTRIBUTED_TERMINALS or pid_raw != b'\0' * 4:
                    raise raw_clock.DiagnosticError('unexpected zero ProcessStartKey')
            elif tcb != '0X0':
                if tcb in start_keys and start_keys[tcb] != start_key:
                    raise raw_clock.DiagnosticError('TDH ProcessStartKey changed within TCB')
                start_keys[tcb] = start_key
        if pid_raw == b'\0' * 4 and target['kind'] not in _UNATTRIBUTED_TERMINALS:
            raise raw_clock.DiagnosticError('unexpected zero ProcessId')
        if target['kind'] in _UNATTRIBUTED_TERMINALS and (pid_raw is None or start_key is None or
                (pid_raw == b'\0' * 4) != (start_key == b'\0' * 8)):
            raise raw_clock.DiagnosticError('unattributed terminal identity fields inconsistent')
    if by_ref:
        raise raw_clock.DiagnosticError('one or more selected native terminals omitted by TDH')
    if primary_tcb not in start_keys or (peer_tcb and peer_tcb not in start_keys):
        raise raw_clock.DiagnosticError('establishment ProcessStartKey missing')
    return {'target_count': len(targets), 'process_start_keys':
            {k: v.hex() for k, v in start_keys.items()}}


def choose_targets(observed, paired_path):
    """Exact FILETIME plus TCPIP/TCB match; ambiguity never picks first."""
    selected = [e for e in observed['events'] if e['terminal'] or
                e['ref'] == observed['connect']['ref'] or
                (observed['peer'] and e['ref'] == observed['peer']['ref'])]
    selected += observed['tuple_terminals']
    if not selected or not observed['termination'] and not observed['tuple_terminals']:
        raise raw_clock.DiagnosticError('selected native generation has no terminal')
    stamps = {}
    for event in selected:
        match = re.search(r'::(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)', event['text'])
        if not match:
            raise raw_clock.DiagnosticError('native target has no exact pktmon time')
        stamp = raw_clock.pktmon_filetime(match.group(1) + '+08:00')
        stamps.setdefault(stamp, []).append(event)
    rows = {stamp: [] for stamp in stamps}
    with paired_path.open(encoding='utf-8') as stream:
        for line in stream:
            row = json.loads(line)
            if row['default_filetime_100ns'] in rows:
                rows[row['default_filetime_100ns']].append(row)
    targets, selectors = [], []
    for stamp, events in stamps.items():
        for event in events:
            tcb = event.get('tcb')
            needle = int(tcb, 16).to_bytes(8, 'little') if tcb and tcb != '0X0' else None
            options = []
            for row in rows[stamp]:
                if row['provider'] != TCPIP_PROVIDER or row['identity_occurrences'] != 1:
                    continue
                payload = base64.b64decode(row['userdata_base64'], validate=True)
                if needle is not None and needle not in payload:
                    continue
                options.append(row)
            if len(options) != 1:
                raise raw_clock.DiagnosticError('native target missing/ambiguous exact binary identity: '
                                                + event['kind'] + '/' + str(tcb))
            row = options[0]
            target = {'kind': event['kind'], 'terminal': event['terminal'],
                      'tcb': tcb, 'local': event.get('local'), 'remote': event.get('remote'),
                      'transition': event.get('transition'),
                      'pktmon_ref': event['ref'], 'seq': row['seq']}
            targets.append(target)
            selectors.append({'seq': row['seq'], 'raw_qpc': row['raw_timestamp'],
                              'provider': row['provider'], 'id': row['id'],
                              'version': row['version'], 'opcode': row['opcode'],
                              'task': row['task'], 'userdata_sha256': row['userdata_sha256'],
                              'identity_sha256': row['identity_sha256'],
                              'target_kind': event['kind'], 'tcb': tcb,
                              'pktmon_ref': event['ref'],
                              'binding_status': row['binding_status']})
    if len({x['seq'] for x in selectors}) != len(selectors):
        raise raw_clock.DiagnosticError('one ETL record selected for multiple native targets')
    return targets, selectors


def run(case_path, evidence_root, output):
    output.mkdir(parents=True, exist_ok=False)
    manifest = {'schema': 'sst.qpc-diagnostic.v1', 'status': 'INCOMPLETE',
                'formal_fault_verdict': 'UNCHANGED', 'inputs_before': {},
                'inputs_after': {}, 'error': None}
    paths = [case_path]
    try:
        case = json.loads(case_path.read_text(encoding='utf-8'))
        evidence = fault.Evidence(evidence_root, case['files'])
        paths += [(evidence_root / item['path']).resolve() for item in case['files']]
        manifest['inputs_before'] = {str(p): _input_hash(p) for p in paths}
        session = case['session']
        capture = evidence.read(session['connection_capture']['metadata_ref'])
        action = next((evidence.read(ref) for ref in case['trigger']['success_refs']
                       if isinstance(evidence.read(ref), dict) and
                       evidence.read(ref).get('schema') == 'fakenet.fault-action.v1'), None)
        probe_rows = [json.loads(line) for line in
                      evidence.data[session['established_ref']['path']].splitlines()]
        ready = next((r for r in probe_rows if r.get('event') == 'ready'), None)
        process_ready = next((r for r in probe_rows if r.get('event') == 'process_ready'
                              and r.get('pid') == session['probe_pid']), None)
        established = evidence.read(session['established_ref'])
        if (not action or not ready or not capture.get('native_identity_before') or
                not capture.get('native_identity_after') or not ready.get('native_identity') or
                not action.get('native_identity')):
            raise raw_clock.DiagnosticError('UNSUPPORTED: historical capture lacks native boot/process identity')
        ipc_rows = [json.loads(line) for line in
                    evidence.data[case['start_response_ref']['path']].splitlines()]
        managed_pid, managed_created = tcpip.managed_identity(ipc_rows, case['run_id'])
        etl = (evidence_root / session['connection_capture']['etl_path']).resolve()
        text_path = session['connection_capture']['text_path']
        text = evidence.data[text_path]
        log_path = session['managed_ref']['path']
        observed = tcpip.connection_events(text, text_path,
            evidence.data[log_path].decode('utf-8-sig'), session['probe_pid'],
            session['src'], session['dst'], managed_pid, log_path=log_path)
        if session['connection_event_refs'] != [e['ref'] for e in observed['events']]:
            raise raw_clock.DiagnosticError('native generation refs changed/incomplete')
        if session.get('tuple_terminal_refs', []) != [e['ref'] for e in observed['tuple_terminals']]:
            raise raw_clock.DiagnosticError('tuple terminal refs changed/incomplete')
        if session['generation_manifest'] != observed['generation_manifest']:
            raise raw_clock.DiagnosticError('native generation manifest changed')
        export = raw_clock.export(etl, output / 'raw')
        header = export['passes'][0]['header']
        manifest['identity'] = check_provenance(capture, ready, process_ready,
            established, action, header, case['candidate_id'], case['run_id'],
            managed_pid, managed_created)
        targets, selectors = choose_targets(observed, output / 'raw' / 'paired.jsonl')
        selector_path = output / 'selectors.json'
        selector_path.write_text(json.dumps({'schema': 'fakenet.t007-r02-tdh-selectors.v1',
            'source_event_count': export['paired_events'],
            'source_etl_sha256': export['input_before']['sha256'],
            'selectors': selectors}, indent=2) + '\n')
        manifest['targets'] = targets
        tdh = tdh_metadata.run(etl, selector_path, output / 'tdh')
        tdh_rows = [json.loads(line) for line in (output / 'tdh' / 'metadata.jsonl').read_text().splitlines()]
        manifest['tdh_semantics'] = validate_tdh_semantics(tdh_rows, targets,
            observed['connect']['tcb'], (observed['peer'] or {}).get('tcb'),
            session['probe_pid'], managed_pid)
        if tdh['target_count'] != len(targets):
            raise raw_clock.DiagnosticError('TDH target count incomplete')
        manifest['capture_run_id'] = capture['capture_run_id']
        manifest['managed_run_id'] = case['run_id']
        manifest['candidate_id'] = case['candidate_id']
        manifest['status'] = 'COMPLETE_DIAGNOSTIC_ONLY'
    except BaseException as exc:  # preserve incomplete manifest for review
        manifest['error'] = {'type': type(exc).__name__, 'message': str(exc),
                             'traceback': traceback.format_exc()}
    finally:
        manifest['inputs_after'] = {str(p): _input_hash(p) for p in paths if p.is_file()}
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
                      'error': result['error']['message'] if result['error'] else None}))
    return 0 if result['status'] == 'COMPLETE_DIAGNOSTIC_ONLY' else 1


if __name__ == '__main__':
    sys.exit(main())
