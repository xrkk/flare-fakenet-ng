# Copyright 2026 Google LLC
"""Conservative, offline SST fault-evidence Spike (plan v0.5 §4.1).

This is a deliberately fail-closed evidence adapter. Unsupported native
observations produce a failing check, never an inferred success. Synthetic
fixtures exercise the oracle but cannot qualify a real fault matrix.
"""
import argparse
import datetime as dt
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re

FAULTS = ('listener_stop', 'diverter_stop', 'child_hang', 'policy_pause', 'cleanup_error')
CANDIDATE = 'mcp-c6090f816-93d4b3cf2252'
HEADER = re.compile(r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} ', re.M)
FRAME = re.compile(r'File "([^"\n]+)", line \d+, in ([^\s]+)')
L1 = [('threading.py', '_bootstrap_inner'), ('threading.py', 'run'),
      ('socketserver.py', 'serve_forever'), ('selectors.py', 'select'),
      ('selectors.py', '_select')]
REQUIRED = {'case_id', 'candidate_id', 'run_id', 'fault', 'nonce', 'clock',
            'receipt_ref', 'trigger', 'session', 'start_response_ref',
            'health_refs', 'stop_refs', 'recovery_refs', 'exception_refs', 'files'}


class EvidenceError(ValueError):
    pass


def packet_matches_session(packet, src, dst):
    """Require one decoded TCP packet for the exact connection, either way."""
    if not isinstance(packet, str):
        return False
    endpoint = r'(?:[0-9]{1,3}\.){4}[0-9]+'
    pairs = re.findall(r'(?<![\w.])(' + endpoint + r') > (' + endpoint
                       + r'): Flags \[[^\]\r\n]*\]', packet)
    if len(pairs) != 1:
        return False
    expected = tuple(value.rsplit(':', 1) for value in (src, dst))
    forward = tuple('.'.join(value) for value in expected)
    return pairs[0] in (forward, forward[::-1])


def exception_blocks(text):
    starts = [m.start() for m in HEADER.finditer(text)]
    cuts = sorted(set([0] + starts + [len(text)]))
    return [text[a:b] for a, b in zip(cuts, cuts[1:])
            if 'Traceback (most recent call last)' in text[a:b]
            or 'Unhandled exception' in text[a:b]]


def exception_kind(block):
    """Match the whole stack and error, allowing only the documented fields."""
    if any(s in block for s in ('During handling of', 'direct cause of', 'ExceptionGroup')):
        return None
    if block.count('Traceback (most recent call last):') != 1:
        return None
    frames = [(p.replace('\\', '/').rsplit('/', 1)[-1], f)
              for p, f in FRAME.findall(block)]
    last = block.strip().splitlines()[-1]
    if (re.match(r'^\d{4}-.* ERROR managed\.thread Unhandled exception in managed thread '
                 r'Thread-\d+ \(serve_forever\)\r?\n', block)
            and frames == L1 and re.fullmatch(r'OSError: \[WinError 10038\] .+', last)):
        return 'L1'
    if (re.match(r'^\d{4}-.* ERROR managed ', block)
            and frames and frames[-1] == ('faultinject.py', 'on_stop_error')
            and len(frames) >= 2 and frames[-2][0] == 'managed.py'
            and last == 'RuntimeError: injected cleanup error'
            and 'Unhandled exception' not in block):
        return 'C1'
    return None


def iso_ns(value):
    # Parse original precision without float roundoff; all native exports UTC.
    m = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)?', value)
    if not m:
        raise EvidenceError('unsupported ISO timestamp')
    if not m[3]:
        # CreationTimeUtc.ToString('o') normally has Z; missing zone is unsafe.
        raise EvidenceError('timestamp has no timezone')
    base = dt.datetime.fromisoformat(m[1] + m[3].replace('Z', '+00:00'))
    frac = m[2] or ''
    lo = int(base.timestamp()) * 10**9 + int(frac.ljust(9, '0') or '0')
    return lo, lo + 10 ** (9 - len(frac)) - 1


def time_bounds(event):
    if isinstance(event, str):
        if re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)', event):
            return iso_ns(event)
        stack = re.search(r'LIVE STOP STACKS timestamp=([0-9.]+)', event)
        if stack:
            lo = int(Decimal(stack[1]) * 10**9)
            return lo - 1000, lo + 1000
        packet = re.search(r'::(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)', event)
        if packet:
            return iso_ns(packet[1].replace(' ', 'T') + '+08:00')
        m = HEADER.match(event)
        if not m:
            raise EvidenceError('text event has no native timestamp')
        value = event[:23].replace(' ', 'T').replace(',', '.') + '+08:00'
        return iso_ns(value)
    if event.get('schema') == 'fakenet.fault-action.v1':
        lo = int(event['end_time_ns'])
        return lo, lo + 99
    if 'utc_ticks' in event:
        lo = (int(event['utc_ticks']) - 621355968000000000) * 100
        return lo, lo + 99
    if 'created_utc' in event:
        return iso_ns(event['created_utc'])
    if 'time' in event:
        lo = int(Decimal(str(event['time'])) * 10**9)
        # Original IPC float has at most microsecond-level useful precision.
        return lo - 1000, lo + 1000
    if 'utc' in event:
        return iso_ns(event['utc'])
    raise EvidenceError('no supported raw clock event')


class Evidence:
    def __init__(self, root, files):
        self.root = Path(root).resolve()
        self.data = {}
        for item in files:
            name = item['path']
            if name in self.data:
                raise EvidenceError('duplicate manifest path')
            path = (self.root / name).resolve()
            if not path.is_relative_to(self.root) or not path.is_file():
                raise EvidenceError('missing/escaping evidence path: ' + name)
            raw = path.read_bytes()
            if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256'].lower():
                raise EvidenceError('size/hash mismatch: ' + name)
            self.data[name] = raw

    def read(self, ref):
        if not isinstance(ref, dict):
            raise EvidenceError('missing raw reference')
        raw = self.data.get(ref['path'])
        if raw is None:
            raise EvidenceError('unmanifested reference')
        a, b = ref['byte_start'], ref['byte_end']
        if not isinstance(a, int) or not isinstance(b, int) or not 0 <= a < b <= len(raw):
            raise EvidenceError('invalid byte range')
        encoding = 'utf-16-le' if raw.startswith(b'\xff\xfe') else 'utf-8-sig'
        text = raw[a:b].decode(encoding).lstrip('\ufeff')
        key = ref['event_key']
        if key == 'text':
            return text
        if not key.startswith('json:'):
            raise EvidenceError('unsupported event parser: ' + key)
        obj = json.loads(text)
        pointer = key[5:]
        for token in pointer.split('/')[1:] if pointer else []:
            token = token.replace('~1', '/').replace('~0', '~')
            obj = obj[int(token)] if isinstance(obj, list) else obj[token]
        return obj


def contains_session(begin_upper, trigger_lower, trigger_upper, end_lower):
    return begin_upper <= trigger_lower <= trigger_upper <= end_lower


def assess(case, root, expected_candidate=CANDIDATE):
    if case.get('schema') != 'sst.fault-evidence.case.v1' or not REQUIRED <= case.keys():
        raise EvidenceError('invalid/missing case schema fields')
    if case['fault'] not in FAULTS:
        raise EvidenceError('unknown fault')
    result = {'schema': 'sst.fault-evidence.result.v1', 'case_id': case['case_id'],
              'passed': False, 'synthetic': bool(case.get('synthetic')),
              'checks': [], 'unsupported_observations': []}
    checks = result['checks']

    def check(name, fn, refs=()):
        try:
            ok, reason = fn()
        except (EvidenceError, ValueError, KeyError, TypeError, IndexError) as exc:
            ok, reason = False, str(exc)
        checks.append({'id': name, 'passed': bool(ok), 'reason': reason, 'evidence_refs': list(refs)})
        return bool(ok)

    try:
        evidence = Evidence(root, case['files'])
    except (OSError, EvidenceError, KeyError) as exc:
        checks.append({'id': 'integrity', 'passed': False, 'reason': str(exc), 'evidence_refs': []})
        return result
    checks.append({'id': 'integrity', 'passed': True, 'reason': 'all referenced file bytes verified', 'evidence_refs': []})
    read = evidence.read
    def bounds(event):
        lo, hi = time_bounds(event)
        uncertainty = max(0, int(case['clock']['resolution_ns']) - 1)
        return lo - uncertainty, hi + uncertainty
    fault, run = case['fault'], case['run_id']
    check('candidate', lambda: (case['candidate_id'] == expected_candidate, 'fixed candidate identity: ' + expected_candidate))
    def clock_check():
        clock = case['clock']
        if not (clock['domain'] == 'vm-utc' and 0 < clock['resolution_ns'] <= 10**9
                and clock['discontinuities'] == []):
            return False, 'invalid VM clock declaration'
        for name, raw in evidence.data.items():
            if not name.endswith('-probe.jsonl'):
                continue
            events = [json.loads(line) for line in raw.splitlines()]
            ready = events[0]
            frequency = ready['stopwatch_frequency']
            if frequency <= 0:
                return False, 'invalid native monotonic frequency'
            deltas = [abs((e['utc_ticks'] - ready['utc_ticks']) / 1e7
                          - (e['mono'] - ready['mono']) / frequency) for e in events]
            worst = max(deltas)
            result['clock_max_wall_vs_monotonic_seconds'] = worst
            if worst > clock['resolution_ns'] / 1e9:
                return False, 'wall/monotonic drift exceeds conservative clock bound'
        return True, 'VM UTC with native precision and wall/monotonic cross-check where captured'

    check('clock', clock_check)
    check('receipt', lambda: (read(case['receipt_ref']) == {'fault': fault, 'nonce': case['nonce']},
                             'receipt proves only consumption identity'), [case['receipt_ref']])

    def start_frame():
        original = read(case['start_response_ref'])
        if (original.get('frame', {}).get('run_id') != run or original.get('event') != 'response'
                or original['frame'].get('seq') != 1):
            raise EvidenceError('start IPC response does not identify this run')
        return original['frame']

    def start_trajectory():
        frame = start_frame()
        detail = frame.get('result', {})
        if frame.get('error'):
            return False, 'unattributed start IPC exception'
        if fault in ('child_hang', 'policy_pause', 'cleanup_error'):
            return bool(detail.get('init_evidence') and detail.get('probe')), 'this class does not require a failed start'
        if fault == 'listener_stop':
            dead = [x for x in detail.get('listeners', []) if not x.get('alive')]
            return (detail.get('init_evidence') is True and detail.get('probe') is False
                    and detail.get('capture_threads_alive') is True
                    and detail.get('capture_error') is None and len(dead) == 1
                    and any(h < 0 for h in dead[0].get('handles', []))), 'listener-specific failed start inputs'
        if fault == 'diverter_stop':
            return (diverter_action() and detail.get('init_evidence') is True
                    and detail.get('probe') is False and detail.get('capture_error') is None
                    and bool(detail.get('listeners'))
                    and all(x.get('alive') for x in detail['listeners'])), 'native main handle closure with other startup inputs intact'
        return False, 'native start probe does not independently expose main-handle close'

    def diverter_action():
        for ref in case['trigger']['success_refs']:
            obj = read(ref)
            if not isinstance(obj, dict) or obj.get('schema') != 'fakenet.fault-action.v1':
                continue
            before, after = obj.get('before', {}), obj.get('after', {})
            if (obj.get('run_id') == run and obj.get('nonce') == case['nonce']
                    and obj.get('fault') == 'diverter_stop' and obj.get('action') == 'WinDivertClose'
                    and isinstance(obj.get('pid'), int) and obj['pid'] > 0
                    and obj.get('end_time_ns', 0) >= obj.get('start_time_ns', 1) > 0
                    and before.get('api') == after.get('api') == 'GetHandleInformation'
                    and before.get('supported') is True and after.get('supported') is True
                    and isinstance(before.get('handle'), int) and before['handle'] > 0
                    and before['handle'] == after.get('handle')
                    and before.get('return_code') == 1
                    and after.get('return_code') == 0 and after.get('last_error') == 6):
                return True
        return False

    check('start_attribution', start_trajectory, [case['start_response_ref']])

    def trigger_success():
        observations = [read(ref) for ref in case['trigger']['success_refs']]
        if fault == 'diverter_stop':
            return diverter_action(), 'native same-handle GetHandleInformation valid before close, ERROR_INVALID_HANDLE after close'
        if fault == 'listener_stop':
            frame = start_frame()
            dead = any(not x.get('alive') and any(h < 0 for h in x.get('handles', []))
                       for x in frame.get('result', {}).get('listeners', []))
            return dead and any(isinstance(x, str) and exception_kind(x) == 'L1' for x in observations), 'closed listener descriptor plus exact native L1 block'
        if fault == 'cleanup_error':
            blocks = any(isinstance(x, str) and exception_kind(x) == 'C1' for x in observations)
            ipc = any(isinstance(x, dict) and x.get('frame', {}).get('run_id') == run
                      and 'injected cleanup error' in x['frame'].get('error', '') for x in observations)
            return blocks and ipc, 'native hook traceback and corresponding stop IPC error'
        if fault == 'child_hang':
            # Native CIM process creation facts, not a caller's success label.
            for obj in observations:
                if not isinstance(obj, dict):
                    continue
                rows = obj.get('processes', [])
                parents = {int(x['ProcessId']) for x in rows
                           if x.get('Name') == 'fakenetng-mcp-managed.exe'
                           and ('managed-child ' + run) in (x.get('CommandLine') or '')}
                hangs = [x for x in rows if x.get('Name') == 'fakenetng-mcp.exe'
                         and 'managed-fault-hang' in (x.get('CommandLine') or '')
                         and int(x.get('ParentProcessId', -1)) in parents
                         and x.get('CreationDate')]
                if len(hangs) == 1:
                    return True, 'native child command line, creation and managed parent identified'
            return False, 'managed-fault-hang native creation/parent facts missing'
        if fault == 'policy_pause':
            # Frozen Python frames omit source text. Bind the observed line to
            # the exact source shipped by the two explicitly pinned candidates.
            mapped_source = any(isinstance(x, str) and
                hashlib.sha256(x.encode('utf-8')).hexdigest() in {
                    'd22e2c7b174090e52d4cac96b2ade8ae0da57e4b9a244720d868e897fc249f60',
                    'ce18c70836af10f7c721070fff01cc38dcba41fdb946d5fe74fe73ad9d6fd2c2'}
                and x.splitlines()[126].strip() == 'time.sleep(3600)'
                for x in observations)
            matched = any(isinstance(x, str) and 'LIVE STOP STACKS timestamp=' in x
                          and 'before_listener_phase' in x and 'time.sleep(3600)' in x
                          for x in observations)
            mapped_stack = any(isinstance(x, str) and 'LIVE STOP STACKS timestamp=' in x
                and re.search(r'File "fakenet[\\/]mcp[\\/]faultinject\.py", line 127, in before_listener_phase', x)
                for x in observations)
            matched = matched or (mapped_source and mapped_stack)
            return matched, 'live stop stack must locate the specific pause hook'
        # No normalized caller booleans accepted for unsupported native providers.
        result['unsupported_observations'].append(fault + ': native action-success adapter not established')
        return False, 'no supported raw action-success adapter; no inferred success'

    check('trigger_success', trigger_success, case['trigger'].get('success_refs', []))

    def overlap():
        trigger, session = case['trigger'], case['session']
        lower = read(trigger['lower_ref'])
        upper = read(trigger['upper_ref'])
        if isinstance(lower, dict) and 'created_utc' in lower:
            if (Path(lower.get('path', '').replace('\\', '/')).name != 'fault-triggered.json'
                    or run not in lower['path']):
                raise EvidenceError('receipt metadata is not the native run receipt')
            receipt_bytes = evidence.data[case['receipt_ref']['path']]
            if (lower.get('bytes') != len(receipt_bytes)
                    or lower.get('sha256', '').lower() != hashlib.sha256(receipt_bytes).hexdigest()):
                raise EvidenceError('native receipt metadata hash/size mismatch')
        elif not (isinstance(lower, dict) and lower.get('event') == 'request'
                  and lower.get('frame', {}).get('run_id') == run
                  and lower['frame'].get('kind') in ('start', 'stop')):
            raise EvidenceError('unsupported lower bound')
        if upper == lower or (isinstance(upper, dict) and 'created_utc' in upper):
            raise EvidenceError('receipt metadata cannot be an action upper bound')
        # Upper must itself be among actual action observations/start IPC.
        if trigger['upper_ref'] not in trigger['success_refs'] + [case['start_response_ref']]:
            raise EvidenceError('upper bound not linked to action observation')
        established, managed, end = [read(session[key]) for key in ('established_ref', 'managed_ref', 'end_ref')]
        if established['event'] != 'established' or end['event'] not in ('eof', 'error', 'close'):
            raise EvidenceError('invalid connection lifecycle events')
        for key in ('pid', 'worker', 'seq', 'nonce'):
            if established[key] != end[key]:
                raise EvidenceError('cannot splice different/retried connections')
        # End at the first observed close/error/EOF for this exact attempt.
        lifecycle = []
        first_probe = json.loads(evidence.data[session['established_ref']['path']].splitlines()[0])
        if (first_probe.get('creation_ticks') != session['probe_creation']
                or first_probe.get('pid') != session['probe_pid']):
            raise EvidenceError('probe process creation identity mismatch')
        for raw_line in evidence.data[session['established_ref']['path']].splitlines():
            row = json.loads(raw_line)
            if all(row.get(k) == established[k] for k in ('pid', 'worker', 'seq', 'nonce')):
                lifecycle.append(row)
        ends = [x for x in lifecycle if x.get('event') in ('eof', 'error', 'close')]
        if not ends or bounds(end)[0] != min(bounds(x)[0] for x in ends):
            raise EvidenceError('end is not the first termination of this connection')
        if established['nonce'] != case['nonce'] or established['pid'] != session['probe_pid']:
            raise EvidenceError('probe nonce/PID mismatch')
        # PROCESS_FLOW is extracted from the actual run log, not a caller flag.
        if not isinstance(managed, str) or 'PROCESS_FLOW ' not in managed:
            raise EvidenceError('missing native PROCESS_FLOW mapping')
        address, port = established['src'].rsplit(':', 1)
        if not all(token in managed for token in (f'pid={session["probe_pid"]} ', f'sport={port} ', f'src={address}')):
            raise EvidenceError('managed flow is not this VM outbound probe')
        if established.get('dst') != session['dst'] or established['src'] != session['src']:
            raise EvidenceError('connection tuple mismatch')
        if not session['packet_refs']:
            raise EvidenceError('independent packet capture is missing')
        packet_ends = []
        for ref in session['packet_refs']:
            packet = read(ref)
            if not packet_matches_session(packet, session['src'], session['dst']):
                raise EvidenceError('packet tuple cannot be linked')
            if re.search(r'Flags \[[^\]]*[FR]', packet):
                packet_ends.append(bounds(packet)[0])
        if not packet_ends:
            raise EvidenceError('independent capture has no connection termination')
        begin = max(bounds(established)[1], bounds(managed)[1])
        finish = min([bounds(end)[0]] + packet_ends)
        lo, hi = bounds(lower)[0], bounds(upper)[1]
        result['intervals_ns'] = {'session_begin_upper': begin, 'trigger_lower': lo,
                                  'trigger_upper': hi, 'session_end_lower': finish}
        return contains_session(begin, lo, hi, finish), 'single managed outbound connection must contain entire conservative action interval'

    check('overlap', overlap)

    def logs():
        allowed = {'listener_stop': {'L1'}, 'cleanup_error': {'C1'}}.get(fault, set())
        # Scan complete supplied native run.log, not only whitelisted slices.
        paths = [p for p in evidence.data if Path(p).name == 'run.log']
        if len(paths) != 1:
            raise EvidenceError('exactly one complete run.log required')
        blocks = exception_blocks(evidence.data[paths[0]].decode('utf-8-sig'))
        kinds = [exception_kind(b) for b in blocks]
        return all(k in allowed for k in kinds), 'full run.log exception blocks: ' + repr(kinds)

    check('exception_whitelist', logs, case['exception_refs'])

    def recovery():
        # A terminal label cannot replace the five-section recovery audit.
        raw = [read(ref) for ref in case['recovery_refs']]
        if not raw:
            raise EvidenceError('five-section native recovery evidence absent')
        required = {'dns_servers', 'routes', 'listen_ports', 'windivert_processes', 'services'}
        snapshots = [x for x in raw if isinstance(x, dict) and required <= x.keys()]
        if len(snapshots) != 2:
            raise EvidenceError('two original five-section snapshots required; terminal label is insufficient')
        if any(not isinstance(x[k], (str, list, dict)) for x in snapshots for k in required):
            raise EvidenceError('invalid native recovery section')
        # Reuse the product's comparison semantics, not an acceptance-only exemption.
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
        from fakenet.mcp.baseline import audit_compare
        difference = audit_compare(snapshots[0], snapshots[1])
        stops = [read(ref) for ref in case['stop_refs']]
        terminal = any(isinstance(x, dict) and x.get('state') == 'stopped'
                       and x.get('last_run_outcome') == 'failed'
                       and x.get('run_id') is None and x.get('controller') is None for x in stops)
        restored = any(isinstance(x, dict) and x.get('state') == 'healthy'
                       and x.get('run_id') != run
                       and all(x.get('health', {}).get(k) for k in ('process_alive', 'init_evidence', 'probe'))
                       for x in raw)
        cleaned = any(isinstance(x, dict) and x.get('state', {}).get('needs_recovery') is False
                      and x.get('managed_processes') == [] and x.get('probe_processes') == []
                      and x.get('fault_exists') is False for x in raw if isinstance(x.get('state'), dict))
        return not difference and terminal and restored and cleaned, 'five-section native comparison, terminal lock release, distinct recovery healthy run'


    check('recovery', recovery, case['recovery_refs'])
    result['passed'] = all(c['passed'] for c in checks)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--evidence-root', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--expected-candidate', default=CANDIDATE,
                        help='Candidate identity frozen independently of the case input')
    args = parser.parse_args(argv)
    try:
        case = json.loads(Path(args.input).read_text())
        result = assess(case, args.evidence_root, args.expected_candidate)
        code = 0 if result['passed'] else 3
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result = {'schema': 'sst.fault-evidence.result.v1', 'case_id': None,
                  'passed': False, 'checks': [{'id': 'schema', 'passed': False,
                  'reason': str(exc), 'evidence_refs': []}], 'unsupported_observations': []}
        code = 2
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(text)
    print(json.dumps(result, ensure_ascii=False))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
