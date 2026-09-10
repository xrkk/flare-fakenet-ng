"""Conservative same-run attribution; raw baseline rows are never rewritten."""
from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json


def event_ns(value):
    # ETW UTC timestamps have seven fractional digits. Preserve all of them.
    head, fraction = value.removesuffix('Z').split('.')
    seconds = int(datetime.strptime(head, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc).timestamp())
    return seconds * 10**9 + int(fraction.ljust(9, '0'))


def udp_rows(text):
    rows = Counter()
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0].upper() == 'UDP':
            if len(parts) != 4 or parts[2] != '*:*':
                raise ValueError('unrecognized UDP observation')
            address, port = parts[1].rsplit(':', 1)
            address = str(ipaddress.ip_address(address.strip('[]')))
            rows[(address, int(port), int(parts[3]))] += 1
    return rows


def closed_udp_removals(baseline, sample, proof):
    """Explain only fully observed, closed foreign ephemeral UDP removals.

    No port threshold, process-name allowlist, dual-stack projection, addition
    exemption or process lifetime inference. Every ambiguity remains unknown.
    """
    from fakenet.mcp.baseline import audit_compare
    from fakenet.mcp.endpoint_evidence import udp_lifetimes
    result = {'accepted': False, 'attributed': [], 'unresolved': []}
    try:
        run = baseline['run_id']
        if (sample['run_id'] != run or proof['run_id'] != run or
                proof['start']['run_id'] != run or proof['end']['run_id'] != run or
                proof['end'].get('complete') is not True or proof['end'].get('absent') is not True):
            raise ValueError('run identity or complete coverage unavailable')
        diff = audit_compare(baseline['sections'], sample['current'])
        if set(diff) != {'listen_ports'} or diff['listen_ports'].get('collection_failed'):
            raise ValueError('not an isolated complete endpoint difference')
        before_window = baseline['observation_windows']['listen_ports']
        after_window = sample['observation_windows']['listen_ports']
        b0, b1 = before_window['start_ns'], before_window['end_ns']
        a0, a1 = after_window['start_ns'], after_window['end_ns']
        if not proof['start']['time_ns'] <= b0 <= b1 < a0 <= a1 <= proof['end']['time_ns']:
            raise ValueError('sampling window outside complete observation')
        before = udp_rows(baseline['sections']['listen_ports'])
        after = udp_rows(sample['current']['listen_ports'])
        removed, added = before - after, after - before
        raw_diff = diff['listen_ports']
        normalized_removed = Counter(raw_diff['before'].splitlines()) - Counter(raw_diff['after'].splitlines())
        normalized_added = Counter(raw_diff['after'].splitlines()) - Counter(raw_diff['before'].splitlines())
        if added or normalized_added or not removed or sum(removed.values()) != sum(normalized_removed.values()):
            raise ValueError('addition, owner drift or non-UDP difference remains')
        identities = []
        for point in ('start', 'end'):
            rows = proof[point]['processes']
            mapping = {int(r['ProcessId']): r['CreationTime'] for r in rows}
            if len(mapping) != len(rows):
                raise ValueError('ambiguous process identity')
            identities.append(mapping)
        lifetimes = udp_lifetimes(proof['events'])
        managed = json.loads(baseline['sections']['windivert_processes'])['managed']
        managed_pids = {int(row['Id']) for row in managed}
        for (address, port, pid), count in removed.items():
            born = identities[0].get(pid)
            candidates = []
            if count == 1 and pid not in managed_pids and born and born == identities[1].get(pid):
                born_ns = (int(born) - 116444736000000000) * 100
                # A process already alive before observation cannot be a new
                # managed child, whose creation follows baseline capture.
                if born_ns < proof['start']['time_ns']:
                    for life in lifetimes:
                        bound, requested = life['bound'], life['requested_bind']
                        if (life['pid'] != pid or not bound or not requested or
                                bound['address'] != address or bound['port'] != port or
                                requested['port'] != 0 or requested['family'] != bound['family'] or
                                not life['creation_succeeded'] or life['closed'] is None or
                                life['superseded_without_close']):
                            continue
                        created, bound_at, closed = map(event_ns, (
                            life['creation_time'], life['bind_time'], life['close_time']))
                        sends = [s for s in life['outbound'] if s['succeeded'] and
                                 life['bind_event'] < s['event'] < s['completed'] < life['closed']]
                        if born_ns < created <= bound_at <= b0 <= b1 < closed < a0 and sends:
                            candidates.append(life)
            if len(candidates) != 1:
                result['unresolved'].append({'address': address, 'port': port, 'pid': pid, 'count': count})
            else:
                result['attributed'].append({'address': address, 'port': port, 'pid': pid,
                    'creation_time': born, 'lifetime': candidates[0], 'etl_sha256': proof['etl_sha256']})
        result['accepted'] = bool(result['attributed']) and not result['unresolved']
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        result['failure'] = str(exc)
    return result
