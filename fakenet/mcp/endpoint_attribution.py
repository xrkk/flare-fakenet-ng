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


def closed_udp_changes(baseline, sample, proof):
    """Explain only fully observed, closed foreign ephemeral UDP changes.

    No port threshold, process-name allowlist or process lifetime inference.
    Dual-stack rows require successful mapped-IPv4 sends and a unique bind.
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
        if not diff:
            return dict(result, accepted=True, raw_equal=True)
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
        if ((removed and added) or not (removed or added) or
                sum(removed.values()) != sum(normalized_removed.values()) or
                sum(added.values()) != sum(normalized_added.values())):
            raise ValueError('mixed changes, owner drift or non-UDP difference remains')
        direction = 'removed' if removed else 'added'
        groups = {}
        for (address, port, pid), count in (removed or added).items():
            groups.setdefault((port, pid), {})[address] = count
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
        for (port, pid), addresses in groups.items():
            born = identities[0].get(pid)
            candidates = []
            if all(n == 1 for n in addresses.values()) and pid not in managed_pids and born and born == identities[1].get(pid):
                born_ns = (int(born) - 116444736000000000) * 100
                # A process already alive before observation cannot be a new
                # managed child, whose creation follows baseline capture.
                if born_ns < proof['start']['time_ns']:
                    for life in lifetimes:
                        bound, requested = life['bound'], life['requested_bind']
                        if (life['pid'] != pid or not bound or not requested or
                                bound['port'] != port or
                                requested['port'] != 0 or requested['family'] != bound['family'] or
                                not life['creation_succeeded'] or life['closed'] is None or
                                life['superseded_without_close']):
                            continue
                        created, bound_at, closed = map(event_ns, (
                            life['creation_time'], life['bind_time'], life['close_time']))
                        sends = [s for s in life['outbound'] if s['succeeded'] and
                                 life['bind_event'] < s['event'] < s['completed'] < life['closed']]
                        exact_address = set(addresses) == {bound['address']}
                        dual_stack = (set(addresses) == {'0.0.0.0', '::'} and
                                      bound['family'] == 23 and bound['address'] == '::' and
                                      any(s['destination']['family'] == 23 and
                                          ipaddress.IPv6Address(s['destination']['address']).ipv4_mapped
                                          for s in sends))
                        if not (exact_address or dual_stack) or not unique_bind(proof['events'], life):
                            continue
                        window_matches = (
                            born_ns < created <= bound_at <= b0 <= b1 < closed < a0
                            if direction == 'removed' else
                            b1 < created <= bound_at <= a0 <= a1 < closed < proof['end']['time_ns'])
                        if window_matches and sends:
                            candidates.append(life)
            if len(candidates) != 1:
                result['unresolved'].append({'addresses': addresses, 'port': port, 'pid': pid, 'direction': direction})
            else:
                result['attributed'].append({'addresses': addresses, 'port': port, 'pid': pid, 'direction': direction,
                    'creation_time': born, 'lifetime': candidates[0], 'etl_sha256': proof['etl_sha256']})
        result['accepted'] = bool(result['attributed']) and not result['unresolved']
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        result['failure'] = str(exc)
    return result


def unique_bind(events, life):
    """Reject competing binds, including sockets created before observation."""
    import xml.etree.ElementTree as ET
    from fakenet.mcp.endpoint_evidence import EVENT_NS, socket_address
    matches = []
    for event in events:
        if event['id'] != 1030:
            continue
        xml = ET.fromstring(event['xml'])
        data = {x.attrib['Name']: x.text for x in xml.findall('e:EventData/e:Data', EVENT_NS)}
        if (data['Process'] == life['process_pointer'] and int(data['EnterExit']) == 1 and
                int(data['Status'], 0) == 0 and socket_address(data['Address'])['port'] == life['bound']['port']):
            matches.append(data['Endpoint'])
    return matches == [life['endpoint_pointer']]


def _managed_process_ids(section):
    """Baseline-managed process ids from the raw windivert_processes JSON."""
    try:
        observed = json.loads(str(section))
    except (TypeError, ValueError):
        raise ValueError('managed process evidence is not parseable')
    if not isinstance(observed, dict) or not isinstance(observed.get('managed'), list):
        raise ValueError('managed process evidence is incomplete')
    ids = set()
    for process in observed['managed']:
        try:
            ids.add(int(process['Id']))
        except (KeyError, TypeError, ValueError):
            raise ValueError('managed process identity is incomplete')
    return ids


def foreign_udp_owner_changes(baseline, sample, proof):
    """Accept isolated UDP endpoint changes owned by pre-existing processes.

    A restoration audit must fail on residue this run created.  A changed
    UDP endpoint whose owning process already existed when the run's endpoint
    trace began, and is not one of the baseline's managed processes, was
    never created by this run: its socket lifecycle is environmental.  Owners
    first observed during the run, baseline-managed owners, mixed or non-UDP
    differences, and any ambiguity refuse; nothing is waived by port range
    or process name.
    """
    from fakenet.mcp.baseline import audit_compare
    result = {'accepted': False, 'attributed': [], 'refused': []}
    try:
        run = baseline['run_id']
        if (sample['run_id'] != run or proof['run_id'] != run or
                proof['start'].get('run_id') != run or proof['end'].get('run_id') != run or
                proof['end'].get('complete') is not True or
                proof['end'].get('absent') is not True):
            raise ValueError('run identity or complete coverage unavailable')
        diff = audit_compare(baseline['sections'], sample['current'])
        if not diff:
            return dict(result, accepted=True, raw_equal=True)
        if set(diff) != {'listen_ports'} or diff['listen_ports'].get('collection_failed'):
            raise ValueError('not an isolated endpoint difference')
        before_window = baseline['observation_windows']['listen_ports']
        after_window = sample['observation_windows']['listen_ports']
        if not (proof['start']['time_ns'] <= before_window['start_ns'] and
                after_window['end_ns'] <= proof['end']['time_ns']):
            raise ValueError('sampling outside complete observation')
        normalized = diff['listen_ports']
        norm_removed = Counter(str(normalized['before']).splitlines()) - Counter(str(normalized['after']).splitlines())
        norm_added = Counter(str(normalized['after']).splitlines()) - Counter(str(normalized['before']).splitlines())
        norm_changed = ([('removed', line) for line in norm_removed.elements()] +
                        [('added', line) for line in norm_added.elements()])
        if not norm_changed:
            raise ValueError('no changed rows in normalized difference')
        for _direction, line in norm_changed:
            parts = line.split()
            if len(parts) != 3 or parts[0].upper() != 'UDP':
                raise ValueError('non-UDP row remains in difference')
        def raw_owner(text, address_port):
            for raw in str(text).splitlines():
                parts = raw.split()
                if (len(parts) == 4 and parts[0].upper() == 'UDP' and
                        parts[1] == address_port and parts[2] == '*:*' and
                        parts[3].isdigit()):
                    return int(parts[3])
            raise ValueError('raw owner row unavailable for %s' % address_port)
        managed = _managed_process_ids(baseline['sections'].get('windivert_processes'))
        start_ids = {int(row['ProcessId']): str(row['CreationTime'])
                     for row in proof['start']['processes']}
        if len(start_ids) != len(proof['start']['processes']):
            raise ValueError('ambiguous process identity')
        for direction, line in norm_changed:
            address_port = line.split()[1]
            owner = raw_owner(baseline['sections']['listen_ports'] if direction == 'removed'
                              else sample['current']['listen_ports'], address_port)
            if owner in managed:
                result['refused'].append({'direction': direction, 'row': line,
                                          'pid': owner, 'reason': 'baseline-managed owner'})
                continue
            if owner not in start_ids:
                result['refused'].append({'direction': direction, 'row': line,
                                          'pid': owner,
                                          'reason': 'owner created during run or unknown'})
                continue
            result['attributed'].append({'direction': direction, 'row': line,
                                         'pid': owner,
                                         'creation_time': start_ids[owner]})
        result['accepted'] = bool(result['attributed']) and not result['refused']
    except Exception as exc:
        result['accepted'] = False
        result['failure'] = str(exc)
    return result
