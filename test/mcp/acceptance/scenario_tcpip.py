# Copyright 2026 Google LLC
"""Pure, fail-closed parsing of the reviewed Win10 TCPIP connection dialect.

No network operations and no caller-provided success labels. Consumers rescan
complete originals to reconstruct identity and all termination observations.
"""
import datetime
import ipaddress
import json
import re


def pair_ipc(rows, run, kind):
    requests = [(i, r) for i, r in enumerate(rows) if r.get('event') == 'request'
                and r.get('frame', {}).get('run_id') == run and r['frame'].get('kind') == kind]
    if len(requests) != 1:
        raise ValueError('IPC requires one same-run ' + kind + ' request')
    i, request = requests[0]
    seq = request['frame'].get('seq')
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        raise ValueError('invalid IPC sequence')
    related = [(j, r) for j, r in enumerate(rows)
               if r.get('frame', {}).get('run_id') == run and r['frame'].get('seq') == seq]
    reqs = [j for j, r in related if r.get('event') == 'request']
    replies = [j for j, r in related if r.get('event') == 'response']
    if reqs != [i] or len(replies) != 1 or replies[0] <= i:
        raise ValueError('missing/duplicate/reversed IPC request-response')
    return i, replies[0]


def managed_identity(rows, run):
    a, b = pair_ipc(rows, run, 'ready')
    start, _ = pair_ipc(rows, run, 'start')
    if b >= start:
        raise ValueError('ready identity must precede start')
    reply = rows[b]['frame']
    identity = reply.get('result', {}).get('identity', {})
    if reply.get('error') or int(identity.get('pid', 0)) <= 0 or int(identity.get('creation_time', 0)) <= 0:
        raise ValueError('managed native ready identity missing')
    return int(identity['pid']), int(identity['creation_time'])


def byte_lines(raw, path):
    utf16 = raw.startswith(b'\xff\xfe')
    bom = 2 if utf16 else (3 if raw.startswith(b'\xef\xbb\xbf') else 0)
    encoding = 'utf-16-le' if utf16 else 'utf-8'
    offset = bom
    for line in raw[bom:].decode(encoding).splitlines(keepends=True):
        end = offset + len(line.encode(encoding))
        yield line, dict(path=path, byte_start=offset, byte_end=end, event_key='text')
        offset = end


def byte_records(raw, path):
    """Preserve a complete native event, including localized continuation lines."""
    current = None
    for line, ref in byte_lines(raw, path):
        starts = re.match(r'^\[\w+\][0-9a-fA-F]+\.[0-9a-fA-F]+::\d{4}-\d\d-\d\d ', line)
        if starts or current is None:
            if current is not None:
                yield current
            current = (line, ref)
        else:
            current = (current[0] + line, dict(current[1], byte_end=ref['byte_end']))
    if current is not None:
        yield current


ESTABLISH = {('Closed', 'SynSent'), ('Listen', 'SynRcvd'),
             ('SynSent', 'Established'), ('SynRcvd', 'Established')}
TERMINATE = {('Established', 'FinWait1'), ('Established', 'CloseWait'),
             ('FinWait1', 'FinWait2'), ('FinWait1', 'Closing'), ('Closing', 'TimeWait'),
             ('TimeWait', 'Closed'), ('CloseWait', 'LastAck'), ('LastAck', 'Closed'),
             ('CloseWait', 'Closed'), ('FinWait2', 'Closed'), ('Closed', 'Closed'),
             ('Established', 'Closed'), ('FinWait1', 'Closed'), ('Closing', 'Closed'),
             ('FinWait2', 'TimeWait'),
             # Deny targets intercepted before establishment close directly
             # from SynSent; the kernel never reaches Established (DIVERT_FAKE).
             ('SynSent', 'Closed'),
             # Handshake-phase RST on the listener side (relay/deny teardown,
             # discovery100-48 sst-096): the accepted TCB reached SYN-received
             # and was reset before ESTABLISHED.
             ('SynRcvd', 'Closed')}
END_VERBS = {'abort issued', 'abort completed', 'shutdown initiated', 'close issued',
             'disconnect completed', 'connection terminated', 'sent RST'}
ADDR = r'(?:\d{1,3}\.){3}\d{1,3}:\d+'
TCB = r'0x[0-9a-fA-F]+'
TRANSITION = re.compile(r'connection (' + TCB + r') transition from (\w+)State\s+to (\w+)State\s*, SndNxt = (\d+)\.')
_MAPPED = re.compile(r'\[::ffff:((?:\d{1,3}\.){3}\d{1,3})\]')


def strip_mapped(text):
    """Display-normalize IPv6-mapped IPv4 endpoints ([::ffff:a.b.c.d]:p).

    Dual-stack sockets log mapped addresses in TCPIP events; the flow
    identity is the embedded IPv4 tuple (discovery100-56 sst-040).
    Applied to in-memory text only: byte-addressed evidence refs keep
    pointing at the original records.
    """
    return _MAPPED.sub(r'\1', text)


ENDPOINT = re.compile(r'(?:connection|Tcb) (' + TCB + r') \(local=(' + ADDR + r') remote=(' + ADDR + r')\)\s*:?[ \t]*(.+)')
ACCEPT = re.compile(r'listener \(local=(' + ADDR + r') remote=(' + ADDR + r')\) accept completed\. TCB = (' + TCB + r')\. PID = (\d+)\.')
RST = re.compile(r'Connection (' + TCB + r') Transport \(Protocol TCP , AddressFamily = IPV4 \) sent RST with Local = (' + ADDR + r'), Remote = (' + ADDR + r')\. Reason = Connection aborted \.' )


def endpoint(value):
    ip, port = value.rsplit(':', 1)
    if str(ipaddress.IPv4Address(ip)) != ip or not 0 < int(port) < 65536:
        raise ValueError('invalid IPv4 endpoint')
    return ip, str(int(port))


def parse_line(text, ref):
    marker = '[Microsoft-Windows-TCPIP] TCP: '
    if marker not in text:
        return None
    body = re.sub(r'\r?\n', ' ', strip_mapped(text).split(marker, 1)[1]).replace('\r', '').strip()
    event = dict(text=text, ref=ref, terminal=False)
    m = TRANSITION.fullmatch(body)
    if m:
        pair = (m[2], m[3])
        if pair not in ESTABLISH | TERMINATE:
            raise ValueError('unknown TCP transition: ' + body)
        event.update(tcb=m[1].upper(), kind='transition', transition=pair, terminal=pair in TERMINATE)
        return event
    m = ACCEPT.fullmatch(body)
    if m:
        endpoint(m[1]); endpoint(m[2])
        event.update(tcb=m[3].upper(), kind='accept completed', local=m[1], remote=m[2], pid=int(m[4]))
        return event
    m = re.fullmatch(r'connection ('+TCB+r'): (?:Send Retransmit round with SndUna = \d+, Round = \d+, SRTT = \d+, RTO = \d+\.|Leaving loss recovery phase with SndUna = \d+ and SndMax = \d+\.|retransmitting connect attempt, RexmitCount = \d+\.)', body)
    m = m or re.fullmatch(r'connection ('+TCB+r') spurious RTO detection (?:initiated|terminated) at \d+\.', body)
    m = m or re.fullmatch(r'connection ('+TCB+r') (?:send: )?Beginning zero-window probing with SndUna = \d+\.', body)
    if m:
        event.update(tcb=m[1].upper(), kind='retransmit context')
        return event
    m = re.fullmatch(r'(?:Inspect Connect has been completed on Tcb ('+TCB+r') with status = STATUS_SUCCESS\.|Tcb ('+TCB+r') is going to output SYN with ISN = \d+, RcvWnd = \d+, RcvWndScale = \d+\.)', body)
    if m:
        event.update(tcb=(m[1] or m[2]).upper(), kind='connect context')
        return event
    m = re.fullmatch(r'(?:connection (' + TCB + r') send keep-alive at SndUna = \d+\.|SWS avoidance began on connection (' + TCB + r')\. Timer set for \d+ ms\. BytesToSend = 0x[0-9a-fA-F]+, SendAvailable = \d+, Cwnd = \d+, MaxSndWnd = 0x[0-9a-fA-F]+\.)', body)
    if m:
        event.update(tcb=(m[1] or m[2]).upper(), kind='transport context')
        return event
    m = re.fullmatch(
        r'connection (' + TCB + r') (?:'
        r'entered BH, BH MSS \d+, original MSS \d+\.|'
        r'Exiting BH due to [^.]+, BH mss \d+, Original MSS \d+\.|'
        r'not entering BH due to [^.]+\.'
        r')', body)
    if m:
        # PMTU black-hole detection shrinks MSS while the connection lives;
        # it is transport context, never a terminal or identity event.
        event.update(tcb=m[1].upper(), kind='transport context', bh=True)
        return event
    m = ENDPOINT.fullmatch(body)
    if m:
        tail = m[4]
        exists = re.fullmatch(r'exists\. State = (\w+)State \. PID = (\d+)\.', tail)
        retransmit = re.fullmatch(r'(?:retransmitting data|retransmitting connect attempt), RexmitCount = \d+\.', tail)
        if exists or retransmit:
            if exists and exists[1] not in {state for pair in ESTABLISH | TERMINATE for state in pair}:
                raise ValueError('unknown existing TCP state')
            endpoint(m[2]); endpoint(m[3])
            event.update(tcb=m[1].upper(), local=m[2], remote=m[3],
                         kind='exists' if exists else 'retransmit context',
                         state=exists[1] if exists else None, pid=int(exists[2]) if exists else None)
            return event
        successful_shutdown = re.fullmatch(r'shutdown initiated \(STATUS_SUCCESS\)\. PID = ([1-9][0-9]*)\.', tail)
        if successful_shutdown:
            tail = 'shutdown initiated. PID = ' + successful_shutdown[1] + '.'
        # Generic normalization: the specific shutdown reason (timeout, abort,
        # local termination, reset, localized message, future variant like
        # I/O request cancelled) does not change the terminal semantics.
        # Some TCPIP providers put a colon directly after the endpoint
        # bracket: "(local=... remote=...): initiating SYN/RST validation."
        tail = re.sub(r'^:\s*', '', tail)
        tail = re.sub(r'shutdown initiated \([^)]*\)\.', 'shutdown initiated.', tail)
        if tail == 'terminating: retransmission timeout expired.':
            tail = 'connection terminated.'
        if tail == 'connection terminated: received RST.':
            tail = 'connection terminated.'
        # Generic connect-failure normalization: any localized status text
        # (I/O request cancelled, connection refused, timeout, etc.) is a
        # terminal connect failure regardless of the specific reason.
        tail = re.sub(r'connect attempt failed with status = .*\.', 'abort issued.', tail)
        valid = re.fullmatch(r'(requested to connect|connect proceeding|connect completed|abort issued|abort completed|shutdown initiated|close issued|disconnect completed|connection terminated|initiating SYN/RST validation|(?:send: )?Beginning zero-window probing with SndUna = \d+)\.(?: PID = (\d+)\.)?', tail)
        if not valid:
            raise ValueError('unsupported TCP lifecycle: ' + body)
        endpoint(m[2]); endpoint(m[3])
        event.update(tcb=m[1].upper(), local=m[2], remote=m[3], kind=valid[1],
                     pid=int(valid[2]) if valid[2] else None,
                     terminal=valid[1] in END_VERBS and
                     valid[1] not in ('initiating SYN/RST validation',
                                      'Beginning zero-window probing'))
        return event
    m = re.fullmatch(r'Connection 0x0 Transport \(Protocol TCP , AddressFamily = IPV4 \) sent RST with Local = (' + ADDR + r'), Remote = (' + ADDR + r')\. Reason = Receive discarded \.', body)
    if m:
        endpoint(m[1]); endpoint(m[2])
        event.update(tcb='0X0', local=m[1], remote=m[2], kind='unattributed_tuple_terminal')
        return event
    m = RST.fullmatch(body)
    if m:
        endpoint(m[2]); endpoint(m[3])
        event.update(tcb=m[1].upper(), local=m[2], remote=m[3], kind='sent RST', terminal=True)
        return event
    raise ValueError('unsupported TCP lifecycle: ' + body)


def fields(line):
    return dict(re.findall(r'(\w+)=([^\s]+)', line))


def flow_matches(row, pid, src, dst):
    a, b = endpoint(src), endpoint(dst)
    wanted = dict(proto='TCP', src=a[0], sport=a[1], dst=b[0], dport=b[1])
    if pid is not None:
        wanted['pid'] = str(pid)
    if all(row.get(k) == v for k, v in wanted.items()):
        return True
    # B3 process-redirect audit vocabulary (discovery100-67 sst-042..044).
    # The mapping line spells the transport key "protocol", not "proto".
    redirect = dict(protocol='TCP', source_ipv4=a[0], source_port=a[1],
                    original_ipv4=b[0], original_port=b[1])
    if pid is not None:
        redirect['pid'] = str(pid)
    return all(row.get(k) == v for k, v in redirect.items())


def policy_scope(line, window):
    if window is None:
        return 'inside'
    m = re.match(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),(\d{3}) ', line)
    if not m:
        raise ValueError('policy timestamp missing')
    epoch = datetime.datetime(1970, 1, 1)
    delta = datetime.datetime.strptime(m[1], '%Y-%m-%d %H:%M:%S') - datetime.timedelta(hours=8) - epoch
    start = (delta.days*86400 + delta.seconds)*10**9 + int(m[2])*10**6
    # Classify by the timestamp point, absorbing cross-layer jitter
    # (WinPS5 clock, WinDivert capture, TCP stack timing) near window
    # boundaries. The original symmetric band created false uncertainty
    # whenever a genuinely-inside event sat near either edge: a wider band
    # rescued upper-edge straddles but manufactured lower-edge ones
    # (discovery100-30/31). A point-based snap avoids both.
    tolerance = 100 * 10**6
    if start < window[0]:
        return 'inside' if window[0] - start <= tolerance else 'outside'
    if start > window[1]:
        return 'inside' if start - window[1] <= tolerance else 'outside'
    return 'inside'


def self_peer_policy(log, path, managed_pid, local, src, policy_window):
    """Peer reverse-flow policy, tolerating pid=unknown attribution.

    The diverter's reverse-flow audit can miss the loopback owner for
    reinjected listener replies (``pid=unknown``); the exact
    listener->client tuple is unique to this peer connection, and the
    TCPIP accept event already carries the authoritative managed pid
    (discovery100-51 sst-038).
    """
    strict = policy_partition(log, path, managed_pid, local, src, policy_window)
    if any(row['fields'].get('disposition') == 'REINJECT_LOCAL'
           for row in strict['inside']):
        return strict
    return policy_partition(log, path, None, local, src, policy_window)


def policy_partition(log, path, pid, src, dst, window=None):
    result = {'inside': [], 'outside': []}
    for line, ref in byte_lines(log.encode('utf-8'), path):
        row = fields(line)
        # ESTABLISHED_BYPASS is the diverter's mid-stream disposition for
        # flows established before capture; it carries the same tuple fields
        # as PROCESS_FLOW after the P4 field enrichment.
        if 'PROCESS_REDIRECT_MAPPING_CREATED' in line and row.get('disposition') is None:
            # The mapping line carries no disposition field; synthesize the
            # redirect class so downstream disposition checks work.
            row = dict(row, disposition='PROCESS_REDIRECT')
        if (('PROCESS_FLOW ' in line or 'ESTABLISHED_BYPASS' in line or
             'PROCESS_REDIRECT_MAPPING_CREATED' in line)
                and flow_matches(row, pid, src, dst)):
            result[policy_scope(line, window)].append(dict(text=line, ref=ref, fields=row))
    return result


def connection_events(raw, path, log, pid, src, dst, managed_pid, policy_window=None, log_path='run.log'):
    """Select by original tuple/PID, then rescan full selected TCB lifecycles."""
    endpoint(src); endpoint(dst)
    lines = [(strip_mapped(text), ref)
             for text, ref in byte_records(raw, path)]
    candidates = []
    # Discovery only recognizes a positive, fully qualified native connect.
    for text, ref in lines:
        if ('[Microsoft-Windows-TCPIP] TCP:' in text and ' connect completed.' in text
                and f'local={src} remote={dst}' in text):
            event = parse_line(text, ref)
            if event and event.get('local') == src and event.get('remote') == dst:
                candidates.append(event)
    if len(candidates) != 1 or candidates[0].get('pid') != pid:
        raise ValueError('TCPIP unique original-tuple/PID connect missing')
    connected = candidates[0]
    primary_policy = policy_partition(log, log_path, pid, src, dst, policy_window)
    matching = [row['fields'] for row in primary_policy['inside']]
    peer_policy = {'inside': [], 'outside': []}
    if not matching:
        # Legacy default.ini templates audit no egress dispositions at all;
        # their per-flow marker is "<process> (<pid>) requested TCP <dst>:<p>".
        # The kernel accept on the local sink (required below) is the
        # takeover proof (discovery100-84/85 sst-074..079: requested lines,
        # connect completed, and a managed listener accept all present).
        a, b = endpoint(src), endpoint(dst)
        legacy = re.compile(
            r'\((\d+)\) requested TCP ' + re.escape(b[0]) + ':' + b[1] + r'\s*$')
        for line in log.splitlines():
            m = legacy.search(line)
            if m and (pid is None or m.group(1) == str(pid)):
                matching = [dict(disposition='LEGACY_SINKHOLE')]
                break
    dispositions = {f.get('disposition') for f in matching}
    if len(dispositions) != 1:
        # A long-held connection can be re-audited as ESTABLISHED_BYPASS
        # during the stop phase; that is a lifecycle stage of the SAME flow
        # (mirrors the peer terminal-phase rule).  The establishment-time
        # disposition is authoritative (discovery100-74 sst-026).
        anchored = [f for f in matching
                    if f.get('disposition') != 'ESTABLISHED_BYPASS']
        if (anchored and
                len({f.get('disposition') for f in anchored}) == 1):
            matching = anchored
            dispositions = {anchored[0].get('disposition')}
    if len(dispositions) != 1:
        raise ValueError('same-run exact PROCESS_FLOW missing/ambiguous')
    disposition = next(iter(dispositions))
    tcbs = {connected['tcb']}
    peer = None
    if disposition in ('DIVERT_FAKE', 'REINJECT_LOCAL') or disposition.startswith('REDIRECT'):
        peers = []
        for text, ref in lines:
            if '[Microsoft-Windows-TCPIP] TCP: listener ' not in text or ' accept completed.' not in text:
                continue
            if not re.search(r'remote=' + re.escape(src) + r'\)', text):
                continue
            event = parse_line(text, ref)
            if event['remote'] == src and event['pid'] == managed_pid:
                observed_policy = self_peer_policy(
                    log, log_path, managed_pid, event['local'], src, policy_window)
                if any(row['fields'].get('disposition') == 'REINJECT_LOCAL' for row in observed_policy['inside']):
                    peers.append(event)
        if len(peers) != 1:
            # Some listener timing produces no userspace accept event at
            # all while the sink's reverse traffic is still reinjected
            # locally (discovery100-56 sst-039).  A reverse REINJECT_LOCAL
            # line for the primary's port is then the peer evidence; the
            # peer TCB is simply unobservable and stays out of the set.
            reverse_line = next((line for line in log.splitlines()
                                 if 'REINJECT_LOCAL' in line and
                                 'dport=%s' % src.rsplit(':', 1)[1] in line), None)
            if reverse_line is None:
                raise ValueError(
                    'unique native relay accept/reverse PROCESS_FLOW missing')
            peer = None
        else:
            peer = peers[0]
        peer_policy = (self_peer_policy(
            log, log_path, managed_pid, peer['local'], src, policy_window)
            if peer is not None else {'inside': [], 'outside': []})
        # The peer connection's terminal phase after the relay closes
        # (BrokenPipe) transitions from REINJECT_LOCAL to ESTABLISHED_BYPASS
        # — both are lifecycle stages of the SAME peer, not conflicting
        # policies (discovery100-32: 0.4ms after window upper edge).
        if policy_window and not {row['fields'].get('disposition')
                                  for row in peer_policy['inside']} <= {'REINJECT_LOCAL',
                                                                        'ESTABLISHED_BYPASS'}:
            raise ValueError('peer policy conflicts within curl process window')
        if peer is not None:
            tcbs.add(peer['tcb'])
            if len(tcbs) != 2:
                raise ValueError('primary and peer share TCB')
    elif disposition not in ('ALLOW_EXTERNAL', 'ALLOW_TAKEOVER_SINK',
                             'ALLOW_INTERNAL_UPSTREAM', 'ALLOW_REVIEWED_IP',
                             'ESTABLISHED_BYPASS', 'PROCESS_REDIRECT',
                             'LEGACY_SINKHOLE'):
        raise ValueError('unsupported direct disposition: ' + str(disposition))
    # ALLOW_REVIEWED_IP is a reviewed-rule direct upstream: the reviewed
    # egress path relays without a local FakeNet peer, like ALLOW_EXTERNAL.
    all_events = []
    tuple_terminals = []
    for text, ref in lines:
        if '[Microsoft-Windows-TCPIP] TCP:' not in text:
            continue
        ids = {v.upper() for v in re.findall(TCB, text)}
        normalized = re.sub(r'\s+', '', text).lower()
        exact_tuple = any((f'local={src}{sep}remote={dst}').lower() in normalized for sep in ('', ','))
        if not (tcbs & ids or exact_tuple):
            continue
        event = parse_line(text, ref)
        if event['kind'] == 'unattributed_tuple_terminal':
            if event['local'] == src and event['remote'] == dst:
                tuple_terminals.append(event)
                continue
            raise ValueError('unattributed event is not the original tuple')
        if event['tcb'] not in tcbs:
            # No provable second identity/lifetime has been supplied for this
            # same tuple. Do not drop a possibly earlier close/RST.
            raise ValueError('original tuple reused by another TCB')
        all_events.append(event)
    generations = []
    selected = []
    for tcb in sorted(tcbs):
        expected = connected if tcb == connected['tcb'] else peer
        groups = reconstruct_generations([e for e in all_events if e['tcb'] == tcb])
        matches = [g for g in groups if any(e['ref'] == expected['ref'] for e in g['events'])]
        if len(matches) != 1 or matches[0]['left_censored']:
            raise ValueError('connection has no unique complete native generation')
        chosen = matches[0]
        if chosen['identity'] != dict(local=expected['local'], remote=expected['remote'], pid=expected['pid']):
            raise ValueError('generation identity mismatch')
        for e in chosen['events']:
            e['generation_ordinal'] = chosen['ordinal']
        selected.extend(chosen['events'])
        expected['generation_ordinal'] = chosen['ordinal']
        generations.extend(dict(tcb=tcb, generation_ordinal=g['ordinal'],
            left_censored=g['left_censored'], birth_ref=g['birth_ref'], closed_ref=g['closed_ref'],
            identity=g['identity'], record_refs=[e['ref'] for e in g['events']]) for g in groups)
    if tuple_terminals:
        same_tuple = [g for g in generations if g['identity'] and
                      (g['identity']['local'], g['identity']['remote']) == (src, dst)]
        if len(same_tuple) != 1 or same_tuple[0]['left_censored']:
            raise ValueError('unattributed tuple spans multiple/unclear generations')
    selected.sort(key=lambda e: e['ref']['byte_start'])
    termination = [e for e in selected if e['terminal']]
    if not termination:
        raise ValueError('TCPIP termination missing')
    return dict(events=selected, connect=connected, peer=peer, termination=termination,
                generation_manifest=generations, tuple_terminals=tuple_terminals,
                policy_inside=sorted(primary_policy['inside']+peer_policy['inside'], key=lambda x:x['ref']['byte_start']),
                policy_outside=sorted(primary_policy['outside']+peer_policy['outside'], key=lambda x:x['ref']['byte_start']))


def reconstruct_generations(events):
    """A close observation bounds the session; Closed permits a new allocation."""
    groups = []
    for event in events:
        if int(event['tcb'], 16) == 0:
            raise ValueError('zero TCB cannot identify a named generation')
        birth = event.get('transition') in {('Closed', 'SynSent'), ('Listen', 'SynRcvd')}
        if birth:
            if groups and groups[-1]['closed_ref'] is None:
                raise ValueError('TCB new birth before prior generation reached Closed')
            groups.append(dict(ordinal=len(groups), left_censored=False, birth_ref=event['ref'],
                               closed_ref=None, identity=None, events=[]))
        elif not groups:
            if event['kind'] != 'exists':
                raise ValueError('TCB missing native birth/existing first generation')
            groups.append(dict(ordinal=0, left_censored=True, birth_ref=None, closed_ref=None,
                               identity=None, events=[]))
        group = groups[-1]
        if event['kind'] == 'exists' and group['events']:
            raise ValueError('unexpected existing generation marker')
        if event.get('local'):
            identity = group['identity']
            if identity is None:
                group['identity'] = dict(local=event['local'], remote=event['remote'], pid=event.get('pid'))
            else:
                if (event['local'], event['remote']) != (identity['local'], identity['remote']):
                    raise ValueError('TCB tuple changed within generation')
                if event.get('pid') is not None:
                    if identity['pid'] is not None and event['pid'] != identity['pid']:
                        raise ValueError('TCB PID identity changed within generation')
                    identity['pid'] = event['pid']
        if event['kind'] in ('connect completed', 'accept completed'):
            if group['closed_ref'] or any(e['kind'] in ('connect completed', 'accept completed') for e in group['events']):
                raise ValueError('duplicate/late generation establishment')
        if event.get('transition', (None, None))[1] == 'Closed' and group['closed_ref'] is None:
            group['closed_ref'] = event['ref']
        group['events'].append(event)
    return groups


def validate_capture(raw, etl, metadata, resolution_ns):
    """Verify complete conversion/clock provenance, returning UTC trace bounds."""
    import hashlib
    if metadata.get('capture_mode') != 'all-components-tcpip':
        raise ValueError('wrong TCPIP capture mode')
    before, after = metadata['clock_before'], metadata['clock_after']
    if before['offset_minutes'] != 480 or after['offset_minutes'] != 480:
        raise ValueError('unsupported/changing capture timezone')
    freq = before['stopwatch_frequency']
    if not isinstance(freq, int) or freq <= 0 or after['stopwatch_frequency'] != freq:
        raise ValueError('invalid capture monotonic frequency')
    wall = (after['utc_ticks'] - before['utc_ticks']) * 100
    mono = (after['mono'] - before['mono']) * 10**9 // freq
    if wall < 0 or mono < 0 or abs(wall - mono) > resolution_ns:
        raise ValueError('capture clock discontinuity')
    conversion = metadata['conversion']
    args = conversion['argv']
    if (conversion.get('exit_code') != 0 or len(args) != 5 or
            args[:2] != ['pktmon', 'etl2txt'] or args[3] != '--out' or
            not str(args[2]).endswith('.etl') or args[4] != args[2][:-4] + '.txt'):
        raise ValueError('invalid TCPIP conversion provenance')
    if conversion.get('etl_sha256') != hashlib.sha256(etl).hexdigest() or conversion.get('text_sha256') != hashlib.sha256(raw).hexdigest():
        raise ValueError('TCPIP ETL/text conversion hash mismatch')
    text = raw.decode('utf-16' if raw.startswith(b'\xff\xfe') else 'utf-8-sig')
    headers = [l for l in text.splitlines() if '[MSNT_SystemTrace]' in l and 'EndTime:' in l and 'StartTime:' in l]
    if len(headers) != 1:
        raise ValueError('missing/ambiguous ETL trace header')
    header = headers[0]
    def number(name):
        matches = re.findall(r'\b' + name + r': (\d+)(?:,|$)', header)
        if len(matches) != 1:
            raise ValueError('ETL header missing/ambiguous ' + name)
        return int(matches[0])
    if number('EventsLost') or number('BuffersLost'):
        raise ValueError('ETL event/buffer loss')
    start, end = number('StartTime'), number('EndTime')
    # Capture clock samples surround native start/stop, not the later conversion.
    begin_ns = (before['utc_ticks'] - 621355968000000000) * 100
    end_ns = (after['utc_ticks'] - 621355968000000000) * 100
    lo, hi = (start - 116444736000000000) * 100, (end - 116444736000000000) * 100
    if not begin_ns - resolution_ns <= lo <= hi <= end_ns + resolution_ns:
        raise ValueError('ETL header outside captured VM clock window')
    if 'LogFileNameString: ' + args[2] not in header:
        raise ValueError('ETL header path differs from conversion input')
    return lo, hi


def validate_tuple_probe(rows, origin, src, dst):
    """CON009: one independently observed probe connection, never nearest-match."""
    matching = [row for row in rows if row.get('src') == src and
                (row.get('actual_dst') or row.get('dst')) == dst]
    if origin.get('event') == 'curl_started':
        starts = [row for row in rows if row.get('event') == 'curl_started' and
                  row.get('pid') == origin.get('pid')]
        if len(starts) != 1 or starts[0] != origin or matching:
            raise ValueError('unattributed tuple has ambiguous curl process leg')
        return
    connection = origin.get('connection_id')
    if not connection or not matching or any(
            row.get('connection_id') != connection or row.get('pid') != origin.get('pid') or
            row.get('nonce') != origin.get('nonce') for row in matching):
        raise ValueError('unattributed tuple spans missing/multiple probe connection IDs')
    starts = [row for row in matching if row.get('event') in ('established', 'case_established')]
    if len(starts) != 1 or starts[0] != origin:
        raise ValueError('unattributed tuple has duplicate/retried probe establishment')


def curl_tuple(log, started):
    dns = started.get('dns_ipv4')
    if not isinstance(dns, list) or not dns:
        raise ValueError('curl lacks prior DNS set')
    if started['dns_before_ticks'] > started['creation_ticks']:
        raise ValueError('curl DNS observation follows native creation')
    candidates = set()
    for line in log.splitlines():
        row = fields(line)
        if ('PROCESS_FLOW ' not in line or row.get('pid') != str(started['pid']) or
                row.get('proto') != 'TCP' or row.get('dport') != '443'):
            continue
        address = ipaddress.IPv4Address(row['dst'])
        if address.is_loopback:
            continue
        if not address.is_global or row['dst'] not in dns:
            raise ValueError('curl destination outside prior DNS set')
        src, dst = row['src']+':'+row['sport'], row['dst']+':'+row['dport']
        endpoint(src); endpoint(dst)
        candidates.add((src, dst))
    if len(candidates) != 1:
        raise ValueError('curl requires one full-run public original tuple')
    return next(iter(candidates))


def scoped_log_event(log, name, wanted, window=None, unique_fields=None):
    """Bind a policy event; repeated packets don't create new upstream sockets."""
    matches, seen = [], set()
    for line in log.splitlines():
        if name + ' ' not in line and not line.rstrip().endswith(name):
            continue
        row = fields(line)
        if not all(row.get(key) == str(value) for key, value in wanted.items()):
            continue
        if window is None:
            return line
        if unique_fields:
            identity = tuple(row.get(key) for key in unique_fields)
            if identity in seen:
                continue
            seen.add(identity)
        if policy_scope(line, window) == 'inside':
            matches.append(line)
    if len(matches) > 1:
        raise ValueError('ambiguous same-window ' + name)
    return matches[0] if matches else None
