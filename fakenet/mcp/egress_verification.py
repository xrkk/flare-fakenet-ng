"""Guest-side egress verification subset and result assembly.

The guest cannot prove host forwarding/NAT or a sample user's context.  This
module therefore reports the guest-observable subset honestly: live FakeNet
facts come from the supervisor, while the diagnostic child collects guest OS
facts and one bounded local echo.  Host-only checks remain null and the
host stdio facade merges them.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import time

from fakenet.mcp import MCP_PACKAGE_VERSION, egress_contract, paths

GUEST_VERIFY_BUDGET_SECONDS = 20.0
ECHO_DESTINATION = '198.51.100.77'
ECHO_PORT = 1337
MAX_TEXT = 64 * 1024


def utc_now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'))


def _remaining(deadline, cap):
    if deadline is None:
        return cap
    return max(0.0, min(cap, deadline - time.monotonic()))


def _run_command(argv, deadline, execute=None):
    timeout = _remaining(deadline, 5.0)
    if timeout <= 0:
        return {'available': False, 'error': 'deadline'}
    if execute is not None:
        try:
            result = execute(argv, timeout)
        except Exception as exc:  # noqa: BLE001 - report the real failure
            return {'available': False, 'error': repr(exc)}
        if isinstance(result, dict):
            return result
        return {'available': False, 'error': 'command adapter returned no dict'}
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace', shell=False)
    except Exception as exc:  # noqa: BLE001 - report the real failure
        return {'available': False, 'error': repr(exc)}
    return {
        'available': completed.returncode == 0,
        'returncode': completed.returncode,
        'stdout': (completed.stdout or '')[:MAX_TEXT],
        'stderr': (completed.stderr or '')[:MAX_TEXT],
    }


def _powershell(script):
    return ['powershell', '-NoProfile', '-NonInteractive', '-Command', script]


def _firewall_profiles(deadline, execute=None):
    script = (
        "$ErrorActionPreference='Stop';"
        "$rows=@(Get-NetFirewallProfile -PolicyStore ActiveStore | "
        "Select-Object Name,Enabled);"
        "ConvertTo-Json -InputObject $rows -Depth 3 -Compress")
    result = _run_command(_powershell(script), deadline, execute)
    if not result.get('available'):
        return result
    try:
        rows = json.loads(result.get('stdout') or 'null')
    except ValueError as exc:
        return {'available': False, 'error': 'firewall-json: %r' % exc}
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return {'available': False, 'error': 'firewall-json: not a list'}
    profiles = []
    for row in rows:
        if not isinstance(row, dict):
            return {'available': False, 'error': 'firewall-json: row'}
        profiles.append({'name': str(row.get('Name') or ''),
                         'enabled': bool(row.get('Enabled'))})
    return {'available': True, 'profiles': profiles}


def _adapter_info(deadline, execute=None):
    script = (
        "$ErrorActionPreference='Stop';"
        "$rows=@(Get-NetAdapter | Select-Object Name,InterfaceDescription,"
        "Status,MacAddress,ifIndex);"
        "ConvertTo-Json -InputObject $rows -Depth 4 -Compress")
    return _run_command(_powershell(script), deadline, execute)


def _echo_probe(nonce, deadline, probe=None):
    started = utc_now()
    timeout = _remaining(deadline, 1.5)
    if timeout <= 0:
        return {'available': False, 'error': 'deadline', 'started_at': started,
                'ended_at': utc_now(), 'nonce_match': False}
    if probe is not None:
        try:
            value = probe(nonce, timeout)
        except Exception as exc:  # noqa: BLE001 - report the real failure
            return {'available': False, 'error': repr(exc),
                    'started_at': started, 'ended_at': utc_now(),
                    'nonce_match': False}
        value.setdefault('started_at', started)
        value.setdefault('ended_at', utc_now())
        value.setdefault('nonce_match',
                         nonce in str(value.get('received') or ''))
        return value
    payload = ('MALTRACE-EGRESS-' + nonce).encode('utf-8')
    result = {'available': False, 'sent': 0, 'received': '',
              'error': None, 'started_at': started, 'ended_at': None,
              'nonce_match': False, 'destination': ECHO_DESTINATION,
              'port': ECHO_PORT}
    sock = None
    try:
        sock = socket.create_connection(
            (ECHO_DESTINATION, ECHO_PORT), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(payload)
        result['sent'] = len(payload)
        raw = sock.recv(4096)
        result['received'] = raw.decode('utf-8', 'replace')
        result['available'] = True
        result['nonce_match'] = nonce in result['received']
    except Exception as exc:  # noqa: BLE001 - report the real failure
        result['error'] = repr(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        result['ended_at'] = utc_now()
    return result


def _guest_evidence_dir(run_id, verification_id):
    root = paths.data_directories()['artifacts']
    return (Path(root) / 'runs' / str(run_id) / 'egress-verification' /
            str(verification_id))


def _write_exclusive(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) +
           '\n').encode('utf-8')
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {'path': str(path), 'sha256': sha256_bytes(raw), 'size': len(raw)}


def collect_guest_subset(payload, deadline, execute=None, probe=None):
    """Fixed diagnostic operation: guest OS facts and one local echo.

    No caller-controlled executable, URL, path or shell is accepted.
    """
    run_id = payload.get('run_id')
    verification_id = payload.get('verification_id')
    nonce = payload.get('probe_nonce')
    if not isinstance(run_id, str) or not isinstance(verification_id, str):
        raise ValueError('guest verification identity invalid')
    if not isinstance(nonce, str) or not 1 <= len(nonce) <= 256:
        raise ValueError('guest verification nonce invalid')
    child = {
        'status': 'ok',
        'run_id': run_id,
        'verification_id': verification_id,
        'identity': {'pid': os.getpid(), 'hostname': socket.gethostname(),
                     'platform': platform.platform()},
        'firewall': _firewall_profiles(deadline, execute),
        'route4': _run_command(['route', 'print', '-4'], deadline, execute),
        'route6': _run_command(['route', 'print', '-6'], deadline, execute),
        'adapters': _adapter_info(deadline, execute),
        'netstat': _run_command(['netstat', '-ano'], deadline, execute),
        'local_echo': (_echo_probe(nonce, deadline, probe)
                       if payload.get('guest_echo_allowed') is True else
                       {'available': False,
                        'error': 'guest_echo_not_authorized',
                        'nonce_match': False}),
        'producer_match': _producer_match(run_id, payload),
    }
    evidence = _write_exclusive(
        _guest_evidence_dir(run_id, verification_id) / 'guest-subset.json',
        child)
    child['evidence'] = evidence
    return child



def _producer_match(run_id, payload):
    pid = payload.get('host_probe_pid')
    creation = payload.get('host_probe_creation')
    nonce = payload.get('probe_nonce')
    started = payload.get('host_probe_started')
    ended = payload.get('host_probe_ended')
    source = payload.get('host_probe_source')
    source_port = payload.get('host_probe_source_port')
    protocol = str(payload.get('host_probe_protocol') or '').upper()
    if type(pid) is not int or type(creation) is not int or not isinstance(
            nonce, str) or not nonce or not started or not ended or not (
                isinstance(source, str) and source) or type(
                    source_port) is not int or protocol not in ('TCP', 'UDP'):
        return {'value': None, 'reason': 'probe_instance_missing',
                'lines': [], 'log_path': None}
    try:
        start_epoch = datetime.fromisoformat(
            str(started).replace('Z', '+00:00')).timestamp()
        end_epoch = datetime.fromisoformat(
            str(ended).replace('Z', '+00:00')).timestamp()
    except (ValueError, TypeError):
        return {'value': None, 'reason': 'probe_window_invalid',
                'lines': [], 'log_path': None}
    root = paths.data_directories()['artifacts']
    log_path = Path(root) / 'runs' / str(run_id) / 'run.log'
    if log_path.is_symlink() or not log_path.is_file():
        return {'value': None, 'reason': 'run_log_missing',
                'lines': [], 'log_path': str(log_path)}
    try:
        raw = log_path.read_bytes()[-512 * 1024:]
    except OSError as exc:
        return {'value': None, 'reason': 'run_log_unreadable: %r' % exc,
                'lines': [], 'log_path': str(log_path)}
    destination = str(payload.get('host_probe_destination') or
                      '198.51.100.77')
    port = payload.get('host_probe_port')
    port_text = str(port) if type(port) is int else '1337'
    lines = []
    for line in raw.decode('utf-8', 'replace').splitlines():
        if 'DIVERT_FAKE' not in line:
            continue
        fields = dict(re.findall(r'([A-Za-z_][A-Za-z0-9_]*)=([^ ]+)', line))
        if str(fields.get('pid')) != str(pid):
            continue
        if str(fields.get('creation')) != str(creation):
            continue
        if str(fields.get('probe_nonce')) != nonce:
            continue
        if str(fields.get('src')) != source:
            continue
        if str(fields.get('sport')) != str(source_port):
            continue
        if str(fields.get('proto', '')).upper() != protocol:
            continue
        try:
            epoch = float(fields.get('epoch'))
        except (TypeError, ValueError):
            continue
        if not start_epoch - 2 <= epoch <= end_epoch + 2:
            continue
        if str(fields.get('dst') or fields.get('original_ip')) != destination:
            continue
        if str(fields.get('dport') or fields.get('original_port')) != port_text:
            continue
        if str(fields.get('proto', '')).upper() not in ('TCP', 'UDP'):
            continue
        if not fields.get('src') or not fields.get('sport'):
            continue
        lines.append(line[:768])
    return {'value': bool(lines),
            'reason': 'diverter_flow_tuple_match' if lines
            else 'no_diverter_flow_tuple_match',
            'lines': lines[:5], 'log_path': str(log_path),
            'log_sha256': sha256_bytes(raw)}



def parse_control_filter(text, control_ip=None):
    """Parse a restricted boolean filter and prove control-port exclusion.

    The real run filter may contain an IP condition joined by ``or`` to a
    conjunction/disjunction of exact ``tcp.SrcPort`` terms.  We parse the
    boolean AST, set the IP predicates to the control-destination case and
    enumerate the remaining port predicates.  For every required control
    port, the filter must be false whenever that port matches; an outer
    ``or true``, ``not`` bypass, equality, DstPort direction, unknown token or
    parse failure is rejected.
    """
    raw = str(text or '').strip()
    if not raw or len(raw) > 8192:
        return {'ok': False, 'reason': 'filter_missing', 'ports': []}
    token_re = re.compile(
        r'\(|\)|\b(?:and|or|not|true|false|outbound|ipv6|ip)\b(?!\.)|'
        r'tcp\.srcport\s*!=\s*\d+|tcp\.srcport\s*==\s*\d+|'
        r'tcp\.dstport\s*!=\s*\d+|tcp\.dstport\s*==\s*\d+|'
        r'(?:ip|ipv6)\.dstaddr\s*(?:!=|==|<=|>=|<|>)\s*[0-9a-fA-F:.]+', re.IGNORECASE)
    tokens = []
    pos = 0
    for match in token_re.finditer(raw):
        if raw[pos:match.start()].strip():
            return {'ok': False, 'reason': 'filter_token_unknown',
                    'ports': []}
        tokens.append(match.group(0).strip().lower())
        pos = match.end()
    if raw[pos:].strip():
        return {'ok': False, 'reason': 'filter_token_unknown', 'ports': []}
    if any(token.startswith('tcp.dstport') for token in tokens):
        return {'ok': False, 'reason': 'filter_inbound_direction',
                'ports': []}
    if 'tcp.srcport' not in ' '.join(tokens):
        return {'ok': False, 'reason': 'filter_no_ports', 'ports': []}

    import ipaddress
    if control_ip:
        try:
            control_address = ipaddress.ip_address(str(control_ip))
        except ValueError:
            return {'ok': False, 'reason': 'control_address_invalid', 'ports': []}
    else:
        # Without an explicit target, prove exclusion for the single exact
        # non-loopback IPv4 control address named in the live filter.
        candidates = set(re.findall(
            r'ip\.dstaddr\s*(?:!=|==)\s*([0-9.]+)', raw, re.I))
        candidates = {ipaddress.ip_address(v) for v in candidates
                      if not ipaddress.ip_address(v).is_loopback}
        if len(candidates) > 1:
            return {'ok': False, 'reason': 'control_address_ambiguous', 'ports': []}
        control_address = next(iter(candidates), None)

    def atom(token):
        if token == 'true':
            return ('const', True)
        if token == 'false':
            return ('const', False)
        if token == 'outbound':
            return ('const', True)
        if token in ('ip', 'ipv6'):
            family = 6 if token == 'ipv6' else 4
            return ('const', control_address is None or
                    control_address.version == family)
        address = re.fullmatch(
            r'(ip|ipv6)\.dstaddr\s*(!=|==|<=|>=|<|>)\s*([0-9a-f:.]+)', token)
        if address:
            if control_address is None:
                raise ValueError('control_address_missing')
            value = ipaddress.ip_address(address.group(3))
            if value.version != control_address.version:
                return ('const', False)
            left, right = int(control_address), int(value)
            matched = {'!=': left != right, '==': left == right,
                       '<': left < right, '>': left > right,
                       '<=': left <= right, '>=': left >= right}[address.group(2)]
            return ('const', matched)
        match = re.match(r'tcp\.srcport\s*(!=|==)\s*(\d+)$', token)
        if not match:
            raise ValueError('filter_atom_unknown')
        port = int(match.group(2))
        if not 1 <= port <= 65535:
            raise ValueError('filter_port_invalid')
        value = ('var', 'port:%d' % port)
        return ('not', value) if match.group(1) == '!=' else value

    def parse_or(index):
        node, index = parse_and(index)
        while index < len(tokens) and tokens[index] == 'or':
            right, index = parse_and(index + 1)
            node = ('or', node, right)
        return node, index

    def parse_and(index):
        node, index = parse_not(index)
        while index < len(tokens) and tokens[index] == 'and':
            right, index = parse_not(index + 1)
            node = ('and', node, right)
        return node, index

    def parse_not(index):
        if index < len(tokens) and tokens[index] == 'not':
            node, index = parse_not(index + 1)
            return ('not', node), index
        return parse_primary(index)

    def parse_primary(index):
        if index >= len(tokens):
            raise ValueError('filter_unexpected_end')
        token = tokens[index]
        if token == '(':
            node, index = parse_or(index + 1)
            if index >= len(tokens) or tokens[index] != ')':
                raise ValueError('filter_parenthesis')
            return node, index + 1
        if token == ')':
            raise ValueError('filter_parenthesis')
        return atom(token), index + 1

    try:
        ast, index = parse_or(0)
        if index != len(tokens):
            raise ValueError('filter_trailing_tokens')
    except ValueError as exc:
        return {'ok': False, 'reason': str(exc), 'ports': []}

    variables = sorted({name for node in _walk_ast(ast)
                        if node[0] == 'var' for name in [node[1]]})
    port_vars = [name for name in variables if name.startswith('port:')]
    ip_vars = [name for name in variables if name.startswith('ip:')]
    if len(port_vars) > 12:
        return {'ok': False, 'reason': 'filter_too_complex', 'ports': []}
    required = []
    for name in port_vars:
        required.append(int(name.split(':', 1)[1]))
    # The caller checks required subset; return all observed ports.
    for target in required:
        others = [name for name in port_vars if name != 'port:%d' % target]
        for bits in range(1 << len(others)):
            assignment = {name: False for name in variables}
            assignment['port:%d' % target] = True
            for index, name in enumerate(others):
                assignment[name] = bool(bits & (1 << index))
            for name in ip_vars:
                assignment[name] = False
            if _eval_ast(ast, assignment):
                return {'ok': False, 'reason': 'filter_control_not_excluded',
                        'ports': required}
    return {'ok': True, 'reason': 'restricted_filter_control_excluded',
            'ports': sorted(required)}


def _walk_ast(node):
    if node[0] == 'var':
        yield node
    elif node[0] == 'not':
        yield from _walk_ast(node[1])
    elif node[0] in ('and', 'or'):
        yield from _walk_ast(node[1])
        yield from _walk_ast(node[2])


def _eval_ast(node, assignment):
    if node[0] == 'const':
        return bool(node[1])
    if node[0] == 'var':
        return bool(assignment.get(node[1], False))
    if node[0] == 'not':
        return not _eval_ast(node[1], assignment)
    if node[0] == 'and':
        return _eval_ast(node[1], assignment) and _eval_ast(node[2], assignment)
    if node[0] == 'or':
        return _eval_ast(node[1], assignment) or _eval_ast(node[2], assignment)
    return False


def _inbound_safe(health):
    mode = health.get('capture_mode')
    flags = str(health.get('inbound_capture_flags') or '').upper().strip()
    active = health.get('inbound_capture_active')
    inbound_filter = str(health.get('inbound_capture_filter') or '').lower()
    if any(token in flags for token in ('DROP', 'MODIFY', 'REDIRECT',
                                        'INJECT')):
        return False, 'inbound_flags_rewrite'
    if mode == 'sniff':
        if active is True and flags == 'SNIFF' and 'inbound' in inbound_filter:
            return True, 'sniff_record_only_handle'
        return False, 'sniff_handle_not_record_only'
    if mode in ('outbound_only', 'listener_only'):
        if active in (False, None):
            return True, 'inbound_absent_or_non_owning'
        return False, 'inbound_active_without_sniff'
    return False, 'inbound_mode_unrecognized'




def filter_ports(text):
    return parse_control_filter(text)['ports']



def _evidence_ref(side, path, digest, kind):
    return {'side': side, 'path': str(path), 'sha256': digest, 'kind': kind}


def _check(value, refs):
    return {'value': value, 'evidence_refs': refs}


def _step(step_id, outcome, expected, observed, reason, refs, started=None,
          ended=None):
    return {'id': step_id, 'outcome': outcome, 'expected': expected,
            'observed': observed, 'reason_code': reason,
            'evidence_refs': refs, 'started_at': started or utc_now(),
            'ended_at': ended or utc_now()}


def _health_ok(health, snapshot):
    return bool(
        snapshot.get('state') == 'healthy' and
        health.get('process_alive') is True and
        health.get('init_evidence') is True and
        health.get('probe') is True and
        health.get('capture_threads_alive') is True and
        health.get('capture_error') is None)


def build_guest_result(*, command_id, request, snapshot, health, child,
                       started_at=None, live_evidence=None):
    """Assemble the honest guest-only subset result.

    This function is also used by offline tests with injected child/health
    dictionaries.  It never upgrades a host-only check to pass.
    """
    started = started_at or utc_now()
    ended = utc_now()
    required = list(request['required_control_ports'])
    final_filter = str(health.get('final_filter') or '')
    control_parse = parse_control_filter(
        final_filter, health.get('control_link_exclude_ip'))
    effective = control_parse['ports']
    inbound_mode = health.get('capture_mode')
    inbound_filter = health.get('inbound_capture_filter')
    inbound_flags = health.get('inbound_capture_flags')
    inbound_ok, inbound_reason = _inbound_safe(health)
    firewall = child.get('firewall') or {}
    profiles = firewall.get('profiles') or []
    firewall_ok = (bool(firewall.get('available')) and len(profiles) == 3 and
                   {row.get('name') for row in profiles} ==
                   {'Domain', 'Private', 'Public'} and
                   all(row.get('enabled') is False and
                       row.get('name') in ('Domain', 'Private', 'Public')
                       for row in profiles))
    health_ok = _health_ok(health, snapshot)
    exclusions_ok = (control_parse['ok'] and inbound_ok and
                     set(required).issubset(set(effective)))
    echo = child.get('local_echo') or {}
    echo_ok = bool(echo.get('available') and echo.get('nonce_match'))
    producer = child.get('producer_match') or {}
    producer_value = producer.get('value')
    evidence = child.get('evidence') or {}
    evidence_path = evidence.get('path')
    evidence_sha = evidence.get('sha256')
    live_path = (live_evidence or {}).get('path', 'live-health')
    live_sha = (live_evidence or {}).get('sha256') or sha256_bytes(
        canonical_json(health).encode('utf-8'))
    filter_sha = sha256_bytes(final_filter.encode('utf-8'))
    refs = []
    if evidence_path and evidence_sha:
        refs.append(_evidence_ref('guest', evidence_path, evidence_sha,
                                  'guest-subset'))
    refs.append(_evidence_ref('guest', live_path, live_sha,
                              'live-health'))
    checks = {
        'firewall_disabled': _check(
            True if firewall_ok else (False if firewall.get('available')
                                      else None),
            [r['path'] + '#' + r['sha256'] for r in refs
             if r['kind'] == 'guest-subset']),
        'fakenet_running_healthy': _check(
            True if health_ok else False,
            [r['path'] + '#' + r['sha256'] for r in refs
             if r['kind'] == 'live-health']),
        'mcp_control_exclusions_effective': _check(
            True if exclusions_ok else (False if final_filter else None),
            [r['path'] + '#' + r['sha256'] for r in refs
             if r['kind'] == 'live-health']),
        'blocked_before_interception': _check(None, []),
        'control_channels_reachable': _check(None, []),
        'local_interception_observed': _check(None, []),
        'independent_egress_blocked': _check(None, []),
        'sample_path_equivalent': _check(None, []),
    }
    plan = {
        'run_id': request['run_id'],
        'vm_epoch': request['vm_epoch'],
        'policy_identity': request['policy_identity'],
        'execution_context_identity': request['execution_context_identity'],
        'probe_nonce': request['probe_nonce'],
        'required_control_ports': required,
    }
    observation = {
        'run_id': plan['run_id'],
        'vm_epoch': plan['vm_epoch'],
        'policy_identity': plan['policy_identity'],
        'execution_context_identity': plan['execution_context_identity'],
        'response_nonce': request['probe_nonce'] if echo_ok else None,
        'effective_control_exclusion_ports': effective or None,
        'checks': checks,
    }
    conclusion = egress_contract.evaluate_interception_qualification(
        plan, observation)
    status = conclusion['status']
    steps = [
        _step('guest_health', 'pass' if health_ok else 'fail',
              'healthy core with real handles/listeners',
              {'state': snapshot.get('state'), 'health': health},
              'healthy' if health_ok else 'health_or_handle_unconfirmed',
              [dict(r) for r in refs
               if r['kind'] == 'live-health'], started, ended),
        _step('guest_control_filter',
              'pass' if exclusions_ok else ('fail' if final_filter else 'unknown'),
              'required ports in final filter and inbound not rewriting',
              {'final_filter': final_filter, 'effective_ports': effective,
               'filter_reason': control_parse['reason'],
               'inbound_capture_filter': inbound_filter,
               'inbound_capture_flags': inbound_flags,
               'capture_mode': inbound_mode,
               'inbound_reason': inbound_reason},
              'control_ports_present' if exclusions_ok
              else 'control_filter_unverified',
              [dict(r) for r in refs
               if r['kind'] == 'live-health'], started, ended),
        _step('guest_inbound_capture',
              'pass' if inbound_ok else 'fail',
              'record-only/absent inbound path, no delivery rewrite',
              {'mode': inbound_mode, 'filter': inbound_filter,
               'flags': inbound_flags,
               'active': health.get('inbound_capture_active'),
               'reason': inbound_reason},
              'record_only_inbound' if inbound_ok else inbound_reason,
              [], started, ended),
        _step('guest_firewall',
              'pass' if firewall_ok else ('fail' if firewall.get('available')
                                          else 'unknown'),
              'ActiveStore Domain/Private/Public Enabled=False',
              {'profiles': profiles, 'error': firewall.get('error')},
              'firewall_disabled' if firewall_ok else 'firewall_unconfirmed',
              [dict(r) for r in refs
               if r['kind'] == 'guest-subset'], started, ended),
        _step('guest_route',
              'pass' if child.get('route4', {}).get('available') else 'unknown',
              'current guest IPv4/IPv6 route facts',
              {'route4': child.get('route4'), 'route6': child.get('route6')},
              'route_read' if child.get('route4', {}).get('available')
              else 'route_unavailable', [], started, ended),
        _step('guest_adapters',
              'pass' if child.get('adapters', {}).get('available')
              else 'unknown', 'current guest NIC facts',
              {'adapters': child.get('adapters'),
               'netstat': child.get('netstat')},
              'adapter_read' if child.get('adapters', {}).get('available')
              else 'adapter_unavailable', [], started, ended),
        _step('guest_local_echo',
              'pass' if echo_ok else ('fail' if echo.get('available')
                                      else 'unknown'),
              'TCP/1337 local echo with request nonce',
              {'sent': echo.get('sent'), 'received': echo.get('received'),
               'error': echo.get('error'),
               'destination': echo.get('destination')},
              'nonce_echoed' if echo_ok else 'nonce_not_echoed',
              [dict(r) for r in refs
               if r['kind'] == 'guest-subset'], started, ended),
        _step('guest_producer_match',
              'pass' if producer_value is True else
              ('fail' if producer_value is False else 'unknown'),
              'host probe PID/tuple appears in current Diverter run log',
              {'producer': producer},
              'diverter_flow_match' if producer_value is True else
              'producer_match_unconfirmed', [], started, ended),
        _step('guest_artifacts',
              'pass' if evidence_path and evidence_sha else 'unknown',
              'guest raw subset artifact with hash',
              {'path': evidence_path, 'sha256': evidence_sha,
               'size': evidence.get('size')},
              'artifact_published' if evidence_path else 'artifact_missing',
              [dict(r) for r in refs
               if r['kind'] == 'guest-subset'], started, ended),
        _step('guest_consistency',
              'pass' if (request.get('run_id') == snapshot.get('run_id') and
                         request.get('controller') in (None, snapshot.get(
                             'controller'))) else 'fail',
              'same run/controller before and after',
              {'request_run_id': request.get('run_id'),
               'snapshot_run_id': snapshot.get('run_id'),
               'controller': snapshot.get('controller')},
              'binding_stable', [], started, ended),
    ]
    executed = sum(1 for step in steps if step['outcome'] != 'not_run')
    manifest = {
        'sha256': sha256_bytes(canonical_json(refs).encode('utf-8')),
        'entries': refs,
        'invalidation_conditions': [
            'run_id', 'vm_epoch', 'policy_identity',
            'execution_context_identity', 'config_identity',
            'final_filter', 'network_boundary', 'host_evidence',
            'service_restart', 'command_cache_eviction', 'nonce_reuse',
            'evidence_hash',
        ],
    }
    result = {
        'schema_version': egress_contract.SCHEMA_VERSION,
        'verification_id': request['verification_id'],
        'command_id': command_id,
        'lifecycle': {'state': 'completed', 'started_at': started,
                      'ended_at': ended, 'duration_ms': None,
                      'reason': None},
        'verdict': egress_contract.verdict_from_status(status),
        'bindings': {
            'run_id': snapshot.get('run_id'),
            'vm_epoch': request['vm_epoch'],
            'policy_identity': request['policy_identity'],
            'execution_context_identity':
                request['execution_context_identity'],
            'probe_nonce': request['probe_nonce'],
            'response_nonce': observation['response_nonce'],
            'required_control_ports': required,
            'effective_control_exclusion_ports': effective or None,
            'config_identity': snapshot.get('config_identity'),
            'final_filter_sha256': filter_sha,
            'host_evidence_sha256': request.get('host_evidence_sha256'),
            'guest_evidence_sha256': evidence_sha,
            'controller_identity': snapshot.get('controller'),
            'facade_version': MCP_PACKAGE_VERSION,
            'matrix_version': request['matrix_version'],
        },
        'steps': steps,
        'checks': checks,
        'helper_input': {'plan': plan, 'observation': observation},
        'conclusion': {
            'status': status,
            'verdict': egress_contract.verdict_from_status(status),
            'failed_checks': conclusion['failed_checks'],
            'unknown_checks': conclusion['unknown_checks'],
            'sample_path_qualified': conclusion['sample_path_qualified'],
            'stop_remaining_probes': conclusion['stop_remaining_probes'],
            'authorized': False,
            'reason': ('guest_only_host_facts_unknown'
                       if status == 'underdetermined' else status),
        },
        'coverage': {'matrix_version': request['matrix_version'],
                     'planned': len(steps), 'executed': executed,
                     'not_run': []},
        'manifest': manifest,
        'invalidation_conditions': manifest['invalidation_conditions'],
        'limitations': [
            'guest-only subset; host forwarding/NAT/control channels unknown',
            'guest LocalSystem probe does not prove sample user context',
            'TEST-NET echo/timeout is not host egress-block evidence',
        ],
        'producer_match': producer_value,
        'authorized': False,
        'error': None,
    }
    return result
