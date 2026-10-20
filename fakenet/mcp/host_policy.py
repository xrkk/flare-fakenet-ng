"""Strict structural validation of the one-VM local fixture, not AI assertions.

This pure module consumes complete root-collected nft JSON.  Unknown rule shapes
are deliberately unsupported.  Counter values/elements are separated from policy
semantics so that normal traffic does not change the policy identity.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import math
import re

POLICY_SCHEMA = 'fakenetng.host-local-policy.v2'
TABLE = 'mt_egress_fixture'
PORTS = (28787, 28788, 28790)


def _sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def _norm_uuid(value):
    return re.sub(r'[\s-]', '', str(value or '')).lower()


def _norm_mac(value):
    return str(value or '').replace('-', '').replace(':', '').lower()


def _match(left, right):
    return {'match': {'op': '==', 'left': left, 'right': right}}


def _meta(key):
    return {'meta': {'key': key}}


def _payload(proto, field):
    return {'payload': {'protocol': proto, 'field': field}}


def _ct(key, direction=None, family=None):
    value = {'key': key}
    if direction:
        value['dir'] = direction
    if family:
        value['family'] = family
    return {'ct': value}


def expected_rules(target):
    """The complete supported chain, in order, excluding mutable counters."""
    mac = str(target['mac']).replace('-', ':').lower()
    guest = str(ipaddress.IPv4Address(target['guest_ipv4']))
    host = str(ipaddress.IPv4Address(target['host_ipv4']))
    host_ll = str(ipaddress.IPv6Address(target['host_link_local']))
    solicited = str(ipaddress.IPv6Address(
        int(ipaddress.IPv6Address('ff02::1:ff00:0')) |
        (int(ipaddress.IPv6Address(host_ll)) & 0xffffff)))
    incoming = [_match(_meta('iifname'), 'vmnet8')]
    rules = []
    for kind, destination in [('nd-neighbor-solicit', solicited),
                              ('nd-neighbor-advert', host_ll)]:
        rules.append(incoming + [
            _match(_payload('ether', 'saddr'), mac),
            _match(_meta('l4proto'), 'ipv6-icmp'),
            _match(_payload('ip6', 'hoplimit'), 255),
            _match(_payload('ip6', 'daddr'), destination),
            _match(_payload('icmpv6', 'type'), kind), {'accept': None}])
    # Conntrack direction=reply supplies the exact reciprocal transport tuple.
    # nft 1.0.9 cannot compare two packet/ct expressions directly; neither a
    # broad established exception nor a guessed ephemeral port is accepted.
    for port in PORTS:
        rules.append(incoming + [
            _match(_payload('ether', 'saddr'), mac),
            _match(_meta('l4proto'), 'tcp'),
            _match(_payload('ip', 'saddr'), guest),
            _match(_payload('ip', 'daddr'), host),
            _match(_payload('tcp', 'sport'), port),
            _match(_ct('direction'), 'reply'),
            _match(_ct('state'), 'established'),
            _match(_ct('saddr', 'original', 'ip'), host),
            _match(_ct('daddr', 'original', 'ip'), guest),
            _match(_ct('protocol', 'original'), 'tcp'),
            _match(_ct('proto-dst', 'original'), port),
            _match(_ct('proto-src', 'original'), {'range': [1024, 65535]}),
            _match(_payload('tcp', 'dport'), {'range': [1024, 65535]}),
            {'accept': None}])
    for proto, set_name in [('ip', 'tcp_drop4'), ('ip6', 'tcp_drop6')]:
        concat = {'concat': [_payload(proto, 'saddr'),
                             _payload('tcp', 'sport'),
                             _payload(proto, 'daddr'),
                             _payload('tcp', 'dport')]}
        # A failed set update must not bypass the separate final drop rule.
        rules.append(incoming + [_match(_meta('nfproto'),
                                        'ipv4' if proto == 'ip' else 'ipv6'),
                                  _match(_meta('l4proto'), 'tcp'),
                                  {'set': {'op': 'update', 'set': '@' + set_name,
                                           'elem': {'elem': {'val': concat,
                                                            'timeout': 60000,
                                                            'counter': {}}}}}])
    rules.append(incoming + [{'counter': {}}, {'drop': None}])
    return rules


def _strip_counters(value):
    if isinstance(value, list):
        return [_strip_counters(item) for item in value]
    if isinstance(value, dict):
        return {key: ({} if key == 'counter' else _strip_counters(item))
                for key, item in value.items()}
    return value


def _parse_elements(item, family):
    """libnftables extended concat elements; unsupported output is unknown."""
    rows = []
    for element in item.get('elem', []):
        if not isinstance(element, dict) or set(element) != {'elem'}:
            raise ValueError('unsupported tuple element')
        element = element['elem']
        fields = (element.get('val') or {}).get('concat')
        if not isinstance(fields, list) or len(fields) != 4:
            raise ValueError('tuple concat missing')
        source = ipaddress.ip_address(fields[0])
        destination = ipaddress.ip_address(fields[2])
        version = 4 if family == 'ipv4' else 6
        if source.version != version or destination.version != version:
            raise ValueError('tuple family mismatch')
        sport, dport = fields[1], fields[3]
        count = (element.get('counter') or {}).get('packets')
        if (type(sport) is not int or type(dport) is not int or
                not 1 <= sport <= 65535 or not 1 <= dport <= 65535 or
                type(count) is not int or count < 0):
            raise ValueError('tuple port/counter invalid')
        rows.append({'family': family, 'source': str(source),
                     'source_port': sport, 'destination': str(destination),
                     'destination_port': dport, 'count': count})
    if len({(r['source'], r['source_port'], r['destination'],
             r['destination_port']) for r in rows}) != len(rows):
        raise ValueError('duplicate tuple counters')
    return rows


def parse_ruleset(parsed, target):
    entries = parsed.get('nftables') if isinstance(parsed, dict) else None
    if not isinstance(entries, list):
        raise ValueError('complete nft ruleset missing')
    owned = {'table': [], 'chain': [], 'rule': [], 'set': []}
    others = []
    for entry in entries:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ValueError('invalid nft object')
        kind, value = next(iter(entry.items()))
        if kind == 'metainfo':
            continue
        if not isinstance(value, dict):
            raise ValueError('invalid nft object value')
        if value.get('family') == 'inet' and (
                value.get('table') == TABLE or
                kind == 'table' and value.get('name') == TABLE):
            if kind not in owned:
                raise ValueError('unsupported object in owned table')
            owned[kind].append(value)
        else:
            others.append((kind, value))
    if len(owned['table']) != 1 or len(owned['chain']) != 1:
        raise ValueError('owned table/chain not exclusive')
    chain = owned['chain'][0]
    if (chain.get('name'), chain.get('type'), chain.get('hook'),
            chain.get('prio'), chain.get('policy')) != (
                'prerouting', 'filter', 'prerouting', -150, 'accept'):
        raise ValueError('unexpected owned base chain')
    expressions = []
    for row in owned['rule']:
        if row.get('chain') != 'prerouting' or not isinstance(row.get('expr'), list):
            raise ValueError('unexpected rule chain')
        expressions.append(_strip_counters(row['expr']))
    if expressions != expected_rules(target):
        raise ValueError('owned rule semantics/order mismatch')
    if len(owned['set']) != 2:
        raise ValueError('both bounded tuple sets required')
    drops = []
    semantics = []
    for name, addrtype, family in [('tcp_drop4', 'ipv4_addr', 'ipv4'),
                                    ('tcp_drop6', 'ipv6_addr', 'ipv6')]:
        found = [item for item in owned['set'] if item.get('name') == name]
        if len(found) != 1:
            raise ValueError('tuple set missing/duplicate')
        item = found[0]
        if (item.get('type') != [addrtype, 'inet_service', addrtype, 'inet_service']
                or set(item.get('flags') or []) != {'dynamic', 'timeout'}
                or item.get('size') != 4096 or item.get('timeout') != 60000):
            raise ValueError('tuple set contract mismatch')
        drops.extend(_parse_elements(item, family))
        semantics.append({key: copy.deepcopy(item[key]) for key in
                          ('name', 'type', 'flags', 'size', 'timeout')})
    # Earlier hooks cannot redirect/bypass traffic into the owned chain.  The
    # supported Docker raw rules are only exact matches followed by counter/drop.
    earlier = {(v.get('family'), v.get('table'), v.get('name')) for k, v in others
               if k == 'chain' and v.get('hook') in ('ingress', 'prerouting')
               and (v.get('hook') == 'ingress' or
                    not isinstance(v.get('prio'), int) or v['prio'] <= -150)}
    for kind, value in others:
        if kind == 'flowtable':
            raise ValueError('flowtable bypass unsupported')
        if kind != 'rule' or (value.get('family'), value.get('table'),
                              value.get('chain')) not in earlier:
            continue
        expr = value.get('expr')
        if not isinstance(expr, list) or not expr or expr[-1] != {'drop': None}:
            raise ValueError('unproven earlier rule')
        if any(set(statement) not in ({'match'}, {'counter'}, {'drop'})
               for statement in expr):
            raise ValueError('earlier rewrite/jump unsupported')
    semantic = {'table': TABLE, 'chain': {key: chain[key] for key in
                                        ('name', 'type', 'hook', 'prio', 'policy')},
                'rules': expressions, 'sets': semantics,
                'earlier_rules': [_strip_counters(v.get('expr')) for k, v in others
                                  if k == 'rule' and
                                  (v.get('family'), v.get('table'), v.get('chain'))
                                  in earlier]}
    return semantic, drops


def evaluate(facts, config):
    reasons = []
    result = {'ok': False, 'identity': None, 'reasons': reasons,
              'tcp_drops': [], 'fallback': {}}
    try:
        if not isinstance(facts, dict):
            raise ValueError('observer facts missing')
        target = facts['target']
        uuid = config.get('expected_uuid') or (config.get('vmx') or {}).get('expected_uuid')
        mac = config.get('expected_mac')
        if (not uuid or not mac or _norm_uuid(target.get('vm_uuid')) != _norm_uuid(uuid)
                or _norm_mac(target.get('mac')) != _norm_mac(mac)
                or target.get('guest_ipv4') != config.get('guest_ip')):
            raise ValueError('observer target mismatch')
        if not target.get('boot_id'):
            raise ValueError('guest epoch missing')
        network = facts['network']
        if (network.get('matching_vm') != 1 or network.get('vmnet8_users') != 1
                or network.get('all_nics_mapped') is not True
                or network.get('bypasses') != []):
            raise ValueError('network mapping unproven')
        natd = facts['natd']
        if (natd.get('state') != 'stopped' or
                natd.get('all_threads_stopped') is not True or
                natd.get('pidfd_identity') is not True or
                type(natd.get('pid')) is not int or
                type(natd.get('birth_ticks')) is not int or
                not natd.get('boot_id')):
            raise ValueError('NAT stop identity unproven')
        semantic, drops = parse_ruleset(facts['ruleset'], target)
        observer = facts['observer_identity']
        for key in ('pid', 'birth_ticks', 'boot_id', 'script_sha256',
                    'lease_id', 'window_start', 'window_end'):
            if observer.get(key) in (None, ''):
                raise ValueError('observer lease identity incomplete')
        start, end = float(observer['window_start']), float(observer['window_end'])
        if not all(map(math.isfinite, (start, end))) or not 0 < end - start <= 900:
            raise ValueError('observer window invalid')
        identity = {'policy': semantic, 'target': target,
                    'natd': {key: natd[key] for key in
                             ('pid', 'birth_ticks', 'boot_id', 'state')},
                    'observer': observer, 'network': network}
        result.update(ok=True, identity=_sha(identity), semantic=identity,
                      tcp_drops=drops, sets_complete=True)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        reasons.append(str(exc))
    return result


def drop_tuple_count(facts, *, family, source, source_port, destination,
                     destination_port):
    # Facts are re-parsed here.  Never consume a supplied tcp_drops/verified flag.
    try:
        _, rows = parse_ruleset(facts['ruleset'], facts['target'])
        want = (family, str(ipaddress.ip_address(source)), source_port,
                str(ipaddress.ip_address(destination)), destination_port)
        for row in rows:
            got = tuple(row[k] for k in ('family', 'source', 'source_port',
                                        'destination', 'destination_port'))
            if got == want:
                return row['count']
        return 0  # Only a complete, validated set permits an absent=0 baseline.
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def drop_delta(pre_facts, final_facts, **tuple_fields):
    before = drop_tuple_count(pre_facts, **tuple_fields)
    after = drop_tuple_count(final_facts, **tuple_fields)
    if before is None or after is None or after < before:
        return None
    return after - before
