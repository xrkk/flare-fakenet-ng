"""Observe and recover one exact route added by the original acceptance owner.

This restores driver-owned state; it does not claim that the original product
stop callback removes default routes. No broad route replacement is supported.
"""
import ipaddress
import json
import re
import subprocess


def canonical(rows):
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError('route snapshot must contain original object rows')
    if any(row.get('dst') != 'default' for row in rows):
        raise ValueError('default route snapshot contains another destination')
    return sorted([json.loads(json.dumps(row, sort_keys=True)) for row in rows],
                  key=lambda row: json.dumps(row, sort_keys=True))


def route_snapshot():
    result = subprocess.run(['ip', '-4', '-j', 'route', 'show', 'table', 'all'],
                            capture_output=True, text=True, check=True, timeout=10)
    return canonical([row for row in json.loads(result.stdout) if row.get('dst') == 'default'])


def delete_command(row):
    allowed = {'dst', 'gateway', 'dev', 'table', 'protocol', 'scope', 'prefsrc', 'metric', 'flags'}
    if set(row) - allowed or row.get('dst') != 'default' or row.get('flags', []) != []:
        raise ValueError('route attributes cannot be recovered exactly')
    ipaddress.IPv4Address(row['gateway'])
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,64}', row['dev']):
        raise ValueError('invalid route device')
    argv = ['ip', '-4', 'route', 'del', 'default', 'via', row['gateway'], 'dev', row['dev']]
    for name, option in [('table', 'table'), ('protocol', 'proto'), ('scope', 'scope'),
                         ('prefsrc', 'src'), ('metric', 'metric')]:
        if name in row:
            text = str(row[name])
            if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,64}', text):
                raise ValueError('invalid route qualifier')
            if name == 'prefsrc': ipaddress.IPv4Address(text)
            argv.extend([option, text])
    return argv


def route_delete(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=10).returncode


def owned_row(before, active, ipv4, interface, original_add_succeeded):
    before, active = canonical(before), canonical(active)
    if not original_add_succeeded:
        if before != active: raise ValueError('unowned route drift without original successful add')
        return None
    # Never remove a preexisting default to manufacture a positive precondition.
    if before: raise ValueError('original add was not from the no-default precondition')
    if len(active) != 1: raise ValueError('added route is ambiguous or foreign')
    row = active[0]
    if row.get('gateway') != ipv4 or row.get('dev') != interface:
        raise ValueError('added route does not match the original target/interface')
    delete_command(row)
    return row


def recover_route(before, active, after_stop, ipv4, interface, add_succeeded, quiescent):
    result = dict(before=canonical(before), active=canonical(active),
                  after_stop=canonical(after_stop), after_recovery=None,
                  original_add_succeeded=add_succeeded, quiescent=quiescent,
                  original_stop_restored=canonical(before) == canonical(after_stop),
                  owned=None, command=None, returncode=None, restored=False, error=None)
    try:
        row = owned_row(before, active, ipv4, interface, add_succeeded)
        result['owned'] = row
        if not quiescent: raise ValueError('original route writer has not quiesced')
        # Re-observe immediately before mutation. Unknown concurrent rows refuse.
        observed = route_snapshot()
        if observed != result['after_stop']: raise ValueError('route changed after original stop')
        if row is not None and observed != canonical(before):
            if observed != canonical(active): raise ValueError('foreign default-route drift')
            argv = delete_command(row); result['command'] = argv
            result['returncode'] = route_delete(argv)
            if result['returncode'] != 0: raise ValueError('owned route removal failed')
        result['after_recovery'] = route_snapshot()
        if result['after_recovery'] != canonical(before): raise ValueError('route restoration not observed')
        result['restored'] = True
    except Exception as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
        try: result['after_recovery'] = route_snapshot()
        except Exception: pass
    return result


def verify_route(result, ipv4, interface):
    row = owned_row(result['before'], result['active'], ipv4, interface,
                    result['original_add_succeeded'])
    if result.get('owned') != row or result.get('quiescent') is not True:
        raise ValueError('owned route identity/quiescence missing')
    before, active, stopped = map(canonical, (result['before'], result['active'], result['after_stop']))
    if result.get('original_stop_restored') != (before == stopped):
        raise ValueError('original stop limitation was changed')
    if stopped not in (before, active): raise ValueError('foreign route drift after stop')
    expected = delete_command(row) if row is not None and stopped != before else None
    if result.get('command') != expected or result.get('returncode') != (0 if expected else None):
        raise ValueError('exact owned recovery action missing')
    if canonical(result['after_recovery']) != before or result.get('restored') is not True or result.get('error'):
        raise ValueError('independent route restoration failed')
    return True
