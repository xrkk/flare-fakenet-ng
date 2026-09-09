"""Evaluate real private-pipe evidence using the parent's monotonic clock."""


def check_ipc_case(fault, run_id, rows):
    failures = []
    states = [r for r in rows if r.get('event') == 'health_state' and
              r.get('frame', {}).get('run_id') == run_id]
    errors = [r for r in rows if r.get('event') == 'failure' and
              r.get('frame', {}).get('kind') == 'health' and
              r.get('frame', {}).get('run_id') == run_id]
    if not errors:
        return ['no actual failing health request']
    first = errors[0]
    following = [r for r in states if r['monotonic'] >= first['monotonic']]
    if not following:
        return ['health revocation not recorded']
    if fault in ('ipc_once_timeout', 'ipc_permanent_timeout'):
        if following[0]['frame']['state'] != 'degraded':
            failures.append('first timeout did not revoke healthy to degraded')
        if following[0]['monotonic'] - first['monotonic'] > 0.5:
            failures.append('timeout health publication delayed')
        if fault == 'ipc_permanent_timeout':
            failed = [r for r in following if r['frame']['state'] == 'failed']
            if len(errors) < 2 or not failed or failed[0]['monotonic'] - first['monotonic'] > 4:
                failures.append('two consecutive timeouts did not fail within four seconds')
        else:
            recovered = [r for r in following if r['frame']['state'] == 'healthy']
            responses = [r for r in rows if r.get('event') == 'response' and
                         r.get('frame', {}).get('run_id') == run_id and
                         r['frame']['seq'] > first['frame']['seq'] and
                         r['monotonic'] > first['monotonic']]
            good = [r for r in responses if all(r['frame'].get('result', {}).get(k)
                                               for k in ('init_evidence', 'probe'))]
            if not recovered or not good or good[0]['monotonic'] > recovered[0]['monotonic']:
                failures.append('healthy recovered without a new valid response')
            if any(r['frame']['state'] == 'failed' for r in following):
                failures.append('single dropped response caused terminal failure')
    elif following[0]['frame']['state'] != 'failed' or following[0]['monotonic'] - first['monotonic'] > 0.5:
        failures.append('terminal IPC error not immediately failed')
    return failures
