"""Observe a new SCM instance without issuing any post-crash mutation."""
import json
import time


def observe_no_replay(base, channel, writer, prefix, old_marker):
    from run_p02_acc import call, status
    samples = []
    deadline = time.monotonic() + 10
    while True:
        samples.append({'monotonic': time.monotonic(), 'status': status(base),
                        'events': call(base, 'get_events', {'limit': 500}, controller=None)})
        if time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    writer.add_evidence(prefix + '-no-mutation-observation', samples)
    raw = channel.powershell(
        "Get-Content 'C:\\ProgramData\\FakeNet-NG-MCP\\state\\state.json' -Raw", timeout=30)
    writer.add_evidence(prefix + '-recovery-marker-after', raw)
    marker = json.loads(raw['output'])
    failures = []
    if not old_marker.get('command_id') or not old_marker.get('needs_recovery'):
        failures.append('original in-flight recovery responsibility absent')
    if marker.get('command_id') != old_marker.get('command_id') or marker.get('run_id') != old_marker.get('run_id') or marker.get('needs_recovery') is not False:
        failures.append('original responsibility not retained and cleared by recovery')
    for sample in samples:
        snapshot = sample['status']
        if snapshot.get('error') or snapshot.get('state') != 'stopped' or snapshot.get('run_id') or snapshot.get('health', {}).get('process_alive'):
            failures.append('FakeNet resumed or recovery state drifted')
            break
        events = sample['events']
        if events.get('error') or not any(event.get('kind') == 'recovery' for event in events.get('events', [])):
            failures.append('new incarnation recovery events missing')
            break
        if any(event.get('command_id') or str(event.get('kind', '')).startswith('command.') for event in events['events']):
            failures.append('command execution observed without a new mutation')
            break
    writer.add_evidence(prefix + '-no-replay-checks', {'failures': failures})
    return not failures
