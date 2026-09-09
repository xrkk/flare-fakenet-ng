"""ACC-006: revoke a previously healthy run after losing its live handle."""
import json
import uuid

from helpers import StepError, arm_fault_file, configure_fault_service, export_run_incidents


def run_active_probe_loss(base, channel, writer):
    from run_p03_acc import load_and_start, wait_state, probe_during
    writer.add_evidence('active-probe-mode', configure_fault_service(channel, True, 5))
    ready, initial = wait_state(base, lambda s: s.get('state') in ('stopped', 'failed'), timeout=60)
    if not ready or initial.get('state') != 'stopped' or initial.get('run_id'):
        raise StepError('active probe requires clean entry')
    started = load_and_start(base)
    writer.add_evidence('active-probe-start', started)
    healthy, initial = wait_state(base, lambda s: s.get('state') == 'healthy', timeout=30)
    if not healthy:
        raise StepError('active probe did not first become healthy')
    writer.add_evidence('active-probe-healthy', initial)
    run_id = str(uuid.UUID(initial['run_id']))
    def trigger():
        armed = arm_fault_file(channel, 'diverter_stop')
        settled, final = wait_state(base, lambda s: s.get('state') == 'stopped' and not s.get('run_id'), timeout=420)
        return {'armed': armed, 'settled': settled, 'final': final}
    timeline, outcome = probe_during(trigger, base)
    writer.add_evidence('active-probe-full-window', timeline)
    writer.add_evidence('active-probe-result', outcome or {})
    if outcome is None:
        raise StepError('active probe result unavailable; preserve scene')
    raw = channel.powershell(
        "$d='C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs\\" + run_id + "';"
        "@{parent=(Get-Content (Join-Path $d 'ipc-parent.jsonl') -Raw);"
        "child=(Get-Content (Join-Path $d 'ipc-child.jsonl') -Raw);"
        "receipt=(Get-Content (Join-Path $d 'fault-triggered.json') -Raw|ConvertFrom-Json)}|ConvertTo-Json -Depth 5 -Compress", timeout=30)
    writer.add_evidence('active-probe-actual-pipe', raw)
    facts = json.loads(raw['output'])
    rows = [json.loads(line) for line in facts['parent'].splitlines()]
    requests = {(row['frame']['run_id'], row['frame']['seq']): row for row in rows
                if row['event'] == 'request' and row['frame']['kind'] == 'health'}
    broken = []
    for row in rows:
        frame = row.get('frame') or {}
        key = (frame.get('run_id'), frame.get('seq'))
        detail = frame.get('result') or {}
        if row['event'] == 'response' and key in requests and detail.get('probe') is False and detail.get('init_evidence') is True:
            broken.append((requests[key], row))
    failed = [row for row in rows if row['event'] == 'health_state' and
              (row.get('frame') or {}).get('state') == 'failed' and
              (row.get('frame') or {}).get('identity') == initial['health']['identity']]
    bundles = export_run_incidents(channel, run_id, writer.out_dir)
    writer.add_evidence('active-probe-incidents', bundles)
    writer.evidence.extend({key: bundle[key] for key in ('path', 'size', 'sha256')} for bundle in bundles)
    checks = {
        'healthy_before_arm': healthy,
        'actual_consumed_nonce': facts['receipt'] == {'fault': 'diverter_stop', 'nonce': outcome['armed']['nonce']},
        'fresh_response_probe_failed_with_listeners_alive': bool(broken),
        'same_child_failed_within_four_seconds': bool(broken and failed) and
            0 <= failed[0]['monotonic'] - broken[0][0]['monotonic'] <= 4,
        'whole_window_http_alive': bool(timeline) and all(row['ok'] for row in timeline),
        'incident_bytes_complete': bool(bundles) and all(bundle['complete'] for bundle in bundles),
        'protective_recovery_completed': outcome['settled'] and outcome['final'].get('last_run_outcome') == 'failed',
    }
    writer.add_evidence('active-probe-checks', checks)
    return checks
