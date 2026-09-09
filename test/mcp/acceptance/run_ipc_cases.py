"""P03's real private-pipe matrix; called by the ACC-006 entry."""
import json
import time
import uuid

from helpers import StepError, arm_fault_file, configure_fault_service, export_run_incidents
from ipc_evidence import check_ipc_case

IPC_CASES = ('ipc_once_timeout', 'ipc_permanent_timeout', 'ipc_eof',
             'ipc_wrong_run', 'ipc_repeat', 'ipc_reverse')


def run_ipc_matrix(base, channel, writer):
    from run_p03_acc import load_and_start, wait_state, stop_run, probe_during, disarm_fault, status
    checks = {}
    writer.add_evidence('ipc-test-mode', configure_fault_service(channel, True, 5))
    ready, initial = wait_state(base, lambda x: x.get('state') == 'stopped' and not x.get('run_id'), timeout=60)
    if not ready:
        raise StepError('IPC matrix requires stopped entry; preserve scene')
    for fault in IPC_CASES:
        started = load_and_start(base)
        writer.add_evidence(fault + '-start', started)
        healthy, initial = wait_state(base, lambda x: x.get('state') == 'healthy', timeout=30)
        if not healthy:
            raise StepError('IPC case did not reach healthy: ' + fault)
        run_id = str(uuid.UUID(initial['run_id']))
        def action():
            armed = arm_fault_file(channel, fault)
            revoked, snap = wait_state(base, lambda x: x.get('state') != 'healthy', timeout=12)
            recovered = False
            if fault == 'ipc_once_timeout' and revoked:
                recovered, recovery = wait_state(base, lambda x: x.get('state') in ('healthy', 'failed'), timeout=12)
                recovered = recovered and recovery.get('state') == 'healthy' and recovery.get('run_id') == run_id
                if recovered:
                    stop = stop_run(base)
                    writer.add_evidence(fault + '-normal-stop', stop)
                    if stop.get('error') or stop.get('state') != 'stopped':
                        return dict(armed=armed, revoked=revoked, revoked_status=snap,
                                    recovered=recovered, settled=False, final=status(base))
            settled, final = wait_state(base, lambda x: x.get('state') == 'stopped' and not x.get('run_id'), timeout=420)
            return dict(armed=armed, revoked=revoked, revoked_status=snap,
                        recovered=recovered, settled=settled, final=final)
        timeline, result = probe_during(action, base)
        writer.add_evidence(fault + '-full-probe', timeline)
        writer.add_evidence(fault + '-observations', result or {})
        if result is None:
            raise StepError('IPC action failed without result; preserve scene')
        raw = channel.powershell(
            "$ErrorActionPreference='Stop';$dir=Join-Path $env:ProgramData 'FakeNet-NG-MCP\\artifacts\\runs\\" + run_id + "'; "
            "@{parent=(Get-Content (Join-Path $dir 'ipc-parent.jsonl') -Raw); "
            "child=(Get-Content (Join-Path $dir 'ipc-child.jsonl') -Raw); "
            "receipt=(Get-Content (Join-Path $dir 'fault-triggered.json') -Raw | ConvertFrom-Json)}|ConvertTo-Json -Depth 6 -Compress",
            timeout=30)
        writer.add_evidence(fault + '-raw-pipe-evidence', raw)
        evidence = json.loads(raw['output'])
        rows = [json.loads(line) for line in evidence['parent'].splitlines()]
        failures = check_ipc_case(fault, run_id, rows)
        child = [json.loads(line) for line in evidence['child'].splitlines()]
        expected_action = 'drop' if 'timeout' in fault else 'eof' if fault == 'ipc_eof' else 'send'
        if not any(r['event'] == expected_action for r in child):
            failures.append('actual child pipe action missing')
        if evidence['receipt'] != {'fault': fault, 'nonce': result['armed']['nonce']}:
            failures.append('fault receipt mismatch')
        if not result['settled'] or not timeline or not all(x['ok'] for x in timeline):
            failures.append('cleanup or continuous HTTP probe failed')
        if fault == 'ipc_once_timeout':
            if not result['recovered']:
                failures.append('single timeout did not recover same run')
        if fault != 'ipc_once_timeout' or not result['settled']:
            bundles = export_run_incidents(channel, run_id, writer.out_dir)
            writer.add_evidence(fault + '-incidents', bundles)
            writer.evidence.extend({k: bundle[k] for k in ('path', 'size', 'sha256')} for bundle in bundles)
            if any(not bundle['complete'] for bundle in bundles):
                failures.append('incident package incomplete')
            if fault == 'ipc_permanent_timeout' and not any('userdump.dmp' in bundle['verified_members'] for bundle in bundles):
                failures.append('required timeout dump missing')
            if result['final'].get('last_run_outcome') != 'failed':
                failures.append('failed outcome lost')
        writer.add_evidence(fault + '-checks', {'failures': failures})
        checks[fault] = not failures
        if failures:
            return checks
    disarm_fault(channel, base)
    return checks
