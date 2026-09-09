"""S2: actual initialization failure, not configuration syntax rejection."""
import json
import re
import uuid

from helpers import StepError, arm_fault_file, configure_fault_service, export_run_incidents


def initialization_traceback(log):
    # Frozen Python retains file/function frames but omits source-line text.
    frames = re.findall(r'File "([^"]+)", line \d+, in (\w+)', log.replace('\\', '/'))
    expected = [('fakenet/mcp/managed.py', 'child_main'),
                ('fakenet/fakenet.py', 'start'),
                ('fakenet/mcp/faultinject.py', 'initialize')]
    for offset in range(max(0, len(frames) - len(expected) + 1)):
        if all(path.endswith(wanted_path) and function == wanted_function
               for (path, function), (wanted_path, wanted_function) in
               zip(frames[offset:offset + len(expected)], expected)):
            return ('Traceback (most recent call last)' in log and
                    'RuntimeError: injected managed initialization failure' in log)
    return False


def run_initialization_failure(base, channel, writer):
    from run_p03_acc import call, status, unique_command, wait_state, probe_during
    writer.add_evidence('s2-test-mode', configure_fault_service(channel, True, 5))
    ready, initial = wait_state(base, lambda s: s.get('state') in ('stopped', 'failed'), timeout=60)
    if not ready or initial.get('state') != 'stopped' or initial.get('run_id'):
        raise StepError('S2 requires clean stopped entry; preserve scene')
    loaded = call(base, 'load_config', {'name': 'default.ini',
        'command_id': unique_command('s2-load'), 'expected_state_version': initial['state_version']})
    writer.add_evidence('s2-valid-config-load', loaded)
    if loaded.get('error'):
        raise StepError('S2 valid configuration did not load')
    armed = arm_fault_file(channel, 'initialization_failure')
    writer.add_evidence('s2-armed', armed)
    def start_and_settle():
        started = call(base, 'start', {'command_id': unique_command('s2-start'),
            'expected_state_version': loaded['state_version']}, timeout=420)
        settled, final = wait_state(base, lambda s: s.get('state') in ('stopped', 'failed'), timeout=420)
        return {'started': started, 'settled': settled, 'final': final}
    timeline, result = probe_during(start_and_settle, base)
    writer.add_evidence('s2-entire-initialization-probe', timeline)
    writer.add_evidence('s2-result', result or {})
    if result is None:
        raise StepError('S2 action result unavailable; preserve scene')
    nonce = str(uuid.UUID(armed['nonce']))
    raw = channel.powershell(
        "$ErrorActionPreference='Stop';$root='C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs';"
        "$matches=@(Get-ChildItem $root -Directory | Where-Object {"
        "$p=Join-Path $_.FullName 'fault-triggered.json';"
        "(Test-Path $p) -and ((Get-Content $p -Raw|ConvertFrom-Json).nonce -eq '" + nonce + "')});"
        "if($matches.Count -ne 1){throw 'S2 receipt not unique'};$dir=$matches[0].FullName;"
        "@{run_id=$matches[0].Name;receipt=(Get-Content (Join-Path $dir 'fault-triggered.json') -Raw|ConvertFrom-Json);"
        "log=(Get-Content (Join-Path $dir 'run.log') -Raw);"
        "parent=(Get-Content (Join-Path $dir 'ipc-parent.jsonl') -Raw);"
        "child=(Get-Content (Join-Path $dir 'ipc-child.jsonl') -Raw)}|ConvertTo-Json -Depth 8 -Compress", timeout=30)
    writer.add_evidence('s2-actual-initialization-evidence', raw)
    facts = json.loads(raw['output'])
    run_id = str(uuid.UUID(facts['run_id']))
    parent = [json.loads(line) for line in facts['parent'].splitlines()]
    child = [json.loads(line) for line in facts['child'].splitlines()]
    bundles = export_run_incidents(channel, run_id, writer.out_dir)
    writer.add_evidence('s2-actual-incidents', bundles)
    writer.evidence.extend({key: item[key] for key in ('path', 'size', 'sha256')} for item in bundles)
    return {
        'valid_config_loaded': loaded.get('error') is None,
        'actual_fault_nonce': facts['receipt'] == {'fault': 'initialization_failure', 'nonce': nonce},
        'traceback_inside_fakenet_start': initialization_traceback(facts['log']),
        'actual_child_error_response': any(row.get('event') == 'send' and
            'injected managed initialization failure' in str((row.get('frame') or {}).get('error', '')) for row in child),
        'never_published_healthy': not any(row.get('event') == 'health_state' and
            (row.get('frame') or {}).get('state') == 'healthy' for row in parent),
        'control_link_entire_failure': bool(timeline) and all(row['ok'] for row in timeline),
        'incident_bytes_complete': bool(bundles) and all(item['complete'] for item in bundles),
        'failed_start_fully_recovered': result['settled'] and result['final'].get('state') == 'stopped'
            and not result['final'].get('run_id') and result['final'].get('last_run_outcome') == 'failed',
    }
