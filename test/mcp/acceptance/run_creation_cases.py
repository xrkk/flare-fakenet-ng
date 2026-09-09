"""Native ACC-007 creation windows; no reset or forced recovery on failure."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import time
import uuid

from fakenet.mcp.creation_evidence import CREATION_STAGES
from helpers import StepError, arm_fault_file, configure_fault_service


def crash_window(channel, receipt, command_id):
    observation = receipt['observation']
    expected = dict(run_id=str(uuid.UUID(observation['run_id'])),
                    nonce=str(uuid.UUID(receipt['nonce'])), fault=receipt['fault'],
                    command_id=command_id, supervisor=observation['supervisor'])
    if expected['fault'] != 'create_' + observation['stage'] or observation['stage'] not in CREATION_STAGES:
        raise StepError('creation stage identity mismatch')
    if int(expected['supervisor']['pid']) <= 0 or not str(expected['supervisor']['creation_time']).isdecimal():
        raise StepError('invalid supervisor identity')
    encoded = base64.b64encode(json.dumps(expected).encode()).decode('ascii')
    script = Path(__file__).with_name('crash_creation_window.ps1').read_text().replace('__EXPECTED__', encoded)
    return channel.powershell(script, timeout=60)


def run_creation_matrix(base, channel, writer):
    from run_p03_acc import call, status, unique_command, wait_state
    writer.add_evidence('creation-test-mode', configure_fault_service(channel, True, 5))
    checks = {}
    for stage in CREATION_STAGES:
        initial = status(base)
        if initial.get('state') != 'stopped' or initial.get('run_id'):
            raise StepError('creation window requires stopped entry; preserve scene')
        loaded = call(base, 'load_config', {'name': 'default.ini',
            'command_id': unique_command('creation-load'), 'expected_state_version': initial['state_version']})
        writer.add_evidence(stage + '-load', loaded)
        if loaded.get('error'):
            raise StepError('creation config rejected')
        armed = arm_fault_file(channel, 'create_' + stage)
        writer.add_evidence(stage + '-armed', armed)
        command_id = unique_command('creation-start')
        request = {'command_id': command_id, 'expected_state_version': loaded['state_version']}
        writer.add_evidence(stage + '-start-request', request)
        def start():
            try:
                return {'result': call(base, 'start', request, timeout=90)}
            except Exception as exc:
                return {'transport_error': repr(exc)}
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(start)
            deadline = time.monotonic() + 65
            receipt = None
            while time.monotonic() < deadline:
                raw = channel.powershell(
                    "$ErrorActionPreference='Stop';$root='C:\\ProgramData\\FakeNet-NG-MCP';"
                    "$state=Join-Path $root 'state\\state.json'; if(-not(Test-Path $state)){'null';return};"
                    "$m=Get-Content $state -Raw|ConvertFrom-Json;"
                    "$p=Join-Path $root ('artifacts\\runs\\'+$m.run_id+'\\creation-fault-triggered.json');"
                    "if(Test-Path $p){Get-Content $p -Raw}else{'null'}", timeout=15)
                observed = json.loads(raw['output'])
                if observed and observed.get('nonce') == armed['nonce']:
                    receipt = observed
                    writer.add_evidence(stage + '-actual-receipt', raw)
                    break
                time.sleep(0.25)
            if receipt is None:
                writer.add_evidence(stage + '-start-response', pending.result())
                raise StepError('creation window receipt absent; no crash issued')
            crash = crash_window(channel, receipt, command_id)
            writer.add_evidence(stage + '-actual-crash', crash)
            writer.add_evidence(stage + '-start-response', pending.result())
        actual = json.loads(crash['output'])
        run_id = str(uuid.UUID(receipt['observation']['run_id']))
        settled, final = wait_state(base, lambda x: x.get('state') in ('stopped', 'failed'), timeout=420)
        writer.add_evidence(stage + '-recovered-status', final or {})
        raw = channel.powershell(
            "$ErrorActionPreference='Stop';$dir='C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs\\" + run_id + "';"
            "$ipc=Join-Path $dir 'ipc-parent.jsonl';"
            "@{creation=(Get-Content (Join-Path $dir 'creation.jsonl') -Raw);"
            "ipc=$(if(Test-Path $ipc){Get-Content $ipc -Raw}else{''});"
            "pcaps=@(Get-ChildItem $dir -Filter '*.pcap' | Select-Object Name,Length);"
            "service=(Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\" | Select-Object ProcessId,State)}"
            "|ConvertTo-Json -Depth 8 -Compress", timeout=30)
        writer.add_evidence(stage + '-post-crash-raw', raw)
        facts = json.loads(raw['output'])
        rows = [json.loads(line) for line in facts['creation'].splitlines()]
        pipe = [json.loads(line) for line in facts['ipc'].splitlines()]
        failures = []
        if not actual['supervisor_exited'] or actual['remaining_pids'] or actual['escaped'] or not actual['canary_survived']:
            failures.append('crash containment or unrelated canary failed')
        if [r['stage'] for r in rows] != list(CREATION_STAGES[:CREATION_STAGES.index(stage) + 1]):
            failures.append('actual creation stages differ from selected window')
        if any(r['run_id'] != run_id or r['supervisor'] != receipt['observation']['supervisor'] for r in rows):
            failures.append('creation identity drift')
        if any((r.get('frame') or {}).get('kind') == 'start' for r in pipe) or facts['pcaps']:
            failures.append('takeover before selected creation window')
        if not settled or final.get('state') != 'stopped' or final.get('run_id'):
            failures.append('recovery did not finish stopped')
        if facts['service']['State'] != 'Running' or facts['service']['ProcessId'] == actual['supervisor']['pid']:
            failures.append('new SCM instance missing')
        writer.add_evidence(stage + '-checks', {'failures': failures})
        checks[stage] = not failures
        if failures:
            return checks
    return checks
