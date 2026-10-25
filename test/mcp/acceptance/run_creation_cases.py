"""Native ACC-007 creation windows; no reset or forced recovery on failure."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import time

from fakenet.mcp.creation_evidence import CREATION_STAGES
from helpers import StepError, arm_fault_file, configure_fault_service
from process_recovery import (creation_expected, creation_failures, crash_failures,
                              require_mutation, observe_service, confirm_recovery, script)


def crash_window(channel, receipt, command_id, stage, armed, service):
    expected = creation_expected(receipt, stage, armed, command_id, service)
    Path(__file__).with_name('crash_creation_window.ps1')
    actual, raw = script(channel, 'crash_creation_window.ps1', expected)
    return actual, raw, expected


def run_creation_matrix(base, channel, writer):
    from run_p03_acc import call, unique_command, wait_state
    writer.add_evidence('creation-test-mode', configure_fault_service(channel, True, 5))
    checks = {}
    try:
        for stage in CREATION_STAGES:
            ready, initial = wait_state(base, lambda x: x.get('state') in ('stopped', 'failed'), timeout=60)
            if not ready or initial.get('state') != 'stopped' or initial.get('run_id'):
                raise StepError('creation window requires stopped entry; preserve scene')
            load_command = unique_command('creation-load')
            loaded = call(base, 'load_config', {'name': 'default.ini',
                'command_id': load_command, 'expected_state_version': initial['state_version']})
            writer.add_evidence(stage + '-load', loaded)
            require_mutation(loaded, load_command, initial['state_version'])
            old_events = call(base, 'get_events', {'limit': 500}, controller=None)
            writer.add_evidence(stage + '-events-before', old_events)
            if old_events.get('error') or not old_events.get('events'):
                raise StepError('creation original incarnation events missing')
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
                    # The completion decision is a local observation, distinct from a
                    # terminal start response. Preserve it across independent replay.
                    done = (channel.creation_future_done(pending, stage, command_id)
                            if hasattr(channel, 'creation_future_done') else pending.done())
                    if done:
                        writer.add_evidence(stage + '-start-response', pending.result())
                        raise StepError('creation start ended without a matching consumed receipt; no crash issued')
                    time.sleep(0.25)
                if receipt is None:
                    writer.add_evidence(stage + '-start-response', pending.result())
                    raise StepError('creation window receipt absent; no crash issued')
                service = observe_service(base, channel, writer, stage + '-pinned-before')
                actual, crash, expected = crash_window(channel, receipt, command_id, stage, armed, service)
                writer.add_evidence(stage + '-actual-crash', crash)
                writer.add_evidence(stage + '-start-response', pending.result())
            failures = crash_failures(actual, expected)
            run_id = expected['run_id']
            raw = channel.powershell(
                "$ErrorActionPreference='Stop';$dir='C:\\ProgramData\\FakeNet-NG-MCP\\artifacts\\runs\\" + run_id + "';"
                "$ipc=Join-Path $dir 'ipc-parent.jsonl';"
                "@{creation=(Get-Content (Join-Path $dir 'creation.jsonl') -Raw);"
                "ipc=$(if(Test-Path $ipc){Get-Content $ipc -Raw}else{''});"
                "pcaps=@(Get-ChildItem $dir -Filter '*.pcap' | Select-Object Name,Length)}"
                "|ConvertTo-Json -Depth 8 -Compress", timeout=30)
            writer.add_evidence(stage + '-post-crash-raw', raw)
            failures.extend(creation_failures(json.loads(raw['output']), receipt, stage))
            if not failures:
                failures.extend(confirm_recovery(base, channel, writer, stage, service, old_events, actual['marker']))
            writer.add_evidence(stage + '-checks', {'failures': failures})
            checks[stage] = not failures
            if failures:
                channel.preserve_scene = True
                return checks
        return checks
    except Exception:
        channel.preserve_scene = True
        raise
