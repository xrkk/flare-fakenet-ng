"""ACC019 fixed current-instance two-phase stop and upgrade acceptance."""
import base64
import hashlib
import json
import re
from pathlib import PureWindowsPath
import time
import uuid

from helpers import EXIT_PASS, EXIT_FAIL, EXIT_BLOCKED, StepError
from run_p02_acc import call, status, unique_command, VALID_INI
from run_p03_acc import load_and_start, wait_state


def q(value):
    return "'" + str(value).replace("'", "''") + "'"


def ps(channel, label, script, timeout=60):
    return channel.powershell('# acc019:' + label + '\n$ErrorActionPreference=\'Stop\';' + script, timeout=timeout)


def fact(channel, args, run_id, offset=0):
    root = str(PureWindowsPath(args.programdata_root))
    script = (
        "$root=" + q(root) + ";$svc=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";"
        "$p=if($svc.ProcessId){Get-Process -Id $svc.ProcessId -ErrorAction Stop}else{$null};"
        "$pre=Join-Path $root 'logs\\service-stop-result.json';"
        "$cfg=Join-Path $root 'configs\\service.json';$b=[IO.File]::ReadAllBytes($cfg);"
        "$marker=Join-Path $root 'state\\state.json';"
        "$log=Join-Path $root " + q('artifacts\\runs\\' + run_id + '\\run.log') + ";"
        "$raw=if(Test-Path $log){[IO.File]::ReadAllBytes($log)}else{[byte[]]@()};"
        "if($raw.Length -gt 16777216 -or $raw.Length -lt " + str(offset) + "){throw 'run log changed or oversized'};"
        "$text=if($raw.Length -gt " + str(offset) + "){[Text.Encoding]::UTF8.GetString($raw," + str(offset) + ",$raw.Length-" + str(offset) + ")}else{''};"
        "$children=@(Get-CimInstance Win32_Process | Where-Object {"
        "$_.ExecutablePath -eq " + q(str(PureWindowsPath(args.vm_package_dir) / 'fakenetng-mcp-managed.exe')) +
        " -and $_.CommandLine -match " + q('managed-child[ ]+' + run_id + '(?:[ ]|$)') + "} | Select-Object ProcessId);"
        "@{state=$svc.State;pid=$svc.ProcessId;birth=if($p){$p.StartTime.ToFileTimeUtc().ToString()}else{$null};"
        "prestop=if(Test-Path $pre){Get-Content $pre -Raw|ConvertFrom-Json}else{$null};"
        "marker=if(Test-Path $marker){Get-Content $marker -Raw|ConvertFrom-Json}else{$null};"
        "config_base64=[Convert]::ToBase64String($b);config_sha256=(Get-FileHash $cfg -Algorithm SHA256).Hash.ToLower();"
        "image_sha256=(Get-FileHash " + q(str(PureWindowsPath(args.vm_package_dir) / 'fakenetng-mcp.exe')) + " -Algorithm SHA256).Hash.ToLower();config=([Text.Encoding]::UTF8.GetString($b)|ConvertFrom-Json);children=$children;"
        "log_length=$raw.Length;log=$text}|ConvertTo-Json -Depth 15 -Compress")
    value = json.loads(ps(channel, 'fact', script)['output'])
    if not isinstance(value, dict) or not isinstance(value.get('prestop'), dict):
        raise StepError('current service pre-stop observation unavailable')
    if hashlib.sha256(base64.b64decode(value['config_base64'], validate=True)).hexdigest() != value['config_sha256']:
        raise StepError('service config observation hash differs')
    return value


def launch(channel, args, command, config, nonce):
    argv = ['stop'] if command == 'stop' else ['install', '--listen-ip', config['listen_ip'], '--port', str(config['listen_port'])]
    if command == 'upgrade':
        for host in config['allowed_host_ips']:argv += ['--allowed-host', host]
        for port in config.get('extra_control_ports', []):argv += ['--extra-exclude-port', str(port)]
    directory = str(PureWindowsPath(args.guest_work_root) / ('acc019-' + nonce))
    exe = str(PureWindowsPath(args.vm_package_dir) / 'fakenetng-mcp.exe')
    arguments = ','.join(q(item) for item in argv)
    script = (
        "$ErrorActionPreference='Stop';$dir=" + q(directory) + ";"
        "$p=Start-Process -FilePath " + q(exe) + " -ArgumentList @(" + arguments + ") -PassThru "
        "-RedirectStandardOutput (Join-Path $dir 'stdout.txt') -RedirectStandardError (Join-Path $dir 'stderr.txt');"
        "[void]$p.Handle;$pid0=$p.Id;$birth=$p.StartTime.ToFileTimeUtc().ToString();"
        "$done=$p.WaitForExit(1110000);$exit=if($done){$p.ExitCode}else{$null};"
        "$result=@{nonce=" + q(nonce) + ";argv=@(" + arguments + ");pid=$pid0;birth=$birth;completed=$done;exit_code=$exit;"
        "stdout=[IO.File]::ReadAllText((Join-Path $dir 'stdout.txt'));stderr=[IO.File]::ReadAllText((Join-Path $dir 'stderr.txt'))};"
        "[IO.File]::WriteAllText((Join-Path $dir 'result.new'),($result|ConvertTo-Json -Depth 8 -Compress));"
        "Move-Item -LiteralPath (Join-Path $dir 'result.new') -Destination (Join-Path $dir 'result.json')")
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    channel.preserve_scene = True
    raw = ps(channel, 'launch-' + command,
        "$dir=" + q(directory) + ";if(Test-Path $dir){throw 'owned CLI directory exists'};"
        "New-Item -ItemType Directory -Path $dir|Out-Null;"
        "$p=Start-Process (Join-Path $PSHOME 'powershell.exe') -WindowStyle Hidden -PassThru "
        "-ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand'," + q(encoded) + ");"
        "@{pid=$p.Id;birth=$p.StartTime.ToFileTimeUtc().ToString()}|ConvertTo-Json -Compress")
    process = json.loads(raw['output'])
    if type(process.get('pid')) is not int or process['pid'] <= 0 or not str(process.get('birth', '')).isdigit():
        raise StepError('CLI wrapper process identity unavailable')
    return dict(directory=directory, nonce=nonce, argv=argv, wrapper=process)


def receipt(channel, invocation):
    raw = ps(channel, 'receipt', "$p=" + q(str(PureWindowsPath(invocation['directory']) / 'result.json')) +
             ";if(Test-Path $p){if((Get-Item $p).Length -gt 1048576){throw 'CLI result oversized'};"
             "$r=Get-Content $p -Raw|ConvertFrom-Json;"
             "$w=Get-Process -Id " + str(invocation['wrapper']['pid']) + " -ErrorAction SilentlyContinue;"
             "if($w){[void]$w.Handle;if($w.StartTime.ToFileTimeUtc().ToString() -eq " + q(invocation['wrapper']['birth']) +
             "){if(-not $w.WaitForExit(30000)){throw 'owned CLI wrapper still alive'}}};"
             "$r|Add-Member -NotePropertyName wrapper_exited -NotePropertyValue $true;"
             "$r|ConvertTo-Json -Depth 8 -Compress}else{'null'}")
    value = json.loads(raw['output'])
    if value is not None:
        if (value.get('nonce') != invocation['nonce'] or value.get('argv') != invocation['argv'] or
                type(value.get('pid')) is not int or value['pid'] <= 0 or not str(value.get('birth', '')).isdigit()):
            raise StepError('CLI result identity differs')
        if value.get('completed') is not True or value.get('wrapper_exited') is not True or type(value.get('exit_code')) is not int:
            channel.preserve_scene = True
            raise StepError('owned CLI exit not confirmed; preserve scene')
        channel.preserve_scene = False
    return value


def wait_cli(base, channel, writer, args, invocation, before, run_id, label, stimulate=False):
    timeline, mutations = [], []
    deadline = time.monotonic() + 1140
    result = None
    while time.monotonic() < deadline:
        observed = fact(channel, args, run_id, before['log_length'])
        pre = observed['prestop']
        attributable = (pre.get('pid') == before['pid'] and str(pre.get('creation_time')) == before['birth'] and
                        pre.get('instance_id') == before['prestop'].get('instance_id') and
                        type(pre.get('attempt')) is int and pre['attempt'] > before['prestop']['attempt'])
        try:
            ping = call(base, 'ping', controller=None, timeout=5)
            alive = ping.get('service') == 'fakenetng-mcp'
        except Exception:
            alive = False
        safe_close = (attributable and pre.get('phase') == 'succeeded' and
                      not (observed.get('marker') or {}).get('needs_recovery') and not observed['children'])
        timeline.append(dict(alive=alive, safe_close=safe_close, fact=observed))
        if stimulate and not mutations and attributable and pre.get('phase') == 'draining':
            for name, extra in (('create_config', {'name': 'drain-' + invocation['nonce'][:8] + '.ini', 'content': VALID_INI}),
                                ('edit_config', {'name': 'default.ini', 'content': VALID_INI, 'expected_sha256': 'x'})):
                began = time.monotonic()
                response = call(base, name, dict(extra, command_id=unique_command('d19'), expected_state_version=status(base)['state_version']), timeout=20)
                mutations.append(dict(tool=name, response=response, seconds=time.monotonic()-began))
        result = receipt(channel, invocation)
        if result is not None:break
        time.sleep(.2)
    writer.add_evidence(label + '-timeline', timeline)
    writer.add_evidence(label + '-mutations', mutations)
    writer.add_evidence(label + '-CLI', result or {})
    if result is None:
        channel.preserve_scene = True
        raise StepError('CLI completion unavailable; preserve scene')
    return result, timeline, mutations


def restore_config(channel, args, original, current):
    if original['config_sha256'] == current['config_sha256']:return
    path = str(PureWindowsPath(args.programdata_root) / 'configs/service.json')
    ps(channel, 'restore-config', "$p=" + q(path) + ";"
       "if((Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\").State -ne 'Stopped'){throw 'config restore requires stopped service'};"
       "if((Get-FileHash $p -Algorithm SHA256).Hash.ToLower() -ne " + q(current['config_sha256']) + "){throw 'service config changed; preserve scene'};"
       "[IO.File]::WriteAllBytes($p,[Convert]::FromBase64String(" + q(original['config_base64']) + "));"
       "if((Get-FileHash $p -Algorithm SHA256).Hash.ToLower() -ne " + q(original['config_sha256']) + "){throw 'config restoration hash differs'}")


def restart(channel):
    raw = ps(channel, 'restart', "Start-Service fakenetng-mcp;(Get-Service fakenetng-mcp).Status", timeout=120)
    if raw['output'].strip() != 'Running':raise StepError('service restart not confirmed')


def run(base, channel, writer, args):
    if not getattr(args, 'acc008_capability', None):
        writer.blocker = {'reason': 'current verified ACC008 predecessor required'}
        return EXIT_BLOCKED
    if not getattr(args, 'deploy', False):
        writer.blocker = {'reason': 'ACC019 actual upgrade CLI requires explicit deploy action'}
        return EXIT_BLOCKED
    checks = {}
    for mode in ('stop', 'upgrade'):
        started = load_and_start(base)
        healthy, initial = wait_state(base, lambda row: row.get('state') == 'healthy', timeout=45)
        if not healthy or started.get('error'):raise StepError('ACC019 clean healthy entry required')
        run_id = str(uuid.UUID(initial['run_id']))
        before = fact(channel, args, run_id)
        from fakenet.mcp.config import ServiceConfig
        ServiceConfig.from_dict(before['config'])
        pre0=before['prestop']
        if (before['state']!='Running' or type(before['pid']) is not int or before['pid']<=0 or not str(before['birth']).isdigit() or pre0.get('pid')!=before['pid'] or str(pre0.get('creation_time'))!=before['birth'] or not pre0.get('instance_id') or type(pre0.get('attempt')) is not int):raise StepError('current pre-stop instance not pinned')
        writer.add_evidence(mode + '-before', before)
        raw = ps(channel, 'direct-stop', "sc.exe stop fakenetng-mcp|Out-Null;$rc=$LASTEXITCODE;"
            "$s=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";"
            "$p=Get-Process -Id $s.ProcessId;@{exit_code=$rc;state=$s.State;pid=$p.Id;birth=$p.StartTime.ToFileTimeUtc().ToString()}|ConvertTo-Json -Compress")
        direct = json.loads(raw['output']);writer.add_evidence(mode + '-direct-standard-stop', direct)
        checks[mode + '_direct_STOP_refused'] = (direct.get('exit_code') == 1061 and direct.get('state') == 'Running' and direct.get('pid') == before['pid'] and direct.get('birth') == before['birth'] and status(base).get('state') == 'healthy')
        invocation = launch(channel, args, mode, before['config'], uuid.uuid4().hex)
        writer.add_evidence(mode + '-invocation', invocation)
        result, timeline, mutations = wait_cli(base, channel, writer, args, invocation, before, run_id, mode, stimulate=True)
        final = fact(channel, args, run_id, before['log_length']);writer.add_evidence(mode + '-after', final)
        pre = final['prestop'];text = final['log'];phases = [text.find('STOP_PHASE_END phase=' + name) for name in ('listeners', 'diverter', 'complete')]
        first_closed=next((i for i,item in enumerate(timeline) if not item['alive']),len(timeline))
        checks[mode + '_drain_mutations_rejected'] = (len(mutations) == 2 and all((item['response'].get('error') or {}).get('code') == 'not_allowed_in_state' and item['seconds'] < 2 for item in mutations))
        checks[mode + '_queries_alive_until_safe_shutdown'] = (bool(timeline) and any(item['alive'] for item in timeline) and all(item['alive'] or item['safe_close'] for item in timeline) and not any(item['alive'] for item in timeline[first_closed:]))
        checks[mode + '_current_prestop_succeeded'] = (pre.get('pid') == before['pid'] and str(pre.get('creation_time')) == before['birth'] and pre.get('instance_id') == before['prestop'].get('instance_id') and pre.get('attempt', -1) > before['prestop']['attempt'] and pre.get('phase') == 'succeeded')
        checks[mode + '_stopped_without_responsibility'] = (result['exit_code'] == 0 and final['state'] == 'Stopped' and not final['children'] and (final.get('marker') or {}).get('needs_recovery') is False)
        checks[mode + '_current_ordered_stop_phases'] = all(n >= 0 for n in phases) and phases == sorted(phases) and all(re.search(r'STOP_PHASE_END phase='+name+r'[^\n]*healthy=True',text) for name in ('listeners','diverter','complete'))
        if not checks[mode + '_stopped_without_responsibility']:
            channel.preserve_scene = True
            raise StepError('normal controlled exit did not converge; preserve scene')
        if mode == 'upgrade':
            target = str(PureWindowsPath(invocation['directory']) / 'upgrade-probe.exe')
            copied = ps(channel, 'replace-after-stopped', "$s=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";if($s.State -ne 'Stopped'){throw 'upgrade replacement before stop'};"
                "$exe=" + q(str(PureWindowsPath(args.vm_package_dir) / 'fakenetng-mcp.exe')) + ";"
                "$h=[IO.File]::Open($exe,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$h.Dispose();"
                "Copy-Item -LiteralPath $exe -Destination " + q(target) + ";"
                "@{source=(Get-FileHash $exe -Algorithm SHA256).Hash.ToLower();copy=(Get-FileHash " + q(target) + " -Algorithm SHA256).Hash.ToLower()}|ConvertTo-Json -Compress")
            hashes = json.loads(copied['output']);writer.add_evidence('upgrade-replacement', copied)
            checks['upgrade_files_replaceable_after_stop'] = hashes['source'] == hashes['copy']
            restore_config(channel, args, before, final)
        restart(channel)
        ready, snapshot = wait_state(base, lambda row: row.get('state') == 'stopped' and not row.get('run_id'), timeout=60)
        checks[mode + '_restarted_cleanly'] = ready
    from controlled_exit_failure import audit_failure_case
    checks.update(audit_failure_case(base, channel, writer, args))
    writer.add_evidence('acc019-checks', checks)
    return EXIT_PASS if checks and all(value is True for value in checks.values()) else EXIT_FAIL
