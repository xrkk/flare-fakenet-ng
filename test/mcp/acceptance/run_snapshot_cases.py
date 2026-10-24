"""ACC008 fixed snapshot conditions, exact owned bytes and real startup audits."""
import base64
import hashlib
import json
from pathlib import PureWindowsPath
from helpers import StepError, EXIT_PASS, EXIT_FAIL, EXIT_BLOCKED, controlled_service_stop, kill_owned_process
from snapshot_evidence import control, body, read_files, active_identity, startup_failure, scan_matches
from process_recovery import require_mutation


def run_snapshot_cases(base, channel, writer):
    from run_p03_acc import call, status, wait_state, unique_command, CONTROLLER_A
    checks = {}
    owned = set()
    owned_marker_hashes = set()
    blocked = []
    baseline_hashes = {}
    original_read = read_files

    def observe_files(label, allow_missing=False):
        value = original_read(channel, writer, label)
        observed = {row['path']: row['sha256'] for row in value['baselines']}
        if any((path in observed and observed[path] != sha) or (not allow_missing and path not in observed) for path, sha in baseline_hashes.items()):
            raise StepError('recorded baseline bytes disappeared or changed')
        return value

    def mutation(tool, prefix):
        before = status(base)
        command = unique_command(prefix)
        request = {'command_id': command, 'expected_state_version': before['state_version']}
        if tool == 'load_config': request['name'] = 'default.ini'
        result = call(base, tool, request, timeout=420)
        writer.add_evidence(prefix, result)
        require_mutation(result, command, before['state_version'])
        return result, command

    def begin(prefix):
        current_config = call(base, 'read_config', {'name': 'default.ini'}, controller=None)
        writer.add_evidence(prefix + '-config-bytes', current_config)
        if (current_config.get('error') or current_config.get('name') != 'default.ini' or
                not isinstance(current_config.get('content'), str) or
                hashlib.sha256(current_config['content'].encode()).hexdigest() != current_config.get('sha256')):
            raise StepError('snapshot default configuration bytes not confirmed')
        loaded, _ = mutation('load_config', prefix + '-load')
        if loaded.get('config_identity') != {'name': 'default.ini', 'sha256': current_config['sha256'], **({'builtin': loaded['config_identity']['builtin']} if 'builtin' in (loaded.get('config_identity') or {}) else {})}:
            raise StepError('snapshot loaded config differs from requested bytes')
        started, command = mutation('start', prefix + '-start')
        ready, snap = wait_state(base, lambda s: s.get('state') in ('healthy', 'failed', 'stopped'), timeout=45)
        if not ready or not loaded.get('config_identity') or started.get('config_identity') != loaded['config_identity']:
            raise StepError('snapshot current config/start not confirmed')
        files = observe_files(prefix + '-active-files')
        marker = active_identity(channel, files, started, snap, CONTROLLER_A, command)
        owned.add(marker['run_id'])
        owned_marker_hashes.add(files['marker']['sha256'])
        baseline_hashes[marker['baseline_path']] = next(row['sha256'] for row in files['baselines'] if row['path'] == marker['baseline_path'])
        return files, marker

    def stop_clean(prefix, marker):
        stopped, command = mutation('stop', prefix + '-stop')
        if stopped.get('state') != 'stopped' or stopped.get('run_id'):
            raise StepError('snapshot clean stop not confirmed')
        files = observe_files(prefix + '-stopped-files')
        actual = json.loads(body(files['marker']).decode('utf-8-sig'))
        expected = dict(marker, command_id=command, state_version=stopped['state_version'], needs_recovery=False)
        if actual != expected:
            raise StepError('snapshot clean stop changed responsibility/config or failed to clear')
        owned_marker_hashes.add(files['marker']['sha256'])
        return files

    def inject(prefix, before, raw, running_failed=False):
        if not before.get('marker') or before['marker']['sha256'] not in owned_marker_hashes:
            raise StepError('snapshot injection preimage is not this attempt own marker')
        request = dict(before_sha256=before['marker']['sha256'] if before.get('marker') else None,
                       body=base64.b64encode(raw).decode())
        if running_failed:
            snap = status(base)
            if snap.get('state') != 'failed' or (snap.get('health') or {}).get('process_alive'):
                raise StepError('snapshot failed service restore scope unconfirmed')
            request['service'] = before['service']
        result, record = control(channel, 'restore-failed' if running_failed else 'replace', **request)
        writer.add_evidence(prefix, record)
        if body(result['after']) != raw or result.get('before') != before['marker']:
            raise StepError('snapshot injection/restore bytes differ')
        owned_marker_hashes.add(result['after']['sha256'])
        return result['after']

    def old_incarnation(prefix):
        before = observe_files(prefix + '-instance-before')
        events = call(base, 'get_events', {'limit': 500}, controller=None)
        writer.add_evidence(prefix + '-events-before', events)
        if before['service'].get('state') != 'Running' or before.get('endpoint_owned') is not True:
            raise StepError('snapshot old instance not confirmed')
        return before, events

    def launch(prefix, before, old_events, expected_state, reason=None, no_residue=False):
        writer.add_evidence(prefix + '-service-start', channel.powershell(
            "$ErrorActionPreference='Stop';$s=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";"
            "if($s.State -ne 'Stopped' -or $s.ProcessId){throw 'SCM must be stopped before one start'};"
            "Start-Service fakenetng-mcp; 'START_REQUESTED'", timeout=60))
        ready, snap = wait_state(base, lambda s: s.get('state') in ('stopped', 'failed'), timeout=420)
        writer.add_evidence(prefix + '-status', snap or {})
        first = observe_files(prefix + '-instance-first', allow_missing=no_residue)
        events = call(base, 'get_events', {'limit': 500}, controller=None)
        writer.add_evidence(prefix + '-recovery-events', events)
        last = observe_files(prefix + '-instance-last', allow_missing=no_residue)
        if not ready or snap.get('state') != expected_state or first['service'] != last['service']:
            raise StepError('snapshot recovery state/instance changed')
        startup_failure(before, last, old_events, events, expected_state, reason)
        return last, snap

    try:
        entry = observe_files('acc008-entry-files')
        foreign = {row['path']: row['sha256'] for row in entry['baselines']}
        baseline_hashes.update(foreign)
        files, marker = begin('acc008-normal')
        stop_clean('acc008-normal', marker)
        checks['exact_live_snapshot_and_clean_stop'] = True

        # Reproduce startup disk conditions with the actual pending bytes from
        # this run after a controlled host stop. ACC007 owns abrupt Job collapse.
        files, marker = begin('acc008-corrupt')
        pending_bytes = body(files['marker'])
        stop_clean('acc008-corrupt', marker)
        before, events = old_incarnation('acc008-corrupt')
        writer.add_evidence('acc008-corrupt-service-stop', controlled_service_stop(channel))
        stopped_files = observe_files('acc008-corrupt-injection-preimage')
        injected = inject('acc008-corrupt-injected', stopped_files, b'NOT JSON {{')
        failed, snap = launch('acc008-corrupt', before, events, 'failed', 'corrupt recovery snapshot')
        if failed['marker'] != injected:
            raise StepError('corrupt snapshot was changed without known ownership')
        checks['corrupt_snapshot_fails_recovery'] = True
        mutation('load_config', 'acc008-corrupt-valid-config')
        request = {'command_id': unique_command('acc008-corrupt-refusal'), 'expected_state_version': status(base)['state_version']}
        refused = call(base, 'start', request, timeout=90)
        writer.add_evidence('acc008-corrupt-start-refused', refused)
        if ('unresolved recovery responsibility' not in json.dumps(refused) or
                status(base).get('state') != 'failed' or
                observe_files('acc008-corrupt-after-refusal')['marker'] != injected):
            raise StepError('start refusal not attributable to corrupt recovery snapshot')
        checks['start_forbidden_on_corrupt'] = True
        restore = observe_files('acc008-corrupt-restore-preimage')
        inject('acc008-valid-responsibility-restored', restore, pending_bytes, running_failed=True)
        before, events = old_incarnation('acc008-restored')
        writer.add_evidence('acc008-restored-service-stop', controlled_service_stop(channel))
        launch('acc008-restored', before, events, 'stopped')

        files, marker = begin('acc008-residue')
        pending_bytes = body(files['marker'])
        stop_clean('acc008-residue', marker)
        before, events = old_incarnation('acc008-residue')
        writer.add_evidence('acc008-residue-service-stop', controlled_service_stop(channel))
        stopped_files = observe_files('acc008-residue-injection-preimage')
        inject('acc008-pending-responsibility-injected', stopped_files, pending_bytes)
        listener_body = "$l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,47889);$l.Start();try{[Threading.Thread]::Sleep(600000)}finally{$l.Stop()}"
        encoded = base64.b64encode(listener_body.encode('utf-16-le')).decode()
        listener_raw = channel.powershell(
            "$ErrorActionPreference='Stop';if(Get-NetTCPConnection -LocalPort 47889 -State Listen -ErrorAction SilentlyContinue){throw 'port preoccupied; no listener created'};"
            "$s=New-Object Diagnostics.ProcessStartInfo;$s.FileName=Join-Path $PSHOME 'powershell.exe';"
            "$s.Arguments='-NoProfile -NonInteractive -EncodedCommand " + encoded + "';$s.UseShellExecute=$false;$s.CreateNoWindow=$true;"
            "$p=[Diagnostics.Process]::Start($s);[void]$p.Handle;@{pid=$p.Id;created=$p.StartTime.ToFileTimeUtc()}|ConvertTo-Json -Compress", timeout=30)
        writer.add_evidence('acc008-owned-listener', listener_raw)
        listener = json.loads(listener_raw['output'])
        try:
            writer.add_evidence('acc008-owned-listener-ready', channel.powershell(
                "$ErrorActionPreference='Stop';$deadline=[DateTime]::UtcNow.AddSeconds(15);do{$p=Get-Process -Id " + str(int(listener['pid'])) + ";"
                "if($p.StartTime.ToFileTimeUtc() -ne " + str(int(listener['created'])) + "){throw 'listener birth changed'};"
                "$ready=@(Get-NetTCPConnection -LocalPort 47889 -State Listen -ErrorAction SilentlyContinue | Where-Object OwningProcess -eq $p.Id).Count -gt 0;"
                "if($ready){'OWNED_READY';return};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $deadline);throw 'listener not ready'", timeout=30))
            launch('acc008-residue', before, events, 'failed', 'environment restoration audit failed')
            checks['residue_inconsistency_fails'] = True
        finally:
            writer.add_evidence('acc008-owned-listener-stop', kill_owned_process(channel, listener['pid'], listener['created'], 'ACC008 own listener'))
        before, events = old_incarnation('acc008-residue-recovered')
        writer.add_evidence('acc008-residue-recovered-stop', controlled_service_stop(channel))
        launch('acc008-residue-recovered', before, events, 'stopped')

        mutation('load_config', 'acc008-write-valid-config')
        acl, raw = control(channel, 'acl-read');writer.add_evidence('acc008-original-acl', raw)
        changed, raw = control(channel, 'acl-deny', before=acl['sddl']);writer.add_evidence('acc008-owned-acl-change', raw)
        if changed.get('available') is False:
            if changed.get('before') != acl['sddl']:
                raise StepError('existing ACL cannot be identified')
            blocked.append('write-failure slice unavailable: existing SYSTEM deny retained')
            writer.add_evidence('acc008-write-slice-blocked', {'reason': blocked[-1]})
        else:
            try:
                pre = observe_files('acc008-write-preimage')
                request = {'command_id': unique_command('acc008-write-start'), 'expected_state_version': status(base)['state_version']}
                rejected = call(base, 'start', request, timeout=90)
                writer.add_evidence('acc008-write-start-refused', rejected)
                fresh = status(base)
                writer.add_evidence('acc008-write-start-fresh-status', fresh)
                post = observe_files('acc008-write-postimage')
                same_version = (rejected.get('state_version') == fresh.get('state_version') and
                                rejected.get('command_id') == request['command_id'] and
                                rejected.get('changed') is False and fresh.get('run_id') is None)
                if ('snapshot write failed' not in json.dumps(fresh.get('failure_reason')) or
                        rejected.get('state') != 'failed' or not same_version or
                        post['marker'] != pre['marker'] or (fresh.get('health') or {}).get('process_alive')):
                    raise StepError('write failure did not prove snapshot write-layer refusal/no takeover')
                checks['write_failure_refuses_start'] = True
            finally:
                restored, raw = control(channel, 'acl-restore', before=acl['sddl'], after=changed['after'])
                writer.add_evidence('acc008-original-acl-restored', raw)
                if restored.get('sddl') != acl['sddl']: raise StepError('original ACL restoration unknown')
            before, events = old_incarnation('acc008-after-write')
            writer.add_evidence('acc008-after-write-stop', controlled_service_stop(channel))
            launch('acc008-after-write', before, events, 'stopped')
        current = observe_files('acc008-no-residue-candidates')
        for path, sha in foreign.items():
            if not any(row['path'] == path and row['sha256'] == sha for row in current['baselines']):
                raise StepError('preexisting baseline changed')
        unknown = [r for r in current['baselines'] if PureWindowsPath(r['path']).stem not in owned]
        if foreign or unknown:
            blocked.append('missing-snapshot/no-residue slice requires no foreign baseline; existing evidence retained')
            writer.add_evidence('acc008-missing-slice-blocked', {'reason': blocked[-1], 'foreign': unknown})
        else:
            before, events = old_incarnation('acc008-missing')
            writer.add_evidence('acc008-missing-service-stop', controlled_service_stop(channel))
            from helpers import preserve_owned_state
            preserve_owned_state(channel, writer, owned)
            final, snap = launch('acc008-missing', before, events, 'stopped', no_residue=True)
            if final['marker'] is not None or final['baselines'] or snap.get('run_id'):
                raise StepError('missing snapshot/no residue condition not actually reached')
            checks['missing_without_residue_stopped'] = True
        scan, raw = control(channel, 'scan');writer.add_evidence('acc008-framework-scan', raw)
        checks['no_db_engine_modules'] = scan_matches(channel, scan)
        writer.add_evidence('acc008-checks', dict(checks, blocked=blocked))
        return EXIT_FAIL if not all(checks.values()) else EXIT_BLOCKED if blocked else EXIT_PASS
    except Exception:
        channel.preserve_scene = True
        raise
