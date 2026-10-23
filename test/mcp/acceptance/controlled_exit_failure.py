"""Owned baseline perturbation for ACC019's same-live-instance failure leg."""
import base64
import hashlib
import json
from pathlib import PureWindowsPath
import uuid

from helpers import StepError, controlled_service_stop
from run_p02_acc import status
from run_p03_acc import load_and_start, wait_state
from controlled_exit_case import ps, q, fact, launch, wait_cli, restart


def replace_baseline(channel, path, previous, raw):
    encoded = base64.b64encode(raw).decode('ascii')
    wanted = hashlib.sha256(raw).hexdigest()
    result = ps(channel, 'baseline-write', "$p=" + q(path) + ";"
        "if((Get-FileHash $p -Algorithm SHA256).Hash.ToLower() -ne " + q(previous) + "){throw 'baseline changed; preserve scene'};"
        "[IO.File]::WriteAllBytes($p,[Convert]::FromBase64String(" + q(encoded) + "));"
        "$sha=(Get-FileHash $p -Algorithm SHA256).Hash.ToLower();"
        "if($sha -ne " + q(wanted) + "){throw 'baseline write not confirmed'};"
        "@{sha256=$sha}|ConvertTo-Json -Compress")
    if json.loads(result['output']).get('sha256') != wanted:
        raise StepError('baseline write not observed')


def audit_failure_case(base, channel, writer, args):
    load_and_start(base)
    healthy, snapshot = wait_state(base, lambda row: row.get('state') == 'healthy', timeout=45)
    if not healthy:raise StepError('audit failure leg requires healthy entry')
    run_id = str(uuid.UUID(snapshot['run_id']))
    before = fact(channel, args, run_id)
    writer.add_evidence('audit-failure-before', before)
    path = str(PureWindowsPath(args.programdata_root) / 'baselines' / (run_id + '.json'))
    raw = ps(channel, 'baseline-read', "$p=" + q(path) + ";"
        "if((Get-Item $p).Length -gt 8388608){throw 'baseline oversized'};"
        "$b=[IO.File]::ReadAllBytes($p);@{base64=[Convert]::ToBase64String($b);"
        "sha256=(Get-FileHash $p -Algorithm SHA256).Hash.ToLower()}|ConvertTo-Json -Compress")
    backup = json.loads(raw['output']);body = base64.b64decode(backup['base64'], validate=True)
    if hashlib.sha256(body).hexdigest() != backup['sha256']:raise StepError('baseline backup hash differs')
    baseline = json.loads(body)
    if baseline.get('run_id') != run_id or not isinstance(baseline.get('sections'), dict):raise StepError('baseline is not current run')
    writer.add_evidence('audit-failure-original-baseline', backup)
    baseline['sections']['services'] = str(baseline['sections']['services']) + '\nACC019-INJECTED-' + uuid.uuid4().hex
    injected = json.dumps(baseline, ensure_ascii=False).encode('utf-8')
    digest = hashlib.sha256(injected).hexdigest();changed = False;checks = {}
    try:
        replace_baseline(channel, path, backup['sha256'], injected);changed = True
        for mode in ('stop', 'upgrade'):
            invocation = launch(channel, args, mode, before['config'], uuid.uuid4().hex)
            writer.add_evidence('failed-' + mode + '-invocation', invocation)
            result, timeline, mutations = wait_cli(base, channel, writer, args, invocation, before, run_id, 'failed-' + mode)
            after = fact(channel, args, run_id, before['log_length']);current = status(base)
            writer.add_evidence('failed-' + mode + '-observed', {'service': after, 'status': current})
            pre = after['prestop']
            checks[mode + '_audit_failure_same_instance_online'] = (result['exit_code'] != 0 and after['state'] == 'Running' and after['pid'] == before['pid'] and after['birth'] == before['birth'] and pre.get('instance_id') == before['prestop'].get('instance_id') and pre.get('phase') == 'failed' and pre.get('attempt', -1) > before['prestop']['attempt'] and current.get('state') == 'failed' and all(item['alive'] for item in timeline))
            checks[mode + '_audit_failure_reason_observable'] = ('environment restoration audit failed' in str(current.get('failure_reason')) and 'environment restoration audit failed' in str(pre.get('reason')))
            checks[mode + '_audit_failure_no_replacement'] = after['config_sha256'] == before['config_sha256'] and after['image_sha256'] == before['image_sha256']
            direct = json.loads(ps(channel, 'failed-direct-stop',
                "sc.exe stop fakenetng-mcp|Out-Null;$rc=$LASTEXITCODE;"
                "$s=Get-CimInstance Win32_Service -Filter \"Name='fakenetng-mcp'\";"
                "$p=Get-Process -Id $s.ProcessId;@{exit_code=$rc;state=$s.State;pid=$p.Id;birth=$p.StartTime.ToFileTimeUtc().ToString()}|ConvertTo-Json -Compress")['output'])
            writer.add_evidence('failed-' + mode + '-standard-stop', direct)
            checks[mode + '_failed_standard_STOP_refused'] = (direct.get('exit_code') == 1061 and direct.get('state') == 'Running' and direct.get('pid') == before['pid'] and direct.get('birth') == before['birth'])

    finally:
        if changed:
            if getattr(channel,'preserve_scene',False):raise StepError('owned CLI unresolved; injected baseline retained for recovery')
            try:
                replace_baseline(channel, path, digest, body)
                writer.add_evidence('audit-failure-baseline-restored', {'path': path, 'sha256': backup['sha256']})
                controlled_service_stop(channel)
                restart(channel)
                ready, restored = wait_state(base, lambda row: row.get('state') == 'stopped' and not row.get('run_id'), timeout=60)
                writer.add_evidence('audit-failure-recovery', restored or {})
                if not ready:raise StepError('audit failure recovery not observed')
            except Exception:
                channel.preserve_scene = True
                raise
    return checks
