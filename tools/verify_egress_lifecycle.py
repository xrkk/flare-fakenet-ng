#!/usr/bin/env python3
"""Operator acceptance helper; no implicit FakeNet start/stop or network changes.

Running verification remains the single MCP call. This helper records benign
deployment calibration and before/after connectivity, or evaluates their files.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fakenet.mcp import egress_contract, egress_lifecycle, host_probe, running_observation
from fakenet.mcp.host_stdio import HostFacade


CONNECT_TEMPLATE = r'''
$ErrorActionPreference='Stop'
$client=$null;$ar=$null
$process=Get-Process -Id $PID
$out=[ordered]@{schema='fakenetng.lifecycle-connectivity.v1';connected=$false;peer=$null;started_at=[DateTime]::UtcNow.ToString('o');ended_at=$null;error=$null;identity=[ordered]@{vm_uuid=[string](Get-CimInstance Win32_ComputerSystemProduct).UUID;boot_id=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');account=[Security.Principal.WindowsIdentity]::GetCurrent().Name;sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;session=$process.SessionId}}
try {
 $address=[Net.IPAddress]::Parse('__ADDRESS__');$client=[Net.Sockets.TcpClient]::new($address.AddressFamily)
 $ar=$client.BeginConnect($address,__PORT__,$null,$null)
 if(-not $ar.AsyncWaitHandle.WaitOne(3000)){throw 'connect timeout'}
 $client.EndConnect($ar);$peer=$client.Client.RemoteEndPoint
 $out.connected=$true;$out.peer=[ordered]@{address=[string]$peer.Address;port=[int]$peer.Port}
} catch { $out.error=[string]$_ }
finally {if($ar){try{$ar.AsyncWaitHandle.Dispose()}catch{}};if($client){$client.Close()};$out.ended_at=[DateTime]::UtcNow.ToString('o')}
[Console]::Out.WriteLine('MALTRACE_JSON:'+($out|ConvertTo-Json -Depth 8 -Compress))
'''


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def save(path, value):
    raw = json.dumps(value, ensure_ascii=False, indent=2).encode()
    with path.open('xb') as stream:
        stream.write(raw)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}


def load(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('invalid evidence file')
    return json.loads(path.read_text())


def stopped(facade):
    value = facade._fakenet().get_status(timeout=10)
    if value.get('state') != 'stopped' or value.get('run_id') is not None:
        raise ValueError('engine must already be stopped; no implicit stop')
    return value


def record(facade, phase):
    auth = facade._authorization('lifecycle_connectivity')
    endpoint = facade.config.get('connectivity_endpoint')
    if not isinstance(endpoint, dict) or endpoint not in auth['scope'].get('connectivity_endpoints', []):
        raise ValueError('explicitly authorized public endpoint missing')
    address = str(ipaddress.ip_address(endpoint.get('address')))
    port = endpoint.get('port')
    if not ipaddress.ip_address(address).is_global or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('public endpoint invalid')
    if auth['scope'].get('lifecycle_script_sha256') != hashlib.sha256(CONNECT_TEMPLATE.encode()).hexdigest():
        raise ValueError('connectivity template not authorized')
    directory = facade.output_root / 'lifecycle' / str(uuid.uuid4())
    directory.mkdir(parents=True, exist_ok=False)
    pre = stopped(facade)
    host = facade._host_snapshot(time.monotonic() + 10)
    facade._authorization('lifecycle_connectivity')
    script = CONNECT_TEMPLATE.replace('__ADDRESS__', address).replace('__PORT__', str(port))
    result, raw = facade._windows().probe(script, timeout=8)
    post = stopped(facade)
    if any(pre.get(k) != post.get(k) for k in ('state_version', 'controller', 'run_id')):
        raise ValueError('stopped lifecycle changed during connectivity check')
    references = [save(directory/'status-before.json', pre), save(directory/'status-after.json', post),
                  save(directory/'host.json', host), save(directory/'connectivity.json', {'result':result,'raw':raw})]
    identity = result.get('identity') or {}
    if not all(identity.get(k) is not None for k in ('vm_uuid','boot_id','account','sid','session')):
        raise ValueError('connectivity identity incomplete')
    value = {'phase':phase,'vm_epoch':sha({k:identity[k] for k in ('vm_uuid','boot_id')}),
             'execution_context_identity':sha({k:identity[k] for k in ('account','sid','session')}),
             'network_identity':sha(running_observation.topology(host)), 'endpoint':endpoint,
             'engine_state':'stopped','run_id':None,'connected':result.get('connected'),
             'peer':result.get('peer'),'started_at':result.get('started_at'),'ended_at':result.get('ended_at'),
             'second_blocker_used':False,'evidence_refs':references,'authorized':False}
    return save(directory/'phase.json', value)


def calibrate(facade):
    facade._authorization('visibility_calibration')
    capture_auth = facade._authorization('passive_observe')
    pre = stopped(facade)
    host = facade._host_snapshot(time.monotonic()+10)
    directory = facade.output_root/'calibration'/str(uuid.uuid4())
    directory.mkdir(parents=True,exist_ok=False)
    nonce = secrets.token_hex(16)
    rows = [r for r in host_probe.matrix_steps(50001,50002,nonce) if r['id'] in ('ipv4_udp_random','ipv6_udp_random')]
    payload = host_probe.probe_payload(nonce,rows,positive_enabled=False,calibration_mode=True)
    capture = running_observation.PassiveCapture(directory,host,seconds=15,
        **running_observation.capture_options(facade.config.get('passive_observation') or {},
                                             capture_auth['scope'], host))
    try:
        capture.start()
        facade._authorization('visibility_calibration')
        script = host_probe.probe_script(nonce,rows,positive_enabled=False,calibration_mode=True)
        probe, raw = facade._windows().probe(script,timeout=10)
        host_probe.validate_probe_result(probe,[r['id'] for r in rows],nonce=nonce,
            expected_script_hash=host_probe.script_identity(nonce,rows,positive_enabled=False,calibration_mode=True),positive_required=False)
        post = stopped(facade)
        if pre.get('state_version') != post.get('state_version'):
            raise ValueError('engine lifecycle changed during calibration')
    finally:
        completion = capture.finish()
        save(directory/'capture-completion.json',completion)
    if not completion.get('complete'):
        raise ValueError('calibration capture completion unconfirmed; raw evidence retained')
    # Parse actual stats and records; no visible=true assertion is authored.
    running_observation.parse_capture(capture.path.read_bytes())
    now=time.time()
    value={'schema':'fakenetng.egress-visibility.v1','created_at':datetime.fromtimestamp(now,timezone.utc).isoformat(),
           'expires_at':datetime.fromtimestamp(now+3600,timezone.utc).isoformat(),
           'topology':running_observation.topology(host),'capture_identity':capture.identity,
           'capture':{'path':str(capture.path),'sha256':completion['sha256']},
           'capture_window':{key:completion[key] for key in ('started','ended')},
           'guest_status':save(directory/'stopped-status.json',post),
           'probe':save(directory/'probe.json',probe),'probe_payload':payload,
           'probe_template_sha256':host_probe.script_sha256(host_probe.PROBE_TEMPLATE)}
    save(directory/'probe-raw.json',{'raw':raw})
    return save(directory/'visibility.json',value)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['before','after','calibrate','evaluate'])
    parser.add_argument('--config')
    parser.add_argument('--before');parser.add_argument('--running');parser.add_argument('--after')
    args=parser.parse_args()
    try:
        if args.command=='evaluate':
            before=load(args.before);after=load(args.after);verification=load(args.running)
            running=dict(before,phase='running',verification=verification,
                         started_at=verification.get('lifecycle',{}).get('started_at'),
                         ended_at=verification.get('lifecycle',{}).get('ended_at'))
            # Native facade hashes are different domains from the simple
            # connectivity context. Require raw current provenance instead
            # of guessing equivalence from opaque hash strings.
            provenance=verification.get('lifecycle_identity')
            if not isinstance(provenance,dict):
                result={'verdict':'unknown','unknown':['running_lifecycle_identity_missing'],'authorized':False}
            else:
                running.update(provenance)
                running['evidence_refs']=[{'path':str(Path(args.running).resolve()),'sha256':hashlib.sha256(Path(args.running).read_bytes()).hexdigest()}]
                result=egress_lifecycle.evaluate_lifecycle(before,running,after)
        else:
            if not args.config:raise ValueError('fixed operator config required')
            facade=HostFacade(load(args.config))
            result=calibrate(facade) if args.command=='calibrate' else record(facade,args.command)
        print(json.dumps(result,ensure_ascii=False));return 0 if result.get('verdict')!='fail' else 1
    except Exception as exc:
        print(json.dumps({'verdict':'unknown','error':type(exc).__name__,'reason':str(exc),'authorized':False}));return 2


if __name__=='__main__':raise SystemExit(main())
