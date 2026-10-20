#!/usr/bin/env python3
"""Ordinary-user, read-only quiescence checker for the root fixture.

No endpoint, script, PID or cleanup permission comes from sample bytes. Missing
records, current processes, engine ownership or guest drift refuse release.
This command does not stop engines/services/processes or change guest routes.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO))
from fakenet.mcp.host_stdio import FakeNetHttpClient, WindowsMcpClient


def gather_inputs(config):
    if os.geteuid()==0:raise RuntimeError('business checker must be unprivileged')
    host=json.loads(Path(config['host_config']).read_text())
    expected=[]
    for row in config['owned_processes']:
        if (type(row.get('pid')) is not int or row['pid']<=0 or
                type(row.get('creation_ticks')) is not int or
                row['creation_ticks']<=0):raise RuntimeError('owned process identity invalid')
        expected.append(row)
    for command in config['command_ids']:
        if str(uuid.UUID(command))!=command:raise RuntimeError('invalid command')
        path=Path(host['state_root'])/(command+'.json')
        if path.is_symlink() or not path.is_file():raise RuntimeError('intent record missing')
        record=json.loads(path.read_text())
        if record.get('command_id')!=command or record.get('stage')!='completed':raise RuntimeError('intent not completed')
        result_path=Path(record['result_path'])
        raw=result_path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=record.get('result_sha256'):raise RuntimeError('result identity drift')
        result=json.loads(raw)
        if (result.get('lifecycle') or {}).get('state') in ('ownership_unknown','running','timed_out'):
            raise RuntimeError('remote completion unknown')
        instance=result.get('probe_instance') or record.get('probe_instance')
        if isinstance(instance,dict) and 'windows' in instance:
            instance=instance['windows']
        if instance:
            expected.append({'pid':instance['pid'],'creation_ticks':instance['creation_ticks']})
        elif (result.get('coverage') or {}).get('matrix_not_run')!=30:
            raise RuntimeError('probe ownership evidence missing')
    if not expected:raise RuntimeError('explicit candidate/process inventory required')
    return host,expected


def query_script(config,processes):
    payload={'processes':processes,'service':config['service_baseline']['Name'],
             'guest_changes':config['guest_changes']}
    encoded=base64.b64encode(json.dumps(payload,separators=(',',':')).encode()).decode()
    return r'''$ErrorActionPreference='Stop'
$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))|ConvertFrom-Json
$os=Get-CimInstance Win32_OperatingSystem
$sys=Get-CimInstance Win32_ComputerSystemProduct
$rows=@(foreach($item in $p.processes){
  $existing=Get-Process -Id ([int]$item.pid) -ErrorAction SilentlyContinue
  $current=$null
  if($existing){$current=[ordered]@{pid=$existing.Id;creation_ticks=$existing.StartTime.ToUniversalTime().ToFileTimeUtc()}}
  [ordered]@{requested_pid=[int]$item.pid;requested_creation_ticks=[long]$item.creation_ticks;current_instance=$current}
})
$services=@(Get-CimInstance Win32_Service | Where-Object {$_.Name -eq [string]$p.service})
if($services.Count -ne 1){throw 'service inventory ambiguous'}
$service=$services[0]|Select-Object Name,State,StartMode,PathName
$remaining=@(foreach($item in $p.guest_changes){
  if($item.kind -eq 'address'){
    $found=@(Get-NetIPAddress -InterfaceIndex ([int]$item.if_index) -AddressFamily ([string]$item.family) -ErrorAction Stop | Where-Object {$_.IPAddress -eq [string]$item.value})
  }elseif($item.kind -eq 'route'){
    $found=@(Get-NetRoute -InterfaceIndex ([int]$item.if_index) -AddressFamily ([string]$item.family) -ErrorAction Stop | Where-Object {$_.DestinationPrefix -eq [string]$item.value})
  }else{throw 'unsupported guest change'}
  if($found.Count -gt 0){$item}
})
$result=[ordered]@{vm_uuid=([string]$sys.UUID).ToUpperInvariant();boot_id=$os.LastBootUpTime.ToUniversalTime().ToString('o');process_queries=$rows;service=$service;remaining_guest_changes=$remaining}
'MALTRACE_JSON:'+($result|ConvertTo-Json -Depth 12 -Compress)
'''.replace('__PAYLOAD__',encoded)


def check(config,directory):
    host,processes=gather_inputs(config)
    endpoint=host.get('windows_mcp') or host.get('windows')
    if not endpoint:raise RuntimeError('fixed Windows endpoint missing')
    guest=host.get('fakenet_mcp') or host.get('fakenet')
    if not guest:raise RuntimeError('fixed FakeNet endpoint missing')
    window=WindowsMcpClient(endpoint)
    observed,raw=window.probe(query_script(config,processes),timeout=8)
    output=Path(directory);output.mkdir(parents=True,exist_ok=True)
    (output/('guest-quiescence-'+uuid.uuid4().hex+'.raw')).write_text(raw)
    guest=dict(guest)
    guest.setdefault('allowed_hosts',[host['guest_ip']])
    status=FakeNetHttpClient(guest).get_status(timeout=3)
    (output/('guest-status-'+uuid.uuid4().hex+'.json')).write_text(json.dumps(status,indent=2)+'\n')
    if observed.get('vm_uuid')!=config['vm_uuid'] or observed.get('boot_id')!=config['boot_id']:
        raise RuntimeError('guest epoch changed')
    rows=observed.get('process_queries')
    if not isinstance(rows,list) or len(rows)!=len(processes):raise RuntimeError('process query incomplete')
    for want,row in zip(processes,rows):
        if row.get('requested_pid')!=want['pid'] or row.get('requested_creation_ticks')!=want['creation_ticks']:
            raise RuntimeError('process query identity mismatch')
        # Even PID reuse is refused: do not mistake a newly-live process for absence.
        if row.get('current_instance') is not None:raise RuntimeError('owned PID still live or reused')
    service=observed.get('service')
    service_ok=service==config['service_baseline']
    if not service_ok or observed.get('remaining_guest_changes')!=[]:raise RuntimeError('guest baseline not restored')
    if status.get('state')!='stopped' or status.get('run_id') is not None:raise RuntimeError('guest engine not stopped')
    return {'schema':'fakenetng.guest-quiescence.v1','vm_uuid':config['vm_uuid'],
            'boot_id':config['boot_id'],'command_ids':config['command_ids'],
            'process_queries':rows,'service_restored':service_ok,
            'remaining_guest_changes':[],'engine_state':status['state'],'run_id':status.get('run_id')}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True);p.add_argument('--output',required=True);a=p.parse_args(argv)
    result=check(json.loads(Path(a.config).read_text()),a.output)
    print(json.dumps(result,separators=(',',':')));return 0


if __name__=='__main__':raise SystemExit(main())
