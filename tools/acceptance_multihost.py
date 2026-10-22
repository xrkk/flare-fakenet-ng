"""Finite MultiHost core owner and exact original-client probes.

The Host uses existing channels to stage the pinned request/config, starts one
owned server job, obtains Observe from that target, passes that observation to
client probes, then requests Stop and collects originals. No service is added.
"""
from __future__ import annotations
import argparse
import configparser
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import sys
import time


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_new(path,value):
    with Path(path).open('x',encoding='utf-8') as stream:json.dump(value,stream,indent=2)


def birth(pid):
    return Path('/proc/%d/stat'%pid).read_text().rsplit(')',1)[1].split()[19]


def validate(request,root):
    if request.get('schema')!='fakenet.multihost-request.v1' or request.get('actions')!=['native','multihost']:
        raise ValueError('MultiHost request/actions invalid')
    if not isinstance(request.get('experiment_id'),str) or not request['experiment_id']:
        raise ValueError('MultiHost experiment ID missing')
    directory=Path(request['output_root'])
    if not directory.is_absolute():raise ValueError('absolute MultiHost output root required')
    root=Path(root).resolve()
    for relative,want in request['source_hashes'].items():
        path=root/relative
        if path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file() or sha(path)!=want:
            raise ValueError('MultiHost source mismatch: '+relative)
    ipaddress.IPv4Address(request['server_ipv4'])
    return directory


def serve(request,root):
    from acceptance_runtime import OwnedCore,require_target,network_snapshot,write_json
    directory=validate(request,root);require_target(request['target'])
    if request['target']['platform']!='linux':raise ValueError('original MultiHost server requires Linux')
    config=Path(request['config_path'])
    if not config.is_file() or config.is_symlink() or sha(config)!=request['config_sha256']:
        raise ValueError('MultiHost staged configuration mismatch')
    parser=configparser.RawConfigParser();parser.read(config)
    if parser.get('Diverter','NetworkMode').lower()!='multihost':
        raise ValueError('MultiHost server configuration is not MultiHost')
    limit=request['max_seconds']
    if type(limit) is not int or not 1<=limit<=240:raise ValueError('bounded server window required')
    directory.mkdir(parents=True,exist_ok=False)
    before=network_snapshot();write_json(directory/'network-before.json',before)
    stop=directory/'stop.flag';log=directory/'core.log'
    argv=[sys.executable,'-m','fakenet.fakenet','-n','--no-pause','-c',str(config),'-l',str(log),'-f',str(stop)]
    core=OwnedCore(argv,directory,directory,stop,log,source_root=root)
    error=None;clean=False;owner=None
    try:
        core.start()
        owner={'schema':'fakenet.multihost-owner.v1','experiment_id':request['experiment_id'],
               'target':request['target'],'owner_pid':os.getpid(),'owner_birth':birth(os.getpid()),
               'core_pid':core.process.pid,'core_birth':birth(core.process.pid),
               'config_sha256':sha(config),'source_hashes':request['source_hashes']}
        write_new(directory/'owner.json',owner)
        deadline=time.monotonic()+limit
        while not stop.exists():
            if core.process.poll() is not None:raise RuntimeError('MultiHost core exited before requested Stop')
            if time.monotonic()>=deadline:raise TimeoutError('MultiHost server window exhausted')
            time.sleep(.1)
    except BaseException as exc:error=type(exc).__name__+': '+str(exc)
    finally:
        stopped=core.stop()
        after=network_snapshot();write_json(directory/'network-after.json',after)
        clean=stopped and before==after
        write_json(directory/'server-result.json',{'schema':'fakenet.multihost-server-result.v1',
                   'experiment_id':request['experiment_id'],'owner':owner,'core':core.state,
                   'network_restored':before==after,'cleanup_complete':clean,'error':error})
    return {'passed':error is None and clean,'cleanup_complete':clean}


def observe(request,root):
    from acceptance_runtime import target_identity
    directory=validate(request,root)
    if target_identity()!=request['target']:raise ValueError('MultiHost Observe target mismatch')
    owner=json.loads((directory/'owner.json').read_text())
    if (owner.get('experiment_id')!=request['experiment_id'] or owner.get('target')!=request['target'] or
        owner.get('source_hashes')!=request['source_hashes'] or owner.get('config_sha256')!=request['config_sha256']):
        raise ValueError('MultiHost owner/request mismatch')
    if birth(owner['owner_pid'])!=owner['owner_birth'] or birth(owner['core_pid'])!=owner['core_birth']:
        raise ValueError('MultiHost owned PID was reused or exited')
    if sha(request['config_path'])!=request['config_sha256']:
        raise ValueError('MultiHost configuration changed after start')
    log=(directory/'core.log').read_text(encoding='utf-8',errors='replace')
    if 'FakeNet-NG started successfully' not in log:raise ValueError('MultiHost core not ready')
    if (directory/'stop.flag').exists() or (directory/'server-result.json').exists():
        raise ValueError('MultiHost server already stopping/stopped')
    return {'schema':'fakenet.multihost-observation.v1','owner':owner,
            'config_sha256':sha(request['config_path']),'core_log_sha256':sha(directory/'core.log'),
            'observed_at':time.time(),'core_ready':True}


def stop(request,root):
    directory=validate(request,root)
    result=directory/'server-result.json'
    if result.is_file():return json.loads(result.read_text())
    observed=observe(request,root)
    (directory/'stop.flag').touch(exist_ok=False)
    return {'stop_requested':True,'owner':observed['owner']}


def probes(request,root):
    from acceptance_runtime import require_target
    directory=validate(request,root);require_target(request['target'])
    observation=request.get('server_observation') or {};owner=observation.get('owner') or {}
    if (observation.get('schema')!='fakenet.multihost-observation.v1' or observation.get('core_ready') is not True or
        owner.get('experiment_id')!=request['experiment_id'] or owner.get('config_sha256')!=request['config_sha256'] or
        not owner.get('core_birth') or not owner.get('owner_birth') or
        observation.get('config_sha256')!=request['config_sha256'] or not observation.get('core_log_sha256') or
        not isinstance(observation.get('observed_at'),(int,float)) or not 0<=time.time()-observation['observed_at']<=30):
        raise ValueError('fresh observed server owner/readiness required; boolean ready is insufficient')
    # Import original callbacks only on the explicitly selected client VM.
    spec=importlib.util.spec_from_file_location('fakenet_multihost_original',Path(root)/'test/test.py')
    original=importlib.util.module_from_spec(spec);spec.loader.exec_module(original)
    settings=original.FakeNetTestSettings(str(Path(root)/'test'),singlehost=False,non_interactive=True)
    settings.ext_ip=request['server_ipv4']
    tester=original.FakeNetTester(settings)
    selected=tester.mechanicalSelection(request['checks'])
    directory.mkdir(parents=True,exist_ok=False)
    rows=[]
    for suite,checks in selected:
        for identity,(callback,args,expected) in checks:
            result=tester._tryTest(identity,callback,args,expected)
            rows.append({'id':identity,'status':'pass' if result['passed'] else 'fail','detail':result['detail']})
    result={'schema':'fakenet.multihost-probes.v1','experiment_id':request['experiment_id'],
            'checks':rows,'server_observation':observation,'client_target':request['target']}
    write_new(directory/'probes.json',result)
    return result



def prepare_original_config(root,suite,output):
    """Deterministic original MultiHost fixture, with no client imports/I/O."""
    if suite not in ('General','No Redirect'):
        raise ValueError('suite has no original MultiHost callbacks')
    import shutil
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    parser=configparser.RawConfigParser();parser.read(Path(root)/'test/template.ini')
    parser.set('Diverter','NetworkMode','MultiHost')
    parser.set('Diverter','RedirectAllTraffic','No' if suite=='No Redirect' else 'Yes')
    if suite=='No Redirect':
        parser.remove_section('ProxyTCPListener');parser.remove_section('ProxyUDPListener')
        parser.set('Diverter','DefaultTCPListener','RawTCPListener')
        parser.set('Diverter','DefaultUDPListener','RawUDPListener')
    with (output/'fakenet.ini').open('x') as stream:parser.write(stream)
    names=['fakenet.ini','custom_responses.ini','CustomProviderExample.py','sample_raw_response.txt','sample_raw_tcp_response.txt']
    for name in names[1:]:shutil.copyfile(Path(root)/'test'/name,output/name)
    rows=[{'local':str(output/name),'relative_path':name,'sha256':sha(output/name),'size':(output/name).stat().st_size} for name in names]
    write_new(output/'input-manifest.json',{'suite':suite,'source_template_sha256':sha(Path(root)/'test/template.ini'),'files':rows})
    return rows


def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--request',required=True);parser.add_argument('--request-sha256',required=True)
    parser.add_argument('--action',choices=('serve','observe','stop','probes'),required=True)
    args=parser.parse_args(argv);path=Path(args.request)
    if not path.is_file() or path.is_symlink() or sha(path)!=args.request_sha256:raise ValueError('MultiHost request changed')
    request=json.loads(path.read_text());result=globals()[args.action](request,Path(__file__).resolve().parents[1])
    print(json.dumps(result,sort_keys=True))
    return 1 if result.get('passed') is False else 0


if __name__=='__main__':raise SystemExit(main())
