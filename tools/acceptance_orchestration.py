"""Existing-channel Linux and two-target original MultiHost orchestration."""
from __future__ import annotations
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import time
import uuid
from acceptance_collection import collect, digest
from acceptance_linux import ExistingRemnuxChannel, RemnuxChannelError, save_new


def linux_runtime_block(runtime,case,environment):
    required={'connection_ref','module_root','workspace_id','workspace_root','expected_vm_uuid','python','source_root','work_root','identity'}
    if not required.issubset(runtime):return 'existing REMnux channel references incomplete'
    identity=runtime['identity']
    if not isinstance(identity,dict) or set(identity)!={'platform','hostname'} or identity['platform']!='linux' or not identity['hostname'] or 'linux' not in case['platforms']:
        return 'REMnux requires exact Linux VM identity'
    if not {'native','vm-execute','vm-transfer'}.issubset(environment.get('allowed_actions',[])):
        return 'REMnux native execute and transfer are not authorized'
    for key in ('python','source_root','work_root','workspace_root','module_root','connection_ref'):
        path=PurePosixPath(runtime[key])
        if not path.is_absolute() or '..' in path.parts:return 'REMnux paths must be absolute and normalized'
    try:
        relative=PurePosixPath(runtime['work_root']).relative_to(runtime['workspace_root'])
        if not relative.parts or relative.parts[0]!='work':raise ValueError()
    except ValueError:return 'native work root must be in the selected existing workspace work directory'
    return None


def artifact_index(output):
    rows=[]
    for path in sorted(Path(output).rglob('*')):
        if path.is_symlink():raise ValueError('orchestration evidence symlink')
        if path.is_file():rows.append({'path':str(path.resolve()),'sha256':digest(path),'format':'remote-evidence'})
    return rows


def source_hashes(plan,case):
    result=dict(plan['native_source_hashes']);result.update(plan['source_hashes'][case['id']]);return result


def guest_request(root,case,plan,output):
    import acceptance_native as native
    catalog=json.loads((Path(root)/'docs/acceptance/catalog.json').read_text())
    registered=next(c for s in catalog['suites'] for c in s.get('cases',[]) if c['id']==case['id'])
    checks=native.validate_case(case,root,plan['environment'])[1]
    value = {'schema':'fakenet.native-guest-request.v1','case_id':case['id'],'case':registered,'checks':checks,
            'source_hashes':source_hashes(plan,case),'candidate':plan['candidate'],
            'target':plan['environment']['native_runtime']['identity'],'output_root':output,
            'execution_id':plan['execution_id'],'actions':['native']}
    if case.get('native_driver')=='linux-runtime':value['linux']=plan['environment']['linux']
    return value


def run_linux(root,case,plan,output_dir):
    import acceptance_native as native
    output=Path(output_dir);runtime=plan['environment']['native_runtime']
    reason=linux_runtime_block(runtime,case,plan['environment'])
    if reason:raise ValueError(reason)
    remote_base=PurePosixPath(runtime['work_root'])/plan['execution_id']/case['id']
    remote_output=str(remote_base/'output');request=guest_request(root,case,plan,remote_output)
    path=output/'guest-request.json';save_new(path,request)
    channel=ExistingRemnuxChannel(runtime,output/'transport')
    started=datetime.now(timezone.utc);status='unknown';detail='';clean=False;code=None;exited=False
    driver,checks=native.validate_case(case,root,plan['environment'])
    try:
        channel.health();channel.identity(request['source_hashes'])
        remote_request='published/'+plan['execution_id']+'/'+case['id']+'/request.json'
        channel.put('request',path,remote_request)
        absolute=str(PurePosixPath(runtime['workspace_root'])/remote_request)
        born=channel.start_guest(absolute,digest(path),entry_sha=request['source_hashes']['tools/acceptance_guest.py'])['data']
        terminal=channel.wait_exited(born,case['timeout']+90);exited=True
        save_new(output/'producer-exit.json',terminal)
        collect(channel,'native',remote_output,digest(path),output/'incoming/originals')
        guest=json.loads((output/'incoming/originals/guest-result.json').read_text())
        evaluation,clean=native._remote_original_evaluation(root,case,plan,request,guest,output/'incoming/originals')
        status=evaluation['verdict'];code=guest['receipt']['returncode']
        if code!=0:status='fail'
        if not clean and status=='pass':status='unknown'
    except (RemnuxChannelError,OSError,ValueError,KeyError,TypeError,AssertionError) as error:detail=type(error).__name__+': '+str(error)
    ended=datetime.now(timezone.utc)
    return {'status':status,'detail':detail,'returncode':code,
            'command':native.remote_guest_command(driver,runtime,remote_output,checks),
            'started_at':started.isoformat(),'ended_at':ended.isoformat(),'duration_seconds':(ended-started).total_seconds(),
            'required_checks':checks,'native_target':runtime['identity'],'artifacts':artifact_index(output),
            'cleanup':{'source':'driver','resources':driver['resources'],'recovered':clean and exited,
                       'process_exit':{'exited':exited,'returncode':code,'timed_out':not exited},
                       'remote_output':remote_output,'temp_roots':[str(output.resolve())]}}


def multi_runtime_block(runtime,case,environment):
    if case.get('native_driver')!='upstream-multihost':return 'two-target transport only runs registered MultiHost case'
    if not {'native','multihost','vm-execute','vm-transfer'}.issubset(environment.get('allowed_actions',[])):
        return 'MultiHost actions not authorized'
    for role in ('server','client'):
        target=runtime.get(role)
        if not isinstance(target,dict):return 'MultiHost requires two explicit existing targets'
        if role=='client' and target.get('transport')=='windows-mcp-velo':
            import acceptance_native as native
            reason=native.runtime_block(dict(case,native_driver='pcap-windows-functional',platforms=['windows']),dict(environment,native_runtime=target))
        else:reason=linux_runtime_block(target,case,environment)
        if reason:return role+': '+reason
    client_uuid=(runtime['client'].get('transfer',{}).get('expected_vm_identity',{}).get('vm_uuid')
                 if runtime['client'].get('transport')=='windows-mcp-velo' else runtime['client'].get('expected_vm_uuid'))
    if not client_uuid or runtime['server']['expected_vm_uuid']==client_uuid or runtime['server']['identity']==runtime['client']['identity']:
        return 'MultiHost requires distinct observed VM identities'
    import ipaddress
    try:ipaddress.IPv4Address(runtime['server_ipv4'])
    except (ValueError,KeyError):return 'MultiHost server IPv4 missing/invalid'
    return None


def wait_ready(channel,request_path,request_sha,entry_sha,birth,timeout=30):
    end=time.monotonic()+timeout
    while True:
        value=channel.process(channel.observe_job(birth['job_id']),birth['job_id'])
        if any(value.get(k)!=birth.get(k) for k in ('pid','starttime','unit','cgroup','image')):
            raise RemnuxChannelError('server producer birth changed before readiness')
        if value.get('state') in ('exited','stopped','unknown'):raise RemnuxChannelError('server producer exited before readiness')
        observed=channel.command_json(channel.multihost_control(request_path,request_sha,'observe',entry_sha=entry_sha))
        if observed.get('pending') is not True:return observed
        if time.monotonic()>=end:raise RemnuxChannelError('server not ready within bounded startup window')
        time.sleep(.5)


def stage_request(channel,name,path,experiment):
    relative='published/'+experiment+'/'+name+'.json'
    channel.put(name,path,relative)
    return str(PurePosixPath(channel.runtime['workspace_root'])/relative),digest(path)


def multi_requests(root,case,plan,suite,experiment,files,runtime):
    checks=[x for x in plan['cases'][case['id']]['required_checks'] if x.split('::',1)[0]==suite]
    config_sha=next(row['sha256'] for row in files if row['relative_path']=='fakenet.ini')
    server=runtime['server'];client=runtime['client'];hashes=source_hashes(plan,case)
    common={'schema':'fakenet.multihost-request.v1','actions':['native','multihost'],'experiment_id':experiment,
            'source_hashes':hashes,'server_ipv4':runtime['server_ipv4'],'config_sha256':config_sha,'checks':checks,'max_seconds':240}
    a=dict(common,target=server['identity'],output_root=str(PurePosixPath(server['work_root'])/experiment/'server'),
           config_path=str(PurePosixPath(server['workspace_root'])/'published'/experiment/'fakenet.ini'))
    client_path=PureWindowsPath if client['identity']['platform']=='windows' else PurePosixPath
    b=dict(common,target=client['identity'],output_root=str(client_path(client['work_root'])/experiment/'client'),
           config_path=a['config_path'],server_target=server['identity'])
    return a,b


def run_multihost(root,case,plan,output_dir):
    import acceptance_multihost as multi
    import acceptance_native as native
    output=Path(output_dir);runtime=plan['environment']['native_runtime']
    reason=multi_runtime_block(runtime,case,plan['environment'])
    if reason:raise ValueError(reason)
    if plan['candidate'].get('deployed_identity')!={x:runtime[x]['identity'] for x in ('server','client')}:
        raise ValueError('candidate deployed MultiHost targets differ from selected VMs')
    driver,checks=native.validate_case(case,root,plan['environment'])
    started=datetime.now(timezone.utc);records=[];failure=None
    suites=list(dict.fromkeys(x.split('::',1)[0] for x in checks))
    if any(s not in ('General','No Redirect') for s in suites):raise ValueError('unregistered original MultiHost configuration')
    for number,suite in enumerate(suites):
        directory=output/('suite-%02d'%number);directory.mkdir()
        experiment='mh-'+uuid.uuid4().hex
        record={'suite':suite,'experiment_id':experiment,'server_exited':False,'client_exited':False,
                'server_attempted':False,'client_attempted':False,'error':None};records.append(record)
        server=ExistingRemnuxChannel(runtime['server'],directory/'server-transport')
        windows=runtime['client']['transport']=='windows-mcp-velo'
        if windows:
            from acceptance_windows import ExistingWindowsChannel
            client=ExistingWindowsChannel(root,runtime['client'],directory/'client-transport')
        else:client=ExistingRemnuxChannel(runtime['client'],directory/'client-transport')
        server_birth=None;client_birth=None;server_remote=None;server_sha=None
        server_request=None;client_request=None;windows_terminal=None;client_sha=None
        try:
            hashes=source_hashes(plan,case)
            server.health();server.identity(hashes)
            if windows:
                if client.identity()!=runtime['client']['identity']:raise ValueError('observed Windows client differs')
            else:client.health();client.identity(hashes)
            files=multi.prepare_original_config(root,suite,directory/'configuration')
            server_request,client_request=multi_requests(root,case,plan,suite,experiment,files,runtime)
            save_new(directory/'server-request.json',server_request)
            server.stage_multihost(experiment,files)
            server_remote,server_sha=stage_request(server,'server-request',directory/'server-request.json',experiment)
            entry_sha=hashes['tools/acceptance_multihost.py'];record['server_attempted']=True
            server_birth=server.start_guest(server_remote,server_sha,entry='tools/acceptance_multihost.py',action='serve',entry_sha=entry_sha)['data']
            before=wait_ready(server,server_remote,server_sha,entry_sha,server_birth)
            save_new(directory/'observe-before.json',before)
            client_request['server_observation']=before;save_new(directory/'client-request.json',client_request)
            record['client_attempted']=True
            if windows:
                remote_input=str(PureWindowsPath(runtime['client']['work_root'])/experiment/'input')
                client.transfer('push-request','push',[{'absolute_path':str((directory/'client-request.json').resolve()),'relative_path':'request.json'}],remote_input,producer_reference='closed original MultiHost request')
                client_sha=digest(directory/'client-request.json')
                windows_terminal=client.multihost_probes(str(PureWindowsPath(remote_input)/'request.json'),client_sha,client_request['output_root'],hashes,240)
                if windows_terminal.get('process_exited') is not True:raise ValueError('client producer exit unknown; no collect')
                record['client_exited']=True
                save_new(directory/'client-exit.json',windows_terminal)
            else:
                client_remote,client_sha=stage_request(client,'client-request',directory/'client-request.json',experiment)
                client_birth=client.start_guest(client_remote,client_sha,entry='tools/acceptance_multihost.py',action='probes',entry_sha=entry_sha)['data']
                client_exit=client.wait_exited(client_birth,240);record['client_exited']=True
                save_new(directory/'client-exit.json',client_exit)
            # A negative probe cannot pass a dead/unready server.
            after=server.command_json(server.multihost_control(server_remote,server_sha,'observe',entry_sha=entry_sha))
            if after.get('owner')!=before.get('owner') or after.get('core_ready') is not True:raise ValueError('server owner/readiness changed during original client probes')
            save_new(directory/'observe-after.json',after)
        except (RuntimeError,OSError,ValueError,KeyError,TypeError,AssertionError) as error:
            record['error']=type(error).__name__+': '+str(error);failure=record['error']
        finally:
            # Unknown start keeps its original intent; never replace-start or
            # kill by generic PID/systemd pattern.
            if server_birth is not None:
                try:
                    stopped=server.command_json(server.multihost_control(server_remote,server_sha,'stop',entry_sha=entry_sha))
                    save_new(directory/'stop-response.json',stopped)
                except (RemnuxChannelError,OSError,ValueError,KeyError,TypeError) as error:record['stop_error']=type(error).__name__+': '+str(error)
                try:
                    terminal=server.wait_exited(server_birth,330);record['server_exited']=True;save_new(directory/'server-exit.json',terminal)
                    collect(server,'server',server_request['output_root'],server_sha,directory/'server')
                except (RemnuxChannelError,OSError,ValueError,KeyError,TypeError) as error:record['collection_error']=type(error).__name__+': '+str(error)
            if windows and record['client_exited']:
                try:
                    client.transfer('pull-originals','pull',[{'absolute_path':client_request['output_root'],'relative_path':'client'}],str(directory.resolve()),producer_reference='original multihost-probes completed process observation')
                    # Preserve the original bytes including the nested index;
                    # the side index lets both existing channels use one oracle.
                    (directory/'client-export-index.json').write_bytes((directory/'client/export-index.json').read_bytes())
                except (RuntimeError,OSError,ValueError,KeyError,TypeError) as error:
                    record['client_collection_error']=type(error).__name__+': '+str(error)
            elif client_birth is not None:
                try:
                    if not record['client_exited']:
                        terminal=client.wait_exited(client_birth,90);record['client_exited']=True
                        save_new(directory/'client-exit.json',terminal)
                    collect(client,'client',client_request['output_root'],client_sha,directory/'client')
                except (RemnuxChannelError,OSError,ValueError,KeyError,TypeError) as error:
                    record['client_collection_error']=type(error).__name__+': '+str(error)
        save_new(directory/'orchestration.json',record)
        try:
            rows,clean=evaluate_multihost_suite(root,case,plan,directory,record)
            if not clean or any(x['status']!='pass' for x in rows):failure=failure or 'original MultiHost check or recovery failed'
        except (OSError,ValueError,KeyError,TypeError,AssertionError) as error:failure=failure or str(error)
        if failure:break
    save_new(output/'orchestration.json',{'schema':'fakenet.multihost-run.v1','records':records,'failure':failure})
    clean=False;status='unknown'
    try:
        evaluation,clean=evaluate_multihost(root,case,plan,output);status=evaluation['verdict']
        if failure and status=='pass':status='unknown'
    except (OSError,ValueError,KeyError,TypeError,AssertionError):pass
    ended=datetime.now(timezone.utc)
    return {'status':status,'detail':failure or '', 'returncode':0 if status=='pass' and clean else 1 if status=='fail' else None,
            'command':['registered:upstream-multihost'],'required_checks':checks,
            'native_target':{role:runtime[role]['identity'] for role in ('server','client')},
            'started_at':started.isoformat(),'ended_at':ended.isoformat(),'duration_seconds':(ended-started).total_seconds(),
            'artifacts':artifact_index(output),'cleanup':{'source':'driver','resources':driver['resources'],
                'recovered':clean,'process_exit':{'exited':clean,'timed_out':not clean,'returncode':0 if clean and status=='pass' else None},'temp_roots':[str(output.resolve())]}}


def evaluate_multihost_suite(root,case,plan,directory,record):
    import acceptance_native as native
    from acceptance_collection import validate_index
    directory=Path(directory);runtime=plan['environment']['native_runtime']
    def read(name):return json.loads((directory/name).read_text())
    if record!=read('orchestration.json'):raise ValueError('MultiHost record changed')
    files=read('configuration/input-manifest.json')['files']
    manifest=read('configuration/input-manifest.json')
    expected_names=['fakenet.ini','custom_responses.ini','CustomProviderExample.py','sample_raw_response.txt','sample_raw_tcp_response.txt']
    if [r.get('relative_path') for r in files]!=expected_names or manifest.get('suite')!=record['suite'] or manifest.get('source_template_sha256')!=digest(Path(root)/'test/template.ini'):
        raise ValueError('original MultiHost input manifest differs')
    import configparser,io
    parser=configparser.RawConfigParser();parser.read(Path(root)/'test/template.ini')
    parser.set('Diverter','NetworkMode','MultiHost')
    parser.set('Diverter','RedirectAllTraffic','No' if record['suite']=='No Redirect' else 'Yes')
    if record['suite']=='No Redirect':
        parser.remove_section('ProxyTCPListener');parser.remove_section('ProxyUDPListener')
        parser.set('Diverter','DefaultTCPListener','RawTCPListener');parser.set('Diverter','DefaultUDPListener','RawUDPListener')
    stream=io.StringIO();parser.write(stream)
    if (directory/'configuration/fakenet.ini').read_text()!=stream.getvalue():raise ValueError('configuration is not original MultiHost fixture')
    for name in expected_names[1:]:
        if digest(directory/'configuration'/name)!=digest(Path(root)/'test'/name):raise ValueError('original ancillary bytes changed')
    for row in files:
        local=directory/'configuration'/row['relative_path']
        if digest(local)!=row['sha256'] or local.stat().st_size!=row['size']:raise ValueError('staged configuration changed')
    a,b=read('server-request.json'),read('client-request.json')
    expected_a,expected_b=multi_requests(root,case,plan,record['suite'],record['experiment_id'],files,runtime)
    before,after=read('observe-before.json'),read('observe-after.json');expected_b['server_observation']=before
    if a!=expected_a or b!=expected_b:raise ValueError('MultiHost request differs from frozen plan/configuration')
    for role,request in (('server',a),('client',b)):
        rows=validate_index(read(role+'-export-index.json'),request['output_root'],digest(directory/(role+'-request.json')))
        seen=set()
        for row in rows:
            path=directory/role/row['relative_path']
            if path.is_symlink() or not path.is_file() or path.stat().st_size!=row['size'] or digest(path)!=row['sha256']:raise ValueError('MultiHost original changed/missing')
            seen.add(row['relative_path'])
        actual={p.relative_to(directory/role).as_posix() for p in (directory/role).rglob('*') if p.is_file() and p.name!='export-index.json'}
        if seen!=actual:raise ValueError('MultiHost original set not exact')
        exit_record=read(role+'-exit.json')
        if role=='client' and runtime['client']['identity']['platform']=='windows':
            if exit_record.get('process_exited') is not True:raise ValueError('Windows client producer exit not confirmed')
        elif exit_record.get('state')!='exited':raise ValueError('MultiHost producer exit not confirmed')
    server=read('server/server-result.json');owner=server.get('owner')
    for observation in (before,after):
        if (observation.get('schema')!='fakenet.multihost-observation.v1' or observation.get('core_ready') is not True or
            observation.get('owner')!=owner or observation.get('config_sha256')!=a['config_sha256'] or
            not observation.get('core_log_sha256') or type(observation.get('observed_at')) not in (int,float)):
            raise ValueError('MultiHost real observed owner/readiness missing or changed')
    if (not isinstance(owner,dict) or owner.get('target')!=a['target'] or owner.get('experiment_id')!=a['experiment_id'] or
        owner.get('source_hashes')!=a['source_hashes'] or owner.get('config_sha256')!=a['config_sha256'] or
        not owner.get('core_birth') or not owner.get('owner_birth') or after['observed_at']<before['observed_at']):raise ValueError('MultiHost server owner/source/birth identity mismatch')
    probe=read('client/probes.json')
    if (probe.get('schema')!='fakenet.multihost-probes.v1' or probe.get('experiment_id')!=b['experiment_id'] or
        probe.get('server_observation')!=before or probe.get('client_target')!=b['target']):raise ValueError('MultiHost client result identity mismatch')
    topology=probe.get('topology') or {}
    if topology.get('gateway')!=runtime['server_ipv4'] or not topology.get('dns_servers') or set(topology['dns_servers'])!={runtime['server_ipv4']}:
        raise ValueError('original MultiHost client gateway/DNS prerequisite not observed')
    result=native._judge_rows(probe.get('checks'),b['checks']);core=server.get('core') or {}
    log=(directory/'server/core.log').read_text(errors='replace')
    clean=(record.get('server_exited') is True and record.get('client_exited') is True and
           not any(record.get(k) for k in ('stop_error','collection_error','client_collection_error')) and
           server.get('cleanup_complete') is True and server.get('network_restored') is True and
           server.get('core')==read('server/core-lifecycle.json') and
           core.get('ready') is True and core.get('stopped') is True and core.get('forced') is False and core.get('returncode')==0 and
           'FakeNet-NG started successfully' in log and (directory/'server/core-console.log').is_file() and
           read('server/network-before.json')==read('server/network-after.json') and
           probe.get('cleanup_complete') is True and read('client/network-before.json')==read('client/network-after.json'))
    rows=probe['checks']
    if server.get('error') or probe.get('error') or record.get('error'):rows=[dict(x,status='fail') for x in rows]
    return rows,clean


def evaluate_multihost(root,case,plan,output):
    import acceptance_native as native
    output=Path(output);value=json.loads((output/'orchestration.json').read_text());checks=native.validate_case(case,root,plan['environment'])[1]
    if value.get('schema')!='fakenet.multihost-run.v1':raise ValueError('MultiHost run schema invalid')
    records=value['records'];suites=list(dict.fromkeys(x.split('::',1)[0] for x in checks))
    if not records or [x.get('suite') for x in records]!=suites[:len(records)] or len(records)>len(suites):raise ValueError('MultiHost missing/extra/reordered configuration')
    rows=[];clean=True
    for index,record in enumerate(records):
        found,recovered=evaluate_multihost_suite(root,case,plan,output/('suite-%02d'%index),record);rows+=found;clean=clean and recovered
    result=native._judge_rows(rows,checks)
    if value.get('failure') and result['verdict']=='pass':result['verdict']='unknown'
    return result,clean


def judge_multihost(case,receipt,plan,root):
    output=Path(plan['run_dir'])/'results'/case['id'];actual=artifact_index(output)
    actual=[x for x in actual if Path(x['path']).name!='receipt.json']
    if receipt.get('artifacts')!=actual:return {'status':'unknown','cleanup_ok':False,'reason':'MultiHost evidence set/hash changed'}
    try:evaluation,clean=evaluate_multihost(root,case,plan,output)
    except (OSError,ValueError,KeyError,TypeError,AssertionError) as error:return {'status':'unknown','cleanup_ok':False,'reason':'original MultiHost oracle refused: '+str(error)}
    runtime=plan['environment']['native_runtime'];targets={x:runtime[x]['identity'] for x in ('server','client')};clean=clean and receipt.get('cleanup',{}).get('recovered') is True
    status=evaluation['verdict']
    if receipt.get('command')!=['registered:upstream-multihost'] or receipt.get('native_target')!=targets or receipt.get('required_checks')!=plan['cases'][case['id']]['required_checks']:
        return {'status':'fail','cleanup_ok':False,'reason':'MultiHost outer command/target/selection mismatch'}
    if receipt.get('status')=='fail':status='fail'
    if status=='pass' and (receipt.get('status')!='pass' or receipt.get('returncode')!=0 or not clean):status='unknown'
    return {'status':status,'cleanup_ok':clean,'evaluation':evaluation,'reason':'' if clean else 'MultiHost recovery unverified'}
