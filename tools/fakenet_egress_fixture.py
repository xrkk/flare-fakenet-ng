#!/usr/bin/env python3
"""One foreground, explicitly authorized local fixture. No business imports.

plan is read only. run/recover require an exact reviewed root config. A failed
or unconfirmed guest cleanup retains isolation and durable recovery metadata.
"""
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import pwd
import re
import select
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

TABLE='mt_egress_fixture'
PORTS=(28787,28788,28790)
SCHEMA='fakenetng.host-observer-response.v1'
REQUEST_SCHEMA='fakenetng.host-observer-request.v1'
DEADLINE=1792495773.527152  # original 2026-10-20T19:29:33.527152+08:00
BIN={'nft':'/usr/sbin/nft','ip':'/usr/sbin/ip','ps':'/usr/bin/ps','tc':'/usr/sbin/tc'}
MAX_RAW=1024*1024


def sha(value):
    if not isinstance(value,bytes):
        value=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    return hashlib.sha256(value).hexdigest()


def secure(path,kind='file'):
    path=Path(path)
    if not path.is_absolute(): raise RuntimeError('absolute root path required')
    for parent in path.parents:
        s=parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:
            raise RuntimeError('unsafe root ancestor')
    s=path.lstat()
    if s.st_uid!=0 or s.st_mode&0o022 or path.is_symlink():
        raise RuntimeError('unsafe root object')
    if kind=='file' and not stat.S_ISREG(s.st_mode):raise RuntimeError('not a file')
    if kind=='dir' and not stat.S_ISDIR(s.st_mode):raise RuntimeError('not a directory')
    return path


def read_root(path):
    path=secure(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if before.st_size>MAX_RAW:raise RuntimeError('root input too large')
        raw=os.read(fd,MAX_RAW+1)
        after=os.fstat(fd)
        if len(raw)>MAX_RAW or (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns):
            raise RuntimeError('root input changed')
        return json.loads(raw)
    finally:os.close(fd)


def atomic(path,value,mode=0o644):
    path=Path(path);secure(path.parent,'dir')
    fd,name=tempfile.mkstemp(prefix='.publish-',dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb') as f:
            f.write(json.dumps(value,sort_keys=True,indent=2).encode()+b'\n');f.flush();os.fsync(f.fileno())
        os.replace(name,path)
        d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(d)
        finally:os.close(d)
    finally:
        if os.path.exists(name):os.unlink(name)


def proc(pid):
    base=Path('/proc')/str(int(pid));fields=(base/'stat').read_text().rsplit(')',1)[1].split()
    uids=[]
    for line in (base/'status').read_text().splitlines():
        if line.startswith('Uid:'):uids=list(map(int,line.split()[1:]))
    if len(uids)!=4 or any(uids):raise RuntimeError('not a root process')
    if fields[0] in ('Z','X','x'):raise RuntimeError('process exited')
    states=[]
    for task in (base/'task').iterdir():states.append((task/'stat').read_text().rsplit(')',1)[1].split()[0])
    return {'pid':int(pid),'birth_ticks':int(fields[19]),'uid':0,
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'comm':(base/'comm').read_text().strip(),
            'argv':[(b.decode('utf8','replace')) for b in (base/'cmdline').read_bytes().split(b'\0') if b],
            'thread_states':states}


def load_config(path,privileged=False):
    value=read_root(path) if privileged else json.loads(Path(path).read_text())
    allowed={'schema','commands','target','vmx_path','natd_pid','natd_birth_ticks',
             'window_start','window_end','runner','quiescence_checker'}
    if set(value)!=allowed or value['schema']!='fakenetng.local-fixture.config.v2':
        raise RuntimeError('strict v2 fixture configuration required')
    if not isinstance(value['commands'],list) or not 1<=len(value['commands'])<=12:
        raise RuntimeError('finite registered command list required')
    for command in value['commands']:
        if str(uuid.UUID(command))!=command:raise RuntimeError('canonical command ID required')
    if len(set(value['commands']))!=len(value['commands']):raise RuntimeError('duplicate commands')
    start,end=map(float,(value['window_start'],value['window_end']))
    if not all(map(math.isfinite,(start,end))) or not 0<end-start<=900 or end>DEADLINE:
        raise RuntimeError('window exceeds original budget')
    t=value['target']
    if set(t)!={'vm_uuid','mac','guest_ipv4','guest_ipv6','host_ipv4','host_link_local','boot_id'}:
        raise RuntimeError('complete fixed target required')
    if re.sub(r'[\s-]','',t['vm_uuid']).lower()!='b3e04d563db29f3d4d523ec22c4cfdc0' and re.sub(r'[\s-]','',t['vm_uuid']).lower()!='564de0b3b23d3d9f4d523ec22c4cfdc0':
        raise RuntimeError('target UUID outside approved VM')
    if t['mac'].lower()!='00:0c:29:4c:fd:c0':raise RuntimeError('target MAC mismatch')
    if str(ipaddress.IPv4Address(t['guest_ipv4']))!='192.168.204.149' or str(ipaddress.IPv4Address(t['host_ipv4']))!='192.168.204.1':raise RuntimeError('target IPv4 mismatch')
    if str(ipaddress.IPv6Address(t['guest_ipv6']))!='2001:db8:204::149' or str(ipaddress.IPv6Address(t['host_link_local']))!='fe80::250:56ff:fec0:8':raise RuntimeError('target IPv6 mismatch')
    if not t['boot_id']:raise RuntimeError('guest epoch required')
    for key in ('runner','quiescence_checker'):
        spec=value[key]
        if set(spec)!={'python','script','script_sha256','args','uid','gid'}:raise RuntimeError('fixed unprivileged script specification required')
        if spec['uid']!=1000 or spec['gid']!=1000:raise RuntimeError('only reviewed ordinary user')
        if not all(Path(spec[k]).is_absolute() for k in ('python','script')):raise RuntimeError('absolute runner paths required')
        if not isinstance(spec['args'],list) or not all(isinstance(a,str) and '\0' not in a for a in spec['args']):raise RuntimeError('runner arguments invalid')
        if sha(Path(spec['script']).read_bytes())!=spec['script_sha256']:raise RuntimeError('reviewed ordinary script changed')
    return value


def command(argv,directory,tag,timeout=2):
    if not Path(argv[0]).is_absolute():raise RuntimeError('absolute executable required')
    with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
        with subprocess.Popen(argv,stdout=out,stderr=err,stdin=subprocess.DEVNULL,
                              env={'PATH':'/usr/sbin:/usr/bin','LANG':'C','LC_ALL':'C'},close_fds=True) as child:
            try:code=child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                child.kill();child.wait();raise RuntimeError('fixed command timeout')
        out.seek(0);err.seek(0);stdout=out.read(MAX_RAW+1);stderr=err.read(MAX_RAW+1)
    if len(stdout)>MAX_RAW or len(stderr)>MAX_RAW:raise RuntimeError('fixed command output limit')
    record={'argv':argv,'exit_code':code,'stdout':stdout.decode('utf8','replace'),
            'stderr':stderr.decode('utf8','replace'),'at':time.time()}
    atomic(Path(directory)/('raw-'+tag+'-'+uuid.uuid4().hex+'.json'),record)
    if code:raise RuntimeError('fixed command failed: '+argv[0])
    return record['stdout']


def vm_mapping(config,directory):
    lines=command([BIN['ps'],'-C','vmware-vmx','-C','vmnet-natd','-o','pid=,comm=,args='],directory,'ps').splitlines()
    vms=[];nats=[]
    for line in lines:
        parts=line.split(None,2)
        if len(parts)!=3:raise RuntimeError('process mapping malformed')
        if parts[1]=='vmware-vmx':vms.append(parts)
        elif parts[1]=='vmnet-natd':nats.append(parts)
    if len(vms)!=1 or len(nats)!=1 or nats[0][0]!=str(config['natd_pid']):raise RuntimeError('VM/NAT not unique')
    if config['vmx_path'] not in shlex.split(vms[0][2]):raise RuntimeError('actual VMX argv mismatch')
    vmx={}
    for line in Path(config['vmx_path']).read_text().splitlines():
        match=re.match(r'^\s*([\w.]+)\s*=\s*"(.*)"\s*$',line)
        if match:vmx[match[1].lower()]=match[2]
    enabled=sorted(k[:-8] for k,v in vmx.items() if re.fullmatch(r'ethernet\d+\.present',k) and v.lower()=='true')
    if enabled!=['ethernet0'] or vmx.get('ethernet0.connectiontype')!='nat':raise RuntimeError('all NICs must be approved vmnet8 NAT')
    mac=vmx.get('ethernet0.generatedaddress',vmx.get('ethernet0.address','')).lower()
    if mac!=config['target']['mac'].lower():raise RuntimeError('actual VMX MAC mismatch')
    if re.sub(r'[\s-]','',vmx.get('uuid.bios','')).lower() not in ('564de0b3b23d3d9f4d523ec22c4cfdc0','b3e04d563db29f3d4d523ec22c4cfdc0'):raise RuntimeError('actual VMX UUID mismatch')
    links=json.loads(command([BIN['ip'],'-j','link'],directory,'links'))
    own=[r for r in links if r.get('ifname')=='vmnet8']
    if len(own)!=1 or own[0].get('master') is not None or 'UP' not in own[0].get('flags',[]):raise RuntimeError('vmnet8 mapping/bridge unknown')
    if own[0].get('xdp'):
        raise RuntimeError('XDP attachment unsupported')
    for direction in ('ingress','egress'):
        filters=json.loads(command([BIN['tc'],'-j','filter','show','dev','vmnet8',direction],directory,'tc-'+direction))
        if filters!=[]:raise RuntimeError('tc bypass unsupported')
    addresses=json.loads(command([BIN['ip'],'-j','addr','show','dev','vmnet8'],directory,'addresses'))
    actual={a['local'] for r in addresses for a in r.get('addr_info',[])}
    if not {config['target']['host_ipv4'],config['target']['host_link_local']}<=actual:raise RuntimeError('host management addresses mismatch')
    return {'matching_vm':1,'vmnet8_users':1,'all_nics_mapped':True,'bypasses':[],
            'vm_process':{'pid':int(vms[0][0]),'vmx_sha256':sha(Path(config['vmx_path']).read_bytes())},
            'interface':own[0]}


def nft_script(config):
    t=config['target'];mac=t['mac'];g=t['guest_ipv4'];h=t['host_ipv4'];ll=t['host_link_local']
    sn=str(ipaddress.IPv6Address(int(ipaddress.IPv6Address('ff02::1:ff00:0'))|(int(ipaddress.IPv6Address(ll))&0xffffff)))
    rows=['table inet '+TABLE+' {']
    for name,typ in [('tcp_drop4','ipv4_addr'),('tcp_drop6','ipv6_addr')]:
        rows+=['set '+name+' { type '+typ+' . inet_service . '+typ+' . inet_service; flags dynamic,timeout; timeout 60s; size 4096; counter; }']
    rows+=['chain prerouting { type filter hook prerouting priority -150; policy accept;']
    for typ,dst in [('nd-neighbor-solicit',sn),('nd-neighbor-advert',ll)]:
        rows+=['iifname "vmnet8" ether saddr '+mac+' meta l4proto ipv6-icmp ip6 hoplimit 255 ip6 daddr '+dst+' icmpv6 type '+typ+' accept']
    for port in PORTS:
        rows+=['iifname "vmnet8" ether saddr '+mac+' meta l4proto tcp ip saddr '+g+' ip daddr '+h+' tcp sport '+str(port)+' ct direction reply ct state established ct original ip saddr '+h+' ct original ip daddr '+g+' ct original protocol tcp ct original proto-dst '+str(port)+' ct original proto-src 1024-65535 tcp dport 1024-65535 accept']
    for proto,name in [('ip','tcp_drop4'),('ip6','tcp_drop6')]:
        rows+=['iifname "vmnet8" meta nfproto '+('ipv4' if proto=='ip' else 'ipv6')+' meta l4proto tcp update @'+name+' { '+proto+' saddr . tcp sport . '+proto+' daddr . tcp dport timeout 60s counter }']
    rows+=['iifname "vmnet8" counter drop','}','}','']
    return '\n'.join(rows)


def normalize_rules(value):
    if isinstance(value,list):return [normalize_rules(x) for x in value]
    if isinstance(value,dict):return {k:({} if k=='counter' else normalize_rules(v)) for k,v in value.items() if k not in ('handle','expires','packets','bytes','metainfo') and not (k=='elem' and 'name' in value and 'type' in value)}
    return value


def spawn(spec,directory,tag):
    # Root never imports the business application. All descriptors/groups are
    # closed before the ordinary interpreter reads any project code.
    if sha(Path(spec['script']).read_bytes())!=spec['script_sha256']:raise RuntimeError('ordinary script drift')
    out=open(Path(directory)/(tag+'.stdout'),'xb');err=open(Path(directory)/(tag+'.stderr'),'xb')
    user=pwd.getpwuid(spec['uid'])
    env={'PATH':'/usr/sbin:/usr/bin','HOME':user.pw_dir,'USER':user.pw_name,'LANG':'C.UTF-8','FAKENET_EGRESS_FIXTURE_DIR':str(directory)}
    child=subprocess.Popen([spec['python'],spec['script'],*spec['args']],stdin=subprocess.DEVNULL,stdout=out,stderr=err,
                           env=env,cwd=user.pw_dir,close_fds=True,user=spec['uid'],group=spec['gid'],extra_groups=[],start_new_session=True)
    out.close();err.close();return child


def current_nat(config):
    value=proc(config['natd_pid'])
    if value['birth_ticks']!=config['natd_birth_ticks'] or value['comm']!='vmnet-natd':raise RuntimeError('NAT birth/name mismatch')
    # Workstation's Linux daemon does not advertise its PID file in argv.
    # Bind its fixed vmnet8 configuration and kernel birth identity first;
    # then stable-read the canonical root-owned runtime file. Never infer a
    # PID path from an arbitrary argv suffix or trust a bare file PID alone.
    argv=value.get('argv')
    if argv!=['/usr/bin/vmnet-natd','-s','6','-m',
              '/etc/vmware/vmnet8/nat.mac','-c',
              '/etc/vmware/vmnet8/nat/nat.conf']:
        raise RuntimeError('NAT vmnet8 argv identity mismatch')
    pid=read_root('/run/vmnet-natd-8.pid')
    if type(pid) is not int or pid!=value['pid']:
        raise RuntimeError('NAT pidfile identity mismatch')
    return value


def validate_request(value,config,now=None):
    now=time.time() if now is None else now
    if not isinstance(value,dict) or set(value)!={'schema','version','command_id','phase','challenge'}:raise RuntimeError('strict request required')
    if value['schema']!=REQUEST_SCHEMA or type(value['version']) is not int or value['version']!=1:raise RuntimeError('request version mismatch')
    if value['command_id'] not in config['commands'] or value['phase'] not in ('pre','final'):raise RuntimeError('request identity invalid')
    if not isinstance(value['challenge'],str) or not re.fullmatch('[0-9a-f]{32,128}',value['challenge']):raise RuntimeError('challenge invalid')
    if not config['window_start']<=now<=config['window_end']:raise RuntimeError('lease expired')
    return value


def collect_facts(config,directory,producer,held_pidfd):
    network=vm_mapping(config,directory)
    nat=current_nat(config)
    stopped=bool(nat['thread_states']) and all(s in ('T','t') for s in nat['thread_states'])
    rules=json.loads(command([BIN['nft'],'-j','list','ruleset'],directory,'ruleset'))
    return {'target':config['target'],'network':network,
            'natd':{**nat,'state':'stopped' if stopped else 'running','all_threads_stopped':stopped,'pidfd_identity':held_pidfd is not None},
            'ruleset':rules,'observer_identity':producer}


def check_quiescence(config,directory):
    checker=spawn(config['quiescence_checker'],directory,'cleanup-check-'+uuid.uuid4().hex)
    try:code=checker.wait(timeout=12)
    except subprocess.TimeoutExpired:
        os.killpg(checker.pid,signal.SIGKILL);checker.wait();raise RuntimeError('cleanup checker timeout; isolation retained')
    # Exit zero is insufficient: the reviewed ordinary script publishes a
    # root-readable report at its fixed stdout, checked below by its caller.
    if code:raise RuntimeError('guest cleanup not confirmed; isolation retained')
    name=Path(checker.args[1]).name
    # The checker must implement the fixed, independently queried cleanup ABI.
    if name!='fakenet_egress_guest_control.py':raise RuntimeError('unsupported cleanup checker; isolation retained')
    outputs=sorted(Path(directory).glob('cleanup-check-*.stdout'),key=lambda p:p.stat().st_mtime_ns)
    data=json.loads(outputs[-1].read_text())
    if (data.get('schema')!='fakenetng.guest-quiescence.v1' or data.get('vm_uuid')!=config['target']['vm_uuid'] or data.get('boot_id')!=config['target']['boot_id'] or data.get('command_ids')!=config['commands']):raise RuntimeError('cleanup identity mismatch; isolation retained')
    if data.get('engine_state')!='stopped' or data.get('run_id') is not None:raise RuntimeError('engine still active')
    if not isinstance(data.get('process_queries'),list) or not data['process_queries']:raise RuntimeError('actual process queries missing')
    if any(r.get('current_instance') is not None for r in data['process_queries']):raise RuntimeError('owned probe/candidate still live')
    if data.get('remaining_guest_changes')!=[] or data.get('service_restored') is not True:raise RuntimeError('guest restoration not confirmed')


def recover(state_path,config,directory,fd=None):
    state=read_root(state_path)
    if state.get('config_sha256')!=sha(config) or state.get('host_boot')!=proc(os.getpid())['boot_id']:raise RuntimeError('recovery identity mismatch')
    check_quiescence(config,directory)
    live=current_nat(config)
    if live['birth_ticks']!=state['nat_before']['birth_ticks']:raise RuntimeError('NAT PID reused')
    if live.get('argv')!=state['nat_before'].get('argv'):raise RuntimeError('NAT argv changed')
    table=json.loads(command([BIN['nft'],'-j','list','table','inet',TABLE],directory,'recovery-table'))
    if sha(normalize_rules(table))!=state.get('table_semantic_sha256'):raise RuntimeError('owned table drift; isolation retained')
    own=fd is None
    if own:fd=os.pidfd_open(config['natd_pid'])
    try:
        current_nat(config)  # after opening pidfd, before any signal
        signal.pidfd_send_signal(fd,signal.SIGCONT)
        stop=time.monotonic()+2
        while time.monotonic()<stop:
            live=current_nat(config)
            if all(s not in ('T','t') for s in live['thread_states']):break
            time.sleep(.02)
        else:raise RuntimeError('NAT did not resume; isolation retained')
        # Query the control channels again while final drop remains installed.
        check_quiescence(config,directory)
        command([BIN['nft'],'delete','table','inet',TABLE],directory,'delete-owned-table')
        state['stage']='recovered';state['ended_at']=time.time();atomic(state_path,state,0o600)
    finally:
        if own:os.close(fd)


def preflight_rules(parsed):
    entries=parsed.get('nftables') if isinstance(parsed,dict) else None
    if not isinstance(entries,list):raise RuntimeError('complete ruleset required')
    earlier=set()
    for entry in entries:
        if 'flowtable' in entry:raise RuntimeError('flowtable bypass unsupported')
        chain=entry.get('chain')
        if chain and chain.get('hook') in ('ingress','prerouting'):
            priority=chain.get('prio')
            if not isinstance(priority,int):raise RuntimeError('unknown hook priority')
            if chain['hook']=='ingress' or priority<=-150:
                earlier.add((chain.get('family'),chain.get('table'),chain.get('name')))
    for entry in entries:
        rule=entry.get('rule')
        if not rule or (rule.get('family'),rule.get('table'),rule.get('chain')) not in earlier:continue
        statements=rule.get('expr')
        if not isinstance(statements,list) or not statements or statements[-1]!={'drop':None}:raise RuntimeError('unproven earlier path')
        if any(set(statement) not in ({'match'},{'counter'},{'drop'}) for statement in statements):raise RuntimeError('earlier rewrite/jump unsupported')


def run(config_path):
    if os.geteuid()!=0:raise RuntimeError('root required')
    config=load_config(config_path,True)
    if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
        raise RuntimeError('pidfd capability required before creating fixture')
    if Path(config['quiescence_checker']['script']).name!='fakenet_egress_guest_control.py':
        raise RuntimeError('fixed guest quiescence checker required before mutation')
    if not config['window_start']<=time.time()<config['window_end']:raise RuntimeError('window inactive')
    directory=Path(tempfile.mkdtemp(prefix='fakenet-egress-',dir='/run'));os.chmod(directory,0o755)
    (directory/'responses').mkdir(mode=0o755);(directory/'responses/.keep').touch(mode=0o644)
    os.mkfifo(directory/'request.fifo',0o622);os.chmod(directory/'request.fifo',0o622)
    owner=proc(os.getpid());lease=uuid.uuid4().hex;producer={k:owner[k] for k in ('pid','birth_ticks','boot_id')}
    producer.update(script_sha256=sha(Path(__file__).read_bytes()),lease_id=lease,window_start=config['window_start'],window_end=config['window_end'])
    nat=current_nat(config);vm_mapping(config,directory)
    fd=os.pidfd_open(config['natd_pid']);current_nat(config)
    state={'schema':'fakenetng.fixture-state.v2','config_sha256':sha(config),'config':config,'nat_before':nat,'host_boot':owner['boot_id'],'stage':'intent','directory':str(directory)}
    state_path=directory/'state.json';atomic(state_path,state,0o600)
    fifo=os.open(directory/'request.fifo',os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC)
    child=None;installed=False;applied=False;stop_requested=False
    def stop(signum,frame):
        nonlocal stop_requested
        stop_requested=True
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(sig,stop)
    try:
        # Exact owner table must not exist. Do not treat arbitrary nft failure as absence.
        rules=json.loads(command([BIN['nft'],'-j','list','ruleset'],directory,'before'))
        preflight_rules(rules)
        if any(e.get('table',{}).get('family')=='inet' and e.get('table',{}).get('name')==TABLE for e in rules.get('nftables',[])):raise RuntimeError('owned table already exists')
        script=directory/'rules.nft';script.write_text(nft_script(config));os.chmod(script,0o600)
        command([BIN['nft'],'-c','-f',str(script)],directory,'nft-check')
        # Persisted intent precedes every change. Atomic nft transaction creates only this table.
        state['stage']='installing';atomic(state_path,state,0o600)
        command([BIN['nft'],'-f',str(script)],directory,'nft-apply');installed=True
        table=json.loads(command([BIN['nft'],'-j','list','table','inet',TABLE],directory,'owned-table'))
        state['table_semantic_sha256']=sha(normalize_rules(table));state['stage']='stopping-nat';atomic(state_path,state,0o600)
        current_nat(config);signal.pidfd_send_signal(fd,signal.SIGSTOP)
        applied=True;until=time.monotonic()+2
        while time.monotonic()<until:
            live=current_nat(config)
            if live['thread_states'] and all(s in ('T','t') for s in live['thread_states']):break
            time.sleep(.02)
        else:raise RuntimeError('NAT thread stop unknown; isolation retained')
        state['stage']='active';atomic(state_path,state,0o600)
        atomic(directory/'producer.json',{'schema':'fakenetng.host-observer-producer.v2',**producer,'uid':0})
        print(json.dumps({'directory':str(directory),'state':str(state_path),'recover':['python3',str(Path(__file__).absolute()),'recover','--config',str(Path(config_path).absolute()),'--state',str(state_path),'--confirm','local-fixture-only']}),flush=True)
        child=spawn(config['runner'],directory,'runner');buffer=b'';seen=set();requests=0
        while time.time()<config['window_end'] and not stop_requested and child.poll() is None:
            ready,_,_=select.select([fifo],[],[],min(.1,max(0,config['window_end']-time.time())))
            if not ready:continue
            buffer+=os.read(fifo,4096)
            if len(buffer)>4096:buffer=b'';continue
            if b'\n' not in buffer:continue
            line,buffer=buffer.split(b'\n',1)
            try:
                req=validate_request(json.loads(line),config)
                if req['challenge'] in seen or requests>=128:raise RuntimeError('request replay/limit')
                requests+=1;seen.add(req['challenge'])
                facts=collect_facts(config,directory,producer,fd)
                response={'schema':SCHEMA,'command_id':req['command_id'],'phase':req['phase'],'challenge':req['challenge'],'producer':{'uid':0,**producer},'script_sha256':producer['script_sha256'],'collected_at':time.time(),'facts':facts}
                atomic(directory/'responses'/(req['challenge']+'.json'),response)
            except Exception as exc:atomic(directory/('rejected-'+uuid.uuid4().hex+'.json'),{'error':str(exc)})
        if child.poll() is None:
            os.killpg(child.pid,signal.SIGTERM)
            try:child.wait(timeout=2)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
        state['runner_exit']=child.returncode;state['stage']='recovering';atomic(state_path,state,0o600)
        recover(state_path,config,directory,fd)
        return child.returncode
    except BaseException as exc:
        may_have_changed=installed or state.get('stage') in ('installing','stopping-nat','active','recovering')
        state['stage']='recovery_required' if may_have_changed else 'not_applied';state['error']=str(exc);state['nat_stop_attempted']=applied
        atomic(state_path,state,0o600)
        print(json.dumps({'status':'RECOVERY_REQUIRED' if may_have_changed else 'NOT_APPLIED','state':str(state_path),'reason':str(exc)}),flush=True)
        # No rollback that might release the last boundary after an unknown stop.
        raise
    finally:
        if child is not None and child.poll() is None:
            os.killpg(child.pid,signal.SIGKILL);child.wait()
        os.close(fifo);os.close(fd)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('command',choices=('plan','run','recover'));parser.add_argument('--config',required=True);parser.add_argument('--state');parser.add_argument('--confirm');args=parser.parse_args(argv)
    if args.command=='plan':
        cfg=load_config(args.config);print(json.dumps({'mutations_executed':False,'nft':nft_script(cfg),'window':[cfg['window_start'],cfg['window_end']]}));return 0
    if args.confirm!='local-fixture-only':raise RuntimeError('explicit reviewed authorization required')
    if args.command=='run':return run(args.config)
    if os.geteuid()!=0 or not args.state:raise RuntimeError('root and original state required')
    cfg=load_config(args.config,True);recover(args.state,cfg,Path(args.state).parent);return 0


if __name__=='__main__':raise SystemExit(main())
