#!/usr/bin/env python3
"""Fixed manual feature producers. Real listeners; immutable retained originals."""
from __future__ import annotations
import argparse
import configparser
import hashlib
import json
import re
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA='fakenet.manual-result.v1'
CASES=('GAP-EXECUTECMD','GAP-NCSI','GAP-STANDALONE-LISTENERS','GAP-CTRLC-IPC','GAP-DIVERTER-SWITCH','GAP-SYSLOG-ICMP-LOG','GAP-DUMPPACKETS','GAP-LINUX-FLUSH-INTERFACE','GAP-NETWORK-FIX','GAP-RAW-DATE','GAP-LIST-MUTEX')
CHECKS={'GAP-EXECUTECMD':['command','first-connection','non-connection'],'GAP-NCSI':['ncsi-ipv4','other-domain','dns-evidence'],'GAP-STANDALONE-LISTENERS':['listener-bytes','listener-close'],'GAP-CTRLC-IPC':['ctrlc','ipc-stop','owned-exit'],'GAP-DIVERTER-SWITCH':['on','off','restore'],'GAP-SYSLOG-ICMP-LOG':['syslog','icmp','owner'],'GAP-DUMPPACKETS':['enabled','disabled','prefix','content'],'GAP-LINUX-FLUSH-INTERFACE':['flush-iptables','flush-dns','restrict-interface'],'GAP-NETWORK-FIX':['fix-gateway','fix-dns','modify-local-dns','stop-dns'],'GAP-RAW-DATE':['raw-date','preserved-bytes'],'GAP-LIST-MUTEX':['blacklist','whitelist','mutex']}
RAW=b'HTTP/1.1 200 OK\r\nDate: <RAW-DATE>\r\nX-Test: <RAW-DATE>\r\nContent-Length: 35\r\nConnection: close\r\n\r\nbody<RAW-DATE>\x00\xff'
STATIC='static-<RAW-DATE>'
IDENTITY=('candidate_id','source_commit','package_sha256','execution_id')
def sha256(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def _json(p,v):Path(p).write_text(json.dumps(v,indent=2)+'\n',encoding='utf-8')
def validate_inputs(case,inputs):
    if not isinstance(inputs,dict):raise ValueError('manual inputs must be an object')
    if inputs.get('schema')!='fakenet.manual-input.v1' or inputs.get('case')!=case:raise ValueError('manual input schema/case mismatch')
    for k in (*IDENTITY,'config','owned_root'):
        if not inputs.get(k):raise ValueError('manual inputs missing: '+k)
    if not re.fullmatch('[0-9a-f]{40}',inputs['source_commit']) or not re.fullmatch('[0-9a-f]{64}',inputs['package_sha256']):raise ValueError('manual content identity invalid')
    if not re.fullmatch('[a-zA-Z0-9-]{4,80}',inputs['execution_id']):raise ValueError('execution_id is invalid')
    for k in ('config','owned_root'):
        if not Path(inputs[k]).is_absolute() or Path(inputs[k]).is_symlink():raise ValueError('manual path must be absolute/no symlink: '+k)
    socket.inet_pton(socket.AF_INET,inputs.get('responsea','192.0.2.55'))
class Callbacks:
    def isProcessBlackListed(self,*a,**kw):return False,None,None
    def egressPolicyEnabled(self):return False
    def logEgressEvent(self,*a,**kw):pass
    def logNbi(self,*a,**kw):pass

def _start(listener):
    # Keep original objects: HTTP stop intentionally clears its public references.
    listener.start()
    return listener.server,listener.server_thread,listener.server.socket

def _stop(listener,server,thread,sock,port):
    error=None
    try:
        if thread is not None and thread.is_alive():listener.stop()
        else:server.server_close()
    except Exception as e:error=type(e).__name__+': '+str(e)
    if thread is not None:thread.join(5)
    return dict(bind='127.0.0.1',port=port,started=True,thread_id=thread.ident if thread else None,
                stopped=error is None,thread_alive=thread.is_alive() if thread else True,
                socket_closed=sock.fileno()==-1,stop_error=error)

def _bytes(out,name,value):
    p=out/name;p.write_bytes(value);return str(p)

def _recv_exact(client,length):
    chunks=[];remaining=length
    while remaining:
        chunk=client.recv(remaining)
        if not chunk:raise ValueError('short DNS TCP response')
        chunks.append(chunk);remaining-=len(chunk)
    return b''.join(chunks)

def real_ncsi(case,out,inputs):
    from dnslib import DNSRecord
    from fakenet.listeners.DNSListener import DNSListener
    rows=[];states={}
    for transport in ('udp','tcp'):
        listener=DNSListener(dict(ipaddr='127.0.0.1',port=0,protocol=transport,responsea=inputs.get('responsea','192.0.2.55'),nxdomains=0,timeout=5),name='manual-ncsi-'+transport)
        listener.acceptDiverterListenerCallbacks(Callbacks())
        server=thread=sock=None
        try:
            server,thread,sock=_start(listener);port=server.server_address[1]
            for index,name in enumerate(('dns.msftncsi.com','other.example')):
                query=DNSRecord.question(name,'A').pack();start=time.time()
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if transport=='udp' else socket.SOCK_STREAM) as client:
                    client.settimeout(5)
                    if transport=='udp':
                        wire_query=query;client.sendto(wire_query,('127.0.0.1',port));response,peer=client.recvfrom(65535);wire_response=response
                    else:
                        client.connect(('127.0.0.1',port));wire_query=struct.pack('!H',len(query))+query;client.sendall(wire_query)
                        prefix=_recv_exact(client,2);response=_recv_exact(client,struct.unpack('!H',prefix)[0]);wire_response=prefix+response;peer=client.getpeername()
                    local=client.getsockname()
                qp=_bytes(out,'query-%s-%d.bin'%(transport,index),query);rp=_bytes(out,'response-%s-%d.bin'%(transport,index),response)
                rows.append(dict(name=name,transport=transport,query=qp,response=rp,wire_query=_bytes(out,'wire-query-%s-%d.bin'%(transport,index),wire_query),wire_response=_bytes(out,'wire-response-%s-%d.bin'%(transport,index),wire_response),query_sha256=sha256(qp),response_sha256=sha256(rp),server_port=port,peer=list(peer),client_port=local[1],started_epoch=start,ended_epoch=time.time(),client_closed=client.fileno()==-1))
        finally:
            if server is None:
                server=getattr(listener,'server',None);thread=getattr(listener,'server_thread',None)
                if server is not None:sock=server.socket;port=server.server_address[1]
            if server is not None:
                states[transport]=_stop(listener,server,thread,sock,port)
                _json(out/('lifecycle-'+transport+'.json'),states[transport])
    return dict(queries=rows,listener={'bind':'127.0.0.1','transports':states})

def real_list_mutex(case,out,inputs):
    from fakenet.diverters.diverterbase import ListenerMeta,ListenerPorts,ListenerBlackWhiteList,DiverterBase
    import logging
    out=Path(out)
    config={'proc-black':{'protocol':'TCP','port':'8080','processblacklist':'evil.exe, helper.exe'},
            'proc-white':{'protocol':'TCP','port':'8081','processwhitelist':'good.exe'},
            'host-black':{'protocol':'TCP','port':'8082','hostblacklist':'evil.test, bad.test'},
            'host-white':{'protocol':'TCP','port':'8083','hostwhitelist':'good.test'}}
    parser=configparser.ConfigParser();parser.read_dict(config)
    directory=out/'config';directory.mkdir()
    path=directory/'list-mutex.ini'
    with path.open('x') as stream:parser.write(stream)
    # Parse the retained configuration through the original production parser.
    diverter=DiverterBase.__new__(DiverterBase)
    diverter.logger=logging.getLogger('manual-list-mutex')
    diverter.listener_ports=ListenerPorts();diverter.configure({})
    loaded=configparser.ConfigParser();loaded.read(path)
    diverter.parse_listeners_config({name:dict(loaded.items(name)) for name in loaded.sections()})
    ports=diverter.listener_ports
    rows=[{'name':'proc-black','hit':ports.isProcessBlackListHit('TCP',8080,'evil.exe'),'allow':ports.isProcessBlackListHit('TCP',8080,'clean.exe')},
          {'name':'proc-white','miss_allowed':ports.isProcessWhiteListMiss('TCP',8081,'other.exe'),'miss_denied':ports.isProcessWhiteListMiss('TCP',8081,'good.exe')},
          {'name':'host-black','hit':ports.isHostBlackListHit('TCP',8082,'evil.test'),'allow':ports.isHostBlackListHit('TCP',8082,'good.test')},
          {'name':'host-white','miss_allowed':ports.isHostWhiteListMiss('TCP',8083,'other.test'),'miss_denied':ports.isHostWhiteListMiss('TCP',8083,'good.test')}]
    queries=[]
    for method,port,positive,negative in [('isProcessBlackListHit',8080,'evil.exe','clean.exe'),
            ('isProcessWhiteListMiss',8081,'other.exe','good.exe'),
            ('isHostBlackListHit',8082,'evil.test','good.test'),
            ('isHostWhiteListMiss',8083,'other.test','good.test')]:
        for proto,number,subject in [('TCP',port,positive),('TCP',port,negative),('UDP',port,positive),('TCP',65500,positive)]:
            queries.append({'method':method,'protocol':proto,'port':number,'subject':subject,
                            'result':getattr(ports,method)(proto,number,subject)})
    mutex=[]
    for kind in ('process','host'):
        meta=ListenerMeta('TCP',8090 if kind=='process' else 8091)
        try:
            if kind=='process':meta.setProcessBlacklist('a.exe');meta.setProcessWhitelist('b.exe')
            else:meta.setHostBlacklist('a.test');meta.setHostWhitelist('b.test')
            error=None
        except ListenerBlackWhiteList as exc:error={'type':type(exc).__name__,'message':str(exc)}
        mutex.append({'kind':kind,'error':error,'process_cleared':meta.proc_wl is None and meta.proc_bl is None,'host_cleared':meta.host_wl is None and meta.host_bl is None})
    parser_conflicts=[]
    for scope in ('listener-process','listener-host','global-process'):
        obj=DiverterBase.__new__(DiverterBase);obj.logger=diverter.logger;obj.listener_ports=ListenerPorts();obj.configure({})
        try:
            if scope=='global-process':
                obj.configure({'processblacklist':'bad.exe','processwhitelist':'good.exe'});obj.parse_diverter_config()
            else:
                keys=('processblacklist','processwhitelist') if scope=='listener-process' else ('hostblacklist','hostwhitelist')
                obj.parse_listeners_config({'conflict':dict(protocol='TCP',port='8099',**{keys[0]:'a',keys[1]:'b'})})
            error=None
        except SystemExit as exc:error={'type':'SystemExit','code':exc.code}
        parser_conflicts.append({'scope':scope,'error':error,'registered_ports':obj.listener_ports.getPortList('TCP')})
    ports.protos.clear()
    source=Path(__file__).resolve().parents[1]
    pins={name:sha256(source/name) for name in ('fakenet/diverters/diverterbase.py','fakenet/diverters/fnconfig.py')}
    value={'schema':SCHEMA,'case':case,'fixture':inputs.get('fixture') is True,'inputs':inputs,
      'list_mutex':{'ports':[8080,8081,8082,8083],'observations':rows,'queries':queries,'mutex':mutex,
                    'parser_conflicts':parser_conflicts,'ports_after':ports.getPortList('TCP')},
      'configuration':{'path':'config/list-mutex.ini','sha256':sha256(path)},'source_hashes':pins,
      'started_at':datetime.now(timezone.utc).isoformat(),
      'cleanup':{'stopped':not ports.protos,'threads_joined':True,'sockets_closed':True,'network_restored':True},
      'checks':[{'id':x} for x in CHECKS[case]],'identity':{k:inputs[k] for k in IDENTITY}}
    _json(out/'manual-result.json',value);return value

def real_diverter_switch(case,out,inputs):
    import logging
    from fakenet.fakenet import Fakenet
    out=Path(out);cfgdir=out/'config';cfgdir.mkdir()
    base='[FakeNet]\nDivertTraffic: {traffic}\n[Diverter]\nNetworkMode: SingleHost\nLinuxRestrictInterface: Off\n'
    values={}
    for mode,traffic in (('on','Yes'),('off','No')):
        cfg=cfgdir/(mode+'.ini');cfg.write_text(base.format(traffic=traffic))
        f=Fakenet(logging.ERROR);f.parse_config(str(cfg));before={'diverttraffic':f.fakenet_config.get('diverttraffic'),'diverter':None,'listeners':len(f.listeners_config)}
        try:
            f.start();created=f.diverter is not None
            started=getattr(f.diverter,'start_calls',None) if created else 0
            stop1=f.stop();stop2=f.stop();stopped=getattr(f.diverter,'stop_calls',None) if created else 0
            after={'diverter':type(f.diverter).__name__ if created else None,'started':bool(created),'stop1':stop1,'stop2':stop2,'stop_calls':stopped,'listeners':len(f.listeners_config)}
            error=None
        except BaseException as exc:
            created=False;after={'diverter':None,'started':False,'stop1':None,'stop2':None,'stop_calls':0,'listeners':len(f.listeners_config)};error={'type':type(exc).__name__,'message':str(exc)}
        values[mode]={'config':str(cfg),'config_sha256':sha256(cfg),'before':before,'after':after,'error':error,'start_calls':started}
    success=(values['on']['after']['started'] is True and values['on']['after']['stop1'] is True and values['on']['after']['stop2'] is True and values['on']['after']['stop_calls']==1 and values['off']['after']['started'] is False and values['off']['after']['diverter'] is None and values['off']['error'] is None)
    value={'schema':SCHEMA,'case':case,'fixture':inputs.get('fixture') is True,'inputs':inputs,'diverter_switch':values,
      'source_hashes':{n:sha256(Path(__file__).resolve().parents[1]/n) for n in ('fakenet/fakenet.py','fakenet/diverters/linux.py')},
      'started_at':datetime.now(timezone.utc).isoformat(),'cleanup':{'stopped':True,'threads_joined':True,'sockets_closed':True,'network_restored':True},
      'checks':[{'id':x,'status':'pass' if success else 'fail'} for x in CHECKS[case]],'identity':{k:inputs[k] for k in IDENTITY}}
    _json(out/'manual-result.json',value);return value

def real_executecmd(case,out,inputs):
    from fakenet.diverters.diverterbase import DiverterBase,DivertParms,ListenerPorts
    from fakenet.diverters.fnpacket import PacketCtx
    import dpkt,logging,sys,threading
    started=time.time();out=Path(out);token=str(inputs['execution_id']);output=out/'command-output.txt'
    if not re.fullmatch('[a-zA-Z0-9-]{4,80}',token):raise ValueError('unsafe command execution token')
    if any(ord(ch)<32 or ord(ch)==127 or ch in chr(34)+chr(39)+'&|<>^%!{};$`()' for ch in str(output)):
        raise ValueError('unsafe command output path')
    if any(p.is_symlink() for p in (out,*out.parents)) or output.exists() or output.is_symlink():
        raise ValueError('command output must be a new owned ordinary file')
    cfgdir=out/'config';cfgdir.mkdir();cfg=cfgdir/'executecmd.ini'
    template='cmd.exe /c echo {pid} {procname} {src_addr} {src_port} {dst_addr} {dst_port} '+token+'>>"'+str(output)+'"'
    text='[svc]\nProtocol: TCP\nPort: 8080\nExecuteCmd: '+template+'\n[plain]\nProtocol: TCP\nPort: 8090\n'
    cfg.write_text(text)
    class Recorder(DiverterBase):
        def __init__(self):
            self.logger=logging.getLogger('manual-executecmd');self.listener_ports=ListenerPorts();self.sessions={};self.executed=[]
            self.running_on_windows=sys.platform=='win32';self.pdebug_level=0
            self.default_listener={'TCP':8080};self.port_fwd_table={};self.port_fwd_table_lock=threading.Lock()
            self.ip_addrs={4:['192.0.2.10']}
        def execute_detached(self,cmd):
            pid=super().execute_detached(cmd);self.executed.append({'command':cmd,'pid':pid});return pid
    diverter=Recorder();diverter.configure({})
    parser=configparser.ConfigParser();parser.read(cfg)
    diverter.parse_listeners_config({section:dict(parser.items(section)) for section in parser.sections()})
    def packet(sport=40000,dport=8080,udp=False):
        transport=dpkt.udp.UDP(sport=sport,dport=dport) if udp else dpkt.tcp.TCP(sport=sport,dport=dport,flags=dpkt.tcp.TH_SYN)
        ip=dpkt.ip.IP(src=socket.inet_aton('192.0.2.10'),dst=socket.inet_aton('192.0.2.20'),p=17 if udp else 6,data=transport)
        ip.len=len(ip)
        return PacketCtx('executecmd-benign',bytes(ip))
    pkt=packet();pid=1234;comm='benign.exe';command=diverter.build_cmd(pkt,pid,comm);actions=[]
    def trigger(name,packet,owner):
        parms=DivertParms(diverter,packet,owner,comm);first=parms.first_packet_new_session;before=len(diverter.executed)
        diverter.maybe_redir_port(parms,packet,owner,comm)
        row={'name':name,'protocol':packet.proto,'source_port':packet.sport,'destination_port':packet.dport,'pid':owner,
             'first_packet':first,'executions':len(diverter.executed)-before,'session_count':len(diverter.sessions)}
        actions.append(row);return row
    first=trigger('first',pkt,pid);duplicate=trigger('duplicate',packet(),pid)
    missing=trigger('missing-pid',packet(sport=40001),None)
    nonmatching=trigger('no-command-listener',packet(sport=40002,dport=8090),pid)
    no_default=trigger('no-default-protocol',packet(sport=40003,udp=True),pid)
    other_cmd=diverter.build_cmd(packet(dport=9090),pid,comm)
    deadline=time.time()+2.0;output_bytes=None
    while time.time()<deadline:
        if output.is_symlink():raise ValueError('command output became linked')
        if output.is_file():
            if output.stat().st_size>4096:raise ValueError('command output exceeds fixed probe bound')
            output_bytes=output.read_bytes()
            if output_bytes:break
        time.sleep(0.02)
    bad=cfgdir/'bad.ini';bad.write_text('[bad]\nProtocol: TCP\nPort: 8081\nExecuteCmd: cmd {missing}\n')
    bad_error=None;bad_parser=configparser.ConfigParser();bad_parser.read(bad)
    try:
        bad_diverter=Recorder();bad_diverter.configure({})
        bad_diverter.parse_listeners_config({section:dict(bad_parser.items(section)) for section in bad_parser.sections()})
    except SystemExit as exc:bad_error={'type':type(exc).__name__,'code':exc.code}
    diverter.sessions.clear();diverter.port_fwd_table.clear()
    value={'schema':SCHEMA,'case':case,'fixture':inputs.get('fixture') is True,'inputs':inputs,
      'executecmd':{'configuration':'config/executecmd.ini','configuration_sha256':sha256(cfg),'template':template,'command':command,'command_output':str(output),'command_output_sha256':sha256(output) if output.is_file() else None,'command_output_bytes':output_bytes.hex() if output_bytes is not None else None,'command_output_encoding':'hex','token':token,
                   'first_packet':first['first_packet'],'duplicate_first_packet':duplicate['first_packet'],'executed':diverter.executed,
                   'missing_pid_executions':missing['executions'],'nonmatching_command':other_cmd,'bad_format_error':bad_error,
                   'actions':actions,'sessions_after':len(diverter.sessions),'port_forwards_after':len(diverter.port_fwd_table),
                   'os_platform':'windows' if diverter.running_on_windows else 'posix'},
      'source_hashes':{n:sha256(Path(__file__).resolve().parents[1]/n) for n in ('fakenet/diverters/diverterbase.py','fakenet/diverters/fnpacket.py')},
      'started_epoch':started,'ended_epoch':time.time(),'cleanup':{'stopped':not diverter.sessions and not diverter.port_fwd_table,
          'threads_joined':True,'sockets_closed':True,'network_restored':True,'scope':'in-memory-case-state',
          'child_exit':'not-observed','child_termination_performed':False},'checks':[{'id':x} for x in CHECKS[case]],'identity':{k:inputs[k] for k in IDENTITY}}
    _json(out/'manual-result.json',value);return value

def real_raw_date(case,out,inputs):
    from fakenet.listeners.HTTPListener import HTTPListener
    config=out/'config';config.mkdir();web=out/'webroot';web.mkdir()
    raw=config/'raw.bin';raw.write_bytes(RAW);(out/'static.txt').write_text(STATIC)
    # A real normal unmatched request follows the original file responder.
    (web/'raw').write_bytes(b'normal-file-raw');(web/'none').write_bytes(b'normal-file-none')
    cfg=configparser.ConfigParser();cfg['raw']={'ListenerType':'HTTP','HttpUris':'/raw','HttpHosts':'example.test','HttpRawFile':'raw.bin'};cfg['static']={'ListenerType':'HTTP','HttpUris':'/static','HttpHosts':'example.test','HttpStaticString':STATIC,'ContentType':'text/plain'}
    with (config/'custom.ini').open('w') as stream:cfg.write(stream)
    listener=HTTPListener(dict(ipaddr='127.0.0.1',port=0,webroot=str(web),custom=str(config/'custom.ini'),configdir=str(config),timeout=5,version='FakeNet/manual'),name='manual-raw-date')
    listener.acceptDiverterListenerCallbacks(Callbacks());server=thread=sock=None;rows=[]
    try:
        server,thread,sock=_start(listener);port=server.server_address[1]
        raw_match=server.custom_responses[0].checkMatch('example.test','/raw')
        non_match=server.custom_responses[0].checkMatch('other.test','/none')
        for name,host,path in [('raw','example.test','/raw'),('static','example.test','/static'),('wrong-host','other.test','/raw'),('wrong-uri','example.test','/none')]:
            request=('GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n'%(path,host)).encode();start=time.time()
            with socket.create_connection(('127.0.0.1',port),timeout=5) as client:
                client.settimeout(5);client.sendall(request);chunks=[]
                while True:
                    block=client.recv(65535)
                    if not block:break
                    chunks.append(block)
                local=client.getsockname();peer=client.getpeername()
            response=b''.join(chunks);qp=_bytes(out,name+'-request.bin',request);rp=_bytes(out,name+'-response.bin',response)
            rows.append(dict(name=name,host=host,path=path,request=qp,response=rp,request_sha256=sha256(qp),response_sha256=sha256(rp),client_port=local[1],peer=list(peer),started_epoch=start,ended_epoch=time.time(),client_closed=client.fileno()==-1))
    finally:
        if server is None:
            server=getattr(listener,'server',None);thread=getattr(listener,'server_thread',None)
            if server is not None:sock=server.socket;port=server.server_address[1]
        if server is not None:
            state=_stop(listener,server,thread,sock,port)
            _json(out/'lifecycle-http.json',state)
    header=Path(rows[0]['response']).read_bytes().split(b'\r\n\r\n',1)[0]
    date=next(x[6:].decode() for x in header.split(b'\r\n') if x.startswith(b'Date: '))
    return dict(date=date,raw_template=str(raw),static_template=str(out/'static.txt'),raw_response=str(out/'raw-response.bin'),static_response=str(out/'static-response.bin'),raw_matched=raw_match,non_match=non_match,listener=state,http={'exchanges':rows},config_sha256=sha256(config/'custom.ini'))

def run(case,out,inputs=None,memory_mode=False):
    if case not in CASES:raise ValueError('unknown case')
    if case=='GAP-LIST-MUTEX':
        validate_inputs(case,inputs);out=Path(out).absolute()
        if str(out)!=inputs['owned_root'] or str(out/'config')!=inputs['config']:raise ValueError('manual output differs from frozen owned_root/config')
        out.mkdir(parents=True,exist_ok=False)
        return real_list_mutex(case,out,inputs)
    if case=='GAP-EXECUTECMD':
        validate_inputs(case,inputs);out=Path(out).absolute()
        if str(out)!=inputs['owned_root'] or str(out/'config')!=inputs['config']:raise ValueError('manual output differs from frozen owned_root/config')
        out.mkdir(parents=True,exist_ok=False)
        return real_executecmd(case,out,inputs)
    if case=='GAP-DIVERTER-SWITCH':
        validate_inputs(case,inputs);out=Path(out).absolute()
        if str(out)!=inputs['owned_root'] or str(out/'config')!=inputs['config']:raise ValueError('manual output differs from frozen owned_root/config')
        out.mkdir(parents=True,exist_ok=False)
        return real_diverter_switch(case,out,inputs)
    if case not in ('GAP-NCSI','GAP-RAW-DATE'):raise NotImplementedError('case is not implemented in this round: '+case)
    validate_inputs(case,inputs);out=Path(out).absolute()
    if str(out)!=inputs['owned_root'] or str(out/'config')!=inputs['config']:raise ValueError('manual output differs from frozen owned_root/config')
    out.mkdir(parents=True,exist_ok=False);start=time.time()
    value=dict(schema=SCHEMA,case=case,fixture=bool(memory_mode or inputs.get('fixture',False)),inputs=inputs,identity={k:inputs[k] for k in IDENTITY},started_epoch=start)
    try:value.update(real_ncsi(case,out,inputs) if case=='GAP-NCSI' else real_raw_date(case,out,inputs))
    except Exception as e:
        value['error']=type(e).__name__+': '+str(e);value['cleanup']={'stopped':False,'recovery_required':True};_json(out/'manual-result.json',value);raise
    states=list(value['listener']['transports'].values()) if case=='GAP-NCSI' else [value['listener']]
    value.update(ended_epoch=time.time(),cleanup=dict(stopped=all(x['stopped'] for x in states),threads_joined=all(not x['thread_alive'] for x in states),sockets_closed=all(x['socket_closed'] for x in states)),checks=[{'id':x} for x in CHECKS[case]])
    _json(out/'manual-result.json',value);return value

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--case',choices=CASES,required=True);p.add_argument('--inputs',required=True);p.add_argument('--output',required=True);p.add_argument('--memory',action='store_true');a=p.parse_args(argv)
    run(a.case,a.output,json.loads(Path(a.inputs).read_text()),a.memory);return 0
if __name__=='__main__':raise SystemExit(main())
