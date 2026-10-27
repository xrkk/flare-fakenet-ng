#!/usr/bin/env python3
"""Fixed Windows process/payload regression; memory mode replaces OS edges only."""
from __future__ import annotations
import argparse
import ast
import configparser
import hashlib
import ipaddress
import json
import logging
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
SCHEMA = 'fakenet.headless-result.v2'
PROCESS_CHECKS = ['identity', 'target-positive', 'non-target-negative', 'owner-bounded', 'budget', 'pcap-restore']
PAYLOAD_CHECKS = ['integrity', 'report', 'reassembly']
PE_BYTES = {'target': b'MZ\x00benign-memory-target', 'non-target': b'MZ\x00benign-memory-negative'}
CONTROL_PROTECTED_TCP_PORTS = ('28787', '28790')


def sha256(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write_json(path, value): Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
def read_json(path): return json.loads(Path(path).read_text(encoding='utf-8'))
def canonical(path): return ntpath.normcase(ntpath.normpath(str(path).removeprefix('\\\\?\\')))


def owner_budget():
    """Derive the burst size from the actual bounded token bucket."""
    path = ROOT/'fakenet/diverters/processredirect.py'
    tree = ast.parse(path.read_text())
    method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_consume_query_budget_locked')
    call = next(n for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'min')
    capacity = int(ast.literal_eval(call.args[0]))
    rate = next(float(n.value) for n in ast.walk(call.args[1]) if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)))
    if not 1 <= capacity <= 64 or not rate > 0: raise ValueError('unsupported owner token bucket contract')
    return {'capacity': capacity, 'refill_per_second': rate, 'burst': capacity + int(rate) + 1, 'burst_window_seconds': 1, 'source_sha256': sha256(path)}


def memory_inputs():
    return {'schema': 'fakenet.headless-input.v2', 'source_ip': '192.168.204.100',
            'target_ip': '192.168.204.1', 'original_ip': '192.0.2.10', 'port': 3585,
            'upstream_dns': '192.168.204.2', 'target_path': 'E:/benign/target.exe',
            'non_target_path': 'E:/benign/negative.exe',
            'target_sha256': hashlib.sha256(PE_BYTES['target']).hexdigest(),
            'non_target_sha256': hashlib.sha256(PE_BYTES['non-target']).hexdigest()}


def validate_inputs(mode, value, selected=None):
    checks = PROCESS_CHECKS if mode == 'process' else PAYLOAD_CHECKS if mode == 'payload' else []
    selected = list(checks) if selected is None else list(selected)
    if not selected or len(set(selected)) != len(selected) or not set(selected) <= set(checks):
        raise ValueError('invalid/empty/duplicate headless selection')
    fields = set(memory_inputs())
    pe_fields={'target_path','non_target_path','target_sha256','non_target_sha256'}
    allowed_sets=[fields] if mode=='process' else [fields,fields-pe_fields]
    if not isinstance(value, dict) or set(value) not in allowed_sets or value.get('schema') != 'fakenet.headless-input.v2':
        raise ValueError('explicit headless inputs required; commands/artifacts are not supported')
    from fakenet.diverters.processredirect import _global_ipv4, _rfc1918_ipv4
    if not _global_ipv4(value['original_ip']) or not _rfc1918_ipv4(value['target_ip']):
        raise ValueError('original A / private sink B does not match core grammar')
    for name in ('source_ip', 'upstream_dns'):
        address = ipaddress.ip_address(value[name])
        if address.version != 4 or address.is_multicast or address.is_unspecified: raise ValueError('invalid '+name)
    if value['source_ip'] == value['target_ip']: raise ValueError('guest and sink must differ')
    if type(value['port']) is not int or not 1024 <= value['port'] <= 65535: raise ValueError('invalid sink port')
    for role in (() if mode=='payload' and 'target_path' not in value else ('target', 'non_target')):
        path = PureWindowsPath(value[role+'_path'])
        if not path.is_absolute() or path.suffix.lower() != '.exe' or ':' in str(path)[2:]: raise ValueError('absolute native PE path required')
        if not re.fullmatch('[0-9a-f]{64}', value[role+'_sha256']): raise ValueError('invalid native PE hash')
    if mode=='process' and (canonical(value['target_path']) == canonical(value['non_target_path']) or value['target_sha256'] == value['non_target_sha256']):
        raise ValueError('target and negative PE identities must differ')
    return [name for name in checks if name in selected]


def config_text(mode, inputs, output, source_root=None):
    def joined(base,*parts):
        return str(PureWindowsPath(base).joinpath(*parts)) if PureWindowsPath(str(base)).is_absolute() else str(Path(base).joinpath(*parts))
    parser = configparser.ConfigParser(interpolation=None); parser.optionxform = str
    template = 'process_redirect_windows.ini' if mode == 'process' else 'domain_takeover_windows.ini'
    parser.read(ROOT/'fakenet/configs'/template, encoding='utf-8-sig')
    d = parser['Diverter']
    tcp_blacklist = [p.strip() for p in d.get('BlackListPortsTCP', '').split(',') if p.strip()]
    for port in ('139',) + CONTROL_PROTECTED_TCP_PORTS:
        if port not in tcp_blacklist: tcp_blacklist.append(port)
    d.update(DumpPackets='Yes', DumpPacketsFilePrefix=joined(output,'capture'),
             ExternalDnsServer=inputs['upstream_dns'], ExternalAllowedDomains='headless.invalid',
             BlackListPortsTCP=','.join(tcp_blacklist), BlackListPortsUDP='67,68,137,138,443,1900,5355')
    if str(inputs['port']) in [p.strip() for p in d['BlackListPortsUDP'].split(',')]: raise ValueError('sink port bypasses policy')
    if mode == 'process':
        d.update(ExternalProcessRedirectEnabled='Yes', ExternalProcessRedirectProtocol='TCP',
                 ExternalProcessRedirectImagePath=inputs['target_path'], ExternalProcessRedirectImageSHA256=inputs['target_sha256'],
                 ExternalProcessRedirectOriginalIPv4=inputs['original_ip'], ExternalProcessRedirectTargetIPv4=inputs['target_ip'])
    else:
        d.update(ExternalTakeoverIPv4=inputs['target_ip'], ExternalTakeoverProbeTCPPorts=str(inputs['port']))
    for section in parser.sections():
        for key, value in list(parser[section].items()):
            if value == 'GetFirstNonLoopback': parser[section][key] = inputs['source_ip']
            elif key in ('ResponseA',) and mode == 'payload': parser[section][key] = inputs['target_ip']
            elif value.startswith('configs/'): parser[section][key] = joined(source_root or ROOT,'fakenet',value)
    from io import StringIO
    stream=StringIO();parser.write(stream);return stream.getvalue()


class NativeBoundary:
    fixture = False
    def __init__(self, output, inputs, mode):
        self.output=Path(output);self.inputs=inputs;self.mode=mode;self.core=None;self.capture_owned=False
    def identities(self):
        from acceptance_runtime import require_target
        require_target({'platform':'windows','hostname':socket.gethostname()})
        if self.mode=='payload':return {}
        import psutil
        masks=[a.netmask for addresses in psutil.net_if_addrs().values() for a in addresses
               if a.family==socket.AF_INET and a.address==self.inputs['source_ip']]
        if len(masks)!=1 or ipaddress.ip_address(self.inputs['target_ip']) not in ipaddress.ip_network(self.inputs['source_ip']+'/'+masks[0],strict=False):
            raise ValueError('B is not on the observed guest interface')
        result={}
        for role, key in [('target','target'),('non-target','non_target')]:
            path=Path(self.inputs[key+'_path'])
            if not path.is_file() or path.is_symlink() or path.read_bytes()[:2]!=b'MZ' or sha256(path)!=self.inputs[key+'_sha256']:
                raise ValueError('native PE identity differs: '+role)
            copy=self.output/(role+'.exe');shutil.copyfile(path,copy)
            result[role]={'original_path':str(path),'copy':copy.name,'sha256':sha256(copy)}
        return result
    def snapshot(self):
        from acceptance_runtime import network_snapshot
        return network_snapshot()
    def exchange(self, protocol, nonce):
        from acceptance_policy import _tcp_exchange, _udp_exchange
        trace={};fn=_tcp_exchange if protocol=='TCP' else _udp_exchange
        fn(self.inputs['target_ip'],self.inputs['port'],nonce,3,trace=trace)
        trace.update(nonce=nonce,pid=os.getpid(),process=Path(sys.executable).name)
        return trace
    def start_core(self, config):
        from acceptance_runtime import OwnedCore
        import psutil
        self.core=OwnedCore([sys.executable,'-m','fakenet.fakenet','-n','--no-pause','-c',str(config),'-l',str(self.output/'core.log'),'-f',str(self.output/'stop.flag')],self.output,self.output,self.output/'stop.flag',self.output/'core.log',source_root=ROOT)
        try:
            self.core.start();return {'pid':self.core.process.pid,'birth':psutil.Process(self.core.process.pid).create_time()}
        except BaseException:
            self.stop_core();raise
    def stop_core(self):
        if self.core is None:return {'exited':False,'returncode':None,'forced':False}
        import psutil
        process=self.core.process
        try:birth=psutil.Process(process.pid).create_time() if process and process.poll() is None else None
        except psutil.Error:birth=None
        if not self.core.state.get('stopped'):self.core.stop()
        return dict(self.core.state,exited=self.core.state.get('stopped') is True,birth=birth)
    def command(self, name, argv, timeout=30):
        started=time.time()
        with (self.output/(name+'.stdout')).open('xb') as stdout,(self.output/(name+'.stderr')).open('xb') as stderr:
            result=subprocess.run(argv,cwd=self.output,stdout=stdout,stderr=stderr,timeout=timeout,shell=False)
        write_json(self.output/(name+'.command.json'),{'argv':argv,'returncode':result.returncode,'started_at':started,'ended_at':time.time()})
        if result.returncode:raise RuntimeError(name+' failed rc='+str(result.returncode))
        return (self.output/(name+'.stdout')).read_text(errors='replace')
    def start_capture(self):
        status=self.command('capture-status-before',['pktmon.exe','status'])
        if not re.search(r'not running|stopped|未运行|已停止',status,re.I):raise ValueError('another/unknown pktmon owner')
        self.capture_owned=True
        self.capture_start=time.time()
        self.command('capture-start',['pktmon.exe','start','--capture','--comp','nics','--pkt-size','0','--file-name',str(self.output/'wire.etl')])
        self.capture_start=time.time()
        return {'started_at':self.capture_start,'owned':True,'path':'wire.etl'}
    def stop_capture(self):
        if not self.capture_owned:return {'stopped':False,'owned':False}
        status=self.command('capture-status-after',['pktmon.exe','status'])
        if 'wire.etl' not in status:raise ValueError('pktmon owner not confirmed; preserve recovery requirement')
        self.command('capture-stop',['pktmon.exe','stop']);self.capture_owned=False
        self.command('capture-convert',['pktmon.exe','etl2pcap',str(self.output/'wire.etl'),'--out',str(self.output/'wire.pcapng')])
        return {'stopped':True,'owned':True,'started_at':self.capture_start,'ended_at':time.time()}
    def client(self, name, role, count, parallel, nonce):
        import psutil
        key='target' if role=='target' else 'non_target'
        argv=[self.inputs[key+'_path'],'--host',self.inputs['original_ip'],'--port',str(self.inputs['port']),
              '--parallel-connections' if parallel else '--connections',str(count),'--nonce-prefix',nonce]
        if not parallel and count>1:argv+=['--minimum-start-interval-ms','40']
        started=time.time();forced=False;birth=None
        with (self.output/(name+'.jsonl')).open('xb') as stdout,(self.output/(name+'.stderr')).open('xb') as stderr:
            process=subprocess.Popen(argv,cwd=self.output,stdout=stdout,stderr=stderr,shell=False)
            try:
                birth=psutil.Process(process.pid).create_time();code=process.wait(timeout=30)
            except BaseException:
                if process.poll() is None:
                    forced=True;process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                raise
            finally:
                write_json(self.output/(name+'.owner.json'),{'argv':argv,'pid':process.pid,'birth':birth,'returncode':process.poll(),'exited':process.poll() is not None,'forced':forced,'started_at':started,'ended_at':time.time()})
        return {'path':name+'.jsonl','owner':name+'.owner.json','returncode':code,'count':count,'role':role,'nonce_prefix':nonce}
    def finalize(self):
        # Only files named by this owned core's closed log are used.
        text=(self.output/'core.log').read_text(errors='replace')
        raw_match=re.findall(r'PCAP_DUAL_SUMMARY\s+raw=(.+?)\s+ethernet=(.+?)\s+raw_count=',text)
        reports=re.findall(r'Generated new HTML report:\s*(.+)$',text,re.M)
        if len(raw_match)!=1 or len(reports)!=1:raise ValueError('owned core closed artifact paths missing/ambiguous')
        paths={}
        for key,name in [('raw',raw_match[0][0]),('converted',raw_match[0][1]),('html',reports[0].strip())]:
            path=(self.output/name).resolve()
            if not path.is_relative_to(self.output.resolve()) or not path.is_file() or path.is_symlink():raise ValueError('core artifact escapes owned directory')
            paths[key]=path.name
        if self.mode=='payload':
            from fakenet.payload_report import load_capture_originals
            loaded=load_capture_originals(str(self.output/paths['raw']),str(self.output/paths['converted']))
            write_json(self.output/'index.json',loaded.entries);paths['index']='index.json'
        return paths


class MemoryBoundary(NativeBoundary):
    """Simulated OS/core writes; all orchestration and content judges stay real."""
    fixture=True
    def __init__(self, output, inputs, mode):
        super().__init__(output,inputs,mode);self.flows=[];self.pid=4000;self.capturing=False
    def identities(self):
        if self.mode=='payload':return {}
        result={}
        for role,key in [('target','target'),('non-target','non_target')]:
            path=self.output/(role+'.exe');path.write_bytes(PE_BYTES[role])
            if sha256(path)!=self.inputs[key+'_sha256']:raise ValueError('memory PE identity differs')
            result[role]={'copy':path.name,'original_path':self.inputs[key+'_path'],'sha256':sha256(path)}
        return result
    def snapshot(self):return {'fixture':True,'routes':['bound-interface'],'dns':['original']}
    def exchange(self, protocol, nonce):
        request=('FNPR/1|%s|target\n'%nonce).encode();response=('FNPR/1|%s|OK\n'%nonce).encode()
        self.pid+=1;sport=40000+self.pid;stamp=time.time()
        flow={'proto':protocol,'src':self.inputs['source_ip'],'sport':sport,'dst':self.inputs['target_ip'],'port':self.inputs['port']}
        value={'tuple':flow,'nonce':nonce,'request_hex':request.hex(),'response_hex':response.hex(),'sent':True,'started_at':stamp,'ended_at':time.time(),'pid':os.getpid(),'process':Path(sys.executable).name}
        if self.core is not None:self.flows.append(value)
        return value
    def start_core(self,config):
        self.core=True;(self.output/'core.log').write_text('PROCESS_REDIRECT_READY\nPROCESS_REDIRECT_WINDIVERT_BASELINE\n')
        return {'pid':4242,'birth':1.0}
    def stop_core(self):
        if self.core is not None:
            self._artifacts();self.core=None
        return {'source':'owned-core','pid':4242,'birth':1.0,'exited':True,'returncode':0,'forced':False}
    def start_capture(self):
        self.capturing=True;self.capture_start=time.time()
        return {'owned':True,'started_at':self.capture_start,'path':'wire.pcapng'}
    def stop_capture(self):
        self.capturing=False;return {'owned':True,'stopped':True,'started_at':self.capture_start,'ended_at':time.time()}
    def client(self,name,role,count,parallel,nonce):
        self.pid+=1;pid=self.pid;started=time.time();rows=[{'event':'identity','role':role,'pid':pid,'creation_time':pid*10,'final_path':self.inputs['target_path' if role=='target' else 'non_target_path']}]
        failures=1 if parallel else count if role=='non-target' else 0
        for index in range(count):
            token='%s-%d-%d'%(nonce,pid,index);sport=40000+pid+index
            failed=index<failures
            rows.append({'event':'connection','role':role,'index':index,'success':not failed,'winsock_error':10061 if failed else 0,'failure_stage':'connect' if failed else '',
                         'local':'%s:%d'%(self.inputs['source_ip'],sport),'peer':'%s:%d'%(self.inputs['original_ip'],self.inputs['port']),'nonce':token,'epoch_ms':int(time.time()*1000)})
            if not failed:
                self.flows.append({'tuple':{'proto':'TCP','src':self.inputs['source_ip'],'sport':sport,'dst':self.inputs['target_ip'],'port':self.inputs['port']},'nonce':token,
                                   'request_hex':('FNPR/1|%s|target\n'%token).encode().hex(),'response_hex':('FNPR/1|%s|OK\n'%token).encode().hex(),'started_at':time.time(),'ended_at':time.time(),'pid':pid,'process':'target.exe'})
        rows.append({'event':'summary','role':role,'connections':count,'failures':failures,'elapsed_ms':int(count*40)})
        (self.output/(name+'.jsonl')).write_text(''.join(json.dumps(r)+'\n' for r in rows))
        code=1 if failures else 0
        write_json(self.output/(name+'.owner.json'),{'pid':pid,'birth':pid*10,'returncode':code,'exited':True,'forced':False,'started_at':started,'ended_at':time.time()})
        return {'path':name+'.jsonl','owner':name+'.owner.json','returncode':code,'count':count,'role':role,'nonce_prefix':nonce}
    def _artifacts(self):
        import dpkt
        from fakenet.diverters.pcapwriter import DualPcapWriter
        from fakenet.payload_report import CaptureObservationIndex,SessionFlowRegistry,build_payload_report
        registry=SessionFlowRegistry();index=CaptureObservationIndex();writer=DualPcapWriter(str(self.output/'raw.pcap'),str(self.output/'converted.pcap'),logging.getLogger('headless-memory'))
        wire=[]
        for flow in self.flows:
            f=flow['tuple'];request=bytes.fromhex(flow['request_hex']);response=bytes.fromhex(flow['response_hex'])
            for direction,src,dst,sport,dport,sequence,payload in [('outbound',f['src'],f['dst'],f['sport'],f['port'],100,request),('inbound',f['dst'],f['src'],f['port'],f['sport'],500,response)]:
                if f['proto']=='TCP':transport=dpkt.tcp.TCP(sport=sport,dport=dport,seq=sequence,ack=1,flags=0x18,data=payload);transport.off=5;proto=6
                else:transport=dpkt.udp.UDP(sport=sport,dport=dport,data=payload);transport.ulen=len(transport);proto=17
                packet=dpkt.ip.IP(src=socket.inet_aton(src),dst=socket.inet_aton(dst),p=proto,ttl=64,data=transport);packet.len=len(packet);raw=bytes(packet)
                logical=index.new_logical_packet_id(direction);stamp=max(flow['started_at'],self.capture_start if self.capturing else 0)
                flow_id=registry.observe_packet(raw,direction=direction,timestamp=stamp,logical_packet_id=logical)
                registry.update(flow_id,owner=flow['process'],pid=flow['pid'],process=flow['process'],disposition='ALLOW_TAKEOVER_SINK',domain='headless.invalid')
                writer.write_ip_packet(raw);index.record(raw,'initial',logical_packet_id=logical,flow_id=flow_id,direction=direction,timestamp=writer.last_timestamp,record_ordinal=writer.last_record_ordinal)
                if stamp>=self.capture_start:wire.append((stamp,raw))
        writer.close()
        with (self.output/'wire.pcapng').open('wb') as stream:
            capture=dpkt.pcapng.Writer(stream,linktype=101)
            for stamp,raw in wire:capture.writepkt(raw,ts=stamp)
        write_json(self.output/'index.json',index.snapshot())
        model=build_payload_report(str(self.output/'raw.pcap'),index,registry,capture_health={'writer_health':True,'coverage_health':True,'reassembly_health':True},converted_pcap_path=str(self.output/'converted.pcap'))
        (self.output/'report.html').write_text('<script id="payload-data" type="application/json">'+json.dumps(model)+'</script>')
        with (self.output/'core.log').open('a') as stream:
            stream.write('PROCESS_REDIRECT_QUIESCENCE_OK\nPROCESS_REDIRECT_AUDIT_SUMMARY\n')
            for f in self.flows:stream.write('PROCESS_REDIRECT_MAPPING_CREATED pid=%d source_ipv4=%s source_port=%d original_ipv4=%s target_ipv4=%s original_port=%d target_port=%d process_image_sha256=%s process_creation_time=%d\n'%(f['pid'],f['tuple']['src'],f['tuple']['sport'],self.inputs['original_ip'],self.inputs['target_ip'],self.inputs['port'],self.inputs['port'],self.inputs['target_sha256'],f['pid']*10))
            stream.write('owner_query_budget_exhausted=1\nALLOW_TAKEOVER_SINK %s pid=%d\n'%(Path(sys.executable).name,os.getpid()))
    def finalize(self):return {'raw':'raw.pcap','converted':'converted.pcap','wire':'wire.pcapng','index':'index.json','html':'report.html'}


def run(mode, output, inputs=None, memory=False, selected=None, boundary=None):
    if memory and inputs is None:inputs=memory_inputs()
    selected=validate_inputs(mode,inputs,selected)
    output=Path(output).resolve()
    if output.exists():raise FileExistsError(output)
    # Config generation and all schema checks happen before output/process actions.
    config=config_text(mode,inputs,output)
    if mode=='process':budget=owner_budget()
    else:budget=None
    output.mkdir(parents=True)
    io=boundary or (MemoryBoundary(output,inputs,mode) if memory else NativeBoundary(output,inputs,mode))
    result={'schema':SCHEMA,'mode':mode,'fixture':io.fixture,'inputs':inputs,'selection':selected,'config':'session.ini','clients':{},'probes':[],'paths':{},'budget':budget,'error':None}
    (output/'session.ini').write_text(config,encoding='utf-8');write_json(output/'inputs.json',inputs)
    before=None;core_started=False;capture_started=False;life={};capture_life={};owner={}
    try:
        result['identities']=io.identities();before=io.snapshot();write_json(output/'network-before.json',before)
        if set(selected) != {'identity'}:
            protocols=['TCP'] if mode=='process' else ['TCP','UDP']
            result['controls']=[io.exchange(p,'control-'+uuid.uuid4().hex) for p in protocols]
            for c in result['controls']:
                f=c.get('tuple') or {}
                if (f.get('src'),f.get('dst'),f.get('port'))!=(inputs['source_ip'],inputs['target_ip'],inputs['port']):raise ValueError('control source/route differs from selected interface')
                if bytes.fromhex(c.get('response_hex',''))!=('FNPR/1|%s|OK\n'%c['nonce']).encode():raise ValueError('controlled sink is not reachable before core')
            core_started=True;owner=io.start_core(output/'session.ini')
            if mode=='process' and 'non-target-negative' in selected:
                result['clients']['non-target']=io.client('negative','non-target',1,False,'negative-'+uuid.uuid4().hex)
            capture_started=True;result['capture']=io.start_capture()
            if mode=='process':
                work=[('target-positive','positive',1,False),('owner-bounded','owner',2,False),('budget','burst',budget['burst'],True)]
                for check,name,count,parallel in work:
                    if check in selected or check=='target-positive' and 'pcap-restore' in selected:
                        result['clients'][name]=io.client(name,'target',count,parallel,name+'-'+uuid.uuid4().hex)
            else:
                result['probes']=[io.exchange(p,'payload-'+uuid.uuid4().hex) for p in ('TCP','UDP')]
    except (Exception, KeyboardInterrupt) as exc:result['error']=type(exc).__name__+': '+str(exc)
    finally:
        if core_started:
            try:life=io.stop_core()
            except Exception as exc:life={'exited':False,'error':str(exc)}
        else:life={'not_started':True,'exited':True,'returncode':0,'forced':False}
        if owner:life.update(pid=owner['pid'],birth=owner['birth'])
        write_json(output/'owned-core.json',life)
        if capture_started:
            try:capture_life=io.stop_capture()
            except Exception as exc:capture_life={'stopped':False,'error':str(exc)}
        else:capture_life={'not_started':True,'stopped':True}
        write_json(output/'owned-capture.json',capture_life)
        try:after=io.snapshot()
        except Exception as exc:after={'error':str(exc)}
        write_json(output/'network-after.json',after)
    if core_started and life.get('exited'):
        try:result['paths']=io.finalize()
        except Exception as exc:result['error']=(result['error'] or '')+'; finalize: '+str(exc)
    result['core']='owned-core.json';result['capture_lifecycle']='owned-capture.json'
    result['network_before']='network-before.json';result['network_after']='network-after.json'
    result['log']='core.log';result['capture_started_at']=(result.get('capture') or {}).get('started_at')
    write_json(output/'headless-result.json',result)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser();parser.add_argument('--mode',choices=['process','payload'],required=True)
    parser.add_argument('--inputs');parser.add_argument('--output',required=True);parser.add_argument('--memory',action='store_true');parser.add_argument('--checks')
    args=parser.parse_args(argv);selected=args.checks.split(',') if args.checks else None
    value=run(args.mode,args.output,read_json(args.inputs) if args.inputs else None,args.memory,selected)
    print(json.dumps({'error':value['error'],'fixture':value['fixture'],'selection':value['selection']}))
    return 1 if value['error'] else 0

if __name__=='__main__':raise SystemExit(main())
