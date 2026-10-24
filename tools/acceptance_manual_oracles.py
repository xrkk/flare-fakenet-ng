#!/usr/bin/env python3
"""Read original wire bytes and frozen expectations, never producer verdicts."""
from __future__ import annotations
from collections import Counter
from datetime import timezone
import email.utils
import configparser
import hashlib
import json
import struct
from pathlib import Path
RAW=b'HTTP/1.1 200 OK\r\nDate: <RAW-DATE>\r\nX-Test: <RAW-DATE>\r\nContent-Length: 35\r\nConnection: close\r\n\r\nbody<RAW-DATE>\x00\xff'
STATIC=b'static-<RAW-DATE>'

def _evaluate_list_mutex(root,original,expected_inputs,allow_fixture=False):
    from fakenet.diverters.diverterbase import ListenerMeta,ListenerPorts,ListenerBlackWhiteList,DiverterBase
    import logging
    base=Path(original).resolve();path=base/'manual-result.json'
    if path.is_symlink() or not path.is_file():raise ValueError('original missing or linked')
    v=json.loads(path.read_text())
    if v.get('schema')!='fakenet.manual-result.v1' or v.get('case')!='GAP-LIST-MUTEX':raise ValueError('case/schema mismatch')
    if not isinstance(expected_inputs,dict) or v.get('inputs')!=expected_inputs:raise ValueError('frozen inputs mismatch')
    for k in ('candidate_id','source_commit','package_sha256','execution_id'):
        if v.get('identity',{}).get(k)!=expected_inputs.get(k):raise ValueError('identity mismatch: '+k)
    if type(v.get('fixture')) is not bool or v['fixture']!=(expected_inputs.get('fixture') is True):raise ValueError('fixture identity missing/changed')
    if v['fixture'] and not allow_fixture:raise ValueError('fixture cannot native credit')
    if str(base)!=expected_inputs.get('owned_root'):raise ValueError('frozen owned root mismatch')
    wanted={'proc-black':{'protocol':'TCP','port':'8080','processblacklist':'evil.exe, helper.exe'},
            'proc-white':{'protocol':'TCP','port':'8081','processwhitelist':'good.exe'},
            'host-black':{'protocol':'TCP','port':'8082','hostblacklist':'evil.test, bad.test'},
            'host-white':{'protocol':'TCP','port':'8083','hostwhitelist':'good.test'}}
    config=base/'config/list-mutex.ini'
    if config.is_symlink() or not config.is_file() or not config.resolve().is_relative_to(base):raise ValueError('configuration original missing/escaped')
    if v.get('configuration')!={'path':'config/list-mutex.ini','sha256':hashlib.sha256(config.read_bytes()).hexdigest()}:raise ValueError('configuration hash differs')
    parser=configparser.ConfigParser();parser.read(config)
    if {sec:dict(parser.items(sec)) for sec in parser.sections()}!=wanted:raise ValueError('frozen list configuration/target changed')
    names=('fakenet/diverters/diverterbase.py','fakenet/diverters/fnconfig.py')
    if v.get('source_hashes')!={name:hashlib.sha256((Path(root)/name).read_bytes()).hexdigest() for name in names}:raise ValueError('production source binding mismatch')
    obj=DiverterBase.__new__(DiverterBase);obj.logger=logging.getLogger('oracle-list-mutex');obj.listener_ports=ListenerPorts();obj.configure({})
    obj.parse_listeners_config({sec:dict(parser.items(sec)) for sec in parser.sections()})
    ports=obj.listener_ports;queries=[];errors=[]
    for method,port,positive,negative in [('isProcessBlackListHit',8080,'evil.exe','clean.exe'),
            ('isProcessWhiteListMiss',8081,'other.exe','good.exe'),
            ('isHostBlackListHit',8082,'evil.test','good.test'),
            ('isHostWhiteListMiss',8083,'other.test','good.test')]:
        for index,(proto,number,subject) in enumerate([('TCP',port,positive),('TCP',port,negative),('UDP',port,positive),('TCP',65500,positive)]):
            observed=getattr(ports,method)(proto,number,subject)
            if observed is not (index==0):errors.append('production predicate violates positive/negative target '+method)
            queries.append({'method':method,'protocol':proto,'port':number,'subject':subject,'result':observed})
    data=v.get('list_mutex') or {}
    expected_rows=[{'name':'proc-black','hit':True,'allow':False}, {'name':'proc-white','miss_allowed':True,'miss_denied':False},
                   {'name':'host-black','hit':True,'allow':False}, {'name':'host-white','miss_allowed':True,'miss_denied':False}]
    if data.get('observations')!=expected_rows or data.get('queries')!=queries:errors.append('original list observations disagree')
    if data.get('ports')!=[8080,8081,8082,8083] or data.get('ports_after')!=[]:errors.append('port identity/lifecycle mismatch')
    mutex=[]
    for kind in ('process','host'):
        meta=ListenerMeta('TCP',8090 if kind=='process' else 8091)
        try:
            if kind=='process':meta.setProcessBlacklist('a.exe');meta.setProcessWhitelist('b.exe')
            else:meta.setHostBlacklist('a.test');meta.setHostWhitelist('b.test')
            error=None;errors.append(kind+' mutex unexpectedly accepted')
        except ListenerBlackWhiteList as exc:error={'type':type(exc).__name__,'message':str(exc)}
        mutex.append({'kind':kind,'error':error,'process_cleared':meta.proc_wl is None and meta.proc_bl is None,'host_cleared':meta.host_wl is None and meta.host_bl is None})
    if data.get('mutex')!=mutex:errors.append('original mutex records missing/duplicate/foreign/error mismatch')
    for entry in mutex:
        error=entry.get('error')
        if (not isinstance(error,dict) or error.get('type')!='ListenerBlackWhiteList' or
                not isinstance(error.get('message'),str) or not error['message'].strip()):
            errors.append('mutex exception type/message not independently proven')
        if entry.get('process_cleared') is not True or entry.get('host_cleared') is not True:
            errors.append('mutex lists not cleared by original production path')
    conflicts=[]
    for scope in ('listener-process','listener-host','global-process'):
        d=DiverterBase.__new__(DiverterBase);d.logger=obj.logger;d.listener_ports=ListenerPorts();d.configure({})
        try:
            if scope=='global-process':d.configure({'processblacklist':'bad.exe','processwhitelist':'good.exe'});d.parse_diverter_config()
            else:
                keys=('processblacklist','processwhitelist') if scope=='listener-process' else ('hostblacklist','hostwhitelist')
                d.parse_listeners_config({'conflict':dict(protocol='TCP',port='8099',**{keys[0]:'a',keys[1]:'b'})})
            error=None;errors.append(scope+' parser accepted conflict')
        except SystemExit as exc:
            error={'type':'SystemExit','code':exc.code}
            if exc.code!=1:errors.append('unexpected conflict exit')
        conflicts.append({'scope':scope,'error':error,'registered_ports':d.listener_ports.getPortList('TCP')})
        if (not isinstance(error,dict) or error.get('type')!='SystemExit' or error.get('code')!=1 or
                d.listener_ports.getPortList('TCP')!=[]):
            errors.append('parser conflict did not exit 1 before registering a port')
    if data.get('parser_conflicts')!=conflicts:errors.append('original parser conflict observations differ')
    if v.get('cleanup')!={'stopped':True,'threads_joined':True,'sockets_closed':True,'network_restored':True}:errors.append('pure-logic lifecycle missing/changed')
    if v.get('checks')!=[{'id':k} for k in ('blacklist','whitelist','mutex')]:errors.append('exact check set differs')
    return [{'id':k,'status':'fail' if errors else 'pass'} for k in ('blacklist','whitelist','mutex')],not errors,{'failures':errors}

def evaluate(root,original,case,expected_inputs,allow_fixture=False):
    if case=='GAP-LIST-MUTEX':return _evaluate_list_mutex(root,original,expected_inputs,allow_fixture)
    if case not in ('GAP-NCSI','GAP-RAW-DATE'):raise NotImplementedError('case is not implemented in this round: '+case)
    base=Path(original).resolve()
    def read(path):
        p=Path(path)
        if not p.is_absolute() or not p.is_file() or p.is_symlink() or not p.resolve().is_relative_to(base):raise ValueError('original path missing/outside owned case')
        return p.read_bytes()
    v=json.loads(read(base/'manual-result.json'))
    if v.get('schema')!='fakenet.manual-result.v1' or v.get('case')!=case:raise ValueError('case/schema mismatch')
    if not isinstance(expected_inputs,dict) or v.get('inputs')!=expected_inputs:raise ValueError('frozen inputs mismatch')
    for k in ('candidate_id','source_commit','package_sha256','execution_id'):
        if v.get('identity',{}).get(k)!=expected_inputs.get(k):raise ValueError('identity mismatch: '+k)
    if v.get('fixture') and not allow_fixture:raise ValueError('fixture cannot native credit')
    if str(base)!=expected_inputs.get('owned_root'):raise ValueError('frozen owned root mismatch')
    errors=[]
    def need(ok,reason):
        if not ok:errors.append(reason)
    states=list(v.get('listener',{}).get('transports',{}).values()) if case=='GAP-NCSI' else [v.get('listener',{})]
    need(len(states)==(2 if case=='GAP-NCSI' else 1),'lifecycle missing listeners')
    for index,s in enumerate(states):
        name=('lifecycle-'+list(v['listener']['transports'])[index]+'.json') if case=='GAP-NCSI' else 'lifecycle-http.json'
        need(json.loads(read(base/name))==s,'lifecycle original observations mismatch')
        need(s.get('started') is True and s.get('stopped') is True and s.get('thread_alive') is False and s.get('socket_closed') is True and s.get('stop_error') is None and isinstance(s.get('thread_id'),int),'lifecycle stop observation failed')
        need(s.get('bind')=='127.0.0.1' and isinstance(s.get('port'),int) and s['port']>0,'lifecycle endpoint missing')
    need(all(v.get('cleanup',{}).get(k) is True for k in ('stopped','threads_joined','sockets_closed')),'lifecycle cleanup failed')
    need(not v.get('error'),'producer error')
    if case=='GAP-NCSI':
        from dnslib import DNSRecord,QTYPE
        expected={(t,n) for t in ('udp','tcp') for n in ('dns.msftncsi.com','other.example')}
        rows=v.get('queries',[]);counts=Counter((r.get('transport'),r.get('name')) for r in rows)
        need(set(counts)==expected and all(x==1 for x in counts.values()),'four-combination DNS coverage failed')
        for row in rows:
            try:
                qb=read(row['query']);rb=read(row['response']);q=DNSRecord.parse(qb);r=DNSRecord.parse(rb)
                wire_query=read(row['wire_query']);wire_response=read(row['wire_response'])
                if row['transport']=='tcp':
                    if wire_query!=struct.pack('!H',len(qb))+qb or wire_response!=struct.pack('!H',len(rb))+rb:raise ValueError('TCP frame boundary mismatch')
                elif wire_query!=qb or wire_response!=rb:raise ValueError('UDP datagram mismatch')
                name=str(q.q.qname).rstrip('.');want='131.107.255.225' if name=='dns.msftncsi.com' else expected_inputs.get('responsea','192.0.2.55')
                if (len(q.questions)!=1 or len(r.questions)!=1 or len(r.rr)!=1 or name!=row['name'] or name not in ('dns.msftncsi.com','other.example') or q.header.id!=r.header.id or q.header.qr!=0 or r.header.qr!=1 or r.header.rcode!=0 or q.q.qtype!=QTYPE.A or str(r.q.qname)!=str(q.q.qname) or r.q.qtype!=QTYPE.A or [str(a.rdata) for a in r.rr if a.rtype==QTYPE.A]!=[want]):raise ValueError('wire identity/answer mismatch')
                for k,data in [('query',qb),('response',rb)]:
                    if row.get(k+'_sha256')!=hashlib.sha256(data).hexdigest():raise ValueError('byte hash mismatch')
                s=v['listener']['transports'][row['transport']]
                if row['peer']!=['127.0.0.1',s['port']] or row['server_port']!=s['port'] or not row.get('client_port') or row.get('client_closed') is not True:raise ValueError('wire endpoint/client exit mismatch')
            except Exception as e:errors.append('DNS bytes: '+str(e))
        checks=['ncsi-ipv4','other-domain','dns-evidence']
    else:
        try:
            need(read(v['raw_template'])==RAW,'template raw differs from fixed stimulus')
            need(read(v['static_template'])==STATIC,'template static differs from fixed stimulus')
            config_bytes=read(base/'config/custom.ini');config=configparser.ConfigParser();config.read_string(config_bytes.decode())
            wanted={'raw':{'listenertype':'HTTP','httpuris':'/raw','httphosts':'example.test','httprawfile':'raw.bin'},'static':{'listenertype':'HTTP','httpuris':'/static','httphosts':'example.test','httpstaticstring':STATIC.decode(),'contenttype':'text/plain'}}
            need({section:dict(config.items(section)) for section in config.sections()}==wanted,'template configuration mismatch')
            need(hashlib.sha256(config_bytes).hexdigest()==v.get('config_sha256'),'template configuration hash mismatch')
            need(Path(v['raw_template'])==base/'config/raw.bin' and Path(v['static_template'])==base/'static.txt','template path mismatch')
            exchanges=v['http']['exchanges'];expected={'raw':('example.test','/raw'),'static':('example.test','/static'),'wrong-host':('other.test','/raw'),'wrong-uri':('example.test','/none')}
            need(Counter(r.get('name') for r in exchanges)==Counter(expected.keys()),'HTTP request coverage failed')
            for row in exchanges:
                name=row['name'];host,path=expected[name];request=read(row['request']);response=read(row['response'])
                need(row['host']==host and row['path']==path and request==('GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n'%(path,host)).encode(),'HTTP request identity mismatch')
                need(row['peer']==['127.0.0.1',v['listener']['port']] and row['client_closed'] is True,'lifecycle HTTP peer/client failed')
                try:
                    header,body=response.split(b'\r\n\r\n',1);lines=header.split(b'\r\n');fields={k.decode().lower():val.strip() for k,val in (line.split(b':',1) for line in lines[1:])}
                    date=fields['date'];dt=email.utils.parsedate_to_datetime(date.decode());stamp=dt.timestamp()
                    if dt.tzinfo is None or not row['started_epoch']-2<=stamp<=row['ended_epoch']+2:raise ValueError('HTTP date outside original observation window')
                    if email.utils.format_datetime(dt,usegmt=True).encode()!=date:raise ValueError('HTTP date not canonical RFC')
                    if name=='raw':need(response==RAW.replace(b'<RAW-DATE>',date),'HTTP bytes raw mismatch')
                    else:
                        expected_body=STATIC.replace(b'<RAW-DATE>',date) if name=='static' else (b'normal-file-raw' if name=='wrong-host' else b'normal-file-none')
                        need(lines[0]==b'HTTP/1.0 200 OK' and body==expected_body and int(fields['content-length'])==len(body),'HTTP bytes static/file framing mismatch')
                        expected_header=b'HTTP/1.0 200 OK\r\nServer: FakeNet/manual\r\nDate: '+date+b'\r\n'
                        if name!='static':expected_header+=b'Content-Type: text/html\r\n'
                        expected_header+=b'Content-Length: '+str(len(expected_body)).encode()+b'\r\n\r\n'
                        need(response==expected_header+expected_body,'HTTP bytes original headers/body mismatch')
                    need(b'<RAW-DATE>' not in response,'HTTP bytes placeholder remains')
                except (ValueError,KeyError,TypeError) as e:errors.append(str(e) if 'HTTP date' in str(e) else 'HTTP bytes: '+str(e))
        except (ValueError,KeyError,TypeError) as e:errors.append('HTTP bytes: '+str(e))
        checks=['raw-date','preserved-bytes']
    rows=[{'id':k,'status':'fail' if errors else 'pass'} for k in checks]
    return rows,not errors,{'failures':errors}
