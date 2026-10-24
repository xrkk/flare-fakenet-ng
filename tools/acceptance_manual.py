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

def real_syslog_icmp(case, out, inputs):
    import logging
    import os
    import sys
    from fakenet import fakenet as core
    from fakenet.diverters.diverterbase import DiverterBase
    from fakenet.diverters.fnpacket import PacketCtx
    out = Path(out)
    cfgdir = out / 'config'
    cfgdir.mkdir()
    cfg = cfgdir / 'syslog.ini'
    cfg.write_text('[FakeNet]\nDivertTraffic: No\n')
    started = datetime.now(timezone.utc).isoformat()
    token = inputs['execution_id']
    sink = out / 'syslog.sink'
    if inputs.get('syslog_sink', str(sink)) != str(sink):
        raise ValueError('syslog sink must be the owned original')
    loggers = [logging.getLogger(name) for name in ('', 'FakeNet', 'Diverter', 'manual-syslog-icmp')]
    def snapshot():
        return [{'name': logger.name, 'handlers': [id(handler) for handler in logger.handlers],
                 'level': logger.level, 'propagate': logger.propagate, 'disabled': logger.disabled}
                for logger in loggers]
    saved = [(logger, list(logger.handlers), logger.level, logger.propagate, logger.disabled) for logger in loggers]
    before = snapshot()
    old_argv = sys.argv
    old_profile = sys.getprofile()
    calls = []
    records = []
    methods = {getattr(core.Fakenet, name).__code__: name for name in ('parse_config', 'start', 'stop')}
    def observe(frame, event, arg):
        if event == 'call' and frame.f_code in methods:
            calls.append({'method': methods[frame.f_code], 'event': 'call'})
        if event == 'call' and frame.f_code is logging.Logger.callHandlers.__code__:
            record = frame.f_locals['record']
            records.append({'logger': record.name, 'process': record.process, 'message': record.getMessage()})
    created = []
    exits = {}
    errors = []
    try:
        sys.setprofile(observe)
        for mode, enabled in (('on', True), ('off', False)):
            flag = out / ('stop-' + token + '-' + mode)
            flag.write_text('owned stop flag')
            argv = ['fakenet', '-c', str(cfg), '-p', '-n', '-l', str(out / ('main-' + mode + '.log')), '-f', str(flag)]
            if enabled:
                argv.append('-s')
            sys.argv = argv
            first = len(calls)
            try:
                core.main()
            except SystemExit as exc:
                exits[mode] = {'returncode': exc.code, 'calls': calls[first:]}
            except Exception as exc:
                errors.append(type(exc).__name__ + ': ' + str(exc))
            finally:
                for logger in loggers:
                    for handler in list(logger.handlers):
                        if not any(handler in prior for _, prior, *_ in saved):
                            handler.flush()
                            handler.close()
                            created.append({'class': type(handler).__name__,
                                            'closed': bool(getattr(handler, '_closed', False)),
                                            'stream_closed': getattr(handler, 'stream', None) is None or handler.stream.closed})
                            logger.removeHandler(handler)
        packets = {'icmp': bytes.fromhex('4500001c0001000040010000c000020ac00002140800000010e10001'),
                   'tcp': bytes.fromhex('450000280001000040060000c000020ac00002149c401f9000000000000000005002200000000000')}
        for kind, raw in packets.items():
            (out / ('packet-' + kind + '.bin')).write_bytes(raw)
        logger = loggers[-1]
        logger.setLevel(logging.INFO)
        logger.propagate = False
        d = DiverterBase.__new__(DiverterBase)
        d.logger = logger
        phases = {}
        for phase, kind, windows, blocked in (('linux', 'icmp', False, False), ('nonicmp', 'tcp', False, False),
                                               ('blocked', 'icmp', True, True), ('windows', 'icmp', True, False)):
            packet = PacketCtx('logging-' + phase, packets[kind])
            d.running_on_windows = windows
            d.blacklist_ids = {'ICMP': [4321] if blocked else []}
            handler = logging.FileHandler(out / ('icmp-' + phase + '.log'), encoding='utf-8')
            logger.addHandler(handler)
            try:
                d.check_log_icmp(None, packet)
            finally:
                handler.flush()
                handler.close()
                logger.removeHandler(handler)
            phases[phase] = {'raw': str(out / ('packet-' + kind + '.bin')), 'is_icmp': packet.is_icmp,
                             'closed': handler.stream is None and handler._closed}
        (out / 'icmp.log').write_bytes((out / 'icmp-linux.log').read_bytes() + (out / 'icmp-windows.log').read_bytes())
        # Native collectors read existing system records only; fixture sinks are
        # produced by the test's OS backend, never by this producer.
        if not sink.exists() and inputs.get('fixture') is not True:
            messages = []
            if core.platform.system() == 'Windows':
                import win32evtlog
                handle = win32evtlog.OpenEventLog(None, 'Application')
                try:
                    events = win32evtlog.ReadEventLog(handle, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
                    for event in events:
                        if event.SourceName == 'FakeNet-NG':
                            messages.extend(text for text in (event.StringInserts or []) if token in text)
                finally:
                    win32evtlog.CloseEventLog(handle)
            else:
                for path in (Path('/var/log/syslog'), Path('/var/log/messages')):
                    if path.is_file():
                        with path.open(errors='replace') as stream:
                            messages.extend(line.rstrip('\n') for line in stream if 'FakeNet-NG' in line and token in line)
            if messages:
                sink.write_text('\n'.join(messages) + '\n', encoding='utf-8')
    except Exception as exc:
        errors.append(type(exc).__name__ + ': ' + str(exc))
    finally:
        sys.setprofile(old_profile)
        sys.argv = old_argv
        for logger, handlers, level, propagate, disabled in saved:
            for handler in list(logger.handlers):
                if handler not in handlers:
                    handler.close()
            logger.handlers = handlers
            logger.setLevel(level)
            logger.propagate = propagate
            logger.disabled = disabled
    lifecycle = {'before': before, 'after': snapshot(), 'created_handlers': created,
                 'argv_restored': sys.argv is old_argv, 'profile_restored': sys.getprofile() is old_profile,
                 'pid': os.getpid(), 'token': token, 'calls': calls, 'records': records,
                 'phases': locals().get('phases', {}), 'errors': errors}
    _json(out / 'lifecycle.json', lifecycle)
    source = Path(__file__).resolve().parents[1]
    value = {'schema': SCHEMA, 'case': case, 'fixture': inputs.get('fixture') is True, 'inputs': inputs,
             'evidence_kind': 'original-core-and-packet-logging',
             'syslog_icmp': {'config': str(cfg), 'config_sha256': sha256(cfg), 'main_rc_on': exits.get('on', {}).get('returncode'),
                            'main_rc_off': exits.get('off', {}).get('returncode'), 'main_log_on': str(out / 'main-on.log'),
                            'main_log_off': str(out / 'main-off.log'), 'syslog_sink': str(sink),
                            'syslog_sink_sha256': sha256(sink) if sink.is_file() else None,
                            'icmp_log': str(out / 'icmp.log'), 'icmp_log_sha256': sha256(out / 'icmp.log') if (out / 'icmp.log').is_file() else None,
                            'icmp_type': 8, 'icmp_code': 0, 'icmp_id': 4321, 'owner_pid': os.getpid(),
                            'execution_token': token, 'handler_closed': all(item['closed'] and item['stream_closed'] for item in created), 'exits': exits},
             'source_hashes': {name: sha256(source / name) for name in ('fakenet/fakenet.py', 'fakenet/diverters/fnpacket.py', 'fakenet/diverters/diverterbase.py')},
             'started_at': started, 'ended_at': datetime.now(timezone.utc).isoformat(),
             'cleanup': {'scope': 'owned-handlers-and-logger-state', 'stopped': before == snapshot() and not errors,
                         'system_network_restored': 'not-exercised'},
             'checks': [{'id': name} for name in CHECKS[case]], 'identity': {name: inputs[name] for name in IDENTITY}}
    _json(out / 'manual-result.json', value)
    return value

def real_ctrlc_ipc(case,out,inputs):
    import logging
    import os
    import _thread
    import signal
    import sys
    import threading
    import time
    from fakenet import fakenet as core
    if threading.current_thread() is not threading.main_thread():
        raise ValueError('Ctrl-C control is only allowed in this checker main thread')
    out=Path(out)
    cfgdir=out/'config';cfgdir.mkdir()
    cfg=cfgdir/'shutdown.ini'
    cfg.write_text('[FakeNet]\nDivertTraffic: Yes\n[Diverter]\nNetworkMode: SingleHost\nLinuxRestrictInterface: Off\n',encoding='ascii')
    token=inputs['execution_id'];owner=os.getpid();started=datetime.now(timezone.utc).isoformat()
    loggers=[logging.getLogger(''),logging.getLogger('FakeNet')]
    saved=[(logger,list(logger.handlers),logger.level,logger.propagate,logger.disabled) for logger in loggers]
    initial_ids={id(handler) for logger in loggers for handler in logger.handlers}
    def snapshot():
        return [{'name':logger.name,'handlers':[id(handler) for handler in logger.handlers],
                 'level':logger.level,'propagate':logger.propagate,'disabled':logger.disabled}
                for logger in loggers]
    before=snapshot();created=[];errors=[];branches={}
    old_argv=sys.argv;old_profile=sys.getprofile()
    def signal_ids():
        return {name:id(signal.getsignal(getattr(signal,name))) for name in ('SIGINT','SIGTERM')}
    signal_before=signal_ids()
    def collect_created():
        for logger in loggers:
            for handler in list(logger.handlers):
                if id(handler) not in initial_ids and handler not in created:
                    created.append(handler)
    try:
        for mode in ('ctrlc','ipc'):
            folder=out/mode;folder.mkdir()
            flag=folder/('stop-'+token+'-'+mode+'.flag')
            unrelated=folder/'unrelated.flag'
            unrelated_text='unrelated-'+token+'-'+mode
            unrelated.write_text(unrelated_text+'\n',encoding='utf-8')
            log=folder/'main.log'
            wait_entered=threading.Event();done=threading.Event();fired=threading.Event();control_lock=threading.Lock()
            holder={};events=[];watch_errors=[];observations={}
            backend_events=[];wrapped=[]
            def observe_backend(obj, name):
                original=getattr(obj,name)
                had=name in obj.__dict__;prior=obj.__dict__.get(name)
                def observed(*args,**kwargs):
                    backend_events.append({'method':name,'event':'call'})
                    try:
                        result=original(*args,**kwargs)
                    except BaseException as exc:
                        backend_events.append({'method':name,'event':'error','type':type(exc).__name__})
                        raise
                    backend_events.append({'method':name,'event':'return','result':result if name=='stop' else None})
                    return result
                setattr(obj,name,observed)
                wrapped.append((obj,name,had,prior))
            def observe(frame,event,arg):
                code=frame.f_code
                if code is core.Fakenet.start.__code__ and event=='call':
                    holder['fakenet']=frame.f_locals['self']
                f=holder.get('fakenet');backend=getattr(f,'diverter',None)
                start=getattr(type(backend),'start',None) if backend is not None else None
                if start is not None and code is getattr(start,'__code__',None) and frame.f_locals.get('self') is backend:
                    if event=='call':backend_events.append({'method':'start','event':'call'})
                    elif event=='return':backend_events.append({'method':'start','event':'return','result':arg})
                if event=='call':
                    for method in ('parse_config','start','stop'):
                        if code is getattr(core.Fakenet,method).__code__:
                            events.append({'method':method,'event':'call'})
                    if code is core.wait_for_shutdown.__code__:
                        events.append({'method':'wait_for_shutdown','event':'call'})
                        holder['fakenet']=frame.f_locals.get('fakenet')
                        holder['stop_flag']=frame.f_locals.get('stop_flag')
                        backend=getattr(holder['fakenet'],'diverter',None)
                        if backend is not None:
                            observe_backend(backend,'stop')
                            observe_backend(backend,'wait_for_capture_failure')
                        wait_entered.set()
                elif event=='return':
                    for method in ('parse_config','start','stop'):
                        if code is getattr(core.Fakenet,method).__code__:
                            events.append({'method':method,'event':'return','result':arg if method=='stop' else None})
                    if code is core.wait_for_shutdown.__code__:
                        events.append({'method':'wait_for_shutdown','event':'return','result':arg})
                if old_profile is not None:old_profile(frame,event,arg)
            def watcher():
                if not wait_entered.wait(3.0):
                    watch_errors.append('original wait_for_shutdown was not entered')
                    return
                if mode=='ipc':
                    time.sleep(0.25)
                    with control_lock:
                        if done.is_set():return
                        observations['unrelated_window_epoch']=time.time()
                        observations['stop_calls_before_correct']=sum(1 for event in events if event.get('method')=='stop' and event.get('event')=='call')
                        observations['stop_started_before_correct']=bool(getattr(holder.get('fakenet'),'_stop_started',False))
                        observations['expected_existed_before_trigger']=flag.exists()
                        observations['unrelated_existed_before_trigger']=unrelated.exists()
                        if flag.exists():
                            watch_errors.append('expected stop flag existed before trigger')
                            return
                        flag.write_text('stop-'+token+'\n',encoding='utf-8')
                        observations['correct_flag_written_epoch']=time.time();fired.set()
                else:
                    time.sleep(0.05)
                    with control_lock:
                        if done.is_set():return
                        observations['interrupt_main_epoch']=time.time()
                        _thread.interrupt_main();fired.set()
            thread=threading.Thread(target=watcher,name='owned-'+mode+'-'+token)
            thread.start()
            rc=None;error=None
            try:
                sys.argv=['fakenet','-c',str(cfg),'-f',str(flag),'-p','-n','-l',str(log)]
                sys.setprofile(observe)
                core.main()
            except SystemExit as exc:
                rc=exc.code
            except BaseException as exc:
                error={'type':type(exc).__name__,'message':str(exc)}
            finally:
                with control_lock:
                    done.set()
                thread.join(5.0)
                if thread.is_alive():watch_errors.append('owned watcher thread did not join')
                sys.setprofile(old_profile)
                for obj,name,had,prior in reversed(wrapped):
                    if had:setattr(obj,name,prior)
                    else:delattr(obj,name)
                sys.argv=old_argv
            collect_created()
            f=holder.get('fakenet');backend=getattr(f,'diverter',None) if f is not None else None
            def attr(obj,name):
                return getattr(obj,name,None) if obj is not None else None
            runtime={'fakenet_class':type(f).__name__ if f is not None else None,
                     'listener_count':len(f.running_listener_providers) if f is not None else None,
                     'diverter_class':type(backend).__name__ if backend is not None else None,
                     'backend_observations':backend_events,
                     'start_calls':sum(row['method']=='start' and row['event']=='call' for row in backend_events),
                     'stop_calls':sum(row['method']=='stop' and row['event']=='call' for row in backend_events),
                     'wait_calls':sum(row['method']=='wait_for_capture_failure' and row['event']=='call' for row in backend_events),
                     'backend_started':any(row['method']=='start' and row['event']=='return' and row.get('result') is not False for row in backend_events),
                     'backend_stopped':any(row['method']=='stop' and row['event']=='return' and row.get('result') is not False for row in backend_events),
                     'stop_started':attr(f,'_stop_started'),
                     'stop_complete':bool(f._stop_complete.is_set()) if f is not None else None,
                     'stop_result':attr(f,'_stop_result'),
                     'stop_error':(None if f is None or f._stop_error is None else {'type':type(f._stop_error).__name__,'message':str(f._stop_error)})}
            branches[mode]={'config':str(cfg),'config_sha256':sha256(cfg),'log':str(log),
                            'log_sha256':sha256(log) if log.is_file() else None,
                            'flag':str(flag),'flag_exists_after':flag.exists(),
                            'unrelated_flag':str(unrelated),'unrelated_exists_after':unrelated.exists(),
                            'unrelated_text_after':unrelated.read_text(encoding='utf-8') if unrelated.is_file() else None,
                            'rc':rc,'error':error,'calls':events,'wait_entered':wait_entered.is_set(),
                            'watcher_fired':fired.is_set(),'watcher_alive':thread.is_alive(),
                            'watcher_errors':watch_errors,'observations':observations,'runtime':runtime,
                            'stop_flag_argument':holder.get('stop_flag'),
                            'backend_wrappers_restored':all((name in obj.__dict__)==had and (not had or obj.__dict__.get(name) is prior) for obj,name,had,prior in wrapped)}
        signal_after=signal_ids()
    finally:
        for handler in created:
            try:
                handler.flush();handler.close()
            except Exception as exc:
                errors.append(type(exc).__name__+': '+str(exc))
        for logger,handlers,level,propagate,disabled in saved:
            for handler in list(logger.handlers):
                if handler not in handlers:
                    try:handler.close()
                    except Exception:pass
            logger.handlers=handlers
            logger.setLevel(level);logger.propagate=propagate;logger.disabled=disabled
        sys.argv=old_argv;sys.setprofile(old_profile)
    after=snapshot();thread_names=[thread.name for thread in threading.enumerate()]
    owned_absent=not any(name.startswith('owned-') and token in name for name in thread_names)
    branch_ok=bool(branches) and all(item['error'] is None and item['rc']==0 and item['wait_entered'] and item['watcher_fired']
        and not item['watcher_alive'] and not item['watcher_errors'] and not item['flag_exists_after']
        and item['stop_flag_argument']==item['flag'] and item['runtime']['stop_complete'] is True
        and item['runtime']['stop_result'] is True and item['runtime']['stop_error'] is None
        for item in branches.values())
    lifecycle={'scope':'owned-main-ctrlc-file-ipc-and-runtime-state','signal_ids_before':signal_before,
               'signal_ids_after':signal_after,'signals_restored':signal_before==signal_after,
               'logger_before':before,'logger_after':after,'logger_restored':before==after,
               'argv_restored':sys.argv is old_argv,'profile_restored':sys.getprofile() is old_profile,
               'owned_threads_absent':owned_absent,'thread_names':thread_names,'errors':errors,
               'pid':owner,'token':token,'created_handlers':[{'class':type(handler).__name__,'closed':bool(getattr(handler,'_closed',False))} for handler in created]}
    _json(out/'lifecycle.json',lifecycle)
    source=Path(__file__).resolve().parents[1]
    value={'schema':SCHEMA,'case':case,'fixture':inputs.get('fixture') is True,'inputs':inputs,
           'evidence_kind':'original-main-ctrl-c-and-file-ipc','ctrlc_ipc':{'config':str(cfg),'config_sha256':sha256(cfg),
             'branches':branches,'owner_pid':owner,'execution_token':token,'checks':list(CHECKS[case])},
           'source_hashes':{name:sha256(source/name) for name in ('fakenet/fakenet.py',)},
           'started_at':started,'ended_at':datetime.now(timezone.utc).isoformat(),
           'cleanup':{'scope':'owned-main-ctrlc-file-ipc-and-runtime-state','stopped':branch_ok,
                      'threads_joined':owned_absent,'flags_removed':all(not item['flag_exists_after'] for item in branches.values()),
                      'logger_restored':before==after,'argv_restored':sys.argv is old_argv,
                      'profile_restored':sys.getprofile() is old_profile,'signals_restored':signal_before==signal_after,
                      'system_network_restored':'not-exercised','system_console_used':False},
           'checks':[{'id':name} for name in CHECKS[case]],'identity':{name:inputs[name] for name in IDENTITY}}
    _json(out/'manual-result.json',value);return value

def real_linux_flush_interface(case,out,inputs):
    import configparser
    import logging
    import os
    import sys
    import types
    from fakenet.diverters import linux, linutil
    from fakenet.diverters.linux import Diverter
    out=Path(out);cfgdir=out/'config';cfgdir.mkdir()
    token=inputs['execution_id'];owner=os.getpid();started=datetime.now(timezone.utc).isoformat()
    log=out/'diverter.log';log_handler=logging.FileHandler(log,mode='x',encoding='utf-8')
    log_handler.setFormatter(logging.Formatter('%(levelname)s %(name)s pid=%(process)d %(message)s'))
    logger=logging.getLogger('Diverter');old_handlers=list(logger.handlers);old_level=logger.level
    logger.addHandler(log_handler);logger.setLevel(logging.INFO)
    scenarios=(
        ('flush_on','SingleHost','Yes','service dns-clean restart','Off'),
        ('flush_off','SingleHost','No',None,'Off'),
        ('dns_nonzero','SingleHost','No','false','Off'),
        ('multihost_iface','MultiHost','No',None,'eth1'),
        ('multihost_off','MultiHost','No',None,'Off'),
        ('singlehost_iface','SingleHost','No',None,'eth1'),
    )
    branches={}
    os_calls=out/'os-calls.jsonl'
    os_calls.touch(exist_ok=False)
    originals={'linux':linux.subprocess,'linutil':linutil.subprocess}
    old_profile=sys.getprofile()
    current={'branch':None}
    queues={}
    def record(kind,**fields):
        row={'branch':current['branch'],'kind':kind};row.update(fields)
        with os_calls.open('a',encoding='utf-8') as stream:
            stream.write(json.dumps(row,sort_keys=True)+'\n')
    def proxy(module):
        class Output:
            def __init__(self,stream):self.stream=stream
            def read(self,*args):
                data=self.stream.read(*args)
                with (out/('capture-save-'+current['branch']+'.bin')).open('ab') as stream:stream.write(data)
                return data
            def __getattr__(self,name):return getattr(self.stream,name)
        class Process:
            def __init__(self,argv,*args,**kwargs):
                record('popen',argv=list(argv))
                self.argv=list(argv);self.child=module.Popen(argv,*args,**kwargs)
                self.stdout=Output(self.child.stdout) if self.argv==['iptables-save'] and self.child.stdout is not None else getattr(self.child,'stdout',None)
            def wait(self,*args,**kwargs):
                rc=self.child.wait(*args,**kwargs);record('wait',argv=self.argv,rc=rc);return rc
            def communicate(self,input=None,*args,**kwargs):
                record('communicate',argv=self.argv,input_hex=bytes(input or b'').hex())
                return self.child.communicate(input,*args,**kwargs)
            def __getattr__(self,name):return getattr(self.child,name)
        def call(argv,*args,**kwargs):
            rc=module.call(argv,*args,**kwargs);record('call',argv=list(argv),rc=rc);return rc
        class Module:
            Popen=Process
            def __getattr__(self,name):return getattr(module,name)
        value=Module();value.call=call
        return value
    def observe(frame,event,arg):
        if event=='call' and frame.f_code is linutil.LinuxDiverterNfqueue.start.__code__:
            q=frame.f_locals['self'];queues[id(q._nfqueue)]=q.qno
        if event=='return':
            obj=frame.f_locals.get('self');qno=queues.get(id(obj))
            if qno is not None and frame.f_code.co_name in ('bind','unbind'):
                record(frame.f_code.co_name,qno=qno)
        if event=='c_return':
            qno=queues.get(id(getattr(arg,'__self__',None)))
            name=getattr(arg,'__name__',None)
            if qno is not None and name in ('bind','unbind'):record(name,qno=qno)
    linux.subprocess=proxy(originals['linux']);linutil.subprocess=proxy(originals['linutil'])
    sys.setprofile(observe)
    def queue_rows(d):
        rows=[]
        for q in getattr(d,'nfqueues',[]) or []:
            rule=getattr(q,'_rule',None)
            error=getattr(q,'thread_error',None)
            stop_error=getattr(q,'stop_error',None)
            rows.append({'qno':getattr(q,'qno',None),'chain':getattr(q,'chain',None),
                         'table':getattr(q,'table',None),'add':getattr(rule,'_addcmd',None),
                         'remove':getattr(rule,'_remcmd',None),'started':getattr(q,'_started',None),
                         'bound':getattr(q,'_bound',None),'rule_added':getattr(q,'_rule_added',None),
                         'thread_alive':bool(getattr(q,'thread_alive',False)),
                         'thread_error':None if error is None else {'type':type(error).__name__,'message':str(error)},
                         'stop_error':None if stop_error is None else {'type':type(stop_error).__name__,'message':str(stop_error)}})
        return rows
    def rule_rows(d):
        rows=[]
        for rule in getattr(d,'rules_added',[]) or []:
            rows.append({'add':getattr(rule,'_addcmd',None),'remove':getattr(rule,'_remcmd',None)})
        return rows
    try:
        for name,mode,flush,dns,restrict in scenarios:
            cfg=cfgdir/(name+'.ini')
            lines=['[FakeNet]','DivertTraffic: Yes','[Diverter]','NetworkMode: '+mode,
                   'LinuxFlushIptables: '+flush]
            if dns is not None:lines.append('LinuxFlushDNSCommand: '+dns)
            lines.append('LinuxRestrictInterface: '+restrict)
            cfg.write_text('\n'.join(lines)+'\n',encoding='ascii')
            current['branch']=name
            queues.clear()
            (out/'active-branch').write_text(name,encoding='utf-8')
            logger.info('MANUAL-LINUX-BRANCH %s token=%s',name,token)
            parser=configparser.ConfigParser();parser.read(cfg)
            d=None;start_result=None;stop_result=None;start_error=None;stop_error=None
            try:
                d=Diverter(dict(parser.items('Diverter')),{},{4:['192.0.2.10'],6:[]})
                bindings=list(d.linux_get_current_nfnlq_bindings())
                _json(out/('bindings-before-'+name+'.json'),bindings)
                start_result=d.startCallback()
            except BaseException as exc:
                start_error={'type':type(exc).__name__,'message':str(exc)}
            before_queues=queue_rows(d) if d is not None else []
            before_rules=rule_rows(d) if d is not None else []
            snapshot=bytes(getattr(d,'iptables_captured',b'') or b'') if d is not None else b''
            snapshot_path=out/('snapshot-'+name+'.sav');snapshot_path.write_bytes(snapshot)
            if d is not None:
                try:
                    stop_result=d.stopCallback()
                except BaseException as exc:
                    stop_error={'type':type(exc).__name__,'message':str(exc)}
            after_queues=queue_rows(d) if d is not None else []
            after_rules=rule_rows(d) if d is not None else []
            policy=getattr(d,'net_policy',None) if d is not None else None
            branches[name]={'config':str(cfg),'config_sha256':sha256(cfg),
                'network_mode':getattr(d,'network_mode',None) if d is not None else mode,
                'single_host_mode':getattr(d,'single_host_mode',None) if d is not None else None,
                'flush_iptables':getattr(d,'is_set',lambda x:False)('linuxflushiptables') if d is not None else None,
                'dns_command':getattr(d,'getconfigval',lambda x:None)('linuxflushdnscommand') if d is not None else None,
                'restrict_interface':getattr(d,'getconfigval',lambda x:None)('linuxrestrictinterface') if d is not None else None,
                'start_result':start_result,'stop_result':stop_result,'start_error':start_error,'stop_error':stop_error,
                'queues_after_start':before_queues,'queues_after_stop':after_queues,
                'rules_after_start':before_rules,'rules_after_stop':after_rules,
                'snapshot':str(snapshot_path),'snapshot_sha256':sha256(snapshot_path),'snapshot_bytes':len(snapshot),
                'net_policy':{'class':type(policy).__name__ if policy is not None else None,
                              'calls':list(getattr(policy,'calls',[]) or []),
                              'mode':getattr(policy,'mode',None) if policy is not None else None}}
    finally:
        sys.setprofile(old_profile)
        linux.subprocess=originals['linux'];linutil.subprocess=originals['linutil']
        logger.removeHandler(log_handler);log_handler.close();logger.setLevel(old_level);logger.handlers=old_handlers
    _json(out/'observer-lifecycle.json',{'profile_restored':sys.getprofile() is old_profile,'linux_module_restored':linux.subprocess is originals['linux'],'linutil_module_restored':linutil.subprocess is originals['linutil'],'logger_handlers_restored':logger.handlers==old_handlers,'logger_level_restored':logger.level==old_level,'handler_closed':log_handler.stream is None and log_handler._closed})
    cleanup_ok=all(item['stop_result'] is True and item['start_result'] is True and item['start_error'] is None and item['stop_error'] is None
                   and all(not q['thread_alive'] and not q['rule_added'] for q in item['queues_after_stop']) for item in branches.values())
    source=Path(__file__).resolve().parents[1]
    value={'schema':SCHEMA,'case':case,'fixture':inputs.get('fixture') is True,
      'evidence_kind':'original-linux-callback-os-boundary','inputs':inputs,
      'linux_flush_interface':{'config_dir':str(cfgdir),'branches':branches,'log':str(log),
          'log_sha256':sha256(log),'os_calls':str(os_calls),
          'os_calls_sha256':sha256(os_calls) if os_calls.is_file() else None,
          'owner_pid':owner,'execution_token':token},
      'source_hashes':{name:sha256(source/name) for name in ('fakenet/diverters/linux.py','fakenet/diverters/linutil.py','fakenet/diverters/diverterbase.py')},
      'started_at':started,'ended_at':datetime.now(timezone.utc).isoformat(),
      'cleanup':{'scope':'owned-linux-callback-os-boundary','stopped':cleanup_ok,
                 'threads_joined':cleanup_ok,'rules_cleared':cleanup_ok,
                 'system_network_restored':'not-exercised','system_iptables_restored':'not-exercised'},
      'checks':[{'id':x} for x in CHECKS[case]],'identity':{k:inputs[k] for k in IDENTITY}}
    _json(out/'manual-result.json',value);return value

def real_dumppackets(case, out, inputs):
    import logging
    from fakenet.diverters.diverterbase import DiverterBase
    out = Path(out)
    cfgdir = out / 'config'
    cfgdir.mkdir()
    started = datetime.now(timezone.utc).isoformat()
    # Fixed benign IPv4/TCP and IPv4/UDP bytes, replayed into the real writer.
    packets = [bytes.fromhex('450000280001000040060000c000020ac00002149c401f9000000000000000005002200000000000'),
               bytes.fromhex('450000200002000040110000c000020ac00002149c411f91000c000074657374')]
    for number, packet in enumerate(packets):
        (out / ('packet-%d.bin' % number)).write_bytes(packet)
    result = {}
    for mode, setting in (('enabled', 'Yes'), ('disabled', 'No')):
        folder = out / mode
        folder.mkdir()
        prefix = str(folder / 'customcap')
        cfg = cfgdir / (mode + '.ini')
        cfg.write_text('[Diverter]\nDumpPackets: ' + setting + '\nDumpPacketsFilePrefix: ' + prefix + '\n')
        loaded = configparser.ConfigParser()
        loaded.read(cfg)
        d = DiverterBase.__new__(DiverterBase)
        d.logger = logging.getLogger('manual-dumppackets')
        d._initialize_capture_state()
        d.configure(dict(loaded.items('Diverter')))
        before = sorted(path.name for path in folder.iterdir())
        summary = None
        error = None
        close_error = None
        observations = []
        try:
            d.parse_diverter_config()
            d._start_capture()
            if d.dual_pcap is not None:
                for number, packet in enumerate(packets):
                    observations.append(d.record_raw_capture(
                        packet, observation_role='inbound', direction='inbound',
                        logical_packet_id='dump-packet-%d' % number))
        except Exception as exc:
            error = {'type': type(exc).__name__, 'message': str(exc)}
        finally:
            try:
                summary = d._close_capture()
            except Exception as exc:
                close_error = {'type': type(exc).__name__, 'message': str(exc)}
        writer = d.dual_pcap
        originals = d._capture_originals
        streams = [getattr(writer, name, None) for name in ('_raw_file', '_ethernet_file')]
        streams += [getattr(originals, name, None) for name in ('_observations_stream', '_nbis_stream')]
        closed = all(stream is None or stream.closed for stream in streams)
        lifecycle = {'scope': 'owned-capture-files', 'streams_closed': closed,
                     'writer_present': writer is not None,
                     'writer_closed': writer is None or writer._closed,
                     'originals_closed': originals is None or originals._closed,
                     'originals_sealed': originals is not None and originals.sealed,
                     'capture_failure': str(d.capture_failure) if d.capture_failure else None,
                     'close_error': close_error, 'observations': observations}
        _json(out / ('lifecycle-' + mode + '.json'), lifecycle)
        result[mode] = {'config': str(cfg), 'config_sha256': sha256(cfg),
                        'folder': str(folder), 'prefix': prefix, 'dump': d.dump_packets,
                        'before': before, 'pcap_files': sorted(path.name for path in folder.glob('*.pcap')),
                        'summary': summary._asdict() if summary is not None else None,
                        'error': error, 'writer_closed': closed and lifecycle['writer_closed']}
    source = Path(__file__).resolve().parents[1]
    sources = ('fakenet/diverters/diverterbase.py', 'fakenet/diverters/fnconfig.py',
               'fakenet/diverters/pcapwriter.py', 'fakenet/capture_originals.py', 'fakenet/payload_report.py')
    value = {'schema': SCHEMA, 'case': case, 'fixture': inputs.get('fixture') is True,
             'evidence_kind': 'offline-packet-replay', 'wire_capture': False,
             'inputs': inputs, 'dumppackets': result,
             'source_hashes': {name: sha256(source / name) for name in sources},
             'started_at': started, 'ended_at': datetime.now(timezone.utc).isoformat(),
             'cleanup': {'scope': 'owned-capture-files',
                         'stopped': all(item['writer_closed'] for item in result.values()),
                         'system_network_restored': 'not-exercised'},
             'checks': [{'id': name} for name in CHECKS[case]],
             'identity': {name: inputs[name] for name in IDENTITY}}
    _json(out / 'manual-result.json', value)
    return value

def real_diverter_switch(case,out,inputs):
    import logging,sys
    from fakenet.fakenet import Fakenet
    out=Path(out);cfgdir=out/'config';cfgdir.mkdir();values={}
    base='[FakeNet]\nDivertTraffic: {traffic}\n[Diverter]\nNetworkMode: SingleHost\nLinuxRestrictInterface: Off\n'
    for mode,traffic in (('on','Yes'),('off','No')):
        cfg=cfgdir/(mode+'.ini');cfg.write_text(base.format(traffic=traffic))
        f=Fakenet(logging.INFO);f.parse_config(str(cfg));before={'diverttraffic':f.fakenet_config.get('diverttraffic'),'diverter':None,'listeners':len(f.listeners_config)}
        log=out/(mode+'-core.log');handler=logging.FileHandler(log,mode='x');handler.setFormatter(logging.Formatter('%(message)s'))
        f.logger.addHandler(handler);previous=sys.getprofile();calls=[];error=None;stop_errors=[];stops=[];started=False;active=None
        def observe(frame,event,arg):
            backend=f.diverter
            if backend is not None and frame.f_locals.get('self') is backend and event in ('call','return'):
                for method in ('start','stop'):
                    target=getattr(getattr(backend,method,None),'__func__',None)
                    if target is not None and frame.f_code is target.__code__:
                        calls.append({'method':method,'event':event})
            if previous is not None:previous(frame,event,arg)
        sys.setprofile(observe)
        try:
            f.start();started=True;active=type(f.diverter).__name__ if f.diverter is not None else None
        except BaseException as exc:error={'type':type(exc).__name__,'message':str(exc)}
        finally:
            try:
                for index in range(2):
                    try:stops.append(f.stop())
                    except BaseException as exc:
                        stops.append(None);stop_errors.append({'type':type(exc).__name__,'message':str(exc)})
            finally:
                sys.setprofile(previous);f.logger.removeHandler(handler);handler.close()
        created=f.diverter is not None
        start_calls=sum(x=={'method':'start','event':'call'} for x in calls)
        stop_calls=sum(x=={'method':'stop','event':'call'} for x in calls)
        after={'diverter':type(f.diverter).__name__ if created else None,'started':started and created,
               'stop1':stops[0],'stop2':stops[1],'stop_calls':stop_calls,'listeners':len(f.listeners_config)}
        observation={'schema':'fakenet.switch-observation.v1','mode':mode,'execution_id':inputs['execution_id'],
                     'calls':calls,'stop_complete':f._stop_complete.is_set(),'stop_result':f._stop_result,
                     'stop_error':type(f._stop_error).__name__ if f._stop_error else None,'start_error':error,'stop_errors':stop_errors}
        raw=out/(mode+'-observation.json');_json(raw,observation)
        values[mode]={'config':str(cfg),'config_sha256':sha256(cfg),'before':before,'after':after,'error':error,'start_calls':start_calls,
                     'observation':str(raw),'observation_sha256':sha256(raw),'core_log':str(log),'core_log_sha256':sha256(log)}
    restored=all(v['error'] is None and v['after']['stop1'] is True and v['after']['stop2'] is True for v in values.values())
    value={'schema':SCHEMA,'case':case,'fixture':inputs.get('fixture') is True,'inputs':inputs,'diverter_switch':values,
      'source_hashes':{n:sha256(Path(__file__).resolve().parents[1]/n) for n in ('fakenet/fakenet.py','fakenet/diverters/linux.py','fakenet/diverters/windows.py')},
      'cleanup':{'stopped':restored,'scope':'observed-core-start-stop','system_network_restored':'unverified'},
      'checks':[{'id':x} for x in CHECKS[case]],'identity':{k:inputs[k] for k in IDENTITY}}
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
    if case=='GAP-DUMPPACKETS':
        validate_inputs(case,inputs);out=Path(out).absolute()
        if str(out)!=inputs['owned_root'] or str(out/'config')!=inputs['config']:raise ValueError('manual output differs from frozen owned_root/config')
        out.mkdir(parents=True,exist_ok=False)
        return real_dumppackets(case,out,inputs)
    if case=='GAP-SYSLOG-ICMP-LOG':
        validate_inputs(case,inputs);out=Path(out).absolute()
        if str(out)!=inputs['owned_root'] or str(out/'config')!=inputs['config']:raise ValueError('manual output differs from frozen owned_root/config')
        out.mkdir(parents=True,exist_ok=False)
        return real_syslog_icmp(case,out,inputs)
    if case=='GAP-CTRLC-IPC':
        validate_inputs(case,inputs);out=Path(out).absolute()
        if str(out)!=inputs['owned_root'] or str(out/'config')!=inputs['config']:raise ValueError('manual output differs from frozen owned_root/config')
        out.mkdir(parents=True,exist_ok=False)
        return real_ctrlc_ipc(case,out,inputs)
    if case=='GAP-LINUX-FLUSH-INTERFACE':
        validate_inputs(case,inputs);out=Path(out).absolute()
        if str(out)!=inputs['owned_root'] or str(out/'config')!=inputs['config']:raise ValueError('manual output differs from frozen owned_root/config')
        out.mkdir(parents=True,exist_ok=False)
        return real_linux_flush_interface(case,out,inputs)
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
