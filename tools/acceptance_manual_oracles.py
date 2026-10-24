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

def _evaluate_syslog_icmp(root,original,expected_inputs,allow_fixture=False):
    base=Path(original).resolve();path=base/'manual-result.json'
    if path.is_symlink() or not path.is_file():raise ValueError('original missing or linked')
    v=json.loads(path.read_text())
    if v.get('schema')!='fakenet.manual-result.v1' or v.get('case')!='GAP-SYSLOG-ICMP-LOG':raise ValueError('case/schema mismatch')
    if v.get('inputs')!=expected_inputs:raise ValueError('frozen inputs mismatch')
    for k in ('candidate_id','source_commit','package_sha256','execution_id'):
        if v.get('identity',{}).get(k)!=expected_inputs.get(k):raise ValueError('identity mismatch: '+k)
    if type(v.get('fixture')) is not bool or v['fixture']!=(expected_inputs.get('fixture') is True):raise ValueError('fixture identity mismatch')
    if v['fixture'] and not allow_fixture:raise ValueError('fixture cannot native credit')
    if str(base)!=expected_inputs.get('owned_root'):raise ValueError('frozen owned root mismatch')
    d=v.get('syslog_icmp') or {};errors=[]
    if d.get('main_rc_on')!=0 or d.get('main_rc_off')!=0:errors.append('original main -s/off exit mismatch')
    sink=Path(d.get('syslog_sink',''));sink_bytes=sink.read_bytes() if sink.is_file() else b''
    if not sink_bytes or b'"levelName"' not in sink_bytes or b'FakeNet-NG' not in sink_bytes:errors.append('syslog sink original bytes missing/not formatter output')
    log=Path(d.get('icmp_log',''));lines=log.read_text(encoding='utf-8').splitlines() if log.is_file() else []
    if len(lines)!=1 or 'ICMP type 8 code 0' not in lines[0]:errors.append('ICMP log must contain exactly one positive log line')
    if d.get('icmp_type')!=8 or d.get('icmp_code')!=0 or d.get('icmp_id')!=4321:errors.append('ICMP parser fields differ')
    if d.get('execution_token')!=expected_inputs['execution_id'] or not isinstance(d.get('owner_pid'),int) or d['owner_pid']<=0:errors.append('owner/token mismatch')
    if v.get('source_hashes')!={n:hashlib.sha256((Path(root)/n).read_bytes()).hexdigest() for n in ('fakenet/fakenet.py','fakenet/diverters/fnpacket.py','fakenet/diverters/diverterbase.py')}:errors.append('source binding mismatch')
    if v.get('cleanup')!={'stopped':True,'threads_joined':True,'sockets_closed':True,'network_restored':True}:errors.append('cleanup mismatch')
    return [{'id':k,'status':'fail' if errors else 'pass'} for k in ('syslog','icmp','owner')],not errors,{'failures':errors}

def _evaluate_dumppackets(root, original, expected_inputs, allow_fixture=False):
    import configparser
    import dpkt
    from fakenet.payload_report import load_capture_originals
    base = Path(original).absolute()
    errors = []
    def require(condition, reason):
        if not condition:
            raise ValueError(reason)
    def plain(path):
        path = Path(path)
        require(path.is_file(), 'missing original: ' + str(path))
        require(not any(item.is_symlink() for item in (path, *path.parents)), 'linked original')
        return path
    try:
        require(str(base) == expected_inputs.get('owned_root'), 'frozen owned root mismatch')
        v = json.loads(plain(base / 'manual-result.json').read_text())
        require(v.get('schema') == 'fakenet.manual-result.v1' and v.get('case') == 'GAP-DUMPPACKETS', 'case/schema mismatch')
        require(v.get('inputs') == expected_inputs, 'frozen inputs mismatch')
        require(v.get('identity') == {key: expected_inputs[key] for key in ('candidate_id', 'source_commit', 'package_sha256', 'execution_id')}, 'identity mismatch')
        require(type(v.get('fixture')) is bool and v['fixture'] == (expected_inputs.get('fixture') is True), 'fixture identity mismatch')
        require(not v['fixture'] or allow_fixture, 'fixture cannot native credit')
        require(v.get('evidence_kind') == 'offline-packet-replay' and v.get('wire_capture') is False, 'packet replay provenance missing')
        require(v.get('checks') == [{'id': key} for key in ('enabled', 'disabled', 'prefix', 'content')], 'checks mismatch')
        require(v.get('cleanup') == {'scope': 'owned-capture-files', 'stopped': True, 'system_network_restored': 'not-exercised'}, 'owned cleanup mismatch')
        # Independent literal packet truth, never selected by the producer's files.
        expected = [bytes.fromhex('450000280001000040060000c000020ac00002149c401f9000000000000000005002200000000000'),
                    bytes.fromhex('450000200002000040110000c000020ac00002149c411f91000c000074657374')]
        for number, packet in enumerate(expected):
            require(plain(base / ('packet-%d.bin' % number)).read_bytes() == packet, 'fixed packet input mismatch')
        sources = ('fakenet/diverters/diverterbase.py', 'fakenet/diverters/fnconfig.py',
                   'fakenet/diverters/pcapwriter.py', 'fakenet/capture_originals.py', 'fakenet/payload_report.py')
        require(v.get('source_hashes') == {name: hashlib.sha256((Path(root) / name).read_bytes()).hexdigest() for name in sources}, 'source binding mismatch')
        require(set(v.get('dumppackets', {})) == {'enabled', 'disabled'}, 'missing capture branch')
        for mode, setting in (('enabled', 'Yes'), ('disabled', 'No')):
            item = v['dumppackets'][mode]
            folder = base / mode
            cfg = base / 'config' / (mode + '.ini')
            prefix = str(folder / 'customcap')
            require(folder.is_dir() and not any(path.is_symlink() for path in (folder, *folder.parents)), 'owned branch path mismatch')
            require(item.get('folder') == str(folder) and item.get('prefix') == prefix and item.get('config') == str(cfg), 'owned configuration/prefix mismatch')
            require(plain(cfg).read_text() == '[Diverter]\nDumpPackets: ' + setting + '\nDumpPacketsFilePrefix: ' + prefix + '\n', 'exact configuration mismatch')
            require(item.get('config_sha256') == hashlib.sha256(cfg.read_bytes()).hexdigest(), 'configuration hash mismatch')
            parser = configparser.ConfigParser()
            parser.read(cfg)
            require(parser.getboolean('Diverter', 'DumpPackets') == (mode == 'enabled'), 'configured switch mismatch')
            require(item.get('before') == [] and item.get('error') is None and item.get('writer_closed') is True, 'branch before/error/close mismatch')
            files = sorted(path.name for path in folder.glob('*.pcap'))
            require(item.get('pcap_files') == files, 'actual PCAP inventory mismatch')
            lifecycle = json.loads(plain(base / ('lifecycle-' + mode + '.json')).read_text())
            require(lifecycle.get('scope') == 'owned-capture-files' and lifecycle.get('streams_closed') is True and lifecycle.get('writer_closed') is True and lifecycle.get('originals_closed') is True and lifecycle.get('close_error') is None and lifecycle.get('capture_failure') is None, 'actual writer lifecycle mismatch')
            if mode == 'disabled':
                require(not list(folder.iterdir()) and item.get('summary') is None and lifecycle.get('writer_present') is False and lifecycle.get('originals_sealed') is False and lifecycle.get('observations') == [], 'disabled output/writer mismatch')
                continue
            require(len(files) == 2 and all(name.startswith('customcap_') and Path(name).name == name for name in files), 'enabled custom prefix output missing')
            raw = plain(folder / next(name for name in files if not name.endswith('-converted.pcap')))
            converted = plain(folder / next(name for name in files if name.endswith('-converted.pcap')))
            loaded = load_capture_originals(raw, converted)
            with raw.open('rb') as stream:
                reader = dpkt.pcap.Reader(stream)
                require(reader.datalink() == dpkt.pcap.DLT_RAW, 'raw linktype mismatch')
                raws = [bytes(packet) for _, packet in reader]
            with converted.open('rb') as stream:
                reader = dpkt.pcap.Reader(stream)
                require(reader.datalink() == dpkt.pcap.DLT_EN10MB, 'converted linktype mismatch')
                converted_packets = [bytes(packet) for _, packet in reader]
            header = bytes.fromhex('0200000000020200000000010800')
            require(raws == expected and converted_packets == [header + packet for packet in expected], 'PCAP bytes/frames differ from independent fixed packets')
            require(lifecycle.get('writer_present') is True and lifecycle.get('originals_sealed') is True and lifecycle.get('observations') == loaded.entries, 'sealed observations/lifecycle mismatch')
            for number, entry in enumerate(loaded.entries):
                require(entry.get('logical_packet_id') == 'dump-packet-%d' % number and entry.get('direction') == 'inbound' and entry.get('observation_role') == 'inbound', 'observation direction/identity mismatch')
            require(len(loaded.entries) == len(expected), 'observation count mismatch')
            require(set(path.name for path in folder.iterdir()) == {raw.name, converted.name, raw.name + '.observations.ndjson', raw.name + '.nbis.ndjson', raw.name + '.capture-originals.json'}, 'capture original inventory mismatch')
            summary = item.get('summary') or {}
            require(summary.get('raw_filename') == str(raw) and summary.get('ethernet_filename') == str(converted) and summary.get('raw_write_count') == len(expected) and summary.get('ethernet_write_count') == len(expected) and summary.get('healthy') is True and summary.get('discarded') is False, 'writer summary mismatch')
    except Exception as exc:
        errors.append(type(exc).__name__ + ': ' + str(exc))
    return [{'id': key, 'status': 'fail' if errors else 'pass'} for key in ('enabled', 'disabled', 'prefix', 'content')], not errors, {'failures': errors}

def _evaluate_diverter_switch(root,original,expected_inputs,allow_fixture=False):
    base=Path(original).resolve();path=base/'manual-result.json'
    if path.is_symlink() or not path.is_file():raise ValueError('original missing or linked')
    v=json.loads(path.read_text())
    if v.get('schema')!='fakenet.manual-result.v1' or v.get('case')!='GAP-DIVERTER-SWITCH':raise ValueError('case/schema mismatch')
    if v.get('inputs')!=expected_inputs:raise ValueError('frozen inputs mismatch')
    for k in ('candidate_id','source_commit','package_sha256','execution_id'):
        if v.get('identity',{}).get(k)!=expected_inputs.get(k):raise ValueError('identity mismatch: '+k)
    if type(v.get('fixture')) is not bool or v['fixture']!=(expected_inputs.get('fixture') is True):raise ValueError('fixture identity mismatch')
    if v['fixture'] and not allow_fixture:raise ValueError('fixture cannot native credit')
    if str(base)!=expected_inputs.get('owned_root'):raise ValueError('frozen owned root mismatch')
    errors=[];data=v.get('diverter_switch') or {}
    if set(data)!=set(('on','off')):errors.append('exact branch set differs')
    for mode,traffic in (('on','Yes'),('off','No')):
        item=data.get(mode) or {};cfg=base/'config'/(mode+'.ini')
        if item.get('config')!=str(cfg) or not cfg.is_file() or cfg.is_symlink() or item.get('config_sha256')!=hashlib.sha256(cfg.read_bytes()).hexdigest():
            errors.append(mode+' config missing/changed/foreign');continue
        text='[FakeNet]\nDivertTraffic: '+traffic+'\n[Diverter]\nNetworkMode: SingleHost\nLinuxRestrictInterface: Off\n'
        if cfg.read_text()!=text:errors.append(mode+' traffic configuration differs')
        if item.get('before')!={'diverttraffic':traffic,'diverter':None,'listeners':0}:errors.append(mode+' before state differs')
        if item.get('error') is not None:errors.append(mode+' production error')
        after=item.get('after') or {};on=mode=='on'
        if item.get('start_calls')!=(1 if on else 0):errors.append(mode+' backend start not observed once')
        if (after.get('started') is not on or (on and not after.get('diverter')) or (not on and after.get('diverter') is not None)
                or after.get('stop1') is not True or after.get('stop2') is not True or after.get('stop_calls')!=(1 if on else 0)
                or after.get('listeners')!=0):errors.append(mode+' start/stop/restore mismatch')
        obs=base/(mode+'-observation.json');log=base/(mode+'-core.log')
        if (item.get('observation')!=str(obs) or not obs.is_file() or obs.is_symlink() or item.get('observation_sha256')!=hashlib.sha256(obs.read_bytes()).hexdigest()
                or item.get('core_log')!=str(log) or not log.is_file() or log.is_symlink() or item.get('core_log_sha256')!=hashlib.sha256(log.read_bytes()).hexdigest()):
            errors.append(mode+' observation/log original missing/changed');continue
        expected_calls=[{'method':method,'event':event} for method in ('start','stop') for event in ('call','return')] if on else []
        expected_obs={'schema':'fakenet.switch-observation.v1','mode':mode,'execution_id':expected_inputs['execution_id'],
                      'calls':expected_calls,'stop_complete':True,'stop_result':True,'stop_error':None,'start_error':None,'stop_errors':[]}
        if json.loads(obs.read_text())!=expected_obs:errors.append(mode+' original call/cleanup observations differ')
        lines=log.read_text().splitlines()
        if lines.count('DEFAULT_INTERCEPTION_READY')!=(1 if on else 0):errors.append(mode+' original interception-ready marker differs')
        if not any(line.startswith('STOP_PHASE_END phase=complete') and line.endswith('healthy=True') for line in lines):errors.append(mode+' stop completion log missing')
    if v.get('source_hashes')!={n:hashlib.sha256((Path(root)/n).read_bytes()).hexdigest() for n in ('fakenet/fakenet.py','fakenet/diverters/linux.py','fakenet/diverters/windows.py')}:errors.append('source binding mismatch')
    if v.get('cleanup')!={'stopped':True,'scope':'observed-core-start-stop','system_network_restored':'unverified'}:errors.append('cleanup mismatch')
    if v.get('checks')!=[{'id':k} for k in ('on','off','restore')]:errors.append('exact check set differs')
    return [{'id':k,'status':'fail' if errors else 'pass'} for k in ('on','off','restore')],not errors,{'failures':errors}

def _evaluate_executecmd(root,original,expected_inputs,allow_fixture=False):
    from types import SimpleNamespace
    from fakenet.diverters.diverterbase import DiverterBase,DivertParms
    import logging
    base=Path(original).resolve();path=base/'manual-result.json'
    if path.is_symlink() or not path.is_file():raise ValueError('original missing or linked')
    v=json.loads(path.read_text())
    if v.get('schema')!='fakenet.manual-result.v1' or v.get('case')!='GAP-EXECUTECMD':raise ValueError('case/schema mismatch')
    if v.get('inputs')!=expected_inputs:raise ValueError('frozen inputs mismatch')
    for k in ('candidate_id','source_commit','package_sha256','execution_id'):
        if v.get('identity',{}).get(k)!=expected_inputs.get(k):raise ValueError('identity mismatch: '+k)
    if type(v.get('fixture')) is not bool or v['fixture']!=(expected_inputs.get('fixture') is True):raise ValueError('fixture identity/credit mismatch')
    if v['fixture'] and not allow_fixture:raise ValueError('fixture cannot native credit')
    if not v['fixture'] and (v.get('executecmd',{}).get('os_platform')!='windows'):raise ValueError('native command evidence requires Windows platform')
    if str(base)!=expected_inputs.get('owned_root'):raise ValueError('frozen owned root mismatch')
    data=v.get('executecmd') or {};cfg=base/'config/executecmd.ini';errors=[]
    if not cfg.is_file() or cfg.is_symlink() or data.get('configuration')!='config/executecmd.ini' or data.get('configuration_sha256')!=hashlib.sha256(cfg.read_bytes()).hexdigest():raise ValueError('configuration original missing/changed')
    token=str(expected_inputs['execution_id']);output=base/'command-output.txt'
    template='cmd.exe /c echo {pid} {procname} {src_addr} {src_port} {dst_addr} {dst_port} '+token+'>>"'+str(output)+'"'
    if cfg.read_text()!='[svc]\nProtocol: TCP\nPort: 8080\nExecuteCmd: '+template+'\n[plain]\nProtocol: TCP\nPort: 8090\n':errors.append('frozen configuration differs')
    diverter=DiverterBase.__new__(DiverterBase);diverter.logger=logging.getLogger('oracle-executecmd');diverter.sessions={};diverter.configure({});diverter.listener_ports=__import__('fakenet.diverters.diverterbase',fromlist=['ListenerPorts']).ListenerPorts()
    diverter.parse_listeners_config({'svc':{'protocol':'TCP','port':'8080','executecmd':template}})
    pkt=SimpleNamespace(proto='TCP',sport=40000,dport=8080,src_ip='192.0.2.10',dst_ip='192.0.2.20',src_ip0='192.0.2.10',dst_ip0='192.0.2.20',dport0=8080,_dport0=8080,ipver=4)
    payload='1234 benign.exe 192.0.2.10 40000 192.0.2.20 8080 '+token
    expected='cmd.exe /c echo '+payload+'>>"'+str(output)+'"'
    if diverter.build_cmd(pkt,1234,'benign.exe')!=expected:errors.append('production build_cmd differs')
    parms=DivertParms(diverter,pkt,1234,'benign.exe')
    if parms.first_packet_new_session is not True:errors.append('first session predicate false')
    diverter.addSession(pkt,1234,'benign.exe')
    if DivertParms(diverter,pkt,1234,'benign.exe').first_packet_new_session is not False:errors.append('duplicate session predicate true')
    raw=None
    if data.get('command_output')!=str(output) or not output.is_file() or output.is_symlink():
        errors.append('command output original missing/changed')
    elif output.stat().st_size>4096:errors.append('command output exceeds fixed probe bound')
    else:
        raw=output.read_bytes()
        if data.get('command_output_sha256')!=hashlib.sha256(raw).hexdigest():errors.append('command output original missing/changed')
        if raw not in ((payload+'\n').encode('ascii'),(payload+'\r\n').encode('ascii')):
            errors.append('command output six fields/token or line count differs')
        if data.get('command_output_encoding')!='hex' or data.get('command_output_bytes')!=raw.hex():
            errors.append('command output byte observation differs')
    if data.get('token')!=token:errors.append('command token differs')
    if data.get('command')!=expected or data.get('first_packet') is not True or data.get('duplicate_first_packet') is not False:errors.append('command/session originals mismatch')
    executed=data.get('executed')
    if not isinstance(executed,list) or len(executed)!=1 or executed[0].get('command')!=expected or type(executed[0].get('pid')) is not int or executed[0]['pid']<=0:errors.append('first execution original mismatch')
    if data.get('missing_pid_executions')!=0:errors.append('missing PID executed')
    if data.get('nonmatching_command') is not None:errors.append('nonmatching port built command')
    bad=data.get('bad_format_error')
    if not isinstance(bad,dict) or bad.get('type')!='SystemExit' or bad.get('code')!=1:errors.append('bad format did not exit 1')
    expected_actions=[
      {'name':'first','protocol':'TCP','source_port':40000,'destination_port':8080,'pid':1234,'first_packet':True,'executions':1,'session_count':1},
      {'name':'duplicate','protocol':'TCP','source_port':40000,'destination_port':8080,'pid':1234,'first_packet':False,'executions':0,'session_count':1},
      {'name':'missing-pid','protocol':'TCP','source_port':40001,'destination_port':8080,'pid':None,'first_packet':True,'executions':0,'session_count':2},
      {'name':'no-command-listener','protocol':'TCP','source_port':40002,'destination_port':8090,'pid':1234,'first_packet':True,'executions':0,'session_count':3},
      {'name':'no-default-protocol','protocol':'UDP','source_port':40003,'destination_port':8080,'pid':1234,'first_packet':True,'executions':0,'session_count':3}]
    if data.get('actions')!=expected_actions:errors.append('original first/duplicate/nontrigger action sequence differs')
    if data.get('sessions_after')!=0 or data.get('port_forwards_after')!=0:errors.append('original in-memory state not restored')
    if data.get('template')!=template:errors.append('command template identity differs')
    if v.get('checks')!=[{'id':k} for k in ('command','first-connection','non-connection')]:errors.append('exact check set differs')
    if v.get('source_hashes')!={n:hashlib.sha256((Path(root)/n).read_bytes()).hexdigest() for n in ('fakenet/diverters/diverterbase.py','fakenet/diverters/fnpacket.py')}:errors.append('source binding mismatch')
    if v.get('cleanup')!={'stopped':True,'threads_joined':True,'sockets_closed':True,'network_restored':True,
            'scope':'in-memory-case-state','child_exit':'not-observed','child_termination_performed':False}:errors.append('cleanup mismatch')
    out=[{'id':k,'status':'fail' if errors else 'pass'} for k in ('command','first-connection','non-connection')]
    return out,not errors,{'failures':errors}

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
    if case=='GAP-SYSLOG-ICMP-LOG':return _evaluate_syslog_icmp(root,original,expected_inputs,allow_fixture)
    if case=='GAP-DUMPPACKETS':return _evaluate_dumppackets(root,original,expected_inputs,allow_fixture)
    if case=='GAP-DIVERTER-SWITCH':return _evaluate_diverter_switch(root,original,expected_inputs,allow_fixture)
    if case=='GAP-EXECUTECMD':return _evaluate_executecmd(root,original,expected_inputs,allow_fixture)
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
