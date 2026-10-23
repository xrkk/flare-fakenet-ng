"""Reconstruct headless verdicts from bound original bytes, never producer checks."""
from __future__ import annotations
import configparser
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

SCHEMA='fakenet.headless-result.v2'


def _read(path):return Path(path).read_text(encoding='utf-8',errors='strict')
def _sha256(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def _load(root,relative):
    spec=importlib.util.spec_from_file_location('headless_original_'+Path(relative).stem,Path(root)/relative)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def _safe(original,item,label):
    root=Path(original).resolve()
    if not isinstance(item,str) or Path(item).is_absolute() or '..' in Path(item).parts:raise ValueError(label+' is not an owned relative path')
    path=Path(original)/item
    for node in (path,*path.parents):
        if node==Path(original).parent:break
        if node.is_symlink():raise ValueError(label+' contains symlink')
    if not path.is_file() or not path.resolve().is_relative_to(root):raise ValueError(label+' missing/escaped')
    return path


def _json(original,name):return json.loads(_read(_safe(original,name,name)))


def _recovery(original,value):
    try:
        before=_json(original,value['network_before']);after=_json(original,value['network_after'])
        core=_json(original,value['core']);capture=_json(original,value['capture_lifecycle'])
        clean=bool(before) and before==after and 'error' not in before and core.get('exited') is True and core.get('returncode')==0 and core.get('forced',False) is False and capture.get('stopped') is True
        if not core.get('not_started'):clean=clean and type(core.get('pid')) is int and core['pid']>0 and bool(core.get('birth'))
        if not value['fixture']:clean=clean and not before.get('fixture')
        return bool(clean)
    except (OSError,ValueError,KeyError,TypeError):return False


def _configuration(root,original,value,inputs,producer_directory,source_root=None):
    import acceptance_headless as driver
    path=_safe(original,value['config'],'configuration')
    expected=driver.config_text(value['mode'],inputs,producer_directory or original,source_root)
    def parsed(text):
        p=configparser.ConfigParser(interpolation=None);p.optionxform=str;p.read_string(text)
        return {section:dict(p[section]) for section in p.sections()}
    if parsed(_read(path))!=parsed(expected):raise ValueError('actual configuration differs from frozen inputs/template')


def _packets(original,value):
    from acceptance_policy_oracles import _pcap_packets
    return _pcap_packets(_safe(original,value['paths']['wire'],'wire capture'))


def _roundtrip(packets,flow,nonce,start,end,role='target'):
    from acceptance_policy_oracles import _matching,_stream,Unobservable
    selected=_matching(packets,flow,start,end)
    out=[p for p in selected if p['direction']=='out'];incoming=[p for p in selected if p['direction']=='in']
    if not out or not incoming:raise Unobservable('matching bidirectional wire flow missing')
    request=('FNPR/1|%s|%s\n'%(nonce,role)).encode();response=('FNPR/1|%s|OK\n'%nonce).encode()
    if request not in _stream(out) or response not in _stream(incoming):raise ValueError('wire nonce/application response differs')
    return request,response


def _identities(original,value,inputs):
    if value['mode']=='payload':return True
    import acceptance_headless as driver
    identities=value.get('identities') or {}
    for role,key in [('target','target'),('non-target','non_target')]:
        row=identities[role];copy=_safe(original,row['copy'],role+' PE')
        if driver.canonical(row['original_path'])!=driver.canonical(inputs[key+'_path']) or _sha256(copy)!=inputs[key+'_sha256'] or row['sha256']!=inputs[key+'_sha256'] or copy.read_bytes()[:2]!=b'MZ':raise ValueError('PE identity/hash/path differs from frozen input')
    return True


def _client(original,value,inputs,name,count,role,failures):
    import acceptance_headless as driver
    verifier=_load(Path(driver.ROOT),'test/process_redirect_vm/verify_process_redirect.py')
    record=value['clients'][name];path=_safe(original,record['path'],name+' client')
    result=verifier.validate_client_log(path,role,count,'%s:%d'%(inputs['original_ip'],inputs['port']),failures)
    rows=verifier.read_jsonl(path);identity=rows[0];connections=rows[1:-1]
    expected_path=inputs['target_path' if role=='target' else 'non_target_path']
    owner=_json(original,record['owner'])
    if driver.canonical(identity['final_path'])!=driver.canonical(expected_path) or identity['pid']!=owner.get('pid') or owner.get('exited') is not True or owner.get('forced') is not False or owner.get('returncode')!=record.get('returncode'):
        raise ValueError(name+' process owner/path/exit differs')
    if not identity.get('creation_time') or not owner.get('birth'):raise ValueError(name+' process birth missing')
    if not value['fixture'] and abs(identity['creation_time']/10000000-11644473600-owner['birth'])>.1:raise ValueError(name+' process birth differs')
    if any(not r['nonce'].startswith(record['nonce_prefix']+'-'+str(identity['pid'])+'-') for r in connections):raise ValueError(name+' current nonce does not bind original process')
    if record.get('count')!=count or record.get('role')!=role:raise ValueError(name+' selection count/role differs')
    return result,identity,connections,owner


def evaluate_process(root,original,checks,allow_fixture=False,expected_inputs=None,producer_directory=None,source_root=None):
    return evaluate(root,original,'process',checks,allow_fixture,expected_inputs,producer_directory,source_root)


def evaluate_payload(root,original,checks,allow_fixture=False,expected_inputs=None,producer_directory=None,source_root=None):
    return evaluate(root,original,'payload',checks,allow_fixture,expected_inputs,producer_directory,source_root)


def evaluate(root,original,mode,checks,allow_fixture=False,expected_inputs=None,producer_directory=None,source_root=None):
    import acceptance_headless as driver
    from acceptance_policy_oracles import Unobservable
    from fakenet.payload_report import PayloadReportError
    original=Path(original);value=_json(original,'headless-result.json')
    if value.get('schema')!=SCHEMA or value.get('mode')!=mode:raise ValueError('headless schema/mode mismatch')
    fixture=value.get('fixture') is True
    if fixture and not allow_fixture:raise ValueError('fixture cannot earn native credit')
    inputs=value.get('inputs')
    selection=driver.validate_inputs(mode,inputs,checks)
    if value.get('selection')!=selection:raise ValueError('selection differs from frozen case')
    if expected_inputs is not None and inputs!=expected_inputs:raise ValueError('inputs differ from frozen plan')
    clean=_recovery(original,value)
    try:
        _configuration(root,original,value,inputs,producer_directory,source_root)
        _identities(original,value,inputs)
    except ValueError as exc:
        return [{'id':name,'status':'fail','reason':str(exc)} for name in selection],clean,{'mismatch':str(exc)}
    if value.get('error'):return [{'id':c,'status':'fail','reason':value['error']} for c in selection],clean,{'producer_error':value['error']}
    if set(selection)=={'identity'}:return [{'id':'identity','status':'pass'}],clean,{}
    controls=value.get('controls') or []
    protocols={'TCP'} if mode=='process' else {'TCP','UDP'}
    for protocol in protocols:
        matches=[c for c in controls if c.get('tuple',{}).get('proto')==protocol]
        if len(matches)!=1:raise ValueError('stopped control set differs')
        c=matches[0];f=c['tuple']
        if (f['src'],f['dst'],f['port'])!=(inputs['source_ip'],inputs['target_ip'],inputs['port']) or bytes.fromhex(c['response_hex'])!=('FNPR/1|%s|OK\n'%c['nonce']).encode():raise ValueError('sink stopped-state control did not succeed')
    packets=_packets(original,value);rows=[]
    if mode=='process':
        log=_read(_safe(original,value['log'],'core log'));verifier=_load(root,'test/process_redirect_vm/verify_process_redirect.py');verifier.validate_runtime_log(log)
        budget=driver.owner_budget()
        if value.get('budget')!=budget:raise ValueError('owner budget not derived from frozen core')
        # NIC capture belongs only to target clients, after the non-target phase.
        if any(p['src']==inputs['original_ip'] or p['dst']==inputs['original_ip'] for p in packets):raise ValueError('target capture contains original A traffic')
        for name in selection:
            try:
                if name=='identity':pass
                elif name=='non-target-negative':
                    _client(original,value,inputs,'non-target',1,'non-target',1)
                elif name=='pcap-restore':
                    if not clean:raise ValueError('independent network/owned cleanup not restored')
                    _verify_positive(original,value,inputs,packets,'positive',1,verifier,log)
                    pair=_load(root,'test/dual_pcap_vm/verify_dual_pcap.py')
                    pair.verify(str(_safe(original,value['paths']['raw'],'raw')),str(_safe(original,value['paths']['converted'],'converted')),expected_versions=(4,))
                else:
                    label,count=('positive',1) if name=='target-positive' else ('owner',2) if name=='owner-bounded' else ('burst',budget['burst'])
                    _verify_positive(original,value,inputs,packets,label,count,verifier,log)
                    if name=='budget':
                        result,identity,connections,owner=_client(original,value,inputs,'burst',budget['burst'],'target','budget_pressure')
                        if owner['ended_at']-owner['started_at']>30:raise ValueError('burst execution is not bounded')
                        if not any(c['success'] for c in connections) or not re.search(r'owner_query_budget_exhausted=([1-9][0-9]*)',log):raise ValueError('bounded burst did not trigger observed core budget')
                rows.append({'id':name,'status':'pass'})
            except Unobservable as exc:rows.append({'id':name,'status':'unknown','reason':str(exc)})
            except (ValueError,KeyError,TypeError,OSError,AssertionError,PayloadReportError) as exc:rows.append({'id':name,'status':'fail','reason':str(exc)})
    else:
        paths={key:_safe(original,value['paths'][key],key) for key in ('raw','converted','index','html','wire')}
        probes=value.get('probes') or []
        if len(probes)!=2 or {p['tuple']['proto'] for p in probes}!={'TCP','UDP'}:raise ValueError('payload TCP/UDP probe set differs')
        identities=set()
        for probe in probes:
            f=probe['tuple']
            if (f['src'],f['dst'],f['port'])!=(inputs['source_ip'],inputs['target_ip'],inputs['port']):raise ValueError('payload flow differs from frozen endpoints')
            _roundtrip(packets,f,probe['nonce'],probe['started_at'],probe['ended_at'])
            if not probe.get('pid') or not probe.get('process'):raise ValueError('payload producer identity missing')
            identities.add((probe['pid'],probe['process']))
        report=_load(root,'test/gui_vm/verify_payload_report.py');integrity=_load(root,'test/gui_vm/verify_payload_integrity.py');reassembly=_load(root,'test/gui_vm/verify_reassembly.py')
        model=integrity._html_model(str(paths['html']))
        flows=[f for f in model['flows'] if f.get('disposition')=='ALLOW_TAKEOVER_SINK']
        if not flows or {(f.get('pid'),f.get('process')) for f in flows}!=identities:raise ValueError('HTML flow PID/producer binding differs or multiple candidates')
        if {f['protocol'].upper() for f in flows}!={'TCP','UDP'}:raise ValueError('HTML TCP/UDP directions missing')
        for flow in flows:
            if len(flow.get('directions') or {})!=2:raise ValueError('HTML payload missing direction')
        for name in selection:
            try:
                if name=='report':res=report.verify(str(paths['html']))
                elif name=='integrity':res=integrity.verify(str(paths['raw']),str(paths['wire']),str(paths['html']),str(_safe(original,value['log'],'log')),str(_safe(original,value['config'],'config')),value['capture_started_at'])
                else:res=reassembly.verify(str(paths['raw']),str(paths['index']),str(paths['converted']))
                if res.get('verdict')!='PASS':raise ValueError('original '+name+' verifier refused')
                rows.append({'id':name,'status':'pass'})
            except (ValueError,KeyError,TypeError,OSError,AssertionError,PayloadReportError) as exc:rows.append({'id':name,'status':'fail','reason':str(exc)})
    return rows,clean,{}


def _verify_positive(original,value,inputs,packets,name,count,verifier,log):
    budget_mode='budget_pressure' if name=='burst' else 0
    result,identity,connections,owner=_client(original,value,inputs,name,count,'target',budget_mode)
    for row in connections:
        if not row['success']:continue
        src,sport=row['local'].rsplit(':',1)
        if src!=inputs['source_ip']:raise ValueError('client source differs from frozen interface')
        flow={'proto':'TCP','src':src,'sport':int(sport),'dst':inputs['target_ip'],'port':inputs['port']}
        _roundtrip(packets,flow,row['nonce'],owner['started_at']-.01,owner['ended_at']+.01)
    # Mapping identity is emitted by the actual process-redirection core.
    for row in connections:
        if not row['success']:continue
        src,sport=row['local'].rsplit(':',1)
        matches=[]
        for line in log.splitlines():
            if 'PROCESS_REDIRECT_MAPPING_CREATED' not in line:continue
            fields=dict(re.findall(r'(\w+)=([^\s]+)',line))
            wanted={'pid':str(identity['pid']),'source_ipv4':src,'source_port':sport,
                    'original_ipv4':inputs['original_ip'],'target_ipv4':inputs['target_ip'],
                    'original_port':str(inputs['port']),'target_port':str(inputs['port']),
                    'process_image_sha256':inputs['target_sha256'],
                    'process_creation_time':str(identity['creation_time'])}
            if all(fields.get(k)==v for k,v in wanted.items()):matches.append(fields)
        if len(matches)!=1:raise ValueError('missing/ambiguous exact mapping owner/flow/image identity')
    required=sum(1 for c in connections if c['success'])
    if len(re.findall('PROCESS_REDIRECT_MAPPING_CREATED',log))<required:raise ValueError('mapping log incomplete')


def verify_services(original,directory,inputs):
    """Closed host service evidence, correlated across clocks by nonce/flow/bytes."""
    value=_json(original,'headless-result.json');directory=Path(directory)
    ready=read_json(directory/'ready.json');life=read_json(directory/'lifecycle.json')
    if not ready.get('ready') or not life.get('stopped') or life.get('id')!=ready.get('id') or life.get('birth')!=ready.get('birth') or not life.get('birth'):raise ValueError('host owned service lifecycle missing')
    if (life['bind_ipv4'],life['port'],life['allowed_peer_ipv4'])!=(inputs['target_ip'],inputs['port'],inputs['source_ip']):raise ValueError('host endpoint binding differs')
    events=[json.loads(line) for line in _read(directory/'events.jsonl').splitlines() if line]
    wanted=[];forbidden=[]
    if value['mode']=='payload':
        wanted=[(p['nonce'],p['tuple'],bytes.fromhex(p['request_hex']),bytes.fromhex(p['response_hex'])) for p in value['probes']]
    else:
        for name,record in value['clients'].items():
            rows=[json.loads(line) for line in _read(_safe(original,record['path'],'client')).splitlines()]
            for c in rows[1:-1]:
                if record['role']=='non-target':forbidden.append(c['nonce']);continue
                if not c['success']:continue
                src,sport=c['local'].rsplit(':',1);flow={'proto':'TCP','src':src,'sport':int(sport),'dst':inputs['target_ip'],'port':inputs['port']}
                wanted.append((c['nonce'],flow,('FNPR/1|%s|target\n'%c['nonce']).encode(),('FNPR/1|%s|OK\n'%c['nonce']).encode()))
    if any(e.get('nonce') in forbidden for e in events):raise ValueError('non-target reached controlled sink')
    for nonce,flow,request,response in wanted:
        matches=[e for e in events if e.get('nonce')==nonce and e.get('owner')==life['id']]
        if len(matches)!=1:raise ValueError('missing/duplicate independent host nonce')
        e=matches[0]
        if (e.get('transport'),e.get('peer_ip'),e.get('peer_port'))!=(flow['proto'],flow['src'],flow['sport']) or e.get('request_hex')!=request.hex() or e.get('response_hex')!=response.hex() or not life['started_at']<=e['time']<=life['ended_at']:raise ValueError('independent host flow/bytes/lifetime differs')
    return True


def read_json(path):return json.loads(_read(path))
