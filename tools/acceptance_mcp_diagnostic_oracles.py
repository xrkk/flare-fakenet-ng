"""Closed-byte diagnostic judgments; native execution is never inferred from labels."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path, PureWindowsPath
import tempfile
import zipfile

MAX_ARCHIVE_BYTES=512*1024*1024
MAX_MEMBERS=4096


def _digest(raw):return hashlib.sha256(raw).hexdigest()


def _raw_response(response):
    if (not isinstance(response,dict) or response.get('exit_code')!=0
            or response.get('is_error') is not False):
        raise ValueError('diagnostic raw transport is unconfirmed')
    value=json.loads(response['output'])
    if not isinstance(value,dict) or set(value)!={'base64','sha256'}:
        raise ValueError('diagnostic raw byte receipt differs')
    if not isinstance(value['base64'],str) or len(value['base64'])>12000:
        raise ValueError('diagnostic raw receipt exceeds bound')
    raw=base64.b64decode(value['base64'],validate=True)
    if len(raw)>8192 or _digest(raw)!=value['sha256']:
        raise ValueError('diagnostic raw byte identity differs')
    return json.loads(raw)


def _archive(exported,run_id,*,remaining=None):
    remaining=MAX_ARCHIVE_BYTES if remaining is None else remaining
    path=Path(exported.get('path',''))
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError('original diagnostic archive identity refused')
    size=path.stat().st_size
    if not 0<size<=MAX_ARCHIVE_BYTES:raise ValueError('original archive exceeds bound')
    raw=path.read_bytes()
    if size!=exported.get('size') or _digest(raw)!=exported.get('sha256'):
        raise ValueError('original diagnostic archive bytes differ')
    with zipfile.ZipFile(path) as bundle:
        infos=bundle.infolist();names=[i.filename for i in infos]
        if (not 1<=len(infos)<=MAX_MEMBERS or len(set(names))!=len(names)
                or sum(i.file_size for i in infos)>remaining
                or any(i.flag_bits&1 or i.file_size<0 or i.compress_size<0
                       or (i.external_attr>>16)&0o170000==0o120000 for i in infos)):
            raise ValueError('diagnostic archive expansion or member identity refused')
        if any('/' in n or '\\' in n or n in ('','.','..') for n in names):
            raise ValueError('diagnostic archive path refused')
        manifest=json.loads(bundle.read('manifest.json'))
        if manifest.get('run_id')!=run_id:raise ValueError('diagnostic archive run differs')
        return path,{n:bundle.read(n) for n in names},sum(i.file_size for i in infos)


def _transport_rows(records):
    if not isinstance(records,list) or not records:
        raise ValueError('original diagnostic transport missing')
    values=[]
    for row in records:
        if row.get('kind')!='powershell' or row.get('error'):
            continue
        response=row.get('output') or {}
        if response.get('exit_code')!=0 or response.get('is_error') is not False:
            continue
        try:
            parsed=json.loads(response['output'])
        except (KeyError,TypeError,ValueError):
            continue
        values.append((row.get('input',{}).get('command',''),response,parsed))
    return values


def _require_original_response(rows,path,response):
    literal=str(path).replace("'","''")
    if not any(literal in command and original==response for command,original,parsed in rows):
        raise ValueError('diagnostic raw response absent from original transport')


def validate_original_record(record,fault_evidence,exports,*,expected=None,root=None,transport=None):
    if expected is None or root is None:raise ValueError('frozen original inputs required')
    if not isinstance(record,dict) or record.get('class') not in ('native_crash','stacks_unavailable'):
        raise ValueError('no verified producer for this diagnostic class')
    import acceptance_mcp as m
    mods=m.modules(root)
    if record.get('diagnostic_source_pins')!=m.source_pins(root):
        raise ValueError('diagnostic source closure changed')
    exports=record.get('incident_exports') if exports is None else exports
    if not isinstance(exports,list) or not 1<=len(exports)<=128:
        raise ValueError('diagnostic export set is unbounded or missing')
    archives=[];total=0
    for exported in exports:
        archive=_archive(exported,record.get('run_id'),remaining=MAX_ARCHIVE_BYTES-total);total+=archive[2]
        if total>MAX_ARCHIVE_BYTES:raise ValueError('diagnostic total expansion exceeds bound')
        archives.append(archive)
    fault=record['class']
    context=record.get('expected_diagnostic') if fault=='stacks_unavailable' else None
    if fault_evidence!=record.get('fault_evidence') or exports!=record.get('incident_exports'):
        raise ValueError('detached diagnostic source objects')
    from fakenet.mcp import diagnostic_faults as d
    rows=_transport_rows(transport)
    raw=record.get('diagnostic_raw') or {}
    for name in ('diagnostic-window.json','diagnostic-triggered.json'):
        _require_original_response(rows,PureWindowsPath(expected['programdata_root'])/
            'artifacts'/'runs'/record['run_id']/name,raw.get(name))
    window=_raw_response(raw.get('diagnostic-window.json'))
    trigger=_raw_response(raw.get('diagnostic-triggered.json'))
    if set(window)!={'schema','plan','ready'} or window['schema']!='fakenet.diagnostic-window.v1':
        raise ValueError('diagnostic window raw schema differs')
    plan=window['plan'];ready=window['ready'];arm=record.get('diagnostic_arm')
    if plan!=record.get('diagnostic_plan') or ready!=record.get('diagnostic_ready'):
        raise ValueError('diagnostic window differs from original bytes')
    if not isinstance(arm,dict) or not d.arm_shape(arm):
        raise ValueError('diagnostic original arm missing')
    if (set(plan)!=d.PLAN_KEYS or set(ready)!=d.READY_KEYS
            or plan['schema']!=d.PLAN_SCHEMA or ready['schema']!=d.READY_SCHEMA):
        raise ValueError('diagnostic plan/ready schema differs')
    for key in ('fault','nonce','expires_ns','config_sha256','service_identity'):
        if plan[key]!=ready[key]:raise ValueError('diagnostic ready plan binding differs')
    if {key:ready[key] for key in d.ARM_KEYS}!=arm:
        raise ValueError('diagnostic arm differs from actual child observation')
    if {key:trigger.get(key) for key in d.ARM_KEYS}!=arm:
        raise ValueError('diagnostic trigger target differs')
    if (plan['fault']!=fault or plan['config_sha256']!=expected['config_identity']['sha256']
            or record.get('nonce')!=plan['nonce'] or record.get('run_id')!=ready['run_id']):
        raise ValueError('diagnostic frozen configuration/run/nonce differs')
    for key,expected_value in (('plan',plan),('ready',ready),('arm',arm)):
        name={'plan':'diagnostic-plan.json','ready':'diagnostic-ready.json','arm':'fault-injection.json'}[key]
        literal=str(PureWindowsPath(expected['programdata_root'])/'logs'/name).replace("'","''")
        if not any(literal in cmd and parsed==expected_value for cmd,response,parsed in rows):
            raise ValueError('diagnostic '+key+' not observed in original transport')
    event=trigger.get('observed_time_ns')
    if type(event) is not int or not plan['expires_ns']-d.ARM_WINDOW_NS<=event<plan['expires_ns']:
        raise ValueError('diagnostic trigger outside original bounded window')
    if not record['probe_window_start']<=event/1e9<=record['probe_window_end']:
        raise ValueError('diagnostic trigger outside original observation window')
    if fault=='stacks_unavailable':
        if not isinstance(context,dict):raise ValueError('original no-stack context missing')
        mods['evidence_integrity'].validate_stack_context(context,record['run_id'])
        if any(context.get(k)!=v for k,v in [('plan',plan),('ready',ready),('arm',arm),('trigger',trigger)]):
            raise ValueError('no-stack context detached from original window')
        for key,name in [('window','diagnostic-window.json'),('trigger','diagnostic-triggered.json')]:
            if context['originals'][key]!=raw[name]:raise ValueError('no-stack raw observations detached')
        for name in context['fallback_files']:
            _require_original_response(rows,PureWindowsPath(expected['programdata_root'])/
                'artifacts'/'runs'/record['run_id']/name,context['originals']['fallbacks'])
    issues=mods['evidence_integrity'].validate_round(record,expected['identity'],expected_diagnostic=context)
    if issues:raise ValueError('original round rejected: '+str(issues))
    original_receipt=(fault_evidence.get('receipt') or {})
    if (original_receipt.get('run_id')!=ready['run_id']
            or original_receipt.get('receipt')!={'fault':fault,'nonce':plan['nonce']}):
        raise ValueError('original fault receipt differs from native trigger')
    cleanup=record.get('diagnostic_cleanup')
    if (not isinstance(cleanup,dict) or set(cleanup)!={'plan','ready','arm'}
            or any(v not in ('absent','owned_removed') for v in cleanup.values())):
        raise ValueError('diagnostic owned cleanup incomplete')
    for key,outcome in cleanup.items():
        name={'plan':'diagnostic-plan.json','ready':'diagnostic-ready.json','arm':'fault-injection.json'}[key]
        literal=str(PureWindowsPath(expected['programdata_root'])/'logs'/name).replace("'","''")
        observed=any(literal in cmd and
            ((outcome=='absent' and parsed is None) or
             (outcome=='owned_removed' and parsed=={'removed':True,'absent':True}))
            for cmd,response,parsed in rows)
        if not observed:raise ValueError('diagnostic cleanup transport missing: '+key)
    restore=record.get('diagnostic_service_restoration') or {}
    before=restore.get('before') or {};after=restore.get('after') or {}
    keys=('image','sha256','enabled','grace','fault_exists','service_config')
    if (not all(k in before and k in after and before[k]==after[k] for k in keys)
            or record.get('diagnostic_restore_error')):
        raise ValueError('diagnostic service restoration unconfirmed')
    service=record.get('diagnostic_service_observation') or {}
    if (service.get('enabled') is not True or service.get('fault_exists') is not False
            or service.get('grace')!=5
            or any(service.get(k)!=before.get(k) for k in ('image','sha256'))
            or service.get('pid')!=plan['service_identity']['pid']
            or service.get('birth')!=plan['service_identity']['creation_time']):
        raise ValueError('diagnostic post-enable service identity differs')
    for observation in (before,service,after):
        if not any('Get-CimInstance Win32_Service' in cmd and parsed==observation
                   for cmd,response,parsed in rows):
            raise ValueError('diagnostic service observation absent from transport')
    facts=[]
    for exported,(path,members,expanded) in zip(exports,archives):
        issues=mods['evidence_integrity'].validate_incident_export(exported,ready['run_id'],fault_round=True,expected_diagnostic=context)
        if issues:raise ValueError('original diagnostic export refused: '+str(issues))
        versions=json.loads(members['versions.json'])
        observed=versions.get('managed_process') or {};identity=observed.get('identity') or {}
        if any(identity.get(k)!=arm[k] for k in ('pid','creation_time')):
            raise ValueError('original incident target birth differs')
        if versions.get('config_sha256')!=arm['config_sha256']:
            raise ValueError('original incident configuration differs')
        code=observed.get('exit_code')
        if type(code) is not int or code&0xffffffff not in (0xc0000602,0xc0000409):
            raise ValueError('original incident has no fail-fast native exit observation')
        exit_record=json.loads(members['managed-exit.json'])
        target=exit_record.get('target') or {}
        if (exit_record.get('schema')!='fakenet.exit-result.v1'
                or target.get('run_id')!=ready['run_id']
                or any(target.get(k)!=arm[k] for k in ('pid','creation_time'))):
            raise ValueError('original exit monitor target evidence differs')
        dump=members['userdump.dmp']
        with tempfile.TemporaryDirectory(prefix='diagnostic-native-',dir=path.parent) as directory:
            dump_path=Path(directory)/'userdump.dmp'
            dump_path.write_bytes(dump)
            from fakenet.mcp.exit_native import verify_dump
            if verify_dump(dump_path,arm['pid'])!=len(dump):
                raise ValueError('original native dump size differs')
        facts.append({'path':str(path),'dump_sha256':_digest(dump),'exit_code':code,'exit_monitor_complete':exit_record.get('complete')})
    return {'run_id':ready['run_id'],'class':fault,'nonce':plan['nonce'],
            'original_packages':facts,'full_acc014_credit':False}


def validate_unknown_original(record,exports,known_cause=None,**kwargs):
    # No caller boolean can establish an independent unknown-cause judgment.
    raise ValueError('unknown-cause producer and independent original observation unavailable')
