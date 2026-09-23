#!/usr/bin/env python3
"""Read-only TDH metadata and raw property export for selected existing ETL events."""
import argparse
import base64
import ctypes as C
import datetime
import hashlib
import json
import os
from pathlib import Path
import struct
import traceback

import etl_raw_clock as e

ERROR_INSUFFICIENT_BUFFER=122
class PROPERTY_DATA_DESCRIPTOR(C.Structure):
    _fields_=[('PropertyName',C.c_uint64),('ArrayIndex',C.c_uint32),('Reserved',C.c_uint32)]

def utf16_at(blob, offset):
    if not offset:
        return None
    if offset < 0 or offset >= len(blob) or offset % 2:
        raise e.DiagnosticError('invalid TDH string offset '+str(offset))
    end=offset
    while end+1<len(blob) and blob[end:end+2]!=b'\0\0':
        end+=2
    if end+1>=len(blob):
        raise e.DiagnosticError('unterminated TDH string')
    return blob[offset:end].decode('utf-16-le')

def parse_tei(blob):
    if len(blob)<112:
        raise e.DiagnosticError('TRACE_EVENT_INFO too short')
    names=['provider','level','channel','keywords','task','opcode','event_message','provider_message','binary_xml','binary_xml_size','event_name','event_attributes']
    offsets=dict(zip(names,struct.unpack_from('<12I',blob,52)))
    count,top,flags=struct.unpack_from('<III',blob,100)
    if count>65535 or top>count or 112+count*24>len(blob):
        raise e.DiagnosticError('TRACE_EVENT_INFO property array outside buffer')
    out={'provider_guid':str(e.uuid.UUID(bytes_le=blob[:16])),'event_guid':str(e.uuid.UUID(bytes_le=blob[16:32])),'event_descriptor_bytes':blob[32:48].hex(),'decoding_source':struct.unpack_from('<I',blob,48)[0],'string_offsets':offsets,'strings':{k:utf16_at(blob,v) for k,v in offsets.items() if v and k not in ('binary_xml','binary_xml_size')},'property_count':count,'top_level_property_count':top,'flags':flags,'properties':[]}
    for i in range(count):
        off=112+i*24
        pflags,nameoff=struct.unpack_from('<II',blob,off)
        t0,t1,third=struct.unpack_from('<HHI',blob,off+8)
        pcount,plen,reserved=struct.unpack_from('<HHI',blob,off+16)
        out['properties'].append({'index':i,'metadata_record_offset':off,'flags':pflags,'name_offset':nameoff,'name':utf16_at(blob,nameoff),'in_type_or_struct_start':t0,'out_type_or_struct_members':t1,'map_or_schema_offset':third,'count_or_index':pcount,'length_or_index':plen,'reserved_or_tags':reserved,'is_top_level':i<top})
    return out

def raw_offsets(haystack, needle):
    if not needle:return []
    offsets=[];start=0
    while True:
        at=haystack.find(needle,start)
        if at<0:break
        offsets.append(at);start=at+1
    return offsets

def property_path(properties, index, top_count):
    item=properties[index]
    if index<top_count:
        return [item['name']]
    parents=[p for p in properties[:top_count] if p['flags'] & 1 and
             p['in_type_or_struct_start']<=index<p['in_type_or_struct_start']+p['out_type_or_struct_members']]
    if len(parents)!=1:
        raise e.DiagnosticError('nested property has no unique struct parent')
    return [parents[0]['name'],item['name']]

def configure_tdh():
    api=C.WinDLL('tdh',use_last_error=True)
    api.TdhGetEventInformation.argtypes=[C.POINTER(e.EVENT_RECORD),C.c_uint32,C.c_void_p,C.c_void_p,C.POINTER(C.c_uint32)]
    api.TdhGetEventInformation.restype=C.c_uint32
    api.TdhGetPropertySize.argtypes=[C.POINTER(e.EVENT_RECORD),C.c_uint32,C.c_void_p,C.c_uint32,C.POINTER(PROPERTY_DATA_DESCRIPTOR),C.POINTER(C.c_uint32)]
    api.TdhGetPropertySize.restype=C.c_uint32
    api.TdhGetProperty.argtypes=[C.POINTER(e.EVENT_RECORD),C.c_uint32,C.c_void_p,C.c_uint32,C.POINTER(PROPERTY_DATA_DESCRIPTOR),C.c_uint32,C.c_void_p]
    api.TdhGetProperty.restype=C.c_uint32
    # Some older TDH implementations do not expose the map API. Preserve
    # that fact in the diagnostic record; the auxiliary semantic gate rejects
    # a missing map, while existing TDH property export remains available.
    map_api=getattr(api,'TdhGetEventMapInformation',None)
    if map_api is not None:
        map_api.argtypes=[C.POINTER(e.EVENT_RECORD),C.c_wchar_p,C.c_void_p,C.POINTER(C.c_uint32)]
        map_api.restype=C.c_uint32
    return api


def capture_event_map(ptr, api, name):
    """Preserve TDH's opaque EVENT_MAP_INFO bytes without interpreting ABI layout."""
    result={'name':name,'api_available':False,'first_status':None,
            'required_size':None,'second_status':None,'buffer_sha256':None,
            'buffer_base64':None}
    fn=getattr(api,'TdhGetEventMapInformation',None)
    if fn is None:
        return result
    result['api_available']=True
    needed=C.c_uint32(0)
    code=fn(ptr,name,None,C.byref(needed))
    result['first_status']=int(code)
    result['required_size']=int(needed.value)
    if code!=ERROR_INSUFFICIENT_BUFFER or not 16<=needed.value<=16*1024*1024:
        return result
    capacity=needed.value
    buffer=C.create_string_buffer(capacity)
    code=fn(ptr,name,buffer,C.byref(needed))
    result['second_status']=int(code)
    if code or needed.value>capacity:
        return result
    blob=buffer.raw[:needed.value]
    result['buffer_sha256']=hashlib.sha256(blob).hexdigest()
    result['buffer_base64']=base64.b64encode(blob).decode('ascii')
    return result

def decode_target(ptr, selector, api):
    record=e.record_dict(ptr.contents)
    for key,want in [('timestamp',selector['raw_qpc']),('provider',selector['provider']),('id',selector['id']),('version',selector['version']),('opcode',selector['opcode']),('task',selector['task']),('userdata_sha256',selector['userdata_sha256'])]:
        if record[key]!=want:
            raise e.DiagnosticError('selected event changed at seq '+str(selector['seq'])+' field '+key)
    if e.identity_digest(record)!=selector['identity_sha256']:
        raise e.DiagnosticError('selected full non-time identity changed at seq '+str(selector['seq']))
    result={'selector':selector,'record':record,'tdh':{'first_status':None,'required_size':None,'second_status':None,'buffer_sha256':None,'buffer_base64':None,'parsed':None},'property_results':[]}
    needed=C.c_uint32(0)
    code=api.TdhGetEventInformation(ptr,0,None,None,C.byref(needed))
    result['tdh']['first_status']=code; result['tdh']['required_size']=needed.value
    if code!=ERROR_INSUFFICIENT_BUFFER or needed.value<112 or needed.value>16*1024*1024:
        return result
    buf=C.create_string_buffer(needed.value)
    code=api.TdhGetEventInformation(ptr,0,None,buf,C.byref(needed))
    result['tdh']['second_status']=code
    if code:return result
    blob=buf.raw[:needed.value]
    result['tdh']['buffer_sha256']=hashlib.sha256(blob).hexdigest()
    result['tdh']['buffer_base64']=base64.b64encode(blob).decode('ascii')
    parsed=parse_tei(blob)
    result['tdh']['parsed']=parsed
    user=base64.b64decode(record['userdata_base64'])
    for prop in parsed['properties']:
        name=prop['name']
        path=property_path(parsed['properties'],prop['index'],parsed['top_level_property_count'])
        entry={'index':prop['index'],'name':name,'path':path,'in_type_or_struct_start':prop['in_type_or_struct_start'],'out_type_or_struct_members':prop['out_type_or_struct_members'],'metadata_record_offset':prop['metadata_record_offset'],'name_offset':prop['name_offset'],'size_status':None,'size':None,'property_status':None,'raw_base64':None,'raw_sha256':None,'candidate_userdata_offsets':[],'payload_offset_authoritative':False}
        if not name:
            result['property_results'].append(entry);continue
        namebufs=[C.create_unicode_buffer(part) for part in path]
        desc=(PROPERTY_DATA_DESCRIPTOR*len(path))()
        for i,namebuf in enumerate(namebufs):
            desc[i]=PROPERTY_DATA_DESCRIPTOR(C.cast(namebuf,C.c_void_p).value,0 if i==0 and len(path)>1 else 0xffffffff,0)
        size=C.c_uint32(0)
        entry['size_status']=api.TdhGetPropertySize(ptr,0,None,len(path),desc,C.byref(size))
        entry['size']=size.value
        if entry['size_status']==0 and size.value<=16*1024*1024:
            value=C.create_string_buffer(max(1,size.value))
            entry['property_status']=api.TdhGetProperty(ptr,0,None,len(path),desc,size.value,value)
            if entry['property_status']==0:
                raw=value.raw[:size.value]
                entry['raw_base64']=base64.b64encode(raw).decode('ascii')
                entry['raw_sha256']=hashlib.sha256(raw).hexdigest()
                entry['candidate_userdata_offsets']=raw_offsets(user,raw)
        if name=='Reason' and record['id']==1479:
            offset=prop['map_or_schema_offset']
            entry['event_map']=(capture_event_map(ptr,api,utf16_at(blob,offset))
                                if offset else {'name':None,'api_available':False,
                                                'missing_map_name':True})
        result['property_results'].append(entry)
    return result

def run(etl, selector_path, output):
    if os.name!='nt':raise e.DiagnosticError('native Windows Python required')
    e.layout_check()
    if C.sizeof(PROPERTY_DATA_DESCRIPTOR)!=16:raise e.DiagnosticError('PROPERTY_DATA_DESCRIPTOR ABI mismatch')
    source=json.loads(selector_path.read_text(encoding='utf-8'))
    selectors={item['seq']:item for item in source['selectors']}
    if len(selectors)!=len(source['selectors']):raise e.DiagnosticError('duplicate selector seq')
    before={'etl':e.sha_file(etl),'selectors':e.sha_file(selector_path)}
    if before['etl']['sha256']!=source['source_etl_sha256']:
        raise e.DiagnosticError('selector ETL SHA does not match input')
    e.prepare_output(output)
    manifest={'schema':'fakenet.t007-r02-tdh-metadata.v1','status':'FAILED','started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'input_before':before,'input_after':None,'source_event_count':source['source_event_count'],'target_count':len(selectors),'observed_count':0,'target_records':0,'tdh_success_count':0,'property_failure_count':0,'api':{},'error':None}
    try:
        adv=C.WinDLL('advapi32',use_last_error=True);tdh=configure_tdh()
        adv.OpenTraceW.argtypes=[C.POINTER(e.EVENT_TRACE_LOGFILEW)];adv.OpenTraceW.restype=C.c_uint64
        adv.ProcessTrace.argtypes=[C.POINTER(C.c_uint64),C.c_uint32,C.c_void_p,C.c_void_p];adv.ProcessTrace.restype=C.c_uint32
        adv.CloseTrace.argtypes=[C.c_uint64];adv.CloseTrace.restype=C.c_uint32
        logfile=e.EVENT_TRACE_LOGFILEW();filename=C.create_unicode_buffer(str(etl));logfile.LogFileName=C.cast(filename,C.c_void_p).value;logfile.ProcessTraceMode=e.EVENT_RECORD_MODE|e.RAW
        callbacks=[];errors=[];seen=set();count=0
        with (output/'metadata.jsonl').open('x',encoding='utf-8') as stream:
            def emit(ptr):
                nonlocal count
                selector=selectors.get(count)
                if selector:
                    item=decode_target(ptr,selector,tdh)
                    stream.write(json.dumps(item,sort_keys=True)+'\n')
                    seen.add(count)
                    manifest['target_records']+=1
                    manifest['tdh_success_count']+=item['tdh']['second_status']==0
                    manifest['property_failure_count']+=sum(p['size_status']!=0 or p['property_status']!=0 for p in item['property_results'])
                count+=1
            callback=C.WINFUNCTYPE(None,C.POINTER(e.EVENT_RECORD))(e.callback_guard(emit,errors));callbacks.append(callback)
            logfile.EventRecordCallback=C.cast(callback,C.c_void_p).value
            C.set_last_error(0);handle=adv.OpenTraceW(C.byref(logfile))
            manifest['api']['open_trace_handle']=handle;manifest['api']['open_trace_last_error']=C.get_last_error()
            if handle==0xffffffffffffffff:raise e.DiagnosticError('OpenTraceW failed')
            try:
                manifest['api']['header']=e.header_dict(logfile.LogfileHeader)
                e.clock_check(manifest['api']['header'])
                handles=(C.c_uint64*1)(handle)
                C.set_last_error(0);manifest['api']['process_trace_return']=adv.ProcessTrace(handles,1,None,None);manifest['api']['process_trace_last_error']=C.get_last_error()
                manifest['observed_count']=count
                manifest['api']['buffers_read']=logfile.BuffersRead
                manifest['api']['events_lost_output']=logfile.EventsLost
                if errors:raise e.DiagnosticError('callback error: '+json.dumps(errors[0]))
                if manifest['api']['process_trace_return']!=0:raise e.DiagnosticError('ProcessTrace failed')
                if logfile.EventsLost:raise e.DiagnosticError('logfile output reports lost events')
            finally:
                C.set_last_error(0);manifest['api']['close_trace_return']=adv.CloseTrace(handle);manifest['api']['close_trace_last_error']=C.get_last_error()
        if manifest['api']['close_trace_return']!=0:raise e.DiagnosticError('CloseTrace failed')
        if count!=source['source_event_count'] or seen!=set(selectors):raise e.DiagnosticError('event count or target set changed')
        if manifest['tdh_success_count']!=len(selectors):raise e.DiagnosticError('TDH metadata missing for one or more targets')
        if manifest['property_failure_count']:raise e.DiagnosticError('TDH property extraction incomplete')
        manifest['status']='COMPLETE_DIAGNOSTIC_ONLY'
    except BaseException as exc:
        manifest['error']={'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()}
    finally:
        try:manifest['input_after']={'etl':e.sha_file(etl),'selectors':e.sha_file(selector_path)}
        except OSError as exc:manifest['input_after']={'error':str(exc)}
        if manifest['input_before']!=manifest['input_after']:
            manifest['status']='FAILED';manifest['error']={'type':'InputChanged','message':'input changed during metadata export'}
        (output/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    if manifest['status']!='COMPLETE_DIAGNOSTIC_ONLY':raise e.DiagnosticError(manifest['error']['message'])
    return manifest

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--etl',type=Path,required=True);p.add_argument('--targets',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    try:print(json.dumps({'status':run(args.etl.resolve(),args.targets.resolve(),args.output.resolve())['status']}))
    except (e.DiagnosticError,OSError,ValueError) as exc:
        p.exit(1,type(exc).__name__+': '+str(exc)+'\n')
if __name__=='__main__':main()
