"""Current source handoff rechecks real loopback transport and original capture."""
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials, write_json
from test_formal_runtime_producer import current
from test_formal_runtime_producer_source import pin_source, ExactCaptureClient
from test_formal_runtime_instance import subject, PROFILE
from test_formal_runtime_clients import server, client
from formal_runtime import current_source, instance, producer, source
from formal_runtime.context import MaterialError


@pytest.fixture
def live(current,server):
    context=pin_source(current)
    producer.register_execution(context)
    r=subject(context)
    state=instance.Responsibility()
    vm=client(server,context,vm=True,state=state)
    service=client(server,context,state=state)
    boundary=ExactCaptureClient(context,success=True)
    server.vm_boundary=boundary.powershell
    r.vm=instance.ProtectedVm(vm,context,state)
    instance.bind_namespace(r,context)
    guest=r._guest_scenario_root('sst-001',1)
    boundary.run=guest+r'\run-01'
    capture=r._start_capture_and_probe(guest,PROFILE,'bound-nonce','run-01')
    service.tool_outcome('get_status',{},3)
    write_json(context.evidence_root/'execution-context.json',{'backup_names':['owned-environment.xml']})
    return context,r,vm,service,capture,server


def test_actual_current_capture_and_ended_transport_do_not_self_grant_historical_credit(live):
    context,r,vm,service,capture,server=live
    authority,binding=current_source.resolve_current(context,r.vm,service)
    assert authority.index_record is None and binding.values['historical_source_authority'] is False
    assert binding.values['derived_from_current_original_execution'] is True
    assert binding.values['derived_from_actual_immutable_source'] is False
    assert binding.values['transport_host_writers_ended'] is True
    assert binding.values['guest_business_writer_closure_not_granted'] is True
    assert binding.values['captures'][0]['pid']==capture['pid']
    assert len(server.received)==7  # Two original fresh VM sessions plus actual service status.
    assert vm.responsibility()['host_writers_ended'] and service.responsibility()['host_writers_ended']
    assert not (context.evidence_root/'full-SHA-index.json').exists()
    assert any('completion.json'==Path(row['path']).name for row in binding.values['witnesses'])
    assert not r.vm.state.admission_ready


@pytest.mark.parametrize('change,reason',[
    ('intent','fingerprint mismatch'),('vm-terminal','dispatch terminal changed'),
    ('transport-terminal','transport terminal changed'),('completion','completion changed or unclosed'),
    ('orphan','journal/disk dispatch set differs'),('fake-client','actual same-context Fresh')])
def test_current_actual_evidence_changes_or_caller_stopped_flag_cannot_grant_source(live,change,reason):
    context,r,vm,service,_,_=live
    if change=='intent':next((context.evidence_root/'VM-final-intents').glob('*.json')).write_text('changed')
    elif change=='vm-terminal':
        path=next((context.evidence_root/'VM-final-terminals').glob('*.json'))
        value=json.loads(path.read_bytes());value['response_known']=False;write_json(path,value)
    elif change=='transport-terminal':
        path=next(vm.root.rglob('call-terminal.json'));value=json.loads(path.read_bytes())
        value['response_known']=False;write_json(path,value)
    elif change=='completion':
        path=next(vm.root.rglob('completion.json'));value=json.loads(path.read_bytes())
        value['local_writer_ended']=False;write_json(path,value)
    elif change=='orphan':write_json(context.evidence_root/'VM-final-intents'/('0'*32+'.json'),{'command':'fake'})
    else:service=SimpleNamespace(responsibility=lambda:{'host_writers_ended':True,'audit_safe':True})
    with pytest.raises((source.SourceError,MaterialError),match=reason):
        current_source.resolve_current(context,r.vm,service)


def test_current_snapshot_pins_bytes_and_never_extends_to_later_new_files(live):
    context,r,_,service,_,_=live
    authority,_=current_source.resolve_current(context,r.vm,service)
    path=context.evidence_root/'execution-context.json';path.write_text('later change')
    with pytest.raises(MaterialError,match='fingerprint mismatch'):authority.read(path)
    path=context.evidence_root/'later-file.json';write_json(path,{'new':True})
    with pytest.raises(source.SourceError,match='closed snapshot'):authority.read(path)
    with pytest.raises(source.SourceError,match='reference escape'):authority.read(context.materials_path)


def test_changed_current_independent_material_stops_before_source_read_or_new_RPC(live):
    context,r,_,service,_,server=live
    count=len(server.received)
    context.materials_path.write_text('changed independent original material')
    with pytest.raises(MaterialError,match='materials SHA256'):
        current_source.resolve_current(context,r.vm,service)
    assert len(server.received)==count


def test_actual_inflight_transport_blocks_handoff_until_own_host_writer_exits(live):
    context,r,_,service,_,server=live
    server.mode='unknown';errors=[]
    baseline=len(server.received)
    def call():
        try:service.tool_outcome('get_status',{},3)
        except BaseException as error:errors.append(error)
    thread=threading.Thread(target=call);thread.start()
    try:
        end=time.monotonic()+1
        while len(server.received)==baseline and time.monotonic()<end:time.sleep(.01)
        assert len(server.received)>baseline
        with pytest.raises(source.SourceError,match='closure unresolved'):
            current_source.resolve_current(context,r.vm,service)
    finally:
        server.stop_event.set();thread.join(4)
    assert not thread.is_alive() and not errors
    assert service.responsibility()['host_writers_ended']
    current_source.resolve_current(context,r.vm,service)
