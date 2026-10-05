"""Current source exports through original inventory and real bounded transport."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_formal_runtime_context import materials
from test_formal_runtime_producer import current
from test_formal_runtime_clients import server
from test_formal_runtime_current_source import live
from test_formal_runtime_source_export import SourceClient, RID, exporting
from test_formal_runtime_source import historical
from formal_runtime import current_source, source
from bounded_mcp import TransportUnknown


def exporting_live(live,failure=None):
    context,r,vm,service,_,server=live
    class ProductEnvironment:
        controller_id=''
        def tool_outcome(self,name,args=None,timeout=120):
            assert name=='start'
            return {'ok':True,'error':None,'value':{'state':'healthy','run_id':RID}}
    server.store=ProductEnvironment()
    outcome=service.tool_outcome('start',{'command_id':'controlled-owned-run'},3)
    assert outcome['value']['run_id']==RID
    _,binding=current_source.resolve_current(context,r.vm,service)
    boundary=SourceClient(binding,failure)
    server.vm_boundary=boundary.powershell
    return context,r,vm,service,boundary


def test_current_actual_original_copy_native_UUID_and_closed_host_index_publication(live):
    context,r,vm,service,boundary=exporting_live(live)
    protected=r.vm;old_binding=r.physical_source_binding
    out=context.evidence_root/'current-export'
    result=source.export_current_source(r,context,service,out)
    assert result['passed'] and result['local_writers_ended']
    assert result['guest_writes']==result['deletions']==0
    assert result['full_SHA'] and result['before_after_size_double_SHA']
    assert r.vm is protected and r.physical_source_binding is old_binding
    exported=json.loads((out/'guest-original-index.json').read_bytes())
    assert {row['guest']['path'] for row in exported}==set(boundary.bytes)
    assert all(Path(row['host_path']).read_bytes()==boundary.bytes[row['guest']['path']] for row in exported)
    assert any(RID in row['guest']['path'] for row in exported)  # Actual service transport response UUID.
    closure=json.loads((out/'host-transport-closure.json').read_bytes())
    assert closure['host_writers_ended'] and closure['guest_business_writer_closure_not_granted']
    assert len(closure['actual_terminal_and_completion_witnesses'])>10
    assert vm.responsibility()['host_writers_ended']
    assert all(timeout<=30 and 'transport-stage' not in command for command,timeout in boundary.calls)
    assert not (context.evidence_root/'full-SHA-index.json').exists()
    count=len(boundary.calls)
    with pytest.raises(source.SourceError,match='never retry'):
        source.export_current_source(r,context,service,out)
    assert len(boundary.calls)==count


@pytest.mark.parametrize('failure,reason',[
    ('writer','active or UNKNOWN'),('missing','required originals missing'),
    ('after-change','changed during export'),('wrong-source','cross-source/unowned'),
    ('unknown','unknown')])
def test_current_failure_preserves_primary_and_partials_without_replay(live,failure,reason):
    context,r,vm,service,boundary=exporting_live(live,failure)
    protected=r.vm;out=context.evidence_root/('export-'+failure)
    expected=TransportUnknown if failure=='unknown' else source.SourceError
    with pytest.raises(expected):source.export_current_source(r,context,service,out)
    assert r.vm is protected and not (out/'guest-original-index.json').exists()
    terminal=json.loads((out/'source-export-terminal.json').read_bytes())
    assert not terminal['passed'] and terminal['export_withheld_or_incomplete']
    assert vm.responsibility()['host_writers_ended']
    if failure=='unknown':
        assert sum('OpenRead(' in c for c,_ in boundary.calls)==1
    if failure=='after-change':assert list((out/'guest-originals').rglob('*'))
    count=len(boundary.calls)
    with pytest.raises(source.SourceError,match='never retry'):
        source.export_current_source(r,context,service,out)
    assert len(boundary.calls)==count


def test_known_final_inventory_with_transport_audit_failure_cannot_publish_index(live,monkeypatch):
    context,r,vm,service,boundary=exporting_live(live)
    out=context.evidence_root/'export-final-audit-failure'
    original_open=Path.open
    def io_boundary(path,*args,**kwargs):
        mode=args[0] if args else kwargs.get('mode','r')
        if (path.name=='call-terminal.json' and mode=='x' and boundary.inventories>=2
                and "('recovery-audit-'+$id+'-*')" in boundary.calls[-1][0]):
            raise OSError('controlled final transport terminal storage failure')
        return original_open(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',io_boundary)
    with pytest.raises(source.SourceError,match='closure unresolved'):
        source.export_current_source(r,context,service,out)
    assert not (out/'guest-original-index.json').exists()
    assert list((out/'guest-originals').rglob('*'))
    terminal=json.loads((out/'source-export-terminal.json').read_bytes())
    assert not terminal['passed'] and terminal['local_writers_ended'] is False
    assert vm.audit_failures and not r.vm.state.safe
    assert not vm.responsibility()['audit_safe'] and vm.responsibility()['host_writers_ended']
    assert (out/'source-post-inventory-value.json').is_file()
    assert next(iter(vm.audit_failures.values()))['not_remote_response_unknown'] is True


def test_original_source_failure_not_masked_by_terminal_audit_IO(exporting,monkeypatch):
    context,root,binding,r=exporting
    boundary=SourceClient(binding,'writer');r.vm=boundary
    original_open=Path.open
    def io_boundary(path,*args,**kwargs):
        if path.name=='source-export-terminal.json':raise OSError('controlled terminal IO failure')
        return original_open(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',io_boundary)
    with pytest.raises(source.SourceError,match='active or UNKNOWN') as caught:
        source.export_source(r,context,root,context.evidence_root/'failed-terminal')
    assert 'independent source-export terminal audit' in caught.value.__notes__[0]
    assert r.vm is boundary and not any('OpenRead(' in command for command,_ in boundary.calls)
