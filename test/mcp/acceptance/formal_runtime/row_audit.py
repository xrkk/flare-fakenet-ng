"""Independent original per-row audit inside the original traffic recheck seam."""
from contextlib import contextmanager
import copy
from pathlib import Path
import subprocess
import sys

from .context import checked_record, read_json, load_context, exact_path
from .producer import file_record
from .command_transport import write_new_json
from .runner import require, _capacity
from .current_source import resolve_current_capture, CurrentAuthority, _transport_closed
from .source import ReadOnlySourceVm, source_capture_gate
from .preparation import check_audit_copies, output_inventory


def _records(execution, result, sid):
    context = execution.context.revalidate(); root = context.evidence_root
    require(sid in execution.request.scenario_ids, 'row audit outside original selected batch')
    require(execution.state.safe and execution.state.admission_ready
            and not execution.captures.owned and not execution.coordinator.fault_restore_pending,
            'row audit requires actual native/writer/restoration closure')
    stored = root/'results'/('scenario-'+sid+'.json')
    require(read_json(stored) == result and result.get('state') == 'pass'
            and result.get('scenario_id') == sid and type(result.get('attempt')) is int
            and result['attempt'] > 0, 'row original immutable result differs')
    _capacity(context, 1)
    _, binding = resolve_current_capture(context, execution.runner.vm, execution.service)
    gate = root/'row-source-gates'/sid; require(not gate.exists(), 'row closure already exists; no retry')
    gate.mkdir(parents=True)
    original = execution.runner.vm
    try:
        execution.runner.vm = ReadOnlySourceVm(original, context, binding, gate)
        source_capture_gate(execution.runner, binding, gate)
    finally:
        execution.runner.vm = original
    authority = CurrentAuthority(context, original, execution.service)
    witnesses = [record for record in authority.witnesses if Path(record['path']).is_relative_to(root)]
    # The source subset is immutable selected-attempt data, not a claim that
    # the still-paused batch root has no future files. Mapper uses original
    # source paths, so its two-key projection still compares the real proof.
    prefix = execution.request.scenario_ids[:execution.request.scenario_ids.index(sid)+1]
    paths = [root/'scenario-manifest.json',root/'execution-binding.json',
             root/'formal-batches'/execution.request.batch_id/'start.json',
             gate/'source-capture-gate-original.json', *[Path(r['path']) for r in witnesses]]
    for item in prefix:
        saved = root/'results'/('scenario-'+item+'.json')
        if item != sid:
            audited = execution.row_audits.records.get(item)
            require(audited is not None, 'earlier original row audit absent')
            require(checked_record(audited['original_result']) == saved, 'earlier audited result differs')
        value = read_json(saved)
        require(value.get('state') == 'pass' and type(value.get('attempt')) is int
                and value['attempt'] > 0, 'row prefix original result is not a pass')
        case = root/'evidence'/item/('attempt-%02d'%value['attempt'])
        require(case.is_dir(), 'row original attempt dependencies absent')
        paths += [saved, *[p for p in case.rglob('*') if p.is_file()]]
    records = []
    for path in sorted(set(paths)):
        path = exact_path(str(path)); require(path.is_relative_to(root), 'row source dependency escape')
        records.append(file_record(path))
    write_new_json(gate/'source-closure.json', {'materials_sha256':context.materials_sha256,
        'scenario_id':sid,'capture_query_only':True,'actual_immutable_witnesses':witnesses,
        'capture_sessions':sorted(k['name'] for k in binding.values['kernels']),
        'new_formal_credit':0})
    records.append(file_record(gate/'source-closure.json'))
    for record in records: checked_record(record)
    index = root/('row-source-index-'+sid+'.json')
    write_new_json(index, {'schema':'fakenetng.formal-runtime.row-source-index.v1','root':str(root),
        'materials_sha256':context.materials_sha256,'batch_id':execution.request.batch_id,'scenario_id':sid,
        'rows':[dict(r,path=Path(r['path']).relative_to(root).as_posix()) for r in records],
        'entire_batch_root_immutable':False,'selected_attempt_writers_closed':True,'new_formal_credit':0})
    _transport_closed(execution.vm,context,'vm'); _transport_closed(execution.service,context,'service')
    return file_record(index)


def freeze(context, request, sid, index):
    root=context.audit_root/'row-audit-inputs'/sid; require(not root.exists(),'row audit inputs exist; no retry')
    root.mkdir(parents=True)
    # Establish the shared parent before the child installs its write guard;
    # that child may create only its own scenario output directory.
    (context.audit_root/'row-audits').mkdir(exist_ok=True)
    data=copy.deepcopy(read_json(context.materials_path))
    unused=context.audit_root.parent/(context.audit_root.name+'-row-unused-'+sid)
    data.update(evidence_root=str(unused),audit_root=str(context.audit_root/'row-audits'/sid))
    data['protected_sources'].append(str(context.evidence_root));data['source_indices'].append(index)
    from .row_selection import selected_prefix
    selected=root/'selection.json';write_new_json(selected,selected_prefix(context,request,sid))
    data['credited_selection']=file_record(selected)
    plan=read_json(checked_record(data['plan']));plan.update(root=str(unused),row_audit={
        'main_materials':file_record(context.materials_path),'batch_id':request.batch_id,
        'scenario_id':sid,'source_index':index})
    for kind in ('benign','fault'):
        value=read_json(checked_record(data['suite_argv'][kind]));value['argv'][value['argv'].index('--suite-root')+1]=str(unused)
        target=root/(kind+'-argv.json');write_new_json(target,value);data['suite_argv'][kind]=file_record(target)
    target=root/'plan.json';write_new_json(target,plan);data['plan']=file_record(target)
    target=root/'materials.json';write_new_json(target,data);record=file_record(target)
    child=load_context(target,record['sha256'],repository_root=context.repository_root,source_root=context.source_root)
    from .row_selection import selection
    selection(child)
    return child


class RowAudits:
    def __init__(self, execution):
        from .execution import Execution
        require(isinstance(execution,Execution),'row audit requires actual execution')
        self.execution=execution;self.processes=[];self.records={};self.errors={}

    @property
    def writers_ended(self):
        return all(process.poll() is not None for process in self.processes)

    def run(self, result, sid):
        execution=self.execution;context=execution.context
        index=_records(execution,result,sid);child=freeze(context,execution.request,sid,index)
        root=context.audit_root/'row-audit-processes'/sid;root.mkdir(parents=True,exist_ok=False)
        command=[sys.executable,'-B',str(context.source_root/'test/mcp/acceptance/run_formal_source_audit.py'),
            '--materials-json',str(child.materials_path),'--materials-sha256',child.materials_sha256,
            '--selection-json',child.materials['credited_selection']['path'],'--scope','row-selection',
            '--repository-root',str(context.repository_root)]
        write_new_json(root/'intent.json',{'argv':command,'source_index':index,'main_materials_sha256':context.materials_sha256})
        process=None;failure=None;verdict=None
        try:
            with (root/'stdout').open('xb') as stdout,(root/'stderr').open('xb') as stderr:
                process=subprocess.Popen(command,cwd=context.source_root,stdout=stdout,stderr=stderr)
                self.processes.append(process)
                code=process.wait(timeout=7200)
            write_new_json(root/'completion.json',{'pid':process.pid,'returncode':code,'audit_process_waited':True,
                'stdout':file_record(root/'stdout'),'stderr':file_record(root/'stderr')})
            require(code==0,'independent original row audit failed: '+sid)
            verdict=read_json(child.audit_root/'audit-result.json');terminal=read_json(child.audit_root/'audit-terminal.json')
            require(verdict.get('schema')=='fakenetng.formal-runtime.original-source-audit.v1'
                and verdict.get('passed') is True and verdict.get('scope')=='row-selection'
                and verdict.get('selected')==read_json(checked_record(dict(child.materials['credited_selection'])))
                and verdict.get('VM_calls')==0
                and verdict.get('adapter_restored') is True and terminal.get('passed') is True
                and terminal.get('error') is None and terminal.get('adapter_restored') is True
                and terminal.get('host_audit_writers_ended') is True,'original row audit terminal incomplete')
            check_audit_copies(child,verdict)
            # Re-read only the immutable indexed subset, not later batch files.
            from .row_selection import selection
            selection(child)
            files=output_inventory(child.audit_root)
            write_new_json(root/'output-index.json',{'audit_materials_sha256':child.materials_sha256,'files':files})
            return {'source_index':index,'result':file_record(child.audit_root/'audit-result.json'),
                    'output_index':file_record(root/'output-index.json'),'new_formal_credit':0}
        except BaseException as error:
            failure=error
            raise
        finally:
            if process is not None and process.poll() is None:
                try:
                    process.terminate()
                    try:process.wait(10)
                    except subprocess.TimeoutExpired:process.kill();process.wait(5)
                except BaseException as error:
                    if failure is not None:failure.add_note('owned audit writer shutdown failed: '+repr(error))
                    else:raise
            try:
                write_new_json(root/'terminal.json',{'error':repr(failure) if failure else None,
                    'original_audit_passed':verdict is not None and failure is None,
                    'audit_writer_ended':process is None or process.poll() is not None,
                    'pid':process.pid if process else None,'new_formal_credit':0})
            except BaseException as error:
                if failure is not None:failure.add_note('row audit terminal storage failed: '+repr(error))
                else:raise

    @contextmanager
    def installed(self):
        runner=self.execution.runner;original=runner._traffic_recheck_issues
        def recheck(result,scenario):
            issues=original(result,scenario)
            sid=result.get('scenario_id')
            if issues or result.get('state')!='pass':return issues
            if sid in self.errors:return issues+[self.errors[sid]]
            if sid in self.records:
                checked_record(self.records[sid]['original_result'])
                return issues
            try:
                value=self.run(result,sid)
                value['original_result']=file_record(runner._result_path(sid));self.records[sid]=value
                return issues
            except BaseException as error:
                self.errors[sid]='independent original row audit failed: '+repr(error)
                return issues+[self.errors[sid]]
        runner._traffic_recheck_issues=recheck
        try:yield self
        finally:runner._traffic_recheck_issues=original
