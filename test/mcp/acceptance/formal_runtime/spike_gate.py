"""Full original Spike rejudging in a separate, owned audit interpreter."""
from contextlib import contextmanager
import copy
from pathlib import Path
import subprocess
import sys

from .context import checked_record, read_json, load_context
from .producer import file_record
from .command_transport import write_new_json
from .runner import require, _capacity
from .preparation import check_audit_copies, output_inventory


def original_selection(context):
    report = read_json(checked_record(dict(context.materials['spike_source'])))
    cases = report.get('cases')
    require(isinstance(cases, list) and len(cases) == 5
            and all(isinstance(row, dict) and isinstance(row.get('scenario_id'), str) for row in cases),
            'runtime Spike requires original five-case source')
    root = str(Path(context.materials['spike_source']['path']).parent)
    value = {row['scenario_id']:root for row in cases}
    require(len(value) == 5, 'runtime Spike source cases duplicated')
    return value


def selection(context):
    """Data-only lineage; actual full original Spike gate remains mandatory."""
    context.revalidate()
    plan = read_json(checked_record(dict(context.materials['plan'])))
    binding = plan.get('runtime_spike_audit')
    require(isinstance(binding, dict) and set(binding) == {'main_materials','ordinal'},
            'runtime Spike audit exact parent lineage absent')
    ordinal = binding['ordinal']
    require(type(ordinal) is int and ordinal > 0, 'runtime Spike ordinal invalid')
    parent = load_context(checked_record(binding['main_materials']), binding['main_materials']['sha256'],
                         repository_root=context.repository_root, source_root=context.source_root)
    require(context.audit_root == parent.audit_root/'runtime-spike-audits'/('%04d'%ordinal)
            and not context.evidence_root.exists(), 'runtime Spike output lineage differs')
    require(context.candidate_identity == parent.candidate_identity and context.tool_source == parent.tool_source
            and context.physical_namespace == parent.physical_namespace, 'runtime Spike producer identity differs')
    for key in ('source_indices','credited_selection','spike_source','resource_plan','protected_sources'):
        require(context.materials[key] == parent.materials[key], 'runtime Spike original binding differs: '+key)
    original_plan = read_json(checked_record(dict(parent.materials['plan'])))
    expected_plan = dict(original_plan, root=str(context.evidence_root), runtime_spike_audit=binding)
    require(plan == expected_plan, 'runtime Spike original plan changed beyond owned output/lineage')
    for kind in ('benign','fault'):
        original = read_json(checked_record(dict(parent.materials['suite_argv'][kind])))
        supplied = read_json(checked_record(dict(context.materials['suite_argv'][kind])))
        args = list(supplied['argv']);args[args.index('--suite-root')+1] = str(parent.evidence_root)
        require(dict(supplied,argv=args) == original, 'runtime Spike original argv differs')
    return original_selection(parent)


def freeze(context, ordinal):
    context.revalidate()
    root = context.audit_root/'runtime-spike-inputs'/('%04d'%ordinal)
    require(not root.exists(), 'runtime Spike audit inputs exist; no retry')
    root.mkdir(parents=True)
    (context.audit_root/'runtime-spike-audits').mkdir(exist_ok=True)
    data = copy.deepcopy(read_json(context.materials_path))
    unused = context.audit_root.parent/(context.audit_root.name+'-spike-unused-%04d'%ordinal)
    data.update(evidence_root=str(unused),audit_root=str(context.audit_root/'runtime-spike-audits'/('%04d'%ordinal)))
    for kind in ('benign','fault'):
        value = read_json(checked_record(data['suite_argv'][kind]))
        value['argv'][value['argv'].index('--suite-root')+1] = str(unused)
        path = root/(kind+'-argv.json');write_new_json(path,value);data['suite_argv'][kind] = file_record(path)
    plan = read_json(checked_record(data['plan']))
    plan.update(root=str(unused),runtime_spike_audit={'main_materials':file_record(context.materials_path),'ordinal':ordinal})
    path = root/'plan.json';write_new_json(path,plan);data['plan'] = file_record(path)
    path = root/'selection.json';write_new_json(path,original_selection(context));selected = file_record(path)
    path = root/'materials.json';write_new_json(path,data);pin = file_record(path)
    child = load_context(path,pin['sha256'],repository_root=context.repository_root,source_root=context.source_root)
    require(selection(child) == read_json(checked_record(selected)), 'runtime Spike frozen selection differs')
    return child, selected


class SpikeAudits:
    def __init__(self, context, runner):
        self.context = context.revalidate();self.runner = runner;self.processes = [];self.records = [];self.ordinal = 0
        require(runner.root == context.evidence_root, 'runtime Spike runner/context differs')

    @property
    def writers_ended(self):
        return all(process.poll() is not None for process in self.processes)

    def run(self):
        context = self.context.revalidate();_capacity(context,1)
        self.ordinal += 1
        child, selected = freeze(context,self.ordinal)
        root = context.audit_root/'runtime-spike-processes'/('%04d'%self.ordinal)
        root.mkdir(parents=True,exist_ok=False)
        command = [sys.executable,'-B',str(context.source_root/'test/mcp/acceptance/run_formal_source_audit.py'),
            '--materials-json',str(child.materials_path),'--materials-sha256',child.materials_sha256,
            '--selection-json',selected['path'],'--scope','spike-only','--repository-root',str(context.repository_root)]
        write_new_json(root/'intent.json',{'argv':command,'main_materials_sha256':context.materials_sha256,
            'audit_materials':file_record(child.materials_path),'selection':selected})
        process = None;failure = None;verdict = None
        try:
            with (root/'stdout').open('xb') as stdout,(root/'stderr').open('xb') as stderr:
                process = subprocess.Popen(command,cwd=context.source_root,stdout=stdout,stderr=stderr)
                self.processes.append(process);code = process.wait(timeout=7200)
            write_new_json(root/'completion.json',{'pid':process.pid,'returncode':code,'audit_process_waited':True,
                'stdout':file_record(root/'stdout'),'stderr':file_record(root/'stderr')})
            require(code == 0, 'independent original runtime Spike audit failed')
            verdict = read_json(child.audit_root/'audit-result.json')
            terminal = read_json(child.audit_root/'audit-terminal.json')
            require(verdict.get('schema') == 'fakenetng.formal-runtime.original-source-audit.v1'
                and verdict.get('passed') is True and verdict.get('scope') == 'spike-only'
                and verdict.get('selected') == selection(child) and verdict.get('VM_calls') == 0
                and verdict.get('new_formal_credit') == 0 and verdict.get('adapter_restored') is True
                and terminal.get('passed') is True and terminal.get('error') is None
                and terminal.get('adapter_restored') is True and terminal.get('host_audit_writers_ended') is True,
                'runtime Spike original audit terminal incomplete')
            check_audit_copies(child,verdict)
            files = output_inventory(child.audit_root)
            write_new_json(root/'output-index.json',{'audit_materials_sha256':child.materials_sha256,'files':files})
            context.revalidate();selection(child)
            require(output_inventory(child.audit_root) == files, 'runtime Spike audit outputs changed')
            self.records.append({'result':file_record(child.audit_root/'audit-result.json'),
                'output_index':file_record(root/'output-index.json'),'new_formal_credit':0})
        except BaseException as error:
            failure = error;raise
        finally:
            if process is not None and process.poll() is None:
                try:
                    process.terminate()
                    try:process.wait(10)
                    except subprocess.TimeoutExpired:process.kill();process.wait(5)
                except BaseException as error:
                    if failure is not None:failure.add_note('owned Spike audit writer shutdown failed: '+repr(error))
                    else:raise
            try:
                write_new_json(root/'terminal.json',{'passed':verdict is not None and failure is None,
                    'error':repr(failure) if failure else None,'audit_writer_ended':self.writers_ended,
                    'pid':process.pid if process else None,'VM_calls':0,'new_formal_credit':0})
            except BaseException as error:
                if failure is not None:failure.add_note('runtime Spike terminal storage failed: '+repr(error))
                else:raise

    @contextmanager
    def installed(self):
        original = self.runner._require_fault_spike
        self.runner._require_fault_spike = self.run
        try:yield self
        finally:self.runner._require_fault_spike = original
