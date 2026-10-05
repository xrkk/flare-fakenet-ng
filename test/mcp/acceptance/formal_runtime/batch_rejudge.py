"""Freeze a sealed new-batch audit and invoke only the independent original CLI."""
import copy
import subprocess
import sys

from .context import checked_record, read_json, load_context
from .producer import file_record
from .command_transport import write_new_json
from .runner import require, single_batch_request
from .runtime_sources import qualify, loaded_sources
from .sealing import check_index
from .preparation import output_inventory, check_audit_copies


def freeze(context, batch_id, index_record):
    context.revalidate()
    request = single_batch_request(context, batch_id)
    index = check_index(context.evidence_root, index_record)
    require(index['materials_sha256'] == context.materials_sha256 and index['batch_id'] == batch_id,
            'new source seal belongs to another execution')
    root = context.audit_root/'new-batch-inputs'
    require(not root.exists() and not (context.audit_root/'new-batch-audit').exists(),
            'new batch audit already exists; no implicit retry')
    root.mkdir()
    data = copy.deepcopy(read_json(context.materials_path))
    child_root = context.audit_root.parent/(context.audit_root.name+'-new-audit-unused-business')
    data.update(evidence_root=str(child_root), audit_root=str(context.audit_root/'new-batch-audit'))
    data['protected_sources'].append(str(context.evidence_root))
    data['source_indices'].append(index_record)
    selected = root/'selection.json'
    write_new_json(selected, {sid: str(context.evidence_root) for sid in request.scenario_ids})
    data['credited_selection'] = file_record(selected)
    plan = read_json(checked_record(data['plan']))
    plan.update(root=str(child_root), new_batch_audit={
        'main_materials': file_record(context.materials_path), 'batch_id': batch_id, 'source_index': index_record})
    for kind in ('benign', 'fault'):
        argv = read_json(checked_record(data['suite_argv'][kind]))
        argv['argv'][argv['argv'].index('--suite-root')+1] = str(child_root)
        target = root/(kind+'-argv.json'); write_new_json(target, argv)
        data['suite_argv'][kind] = file_record(target)
    target = root/'plan.json'; write_new_json(target, plan); data['plan'] = file_record(target)
    material = root/'materials.json'; write_new_json(material, data)
    record = file_record(material)
    child = load_context(material, record['sha256'], repository_root=context.repository_root,
                         source_root=context.source_root)
    from .batch_selection import selection
    selection(child)
    return child


def run(context, batch_id, index_record, entry):
    qualified = qualify(context, entry); loaded_sources(context, qualified)
    child = freeze(context, batch_id, index_record)
    root = context.audit_root
    command = [sys.executable, '-B', str(context.source_root/'test/mcp/acceptance/run_formal_source_audit.py'),
               '--materials-json', str(child.materials_path), '--materials-sha256', child.materials_sha256,
               '--selection-json', child.materials['credited_selection']['path'], '--scope', 'batch-selection',
               '--repository-root', str(context.repository_root)]
    write_new_json(root/'new-batch-audit-intent.json', {'argv': command,
        'main_materials_sha256': context.materials_sha256, 'source_index': index_record})
    failure, result, waited = None, None, False
    try:
        with (root/'new-batch-audit.stdout').open('xb') as stdout, (root/'new-batch-audit.stderr').open('xb') as stderr:
            completed = subprocess.run(command, cwd=context.source_root, stdout=stdout, stderr=stderr)
        waited = True
        write_new_json(root/'new-batch-audit-completion.json', {
            'exit_code': completed.returncode, 'audit_process_waited': True,
            'stdout': file_record(root/'new-batch-audit.stdout'),
            'stderr': file_record(root/'new-batch-audit.stderr')})
        require(completed.returncode == 0, 'independent original new-batch audit failed')
        verdict = read_json(child.audit_root/'audit-result.json')
        terminal = read_json(child.audit_root/'audit-terminal.json')
        require(verdict.get('schema') == 'fakenetng.formal-runtime.original-source-audit.v1'
                and verdict.get('scope') == 'batch-selection' and verdict.get('passed') is True
                and verdict.get('selected') == read_json(checked_record(dict(child.materials['credited_selection'])))
                and verdict.get('adapter_restored') is True and verdict.get('VM_calls') == 0
                and terminal.get('passed') is True and terminal.get('error') is None
                and terminal.get('adapter_restored') is True and terminal.get('host_audit_writers_ended') is True,
                'independent new-batch original audit terminal incomplete')
        check_audit_copies(child, verdict)
        check_index(context.evidence_root, index_record)
        outputs = output_inventory(child.audit_root)
        qualify(context, entry); loaded_sources(context, qualified)
        require(output_inventory(child.audit_root) == outputs, 'new-batch audit outputs changed')
        result = {'schema': 'fakenetng.formal-runtime.new-batch-rejudge.v1',
            'passed': True, 'batch_id': batch_id, 'main_materials_sha256': context.materials_sha256,
            'source_index': index_record, 'audit_materials': file_record(child.materials_path),
            'audit_outputs': outputs, 'independently_rejudged_scenarios': list(verdict['selected']),
            'new_formal_credit': 0, 'originals_retained': True}
        write_new_json(root/'new-batch-rejudge-result.json', result)
        return result
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            write_new_json(root/'new-batch-rejudge-terminal.json', {'passed': result is not None and failure is None,
                'error': repr(failure) if failure else None, 'audit_process_waited': waited,
                'batch_id': batch_id, 'source_index': index_record, 'new_formal_credit': 0})
        except BaseException as secondary:
            if failure is not None: failure.add_note('new-batch rejudge terminal failed: '+repr(secondary))
            else: raise
