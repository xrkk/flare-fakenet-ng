"""Data-only lineage check for a newly sealed batch in an independent audit."""
from pathlib import Path

from .context import checked_record, read_json, load_context
from .runner import require, single_batch_request
from .source import SourceAuthority
from .sealing import check_index


def selection(context):
    context.revalidate()
    plan = read_json(checked_record(dict(context.materials['plan'])))
    binding = plan.get('new_batch_audit')
    require(isinstance(binding, dict) and set(binding) == {'main_materials', 'batch_id', 'source_index'},
            'new batch audit requires explicit parent lineage and source pin')
    material = checked_record(binding['main_materials'])
    parent = load_context(material, binding['main_materials']['sha256'],
                          repository_root=context.repository_root, source_root=context.source_root)
    request = single_batch_request(parent, binding['batch_id'])
    require(context.candidate_identity == parent.candidate_identity
            and context.tool_source == parent.tool_source
            and context.physical_namespace == parent.physical_namespace
            and context.materials['resource_plan'] == parent.materials['resource_plan'],
            'new audit differs from original candidate/tool/namespace/resources')
    parent_plan = read_json(checked_record(dict(parent.materials['plan'])))
    require(all(plan.get(key) == parent_plan.get(key) for key in ('original_manifest', 'candidate_files')),
            'new audit original candidate/manifest inputs differ')
    require(context.audit_root == parent.audit_root/'new-batch-audit'
            and not context.evidence_root.exists(), 'new audit output lineage/unused business root differs')
    for kind in ('benign', 'fault'):
        original = read_json(checked_record(dict(parent.materials['suite_argv'][kind])))
        invocation = read_json(checked_record(dict(context.materials['suite_argv'][kind])))
        values = list(invocation['argv']); values[values.index('--suite-root')+1] = str(parent.evidence_root)
        require({**invocation, 'argv': values} == original, 'new audit original argv differs')
    original_indices = [dict(row) for row in parent.materials['source_indices']]
    require([dict(row) for row in context.materials['source_indices']] == original_indices+[binding['source_index']],
            'new audit source index lineage differs')
    require(set(parent.materials['protected_sources'])|{str(parent.evidence_root)} <=
            set(context.materials['protected_sources']), 'new audit omits protected originals')
    index = check_index(parent.evidence_root, binding['source_index'])
    require(index.get('materials_sha256') == parent.materials_sha256
            and index.get('batch_id') == request.batch_id, 'source seal parent/batch differs')
    authority = SourceAuthority(context, parent.evidence_root)
    header = authority.read(parent.evidence_root/'execution-binding.json')
    require(header.get('materials') == binding['main_materials']
            and header.get('plan') == dict(parent.materials['plan'])
            and header.get('identity') == dict(parent.candidate_identity)
            and header.get('tool_commit') == parent.tool_source['commit']
            and header.get('physical_namespace') == parent.physical_namespace,
            'sealed producer original materials/identity differ')
    root = parent.evidence_root
    terminal = authority.read(root/'formal-batches'/request.batch_id/'terminal.json')
    start = authority.read(root/'formal-batches'/request.batch_id/'start.json')
    handoff = authority.read(root/'batch-handoff.json')
    status = handoff.get('final_original_status') or {}
    require(start.get('scenario_ids') == list(request.scenario_ids)
            and terminal.get('schema') == 'fakenetng.final100.formal-batch.terminal.v1'
            and terminal.get('batch_id') == request.batch_id and terminal.get('status') == 'complete'
            and terminal.get('passed') is True and terminal.get('stop_reason') is None
            and terminal.get('not_executed') == []
            and handoff.get('original_batch_terminal') == terminal
            and handoff.get('original_primary_error') is None and handoff.get('secondary_errors') == []
            and handoff.get('scenario_ids') == list(request.scenario_ids)
            and status.get('state') == 'stopped' and not status.get('run_id') and not status.get('controller')
            and status.get('config_identity', {}).get('sha256') == parent.candidate_identity['default_sha256'],
            'original batch/closure failed or selected outcome differs')
    events = terminal.get('events')
    require(isinstance(events, list) and [event.get('scenario_id') for event in events] == list(request.scenario_ids)
            and all(event.get('event') == 'executed' and event.get('classification') == 'pass'
                    and event.get('state') == 'pass' and not event.get('traffic_recheck_issues')
                    and not event.get('post_gate_error') for event in events),
            'original batch contains a nonpass or unexecuted row')
    expected = {sid: str(root) for sid in request.scenario_ids}
    pinned = read_json(checked_record(dict(context.materials['credited_selection'])))
    require(pinned == expected, 'new batch audit must select exactly its original planned rows')
    return expected
