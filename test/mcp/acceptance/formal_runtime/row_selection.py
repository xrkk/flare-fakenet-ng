"""Data-only lineage of one indexed, closed attempt while its batch is paused."""
from pathlib import Path

from .context import checked_record, read_json, load_context
from .runner import require, single_batch_request
from .source import SourceAuthority


def selected_prefix(context, request, sid):
    require(sid in request.scenario_ids, 'row outside original batch order')
    original = read_json(checked_record(dict(context.materials['credited_selection'])))
    prefix = request.scenario_ids[:request.scenario_ids.index(sid)+1]
    require(not set(original).intersection(prefix), 'row prefix overlaps original credits')
    return {**original, **{item:str(context.evidence_root) for item in prefix}}


def selection(context):
    context.revalidate()
    plan = read_json(checked_record(dict(context.materials['plan'])))
    row = plan.get('row_audit')
    require(isinstance(row, dict) and set(row) == {'main_materials','batch_id','scenario_id','source_index'},
            'row audit requires exact original parent/row/source pin')
    parent = load_context(checked_record(row['main_materials']), row['main_materials']['sha256'],
                         repository_root=context.repository_root, source_root=context.source_root)
    request = single_batch_request(parent, row['batch_id']); sid = row['scenario_id']
    require(sid in request.scenario_ids, 'row audit is outside the original selected batch')
    require(context.candidate_identity == parent.candidate_identity and context.tool_source == parent.tool_source
            and context.physical_namespace == parent.physical_namespace
            and context.materials['resource_plan'] == parent.materials['resource_plan'],
            'row audit original candidate/tool/namespace/resource differs')
    require(context.audit_root == parent.audit_root/'row-audits'/sid and not context.evidence_root.exists(),
            'row audit output lineage or unused business root differs')
    for kind in ('benign','fault'):
        original = read_json(checked_record(dict(parent.materials['suite_argv'][kind])))
        supplied = read_json(checked_record(dict(context.materials['suite_argv'][kind])))
        args = list(supplied['argv']); args[args.index('--suite-root')+1] = str(parent.evidence_root)
        require({**supplied,'argv':args} == original, 'row audit original argv differs')
    parent_plan = read_json(checked_record(dict(parent.materials['plan'])))
    require(all(plan.get(key) == parent_plan.get(key) for key in ('original_manifest','candidate_files')),
            'row audit original candidate/manifest differs')
    require([dict(r) for r in context.materials['source_indices']] ==
            [dict(r) for r in parent.materials['source_indices']]+[row['source_index']],
            'row audit source indices differ from independently frozen parent')
    require(set(parent.materials['protected_sources'])|{str(parent.evidence_root)} <=
            set(context.materials['protected_sources']), 'row audit omits protected originals')
    root = parent.evidence_root; index = read_json(checked_record(row['source_index']))
    require(Path(row['source_index']['path']) == root/('row-source-index-'+sid+'.json')
            and index.get('schema') == 'fakenetng.formal-runtime.row-source-index.v1'
            and index.get('root') == str(root) and index.get('materials_sha256') == parent.materials_sha256
            and index.get('batch_id') == request.batch_id and index.get('scenario_id') == sid,
            'row source pin identity differs')
    authority = SourceAuthority(context, root)
    binding = authority.read(root/'execution-binding.json')
    require(binding.get('materials') == row['main_materials']
            and binding.get('identity') == dict(parent.candidate_identity)
            and binding.get('plan') == dict(parent.materials['plan'])
            and binding.get('physical_namespace') == parent.physical_namespace
            and binding.get('tool_commit') == parent.tool_source['commit'], 'row original producer differs')
    start = authority.read(root/'formal-batches'/request.batch_id/'start.json')
    require(start.get('scenario_ids') == list(request.scenario_ids), 'row original batch start differs')
    closure = authority.read(root/'row-source-gates'/sid/'source-closure.json')
    raw = authority.read(root/'row-source-gates'/sid/'source-capture-gate-original.json')
    require(closure.get('materials_sha256') == parent.materials_sha256
            and closure.get('scenario_id') == sid and closure.get('capture_query_only') is True,
            'row actual writer/capture closure lineage differs')
    import json
    import scenario_suite as suite
    capture = json.loads(raw['output'])
    require(not capture.get('probe') and not capture.get('children') and suite.Suite._pktmon_stopped(capture['pktmon'])
            and capture.get('sessions') and sorted(s['name'] for s in capture['sessions']) == closure.get('capture_sessions')
            and all(s.get('exit') == -2144337918
                and 'Data Collector Set was not found.' in s.get('query','') for s in capture['sessions']),
            'row original capture query is active or unknown')
    require(isinstance(closure.get('actual_immutable_witnesses'),list) and closure['actual_immutable_witnesses'],
            'row actual immutable writer witnesses absent')
    for record in closure['actual_immutable_witnesses']:
        path = checked_record(record)
        require(path.is_relative_to(root), 'row witness outside exact current execution')
        relative = path.relative_to(root).as_posix(); frozen = authority.rows.get(relative)
        require(frozen is not None and frozen['size'] == record['size'] and frozen['sha256'] == record['sha256'],
                'row actual witness differs from independent index')
        if path.name=='completion.json':
            require(authority.read(path).get('local_writer_ended') is True, 'row actual bounded writer unresolved')
    expected = selected_prefix(parent, request, sid)
    require(read_json(checked_record(dict(context.materials['credited_selection']))) == expected,
            'row audit must select exactly original credits and closed batch prefix')
    return expected
