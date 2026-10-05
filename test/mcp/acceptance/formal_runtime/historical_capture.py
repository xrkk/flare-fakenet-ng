"""Read indexed historical capture identities; never reuse a hard-coded name."""
import json
from pathlib import Path
import re

import scenario_suite as suite
from .context import checked_record, read_json
from .source import SourceAuthority, resolve_source
from .producer import file_record
from .runner import require, _capacity
from .command_transport import write_new_json
from .current_source import _transport_closed


def native_gate(execution, label, *, initial=None, expected_identity=None):
    from .execution import Execution
    from .coordinator import SCENE, validate_scene
    require(isinstance(execution,Execution), 'original scene gate requires actual execution')
    context = execution.context.revalidate();_capacity(context,len(execution.request.scenario_ids))
    require(re.fullmatch('[a-z-]+',label) is not None, 'scene gate label invalid')
    root = context.evidence_root/'original-scene-gates'/label
    require(not root.exists(), 'original scene gate exists; no retry')
    root.mkdir(parents=True)
    status = execution.runner._status(30)
    raw = execution.runner.vm.powershell(SCENE,30)
    write_new_json(root/'scene-original.json',raw);scene = json.loads(raw['output'])
    plan = read_json(checked_record(dict(context.materials['plan'])))
    manifest = read_json(checked_record(plan['candidate_files']['manifest']))
    identity = validate_scene(scene,status,context.candidate_identity,manifest,{'present':False,'values':[]})
    require(isinstance(scene.get('config_sha'),str) and re.fullmatch('[a-f0-9]{64}',scene['config_sha']),
            'original service configuration byte identity absent')
    if initial is not None:
        value = read_json(checked_record(initial))
        require(scene['config_sha'] == value['config_sha'], 'original service configuration bytes not restored')
    require(expected_identity is None or identity == expected_identity, 'original native instance changed after export')
    _transport_closed(execution.vm,context,'vm');_transport_closed(execution.service,context,'service')
    result = {'identity':identity,'config_sha':scene['config_sha'],'status':status,'guest_mutations':0,'new_formal_credit':0}
    write_new_json(root/'result.json',result)
    return file_record(root/'result.json')


def sessions(context):
    context.revalidate()
    selected = read_json(checked_record(dict(context.materials['credited_selection'])))
    roots = {Path(value) for value in selected.values()}
    roots.add(Path(context.materials['spike_source']['path']).parent)
    names = set();witnesses = []
    for root in sorted(roots):
        authority = SourceAuthority(context,root);binding = resolve_source(context,root)
        owned = {row['name'] for row in binding.values['kernels']}
        require(owned, 'historical original capture identities absent')
        names.update(owned)
        # Keep inherited names recorded by the old real read-only baselines,
        # including prior-owner sessions not started by this producer.
        baselines = [name for name in authority.rows if len(Path(name).parts)==1
                     and name.endswith('capture-baseline-original.json')]
        require('final-capture-baseline-original.json' in baselines,
                'historical final original capture baseline unindexed')
        for name in sorted(baselines):
            raw = authority.read(root/name);value = json.loads(raw['output'])
            rows = value.get('sessions')
            require(isinstance(rows,list) and rows and all(isinstance(row,dict)
                    and isinstance(row.get('name'),str) and re.fullmatch(r'SST-Kernel-[a-f0-9-]+',row['name'])
                    and isinstance(row.get('query'),str) and type(row.get('exit')) is int for row in rows),
                    'historical actual capture baseline identity invalid')
            names.update(row['name'] for row in rows)
        witnesses += list(authority.witnesses) + list(binding.values.get('witnesses',()))
        witnesses.append(dict(authority.index_record))
    return sorted(names), [dict(record) for record in witnesses]


def gate(execution, label, *, unused_namespace=False):
    from .execution import Execution
    require(isinstance(execution,Execution), 'historical capture gate requires actual execution')
    context = execution.context.revalidate();_capacity(context,len(execution.request.scenario_ids))
    require(re.fullmatch('[a-z-]+',label) is not None, 'capture baseline label invalid')
    root = context.evidence_root/'historical-capture-gates'/label
    require(not root.exists(), 'historical capture gate exists; no retry')
    names,witnesses = sessions(context)
    root.mkdir(parents=True)
    command = "$ErrorActionPreference='Stop';$rows=@();foreach($name in @("+','.join(suite.quote_ps(name) for name in names)+")){$q=(& logman query $name -ets 2>&1|Out-String);$rows+=@{name=$name;query=$q;exit=$LASTEXITCODE}};@{sessions=$rows;pktmon=(& pktmon status|Out-String)}|ConvertTo-Json -Depth 5 -Compress"
    raw = execution.runner.vm.powershell(command,30)
    write_new_json(root/'capture-baseline-original.json',raw);value = json.loads(raw['output'])
    require(isinstance(value.get('sessions'),list) and len(value['sessions'])==len(names)
            and {row.get('name') for row in value['sessions']}==set(names)
            and suite.Suite._pktmon_stopped(value['pktmon'])
            and all(row.get('exit')==-2144337918 and 'Data Collector Set was not found.' in row.get('query','')
                    for row in value['sessions']), 'historical owned/inherited capture remains active or unknown')
    if unused_namespace:
        raw = execution.runner.vm.powershell("$ErrorActionPreference='Stop';@{exists=(Test-Path -LiteralPath "+suite.quote_ps(context.physical_namespace)+")} | ConvertTo-Json -Compress",30)
        write_new_json(root/'namespace-original.json',raw)
        require(json.loads(raw['output']).get('exists') is False, 'physical guest namespace exists; no implicit resume')
    for record in witnesses:checked_record(dict(record))
    _transport_closed(execution.vm,context,'vm');_transport_closed(execution.service,context,'service')
    result = {'sessions':names,'original_indexed_witnesses':witnesses,'capture_original':file_record(root/'capture-baseline-original.json'),
        'unused_namespace_checked':unused_namespace,'guest_mutations':0,'new_formal_credit':0}
    write_new_json(root/'result.json',result)
    return file_record(root/'result.json')
