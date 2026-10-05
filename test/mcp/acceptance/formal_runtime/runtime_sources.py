"""Qualify the full original runtime's static and explicitly dynamic sources.

This map identifies host tools and immutable candidate helpers separately. It
does not perform preparation, create clients, install auditing, or grant credit.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys

from .context import MaterialError, checked_record, exact_path, file_sha256, read_json
from .runner import require
from .source_graph import source_closure


DYNAMIC = ('run_formal_source_audit.py','scenario_pktmon.py','scenario_fault_evidence.py','sst_fault_evidence.py',
    'scenario_probes.ps1','scenario_qpc_diagnostic.py','scenario_aux_qpc_diagnostic.py',
    'scenario_qpc_identity.py','etl_raw_clock.py','tdh_metadata.py','scenario_tcpip.py',
    'scenario_clock.py','scenario_qpc_offline.py','scenario_aux_qpc_v2.py',
    'scenario_aux_qpc_single_pass.py','scenario_aux_qpc_offline.py','scenario_aux_qpc_contract.py')
ROOT_MODULES = ('fnpr_sentinel',)


def expected_sources(source_root,entry):
    paths=source_closure(source_root,entry,dynamic=DYNAMIC,root_modules=ROOT_MODULES)
    # Original _freeze_faultinject_source copies these candidate bytes to data
    # evidence, even if that module was not otherwise a static import.
    paths.update(source_closure(source_root,source_root/'fakenet/mcp/faultinject.py'))
    return paths


def qualify(context,entry):
    context.revalidate()
    source=context.source_root
    entry=exact_path(str(entry))
    require(entry.is_relative_to(source/'test/mcp/acceptance') and entry.suffix=='.py',
            'runtime entry must be tracked formal acceptance Python')
    plan=read_json(checked_record(dict(context.materials['plan'])))
    extra=plan.get('additional_tool_files')
    require(isinstance(extra,list), 'full runtime requires explicit root-tool file records')
    declared={Path(row['path']):dict(row) for row in context.tool_source['files']}
    root_paths={source/(name+'.py') for name in ROOT_MODULES}
    require(all(isinstance(row,dict) for row in extra), 'runtime root-tool records must be file objects')
    extra_paths={checked_record(row) for row in extra}
    require(len(extra)==len(root_paths) and extra_paths==root_paths,
            'full runtime root-tool records differ from exact FNPR source')
    for row in extra:
        path=checked_record(row)
        require(path not in declared, 'duplicate runtime source declaration')
        declared[path]=row
    records=[]
    for path in sorted(expected_sources(source,entry)):
        relative=path.relative_to(source).as_posix()
        product=path.is_relative_to(source/'fakenet')
        commit=context.candidate_identity['source'] if product else context.tool_source['commit']
        if not product:
            require(path in declared, 'full runtime source dependency not pinned: '+relative)
            checked_record(declared[path])
        try:
            raw=subprocess.run(['git','-C',str(source),'cat-file','blob',commit+':'+relative],
                check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30).stdout
        except (OSError,subprocess.SubprocessError) as error:
            raise MaterialError('runtime source absent from its immutable commit: '+relative) from error
        require(len(raw)==path.stat().st_size and hashlib.sha256(raw).hexdigest()==file_sha256(path),
                'runtime source differs from immutable '+('candidate' if product else 'tool')+' bytes: '+relative)
        records.append({'path':str(path),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                        'kind':'product-helper' if product else 'tool','commit':commit})
    return records


def loaded_sources(context,qualified):
    wanted={Path(row['path']):row for row in qualified}
    records=[]
    for name,module in sorted(sys.modules.copy().items()):
        value=getattr(module,'__file__',None)
        if not value:continue
        path=Path(value)
        if path.suffix not in ('.py','.pyc'):continue
        require(not path.resolve().is_relative_to(context.repository_root/'Logs'), 'runtime loaded code from Logs')
        local=name.startswith(('formal_runtime','scenario_','sst_','etl_','tdh_','fakenet')) or name in ROOT_MODULES
        if path.is_relative_to(context.source_root/'test/mcp/acceptance') or local:
            path=exact_path(str(path))
            require(path in wanted and file_sha256(path)==wanted[path]['sha256'],
                    'actual runtime module outside qualified source: '+name)
            records.append({'module':name,**wanted[path]})
    return records
