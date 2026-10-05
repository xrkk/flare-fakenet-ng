"""Read versioned producer data through an independently indexed authority.

Historical materials and Git blobs are data. They never load the old driver or
revalidate old tool fingerprints against a later consumer worktree.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import subprocess

from .context import MATERIAL_KEYS, SCHEMA, exact_path, _freeze
from .producer import DISPATCH_SCHEMA, EXECUTION_SCHEMA
from .source import NAMESPACE, SourceBinding, SourceError, capture_witness, parts, require


PRODUCER_FILES = frozenset('test/mcp/acceptance/formal_runtime/'+name+'.py'
                          for name in ('context','source','instance','command_transport','producer'))


def _original_tool_data(authority, binding, material):
    source = exact_path(binding['source_root'])
    require(source == authority.context.source_root, 'original producer source repository differs')
    tools = material.get('tool_source')
    require(isinstance(tools, dict) and set(tools) == {'commit','files'}
            and isinstance(tools['commit'], str) and re.fullmatch('[0-9a-f]{40}', tools['commit'])
            and tools['commit'] == binding['tool_commit']
            and isinstance(tools['files'], list) and tools['files'], 'original producer tool binding invalid')
    seen = set()
    for row in tools['files']:
        require(isinstance(row, dict) and set(row) == {'path','size','sha256'}
                and type(row['size']) is int and row['size'] >= 0
                and isinstance(row['sha256'], str) and re.fullmatch('[0-9a-f]{64}', row['sha256']),
                'original producer tool record invalid')
        path = exact_path(row['path'])
        require(path.is_relative_to(source/'test/mcp'), 'original producer tool outside formal source')
        relative = path.relative_to(source).as_posix()
        require(relative not in seen, 'duplicate original producer tool dependency')
        seen.add(relative)
        try:
            raw = subprocess.run(['git','-C',str(source),'cat-file','blob',tools['commit']+':'+relative],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout
        except (OSError, subprocess.SubprocessError) as error:
            raise SourceError('original producer dependency absent from immutable Git: '+relative) from error
        require(len(raw) == row['size'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
                'original producer dependency differs from immutable Git')
    require(PRODUCER_FILES <= seen, 'original producer dependency closure incomplete')


def resolve_indexed(authority):
    """An explicit v1 binding cannot fall back to the historical driver schema."""
    root = authority.root
    binding = authority.read(root/'execution-binding.json')
    require(isinstance(binding, dict) and set(binding) == {
        'schema','original_execution_root','source_root','identity','physical_namespace',
        'source_nonce','materials','plan','tool_commit','no_business_admission'}
        and binding['schema'] == EXECUTION_SCHEMA and binding['no_business_admission'] is True,
        'unknown versioned producer binding')
    original = exact_path(binding['original_execution_root'])
    require(original == root and binding['identity'] == dict(authority.context.candidate_identity),
            'original producer root/candidate differs')
    material_record = binding['materials']
    require(isinstance(material_record, dict) and set(material_record) == {'path','size','sha256'},
            'original producer independent material record missing')
    material_path = exact_path(material_record['path'])
    require(material_path.stat().st_size <= 4*1024*1024, 'original producer material exceeds original bound')
    material = authority.frozen_dependency(material_path, material_record['sha256'])
    require(type(material_record['size']) is int and material_path.stat().st_size == material_record['size'],
            'original producer material size differs')
    require(isinstance(material, dict) and set(material) == MATERIAL_KEYS and material.get('schema') == SCHEMA
            and material['evidence_root'] == str(original)
            and material['candidate_identity'] == binding['identity']
            and material['physical_namespace'] == binding['physical_namespace']
            and material['plan'] == binding['plan'], 'original producer material binding differs')
    plan_record = binding['plan']
    require(isinstance(plan_record, dict) and set(plan_record) == {'path','size','sha256'},
            'original producer plan record missing')
    plan_path = exact_path(plan_record['path'])
    plan = authority.frozen_dependency(plan_path, plan_record['sha256'])
    require(type(plan_record['size']) is int and plan_path.stat().st_size == plan_record['size']
            and plan.get('identity') == binding['identity'] and plan.get('root') == str(original)
            and plan.get('physical_namespace') == binding['physical_namespace'], 'original producer plan differs')
    namespace = binding['physical_namespace']
    match = NAMESPACE.fullmatch(namespace)
    require(match is not None and match['nonce'] == binding['source_nonce']
            and match['scope'] == hashlib.sha256(str(original).encode()).hexdigest()[:12],
            'original producer nonce/scope differs')
    _original_tool_data(authority, binding, material)
    return _dispatch_binding(authority, binding, material_record['sha256'])


def _dispatch_binding(authority, execution, material_sha):
    root = authority.root
    namespace = execution['physical_namespace']
    original = exact_path(execution['original_execution_root'])
    captures, kernels, unresolved = [], [], []
    intents = [relative for relative in authority.rows if len(PurePosixPath(relative).parts) == 2
               and PurePosixPath(relative).parts[0] == 'VM-final-intents']
    require(intents, 'versioned producer has no actual VM dispatch witnesses')
    call_ids = {PurePosixPath(relative).stem for relative in intents}
    for relative in authority.rows:
        path = PurePosixPath(relative)
        if len(path.parts) == 2 and path.parts[0] in ('VM-final-responses','VM-final-terminals'):
            require(path.stem in call_ids and path.suffix == '.json', 'orphan producer response/terminal')
    for relative in sorted(intents):
        path = PurePosixPath(relative)
        key = path.stem
        require(path.suffix == '.json' and re.fullmatch('[0-9a-f]{32}', key), 'producer call ID invalid')
        intent = authority.read(root/relative)
        command = intent.get('command')
        require(intent.get('schema') == DISPATCH_SCHEMA and intent.get('call_id') == key
                and isinstance(command, str) and command
                and intent.get('command_sha256') == hashlib.sha256(command.encode()).hexdigest()
                and intent.get('materials_sha256') == material_sha and intent.get('no_replay') is True,
                'producer actual intent binding differs')
        terminal = authority.read(root/'VM-final-terminals'/(key+'.json'))
        require(terminal.get('schema') == DISPATCH_SCHEMA and terminal.get('call_id') == key
                and terminal.get('intent') == str(root/relative)
                and terminal.get('materials_sha256') == material_sha
                and terminal.get('dispatch_started') is True
                and terminal.get('no_mutation_replay') is True,
                'producer terminal missing or mismatched')
        response = None
        response_path = root/'VM-final-responses'/(key+'.json')
        if terminal.get('response_known') is True:
            require(terminal.get('response_persisted') is True, 'producer known response not persisted')
            record = terminal.get('response')
            row = authority.rows.get(response_path.relative_to(root).as_posix())
            require(row is not None and record == {'path':str(response_path),
                    'size':row.get('size'), 'sha256':row.get('sha256')}, 'producer response fingerprint differs')
            response = authority.read(response_path)
        else:
            require(terminal.get('response_known') is False and terminal.get('response') is None
                    and terminal.get('response_persisted') is False
                    and response_path.relative_to(root).as_posix() not in authority.rows
                    and terminal.get('original_error'), 'producer unknown response has contradictory evidence')
        value = None
        if response is not None:
            require(isinstance(response, dict), 'producer raw VM response is not an object')
            try:
                value = json.loads(response['output'])
            except (KeyError, TypeError, ValueError):
                pass
        if 'logman start $s -ets' in command:
            session = re.search(r"\$s='(SST-Kernel-[a-f0-9-]+)'", command)
            run = re.search(r"\$r='([^']+)'", command)
            require(session and run and run[1].startswith(namespace+'\\scenario-suite-20260912\\')
                    and '..' not in PureWindowsPath(run[1]).parts, 'owned ETW intent identity/root invalid')
            if response is not None:
                require(isinstance(value,dict) and value.get('session_name') == session[1]
                        and value.get('guest') == run[1]
                        and value.get('metadata') == run[1]+r'\kernel-network.metadata.json',
                        'owned ETW actual response differs from exact intent')
            kernels.append({'name':session[1], 'run':run[1],
                'metadata':run[1]+r'\kernel-network.metadata.json', 'etl':run[1]+r'\kernel-network.etl',
                'optional':[run[1]+r'\kernel-network'+suffix for suffix in
                            ('.events.jsonl','.header.xml','.summary.txt')],
                'response_unknown':response is None, 'intent':str(root/relative)})
        capture_intent = '$encoded=' in command and 'probe_creation_ticks' in command
        if isinstance(value, dict) and all(value.get(k) for k in ('guest','etl','probe')):
            require(response.get('exit_code',0) == 0, 'failed VM response cannot supply capture ownership')
            physical, capture = capture_witness(value, command, execution['source_nonce'], original, response_path)
            require(physical == namespace, 'producer actual capture namespace differs')
            captures.append(capture)
        elif capture_intent:
            # A missing/failed capture start cannot disappear from ownership.
            # Accurate original recovery is required before any export gate.
            unresolved.append(str(root/relative))
    require(captures and kernels and len({row['name'] for row in kernels}) == len(kernels),
            'capture/ETW ownership incomplete or duplicate')
    require(len({parts(row['run']) for row in captures}) == len(captures), 'duplicate actual capture producer')
    for capture in captures:
        if capture['required'][0] != capture['run']+r'\pktmon.etl':
            require(any(owner['run_label'] == 'run-01' and owner['required'][0] == capture['required'][0]
                        for owner in captures), 'shared source has no actual owner response')
    required = {path for row in captures for path in row['required']}
    required.update(path for row in kernels for path in (row['metadata'],row['etl']))
    optional = {path for row in captures for path in row['optional']}
    optional.update(path for row in kernels for path in row['optional'])
    runtime = authority.read(root/'execution-context.json')
    require(isinstance(runtime.get('backup_names'), list), 'producer backup inventory missing')
    for name in runtime['backup_names']:
        require(isinstance(name,str) and name and not any(t in name for t in ('/','\\','..')), 'backup name escape')
        required.add(namespace+'\\scenario-suite-20260912\\'+name)
    for relative in sorted(authority.rows):
        if '/' not in relative and relative.startswith('cycle-') and relative.endswith('-intent.json'):
            receipt = authority.read(root/relative)['receipt']
            require(isinstance(receipt,str) and receipt.startswith(namespace+'\\scenario-suite-20260912\\')
                    and '..' not in PureWindowsPath(receipt).parts, 'receipt cross-source path')
            required.add(receipt)
    for path in required|optional:
        require(isinstance(path,str) and path.startswith(namespace+'\\scenario-suite-20260912\\')
                and '..' not in PureWindowsPath(path).parts, 'producer file dependency outside exact namespace')
    return SourceBinding(_freeze({
        'schema':'source-namespace-binding.v1', 'producer_schema':EXECUTION_SCHEMA,
        'identity':execution['identity'], 'source_evidence_root':str(root),
        'original_execution_root':str(original),
        'original_driver':str(Path(execution['source_root'])/'test/mcp/acceptance/formal_runtime/producer.py'),
        'physical_namespace':namespace, 'source_nonce':execution['source_nonce'],
        'captures':captures, 'kernels':kernels, 'unresolved_capture_intents':unresolved,
        'required_files':sorted(required), 'optional_files':sorted(optional-required),
        'witnesses':authority.witnesses, 'source_index':authority.index_record,
        'derived_from_actual_immutable_source':True, 'original_response_unchanged':True,
    }))
