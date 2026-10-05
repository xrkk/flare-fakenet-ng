"""Minimal independent source-index view; source files are never edited."""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import shutil

import scenario_aux_qpc_v2 as v2
import scenario_suite as suite
from .audit import AuditError, SCHEMA, Mapper, require, save
from .context import checked_record, exact_path, read_json, file_sha256
from .source import SourceAuthority


def _source_record(authority, relative):
    path = exact_path(str(authority.root / relative))
    row = authority.rows.get(relative)
    require(row is not None, 'required source file missing/unindexed: ' + str(path))
    require(type(row.get('size')) is int and row['size'] >= 0, 'source size invalid')
    return {'path': str(path), 'size': row['size'], 'sha256': row['sha256']}


def _references(value):
    if isinstance(value, dict):
        if {'path', 'size', 'sha256'} <= value.keys():
            name = value['path']
            # Guest command inventories remain data; relative Suite records
            # are the source-copy graph, never instructions to execute.
            if isinstance(name, str) and not Path(name).is_absolute() and '\\' not in name:
                relative = PurePosixPath(name)
                require(relative.as_posix() == name and '..' not in relative.parts,
                        'source reference relative escape/alias')
                yield {k: value[k] for k in ('path', 'size', 'sha256')}
        for nested in value.values():
            yield from _references(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _references(nested)


def plan_view(context, scope):
    """Read pinned small metadata; inventory exact copy bytes before mutation."""
    context.revalidate()
    plan = read_json(checked_record(dict(context.materials['plan'])))
    original = checked_record(plan['original_manifest'])
    manifest = read_json(original)
    require(not suite.manifest_issues(manifest), 'original manifest contract invalid')
    if scope == 'row-selection':
        from .row_selection import selection as row_selection
        selection = row_selection(context)
        report = None
    elif scope == 'batch-selection':
        from .batch_selection import selection as batch_selection
        selection = batch_selection(context)
        report = None
    elif scope == 'credited-selection':
        selection = read_json(checked_record(dict(context.materials['credited_selection'])))
        report = None
    elif scope == 'spike-only':
        report_path = checked_record(dict(context.materials['spike_source']))
        authority = SourceAuthority(context, report_path.parent)
        report = authority.read(report_path)
        require(report.get('schema') == 'sst.fault-spike.v1' and isinstance(report.get('cases'), list),
                'Spike original selection missing')
        selection = {case['scenario_id']: str(report_path.parent) for case in report['cases']}
        require(len(selection) == len(report['cases']), 'Spike selection duplicated')
    else:
        raise AuditError('unregistered source selection scope')
    require(isinstance(selection, dict) and bool(selection), 'explicit selected source set required')
    product = context.candidate_identity
    identity = {'candidate_id': product['candidate'], 'source_commit': product['source'],
                'package_sha256': product['zip_sha256']}
    selected, sources, files, results = {}, {}, {}, {}
    for sid, location in selection.items():
        require(any(row['scenario_id'] == sid for row in manifest['scenarios']), 'selected scenario outside manifest')
        root = exact_path(location)
        authority = sources.setdefault(root, SourceAuthority(context, root))
        source_manifest = authority.read(root / 'scenario-manifest.json')
        require(source_manifest == manifest and (root / 'scenario-manifest.json').read_bytes() == original.read_bytes(),
                'source manifest differs from original canonical bytes')
        relative_result = 'results/scenario-' + sid + '.json'
        result = authority.read(root / relative_result)
        require(result.get('state') == 'pass' and result.get('scenario_id') == sid
                and result.get('identity') == identity and result.get('scenario') == next(
                    row for row in manifest['scenarios'] if row['scenario_id'] == sid),
                'selected actual pass/candidate/scenario differs')
        require(type(result.get('attempt')) is int and result['attempt'] > 0, 'selected attempt invalid')
        selected[sid] = {'root': location, 'attempt': result['attempt'],
                         'nonce': result['traffic_evidence']['nonce'],
                         'run_ids': [run['run_id'] for run in result['run_chain']]}
        prefix = 'evidence/' + sid + '/attempt-%02d/' % result['attempt']
        wanted = [name for name in authority.rows if name.startswith(prefix)]
        require(bool(wanted), 'selected original attempt dependency set missing')
        wanted += ['scenario-manifest.json', relative_result]
        for relative in wanted:
            record = _source_record(authority, relative)
            if relative == 'scenario-manifest.json' and relative in files:
                # All producers were separately checked against the pinned
                # canonical bytes above; the view has one canonical manifest.
                # Scenario/proof dependencies still require unique producers.
                checked_record(record)
                require(record['size'] == files[relative]['source']['size']
                        and record['sha256'] == files[relative]['source']['sha256'],
                        'canonical source manifest differs across producers')
                continue
            require(relative not in files or files[relative]['source'] == record,
                    'source-copy target collision across selected producers')
            files[relative] = {'source': record, 'root': str(root),
                              'index': dict(authority.index_record)}
        # All relative nested references in the selected result must already
        # belong to its exact indexed attempt (or canonical manifest/result).
        for ref in _references(result):
            item = files.get(ref['path'])
            require(item is not None and (item['root'] == str(root) or ref['path'] == 'scenario-manifest.json')
                    and item['source']['size'] == ref['size'] and item['source']['sha256'] == ref['sha256'],
                    'nested selected source reference missing/wrong attempt/SHA: ' + ref['path'])
        results[sid] = result
    if report is not None:
        root = Path(context.materials['spike_source']['path']).parent
        authority = sources[root]
        record = _source_record(authority, 'fault-spike-result.json')
        require(record == dict(context.materials['spike_source']), 'Spike report original source differs')
        files['fault-spike-result.json'] = {'source': record, 'root': str(root), 'index': dict(authority.index_record)}
        for ref in _references(report):
            item = files.get(ref['path'])
            require(item is not None and item['root'] == str(root)
                    and item['source']['size'] == ref['size'] and item['source']['sha256'] == ref['sha256'],
                    'nested Spike source reference missing/SHA differs')
    total = sum(item['source']['size'] for item in files.values())
    return {'scope': scope, 'identity': identity, 'selected': selected, 'results': results,
            'files': files, 'copy_bytes': total, 'file_count': len(files)}


def check_copy_capacity(context, inventory):
    context.revalidate()
    resource = context.materials['resource_plan']
    require(resource.get('host_reserve_bytes') == 24 * 2**30
            and resource.get('tmp_reserve_bytes') == 768 * 2**20, 'original audit resource floors differ')
    host, tmp = shutil.disk_usage(context.repository_root).free, shutil.disk_usage('/tmp').free
    # Retain both independent copies and bounded original derivation output.
    per_audit = resource.get('per_scenario_audit_copy_bytes')
    require(type(per_audit) is int and per_audit >= 0, 'audit derivation reserve missing')
    reserve = per_audit * len(inventory['selected'])
    need = 24 * 2**30 + inventory['copy_bytes'] + reserve
    require(host >= need and tmp >= 768 * 2**20, 'fresh independent source-copy capacity insufficient')
    return {'host_free_bytes': host, 'tmp_free_bytes': tmp, 'required_host_bytes': need,
            'copy_bytes': inventory['copy_bytes'], 'derivation_reserve_bytes': reserve}


def build_view(context, scope):
    """Fresh copy only; partial failure is preserved and never retried."""
    context.revalidate()
    require(not context.audit_root.exists(), 'existing audit output is not a retry')
    inventory = plan_view(context, scope)
    capacity = check_copy_capacity(context, inventory)
    context.audit_root.mkdir(parents=True, exist_ok=False)
    view = context.audit_root / 'view'
    view.mkdir()
    records, copies, failure = {}, [], None
    try:
        save(context.audit_root / 'source-copy-intent.json', {
            'materials_sha256': context.materials_sha256, 'scope': scope,
            'selected': inventory['selected'], 'files': inventory['files'], 'capacity': capacity})
        for relative, item in inventory['files'].items():
            context.revalidate()
            check_copy_capacity(context, {'selected': inventory['selected'],
                'copy_bytes': sum(row['source']['size'] for name, row in inventory['files'].items()
                                  if name not in {copy['relative'] for copy in copies})})
            source = checked_record(item['source'])
            target = exact_path(str(view / relative))
            require(target.is_relative_to(view) and not target.exists(), 'copy target escape/alias/collision')
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open('rb') as incoming, target.open('xb') as outgoing:
                shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            checked_record(dict(item['source'], path=str(target)))
            checked_record(item['source'])
            require((target.stat().st_dev, target.stat().st_ino) != (source.stat().st_dev, source.stat().st_ino),
                    'source copy inode is not independent')
            row = {'target': str(target), 'source_root': item['root'], 'source_path': str(source),
                   'size': item['source']['size'], 'sha256': item['source']['sha256'],
                   'source_seal': {'root': item['root'], 'index': item['index']['path'],
                                   'sha256': item['index']['sha256']}}
            records[str(target)] = row
            copies.append({'relative': relative, 'record': row})
            if target.name == 'completion.json':
                value = read_json(target)
                require(value.get('local_writer_ended') is True, 'selected transport writer not proven ended')
        contexts = {}
        for sid, result in inventory['results'].items():
            for run in result['run_chain']:
                if not run.get('auxiliary_qpc_proof'):
                    continue
                native = exact_path(str(view / run['auxiliary_qpc_process'][
                    'qpc-process-responsibility.json']['path'])).parent
                case = native / 'auxiliary-qpc-input.json'
                export = native / 'qpc-native/export'
                data = read_json(case)
                contexts[str(case)] = {'keys': [str(exact_path(str(p))) for p in v2._source_paths(case, view, data, export)],
                    'export': str(export), 'role': {'scenario': sid, 'attempt': result['attempt'],
                    'run_label': run['label'], 'run_id': run['run_id'],
                    'nonce': result['traffic_evidence']['nonce'], 'source_root': inventory['selected'][sid]['root']}}
        path = context.audit_root / 'authorities/selected.json'
        path.parent.mkdir()
        snapshot = {'schema': SCHEMA, 'scope': scope, 'runtime_view': str(view), 'records': records,
                    'contexts': contexts, 'selected': inventory['selected'], 'identity': inventory['identity']}
        save(path, snapshot)
        digest = file_sha256(path)
        mapper = Mapper(context, path, digest)
        for item in inventory['files'].values(): checked_record(item['source'])
        for row in records.values(): checked_record({'path': row['target'], 'size': row['size'], 'sha256': row['sha256']})
        save(context.audit_root / 'source-copy-complete.json', {'authority': str(path),
            'authority_sha256': digest, 'files': len(copies), 'bytes': inventory['copy_bytes'],
            'independent_inodes': True, 'source_originals_retained': True, 'no_proof_credit': True})
        return mapper
    except BaseException as error:
        failure = error
        raise
    finally:
        terminal = {'scope': scope, 'copy_completed': failure is None, 'error': repr(failure) if failure else None,
                    'copied': copies, 'host_copy_writers_ended': True,
                    'partial_originals_retained': True, 'VM_calls': 0, 'new_formal_credit': 0}
        try:
            save(context.audit_root / 'source-copy-terminal.json', terminal)
        except BaseException as secondary:
            if failure: failure.add_note('source copy terminal audit failed: ' + repr(secondary))
            else: raise
