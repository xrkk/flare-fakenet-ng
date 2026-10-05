"""Offline preparation through original config semantics and separate audits.

The business interpreter never installs a source mapper or imports the audit
entry. A successful result grants only offline preparation; live identity,
namespace, instance and resource gates remain mandatory before dispatch.
"""
from __future__ import annotations

from pathlib import Path
import json
import hashlib
import subprocess
import sys
from types import SimpleNamespace
from collections.abc import Mapping

from .context import checked_record, load_context, read_json, file_sha256, _overlap
from .config_ownership import selection_plan
from .command_transport import write_new_json
from .runner import check_preparation_inputs, require, _capacity
from .runtime_sources import qualify, loaded_sources
from .source import NAMESPACE, SourceAuthority


def execution_plan(context):
    """Check the original producer's physical identity before preparation."""
    context.revalidate()
    plan = read_json(checked_record(dict(context.materials['plan'])))
    match = NAMESPACE.fullmatch(context.physical_namespace)
    scope = hashlib.sha256(str(context.evidence_root).encode()).hexdigest()[:12]
    require(match is not None and match['scope'] == scope
            and plan.get('nonce') == match['nonce'],
            'preparation producer namespace nonce/scope differs from original output')
    require(type(plan.get('cycles_bound')) is int and plan['cycles_bound'] == 70,
            'original controlled SCM cycle bound differs')
    return {'physical_namespace': context.physical_namespace,
            'nonce': match['nonce'], 'scope': scope, 'cycles_bound': 70}


def configuration_plan(context):
    context.revalidate()
    plan = read_json(checked_record(dict(context.materials['plan'])))
    manifest = read_json(checked_record(plan['original_manifest']))
    # selection_plan inspects the original Suite lifecycle source and needs
    # only args.command and manifest(); no Suite/client/output is constructed.
    expected = selection_plan(SimpleNamespace(args=SimpleNamespace(command='run'),
                                              manifest=lambda: manifest))
    supplied = read_json(checked_record(plan.get('configuration_plan')))
    require(json.dumps(supplied, sort_keys=True) == json.dumps(expected, sort_keys=True),
            'frozen configuration plan differs from original full lifecycle')
    require(len(expected['selected']) == 100 and len(expected['must_be_absent']) == 401
            and expected['restoration_builtin'] == 'default.ini'
            and expected['no_contract_renaming'] is True,
            'original full configuration namespace/restoration contract differs')
    return expected


def audit_jobs(context, *, require_unused=True):
    """Bind both independently pinned audit lanes before creating any output."""
    context.revalidate()
    plan = read_json(checked_record(dict(context.materials['plan'])))
    jobs = plan.get('preparation_audits')
    require(isinstance(jobs, list) and len(jobs) == 2,
            'two explicit independent preparation audits required')
    scopes = ('credited-selection', 'spike-only')
    result = []
    for expected_scope, job in zip(scopes, jobs):
        require(isinstance(job, dict) and set(job) == {'scope', 'materials', 'selection'}
                and job['scope'] == expected_scope,
                'preparation audits must be ordered credited selection then Spike')
        material = checked_record(job['materials'])
        selection_path = checked_record(job['selection'])
        child = load_context(material, job['materials']['sha256'],
                             repository_root=context.repository_root,
                             source_root=context.source_root)
        require(child.candidate_identity == context.candidate_identity
                and child.tool_source == context.tool_source
                and child.physical_namespace == context.physical_namespace,
                'preparation audit candidate/tool/physical identity differs')
        for key in ('source_indices', 'credited_selection', 'spike_source', 'resource_plan'):
            require(child.materials[key] == context.materials[key],
                    'preparation audit source/resource binding differs: ' + key)
        require(set(context.materials['protected_sources']) <= set(child.materials['protected_sources']),
                'preparation audit omits protected original sources')
        child_plan = read_json(checked_record(dict(child.materials['plan'])))
        for key in ('original_manifest', 'candidate_files'):
            require(child_plan.get(key) == plan.get(key),
                    'preparation audit original material differs: ' + key)
        for kind in ('benign', 'fault'):
            original = read_json(checked_record(dict(context.materials['suite_argv'][kind])))
            invocation = read_json(checked_record(dict(child.materials['suite_argv'][kind])))
            values = list(invocation['argv'])
            values[values.index('--suite-root') + 1] = str(context.evidence_root)
            require({**invocation, 'argv': values} == original,
                    'preparation audit original argv differs beyond owned suite root: ' + kind)
        require(child.audit_root == context.audit_root/'preparation-audits'/expected_scope
                and not _overlap(child.evidence_root, context.evidence_root)
                and not _overlap(child.evidence_root, context.audit_root)
                and not child.evidence_root.exists()
                and (not require_unused or not child.audit_root.exists()),
                'preparation audit must own distinct unused output roots')
        for source in (material, selection_path):
            require(not source.is_relative_to(context.evidence_root)
                    and not source.is_relative_to(context.audit_root),
                    'preparation audit input overlaps main output')
        if expected_scope == 'credited-selection':
            require(job['selection'] == dict(context.materials['credited_selection']),
                    'preparation audit credited selection differs')
        else:
            spike = read_json(checked_record(dict(context.materials['spike_source'])))
            cases = spike.get('cases')
            require(isinstance(cases, list) and bool(cases)
                    and all(isinstance(case, dict) and isinstance(case.get('scenario_id'), str)
                            for case in cases), 'original Spike selection cases missing')
            expected = {case['scenario_id']: str(Path(context.materials['spike_source']['path']).parent)
                        for case in cases}
            require(len(expected) == len(cases) and read_json(selection_path) == expected,
                    'preparation audit must select exact original Spike cases')
        result.append((job, child))
    return result


def _record(path):
    return {'path': str(path), 'size': path.stat().st_size, 'sha256': file_sha256(path)}


def output_inventory(root):
    from .context import exact_path
    root = exact_path(str(root))
    records = []
    for path in sorted(root.rglob('*')):
        exact_path(str(path))
        if path.is_file(): records.append(_record(path))
        else: require(path.is_dir(), 'audit output contains a nonregular dependency')
    return records


def check_audit_copies(context, verdict):
    """Read the original authority as data; install no projection or guard."""
    from .context import exact_path
    path = exact_path(verdict['authority'])
    require(path == context.audit_root/'authorities/selected.json'
            and file_sha256(path) == verdict['authority_sha256'],
            'original audit copy authority fingerprint/path differs')
    authority = read_json(path)
    view = context.audit_root/'view'
    require(authority.get('schema') == 'fakenetng.formal-runtime.source-bijection.v1'
            and authority.get('runtime_view') == str(view)
            and authority.get('scope') == verdict['scope'], 'original audit copy authority identity differs')
    rows = authority.get('records')
    require(isinstance(rows, dict) and bool(rows), 'original audit copy dependencies missing')
    sources = {}
    for target, row in rows.items():
        require(isinstance(row, dict) and row.get('target') == target,
                'original audit copy target differs')
        target = exact_path(target); source = exact_path(row['source_path'])
        origin = exact_path(row['source_root'])
        require(source.is_relative_to(origin) and target == view/source.relative_to(origin),
                'original audit copy relative source differs')
        if origin not in sources: sources[origin] = SourceAuthority(context, origin)
        original = sources[origin]; index = dict(original.index_record)
        require(row.get('source_seal') == {'root': str(origin), 'index': index['path'], 'sha256': index['sha256']},
                'original audit copy source seal differs')
        sealed = original.rows.get(source.relative_to(origin).as_posix())
        require(isinstance(sealed, Mapping) and sealed.get('size') == row['size']
                and sealed.get('sha256') == row['sha256'], 'original audit copy is not exact indexed source')
        checked_record({'path': str(source), 'size': row['size'], 'sha256': row['sha256']})
        checked_record({'path': str(target), 'size': row['size'], 'sha256': row['sha256']})
        require((source.stat().st_dev, source.stat().st_ino) != (target.stat().st_dev, target.stat().st_ino),
                'original audit copy shares source inode')


def prepare(context, entry):
    """Perform all offline gates, preserving a failed audit and stopping there."""
    context.revalidate()
    qualified = qualify(context, entry)
    modules = loaded_sources(context, qualified)
    execution = execution_plan(context)
    inputs = check_preparation_inputs(context)
    config = configuration_plan(context)
    jobs = audit_jobs(context)
    context.revalidate()
    root = context.audit_root
    require(not root.exists() and not context.evidence_root.exists(),
            'preparation output exists; no implicit resume')
    root.mkdir(parents=True, exist_ok=False)
    rows, failure, result = [], None, None
    try:
        write_new_json(root/'source-map.json', {'sources': qualified, 'actual_modules': modules})
        write_new_json(root/'configuration-plan.json', config)
        for job, child in jobs:
            context.revalidate()
            checked_record(job['materials']); checked_record(job['selection'])
            prefix = root/('prepare-'+job['scope'])
            command = [sys.executable, '-B', str(context.source_root/'test/mcp/acceptance/run_formal_source_audit.py'),
                       '--materials-json', str(child.materials_path),
                       '--materials-sha256', child.materials_sha256,
                       '--selection-json', job['selection']['path'], '--scope', job['scope'],
                       '--repository-root', str(context.repository_root)]
            write_new_json(prefix.with_suffix('.intent.json'), {'argv': command,
                'main_materials_sha256': context.materials_sha256,
                'audit_materials_sha256': child.materials_sha256})
            # Only the qualified independent audit entry may run here. Its
            # guard denies network/business subprocesses and all child calls
            # are synchronous; capture originals directly, without projection.
            with prefix.with_suffix('.stdout').open('xb') as stdout, prefix.with_suffix('.stderr').open('xb') as stderr:
                completed = subprocess.run(command, cwd=context.source_root, stdout=stdout, stderr=stderr)
            row = {'scope': job['scope'], 'exit_code': completed.returncode,
                   'stdout': _record(prefix.with_suffix('.stdout')),
                   'stderr': _record(prefix.with_suffix('.stderr')),
                   'audit_materials': job['materials'], 'selection': job['selection']}
            rows.append(row)
            write_new_json(prefix.with_suffix('.completion.json'), row)
            row.update(intent=_record(prefix.with_suffix('.intent.json')),
                       completion=_record(prefix.with_suffix('.completion.json')))
            require(completed.returncode == 0, 'original independent preparation audit failed: '+job['scope'])
            audit_path = child.audit_root/'audit-result.json'
            terminal_path = child.audit_root/'audit-terminal.json'
            verdict, terminal = read_json(audit_path), read_json(terminal_path)
            require(verdict.get('schema') == 'fakenetng.formal-runtime.original-source-audit.v1'
                    and verdict.get('passed') is True and verdict.get('scope') == job['scope']
                    and verdict.get('selected') == read_json(checked_record(job['selection']))
                    and verdict.get('adapter_restored') is True and verdict.get('VM_calls') == 0
                    and verdict.get('new_formal_credit') == 0
                    and terminal.get('passed') is True and terminal.get('error') is None
                    and terminal.get('adapter_restored') is True
                    and terminal.get('host_audit_writers_ended') is True,
                    'independent original audit result/terminal incomplete')
            row.update(result=_record(audit_path), terminal=_record(terminal_path))
            check_audit_copies(child, verdict)
            index_path = prefix.with_suffix('.output-index.json')
            write_new_json(index_path, {'audit_root': str(child.audit_root),
                'audit_materials_sha256': child.materials_sha256,
                'audit_process_waited': True, 'files': output_inventory(child.audit_root)})
            row['output_index'] = _record(index_path)
        context.revalidate()
        for row, (_, child) in zip(rows, jobs):
            verdict = read_json(checked_record(row['result']))
            check_audit_copies(child, verdict)
            inventory = read_json(checked_record(row['output_index']))
            require(inventory['files'] == output_inventory(child.audit_root),
                    'original audit outputs changed before preparation publication')
        qualify(context, entry)
        loaded_sources(context, qualified)
        # Audit copies have consumed space since the first input check.
        capacity = _capacity(context, max(len(row['scenario_ids']) for row in inputs['batches']))
        result = {'schema': 'fakenetng.formal-runtime.preparation.v1', 'passed': True,
                  'materials_sha256': context.materials_sha256, 'inputs': inputs,
                  'execution_plan': execution,
                  'configuration_plan': _record(root/'configuration-plan.json'),
                  'source_map': _record(root/'source-map.json'), 'audits': rows,
                  'fresh_capacity_after_audits': capacity,
                  'VM_calls': 0, 'business_authorized': False, 'new_formal_credit': 0,
                  'live_instance_and_resource_admission_required': True}
        write_new_json(root/'preparation-result.json', result)
        return result
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            write_new_json(root/'preparation-terminal.json', {'passed': result is not None and failure is None,
                'materials_sha256': context.materials_sha256, 'error': repr(failure) if failure else None,
                'audits': rows, 'host_audit_processes_waited': True, 'VM_calls': 0, 'new_formal_credit': 0})
        except BaseException as secondary:
            if failure is not None: failure.add_note('preparation terminal failed: '+repr(secondary))
            else: raise
