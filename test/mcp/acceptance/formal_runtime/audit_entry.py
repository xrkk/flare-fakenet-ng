"""Independent original Suite verification; never imported by business runner."""
from __future__ import annotations

import ast
import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import traceback

import formal_batch_v3 as batch
import scenario_suite as suite
from .audit import AuditError, AuditGuard, require, save
from .audit_view import build_view
from .context import checked_record, exact_path, read_json, file_sha256


AUDIT_DYNAMIC = ('scenario_pktmon.py', 'scenario_fault_evidence.py', 'sst_fault_evidence.py')


def source_closure(source_root, entry):
    """Local static imports plus original audit's three file-loaded scripts."""
    local = source_root / 'test/mcp/acceptance'
    def module(name):
        base = source_root if name == 'fakenet' or name.startswith('fakenet.') else local
        path = base.joinpath(*name.split('.'))
        if path.with_suffix('.py').is_file(): return path.with_suffix('.py')
        if (path / '__init__.py').is_file(): return path / '__init__.py'
        if name.startswith(('fakenet.', 'formal_runtime.', 'scenario_', 'sst_', 'etl_', 'tdh_')):
            raise AuditError('local static source dependency missing: ' + name)
        return None
    pending = [entry, *(local / name for name in AUDIT_DYNAMIC)]
    seen = set()
    while pending:
        path = exact_path(str(pending.pop()))
        if path in seen: continue
        require(path.is_file(), 'entry dependency missing: ' + str(path))
        seen.add(path)
        root = source_root if path.is_relative_to(source_root / 'fakenet') else local
        relative = path.relative_to(root)
        parts = list(relative.with_suffix('').parts)
        package = parts[:-1]
        for i in range(1,len(package)+1):
            parent = root.joinpath(*package[:i]) / '__init__.py'
            if parent.is_file(): pending.append(parent)
        tree = ast.parse(path.read_bytes(), filename=str(path))
        names = []
        for node in ast.walk(tree):
            if isinstance(node,ast.Import): names.extend(row.name for row in node.names)
            elif isinstance(node,ast.ImportFrom):
                if node.level:
                    base = package[:len(package)-node.level+1]
                    name = '.'.join(base + ([node.module] if node.module else []))
                else: name = node.module or ''
                if name: names.append(name)
                # A from-import can name a module or a value. Only an actual
                # sibling file/package is a further local dependency.
                for row in node.names:
                    child = name + '.' + row.name if name else row.name
                    base = source_root if child.startswith('fakenet.') else local
                    test = base.joinpath(*child.split('.'))
                    if test.with_suffix('.py').is_file() or (test/'__init__.py').is_file(): names.append(child)
        for name in names:
            path = module(name)
            if path is not None: pending.append(path)
    return seen


def qualify_sources(context, entry, guard):
    context.revalidate()
    require(entry == context.source_root / 'test/mcp/acceptance/run_formal_source_audit.py',
            'independent entry source location differs')
    wanted = source_closure(context.source_root,entry)
    declared = {Path(row['path']):dict(row) for row in context.tool_source['files']}
    tool_paths = {path for path in wanted if path.is_relative_to(context.source_root/'test/mcp')}
    require(tool_paths <= declared.keys(), 'independent entry source closure has unpinned tool dependencies: ' +
            ', '.join(str(path.relative_to(context.source_root)) for path in sorted(tool_paths-declared.keys())))
    records = []
    for path in sorted(wanted):
        if path in tool_paths:
            record = declared[path]
            checked_record(record)
            records.append(dict(record,kind='tool',commit=context.tool_source['commit']))
        else:
            require(path.is_relative_to(context.source_root/'fakenet'), 'unexpected source outside tool/product trees')
            command = ['git','-C',str(context.source_root),'cat-file','blob',
                       context.candidate_identity['source']+':'+path.relative_to(context.source_root).as_posix()]
            guard.git_reads.add(tuple(command))
            raw = subprocess.run(command,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30).stdout
            require(len(raw)==path.stat().st_size and hashlib.sha256(raw).hexdigest()==file_sha256(path),
                    'original audit product helper differs from candidate source: '+str(path))
            records.append({'path':str(path),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                            'kind':'product-helper','commit':context.candidate_identity['source']})
    guard.qualified_files = {Path(row['path']):row['sha256'] for row in records}
    return records


def loaded_sources(context, qualified):
    wanted = {Path(row['path']) for row in qualified}
    rows = []
    for name,module in sorted(sys.modules.copy().items()):
        value = getattr(module,'__file__',None)
        if not value: continue
        path = Path(value)
        if path.suffix not in ('.py','.pyc'): continue
        require(not path.resolve().is_relative_to(context.repository_root/'Logs'), 'audit loaded code from Logs')
        local_name = name.startswith(('formal_runtime', 'scenario_', 'sst_', 'etl_', 'tdh_', 'fakenet'))
        if path.is_relative_to(context.source_root/'test/mcp') or local_name:
            path = exact_path(str(path))
            require(path in wanted, 'actual loaded module outside qualified source closure: '+name+':'+str(path))
            rows.append({'module':name,'path':str(path),'sha256':file_sha256(path)})
    return rows


def run(context, selection_path, scope, entry):
    """Returns original failure/coverage; no network, live Spike or new credit."""
    context.revalidate()
    selection_path = exact_path(str(selection_path))
    require(selection_path.is_file(), 'explicit selection file missing')
    selection = read_json(selection_path)
    if scope=='credited-selection':
        pinned = checked_record(dict(context.materials['credited_selection']))
        require(selection_path==pinned and selection==read_json(pinned), 'selection is not independently pinned credited material')
    else:
        report_path = checked_record(dict(context.materials['spike_source']))
        report = read_json(report_path)
        expected = {case['scenario_id']:str(report_path.parent) for case in report['cases']}
        require(selection==expected and len(expected)==len(report['cases']), 'selection differs from original Spike cases')
    guard = AuditGuard(context)
    qualified = qualify_sources(context,entry,guard)
    initial_modules = loaded_sources(context,qualified)
    sys.addaudithook(guard)
    guard.active = True
    mapper, failure, verify, replay, summary, passed = None, None, None, None, None, False
    try:
        mapper = build_view(context,scope)
        args = copy.copy(batch.load_suite_args(checked_record(dict(context.materials['suite_argv']['benign']))))
        args.suite_root = str(mapper.view if scope=='credited-selection' else context.audit_root/'matrix-view')
        args.target_base_url = args.win10vm_mcp = None
        runner = suite.Suite(args)
        if scope=='spike-only':
            # Distinct roots and identical canonical manifest are required by
            # the original Spike gate; copies never change report references.
            manifest = checked_record(dict(read_json(checked_record(dict(context.materials['plan'])))['original_manifest']))
            target = runner.root/'scenario-manifest.json'
            with manifest.open('rb') as source,target.open('xb') as output: output.write(source.read())
            runner.args.fault_spike_result = str(mapper.view/'fault-spike-result.json')
        with mapper.installed(context.audit_root/'proofs'):
            if scope=='spike-only':
                runner._require_fault_spike()
                passed = True
            else:
                expected = {'missing actual scenario: '+row['scenario_id'] for row in runner.manifest()['scenarios']
                            if row['scenario_id'] not in selection}
                verify = runner.verify()
                require(set(verify['problems'])==expected and len(verify['problems'])==len(expected)
                        and verify['scenario_count']==len(selection) and verify['passed']==(not expected),
                        'original verify has problems beyond exact unselected coverage')
                replay = {sid:runner.verify(replay=sid) for sid in selection}
                require(all(set(value['problems'])==expected and len(value['problems'])==len(expected)
                            for value in replay.values()), 'original selected replay differs')
                summary = runner.summary()
                require(set(summary['integrity']['problems']) == expected
                        and len(summary['integrity']['problems']) == len(expected)
                        and summary['actual']['pass'] == len(selection)
                        and summary['actual']['fail'] == summary['actual']['blocked'] == 0
                        and summary['passed'] == (not expected), 'original summary credit/integrity differs')
                passed = True
        context.revalidate()
        for row in mapper.records.values():
            checked_record({'path':row['source_path'],'size':row['size'],'sha256':row['sha256']})
            checked_record({'path':row['target'],'size':row['size'],'sha256':row['sha256']})
        require(file_sha256(mapper.path)==mapper.sha256, 'authority changed after audit')
        qualify_sources(context,entry,guard)
        modules = loaded_sources(context,qualified)
        return {'schema':'fakenetng.formal-runtime.original-source-audit.v1','passed':passed,
                'scope':scope,'selected':selection,'verify':verify,'replay':replay,'summary':summary,
                'authority':str(mapper.path),'authority_sha256':mapper.sha256,'proof_rebuilds':mapper.count,
                'source_qualification':qualified,'initial_modules':initial_modules,'actual_modules':modules,
                'trace':guard.trace+mapper.guard.trace,'adapter_restored':True,'VM_calls':0,
                'new_formal_credit':0,'full_100_pass':bool(verify and verify['passed'])}
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            if context.audit_root.exists():
                save(context.audit_root/'audit-terminal.json',{'passed':passed and failure is None,
                    'error':repr(failure) if failure else None,'traceback':traceback.format_exc() if failure else None,
                    'verify':verify,'replay':replay,'summary':summary,'source_qualification':qualified,
                    'initial_modules':initial_modules,'adapter_restored':not bool(mapper and mapper.guard.active),
                    'terminal_module_paths': [{'module':name,'path':str(getattr(module,'__file__'))}
                        for name,module in sorted(sys.modules.copy().items()) if getattr(module,'__file__',None)],
                    'VM_calls':0,'new_formal_credit':0,'host_audit_writers_ended':True})
        except BaseException as secondary:
            if failure: failure.add_note('independent audit terminal failed: '+repr(secondary))
            else: raise
        finally:
            guard.active = False
