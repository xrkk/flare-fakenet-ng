"""Consume independently frozen preparation bytes, without installing auditing.

The caller supplies a separately frozen result SHA in addition to the unchanged
main material SHA. No neighbouring self-hash or result flag grants admission.
Live identity, instance and resource gates still remain mandatory.
"""
from dataclasses import dataclass
from pathlib import Path
import json
import re

from .context import checked_record, exact_path, file_sha256, read_json, _freeze
from .preparation import configuration_plan, execution_plan, audit_jobs, output_inventory, check_audit_copies
from .runner import require, check_preparation_inputs
from .runtime_sources import qualify, loaded_sources


@dataclass(frozen=True)
class PreparedExecution:
    context: object
    entry: Path
    receipt: object
    result: object

    def revalidate(self):
        return load_preparation(self.context, Path(self.receipt['path']), self.receipt['sha256'], self.entry)


def load_preparation(context, path, expected_sha256, entry):
    context.revalidate()
    path = exact_path(str(path))
    require(isinstance(expected_sha256, str) and re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None,
            'independent preparation SHA256 is required')
    require(path == context.audit_root/'preparation-result.json'
            and path.is_file() and path.stat().st_size <= 4*2**20,
            'preparation receipt must be the exact owned regular result')
    require(file_sha256(path) == expected_sha256, 'independent preparation SHA256 mismatch')
    result = read_json(path)
    require(isinstance(result, dict) and result.get('schema') == 'fakenetng.formal-runtime.preparation.v1'
            and result.get('passed') is True and result.get('business_authorized') is False
            and type(result.get('VM_calls')) is int and result['VM_calls'] == 0
            and type(result.get('new_formal_credit')) is int and result['new_formal_credit'] == 0
            and result.get('live_instance_and_resource_admission_required') is True,
            'full preparation receipt failed or incomplete; no admission')
    require(result.get('materials_sha256') == context.materials_sha256,
            'preparation receipt belongs to different main material bytes')
    require(not context.evidence_root.exists(), 'prepared business output exists; no implicit retry')
    qualified = qualify(context, entry)
    loaded_sources(context, qualified)
    fresh_inputs = check_preparation_inputs(context, prepared_audit=True)
    original_inputs = result.get('inputs')
    require(isinstance(original_inputs, dict) and
            {key: value for key, value in original_inputs.items() if key != 'capacity'} ==
            {key: value for key, value in fresh_inputs.items() if key != 'capacity'},
            'preparation original input verdict differs from rechecked frozen inputs')
    require(result.get('execution_plan') == execution_plan(context),
            'prepared physical execution plan differs')

    def owned(record, expected):
        require(isinstance(record, dict) and record.get('path') == str(expected),
                'preparation output reference differs from exact owned path')
        return checked_record(record)

    config = read_json(owned(result.get('configuration_plan'), context.audit_root/'configuration-plan.json'))
    require(json.dumps(config, sort_keys=True) == json.dumps(configuration_plan(context), sort_keys=True),
            'prepared original configuration plan differs')
    source_map = read_json(owned(result.get('source_map'), context.audit_root/'source-map.json'))
    require(source_map.get('sources') == qualified, 'prepared source map differs from actual qualified sources')
    jobs = audit_jobs(context, require_unused=False)
    rows = result.get('audits')
    require(isinstance(rows, list) and len(rows) == len(jobs) == 2,
            'prepared independent original audits missing')
    terminal = read_json(context.audit_root/'preparation-terminal.json')
    require(terminal.get('passed') is True and terminal.get('error') is None
            and terminal.get('materials_sha256') == context.materials_sha256
            and terminal.get('audits') == rows and terminal.get('host_audit_processes_waited') is True,
            'preparation terminal/writer closure differs')
    for row, (job, child) in zip(rows, jobs):
        prefix = context.audit_root/('prepare-'+job['scope'])
        require(isinstance(row, dict) and row.get('scope') == job['scope']
                and type(row.get('exit_code')) is int and row['exit_code'] == 0
                and row.get('audit_materials') == job['materials'] and row.get('selection') == job['selection'],
                'prepared audit completion/source identity differs')
        stdout = read_json(owned(row.get('stdout'), prefix.with_suffix('.stdout')))
        owned(row.get('stderr'), prefix.with_suffix('.stderr'))
        require(stdout == {'passed': True, 'scope': job['scope'], 'output': str(child.audit_root), 'new_formal_credit': 0},
                'prepared audit original CLI stdout differs')
        intent = read_json(owned(row.get('intent'), prefix.with_suffix('.intent.json')))
        require(intent.get('main_materials_sha256') == context.materials_sha256
                and intent.get('audit_materials_sha256') == child.materials_sha256,
                'prepared audit command material binding differs')
        command = intent.get('argv')
        require(isinstance(command, list) and len(command) == 13
                and isinstance(command[0], str) and bool(command[0])
                and command[1:] == ['-B', str(context.source_root/'test/mcp/acceptance/run_formal_source_audit.py'),
                    '--materials-json', str(child.materials_path), '--materials-sha256', child.materials_sha256,
                    '--selection-json', job['selection']['path'], '--scope', job['scope'],
                    '--repository-root', str(context.repository_root)],
                'prepared original audit executable/argv differs')
        completion = read_json(owned(row.get('completion'), prefix.with_suffix('.completion.json')))
        require(completion == {key: row[key] for key in ('scope', 'exit_code', 'stdout', 'stderr', 'audit_materials', 'selection')},
                'prepared actual audit completion differs')
        inventory = read_json(owned(row.get('output_index'), prefix.with_suffix('.output-index.json')))
        require(inventory.get('audit_root') == str(child.audit_root)
                and inventory.get('audit_materials_sha256') == child.materials_sha256
                and inventory.get('audit_process_waited') is True
                and inventory.get('files') == output_inventory(child.audit_root),
                'prepared audit proof/copy/output inventory changed')
        verdict = read_json(owned(row.get('result'), child.audit_root/'audit-result.json'))
        audit_terminal = read_json(owned(row.get('terminal'), child.audit_root/'audit-terminal.json'))
        require(verdict.get('passed') is True and verdict.get('scope') == job['scope']
                and verdict.get('selected') == read_json(checked_record(job['selection']))
                and verdict.get('adapter_restored') is True and verdict.get('VM_calls') == 0
                and verdict.get('new_formal_credit') == 0 and audit_terminal.get('passed') is True
                and audit_terminal.get('error') is None and audit_terminal.get('adapter_restored') is True
                and audit_terminal.get('host_audit_writers_ended') is True,
                'prepared original audit verdict/terminal incomplete')
        check_audit_copies(child, verdict)
    context.revalidate()
    require(file_sha256(path) == expected_sha256, 'preparation receipt changed during consumption')
    return PreparedExecution(context, exact_path(str(entry)), _freeze({'path': str(path),
        'size': path.stat().st_size, 'sha256': expected_sha256}), _freeze(result))
