"""Seal owned host originals only after actual runtime writers have closed."""
from pathlib import Path
import stat

from .context import exact_path, read_json, checked_record
from .producer import file_record
from .command_transport import write_new_json
from .runner import require

INDEX_NAME = 'host-source-index.json'


def inventory(root):
    root = exact_path(str(root))
    rows = []
    for path in sorted(root.rglob('*')):
        path = exact_path(str(path))
        if path == root/INDEX_NAME:
            continue
        before = path.stat()
        require(stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode),
                'owned source contains a nonregular dependency')
        if stat.S_ISDIR(before.st_mode):
            continue
        record = file_record(path)
        after = path.stat()
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                'owned source changed while hashing')
        rows.append(dict(record, path=path.relative_to(root).as_posix()))
    return rows


def check_index(root, record):
    path = checked_record(record)
    require(path == root/INDEX_NAME, 'owned source index path differs')
    value = read_json(path)
    require(value.get('schema') == 'fakenetng.formal-runtime.host-source-index.v1'
            and value.get('root') == str(root) and value.get('rows') == inventory(root),
            'owned source file set/bytes changed after seal')
    return value


def seal(execution, handoff):
    from .execution import Execution
    from .current_source import CurrentAuthority
    from .dns_capture import Captures
    require(isinstance(execution, Execution), 'seal requires actual original execution object')
    context = execution.context.revalidate()
    root = context.evidence_root
    require(execution.runner.root == root and execution.coordinator.r is execution.runner,
            'seal requires exact current execution/coordinator')
    require(isinstance(execution.captures, Captures) and not execution.captures.owned
            and execution.captures.runner is execution.runner
            and execution.captures.context.materials_sha256 == context.materials_sha256,
            'seal requires actual closed host captures')
    require(execution.state is execution.runner.vm.state
            and execution.state is execution.coordinator.state
            and execution.state.safe and execution.state.admission_ready
            and not execution.coordinator.fault_restore_pending,
            'seal requires resolved native/restoration responsibility')
    require(execution.row_audits is not None and execution.row_audits.writers_ended
            and not execution.row_audits.errors
            and set(execution.row_audits.records) == set(execution.request.scenario_ids),
            'seal requires independently rejudged original rows and ended audit writers')
    require(handoff.get('original_primary_error') is None and not handoff.get('secondary_errors')
            and handoff.get('final_original_status') is not None
            and handoff.get('current_export', {}).get('passed') is True
            and handoff.get('original_batch_terminal', {}).get('passed') is True,
            'failed or incomplete original batch cannot be sealed for new credit')
    require(read_json(root/'batch-handoff.json') == handoff,
            'actual original handoff changed before seal')
    terminal = read_json(root/'source-originals/source-export-terminal.json')
    require(terminal.get('passed') is True and terminal.get('local_writers_ended') is True,
            'original source export terminal is not closed')
    require(not (root/INDEX_NAME).exists(), 'existing source index is not a retry')
    authority = CurrentAuthority(context, execution.runner.vm, execution.service)
    rows = inventory(root)
    CurrentAuthority(context, execution.runner.vm, execution.service)
    require(inventory(root) == rows, 'owned source changed before publication')
    write_new_json(root/INDEX_NAME, {
        'schema': 'fakenetng.formal-runtime.host-source-index.v1', 'root': str(root),
        'materials_sha256': context.materials_sha256, 'batch_id': execution.request.batch_id,
        'rows': rows, 'actual_transport_witnesses': authority.witnesses,
        'new_formal_credit': 0, 'independent_original_rejudge_required': True})
    record = file_record(root/INDEX_NAME)
    check_index(root, record)
    return record
