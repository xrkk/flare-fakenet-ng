"""P05 must apply the same omission contract as archive verification."""
import ast
from pathlib import Path



def test_fault_manifest_accepts_both_existing_omissions(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parent / "acceptance"))
    from evidence_integrity import incident_entry_omission_allowed
    source = Path(__file__).parent / 'acceptance' / 'run_p05_release.py'
    node = next(n for n in ast.walk(ast.parse(source.read_text()))
                if isinstance(n, ast.FunctionDef) and n.name == 'manifest_acceptable')
    namespace = {'incident_entry_omission_allowed': incident_entry_omission_allowed}
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), 'exec'), namespace)
    skip = dict(item='userdump.dmp', result='skipped',
                failure_reason='no escalation condition', size=0, sha256=None)
    failed = dict(item='managed-exit.json', result='failed',
                  failure_reason='exit evidence incomplete')
    check = namespace['manifest_acceptable']
    assert check({'manifest': dict(complete=False, entries=[skip, failed])})
    for key, value in [('size', 1), ('sha256', 'bad'), ('failure_reason', 'timeout')]:
        assert not check({'manifest': dict(complete=False, entries=[dict(skip, **{key: value}), failed])})
    assert not incident_entry_omission_allowed(failed, fault_round=False)
    assert not incident_entry_omission_allowed(dict(failed, result='skipped'), fault_round=True)
