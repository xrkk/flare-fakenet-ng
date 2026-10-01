"""Exercise the real restart release statement at the capture-creation boundary."""
import ast
from pathlib import Path

import pytest


def release_statement():
    source = Path(__file__).parent / 'acceptance' / 'scenario_suite.py'
    tree = ast.parse(source.read_text(encoding='utf-8'))
    nodes = [node for node in ast.walk(tree)
             if isinstance(node, ast.Assign) and any(
                 isinstance(target, ast.Name) and target.id == 'engine_signal'
                 for target in node.targets)]
    assert len(nodes) == 1
    return compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                   str(source), 'exec')


class ReleaseSpy:
    def __init__(self):
        self.calls = []

    def _release_restart_engine(self, restarted, profile, capture):
        self.calls.append((restarted, profile, capture))
        return {'typed_signal': True}


def invoke(interleave, captures):
    spy = ReleaseSpy()
    values = dict(self=spy, interleave=interleave, captures=captures,
                  second_label='run-02', restarted={'state': 'healthy'},
                  runtime_profile={'bucket': 'B4', 'interleave': interleave})
    exec(release_statement(), values)
    return values['engine_signal'], spy.calls


def test_stop_window_restart_has_no_second_capture_until_first_is_closed():
    signal, calls = invoke('stop-window', {'run-01': {'pid': 10}})
    assert signal is None
    assert calls == []


def test_held_restart_still_releases_the_exact_second_capture():
    capture = {'pid': 20, 'engine_gate': {'nonce': 'bound'}}
    signal, calls = invoke('restart-window', {'run-02': capture})
    assert signal == {'typed_signal': True}
    assert len(calls) == 1 and calls[0][2] is capture


def test_other_missing_second_capture_is_not_silently_accepted():
    with pytest.raises(KeyError, match='run-02'):
        invoke('restart-window', {'run-01': {}})
