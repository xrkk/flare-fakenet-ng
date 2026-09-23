"""Offline guardrails for the unverified auxiliary zero-TCB collector."""
import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_aux_qpc_diagnostic as aux  # noqa: E402


def ref(index):
    return {'path': 'pktmon.txt', 'byte_start': index,
            'byte_end': index + 1, 'event_key': 'text'}


def order_case(connect=100, peer=105, zeros=(106, 107)):
    events = [dict(pktmon_ref=ref(1)), dict(pktmon_ref=ref(2))]
    events += [dict(pktmon_ref=ref(10 + index)) for index in range(len(zeros))]
    selectors = [dict(raw_qpc=value) for value in (connect, peer, *zeros)]
    observed = {'connect': {'ref': ref(1)}, 'peer': {'ref': ref(2)},
                'tuple_terminals': [{'ref': ref(10 + index)}
                                    for index in range(len(zeros))]}
    return observed, events, selectors


@pytest.mark.parametrize('zeros,expected', [((107, 108), True),
                                             ((106, 108), False),
                                             ((105, 108), False),
                                             ((104, 108), False),
                                             ((), False)])
def test_raw_order_is_diagnostic_only_and_requires_every_zero_tcb(zeros, expected):
    observed, targets, selectors = order_case(zeros=zeros)
    result = aux.diagnostic_order(observed, targets, selectors)
    assert result['status'] == 'UNVERIFIED_TDH_SEMANTICS'
    assert result['all_strictly_later_than_one_tick'] is expected
    assert len(result['gaps_ticks']) == len(zeros)


def test_missing_zero_tcb_selector_is_not_an_order_result():
    observed, targets, selectors = order_case()
    targets.pop()
    selectors.pop()
    with pytest.raises(aux.raw_clock.DiagnosticError, match='zero-TCB target omitted'):
        aux.diagnostic_order(observed, targets, selectors)


def test_duplicate_case_identity_fails_before_windows_export(tmp_path, monkeypatch):
    source = tmp_path / 'input.json'
    data = {'schema': 'sst.aux-qpc-input.v1', 'cases': [
        {'case_index': 2, 'connection_id': 'c'},
        {'case_index': 2, 'connection_id': 'c'}]}
    source.write_text(json.dumps(data), encoding='utf-8')
    monkeypatch.setattr(aux.raw_clock, 'export', lambda *_: pytest.fail('Windows export reached'))
    result = aux.run(source, tmp_path, tmp_path / 'out')
    assert result['status'] == 'INCOMPLETE'
    assert 'duplicate auxiliary case identity' in result['error']['message']
    assert result['inputs_before'] == result['inputs_after']
    assert list(result['inputs_before']) == [str(source)]


def test_auxiliary_identity_requires_matching_boot_frequency_and_capture_brackets():
    from test_scenario_qpc_identity import evidence
    args = evidence()
    capture, ready, child, established, _action, header, candidate, managed_run, pid, created = args
    capture['clock_before'].update(q0=1, q1=2)
    capture['clock_after'].update(q0=3, q1=4)
    result = aux.check_aux_provenance(capture, ready, child, established,
                                      header, candidate, managed_run, pid, created)
    assert result['qpc_frequency'] == 10_000_000
    wrong = copy.deepcopy(capture)
    wrong['native_identity_after']['qpc_frequency'] = 9
    with pytest.raises(aux.check_aux_provenance.__globals__['DiagnosticIdentityError']):
        aux.check_aux_provenance(wrong, ready, child, established,
                                 header, candidate, managed_run, pid, created)
