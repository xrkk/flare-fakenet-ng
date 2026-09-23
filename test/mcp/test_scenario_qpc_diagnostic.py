"""Synthetic exact native target matching; no developer-machine Logs input."""
import base64
import importlib.util
import json
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).parent / 'acceptance'
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('scenario_qpc_diagnostic',
                                               HERE / 'scenario_qpc_diagnostic.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def event(kind, terminal, offset):
    return {'kind': kind, 'terminal': terminal, 'tcb': '0X1234',
            'text': f'x::2026-09-23 15:23:52.{offset:09d}',
            'ref': {'path': 'pktmon.txt', 'byte_start': offset,
                    'byte_end': offset + 1, 'event_key': 'text'}}


def pair_row(e, seq, payload=None):
    stamp = module.raw_clock.pktmon_filetime(e['text'].split('::')[1] + '+08:00')
    raw = payload if payload is not None else b'x' + (0x1234).to_bytes(8, 'little')
    return dict(seq=seq, default_filetime_100ns=stamp,
                provider=module.TCPIP_PROVIDER, identity_occurrences=1,
                userdata_base64=base64.b64encode(raw).decode(),
                raw_timestamp=1000 + seq, id=1033 + seq, version=1,
                opcode=0, task=1033 + seq, userdata_sha256='sha' + str(seq),
                identity_sha256='identity' + str(seq), binding_status='unique')


def observed_and_paired(tmp_path):
    connect, terminal = event('connect completed', False, 100), event('connection terminated', True, 200)
    observed = dict(events=[connect, terminal], connect=connect, peer=None,
                    termination=[terminal], tuple_terminals=[])
    paired = tmp_path / 'paired.jsonl'
    rows = [pair_row(connect, 0), pair_row(terminal, 1)]
    paired.write_text(''.join(json.dumps(x) + '\n' for x in rows))
    return observed, paired, rows


def test_full_terminal_set_selected(tmp_path):
    observed, paired, _ = observed_and_paired(tmp_path)
    targets, selectors = module.choose_targets(observed, paired)
    assert [x['kind'] for x in targets] == ['connect completed', 'connection terminated']
    assert [x['seq'] for x in selectors] == [0, 1]


def test_duplicate_or_missing_terminal_never_counts_complete(tmp_path):
    observed, paired, rows = observed_and_paired(tmp_path)
    paired.write_text(''.join(json.dumps(x) + '\n' for x in rows + [dict(rows[1], seq=2)]))
    with pytest.raises(module.raw_clock.DiagnosticError, match='ambiguous'):
        module.choose_targets(observed, paired)
    paired.write_text(json.dumps(rows[0]) + '\n')
    with pytest.raises(module.raw_clock.DiagnosticError, match='missing'):
        module.choose_targets(observed, paired)


def test_payload_change_cannot_match_selected_tcb(tmp_path):
    observed, paired, rows = observed_and_paired(tmp_path)
    rows[1] = pair_row(observed['termination'][0], 1, b'not-the-selected-tcb')
    paired.write_text(''.join(json.dumps(x) + '\n' for x in rows))
    with pytest.raises(module.raw_clock.DiagnosticError, match='missing'):
        module.choose_targets(observed, paired)


def test_tdh_wrong_tcb_rejected():
    target = dict(kind='connect completed', tcb='0X1234', local=None, remote=None,
                  pktmon_ref={'path': 'pktmon.txt', 'byte_start': 1})
    def prop(name, raw):
        return dict(name=name, size_status=0, property_status=0,
                    raw_base64=base64.b64encode(raw).decode())
    record = dict(selector=dict(pktmon_ref=target['pktmon_ref'], tcb='0X1234',
                                target_kind='connect completed'),
                  property_results=[prop('Tcb', (0x1234).to_bytes(8, 'little')),
                                    prop('ProcessId', (1572).to_bytes(4, 'little')),
                                    prop('ProcessStartKey', (1).to_bytes(8, 'little'))])
    assert module.validate_tdh_semantics([record], [target], '0X1234', None, 1572, 8024)['target_count'] == 1
    record['property_results'][0] = prop('Tcb', (0x5678).to_bytes(8, 'little'))
    with pytest.raises(module.raw_clock.DiagnosticError, match='Tcb'):
        module.validate_tdh_semantics([record], [target], '0X1234', None, 1572, 8024)
