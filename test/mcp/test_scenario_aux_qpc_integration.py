"""Auxiliary native collection through the real TCPIP parser and run graph."""
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_suite as suite  # noqa: E402
import scenario_tcpip as tcpip  # noqa: E402
import scenario_aux_qpc_offline as aux_offline  # noqa: E402
from test_sst_tcpip_events import capture, flow, ipc_rows  # noqa: E402


def test_auxiliary_builder_parses_bytes_and_seals_exact_run_case(tmp_path, monkeypatch):
    runner = suite.Suite.__new__(suite.Suite)
    runner.root = tmp_path
    runner.identity = SimpleNamespace(candidate_id='candidate-test')
    attempt = tmp_path / 'evidence' / 'sst-001' / 'attempt-01'
    attempt.mkdir(parents=True)
    src, dst = '192.168.204.233:16633', '119.188.175.46:443'
    rows = [dict(event='ready', nonce='n', pid=7948),
            dict(event='case_established', nonce='n', pid=7948, case_index=2,
                 connection_id='case-2', src=src, actual_dst=dst),
            dict(event='case_close', nonce='n', pid=7948, connection_id='case-2')]
    values = {'probe.jsonl': ''.join(json.dumps(row) + '\n' for row in rows).encode(),
              'pktmon.txt': capture(), 'pktmon.etl': b'fixture ETL',
              'pktmon-nic.json': b'{}\n', 'run.log': flow().encode(),
              'ipc-parent.jsonl': ''.join(json.dumps(row) + '\n'
                                          for row in ipc_rows()).encode()}
    for name, data in values.items():
        (tmp_path / name).write_bytes(data)
    records = {name: suite.file_record(tmp_path / name, tmp_path) for name in values}
    run = {'run_id': 'r', 'label': 'run-01',
           'capture': {'files': [records[name] for name in
                                 ('probe.jsonl', 'pktmon.txt', 'pktmon.etl', 'pktmon-nic.json')]},
           'originals': {'files': [records[name] for name in
                                   ('run.log', 'ipc-parent.jsonl')]}}
    original_parser = tcpip.connection_events
    calls = []
    def parser(raw, *args, **kwargs):
        assert isinstance(raw, bytes)
        result = original_parser(raw, *args, **kwargs)
        calls.append(result)
        return result
    monkeypatch.setattr(tcpip, 'connection_events', parser)
    def fake_export(base_path, descriptor, native_root, evidence, run_id, program):
        assert program == 'scenario_aux_qpc_diagnostic.py' and run_id == 'r'
        assert json.loads(base_path.read_text()) == descriptor
        assert len(descriptor['cases']) == 1
        item = descriptor['cases'][0]
        assert item['connection_refs'] == [x['ref'] for x in calls[0]['events']]
        assert item['generation_manifest'] == calls[0]['generation_manifest']
        assert item['probe_ref']['path'] == 'probe.jsonl'
        assert item['end_refs'][0]['path'] == 'probe.jsonl'
        assert item['case_index'] == 2 and item['connection_id'] == 'case-2'
        assert len(descriptor['files']) == len(values)
        terminal = native_root / 'qpc-process-terminal.json'
        suite.write_new_json(terminal, {'exit_proven': True})
        evidence.add(terminal)
    runner._collect_qpc_export = fake_export
    def fake_derive(case_path, evidence_root, export, output):
        assert case_path.name == 'auxiliary-qpc-input.json'
        assert evidence_root == tmp_path and export.name == 'export'
        output.mkdir()
        suite.write_new_json(output / 'derived.json', {'status': 'COMPLETE_FORMAL_INPUT'})
    monkeypatch.setattr(aux_offline, 'derive', fake_derive)
    evidence = suite.Evidence(attempt)
    runner._collect_auxiliary_qpc(run, 'n', attempt, evidence)
    assert len(calls) == 1
    assert (attempt / 'run-01/auxiliary-qpc/auxiliary-qpc-input.json').is_file()
    assert run['auxiliary_qpc_process']['qpc-process-terminal.json']['sha256']
    assert run['auxiliary_qpc_proof']['sha256']


@pytest.mark.parametrize('terminal', [None, {'exit_proven': False},
                                            {'exit_proven': True, 'run_id': 'wrong'}])
def test_nested_auxiliary_process_responsibility_blocks_next_run(tmp_path, terminal):
    runner = suite.Suite.__new__(suite.Suite)
    runner.root = tmp_path
    runner.vm = object()
    native = tmp_path / 'evidence/sst-001/attempt-01/run-01/auxiliary-qpc'
    native.mkdir(parents=True)
    owner = {'run_id': 'r', 'guest_root': r'C:\guest\aux', 'input_sha256': 'a' * 64}
    suite.write_new_json(native / 'qpc-process-responsibility.json', owner)
    if terminal is not None:
        state = {'schema': 'sst.qpc-host-process-terminal.v1', **owner, **terminal}
        suite.write_new_json(native / 'qpc-process-terminal.json', state)
    with pytest.raises(suite.Blocked, match='responsibility remains unsettled|exit is unproven'):
        runner._continuation_gate()
