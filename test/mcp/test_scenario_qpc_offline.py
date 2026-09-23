"""Small offline export checks; no developer Logs or Windows runtime required."""
import importlib.util
import json
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).parent / 'acceptance'
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('scenario_qpc_offline',
                                               HERE / 'scenario_qpc_offline.py')
offline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(offline)


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + '\n', encoding='utf-8')


def _export_fixture(tmp_path):
    export = tmp_path / 'export'
    output = tmp_path / 'output'
    output.mkdir()
    etl = tmp_path / 'pktmon.etl'
    etl.write_bytes(b'one small immutable ETL identity')
    raw_row = dict(seq=0, timestamp=101, provider='tcpip',
                   id=1033, userdata_base64='AA==')
    raw_row['pass'] = 'raw'
    default_row = dict(raw_row, timestamp=202, **{'pass': 'default'})
    _write(export / 'raw/raw.jsonl', raw_row)
    _write(export / 'raw/default.jsonl', default_row)
    pairing = offline.raw.pair_streams(export / 'raw/raw.jsonl',
        export / 'raw/default.jsonl', export / 'raw/paired.jsonl')
    header = dict(ReservedFlags=1, EventsLost=0, BuffersLost=0)
    passes = [dict(mode=mode, events=1, process_trace_return=0,
                   close_trace_return=0, events_lost_output=0, header=header)
              for mode in ('raw', 'default')]
    etl_hash = offline.raw.sha_file(etl)
    _write(export / 'raw/manifest.json', dict(schema=offline.raw.SCHEMA,
        status='COMPLETE_DIAGNOSTIC_ONLY', error=None, host={'system': 'Windows'},
        input_before=etl_hash, input_after=etl_hash, passes=passes,
        paired_events=1, pairing=pairing))
    selector = dict(seq=0)
    _write(export / 'selectors.json', dict(schema='fakenet.t007-r02-tdh-selectors.v1',
        source_event_count=1, source_etl_sha256=etl_hash['sha256'],
        selectors=[selector]))
    hashes = {'etl': etl_hash, 'selectors': offline.raw.sha_file(export / 'selectors.json')}
    _write(export / 'tdh/manifest.json', dict(schema='fakenet.t007-r02-tdh-metadata.v1',
        status='COMPLETE_DIAGNOSTIC_ONLY', error=None, input_before=hashes,
        input_after=hashes, source_event_count=1, observed_count=1, target_count=1,
        target_records=1, tdh_success_count=1, property_failure_count=0,
        api=dict(process_trace_return=0, close_trace_return=0, header=header)))
    return export, etl, output, selector


def test_offline_raw_repair_and_selector_integrity(tmp_path):
    export, etl, output, selector = _export_fixture(tmp_path)
    source, header = offline.verify_export(export, etl, output)
    assert source['selectors'] == [selector]
    assert header['ReservedFlags'] == 1
    paired = export / 'raw/paired.jsonl'
    row = json.loads(paired.read_text())
    row['raw_timestamp'] += 1
    _write(paired, row)
    with pytest.raises(offline.raw.DiagnosticError, match='paired row changed'):
        offline.verify_export(export, etl, output)


def test_offline_changed_etl_failed_tdh_and_omitted_row_rejected(tmp_path):
    export, etl, output, selector = _export_fixture(tmp_path)
    etl.write_bytes(b'changed')
    with pytest.raises(offline.raw.DiagnosticError, match='raw two-pass manifest'):
        offline.verify_export(export, etl, output)
    etl.write_bytes(b'one small immutable ETL identity')
    path = export / 'tdh/manifest.json'
    manifest = json.loads(path.read_text())
    manifest['status'] = 'FAILED'
    _write(path, manifest)
    with pytest.raises(offline.raw.DiagnosticError, match='TDH manifest'):
        offline.verify_export(export, etl, output)
    with pytest.raises(offline.raw.DiagnosticError, match='row count incomplete'):
        offline.verify_tdh_rows([], [selector])
