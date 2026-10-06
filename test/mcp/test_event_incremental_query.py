# Copyright 2026 Google LLC
"""Incremental event queries: epochs, seq, opaque cursors, retention gaps.

Pure-function coverage over real EventLog windows plus coordinator-level
read-only guarantees: pages never duplicate or skip, run-filtered empty
pages still advance, rebuilt logs reset instead of claiming continuity,
invalid/future cursors are rejected, and concurrent recording never tears
a snapshot or duplicates a seq.
"""

import threading

import pytest

from fakenet.mcp import queries
from fakenet.mcp import tools as tools_module
from fakenet.mcp.coordination import Coordinator, EventLog
from fakenet.mcp.errors import McpError
from fakenet.mcp.testdouble import LifecycleDouble

RUN_A = '11111111-aaaa-4bbb-8ccc-000000000001'
RUN_B = '22222222-aaaa-4bbb-8ccc-000000000002'


def fill(log, count, run_id=None, prefix='e'):
    for index in range(count):
        log.record('%s-%d' % (prefix, index),
                   **({'run_id': run_id} if run_id else {}))


def page(log, *, limit=100, cursor=None, run_id=None):
    epoch, entries, oldest, latest = log.window()
    return queries.events_page(entries, epoch, oldest, latest,
                               limit=limit, cursor_token=cursor,
                               run_id=run_id)


def test_entries_carry_epoch_and_strictly_increasing_seq():
    log = EventLog(limit=500)
    fill(log, 25)
    entries = log.snapshot()
    assert all(entry['epoch'] == log.epoch for entry in entries)
    assert [entry['seq'] for entry in entries] == list(range(1, 26))
    assert entries[0]['kind'] == 'e-0' and entries[0]['timestamp'] > 0


def test_initial_page_returns_recent_matches_with_tail_cursor():
    log = EventLog(limit=500)
    fill(log, 30)
    result = page(log, limit=10)
    assert [entry['seq'] for entry in result['events']] == list(range(21, 31))
    # The tail cursor has nothing ahead; older events remain observable
    # through oldest_seq, not through a backward cursor.
    assert result['has_more'] is False
    assert result['gap'] is False and result['reset_required'] is False
    assert result['oldest_seq'] == 1 and result['latest_seq'] == 30
    epoch, next_seq = queries.decode_cursor(result['next_cursor'])
    assert epoch == log.epoch and next_seq == 30


def test_incremental_pages_cover_everything_exactly_once():
    log = EventLog(limit=500)
    fill(log, 45)
    first = page(log, limit=10)
    # The cursor only walks forward: an initial page is the recent tail and
    # reports nothing ahead of the tail cursor.
    assert [entry['seq'] for entry in first['events']] == list(range(36, 46))
    assert first['has_more'] is False
    # Paging forward from a mid-history cursor returns everything after it,
    # ascending, with no duplicates and no omissions.
    start = queries.encode_cursor(log.epoch, 10)
    collected = []
    cursor = start
    has_more = True
    guard = 0
    while has_more:
        guard += 1
        assert guard < 20, 'pagination did not converge'
        result = page(log, limit=7, cursor=cursor)
        seqs = [entry['seq'] for entry in result['events']]
        assert seqs == sorted(seqs)
        assert all(seq > (collected[-1] if collected else 10) for seq in seqs)
        collected.extend(seqs)
        cursor = result['next_cursor']
        has_more = result['has_more']
        assert result['gap'] is False and result['reset_required'] is False
    assert collected == list(range(11, 46))
    settled = page(log, cursor=cursor)
    assert settled['events'] == [] and settled['has_more'] is False


def test_retention_gap_reported_with_retained_portion():
    log = EventLog(limit=5)
    fill(log, 20)  # retained: seq 16..20
    stale = queries.encode_cursor(log.epoch, 3)
    result = page(log, limit=2, cursor=stale)
    assert result['gap'] is True
    assert result['reset_required'] is False
    assert result['oldest_seq'] == 16 and result['latest_seq'] == 20
    assert [entry['seq'] for entry in result['events']] == [19, 20]
    _, next_seq = queries.decode_cursor(result['next_cursor'])
    assert next_seq == 20


def test_rebuilt_log_resets_epoch_instead_of_continuity():
    old_log = EventLog(limit=500)
    fill(old_log, 10)
    stale = old_log.snapshot()[3]  # seq 4
    cursor = queries.encode_cursor(stale['epoch'], stale['seq'])
    new_log = EventLog(limit=500)
    fill(new_log, 3)
    result = page(new_log, limit=2, cursor=cursor)
    assert result['reset_required'] is True
    assert result['gap'] is False
    assert [entry['seq'] for entry in result['events']] == [2, 3]
    assert result['epoch'] == new_log.epoch
    _, next_seq = queries.decode_cursor(result['next_cursor'])
    assert next_seq == 3


def test_run_filter_matches_own_field_and_empty_pages_advance():
    log = EventLog(limit=500)
    for index in range(6):
        log.record('a-%d' % index, run_id=RUN_A)
        log.record('b-%d' % index, run_id=RUN_B)
    log.record('no-run-field')
    # Only the event's own run_id field decides membership.
    all_a = page(log, run_id=RUN_A)
    assert [entry['kind'] for entry in all_a['events']] == \
        ['a-%d' % index for index in range(6)]
    assert all(entry.get('run_id') == RUN_A for entry in all_a['events'])

    # Initial filtered page: the recent matches with a tail cursor. The
    # cursor walks forward only, so older run_a events are not re-pageable;
    # they remain observable through oldest_seq of the window itself.
    first = page(log, limit=2, run_id=RUN_A)
    assert [entry['kind'] for entry in first['events']] == ['a-4', 'a-5']
    assert first['has_more'] is False  # the scan itself reached the tail
    cursor = first['next_cursor']

    # New run_a events arrive after run_b noise: incremental pages return
    # exactly them, skipping the interleaved run_b entries.
    log.record('b-new', run_id=RUN_B)
    log.record('a-new', run_id=RUN_A)
    result = page(log, cursor=cursor, run_id=RUN_A)
    assert [entry['kind'] for entry in result['events']] == ['a-new']
    cursor = result['next_cursor']

    # An empty page still advances past another run's new events.
    before = queries.decode_cursor(cursor)[1]
    log.record('b-newer', run_id=RUN_B)
    empty = page(log, cursor=cursor, run_id=RUN_A)
    assert empty['events'] == []
    after = queries.decode_cursor(empty['next_cursor'])[1]
    assert after > before  # no empty-page loop: the cursor moved on


def test_invalid_and_future_cursors_rejected():
    log = EventLog(limit=500)
    fill(log, 5)
    for bad in ('garbage', 'fnev1.!!!', 'fnev1', 'ev1.abc'):
        with pytest.raises(queries.InvalidCursor):
            page(log, cursor=bad)
    # Malformed payloads under a valid prefix are rejected at decode time;
    # the encoder refuses to produce them at all.
    import base64 as _base64
    for payload in ({'v': 1, 'epoch': log.epoch, 'seq': 0},
                    {'v': 1, 'epoch': '', 'seq': 1},
                    {'v': 2, 'epoch': log.epoch, 'seq': 1},
                    {'epoch': log.epoch, 'seq': 1}):
        body = _base64.urlsafe_b64encode(
            __import__('json').dumps(payload).encode()).decode().rstrip('=')
        with pytest.raises(queries.InvalidCursor):
            page(log, cursor=queries.CURSOR_PREFIX + body)
    future = queries.encode_cursor(log.epoch, 99)
    with pytest.raises(queries.InvalidCursor, match='beyond the current tail'):
        page(log, cursor=future)
    # Equal to the tail is valid (settled page); only beyond is rejected.
    tail = queries.encode_cursor(log.epoch, 5)
    assert page(log, cursor=tail)['events'] == []


def test_concurrent_record_and_read_never_tear_or_duplicate():
    log = EventLog(limit=500)
    stop = threading.Event()

    def recorder(offset):
        index = 0
        while not stop.is_set():
            log.record('thread-%d-%d' % (offset, index))
            index += 1

    threads = [threading.Thread(target=recorder, args=(offset,), daemon=True)
               for offset in range(4)]
    for thread in threads:
        thread.start()
    try:
        for _ in range(50):
            _, entries, oldest, latest = log.window()
            seqs = [entry['seq'] for entry in entries]
            assert seqs == sorted(seqs)
            assert len(set(seqs)) == len(seqs)
            assert oldest == seqs[0] and latest == seqs[-1]
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=5)
    final = log.snapshot()
    seqs = [entry['seq'] for entry in final]
    assert seqs == list(range(seqs[0], seqs[-1] + 1))
    # The retained window holds only the newest entries.
    assert len(final) == 500 and seqs[0] > 1


def test_coordinator_reads_do_not_bump_state_version():
    coordinator = Coordinator(LifecycleDouble())
    # A real accepted mutation produces events to read.
    coordinator.submit(
        command_id='q-events', expected_version=1, controller='A',
        controller_valid=True, kind='edit', describe={},
        execute=lambda coord: {'state': coord.snapshot()['state'],
                               'changed': True})
    before = coordinator.snapshot()['state_version']
    for _ in range(5):
        epoch, entries, oldest, latest = coordinator.events_window()
        assert epoch and entries and oldest is not None
    assert coordinator.events(5)
    after = coordinator.snapshot()['state_version']
    assert before == after


def test_cursor_roundtrip_rejects_malformed_payloads():
    token = queries.encode_cursor('abc123', 7)
    assert queries.decode_cursor(token) == ('abc123', 7)
    for bad_epoch, bad_seq in ((None, 7), ('abc', '7'), ('abc', True),
                               ('abc', 0), ('abc', -3)):
        with pytest.raises(ValueError):
            queries.encode_cursor(bad_epoch, bad_seq)


def test_run_id_validation_shared_for_event_queries():
    assert tools_module._validated_run_id(None) is None
    with pytest.raises(McpError):
        tools_module._validated_run_id('run/../x')
