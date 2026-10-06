# Copyright 2026 Google LLC
"""Read-only query helpers: opaque event cursors and incremental pages.

These functions are pure over an EventLog window snapshot (epoch, entries,
oldest_seq, latest_seq); the caller takes that snapshot under the event
log's own lock, so record and read stay mutually consistent. Nothing here
mutates coordinator state, state_version, controller or commands.

Cursor contract (fakenet.query.cursor.v1):

* a cursor is an opaque token encoding the epoch and the last scanned seq
  (0 is the seq floor of an epoch, so even an empty log yields a usable
  epoch/0 starting cursor); callers never assemble or parse it themselves;
* without a cursor the page is the most recent ``limit`` matching entries
  and the returned cursor marks the current tail (matched or not; an empty
  log marks the epoch/0 floor, never null);
* with a cursor the page is the entries after it, ascending, bounded by
  ``limit``; entries skipped by a run filter still advance the scan so an
  empty page cannot loop forever;
* a cursor older than the retention window yields ``gap=true`` and the
  retained portion; an epoch change yields ``reset_required=true`` — never
  a claim of continuity;
* an unparsable cursor or a seq beyond the tail is rejected, never treated
  as an initial query.
"""

import base64
import json

CURSOR_PREFIX = 'fnev1.'


class InvalidCursor(ValueError):
    """Raised for unparsable cursors; callers map it to a structured error."""


def encode_cursor(epoch, seq):
    if not isinstance(epoch, str) or not epoch:
        raise ValueError('cursor epoch must be a non-empty string')
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise ValueError('cursor seq must be a non-negative integer')
    raw = json.dumps({'v': 1, 'epoch': epoch, 'seq': seq},
                     separators=(',', ':')).encode('utf-8')
    padded = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
    return CURSOR_PREFIX + padded


def decode_cursor(token):
    if not isinstance(token, str) or not token.startswith(CURSOR_PREFIX):
        raise InvalidCursor('cursor must be an opaque event token')
    body = token[len(CURSOR_PREFIX):]
    try:
        raw = base64.urlsafe_b64decode(body + '=' * (-len(body) % 4))
        payload = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError) as exc:
        raise InvalidCursor('cursor is not a decodable token') from exc
    if not isinstance(payload, dict) or payload.get('v') != 1:
        raise InvalidCursor('cursor version is not supported')
    epoch = payload.get('epoch')
    seq = payload.get('seq')
    if not isinstance(epoch, str) or not epoch:
        raise InvalidCursor('cursor epoch is malformed')
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise InvalidCursor('cursor seq is malformed')
    return epoch, seq


def _matches(entry, run_id):
    # Only the event's own run_id field decides; events without one never
    # match a specific run (no ownership guessing).
    return run_id is None or entry.get('run_id') == run_id


def events_page(entries, epoch, oldest_seq, latest_seq, *,
                limit, cursor_token=None, run_id=None):
    """Compute one incremental event page over a consistent window snapshot.

    ``entries`` is the ascending seq-ordered snapshot of the retained log;
    ``epoch``/``oldest_seq``/``latest_seq`` describe that same snapshot
    (latest_seq=0 means nothing is retained in this epoch). Returns the
    response fields for get_events (events plus the cursor bookkeeping);
    never mutates anything.

    Same-epoch cursors resume with every retained entry after the cursor:
    a cursor below the window resumes from the earliest retained match, so
    paging always covers the retained window without duplicates or drops.
    ``gap`` is reported only when retention provably dropped entries after
    the cursor (cursor_seq < oldest_seq - 1). An epoch change reports
    ``reset_required`` and likewise resumes from the earliest retained
    match of the new epoch.
    """
    if limit is None or limit < 1:
        limit = 100
    reset_required = False
    gap = False
    if cursor_token is not None:
        cursor_epoch, cursor_seq = decode_cursor(cursor_token)
        if cursor_epoch != epoch:
            # The log was rebuilt: continuity cannot be claimed. Resume
            # from the earliest retained match of the new epoch so paging
            # covers the retained window; the returned cursor then walks
            # forward normally within this epoch.
            reset_required = True
            matched = [entry for entry in entries if _matches(entry, run_id)]
            page = matched[:limit]
            has_more = len(matched) > limit
            next_seq = (page[-1]['seq'] if page
                        else (latest_seq if latest_seq is not None else 0))
            return _page_response(page, epoch, oldest_seq, latest_seq,
                                  next_seq, has_more, gap, reset_required)
        if latest_seq is not None and cursor_seq > latest_seq:
            raise InvalidCursor('cursor seq is beyond the current tail')
        # Retention provably dropped entries after the cursor only when the
        # oldest retained seq is not the cursor's immediate successor.
        gap = oldest_seq is not None and cursor_seq < oldest_seq - 1
        # Resume scan: everything after the cursor, in seq order, first
        # ``limit`` matches. A cursor below the window naturally resumes
        # from the earliest retained entry; entries skipped by a run filter
        # still advance the scan so unmatched pages never loop.
        matched = [entry for entry in entries
                   if entry['seq'] > cursor_seq and _matches(entry, run_id)]
        page = matched[:limit]
        if len(matched) > limit:
            next_seq = page[-1]['seq']
            has_more = True
        else:
            next_seq = latest_seq if latest_seq is not None else cursor_seq
            has_more = False
        return _page_response(page, epoch, oldest_seq, latest_seq,
                              next_seq, has_more, gap, reset_required)
    # Initial page (no cursor, epoch reset, or retention gap): the most
    # recent ``limit`` matches, ascending, cursor at the current tail. The
    # cursor only walks forward, so a tail cursor has nothing more ahead;
    # events older than this page stay observable through oldest_seq. An
    # empty log reports the epoch/0 floor so the incremental start exists
    # before the first event is ever recorded.
    matched = [entry for entry in entries if _matches(entry, run_id)]
    page = matched[-limit:] if limit else matched
    has_more = False
    next_seq = latest_seq if latest_seq is not None else 0
    return _page_response(page, epoch, oldest_seq, latest_seq, next_seq,
                          has_more, gap, reset_required)


def _page_response(page, epoch, oldest_seq, latest_seq, next_seq, has_more,
                   gap, reset_required):
    return {
        'events': page,
        'epoch': epoch,
        'next_cursor': (encode_cursor(epoch, next_seq)
                        if next_seq is not None else None),
        'has_more': has_more,
        'gap': gap,
        'reset_required': reset_required,
        'oldest_seq': oldest_seq,
        'latest_seq': latest_seq,
    }
