# Copyright 2026 Google LLC
"""Shared bracketed clock sampling and strict continuity-interval checks.

Sampling defect this closes (clock-audit-01 / codex-clock-01): the four
production clock samples read UTC and the monotonic counter as two unrelated
points without recording the delay between them, so a validator could only
compare two point values. The PowerShell helper here records a QPC bracket
around the UTC read: q0 -> DateTime.UtcNow.Ticks -> q1, with frequency and
timezone read OUTSIDE the bracket and ``mono`` as the exact integer midpoint
of the bracket. One warmup execution runs first and is kept as a diagnostic
field; the single official sample follows, with no retries and no picking.

Validation side, ``check_continuity`` keeps the old contract for old records
(both ends without bracket fields: the original point comparison, original
thresholds, original error messages). For bracketed records the whole
uncertainty interval of wall-minus-mono must fit inside the SAME resolution
budget: true monotonic elapsed lies in
[(after.q0 - before.q1)/freq, (after.q1 - before.q0)/freq], so the interval
is computed with exact integer rational arithmetic (floor/ceil, never
floats) and must be CONTAINED in [-resolution_ns, +resolution_ns]. A wider
bracket can only make a run fail, never pass. Mixed old/new ends, missing
fields, non-integer values, reversed brackets, midpoint mismatches and
frequency changes are rejected.
"""

CLOCK_SAMPLING_SCHEMA = 'sst.clock-sampling.v1'
CLOCK_SAMPLING_VERSION = 1

# Pure-PowerShell sampling helper embedded by all four capture sites. The
# bracket order is fixed: q0 -> utc -> q1; mono is the integer midpoint;
# frequency and timezone are read after the bracket closes; one warmup sample
# runs first and is preserved. Each snippet defines the function once and
# assigns the official record (plus warmup) to $<variable>.
_CLOCK_SAMPLE_PS = (
    "function __sstClock(){"
    "$q0=[Diagnostics.Stopwatch]::GetTimestamp();"
    "$u=[DateTime]::UtcNow.Ticks;"
    "$q1=[Diagnostics.Stopwatch]::GetTimestamp();"
    "@{utc_ticks=$u;q0=$q0;q1=$q1;mono=($q0+(($q1-$q0) -shr 1))}};"
    "$__sstWarm=& __sstClock;"
    "$__sstOff=& __sstClock;")


def clock_sample_ps(variable):
    """The shared snippet assigning a bracketed clock record to $variable."""
    return (_CLOCK_SAMPLE_PS + '$' + variable + "=@{schema='" + CLOCK_SAMPLING_SCHEMA +
            "';version=" + str(CLOCK_SAMPLING_VERSION) + ";utc_ticks=$__sstOff.utc_ticks;"
            'q0=$__sstOff.q0;q1=$__sstOff.q1;mono=$__sstOff.mono;'
            'stopwatch_frequency=[Diagnostics.Stopwatch]::Frequency;'
            'offset_minutes=[int][TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now).TotalMinutes;'
            'warmup=$__sstWarm};')


def _strict_int(value):
    """True only for genuine ints: bool is an int subclass and is rejected."""
    return isinstance(value, int) and not isinstance(value, bool)


def is_bracketed(clock):
    """True when the record carries the new schema with complete brackets."""
    return (isinstance(clock, dict)
            and clock.get('schema') == CLOCK_SAMPLING_SCHEMA
            and _strict_int(clock.get('version'))
            and clock.get('version') == CLOCK_SAMPLING_VERSION
            and all(_strict_int(clock.get(key)) for key in ('utc_ticks', 'q0', 'q1', 'mono')))


def _require_clock_domain(before, after, error):
    freq = before.get('stopwatch_frequency')
    if (not _strict_int(freq) or freq <= 0
            or not _strict_int(after.get('stopwatch_frequency'))
            or after.get('stopwatch_frequency') != freq):
        raise ValueError(error('invalid capture monotonic frequency'))
    for end, name in ((before, 'before'), (after, 'after')):
        for key in ('utc_ticks', 'mono', 'q0', 'q1'):
            if not _strict_int(end.get(key)):
                raise ValueError(error('invalid %s clock %s' % (name, key)))


def check_continuity(before, after, resolution_ns, error):
    """Strict wall-vs-mono continuity for legacy AND bracketed records.

    ``error`` builds the caller's ValueError message so kernel/tcpip keep
    their exact legacy strings; each caller keeps its own existing domain
    checks (timezone, frequency shape) untouched before calling. Legacy
    records (both ends unbracketed) use the original point comparison.
    Bracketed records re-validate every field strictly and require the whole
    uncertainty interval of wall-minus-mono to fit inside the same resolution
    budget.
    """
    for end in (before, after):
        marked = any(key in end for key in ('schema', 'version', 'q0', 'q1', 'warmup'))
        if marked and not is_bracketed(end):
            raise ValueError(error('invalid clock sampling schema or fields'))
    new_before, new_after = is_bracketed(before), is_bracketed(after)
    if new_before != new_after:
        raise ValueError(error('mixed clock sampling schemas'))
    wall = (after['utc_ticks'] - before['utc_ticks']) * 100
    if not new_before:
        mono = (after['mono'] - before['mono']) * 10**9 // before['stopwatch_frequency']
        if wall < 0 or mono < 0 or abs(wall - mono) > resolution_ns:
            raise ValueError(error('clock discontinuity'))
        return {'mode': 'legacy-point', 'wall_ns': wall, 'mono_ns': mono}
    _require_clock_domain(before, after, error)
    for end, name in ((before, 'before'), (after, 'after')):
        q0, q1, mono = end['q0'], end['q1'], end['mono']
        if q0 > q1 or not q0 <= mono <= q1 or mono != q0 + (q1 - q0) // 2:
            raise ValueError(error('invalid %s clock bracket' % name))
    freq = before['stopwatch_frequency']
    # True monotonic elapsed is bracketed by cross-end QPC differences; the
    # bounds are exact integer rationals rounded OUTWARD (floor/ceil, no
    # floats), so containment can only get stricter, never looser.
    elapsed_lo_num = (after['q0'] - before['q1']) * 10**9
    elapsed_hi_num = (after['q1'] - before['q0']) * 10**9
    elapsed_lo = elapsed_lo_num // freq
    ceil_correct = 0 if elapsed_hi_num % freq == 0 else 1
    elapsed_hi = elapsed_hi_num // freq + ceil_correct
    lo = wall - elapsed_hi  # wall minus the largest possible elapsed
    hi = wall - elapsed_lo  # wall minus the smallest possible elapsed
    if wall < 0 or elapsed_lo_num < 0 or lo < -resolution_ns or hi > resolution_ns:
        raise ValueError(error('clock discontinuity'))
    return {'mode': 'interval', 'wall_ns': wall,
            'elapsed_lo_ns': elapsed_lo, 'elapsed_hi_ns': elapsed_hi,
            'wall_minus_mono_lo_ns': lo, 'wall_minus_mono_hi_ns': hi}
