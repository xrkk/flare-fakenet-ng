import unittest

from fakenet.diverters.processredirect import (
    OwnerResolutionStatus, PacketTuple, ProcessOwnerIdentity)
from fakenet.diverters.winutil import (
    InstrumentedProcessIdentityApi, StrictTcpOwnerResolver, TcpOwnerRow)


class OwnerApi(object):
    def __init__(self, rows=(), identities=None, error=None):
        self.rows = list(rows)
        self.identities = identities or {}
        self.error = error
        self.row_calls = 0
        self.identity_calls = []

    def get_tcp_owner_rows(self):
        self.row_calls += 1
        if self.error:
            raise self.error
        return list(self.rows)

    def get_process_identity(self, pid):
        self.identity_calls.append(pid)
        value = self.identities.get(pid)
        if isinstance(value, BaseException):
            raise value
        return value


class Clock(object):
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


def packet():
    return PacketTuple(
        'outbound', 4, False, 'TCP', 0x02,
        '10.0.0.5', 50000, '93.184.216.34', 443, 7, 0)


class StrictTcpOwnerResolverTests(unittest.TestCase):
    def setUp(self):
        self.identity = ProcessOwnerIdentity(
            1234, 77, r'c:\reviewed\client.exe', 7, 11)

    def test_resolves_only_one_complete_tuple_and_revalidates_identity(self):
        rows = [
            TcpOwnerRow('10.0.0.5', 50000, '93.184.216.34', 443, 3, 1234),
            TcpOwnerRow('10.0.0.5', 50000, '93.184.216.35', 443, 3, 2000),
            TcpOwnerRow('10.0.0.6', 50000, '93.184.216.34', 443, 3, 3000),
        ]
        api = OwnerApi(rows, {1234: self.identity})
        resolver = StrictTcpOwnerResolver(api)

        result = resolver.resolve_tcp_owner(packet())

        self.assertEqual(OwnerResolutionStatus.RESOLVED, result.status)
        self.assertEqual(self.identity, result.identity)
        self.assertTrue(resolver.revalidate_process_identity(self.identity))
        self.assertEqual([1234, 1234], api.identity_calls)

    def test_zero_multiple_and_api_errors_remain_distinct(self):
        missing = StrictTcpOwnerResolver(OwnerApi()).resolve_tcp_owner(packet())
        self.assertEqual(OwnerResolutionStatus.NOT_FOUND, missing.status)

        duplicate = TcpOwnerRow(
            '10.0.0.5', 50000, '93.184.216.34', 443, 3, 1234)
        ambiguous = StrictTcpOwnerResolver(
            OwnerApi([duplicate, duplicate])).resolve_tcp_owner(packet())
        self.assertEqual(OwnerResolutionStatus.AMBIGUOUS, ambiguous.status)

        failed = StrictTcpOwnerResolver(
            OwnerApi(error=OSError('injected'))).resolve_tcp_owner(packet())
        self.assertEqual(OwnerResolutionStatus.ERROR, failed.status)

    def test_process_query_failure_is_error_and_changed_identity_fails_recheck(self):
        row = TcpOwnerRow(
            '10.0.0.5', 50000, '93.184.216.34', 443, 3, 1234)
        failed = StrictTcpOwnerResolver(
            OwnerApi([row], {1234: OSError('denied')}))
        self.assertEqual(
            OwnerResolutionStatus.ERROR,
            failed.resolve_tcp_owner(packet()).status)

        changed = ProcessOwnerIdentity(
            1234, 78, self.identity.final_path, 7, 11)
        resolver = StrictTcpOwnerResolver(
            OwnerApi([row], {1234: changed}))
        self.assertFalse(resolver.revalidate_process_identity(self.identity))

    def test_reviewed_identity_cache_is_bounded_short_lived_and_rechecked(self):
        row = TcpOwnerRow(
            '10.0.0.5', 50000, '93.184.216.34', 443, 3, 1234)
        clock = Clock()
        api = OwnerApi([row], {1234: self.identity})
        resolver = StrictTcpOwnerResolver(
            api, reviewed_file_identity=self.identity, clock=clock)

        first = resolver.resolve_tcp_owner(packet())
        second = resolver.resolve_tcp_owner(packet())

        self.assertEqual(OwnerResolutionStatus.RESOLVED, first.status)
        self.assertEqual(OwnerResolutionStatus.RESOLVED, second.status)
        self.assertEqual([1234], api.identity_calls)
        self.assertTrue(resolver.revalidate_process_identity(self.identity))
        self.assertEqual([1234, 1234], api.identity_calls)

        clock.value += 5.1
        resolver.resolve_tcp_owner(packet())
        self.assertEqual([1234, 1234, 1234], api.identity_calls)

    def test_non_reviewed_identity_is_never_reused_from_cache(self):
        row = TcpOwnerRow(
            '10.0.0.5', 50000, '93.184.216.34', 443, 3, 1234)
        other = ProcessOwnerIdentity(
            1234, 77, r'c:\other\client.exe', 7, 99)
        api = OwnerApi([row], {1234: other})
        resolver = StrictTcpOwnerResolver(
            api, reviewed_file_identity=self.identity, clock=Clock())

        resolver.resolve_tcp_owner(packet())
        resolver.resolve_tcp_owner(packet())

        self.assertEqual([1234, 1234], api.identity_calls)


class FakeClock(object):
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class ProgrammableApi(object):
    """Advances the injected clock by a fixed delta on each delegated call."""

    def __init__(self, clock, advance_seconds, rows=(), identity=None,
                 error=None):
        self.clock = clock
        self.advance = advance_seconds
        self.rows = list(rows)
        self.identity = identity
        self.error = error

    def get_tcp_owner_rows(self):
        self.clock.now += self.advance
        if self.error:
            raise self.error
        return list(self.rows)

    def get_process_identity(self, pid):
        self.clock.now += self.advance
        if self.error:
            raise self.error
        return self.identity

    def revalidate_rule_file(self, identity):
        return True


class InstrumentedProcessIdentityApiTests(unittest.TestCase):
    def _collect(self):
        reports = []

        def on_slow(method, elapsed_ms):
            reports.append((method, elapsed_ms))
        return reports, on_slow

    def test_slow_owner_query_reports_method_and_latency(self):
        clock = FakeClock()
        reports, on_slow = self._collect()
        api = ProgrammableApi(clock, 0.75)
        wrapper = InstrumentedProcessIdentityApi(
            api, on_slow_query=on_slow, clock=clock)

        wrapper.get_tcp_owner_rows()

        self.assertEqual([('get_tcp_owner_rows', 750.0)], reports)

    def test_fast_owner_query_is_silent(self):
        clock = FakeClock()
        reports, on_slow = self._collect()
        api = ProgrammableApi(clock, 0.10)
        wrapper = InstrumentedProcessIdentityApi(
            api, on_slow_query=on_slow, clock=clock)

        wrapper.get_tcp_owner_rows()
        wrapper.get_process_identity(123)

        self.assertEqual([], reports)

    def test_delegate_exception_propagates_and_timing_still_runs(self):
        clock = FakeClock()
        reports, on_slow = self._collect()
        api = ProgrammableApi(clock, 0.75, error=OSError('denied'))
        wrapper = InstrumentedProcessIdentityApi(
            api, on_slow_query=on_slow, clock=clock)

        with self.assertRaises(OSError):
            wrapper.get_tcp_owner_rows()

        self.assertEqual([('get_tcp_owner_rows', 750.0)], reports)

    def test_broken_callback_never_breaks_resolution(self):
        clock = FakeClock()

        def explode(method, elapsed_ms):
            raise RuntimeError('telemetry fault')

        api = ProgrammableApi(clock, 0.75, rows=[TcpOwnerRow(
            '10.0.0.5', 50000, '93.184.216.34', 443, 3, 1234)])
        wrapper = InstrumentedProcessIdentityApi(
            api, on_slow_query=explode, clock=clock)

        self.assertEqual(1, len(wrapper.get_tcp_owner_rows()))

    def test_latency_stats_accumulate_then_drain_and_reset(self):
        clock = FakeClock()
        api = ProgrammableApi(clock, 0.10)
        wrapper = InstrumentedProcessIdentityApi(api, clock=clock)

        wrapper.get_tcp_owner_rows()
        wrapper.get_process_identity(1)
        wrapper.get_tcp_owner_rows()

        count, avg, max_ms = wrapper.drain_latency_stats()
        self.assertEqual(3, count)
        self.assertAlmostEqual(100.0, avg)
        self.assertAlmostEqual(100.0, max_ms)

        # Drain resets the accumulator.
        self.assertEqual((0, 0.0, 0.0), wrapper.drain_latency_stats())


if __name__ == '__main__':
    unittest.main()
