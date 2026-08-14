import unittest

from fakenet.diverters.egresspolicy import EgressPolicy, PolicyConfigError
from fakenet.diverters.processredirect import FrozenFileIdentity
from fakenet.diverters.processredirect import (
    OwnerResolution, OwnerResolutionStatus, PacketTuple,
    ProcessOwnerIdentity, ProcessRedirectAction, ProcessRedirectEngine)


def base_config():
    return {
        'externalalloweddomains': 'api.deepseek.com',
        'externalallowedtcpports': '443',
        'externalverifytlssni': 'yes',
        'externalblockexternalipv6': 'yes',
        'externalblockquic': 'yes',
        'externalrelayport': '38927',
        'externaltlshellotimeout': '5',
        'externaltlshellomaxbytes': '65536',
        'externalmaxpendingflows': '256',
        'externalmaxpendingpersource': '32',
        'externalmaxactiverelays': '128',
        'externalmaxactivepersource': '16',
        'externalrelayidletimeout': '300',
        'externalrelaybufferbytes': '1048576',
        'externalnonallowedaction': 'divert',
    }


def enabled_config():
    result = base_config()
    result.update({
        'externalprocessredirectenabled': 'Yes',
        'externalprocessredirectprotocol': 'TCP',
        'externalprocessredirectimagepath': r'C:\Reviewed\client.exe',
        'externalprocessredirectimagesha256': 'a' * 64,
        'externalprocessredirectoriginalipv4': '93.184.216.34',
        'externalprocessredirecttargetipv4': '192.168.204.1',
    })
    return result


class Reviewer(object):
    def __init__(self):
        self.calls = []

    def review_rule_file(self, path, expected_sha256):
        self.calls.append((path, expected_sha256))
        return FrozenFileIdentity(
            final_path=r'c:\reviewed\client.exe',
            volume_serial=7,
            file_id=11,
            sha256=expected_sha256)


class Clock(object):
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class OwnerResolver(object):
    def __init__(self, resolution):
        self.resolution = resolution
        self.resolve_calls = []
        self.revalidate_calls = []

    def resolve_tcp_owner(self, packet):
        self.resolve_calls.append(packet)
        return self.resolution

    def revalidate_process_identity(self, identity):
        self.revalidate_calls.append(identity)
        return True

    def revalidate_rule_file(self, identity):
        return True


class RouteGuard(object):
    def __init__(self, current=True):
        self.current = current
        self.calls = []

    def is_current(self, packet):
        self.calls.append(packet)
        return self.current

    def validate_resume(self):
        return self.current


class FailedRouteGuard(RouteGuard):
    def __init__(self, reason):
        super().__init__(current=False)
        self.failure_reason = reason


class ProcessRedirectConfigurationTests(unittest.TestCase):
    def make_policy(self, cfg, reviewer=None, platform_name='windows'):
        return EgressPolicy(
            cfg, ['10.0.0.5'], ['fe80::1'], '10.0.0.1',
            process_rule_reviewer=reviewer,
            platform_name=platform_name)

    def test_feature_is_default_off_and_does_not_review_placeholder_fields(self):
        cfg = base_config()
        cfg.update({
            'externalprocessredirectenabled': 'No',
            'externalprocessredirectimagepath': '__REVIEWED_PROCESS__',
        })
        reviewer = Reviewer()

        policy = self.make_policy(cfg, reviewer)

        self.assertFalse(policy.process_redirect_enabled)
        self.assertIsNone(policy.process_redirect_rule)
        self.assertEqual([], reviewer.calls)

    def test_enabled_rule_is_canonical_and_reviewed_before_runtime(self):
        reviewer = Reviewer()

        policy = self.make_policy(enabled_config(), reviewer)

        self.assertTrue(policy.process_redirect_enabled)
        self.assertEqual('TCP', policy.process_redirect_rule.protocol)
        self.assertEqual('93.184.216.34',
                         policy.process_redirect_rule.original_ipv4)
        self.assertEqual('192.168.204.1',
                         policy.process_redirect_rule.target_ipv4)
        self.assertEqual(
            [(r'C:\Reviewed\client.exe', 'a' * 64)], reviewer.calls)

    def test_enabled_rule_requires_windows_reviewer_and_all_fields(self):
        with self.assertRaises(PolicyConfigError):
            self.make_policy(enabled_config(), Reviewer(), 'linux')
        with self.assertRaises(PolicyConfigError):
            self.make_policy(enabled_config(), None)
        for field in (
                'externalprocessredirectprotocol',
                'externalprocessredirectimagepath',
                'externalprocessredirectimagesha256',
                'externalprocessredirectoriginalipv4',
                'externalprocessredirecttargetipv4'):
            cfg = enabled_config()
            del cfg[field]
            with self.assertRaises(PolicyConfigError, msg=field):
                self.make_policy(cfg, Reviewer())

    def test_enabled_rule_rejects_invalid_identity_and_addresses(self):
        invalid = (
            ('externalprocessredirectprotocol', 'UDP'),
            ('externalprocessredirectimagepath', r'relative\client.exe'),
            ('externalprocessredirectimagepath', r'C:\Reviewed\client.exe:ads'),
            ('externalprocessredirectimagesha256', 'not-a-hash'),
            ('externalprocessredirectoriginalipv4', '192.168.1.10'),
            ('externalprocessredirecttargetipv4', '8.8.8.8'),
            ('externalprocessredirecttargetipv4', '192.168.0.0'),
            ('externalprocessredirecttargetipv4', '192.168.255.255'),
        )
        for field, value in invalid:
            cfg = enabled_config()
            cfg[field] = value
            with self.assertRaises(PolicyConfigError, msg=(field, value)):
                self.make_policy(cfg, Reviewer())

    def test_enabled_rule_rejects_cross_feature_conflicts(self):
        conflicts = []

        cfg = enabled_config()
        cfg['externalprocessredirectoriginalipv4'] = '10.0.0.5'
        conflicts.append(cfg)

        cfg = enabled_config()
        cfg['externalprocessredirecttargetipv4'] = '10.0.0.5'
        conflicts.append(cfg)

        cfg = enabled_config()
        cfg['externalprocessredirecttargetipv4'] = '10.0.0.1'
        conflicts.append(cfg)

        cfg = enabled_config()
        cfg.update({
            'externaltakeoveripv4': '192.168.204.1',
            'externaltakeoverdnsttl': '60',
        })
        conflicts.append(cfg)

        cfg = enabled_config()
        cfg['externalallowedipv4rules'] = 'TCP/93.184.216.34/443'
        conflicts.append(cfg)

        for cfg in conflicts:
            with self.assertRaises(PolicyConfigError):
                self.make_policy(cfg, Reviewer())


class ProcessRedirectEngineTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.rule = self.make_rule()
        self.owner = ProcessOwnerIdentity(
            pid=1234, creation_time=77,
            final_path=self.rule.file_identity.final_path,
            volume_serial=self.rule.file_identity.volume_serial,
            file_id=self.rule.file_identity.file_id)
        self.resolver = OwnerResolver(OwnerResolution(
            OwnerResolutionStatus.RESOLVED, self.owner))
        self.route = RouteGuard()
        self.engine = ProcessRedirectEngine(
            self.rule, self.resolver, self.route, clock=self.clock)

    @staticmethod
    def make_rule():
        identity = FrozenFileIdentity(
            r'c:\reviewed\client.exe', 7, 11, 'a' * 64)
        from fakenet.diverters.processredirect import ProcessRedirectRule
        return ProcessRedirectRule(
            'TCP', identity.final_path, identity.sha256,
            '93.184.216.34', '192.168.204.1', identity)

    @staticmethod
    def packet(direction='outbound', src='10.0.0.5', sport=50000,
               dst='93.184.216.34', dport=443, flags=0x02,
               fragmented=False):
        return PacketTuple(
            direction=direction, ipv4_version=4, fragmented=fragmented,
            protocol='TCP', tcp_flags=flags,
            source_ipv4=src, source_port=sport,
            target_ipv4=dst, target_port=dport,
            interface_index=7, subinterface_index=0)

    def test_committed_target_syn_supports_round_trip_without_more_owner_queries(self):
        prepared = self.engine.prepare(self.packet())

        self.assertEqual(ProcessRedirectAction.REWRITE_OUTBOUND,
                         prepared.decision.action)
        self.assertEqual('192.168.204.1',
                         prepared.decision.rewrite_target_ipv4)
        self.assertEqual(443, prepared.decision.rewrite_target_port)
        self.assertIsNotNone(prepared.token)
        self.engine.commit(prepared.token, True)

        established = self.engine.prepare(self.packet(flags=0x10))
        self.assertEqual(ProcessRedirectAction.REWRITE_OUTBOUND,
                         established.decision.action)
        self.engine.commit(established.token, True)

        inbound = self.engine.prepare(self.packet(
            direction='inbound', src='192.168.204.1', sport=443,
            dst='10.0.0.5', dport=50000, flags=0x10))
        self.assertEqual(ProcessRedirectAction.REWRITE_INBOUND,
                         inbound.decision.action)
        self.assertEqual('93.184.216.34',
                         inbound.decision.rewrite_source_ipv4)
        self.assertEqual(443, inbound.decision.rewrite_source_port)
        self.engine.commit(inbound.token, True)

        self.assertEqual(1, len(self.resolver.resolve_calls))
        self.assertEqual(1, len(self.resolver.revalidate_calls))

    def test_failed_injection_creates_short_tombstone_and_token_is_exactly_once(self):
        prepared = self.engine.prepare(self.packet())

        self.assertFalse(self.engine.commit(prepared.token, False))
        with self.assertRaises(RuntimeError):
            self.engine.commit(prepared.token, True)

        blocked = self.engine.prepare(self.packet())
        self.assertEqual(ProcessRedirectAction.DROP,
                         blocked.decision.action)
        self.assertEqual('injection_failure_tombstone',
                         blocked.decision.reason)
        self.assertEqual(1, len(self.resolver.resolve_calls))

        self.clock.value += 3.1
        retry = self.engine.prepare(self.packet())
        self.assertEqual(ProcessRedirectAction.REWRITE_OUTBOUND,
                         retry.decision.action)
        self.engine.abort(retry.token, 'test_cleanup')

    def test_successful_rst_closes_mapping_with_normal_tombstone(self):
        first = self.engine.prepare(self.packet())
        self.engine.commit(first.token, True)

        reset = self.engine.prepare(self.packet(flags=0x04))
        self.assertEqual(ProcessRedirectAction.REWRITE_OUTBOUND,
                         reset.decision.action)
        self.engine.commit(reset.token, True)

        late = self.engine.prepare(self.packet(
            direction='inbound', src='192.168.204.1', sport=443,
            dst='10.0.0.5', dport=50000, flags=0x10))
        self.assertEqual(ProcessRedirectAction.DROP, late.decision.action)
        self.assertEqual('normal_close_tombstone', late.decision.reason)

        self.clock.value += 240.1
        unrelated = self.engine.prepare(self.packet(
            direction='inbound', src='192.168.204.1', sport=443,
            dst='10.0.0.5', dport=50000, flags=0x10))
        self.assertEqual(ProcessRedirectAction.PASS_UNCHANGED,
                         unrelated.decision.action)

    def test_half_close_and_idle_timeouts_are_monotonic_and_fail_closed(self):
        first = self.engine.prepare(self.packet())
        self.engine.commit(first.token, True)
        client_fin = self.engine.prepare(self.packet(flags=0x01))
        self.engine.commit(client_fin.token, True)

        self.clock.value += 120.1
        expired_half_close = self.engine.prepare(self.packet(flags=0x10))
        self.assertEqual(ProcessRedirectAction.DROP,
                         expired_half_close.decision.action)
        self.assertEqual('half_close_timeout_tombstone',
                         expired_half_close.decision.reason)

        self.clock.value += 240.1
        new_flow = self.engine.prepare(self.packet(sport=50001))
        self.engine.commit(new_flow.token, True)
        self.clock.value += 1800.1
        idle = self.engine.prepare(self.packet(sport=50001, flags=0x10))
        self.assertEqual(ProcessRedirectAction.DROP, idle.decision.action)
        self.assertEqual('idle_timeout_tombstone', idle.decision.reason)

    def test_owner_query_budget_drops_excess_syn_without_query_or_fallback(self):
        prepared = []
        for offset in range(16):
            item = self.engine.prepare(self.packet(sport=51000 + offset))
            self.assertEqual(ProcessRedirectAction.REWRITE_OUTBOUND,
                             item.decision.action)
            prepared.append(item)

        excess = self.engine.prepare(self.packet(sport=52000))
        self.assertEqual(ProcessRedirectAction.DROP,
                         excess.decision.action)
        self.assertEqual('owner_query_budget_exhausted',
                         excess.decision.reason)
        self.assertEqual(16, len(self.resolver.resolve_calls))

        for item in prepared:
            self.engine.abort(item.token, 'test_cleanup')

    def test_same_syn_reuses_owner_result_for_three_seconds(self):
        non_target = ProcessOwnerIdentity(
            pid=2222, creation_time=88,
            final_path=r'c:\other\client.exe',
            volume_serial=9, file_id=13)
        self.resolver.resolution = OwnerResolution(
            OwnerResolutionStatus.RESOLVED, non_target)

        first = self.engine.prepare(self.packet())
        second = self.engine.prepare(self.packet())

        self.assertEqual(ProcessRedirectAction.PASS_UNCHANGED,
                         first.decision.action)
        self.assertEqual(ProcessRedirectAction.PASS_UNCHANGED,
                         second.decision.action)
        self.assertEqual(1, len(self.resolver.resolve_calls))

        self.clock.value += 3.1
        third = self.engine.prepare(self.packet())
        self.assertEqual(ProcessRedirectAction.PASS_UNCHANGED,
                         third.decision.action)
        self.assertEqual(2, len(self.resolver.resolve_calls))

    def test_single_pid_mapping_limit_counts_only_committed_a_flows(self):
        for offset in range(256):
            item = self.engine.prepare(self.packet(sport=20000 + offset))
            self.assertEqual(ProcessRedirectAction.REWRITE_OUTBOUND,
                             item.decision.action)
            self.engine.commit(item.token, True)
            self.clock.value += 0.04

        excess = self.engine.prepare(self.packet(sport=30000))
        self.assertEqual(ProcessRedirectAction.DROP,
                         excess.decision.action)
        self.assertEqual('per_pid_mapping_capacity',
                         excess.decision.reason)

    def test_suspend_is_local_and_resume_requires_route_and_rule_revalidation(self):
        first = self.engine.prepare(self.packet())
        self.engine.commit(first.token, True)

        self.engine.suspend('route_snapshot_changed')
        blocked = self.engine.prepare(self.packet(sport=50001))
        self.assertEqual(ProcessRedirectAction.DROP,
                         blocked.decision.action)
        self.assertEqual('process_redirect_unavailable',
                         blocked.decision.reason)

        self.route.current = False
        self.assertFalse(self.engine.resume())
        self.route.current = True
        self.assertTrue(self.engine.resume())

        resumed = self.engine.prepare(self.packet(sport=50001))
        self.assertEqual(ProcessRedirectAction.REWRITE_OUTBOUND,
                         resumed.decision.action)
        self.engine.abort(resumed.token, 'test_cleanup')

    def test_route_drift_immediately_suspends_only_this_engine(self):
        self.route.current = False

        blocked = self.engine.prepare(self.packet())

        self.assertEqual(ProcessRedirectAction.DROP,
                         blocked.decision.action)
        self.assertEqual('route_snapshot_changed', blocked.decision.reason)
        self.assertFalse(self.engine.settings()['available'])
        self.assertEqual('route_snapshot_changed',
                         self.engine.settings()['suspend_reason'])

    def test_initial_route_query_timeout_preserves_fail_closed_reason(self):
        self.engine._route_guard = FailedRouteGuard('route_query_timeout')

        blocked = self.engine.prepare(self.packet())

        self.assertEqual(ProcessRedirectAction.DROP,
                         blocked.decision.action)
        self.assertEqual('route_query_timeout', blocked.decision.reason)
        self.assertEqual('route_query_timeout',
                         self.engine.settings()['suspend_reason'])

    def test_pending_transaction_limit_applies_to_established_packets(self):
        first = self.engine.prepare(self.packet())
        self.engine.commit(first.token, True)
        pending = []
        for unused_index in range(128):
            item = self.engine.prepare(self.packet(flags=0x10))
            self.assertEqual(ProcessRedirectAction.REWRITE_OUTBOUND,
                             item.decision.action)
            pending.append(item)

        excess = self.engine.prepare(self.packet(flags=0x10))

        self.assertEqual(ProcessRedirectAction.DROP,
                         excess.decision.action)
        self.assertEqual('pending_transaction_capacity',
                         excess.decision.reason)
        for item in pending:
            self.engine.abort(item.token, 'test_cleanup')

    def test_audit_summary_is_bounded_and_drained_by_interval(self):
        first = self.engine.prepare(self.packet())
        self.engine.commit(first.token, True)
        established = self.engine.prepare(self.packet(flags=0x10))
        self.engine.commit(established.token, True)

        self.assertIsNone(self.engine.drain_audit_summary())
        self.clock.value += 60.1
        summary = self.engine.drain_audit_summary()

        self.assertEqual(1, summary['mappings_created'])
        self.assertEqual(2, summary['forward_packets'])
        self.assertEqual(1, summary['active_mappings'])
        self.assertIsNone(self.engine.drain_audit_summary())

    def test_global_mapping_limit_counts_four_reviewed_processes(self):
        for offset in range(1024):
            identity = ProcessOwnerIdentity(
                pid=4000 + offset // 256,
                creation_time=100 + offset // 256,
                final_path=self.rule.file_identity.final_path,
                volume_serial=self.rule.file_identity.volume_serial,
                file_id=self.rule.file_identity.file_id)
            self.resolver.resolution = OwnerResolution(
                OwnerResolutionStatus.RESOLVED, identity)
            item = self.engine.prepare(self.packet(sport=10000 + offset))
            self.assertEqual(ProcessRedirectAction.REWRITE_OUTBOUND,
                             item.decision.action)
            self.engine.commit(item.token, True)
            self.clock.value += 0.04

        identity = ProcessOwnerIdentity(
            pid=5000, creation_time=200,
            final_path=self.rule.file_identity.final_path,
            volume_serial=self.rule.file_identity.volume_serial,
            file_id=self.rule.file_identity.file_id)
        self.resolver.resolution = OwnerResolution(
            OwnerResolutionStatus.RESOLVED, identity)
        excess = self.engine.prepare(self.packet(sport=20000))

        self.assertEqual(ProcessRedirectAction.DROP,
                         excess.decision.action)
        self.assertEqual('global_mapping_capacity', excess.decision.reason)

    def test_double_fin_closes_mapping_and_rejects_late_packets(self):
        first = self.engine.prepare(self.packet())
        self.engine.commit(first.token, True)
        client_fin = self.engine.prepare(self.packet(flags=0x01))
        self.engine.commit(client_fin.token, True)
        server_fin = self.engine.prepare(self.packet(
            direction='inbound', src='192.168.204.1', sport=443,
            dst='10.0.0.5', dport=50000, flags=0x01))
        self.engine.commit(server_fin.token, True)

        late = self.engine.prepare(self.packet(flags=0x10))

        self.assertEqual(ProcessRedirectAction.DROP, late.decision.action)
        self.assertEqual('normal_close_tombstone', late.decision.reason)

    def test_owner_failure_statuses_are_distinct_and_never_pass(self):
        expected = {
            OwnerResolutionStatus.NOT_FOUND: 'owner_not_found',
            OwnerResolutionStatus.AMBIGUOUS: 'owner_ambiguous',
            OwnerResolutionStatus.ERROR: 'owner_error',
        }
        for offset, (status, reason) in enumerate(expected.items()):
            self.resolver.resolution = OwnerResolution(status)
            result = self.engine.prepare(self.packet(sport=30000 + offset))
            self.assertEqual(ProcessRedirectAction.DROP,
                             result.decision.action)
            self.assertEqual(reason, result.decision.reason)

if __name__ == '__main__':
    unittest.main()
