import unittest

from fakenet.diverters.egresspolicy import (
    EgressPolicy, PolicyConfigError, normalize_hostname)


def config():
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


def takeover_config(probe_ports='', probe_timeout='500'):
    result = config()
    result.update({
        'externaltakeoveripv4': '192.168.204.1',
        'externaltakeoverdnsttl': '60',
        'externaltakeoverprobetcpports': probe_ports,
        'externaltakeoverprobetimeoutms': probe_timeout,
    })
    return result


class Clock(object):
    def __init__(self):
        self.value = 100.0

    def __call__(self):
        return self.value


class EgressPolicyTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.policy = EgressPolicy(
            config(), ['10.0.0.5'], ['fe80::1'], '10.0.0.1', self.clock)

    def test_rejects_unreviewed_ports_and_limits(self):
        bad = config()
        bad['externalallowedtcpports'] = '80,443'
        with self.assertRaises(PolicyConfigError):
            EgressPolicy(bad, ['10.0.0.5'], [], '10.0.0.1')

    def test_hostname_normalization_rejects_empty_labels(self):
        self.assertEqual('api.deepseek.com',
                         normalize_hostname('API.DeepSeek.COM.'))
        with self.assertRaises(PolicyConfigError):
            normalize_hostname('api.deepseek.com..')
        with self.assertRaises(PolicyConfigError):
            normalize_hostname('api..deepseek.com')

    def test_lease_replacement_ttl_and_alias(self):
        installed = self.policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 5), ('127.0.0.1', 60)])
        self.assertEqual(('93.184.216.34',), installed)
        self.assertEqual('api.deepseek.com',
                         self.policy.lease_for('93.184.216.34', 443).domain)
        self.policy.register_alias('api.deepseek.com', 'edge.example.net', 2)
        self.assertEqual('api.deepseek.com',
                         self.policy.resolve_dns_rule('EDGE.EXAMPLE.NET.'))
        self.clock.value += 3
        self.assertIsNone(self.policy.resolve_dns_rule('edge.example.net'))
        self.clock.value += 3
        self.assertIsNone(self.policy.lease_for('93.184.216.34', 443))

    def test_exact_control_flow_and_revoke(self):
        token = self.policy.register_control_flow(
            'dns', 'UDP', '10.0.0.5', 53001, '10.0.0.1', 53)
        self.assertIsNotNone(self.policy.match_control_flow(
            'UDP', '10.0.0.5', 53001, '10.0.0.1', 53))
        self.assertIsNone(self.policy.match_control_flow(
            'UDP', '10.0.0.5', 53002, '10.0.0.1', 53))
        self.policy.revoke_control_flow(token)
        self.assertIsNone(self.policy.match_control_flow(
            'UDP', '10.0.0.5', 53001, '10.0.0.1', 53))

    def test_bidirectional_nat_consumption_and_tombstone(self):
        self.policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 300)])
        mapping = self.policy.create_relay_mapping(
            '10.0.0.5', 50000, '93.184.216.34', 443,
            '10.0.0.5', 38927)
        self.assertEqual(mapping, self.policy.match_relay_forward(
            'TCP', '10.0.0.5', 50000, '93.184.216.34', 443))
        self.assertEqual(mapping, self.policy.match_relay_reverse(
            'TCP', '10.0.0.5', 38927, '10.0.0.5', 50000))
        self.assertEqual(mapping, self.policy.consume_relay_target(
            '10.0.0.5', 50000))
        self.assertIsNone(self.policy.consume_relay_target(
            '10.0.0.5', 50000))
        self.assertTrue(self.policy.activate_relay_mapping(mapping.generation))
        self.policy.close_relay_mapping(mapping.generation)
        self.assertIsNone(self.policy.match_relay_forward(
            'TCP', '10.0.0.5', 50000, '93.184.216.34', 443))
        with self.assertRaises(ValueError):
            self.policy.create_relay_mapping(
                '10.0.0.5', 50000, '93.184.216.34', 443,
                '10.0.0.5', 38927)
        self.clock.value += self.policy.RELAY_TOMBSTONE_SECONDS + 1
        replacement = self.policy.create_relay_mapping(
            '10.0.0.5', 50000, '93.184.216.34', 443,
            '10.0.0.5', 38927)
        self.assertGreater(replacement.generation, mapping.generation)

    def test_existing_mapping_survives_dns_ttl_for_sni_completion(self):
        self.policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 1)])
        mapping = self.policy.create_relay_mapping(
            '10.0.0.5', 50001, '93.184.216.34', 443,
            '10.0.0.5', 38927)
        consumed = self.policy.consume_relay_target('10.0.0.5', 50001)
        self.assertEqual(mapping, consumed)
        self.clock.value += 2
        self.assertIsNone(self.policy.lease_for('93.184.216.34', 443))
        token = self.policy.register_control_flow(
            'tls_relay', 'TCP', '10.0.0.5', 55000,
            '93.184.216.34', 443, domain='api.deepseek.com',
            generation=mapping.generation)
        self.assertIsNotNone(token)

    def test_pending_mapping_deadline_is_not_refreshed_by_packets(self):
        self.policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 60)])
        mapping = self.policy.create_relay_mapping(
            '10.0.0.5', 50002, '93.184.216.34', 443,
            '10.0.0.5', 38927)
        self.clock.value += 9
        self.assertEqual(mapping, self.policy.match_relay_forward(
            'TCP', '10.0.0.5', 50002, '93.184.216.34', 443))
        self.clock.value += 2
        self.assertIsNone(self.policy.match_relay_forward(
            'TCP', '10.0.0.5', 50002, '93.184.216.34', 443))

    def test_pending_mapping_quota_fails_closed(self):
        self.policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 60)])
        for offset in range(32):
            self.policy.create_relay_mapping(
                '10.0.0.5', 51000 + offset, '93.184.216.34', 443,
                '10.0.0.5', 38927)
        with self.assertRaises(RuntimeError):
            self.policy.create_relay_mapping(
                '10.0.0.5', 52000, '93.184.216.34', 443,
                '10.0.0.5', 38927)

    def test_expired_lease_event_is_drained_once(self):
        self.policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 1)])
        self.clock.value += 2
        self.assertEqual(
            (('api.deepseek.com', '93.184.216.34'),),
            self.policy.drain_expired_leases())
        self.assertEqual((), self.policy.drain_expired_leases())

    def test_address_snapshot_removal_revokes_old_flows(self):
        token = self.policy.register_control_flow(
            'dns', 'UDP', '10.0.0.5', 53001, '10.0.0.1', 53)
        self.policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 60)])
        self.policy.create_relay_mapping(
            '10.0.0.5', 53002, '93.184.216.34', 443,
            '10.0.0.5', 38927)
        self.assertTrue(self.policy.update_local_ipv4(['10.0.0.6']))
        self.assertIsNone(self.policy.match_control_flow(
            'UDP', '10.0.0.5', 53001, '10.0.0.1', 53))
        self.assertIsNone(self.policy.match_relay_forward(
            'TCP', '10.0.0.5', 53002, '93.184.216.34', 443))
        self.policy.revoke_control_flow(token)

    def test_global_pending_mapping_quota_fails_closed(self):
        local_ips = ['10.0.1.%d' % value for value in range(1, 10)]
        policy = EgressPolicy(
            config(), local_ips, [], '10.0.0.1', self.clock)
        policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 60)])
        for offset in range(256):
            source = local_ips[offset // 32]
            policy.create_relay_mapping(
                source, 40000 + offset, '93.184.216.34', 443,
                source, 38927)
        with self.assertRaises(RuntimeError):
            policy.create_relay_mapping(
                local_ips[8], 50000, '93.184.216.34', 443,
                local_ips[8], 38927)

    def test_active_relay_per_source_quota_recovers_after_close(self):
        self.policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 60)])
        mappings = []
        for offset in range(17):
            mapping = self.policy.create_relay_mapping(
                '10.0.0.5', 54000 + offset, '93.184.216.34', 443,
                '10.0.0.5', 38927)
            self.assertIs(mapping, self.policy.consume_relay_target(
                '10.0.0.5', 54000 + offset))
            mappings.append(mapping)
        for mapping in mappings[:16]:
            self.assertTrue(self.policy.activate_relay_mapping(
                mapping.generation))
        self.assertFalse(self.policy.activate_relay_mapping(
            mappings[16].generation))
        self.policy.close_relay_mapping(mappings[0].generation)
        self.assertTrue(self.policy.activate_relay_mapping(
            mappings[16].generation))

    def test_control_flow_table_quota_fails_closed(self):
        for offset in range(384):
            self.policy.register_control_flow(
                'dns', 'UDP', '10.0.0.5', 55000 + offset,
                '10.0.0.1', 53)
        with self.assertRaises(RuntimeError):
            self.policy.register_control_flow(
                'dns', 'UDP', '10.0.0.5', 55999,
                '10.0.0.1', 53)

    def test_control_flow_expiry_and_suspend_revoke_state(self):
        token = self.policy.register_control_flow(
            'dns', 'UDP', '10.0.0.5', 56000,
            '10.0.0.1', 53, ttl=1)
        self.assertIsNotNone(self.policy.match_control_flow(
            'UDP', '10.0.0.5', 56000, '10.0.0.1', 53))
        self.clock.value += 2
        self.assertIsNone(self.policy.match_control_flow(
            'UDP', '10.0.0.5', 56000, '10.0.0.1', 53))
        self.policy.revoke_control_flow(token)

        self.policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 60)])
        self.policy.suspend()
        self.assertIsNone(self.policy.lease_for('93.184.216.34', 443))
        with self.assertRaises(RuntimeError):
            self.policy.register_control_flow(
                'dns', 'UDP', '10.0.0.5', 56001,
                '10.0.0.1', 53)

    def test_domain_and_port_matching_are_exact(self):
        self.assertEqual('api.deepseek.com',
                         self.policy.resolve_dns_rule('API.DEEPSEEK.COM.'))
        self.assertIsNone(
            self.policy.resolve_dns_rule('sub.api.deepseek.com'))
        self.policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 60)])
        self.assertIsNotNone(self.policy.lease_for('93.184.216.34', 443))
        self.assertIsNone(self.policy.lease_for('93.184.216.34', 80))

    def test_global_active_relay_quota_fails_closed(self):
        local_ips = ['10.0.2.%d' % value for value in range(1, 10)]
        policy = EgressPolicy(
            config(), local_ips, [], '10.0.0.1', self.clock)
        policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 60)])
        for offset in range(128):
            source = local_ips[offset // 16]
            mapping = policy.create_relay_mapping(
                source, 41000 + offset, '93.184.216.34', 443,
                source, 38927)
            self.assertIs(mapping, policy.consume_relay_target(
                source, 41000 + offset))
            self.assertTrue(policy.activate_relay_mapping(
                mapping.generation))
        overflow = policy.create_relay_mapping(
            local_ips[8], 52000, '93.184.216.34', 443,
            local_ips[8], 38927)
        self.assertIs(overflow, policy.consume_relay_target(
            local_ips[8], 52000))
        self.assertFalse(policy.activate_relay_mapping(
            overflow.generation))

    def test_takeover_activation_is_explicit_and_orphans_fail(self):
        self.assertFalse(self.policy.takeover_enabled)
        orphan = config()
        orphan['externaltakeoverdnsttl'] = '60'
        with self.assertRaises(PolicyConfigError):
            EgressPolicy(orphan, ['10.0.0.5'], [], '10.0.0.1')
        empty = takeover_config()
        empty['externaltakeoveripv4'] = ''
        with self.assertRaises(PolicyConfigError):
            EgressPolicy(empty, ['10.0.0.5'], [], '10.0.0.1')

    def test_takeover_accepts_only_single_rfc1918_ipv4(self):
        accepted = ('10.1.2.3', '172.16.0.1', '172.31.255.254',
                    '192.168.204.1')
        for value in accepted:
            candidate = takeover_config()
            candidate['externaltakeoveripv4'] = value
            policy = EgressPolicy(
                candidate, ['10.0.0.5'], [], '10.0.0.1')
            self.assertEqual(value, policy.takeover_ipv4)
        rejected = (
            '8.8.8.8', '127.0.0.1', '169.254.1.1', '224.0.0.1',
            '0.0.0.0', '255.255.255.255', 'example.com',
            '192.168.204.0/24', '192.168.204.1:443',
            'https://192.168.204.1', '::1')
        for value in rejected:
            candidate = takeover_config()
            candidate['externaltakeoveripv4'] = value
            with self.assertRaises(PolicyConfigError, msg=value):
                EgressPolicy(candidate, ['10.0.0.5'], [], '10.0.0.1')

    def test_takeover_rejects_local_resolver_and_policy_conflicts(self):
        candidate = takeover_config()
        with self.assertRaises(PolicyConfigError):
            EgressPolicy(candidate, ['192.168.204.1'], [], '10.0.0.1')
        with self.assertRaises(PolicyConfigError):
            EgressPolicy(candidate, ['10.0.0.5'], [], '192.168.204.1')
        candidate['externalnonallowedaction'] = 'drop'
        with self.assertRaises(PolicyConfigError):
            EgressPolicy(candidate, ['10.0.0.5'], [], '10.0.0.1')
        candidate = takeover_config()
        candidate['externalalloweddomains'] = 'example.com'
        with self.assertRaises(PolicyConfigError):
            EgressPolicy(candidate, ['10.0.0.5'], [], '10.0.0.1')

    def test_takeover_ttl_and_probe_validation(self):
        for ttl in ('1', '60', '300'):
            candidate = takeover_config()
            candidate['externaltakeoverdnsttl'] = ttl
            policy = EgressPolicy(
                candidate, ['10.0.0.5'], [], '10.0.0.1')
            self.assertEqual(int(ttl), policy.takeover_dns_ttl)
        for ttl in ('', '0', '301', '-1', '1.5'):
            candidate = takeover_config()
            candidate['externaltakeoverdnsttl'] = ttl
            with self.assertRaises(PolicyConfigError, msg=ttl):
                EgressPolicy(candidate, ['10.0.0.5'], [], '10.0.0.1')
        for ports, timeout in (('80,80', '500'), ('0', '500'),
                               ('80,,443', '500'), ('tcp/80', '500'),
                               ('80', '99'), ('80', '5001'),
                               ('80', 'not-an-int')):
            with self.assertRaises(PolicyConfigError):
                EgressPolicy(takeover_config(ports, timeout),
                             ['10.0.0.5'], [], '10.0.0.1')

    def test_takeover_sink_matching_is_exact_and_preserves_ports(self):
        policy = EgressPolicy(
            takeover_config(), ['10.0.0.5'], [], '10.0.0.1', self.clock)
        for proto in ('TCP', 'UDP'):
            for port in (1, 443, 65535):
                self.assertTrue(policy.matches_takeover_sink(
                    proto, '10.0.0.5', 50000, '192.168.204.1', port))
        self.assertFalse(policy.matches_takeover_sink(
            'TCP', '10.0.0.6', 50000, '192.168.204.1', 443))
        self.assertFalse(policy.matches_takeover_sink(
            'TCP', '10.0.0.5', 50000, '192.168.204.2', 443))
        self.assertFalse(policy.matches_takeover_sink(
            'ICMP', '10.0.0.5', 1, '192.168.204.1', 1))

    def test_takeover_suspend_does_not_destroy_deepseek_state(self):
        policy = EgressPolicy(
            takeover_config(), ['10.0.0.5'], [], '10.0.0.1', self.clock)
        policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 60)])
        self.assertTrue(policy.suspend_takeover('route_snapshot_changed'))
        self.assertFalse(policy.takeover_available())
        self.assertIsNotNone(policy.lease_for('93.184.216.34', 443))
        self.assertFalse(policy.matches_takeover_sink(
            'TCP', '10.0.0.5', 50000, '192.168.204.1', 443))

    def test_sink_becoming_local_suspends_only_takeover(self):
        policy = EgressPolicy(
            takeover_config(), ['10.0.0.5'], [], '10.0.0.1', self.clock)
        policy.replace_leases(
            'api.deepseek.com', [('93.184.216.34', 60)])
        self.assertTrue(policy.update_local_ipv4(
            ['10.0.0.5', '192.168.204.1']))
        self.assertFalse(policy.takeover_available())
        self.assertEqual('sink_became_local',
                         policy.takeover_settings()['suspend_reason'])
        self.assertIsNotNone(policy.lease_for('93.184.216.34', 443))

    def test_probe_configuration_never_enters_data_plane_state(self):
        first = EgressPolicy(
            takeover_config('', '500'), ['10.0.0.5'], [], '10.0.0.1')
        second = EgressPolicy(
            takeover_config('80,443', '1000'),
            ['10.0.0.5'], [], '10.0.0.1')
        self.assertEqual(first.takeover_settings(),
                         second.takeover_settings())
        self.assertEqual(
            first.matches_takeover_sink(
                'TCP', '10.0.0.5', 50000, '192.168.204.1', 8080),
            second.matches_takeover_sink(
                'TCP', '10.0.0.5', 50000, '192.168.204.1', 8080))
        self.assertFalse(hasattr(first, 'takeover_probe_ports'))


if __name__ == '__main__':
    unittest.main()
