"""Offline contracts for the real-traffic scenario-suite runner."""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile

import pytest


PATH = Path(__file__).parent / 'acceptance' / 'scenario_suite.py'
SPEC = importlib.util.spec_from_file_location('scenario_suite_test_module', PATH)
suite = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = suite
SPEC.loader.exec_module(suite)


def test_fixed_seed_generates_exact_complete_matrix():
    manifest = suite.build_manifest(20260912)
    assert suite.manifest_issues(manifest) == []
    coverage = suite.planned_coverage(manifest)
    assert coverage['scenario_count'] == 100
    assert coverage['bucket'] == {'B1': 25, 'B2': 20, 'B3': 20, 'B4': 20, 'default': 15}
    assert coverage['fault'] == {name: 3 for name in suite.FAULTS}
    assert all(value >= 5 for value in coverage['tool_distinct_scenarios'].values())
    assert all(len({item['tool'] for item in row['interface_call_plan']}) >= 10
               for row in manifest['scenarios'])


def test_seed_manifest_is_byte_stable_and_changes_only_with_seed():
    first = suite.canonical_bytes(suite.build_manifest(20260912))
    second = suite.canonical_bytes(suite.build_manifest(20260912))
    third = suite.canonical_bytes(suite.build_manifest(20260913))
    assert first == second
    assert first != third


def test_actual_coverage_uses_records_not_only_manifest():
    manifest = suite.build_manifest(20260912)
    records = []
    for row in manifest['scenarios']:
        records.append({
            'scenario_id': row['scenario_id'], 'state': 'pass', 'scenario': row,
            'interface_calls': [{'tool': item['tool'], 'expect': item['expect'], 'ok': True}
                                for item in row['interface_call_plan']],
        })
    actual = suite.actual_coverage(manifest, records)
    assert actual['pass'] == 100
    assert actual['fail'] == actual['blocked'] == 0
    assert actual['problems'] == []
    records.pop()
    assert 'missing actual scenario: sst-100' in suite.actual_coverage(manifest, records)['problems']


def test_result_integrity_rechecks_bound_evidence_bytes():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        evidence = root / 'evidence.json'
        evidence.write_bytes(b'{"proof":true}\n')
        probe = root / 'probe.jsonl'
        pktmon = root / 'pktmon.txt'
        pktmon_nic = root / 'pktmon-nic.json'
        runtime = root / 'runtime.pcap'
        runlog = root / 'run.log'
        probe.write_text('{"event":"close"}\n', encoding='utf-8')
        pktmon.write_text('pktmon\n', encoding='utf-8')
        pktmon_nic.write_text(json.dumps({
            'schema': suite.NIC_CAPTURE_SCHEMA,
            'pktmon_list': ' 9 00-0C-29-C1-CA-49 Intel(R) 82574L Gigabit Network Connection\n',
            'adapters': [{'ifIndex': 11, 'Name': 'Ethernet0',
                          'InterfaceDescription': 'Intel(R) 82574L Gigabit Network Connection',
                          'MacAddress': '00-0C-29-C1-CA-49', 'Status': 'Up'}],
            'pktmon_status_after': '数据包监视器没有运行。',
            'pktmon_counters_after': 'ETW Events Lost: 0\nPolicy Dropped: 8\n',
        }), encoding='utf-8')
        runtime.write_bytes(b'pcap')
        runlog.write_text('complete native run log\n', encoding='utf-8')
        calls = []
        for index, name in enumerate(suite.TOOLS[:10]):
            mutation = index >= 6
            args = {'command_id': 's-01-%03d' % index, 'expected_state_version': index + 1} if mutation else {}
            calls.append({'tool': name, 'ok': True, 'mutation': mutation,
                          'command_id': args.get('command_id'), 'sent_arguments': args,
                          'response': {}, 'expect': 'success'})
        calls.append({'tool': 'create_config', 'ok': False, 'mutation': True,
                      'command_id': 's-01-099',
                      'sent_arguments': {'command_id': 's-01-099', 'expected_state_version': 9},
                      'response': {'result': {}}, 'expect': 'reject_state_conflict',
                      'rejection_oracle': {'side_effect_free': True}})
        sections = {key: '' for key in ('dns_servers', 'routes', 'listen_ports', 'windivert_processes', 'services')}
        result = {
            'schema': suite.SCENARIO_SCHEMA, 'scenario_id': 'sst-001', 'state': 'pass',
            'scenario': {'fault_class': None}, 'interface_calls': calls,
            'traffic_evidence': {'capture_views': [{
                'path': 'evidence.json', 'size': evidence.stat().st_size,
                'sha256': hashlib.sha256(evidence.read_bytes()).hexdigest(),
            }, suite.file_record(probe, root), suite.file_record(pktmon, root), suite.file_record(pktmon_nic, root),
                suite.file_record(runtime, root), suite.file_record(runlog, root)]},
            'run_chain': [{'run_id': 'run-1', 'start_response': {'state': 'healthy'},
                           'capture': {'all_components': True, 'probe_path': 'probe.jsonl', 'pktmon_path': 'pktmon.txt',
                                       'pktmon_nic_path': 'pktmon-nic.json',
                                       'pktmon_binding': suite.pktmon_nic_binding(json.loads(pktmon_nic.read_text())),
                                       'pktmon_capture_issues': [],
                                       'files': [suite.file_record(probe, root), suite.file_record(pktmon, root),
                                                 suite.file_record(pktmon_nic, root)]},
                           'runtime_pcap': suite.file_record(runtime, root),
                           'originals': {'files': [suite.file_record(runlog, root)]},
                           'five_sections_before': sections, 'five_sections_after': sections,
                           'traffic_oracle': {'passed': True}, 'log_clean_issues': []}],
            'five_section_audit': {'before': sections, 'after': sections},
            'recovery': {'final_status': {'state': 'stopped', 'last_run_outcome': 'ok'}, 'cleanup_errors': []},
            'health_trace': {'samples': [{'status': {'state': 'healthy'}} for _ in range(3)]},
        }
        assert suite.result_issues(result, root) == []
        evidence.write_bytes(b'{"proof":false}\n')
        assert suite.result_issues(result, root)
        evidence.write_bytes(b'{"proof":true}\n')
        runlog.write_text('Traceback (most recent call last):\nboom\n', encoding='utf-8')
        assert 'benign complete run.log contains exception marker' in suite.result_issues(result, root)


def test_manifest_requires_real_axis_and_stale_rejection_contract():
    manifest = suite.build_manifest(20260912)
    assert {row['config_profile']['tempo'] for row in manifest['scenarios']} == {
        'hold', 'burst', 'stagger', 'drip', 'overlap'}
    assert all(any(item['expect'] == 'reject_state_conflict'
                   for item in row['interface_call_plan'])
               for row in manifest['scenarios'])
    restart = [row for row in manifest['scenarios'] if row['lifecycle_chain'] == 'restart']
    assert len(restart) >= 5
    for row in restart:
        names = [item['tool'] for item in row['interface_call_plan']]
        assert names.index('get_events') < names.index('restart')
        assert names.index('list_artifacts') < names.index('restart')


def test_manifest_rejects_duplicate_actual_behavior_without_id_or_ordinal():
    manifest = suite.build_manifest(20260912)
    duplicate = json.loads(json.dumps(manifest))
    first = duplicate['scenarios'][0]
    copied = json.loads(json.dumps(first))
    copied['scenario_id'] = duplicate['scenarios'][1]['scenario_id']
    duplicate['scenarios'][1] = copied
    assert any('duplicate actual behaviour' in issue for issue in suite.manifest_issues(duplicate))


def test_gate_command_never_assigns_powershell_automatic_pid_variable():
    runner = object.__new__(suite.Suite)
    runner.vm = object()
    seen = {}

    def fake_vm_json(command, timeout):
        seen['command'] = command
        seen['timeout'] = timeout
        return {'ready': True}, {'output': '{}'}

    runner._vm_json = fake_vm_json
    runner._run_gate('listener_stop', 'nonce', {'probe': r'C:\probe.jsonl', 'pid': 1234})
    assert '$probePid=[int]$est.pid' in seen['command']
    assert '$pid=[int]$est.pid' not in seen['command']
    assert "Select-String -Path $log -SimpleMatch -Pattern 'PROCESS_FLOW '" in seen['command']
    assert '(?:^|\\s)pid=' in seen['command']
    assert '(?:^|\\s)sport=' in seen['command']
    assert '(?:^|\\s)src=' in seen['command']
    # The deployed logger alphabetises fields; matching only a made-up
    # ``PROCESS_FLOW pid=`` prefix would skip this real recorded order.
    line = ('PROCESS_FLOW disposition=DIVERT_FAKE domain=- dport=1337 dst=198.51.100.77 '
            'pid=1234 process=powershell.exe proto=TCP sport=65425 src=192.168.204.233')
    assert all(re.search(r'(?:^|\s)%s=%s(?:\s|$)' % (key, value), line)
               for key, value in {'pid': '1234', 'sport': '65425',
                                  'src': '192.168.204.233'}.items())
    assert seen['timeout'] == 75


def test_pktmon_nic_binding_uses_current_component_catalogue_and_rejects_loss():
    capture = {
        'schema': suite.NIC_CAPTURE_SCHEMA,
        'pktmon_list': '网络适配器:\n 9 00-0C-29-C1-CA-49 Intel(R) 82574L Gigabit Network Connection\n',
        'adapters': [{'ifIndex': 11, 'Name': 'Ethernet0',
                      'InterfaceDescription': 'Intel(R) 82574L Gigabit Network Connection',
                      'MacAddress': '00:0C:29:C1:CA:49', 'Status': 'Up'}],
        'pktmon_status_after': '数据包监视器没有运行。',
        'pktmon_counters_after': 'ETW Events Lost: 0\nPolicy Dropped: 8\n',
    }
    binding = suite.pktmon_nic_binding(capture)
    assert binding['component_ids'] == [9]
    assert binding['bound_adapters'][0]['if_index'] == 11
    trace = 'MSNT_SystemTrace Header\r\nEventsLost: 0\r\nBuffersLost: 0\r\n'
    assert suite.pktmon_capture_issues(capture, trace) == []
    assert suite.pktmon_capture_issues(capture, trace.replace('EventsLost: 0', 'EventsLost: 1')) == [
        'pktmon exported trace reports lost ETW events/buffers']


def test_process_flow_matching_uses_structured_fields_not_logger_order():
    line = ('PROCESS_FLOW disposition=DIVERT_FAKE domain=- dport=1337 dst=198.51.100.77 '
            'pid=1316 process=powershell.exe proto=TCP sport=65425 src=192.168.204.233')
    fields = suite.Suite._log_fields(line)
    assert fields['pid'] == '1316'
    assert fields['src'] == '192.168.204.233'
    assert fields['sport'] == '65425'


def test_b2_traffic_oracle_requires_each_released_case_flow_and_fnpr_receipt():
    """A B2 pass needs reviewed, sink and private-deny evidence separately."""
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        runner = object.__new__(suite.Suite)
        runner.root = root
        profile = suite.materialize_probe_profile(suite.profile_for_bucket('B2', 25), '60.28.220.199')
        nonce = 'oracle-b2'
        expected = {'profile': profile['bucket'], 'variant': profile['variant'],
                    'tempo': profile['tempo'], 'interleave': profile['interleave'],
                    'cadence_ms': profile['cadence_ms'],
                    'target_host': profile['probe_target']['host'],
                    'target_port': profile['probe_target']['port'],
                    'target_protocol': profile['probe_target']['protocol'],
                    'process_mode': profile['probe_target']['process_mode'], 'fnpr_role': '',
                    'startup_retry_seconds': profile['startup_retry_seconds'],
                    'additional_targets': list(profile['probe_cases'])}
        rows = [dict(event='ready', nonce=nonce, **expected),
                {'event': 'released', 'nonce': nonce, 'interleave': profile['interleave']},
                {'event': 'established', 'nonce': nonce, 'connection_id': 'main', 'pid': 777,
                 'src': '192.168.204.233:5000', 'dst': '60.28.220.199:443',
                 'actual_dst': '60.28.220.199:443'},
                {'event': 'send', 'nonce': nonce, 'connection_id': 'main', 'pid': 777,
                 'cadence_ms': profile['cadence_ms'], 'utc_ticks': 1_000_000_000},
                {'event': 'send', 'nonce': nonce, 'connection_id': 'main', 'pid': 777,
                 'cadence_ms': profile['cadence_ms'], 'utc_ticks': 1_000_000_000 + profile['cadence_ms'] * 10_000},
                {'event': 'close', 'nonce': nonce, 'connection_id': 'main', 'pid': 777},
                {'event': 'cases_released', 'nonce': nonce, 'phase': 'after-healthy', 'count': 2},
                {'event': 'case_established', 'nonce': nonce, 'case_index': 1, 'connection_id': 'case-1',
                 'pid': 777, 'src': '192.168.204.233:5001', 'actual_dst': '192.168.204.1:443'},
                {'event': 'case_send', 'nonce': nonce, 'case_index': 1, 'connection_id': 'case-1', 'pid': 777},
                {'event': 'case_response', 'nonce': nonce, 'case_index': 1, 'connection_id': 'case-1',
                 'pid': 777, 'response': 'FNPR/1|oracle-b2|OK\n'},
                {'event': 'case_close', 'nonce': nonce, 'case_index': 1, 'connection_id': 'case-1', 'pid': 777},
                {'event': 'case_established', 'nonce': nonce, 'case_index': 2, 'connection_id': 'case-2',
                 'pid': 777, 'src': '192.168.204.233:5002', 'actual_dst': '10.20.30.41:1337'},
                {'event': 'case_send', 'nonce': nonce, 'case_index': 2, 'connection_id': 'case-2', 'pid': 777},
                {'event': 'case_close', 'nonce': nonce, 'case_index': 2, 'connection_id': 'case-2', 'pid': 777}]
        (root / 'probe.jsonl').write_text('\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
        (root / 'pktmon.txt').write_text('pktmon fixture\n', encoding='utf-8')
        log = ('EGRESS_CONTROL_READY\n'
               'PROCESS_FLOW disposition=ALLOW_REVIEWED_IP dport=443 dst=60.28.220.199 pid=777 proto=TCP sport=5000 src=192.168.204.233\n'
               'ALLOW_REVIEWED_IP_FIRST_FLOW dport=443 ip=60.28.220.199 pid=777 sport=5000 src=192.168.204.233\n'
               'PROCESS_FLOW disposition=ALLOW_TAKEOVER_SINK dport=443 dst=192.168.204.1 pid=777 proto=TCP sport=5001 src=192.168.204.233\n'
               'ALLOW_TAKEOVER_SINK dport=443 ip=192.168.204.1 sport=5001\n'
               'PROCESS_FLOW disposition=DIVERT_FAKE dport=1337 dst=10.20.30.41 pid=777 proto=TCP sport=5002 src=192.168.204.233\n'
               'DIVERT_FAKE original_ip=10.20.30.41 original_port=1337\n')
        (root / 'run.log').write_text(log, encoding='utf-8')

        def packets(capture, src, dst, protocol):
            nic = [{'component': 9}] if dst in ('60.28.220.199:443', '192.168.204.1:443') else []
            return ([{'src': src, 'dst': dst, 'protocol': protocol}], nic, {'component_ids': [9]})

        runner._pktmon_observations = packets
        run = {'capture': {'probe_path': 'probe.jsonl', 'pktmon_path': 'pktmon.txt'},
               'originals': {'files': [{'path': 'run.log'}]}}
        sentinel = {'rows': [{'event': 'probe_ok', 'nonce': nonce, 'role': 'target',
                              'transport': 'tcp', 'peer': '192.168.204.233:5001'}]}
        assert runner._traffic_oracle(run, profile, nonce, sentinel)['passed']
        (root / 'run.log').write_text(log.replace('ALLOW_TAKEOVER_SINK dport=443 ip=192.168.204.1 sport=5001\n', ''),
                                      encoding='utf-8')
        assert not runner._traffic_oracle(run, profile, nonce, sentinel)['passed']


def test_positive_curl_branch_binds_its_pid_flow_and_outer_nic_tuple():
    """The B1/B4 curl path cannot pass from an unrelated relay event."""
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        runner = object.__new__(suite.Suite)
        runner.root = root
        # The reviewed primary keeps this fixture compact; assigning B1 makes
        # the oracle execute the positive-curl branch under test.
        profile = suite.materialize_probe_profile(suite.profile_for_bucket('B2', 25), '60.28.220.199')
        profile['bucket'] = 'B1'
        nonce = 'oracle-curl'
        ready = {'event': 'ready', 'nonce': nonce, 'profile': 'B1', 'variant': profile['variant'],
                 'tempo': profile['tempo'], 'interleave': profile['interleave'],
                 'cadence_ms': profile['cadence_ms'], 'target_host': '60.28.220.199',
                 'target_port': 443, 'target_protocol': 'tls', 'process_mode': 'match',
                 'fnpr_role': '', 'startup_retry_seconds': profile['startup_retry_seconds'],
                 'additional_targets': list(profile['probe_cases'])}
        rows = [ready, {'event': 'released', 'nonce': nonce, 'interleave': profile['interleave']},
                {'event': 'established', 'nonce': nonce, 'connection_id': 'main', 'pid': 777,
                 'src': '192.168.204.233:5000', 'dst': '60.28.220.199:443', 'actual_dst': '60.28.220.199:443'},
                {'event': 'send', 'nonce': nonce, 'connection_id': 'main', 'pid': 777,
                 'cadence_ms': profile['cadence_ms'], 'utc_ticks': 1_000_000_000},
                {'event': 'send', 'nonce': nonce, 'connection_id': 'main', 'pid': 777,
                 'cadence_ms': profile['cadence_ms'], 'utc_ticks': 1_000_000_000 + profile['cadence_ms'] * 10_000},
                {'event': 'close', 'nonce': nonce, 'connection_id': 'main', 'pid': 777},
                {'event': 'cases_released', 'nonce': nonce, 'phase': 'after-healthy', 'count': 2},
                {'event': 'case_established', 'nonce': nonce, 'case_index': 1, 'connection_id': 'case-1', 'pid': 777,
                 'src': '192.168.204.233:5001', 'actual_dst': '192.168.204.1:443'},
                {'event': 'case_send', 'nonce': nonce, 'case_index': 1, 'connection_id': 'case-1', 'pid': 777},
                {'event': 'case_response', 'nonce': nonce, 'case_index': 1, 'connection_id': 'case-1', 'pid': 777,
                 'response': 'FNPR/1|oracle-curl|OK\n'},
                {'event': 'case_close', 'nonce': nonce, 'case_index': 1, 'connection_id': 'case-1', 'pid': 777},
                {'event': 'case_established', 'nonce': nonce, 'case_index': 2, 'connection_id': 'case-2', 'pid': 777,
                 'src': '192.168.204.233:5002', 'actual_dst': '10.20.30.41:1337'},
                {'event': 'case_send', 'nonce': nonce, 'case_index': 2, 'connection_id': 'case-2', 'pid': 777},
                {'event': 'case_close', 'nonce': nonce, 'case_index': 2, 'connection_id': 'case-2', 'pid': 777},
                {'event': 'curl_started', 'nonce': nonce, 'pid': 888},
                {'event': 'curl_completed', 'nonce': nonce, 'pid': 888, 'exit_code': 0, 'http_code': '404'}]
        (root / 'probe.jsonl').write_text('\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
        (root / 'pktmon.txt').write_text('pktmon fixture\n', encoding='utf-8')
        log = ('EGRESS_CONTROL_READY\n'
               'PROCESS_FLOW disposition=ALLOW_REVIEWED_IP dport=443 dst=60.28.220.199 pid=777 proto=TCP sport=5000 src=192.168.204.233\n'
               'ALLOW_REVIEWED_IP_FIRST_FLOW dport=443 ip=60.28.220.199 pid=777 sport=5000 src=192.168.204.233\n'
               'PROCESS_FLOW disposition=ALLOW_TAKEOVER_SINK dport=443 dst=192.168.204.1 pid=777 proto=TCP sport=5001 src=192.168.204.233\n'
               'ALLOW_TAKEOVER_SINK dport=443 ip=192.168.204.1 sport=5001\n'
               'PROCESS_FLOW disposition=DIVERT_FAKE dport=1337 dst=10.20.30.41 pid=777 proto=TCP sport=5002 src=192.168.204.233\n'
               'DIVERT_FAKE original_ip=10.20.30.41 original_port=1337\n'
               'PROCESS_FLOW disposition=REINJECT_LOCAL dport=443 dst=60.28.220.199 pid=888 proto=TCP sport=5003 src=192.168.204.233\n'
               'TLS_SNI_ALLOW domain=api.deepseek.com original_ip=60.28.220.199\n'
               'ALLOW_INTERNAL_UPSTREAM ip=60.28.220.199 kind=tls_relay port=443 sport=38900\n')
        (root / 'run.log').write_text(log, encoding='utf-8')

        def packets(capture, src, dst, protocol):
            nic = ([{'component': 9}] if src.endswith(':38900') or src.endswith(':5000') or
                   src.endswith(':5001') else [])
            return ([{'src': src, 'dst': dst, 'protocol': protocol}], nic, {'component_ids': [9]})

        runner._pktmon_observations = packets
        run = {'capture': {'probe_path': 'probe.jsonl', 'pktmon_path': 'pktmon.txt'},
               'originals': {'files': [{'path': 'run.log'}]}}
        sentinel = {'rows': [{'event': 'probe_ok', 'nonce': nonce, 'role': 'target',
                              'transport': 'tcp', 'peer': '192.168.204.233:5001'}]}
        assert runner._traffic_oracle(run, profile, nonce, sentinel)['passed']
        (root / 'run.log').write_text(log.replace('ALLOW_INTERNAL_UPSTREAM ip=60.28.220.199 kind=tls_relay port=443 sport=38900\n', ''),
                                      encoding='utf-8')
        assert not runner._traffic_oracle(run, profile, nonce, sentinel)['passed']


def test_auxiliary_cases_are_released_for_any_healthy_primary_interleave():
    """B1/B2/B4 boundary cases wait for health, independently of primary timing."""
    runner = object.__new__(suite.Suite)
    calls = []

    def release(capture, profile):
        calls.append(('release', capture, profile['interleave']))
        return {'phase': 'after-healthy'}

    def await_cases(capture, profile, count):
        calls.append(('await', capture, count))
        return {'case_close_count': count}

    runner._release_probe_cases = release
    runner._await_probe_cases = await_cases
    profile = {'interleave': 'before-start',
               'negative_cases': ({'expectation': 'deny'},),
               'probe_cases': ({'expectation': 'takeover_allow'},)}
    run = {}
    runner._run_auxiliary_cases(run, {'case': 'probe.cases'}, profile)
    assert calls == [('release', {'case': 'probe.cases'}, 'before-start'),
                     ('await', {'case': 'probe.cases'}, 2)]
    assert run == {'case_release': {'phase': 'after-healthy'},
                   'case_completion': {'case_close_count': 2}}


def test_fault_cleanup_binds_probe_residue_to_recorded_pid_creation_and_scm_host():
    """Fault cleanup must distinguish a restored MCP host from suite probes.

    The guest probe log is the immutable source for both the PowerShell
    launcher and B3's native child.  A process with either identity still
    present must be reported, while only the SCM-owned ``fakenetng-mcp.exe
    run`` host is permitted to remain after restoration.
    """
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        nonce = 'fault-nonce'
        (root / 'probe.jsonl').write_text(
            '\n'.join(json.dumps(row) for row in (
                {'event': 'ready', 'nonce': nonce, 'pid': 4100,
                 'creation_ticks': 638932111000000000},
                {'event': 'process_ready', 'nonce': nonce, 'pid': 4101,
                 'creation_ticks': 638932111100000000},
            )) + '\n', encoding='utf-8')
        runner = object.__new__(suite.Suite)
        runner.root = root
        runner.vm = object()
        run = {'capture': {'probe_path': 'probe.jsonl', 'probe_launcher_pid': 4100}}
        expected = runner._recorded_probe_identities(run, nonce)
        assert expected == [
            {'pid': 4100, 'creation_ticks': 638932111000000000, 'event': 'ready'},
            {'pid': 4101, 'creation_ticks': 638932111100000000, 'event': 'process_ready'},
        ]
        seen = {}

        def vm_json(command, timeout):
            seen['command'] = command
            seen['timeout'] = timeout
            return ({'state': {'needs_recovery': False}, 'managed_processes': [],
                     'probe_processes': [], 'unknown_related_processes': [],
                     'expected_probes': expected,
                     'query_identity': {'ProcessId': 5099, 'creation_ticks': 638932112000000000,
                                        'Name': 'powershell'},
                     'query_process': [{'ProcessId': 5099, 'creation_ticks': 638932112000000000,
                                        'Name': 'powershell'}],
                     'process_identity_races': [], 'relevant_identity_races': [],
                     'service_host': [{'ProcessId': 1772, 'Name': 'fakenetng-mcp.exe',
                                       'CommandLine': '"C:\\Program Files\\FakeNet-NG-MCP\\fakenetng-mcp.exe" run'}],
                     'fault_exists': False, 'pktmon': '数据包监视器没有运行。'},
                    {'output': '{}'})

        runner._vm_json = vm_json
        observed, _ = runner._cleanup_native(run, nonce)
        assert observed['expected_probes'] == expected
        assert observed['probe_processes'] == []
        assert seen['timeout'] == 90
        # The generated guest query is the public boundary: it receives the
        # exact recorded identities, queries CIM command lines and creation
        # times, preserves the SCM host only by service PID, and emits unknown
        # scenario/native residue into the rejecting probe list.
        assert 'Get-CimInstance Win32_Process' in seen['command']
        assert 'Get-Process -Id $snapshot.ProcessId' in seen['command']
        assert '$nativeTicks=[Int64]$native.StartTime.ToUniversalTime().Ticks' in seen['command']
        assert 'process_identity_races' in seen['command']
        assert 'relevant_identity_races' in seen['command']
        assert 'CommandLine=$snapshot.CommandLine' in seen['command']
        assert 'relevant_process_identity_race' in seen['command']
        assert 'scenario-suite-20260912' in seen['command']
        assert 'scenario-probe-client' in seen['command']
        assert '$service.ProcessId' in seen['command']
        assert 'unknown_related_processes' in seen['command']
        # The querying PowerShell process contains these marker strings in its
        # own command line.  It is excluded by its exact live PID/creation
        # tuple only; an unrelated process that reused an old probe PID is
        # instead retained as a non-residue observation.
        assert '$selfPid=$PID' in seen['command']
        assert '$selfTicks=[Int64]' in seen['command']
        assert 'query_identity' in seen['command']
        assert 'query_process' in seen['command']
        assert 'pid_reuse_nonresidue' in seen['command']
        assert 'recorded_probe_pid_reused_with_different_creation' not in seen['command']


def test_host_only_transfer_serves_only_the_staged_probe_and_stops(monkeypatch):
    """Staging must never expose a directory or leave a host-only listener running."""
    created = []

    class FakeServer:
        def __init__(self, address, handler):
            created.append((address, handler))
            self.server_address = (address[0], 31337)
            self.daemon_threads = False
            self.shutdown_called = False
            self.close_called = False

        def serve_forever(self):
            return

        def shutdown(self):
            self.shutdown_called = True

        def server_close(self):
            self.close_called = True

    monkeypatch.setattr(suite.http.server, 'ThreadingHTTPServer', FakeServer)
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / 'scenario_probes.ps1'
        source.write_bytes(b'probe-bytes')
        with suite.HostOnlyFileTransfer(source, 'scenario_probes.ps1') as transfer:
            assert transfer.url.startswith('http://192.168.204.1:')
            assert transfer.url.endswith('/scenario_probes.ps1')
            assert transfer.sha256 == hashlib.sha256(b'probe-bytes').hexdigest()
            assert transfer.record()['stopped'] is False
        record = transfer.record()
        assert record['bind'] == '192.168.204.1'
        assert record['bytes'] == len(b'probe-bytes')
        assert record['stopped'] is True
        assert created[0][0] == ('192.168.204.1', 0)
        assert transfer.server.shutdown_called and transfer.server.close_called


def test_command_ids_are_unique_across_preserved_suite_roots():
    args = ['generate', '--candidate-id', 'candidate', '--source-commit', 'source',
            '--package-sha256', '0' * 64]
    first = suite.Suite(suite.parse_args([*args, '--suite-root', '/tmp/suite-first']))
    retry = suite.Suite(suite.parse_args([*args, '--suite-root', '/tmp/suite-retry']))
    assert first._command_id('preflight', 1, 1) != retry._command_id('preflight', 1, 1)
    assert first._command_id('sst-001', 1, 3) == first._command_id('sst-001', 1, 3)


def test_vm_transport_ignores_sse_heartbeats_but_rejects_ambiguous_events():
    payload = ': ping\n\nevent: message\ndata: {"jsonrpc":"2.0","result":{}}\n\n'
    assert suite.RawMcp._decode_event_stream(payload) == '{"jsonrpc":"2.0","result":{}}'
    with pytest.raises(suite.SuiteError):
        suite.RawMcp._decode_event_stream('data: {}\n\ndata: {}\n\n')


def test_verify_and_summary_fail_closed_on_incomplete_duplicate_extra_and_fault_raw_inputs():
    with tempfile.TemporaryDirectory() as temp:
        args = suite.parse_args([
            'verify', '--integrity', '--suite-root', temp,
            '--candidate-id', 'candidate', '--source-commit', 'source', '--package-sha256', '0' * 64,
        ])
        runner = suite.Suite(args)
        runner.generate()
        missing = runner.verify()
        assert not missing['passed']
        assert 'missing actual scenario: sst-001' in missing['problems']
        results = Path(temp) / 'results'
        results.mkdir()
        payload = {'schema': suite.SCENARIO_SCHEMA, 'scenario_id': 'sst-001', 'identity': runner.identity.as_dict()}
        (results / 'scenario-sst-001.json').write_text(json.dumps(payload), encoding='utf-8')
        (results / 'scenario-copy.json').write_text(json.dumps(payload), encoding='utf-8')
        extra = dict(payload, scenario_id='sst-999')
        (results / 'scenario-sst-999.json').write_text(json.dumps(extra), encoding='utf-8')
        verification = runner.verify()
        assert not verification['passed']
        assert 'duplicate actual scenario id: sst-001' in verification['problems']
        assert 'extra actual scenario: sst-999' in verification['problems']
        assert not runner.summary()['passed']
        assert suite.fault_recheck_issues({'scenario': {'fault_class': 'listener_stop'},
                                           'fault_evidence': {'adjudication': {}}}, Path(temp))


def test_result_verifier_rejects_missing_runtime_obligations():
    result = {'schema': suite.SCENARIO_SCHEMA, 'scenario_id': 'sst-001', 'state': 'pass',
              'scenario': {'fault_class': None}, 'interface_calls': [],
              'traffic_evidence': {'capture_views': []}, 'run_chain': [],
              'five_section_audit': {}, 'recovery': {}, 'health_trace': {}}
    issues = suite.result_issues(result, Path('.'))
    assert 'per-run independent probe/pktmon evidence missing' not in issues  # no run gets its own error
    assert 'run chain missing' in issues
    assert 'stale optimistic-lock rejection is not preserved/proved' in issues


def test_b3_requires_a_real_probe_executable_identity():
    profile = suite.profile_for_bucket('B3', 0)
    try:
        suite.profile_content(profile, '8.8.8.8')
    except suite.Blocked as exc:
        assert 'probe executable identity' in str(exc)
    else:
        raise AssertionError('B3 accepted an unbound process image')


def test_generate_cli_creates_only_manifest_and_planned_coverage():
    with tempfile.TemporaryDirectory() as temp:
        code = suite.main([
            'generate', '--candidate-id', 'mcp-test', '--source-commit', 'deadbeef',
            '--package-sha256', '0' * 64, '--suite-root', temp, '--regen-check',
        ])
        assert code == 0
        assert (Path(temp) / 'scenario-manifest.json').is_file()
        assert (Path(temp) / 'planned-coverage-report.json').is_file()
        assert not (Path(temp) / 'results').exists()


def test_fault_case_adapter_builds_from_sealed_raw_listener_capture():
    adapter_path = Path(__file__).parent / 'acceptance' / 'scenario_fault_evidence.py'
    adapter_spec = importlib.util.spec_from_file_location('scenario_fault_evidence_test_module', adapter_path)
    adapter = importlib.util.module_from_spec(adapter_spec)
    sys.modules[adapter_spec.name] = adapter
    adapter_spec.loader.exec_module(adapter)
    root = Path('Logs/fakenetng-mcp/scenario-suite-20260912/spike-evidence-contract/attempt-relay-8e4d664-20260912')
    if not root.is_dir():
        return  # this repository keeps the fixture as local acceptance evidence
    record = json.loads((root / 'listener_stop.json').read_text(encoding='utf-8'))
    run_id = record['capture']['run_id']
    audit = next((root / 'recovery-audits').glob('recovery-audit-' + run_id + '-*.jsonl'))
    capture = {'scenario_id': 'fixture-listener', 'candidate_id': 'mcp-c8e4d664b-a458787e6e92',
               'run_id': run_id, 'fault': 'listener_stop', 'nonce': record['nonce'],
               'raw': {'receipt': 'listener_stop/fault-triggered.json',
                       'receipt_metadata': 'listener_stop/vm-file-metadata.json',
                       'ipc': 'listener_stop/ipc-parent.jsonl', 'run_log': 'listener_stop/run.log',
                       'probe': 'listener_stop/listener_stop-probe.jsonl',
                       'pktmon': 'listener_stop/listener_stop-pktmon.txt',
                       'baseline': 'baseline-sections.json',
                       'recovery_audit': str(audit.relative_to(root)),
                       'recovery_healthy': 'recovery-default.json', 'cleanup': 'cleanup-native.json',
                       'terminal': 'listener_stop.json'}}
    case = adapter.build_case(root, capture)
    assert case['candidate_id'] == capture['candidate_id']
    assert case['session']['packet_refs']
    assert all(item['path'] for item in case['files'])


def test_fault_packet_refs_require_the_full_directional_tuple():
    adapter_path = Path(__file__).parent / 'acceptance' / 'scenario_fault_evidence.py'
    adapter_spec = importlib.util.spec_from_file_location('scenario_fault_packet_tuple_module', adapter_path)
    adapter = importlib.util.module_from_spec(adapter_spec)
    sys.modules[adapter_spec.name] = adapter
    adapter_spec.loader.exec_module(adapter)
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        pktmon = root / 'pktmon.txt'
        pktmon.write_text(
            '[header]\n'
            ' 192.168.204.233.51234 > 198.51.100.77.1337: Flags [F.]\n'
            '[remote-fin]\n'
            ' 198.51.100.77.1337 > 192.168.204.233.51234: Flags [F.]\n'
            '[other]\n'
            ' 192.168.204.233.512345 > 198.51.100.77.1337: Flags [F.]\n'
            '[wrong-destination]\n'
            ' 192.168.204.233.51234 > 198.51.100.78.1337: Flags [F.]\n',
            encoding='utf-8')
        refs = adapter._packet_refs(pktmon, root, '192.168.204.233:51234', '198.51.100.77:1337')
        assert len(refs) == 2
