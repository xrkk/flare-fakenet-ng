"""Offline contracts for the real-traffic scenario-suite runner."""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types

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
            'scenario': {'fault_class': None, 'config_profile': suite.profile_for_bucket('default', 0)}, 'interface_calls': calls,
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
    # The observer must skip runs whose run.log is not yet created instead of
    # surfacing a terminating path error (discovery100-109 sst-003). The
    # guard is a statement: Windows PowerShell 5.1 parses `@(if(...){...})`
    # as a ParserError, which killed the whole observer (discovery100-111).
    assert "$flow=@();if(Test-Path -LiteralPath $log){$flow=@(Select-String -LiteralPath $log -SimpleMatch -Pattern @('PROCESS_FLOW ','PROCESS_REDIRECT_MAPPING_CREATED') " in seen['command']
    # B3 mapping rows spell the tuple source_ipv4/source_port; the observer
    # must require the pid on both field families (discovery100-114 sst-035).
    assert "source_port='+[regex]::Escape($port)" in seen['command']
    assert "source_ipv4='+[regex]::Escape($source)" in seen['command']
    assert '@(if(' not in seen['command']
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


def test_pktmon_window_ends_at_diverter_stop_boundary(tmp_path):
    run_log = (
        '2026-09-15 08:36:24,045 INFO FakeNet STOP_PHASE_BEGIN phase=complete\n'
        '2026-09-15 08:36:24,045 INFO FakeNet STOP_PHASE_BEGIN phase=policy_suspend\n'
        '2026-09-15 08:36:26,624 INFO FakeNet STOP_PHASE_BEGIN phase=diverter\n'
        '2026-09-15 08:36:26,726 INFO FakeNet STOP_PHASE_END phase=diverter elapsed_ms=108 healthy=True\n')
    assert suite.Suite._diverter_stop_boundary(run_log) == '2026-09-15 08:36:26.624'
    # A wedged stop (injected policy_pause) never reaches the diverter phase
    # and keeps whole-capture accounting.
    assert suite.Suite._diverter_stop_boundary(
        '2026-09-15 08:36:24,045 INFO FakeNet STOP_PHASE_BEGIN phase=complete\n') is None
    assert suite.Suite._diverter_stop_boundary('') is None

    header = ('[00]2070.1620::%s [Microsoft-Windows-PktMon] PktGroupId 42351，'
              'PktNumber 1，出现 8，方向 Tx ，类型 以太网 ，组件 %d，边缘 1，筛选器 0，'
              'OriginalSize 97，LoggedSize 97 \n'
              '\t00-0C-29-C1-CA-49 > 00-50-56-E7-FE-AA, ethertype IPv4 (0x0800), '
              'length 97: 192.168.204.233.57605 > 123.125.246.121.443: UDP, length 55\n')
    text = ('MSNT_SystemTrace Header\r\nEventsLost: 0\r\nBuffersLost: 0\r\n' +
            header % ('2026-09-15 08:36:10.0000000', 20) +
            header % ('2026-09-15 08:36:26.6230000', 9) +
            header % ('2026-09-15 08:36:26.6582542', 9) +
            header % ('2026-09-15 08:37:11.6032347', 9))
    (tmp_path / 'pktmon.txt').write_bytes(text.encode('utf-16'))
    metadata = {
        'schema': suite.NIC_CAPTURE_SCHEMA,
        'pktmon_list': '网络适配器:\n 9 00-0C-29-C1-CA-49 Intel(R) 82574L Gigabit Network Connection\n',
        'adapters': [{'ifIndex': 11, 'Name': 'Ethernet0',
                      'InterfaceDescription': 'Intel(R) 82574L Gigabit Network Connection',
                      'MacAddress': '00-0C-29-C1-CA-49', 'Status': 'Up'}],
        'pktmon_status_after': '数据包监视器没有运行。',
        'pktmon_counters_after': 'ETW Events Lost: 0\nPolicy Dropped: 8\n',
    }
    (tmp_path / 'pktmon-nic.json').write_text(json.dumps(metadata))
    runner = suite.Suite.__new__(suite.Suite)
    runner.root = tmp_path
    capture = {'pktmon_path': 'pktmon.txt', 'pktmon_nic_path': 'pktmon-nic.json'}
    flow = ('192.168.204.233:57605', '123.125.246.121:443', 'UDP')
    all_packets, nic_packets, binding = runner._pktmon_observations(capture, *flow)
    assert len(all_packets) == 4
    assert len(nic_packets) == 3
    unbounded_nic_trace = [p['timestamp_local'] for p in nic_packets]
    windowed_all, windowed_nic, _ = runner._pktmon_observations(
        capture, *flow, not_after_local='2026-09-15 08:36:26.624')
    # Post-stop stragglers stop being leak evidence once the product can no
    # longer filter; pre-teardown observations (including the last instant
    # before the boundary, and any NIC hit among them) stay counted.
    assert [p['timestamp_local'] for p in windowed_all] == [
        '2026-09-15 08:36:10.0000000', '2026-09-15 08:36:26.6230000']
    assert [p['timestamp_local'] for p in windowed_nic] == [
        '2026-09-15 08:36:26.6230000']
    assert unbounded_nic_trace == [
        '2026-09-15 08:36:26.6230000', '2026-09-15 08:36:26.6582542',
        '2026-09-15 08:37:11.6032347']


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

        def packets(capture, src, dst, protocol, not_after_local=None, not_before_local=None):
            nic = [{'component': 9}] if dst in ('60.28.220.199:443', '192.168.204.1:443') else []
            return ([{'src': src, 'dst': dst, 'protocol': protocol}], nic, {'component_ids': [9]})

        runner._pktmon_observations = packets
        run = {'capture': {'probe_path': 'probe.jsonl', 'pktmon_path': 'pktmon.txt'},
               'originals': {'files': [{'path': 'run.log'}]}}
        sentinel = {'rows': [{'event': 'probe_ok', 'nonce': nonce, 'role': 'target',
                              'transport': 'tcp', 'peer': '192.168.204.233:5001'}]}
        assert runner._traffic_oracle(run, profile, nonce, sentinel)['passed']
        # A UDP deny for the same destination must not prove a TCP relay
        # connection was diverted (candidate08 sst-004 auxiliary case 4).
        unrelated_deny = log.replace(
            'PROCESS_FLOW disposition=DIVERT_FAKE dport=1337 dst=10.20.30.41 pid=777 proto=TCP sport=5002',
            'PROCESS_FLOW disposition=REDIRECT_TLS_RELAY dport=1337 dst=10.20.30.41 pid=777 proto=TCP sport=5002')
        unrelated_deny += ('PROCESS_FLOW disposition=DIVERT_FAKE dport=1337 dst=10.20.30.41 '
                          'pid=777 proto=UDP sport=5009 src=192.168.204.233\n')
        (root / 'run.log').write_text(unrelated_deny, encoding='utf-8')
        assert not runner._traffic_oracle(run, profile, nonce, sentinel)['cases'][1]['passed']
        (root / 'run.log').write_text(log.replace('ALLOW_TAKEOVER_SINK dport=443 ip=192.168.204.1 sport=5001\n', ''),
                                      encoding='utf-8')
        assert not runner._traffic_oracle(run, profile, nonce, sentinel)['passed']


def _b1_sni_oracle_fixture(root, *, handshake_sni='example.com', deny_sni=None,
                           deny_generation='2', deny_reason='ClientHelloError',
                           deny_reason_code='sni_mismatch', deny_original_ip='119.188.175.46',
                           deny_domain='api.deepseek.com', deny_sport='50161',
                           deny_timestamp='2026-09-21 11:38:56,286',
                           extra_lines=(),
                           observation_contract='con008', case4_nic=False,
                           drop_reason_code=False, drop_generation=False,
                           observation_end_lower_delay_ms=400,
                           observation_identity_error=False,
                           native_deny=None, native_shift_ns=None,
                           native_duplicate=False, native_unsupported=False,
                           etw_window_ms=(-30, 10),
                           curl_allow_line=True):
    """B1 fixture whose auxiliary case 4 is the planned SNI-deny case.

    Returns (runner, profile, nonce, run, sentinel, deny_line, deny_ns).
    Everything the strict binding needs (probe ticks, exact-tuple
    PROCESS_FLOW, relay deny line) is realistic; the pktmon seam is stubbed
    and the con008 observation seam returns a structurally realistic
    observation whose end_lower_ns derives from the deny instant (the
    unmocked path is covered by a separate reconstruction test).
    """
    import datetime as _dt
    runner = object.__new__(suite.Suite)
    runner.root = root
    profile = suite.materialize_probe_profile(suite.profile_for_bucket('B1', 0), '60.28.220.199')
    nonce = 'oracle-b1-sni'
    expected = {'profile': profile['bucket'], 'variant': profile['variant'],
                'tempo': profile['tempo'], 'interleave': profile['interleave'],
                'cadence_ms': profile['cadence_ms'],
                'target_host': profile['probe_target']['host'],
                'target_port': profile['probe_target']['port'],
                'target_protocol': profile['probe_target']['protocol'],
                'process_mode': profile['probe_target'].get('process_mode', 'match'),
                'fnpr_role': profile['probe_target'].get('fnpr_role', ''),
                'startup_retry_seconds': profile.get('startup_retry_seconds', 70),
                'additional_targets': list(profile['negative_cases'])}

    def ticks(hour, minute, second, millis):
        stamp = _dt.datetime(2026, 9, 21, hour, minute, second, millis * 1000,
                             tzinfo=_dt.timezone.utc)
        return 621355968000000000 + int(stamp.timestamp() * 10**7)

    rows = [dict(event='ready', nonce=nonce, **expected),
            {'event': 'released', 'nonce': nonce, 'interleave': profile['interleave']},
            {'event': 'established', 'nonce': nonce, 'connection_id': 'main', 'pid': 777,
             'src': '192.168.204.233:5000', 'dst': '60.28.220.199:443',
             'actual_dst': '60.28.220.199:443'},
            {'event': 'send', 'nonce': nonce, 'connection_id': 'main', 'pid': 777,
             'cadence_ms': profile['cadence_ms'], 'utc_ticks': ticks(3, 38, 10, 0)},
            {'event': 'send', 'nonce': nonce, 'connection_id': 'main', 'pid': 777,
             'cadence_ms': profile['cadence_ms'],
             'utc_ticks': ticks(3, 38, 10, 0) + profile['cadence_ms'] * 10_000},
            {'event': 'close', 'nonce': nonce, 'connection_id': 'main', 'pid': 777},
            {'event': 'cases_released', 'nonce': nonce, 'phase': 'after-healthy', 'count': 4},
            {'event': 'case_established', 'nonce': nonce, 'case_index': 1,
             'connection_id': 'case-1', 'pid': 777, 'utc_ticks': ticks(3, 38, 52, 700),
             'src': '192.168.204.233:50158', 'actual_dst': '192.168.204.233:443'},
            {'event': 'case_send', 'nonce': nonce, 'case_index': 1, 'connection_id': 'case-1',
             'pid': 777, 'utc_ticks': ticks(3, 38, 52, 800)},
            {'event': 'case_close', 'nonce': nonce, 'case_index': 1, 'connection_id': 'case-1',
             'pid': 777, 'utc_ticks': ticks(3, 38, 52, 900)},
            {'event': 'case_established', 'nonce': nonce, 'case_index': 2,
             'connection_id': 'case-2', 'pid': 777, 'utc_ticks': ticks(3, 38, 53, 700),
             'src': '192.168.204.233:50159', 'actual_dst': '198.51.100.77:1337'},
            {'event': 'case_send', 'nonce': nonce, 'case_index': 2, 'connection_id': 'case-2',
             'pid': 777, 'utc_ticks': ticks(3, 38, 53, 800)},
            {'event': 'case_close', 'nonce': nonce, 'case_index': 2, 'connection_id': 'case-2',
             'pid': 777, 'utc_ticks': ticks(3, 38, 53, 900)},
            {'event': 'case_udp_sent', 'nonce': nonce, 'case_index': 3,
             'connection_id': 'case-3', 'pid': 777, 'utc_ticks': ticks(3, 38, 54, 700),
             'src': '192.168.204.233:50160', 'actual_dst': '119.188.175.46:443'},
            {'event': 'case_close', 'nonce': nonce, 'case_index': 3, 'connection_id': 'case-3',
             'pid': 777, 'utc_ticks': ticks(3, 38, 54, 900)},
            {'event': 'case_established', 'nonce': nonce, 'case_index': 4,
             'connection_id': 'case-4', 'pid': 777, 'utc_ticks': ticks(3, 38, 56, 100),
             'src': '192.168.204.233:50161', 'actual_dst': '119.188.175.46:443'},
            {'event': 'case_tls_handshake_attempt', 'nonce': nonce, 'case_index': 4,
             'connection_id': 'case-4', 'pid': 777, 'utc_ticks': ticks(3, 38, 56, 280),
             'sni': handshake_sni},
            {'event': 'case_error', 'nonce': nonce, 'case_index': 4, 'connection_id': 'case-4',
             'pid': 777, 'utc_ticks': ticks(3, 38, 56, 320)},
            {'event': 'case_close', 'nonce': nonce, 'case_index': 4, 'connection_id': 'case-4',
             'pid': 777, 'utc_ticks': ticks(3, 38, 56, 400)}]
    (root / 'probe.jsonl').write_text('\n'.join(json.dumps(row) for row in rows) + '\n',
                                      encoding='utf-8')
    (root / 'pktmon.txt').write_text('pktmon fixture\n', encoding='utf-8')
    deny_fields = ['TLS_SNI_DENY domain=%s' % deny_domain,
                   None if drop_generation else 'generation=%s' % deny_generation,
                   'original_ip=%s' % deny_original_ip, 'original_port=443',
                   'reason=%s' % deny_reason,
                   None if drop_reason_code else 'reason_code=%s' % deny_reason_code,
                   'sni=%s' % (deny_sni or handshake_sni),
                   'sport=%s' % deny_sport, 'src=192.168.204.233']
    deny_line = '%s INFO Diverter %s' % (
        deny_timestamp, ' '.join(field for field in deny_fields if field))
    stamp = _dt.datetime.strptime(deny_timestamp, '%Y-%m-%d %H:%M:%S,%f') - _dt.timedelta(hours=8)
    deny_ns = int(stamp.replace(tzinfo=_dt.timezone.utc).timestamp() * 10**9)
    log_lines = [
        'EGRESS_CONTROL_READY',
        '2026-09-21 11:38:52,774 INFO Diverter PROCESS_FLOW disposition=DIVERT_FAKE domain=- dport=443 dst=192.168.204.233 pid=777 process=powershell.exe proto=TCP sport=50158 src=192.168.204.233',
        '2026-09-21 11:38:52,774 INFO Diverter DIVERT_FAKE original_ip=192.168.204.233 original_port=443',
        '2026-09-21 11:38:53,774 INFO Diverter PROCESS_FLOW disposition=DIVERT_FAKE domain=- dport=1337 dst=198.51.100.77 pid=777 process=powershell.exe proto=TCP sport=50159 src=192.168.204.233',
        '2026-09-21 11:38:53,774 INFO Diverter DIVERT_FAKE original_ip=198.51.100.77 original_port=1337',
        '2026-09-21 11:38:54,774 INFO Diverter PROCESS_FLOW disposition=DIVERT_FAKE domain=api.deepseek.com dport=443 dst=119.188.175.46 pid=777 process=powershell.exe proto=UDP sport=50160 src=192.168.204.233',
        '2026-09-21 11:38:54,774 INFO Diverter DIVERT_FAKE original_ip=119.188.175.46 original_port=443',
        '2026-09-21 11:38:56,286 INFO Diverter PROCESS_FLOW disposition=REDIRECT_TLS_RELAY domain=api.deepseek.com dport=443 dst=119.188.175.46 pid=777 process=powershell.exe proto=TCP sport=50161 src=192.168.204.233',
        deny_line]
    if curl_allow_line:
        # Real product TLS_SNI_ALLOW format: no client identity fields.  This
        # one is the later curl connection to the same original destination,
        # provably disjoint from the case window by its conservative bounds.
        log_lines.append('2026-09-21 11:38:59,258 INFO Diverter TLS_SNI_ALLOW '
                         'domain=api.deepseek.com original_ip=119.188.175.46 '
                         'sni=api.deepseek.com')
    log_lines.extend(extra_lines)
    (root / 'run.log').write_text('\n'.join(log_lines) + '\n', encoding='utf-8')

    def packets(capture, src, dst, protocol, not_after_local=None, not_before_local=None):
        nic = ([{'component': 9}] if case4_nic and dst == '119.188.175.46:443'
               and protocol == 'TCP' else [])
        return ([{'src': src, 'dst': dst, 'protocol': protocol}], nic, {'component_ids': [9]})

    runner._pktmon_observations = packets

    def observation(run, origin, ends, nonce, src, dst, protocol, creation_ticks=None, include_begin_bound=False):
        value = {'schema': 'sst.application-observation.v1', 'nonce': nonce,
                 'pid': origin['pid'], 'case_index': origin.get('case_index'),
                 'connection_id': origin.get('connection_id'),
                 'src': src, 'dst': dst, 'protocol': protocol,
                 'begin_upper_ns': ((origin['utc_ticks'] - 621355968000000000) * 100 + 15624999) if include_begin_bound else None,
                 'end_lower_ns': ticks(3, 38, 56, 400) and
                 (ticks(3, 38, 56, 400) - 621355968000000000) * 100 +
                 observation_end_lower_delay_ms * 10**6}
        if native_deny is not None:
            value['etw_connect_upper_ns'] = deny_ns + etw_window_ms[0] * 10**6
            value['etw_terminal_lower_ns'] = deny_ns + etw_window_ms[1] * 10**6
        if observation_identity_error:
            value['connection_id'] = value['connection_id'] + '-other'
        return value

    runner._application_observation = observation
    if native_deny is not None:
        clock = {'supported': not native_unsupported,
                 'api': 'GetSystemTimePreciseAsFileTime',
                 'filetime_100ns': (deny_ns + (native_shift_ns or 0)
                                    + 11644473600000000000) // 100,
                 'qpc_before': 1, 'qpc_after': 2, 'qpc_frequency': 10_000_000}
        if native_unsupported:
            clock = {'supported': False, 'reason': 'unsupported'}
        record = {'schema': 'fakenetng.relay-native-terminal.v1',
                  'outcome': 'deny', 'reason_code': 'sni_mismatch',
                  'src': '192.168.204.233', 'sport': 50161,
                  'domain': 'api.deepseek.com',
                  'original_ip': '119.188.175.46', 'original_port': 443,
                  'generation': 2, 'sni': handshake_sni, 'clock': clock}
        lines = [json.dumps(record)]
        if native_duplicate:
            lines.append(json.dumps(record))
        (root / 'relay-native-events.jsonl').write_text(
            '\n'.join(lines) + '\n', encoding='utf-8')
    capture = {'probe_path': 'probe.jsonl', 'pktmon_path': 'pktmon.txt'}
    if observation_contract:
        capture['observation_contract'] = observation_contract
    run = {'capture': capture, 'originals': {'files': [{'path': 'run.log'}]}}
    sentinel = {'rows': []}
    return runner, profile, nonce, run, sentinel, deny_line, deny_ns


def test_auxiliary_sni_mismatch_deny_binds_strictly():
    """The planned SNI-deny case passes only through a fully bound record."""
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        runner, profile, nonce, run, sentinel, deny_line, deny_ns = _b1_sni_oracle_fixture(root)
        verdict = runner._traffic_oracle(run, profile, nonce, sentinel)
        case4 = verdict['cases'][3]
        assert case4['passed'], case4
        binding = case4['sni_binding']
        assert binding['deny_log'] == deny_line
        assert binding['contract_version'] == 1
        assert binding['sni'] == 'example.com'
        assert binding['domain'] == 'api.deepseek.com'
        assert binding['generation'] == 2
        assert binding['begin_bound_ns'] < deny_ns < binding['end_bound_ns']
        raw = (root / 'run.log').read_bytes()
        ref = binding['deny_log_ref']
        assert raw[ref['byte_start']:ref['byte_end']].decode('utf-8') == deny_line
        # The other deny cases keep their strict DIVERT_FAKE branch.
        assert verdict['cases'][0]['passed'] and verdict['cases'][1]['passed']
        assert verdict['cases'][2]['passed']


def test_auxiliary_sni_mismatch_deny_rejects_substitutes():
    """Every weaker or ambiguous substitute must leave the case failing."""
    cases = [
        ('deny overlaps uncertain establishment', dict(deny_timestamp='2026-09-21 11:38:56,110')),
        ('wrong handshake sni', dict(handshake_sni='example.org')),
        ('deny sni differs from handshake', dict(deny_sni='example.net')),
        ('old unbound deny format', dict(drop_reason_code=True, deny_sport='0')),
        ('parse error not mismatch', dict(deny_reason_code='clienthello_error')),
        ('relay error not mismatch', dict(deny_reason_code='relay_error', deny_reason='OSError')),
        ('missing generation', dict(drop_generation=True)),
        ('generation zero', dict(deny_generation='0')),
        ('generation not an integer', dict(deny_generation='x')),
        ('contradictory allow with identity', dict(extra_lines=(
            '2026-09-21 11:38:56,290 INFO Diverter TLS_SNI_ALLOW domain=api.deepseek.com original_ip=119.188.175.46 sni=example.com sport=50161 src=192.168.204.233',))),
        ('real-format allow inside window', dict(extra_lines=(
            '2026-09-21 11:38:56,300 INFO Diverter TLS_SNI_ALLOW domain=api.deepseek.com original_ip=119.188.175.46 sni=api.deepseek.com',))),
        ('real-format allow at boundary', dict(extra_lines=(
            '2026-09-21 11:38:56,412 INFO Diverter TLS_SNI_ALLOW domain=api.deepseek.com original_ip=119.188.175.46 sni=api.deepseek.com',))),
        ('ambiguous second deny', dict(extra_lines=(
            '2026-09-21 11:38:56,300 INFO Diverter TLS_SNI_DENY domain=api.deepseek.com generation=9 original_ip=119.188.175.46 original_port=443 reason=ClientHelloError reason_code=sni_mismatch sni=example.com sport=50161 src=192.168.204.233',))),
        ('deny after connection window', dict(deny_timestamp='2026-09-21 11:38:57,900')),
        ('deny at end bound boundary', dict(deny_timestamp='2026-09-21 11:38:56,790')),
        ('deny before established', dict(deny_timestamp='2026-09-21 11:38:56,050')),
        ('original target mismatch', dict(deny_original_ip='119.188.175.47')),
        ('domain not this case policy', dict(deny_domain='other.example')),
        ('different source port', dict(deny_sport='50199')),
        ('no con008 observation', dict(observation_contract=None)),
        ('observation identity mismatch', dict(observation_identity_error=True)),
        ('physical egress on NIC', dict(case4_nic=True)),
        # candidate08 sst-004 case-4 shape: the native earliest-termination
        # lower bound precedes the deny even though the probe rows contain it.
        ('native end lower precedes deny', dict(observation_end_lower_delay_ms=-200)),
        # Display precision is not the clock resolution: the deny sits only
        # 10ms before the native end bound -- inside a 1ms display window
        # but outside the frozen 15,625,000ns conservative interval.
        ('display precision is not clock resolution', dict(observation_end_lower_delay_ms=-100)),
    ]
    for name, kwargs in cases:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, profile, nonce, run, sentinel, _, _ = _b1_sni_oracle_fixture(root, **kwargs)
            case4 = runner._traffic_oracle(run, profile, nonce, sentinel)['cases'][3]
            assert not case4['passed'], name
            if name != 'physical egress on NIC':
                # The NIC rejection is independent of the relay decision; the
                # bound record may legitimately remain as diagnostics.
                assert not case4.get('sni_binding'), name


def test_sni_mismatch_binding_rebuilds_from_real_originals_online_and_offline():
    """The binding consumes the real con008 observation and sealed originals.

    Nothing about the application observation is stubbed here: probe.jsonl,
    run.log, pktmon native lifecycle, conversion metadata and managed IPC
    identity are reconstructed from original-like files, the online oracle
    binds case 4 through the real observation end bound, and the offline
    recheck rebuilds and compares the sealed binding from the same files.
    """
    import datetime as _dt
    import hashlib as _hashlib
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        runner = object.__new__(suite.Suite)
        runner.root = root
        runner.identity = types.SimpleNamespace(candidate_id='test-candidate')
        profile = suite.materialize_probe_profile(suite.profile_for_bucket('B1', 0), '60.28.220.199')
        nonce = 'oracle-b1-real'
        expected = {'profile': profile['bucket'], 'variant': profile['variant'],
                    'tempo': profile['tempo'], 'interleave': profile['interleave'],
                    'cadence_ms': profile['cadence_ms'],
                    'target_host': profile['probe_target']['host'],
                    'target_port': profile['probe_target']['port'],
                    'target_protocol': profile['probe_target']['protocol'],
                    'process_mode': profile['probe_target'].get('process_mode', 'match'),
                    'fnpr_role': profile['probe_target'].get('fnpr_role', ''),
                    'startup_retry_seconds': profile.get('startup_retry_seconds', 70),
                    'additional_targets': list(profile['negative_cases'])}

        def ticks(hh, mm, ss, ms):
            stamp = _dt.datetime(2026, 9, 11, hh, mm, ss, ms * 1000, tzinfo=_dt.timezone.utc)
            return 621355968000000000 + int(stamp.timestamp() * 10**7)

        creation = ticks(1, 47, 0, 0)
        rows = [dict(event='ready', nonce=nonce, pid=7948, creation_ticks=creation,
                     stopwatch_frequency=10000000, **expected),
                {'event': 'released', 'nonce': nonce, 'interleave': profile['interleave']},
                {'event': 'established', 'nonce': nonce, 'connection_id': 'main', 'pid': 7948,
                 'utc_ticks': ticks(1, 48, 10, 50),
                 'src': '192.168.204.233:5000', 'dst': '60.28.220.199:443'},
                {'event': 'send', 'nonce': nonce, 'connection_id': 'main', 'pid': 7948,
                 'cadence_ms': profile['cadence_ms'], 'utc_ticks': ticks(1, 48, 10, 0)},
                {'event': 'send', 'nonce': nonce, 'connection_id': 'main', 'pid': 7948,
                 'cadence_ms': profile['cadence_ms'],
                 'utc_ticks': ticks(1, 48, 10, 0) + profile['cadence_ms'] * 10_000},
                {'event': 'tls_handshake_attempt', 'nonce': nonce, 'connection_id': 'main',
                 'pid': 7948, 'utc_ticks': ticks(1, 48, 10, 50), 'sni': 'api.deepseek.com'},
                {'event': 'close', 'nonce': nonce, 'connection_id': 'main', 'pid': 7948,
                 'utc_ticks': ticks(1, 48, 12, 100)},
                {'event': 'cases_released', 'nonce': nonce, 'phase': 'after-healthy', 'count': 4},
                {'event': 'case_established', 'nonce': nonce, 'case_index': 4,
                 'connection_id': 'case-4', 'pid': 7948, 'utc_ticks': ticks(1, 48, 55, 300),
                 'src': '192.168.204.233:50161', 'actual_dst': '119.188.175.46:443'},
                {'event': 'case_tls_handshake_attempt', 'nonce': nonce, 'case_index': 4,
                 'connection_id': 'case-4', 'pid': 7948, 'utc_ticks': ticks(1, 48, 55, 400),
                 'sni': 'example.com'},
                {'event': 'case_error', 'nonce': nonce, 'case_index': 4,
                 'connection_id': 'case-4', 'pid': 7948, 'utc_ticks': ticks(1, 48, 55, 500)},
                {'event': 'case_close', 'nonce': nonce, 'case_index': 4,
                 'connection_id': 'case-4', 'pid': 7948, 'utc_ticks': ticks(1, 48, 55, 600)}]
        (root / 'probe.jsonl').write_text('\n'.join(json.dumps(row) for row in rows) + '\n',
                                          encoding='utf-8')
        (root / 'run.log').write_text(
            'EGRESS_CONTROL_READY\n'
            '2026-09-11 09:48:10,100 INFO Diverter PROCESS_FLOW disposition=REDIRECT_TLS_RELAY domain=api.deepseek.com dport=443 dst=60.28.220.199 pid=7948 process=powershell.exe proto=TCP sport=5000 src=192.168.204.233\n'
            '2026-09-11 09:48:10,150 INFO Diverter TLS_SNI_ALLOW domain=api.deepseek.com original_ip=60.28.220.199 sni=api.deepseek.com\n'
            '2026-09-11 09:48:10,150 INFO Diverter ALLOW_INTERNAL_UPSTREAM ip=60.28.220.199 kind=tls_relay port=443 sport=50111\n'
            '2026-09-11 09:48:10,160 INFO Diverter PROCESS_FLOW disposition=REINJECT_LOCAL domain=- dport=5000 dst=192.168.204.233 pid=404 process=fakenetng-mcp-managed.exe proto=TCP sport=38927 src=192.168.204.233\n'
            '2026-09-11 09:48:55,286 INFO Diverter PROCESS_FLOW disposition=REDIRECT_TLS_RELAY domain=api.deepseek.com dport=443 dst=119.188.175.46 pid=7948 process=powershell.exe proto=TCP sport=50161 src=192.168.204.233\n'
            '2026-09-11 09:48:55,286 INFO Diverter PROCESS_FLOW disposition=REINJECT_LOCAL domain=- dport=50161 dst=192.168.204.233 pid=404 process=fakenetng-mcp-managed.exe proto=TCP sport=38927 src=192.168.204.233\n'
            '2026-09-11 09:48:55,450 INFO Diverter TLS_SNI_DENY domain=api.deepseek.com generation=2 original_ip=119.188.175.46 original_port=443 reason=ClientHelloError reason_code=sni_mismatch sni=example.com sport=50161 src=192.168.204.233\n'
            '2026-09-11 09:48:58,258 INFO Diverter TLS_SNI_ALLOW domain=api.deepseek.com original_ip=119.188.175.46 sni=api.deepseek.com\n',
            encoding='utf-8')
        def filetime(hh, mm, ss, ms=0):
            return (ticks(hh, mm, ss, ms) - 621355968000000000) + 116444736000000000
        header = ('[00]0000.0000::2026-09-11 09:48:54.000000000 [MSNT_SystemTrace] Header, '
                  'EndTime: {end}, StartTime: {start}, EventsLost: 0, BuffersLost: 0, '
                  'LogFileNameString: C:\\run\\pktmon.etl\r\n').format(
                      start=filetime(1, 48, 5, 0), end=filetime(1, 49, 0, 0))

        def native(t, body):
            return f'[00]0001.0002::2026-09-11 09:48:{t} [Microsoft-Windows-TCPIP] TCP: {body}\r\n'

        pktmon_text = ('\ufeff' + header + ''.join([
            native('10.200000000', 'connection 0xCCC transition from ClosedState  to SynSentState , SndNxt = 0.'),
            native('10.300000000', 'connection 0xCCC transition from SynSentState  to EstablishedState , SndNxt = 1.'),
            native('10.350000000', 'connection 0xCCC (local=192.168.204.233:5000 remote=60.28.220.199:443) connect completed. PID = 7948.'),
            native('10.360000000', 'connection 0xDDD transition from ListenState to SynRcvdState , SndNxt = 0.'),
            native('10.370000000', 'listener (local=192.168.204.233:38927 remote=192.168.204.233:5000) accept completed. TCB = 0xDDD. PID = 404.'),
            native('10.380000000', 'connection 0xDDD transition from SynRcvdState  to EstablishedState , SndNxt = 2.'),
            native('12.000000000', 'connection 0xCCC (local=192.168.204.233:5000 remote=60.28.220.199:443) close issued. PID = 7948.'),
            native('12.100000000', 'connection 0xDDD transition from EstablishedState  to FinWait1State , SndNxt = 3.'),
            native('55.200000000', 'connection 0xAAA transition from ClosedState  to SynSentState , SndNxt = 0.'),
            native('55.300000000', 'connection 0xAAA transition from SynSentState  to EstablishedState , SndNxt = 1.'),
            native('55.350000000', 'connection 0xAAA (local=192.168.204.233:50161 remote=119.188.175.46:443) connect completed. PID = 7948.'),
            native('57.000000000', 'connection 0xAAA (local=192.168.204.233:50161 remote=119.188.175.46:443) close issued. PID = 7948.'),
        ])).encode('utf-16-le')
        (root / 'pktmon.txt').write_bytes(pktmon_text)
        (root / 'pktmon.etl').write_bytes(b'fixture ETL')
        meta = dict(capture_mode='all-components-tcpip',
                    clock_before=dict(utc_ticks=ticks(1, 48, 5, 0), mono=0,
                                      stopwatch_frequency=10000000, offset_minutes=480),
                    clock_after=dict(utc_ticks=ticks(1, 49, 0, 0), mono=550000000,
                                     stopwatch_frequency=10000000, offset_minutes=480),
                    conversion=dict(argv=['pktmon', 'etl2txt', 'C:\\run\\pktmon.etl',
                                          '--out', 'C:\\run\\pktmon.txt'], exit_code=0,
                                    etl_sha256=_hashlib.sha256(b'fixture ETL').hexdigest(),
                                    text_sha256=_hashlib.sha256(pktmon_text).hexdigest()))
        (root / 'pktmon-nic.json').write_text(json.dumps(meta), encoding='utf-8')
        stamp = 1789091335.6
        ipc = [dict(event='request', time=stamp, frame=dict(run_id='r', seq=1, kind='ready')),
               dict(event='response', time=stamp, frame=dict(
                   run_id='r', seq=1, result={'identity': {
                       'pid': 404,
                       'creation_time': str(116444736000000000 + creation - 621355968000000000)} })),
               dict(event='request', time=stamp, frame=dict(run_id='r', seq=2, kind='start')),
               dict(event='response', time=stamp, frame=dict(run_id='r', seq=2, result={'probe': True}))]
        (root / 'ipc-parent.jsonl').write_text('\n'.join(json.dumps(row) for row in ipc) + '\n',
                                               encoding='utf-8')

        records = [suite.file_record(path, root) for path in sorted(root.iterdir())]
        run = {'run_id': 'r',
               'capture': {'probe_path': 'probe.jsonl', 'pktmon_path': 'pktmon.txt',
                           'observation_contract': 'con008',
                           'files': [record for record in records
                                     if record['path'] != 'run.log']},
               'originals': {'files': [record for record in records
                                       if record['path'] == 'run.log']},
               'start_response': {'state': 'healthy'}}

        def packets(capture, src, dst, protocol, not_after_local=None, not_before_local=None):
            return ([{'src': src, 'dst': dst, 'protocol': protocol}], [], {'component_ids': [9]})

        runner._pktmon_observations = packets
        verdict = runner._traffic_oracle(run, profile, nonce, None)
        case4 = verdict['cases'][3]
        assert case4['passed'], case4
        binding = case4['sni_binding']
        assert binding['contract_version'] == 1
        # end bound derives from the real observation: the earliest probe
        # terminal row (case_error 55.5Z) minus the frozen uncertainty is
        # tighter than the native terminal.
        assert binding['end_bound_ns'] == (ticks(1, 48, 55, 500) - 621355968000000000) * 100 - 15624999
        raw = (root / 'run.log').read_bytes()
        ref = binding['deny_log_ref']
        assert raw[ref['byte_start']:ref['byte_end']].decode('utf-8') == binding['deny_log']

        # Offline recheck rebuilds from the same sealed originals and the
        # sealed binding survives; tampering it is rejected end to end.
        stored_run = dict(run, traffic_oracle=verdict)
        result = {'traffic_evidence': {'nonce': nonce, 'runtime_profile': profile},
                  'run_chain': [stored_run]}
        expected_row = {'scenario_id': 'sst-x', 'config_profile': profile,
                        'interface_call_plan': []}
        issues = runner._traffic_recheck_issues(result, expected_row)
        assert not [issue for issue in issues if 'binding' in issue], issues
        tampered = json.loads(json.dumps(verdict))
        tampered['cases'][3]['sni_binding']['generation'] = 9
        result['run_chain'][0] = dict(stored_run, traffic_oracle=tampered)
        issues = runner._traffic_recheck_issues(result, expected_row)
        assert any('generation' in issue and 'binding' in issue for issue in issues), issues


def test_stored_sni_binding_tamper_is_rejected_in_recheck():
    """The offline recheck compares every sealed binding field, not just text."""
    base = {'schema': 'sst.sni-mismatch-binding.v1', 'contract_version': 1,
            'deny_log': 'deny line', 'sni': 'example.com', 'domain': 'api.deepseek.com',
            'generation': 2, 'handshake_sni': 'example.com',
            'begin_bound_ns': 100, 'end_bound_ns': 900,
            'deny_log_ref': {'path': 'run.log', 'byte_start': 4, 'byte_end': 13}}
    recomputed = [{'index': 4, 'passed': True, 'sni_binding': dict(base)}]
    assert suite.Suite._stored_binding_issues(
        [{'index': 4, 'sni_binding': dict(base),
          'branch_log': 'TLS_SNI_DENY reason_code=sni_mismatch'}], recomputed) == []
    # Deleting both binding and branch cannot downgrade to a legacy pass.
    assert suite.Suite._stored_binding_issues([{'index': 4}], recomputed)
    for field, value in [('deny_log', 'deny line '), ('sni', 'other.example'),
                         ('domain', 'other.example'), ('generation', 3),
                         ('handshake_sni', 'other.example'),
                         ('begin_bound_ns', 101), ('end_bound_ns', 901)]:
        tampered = dict(base)
        tampered[field] = value
        issues = suite.Suite._stored_binding_issues(
            [{'index': 4, 'sni_binding': tampered}], recomputed)
        assert any(field in issue for issue in issues), field
    moved = dict(base, deny_log_ref={'path': 'run.log', 'byte_start': 5, 'byte_end': 13})
    assert suite.Suite._stored_binding_issues([{'index': 4, 'sni_binding': moved}], recomputed)
    # Scalar/null bindings and unknown contract versions never pass.
    assert suite.Suite._stored_binding_issues([{'index': 4, 'sni_binding': 'x'}], recomputed)
    assert any('not a record' in issue for issue in suite.Suite._stored_binding_issues(
        [{'index': 4, 'sni_binding': 'x'}], recomputed))
    unversioned = dict(base, contract_version=2)
    assert any('contract version' in issue for issue in suite.Suite._stored_binding_issues(
        [{'index': 4, 'sni_binding': unversioned}], recomputed))
    # Deleting the binding from an sni_mismatch branch row strips sealed evidence.
    assert any('binding' in issue
               for issue in suite.Suite._stored_binding_issues(
                   [{'index': 4, 'branch_log': 'TLS_SNI_DENY reason_code=sni_mismatch'}],
                   recomputed))
    # Duplicated case indexes and deleted recomputed cases are rejected.
    assert any('duplicate' in issue for issue in suite.Suite._stored_binding_issues(
        [{'index': 4, 'sni_binding': dict(base)},
         {'index': 4, 'sni_binding': dict(base)}], recomputed))
    assert any('missing from stored rows' in issue
               for issue in suite.Suite._stored_binding_issues([], recomputed))
    assert suite.Suite._stored_binding_issues(
        [{'index': 4, 'sni_binding': dict(base)}], [{'index': 4, 'passed': False}]) == [
        'stored SNI deny binding has no recomputed counterpart (case 4)']


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

        def packets(capture, src, dst, protocol, not_after_local=None, not_before_local=None):
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


def test_acceptance_profiles_preserve_conditional_product_pcap():
    for bucket in ('B1', 'B2', 'B3', 'B4', 'default'):
        profile = suite.profile_for_bucket(bucket, 0)
        identity = dict(path=r'C:\probe.exe', sha256='a'*64, public_ipv4='192.168.204.1', private_ipv4='192.168.204.1')
        rendered = suite.profile_content(profile, '192.168.204.1', identity, '119.188.175.46')
        expected = 'Yes' if bucket in ('B3', 'default') else 'No'
        assert re.findall(r'(?im)^DumpPackets\s*:\s*(\w+)', rendered) == [expected]
        assert suite.runtime_pcap_required(profile) == (expected == 'Yes')


@pytest.mark.parametrize('field', ['tuple_terminal_refs', 'policy_context_refs'])
@pytest.mark.parametrize('slot', ['primary', 'case', 'curl'])
@pytest.mark.parametrize('bad', ['omit', 'duplicate', 'reorder', 'generation'])
def test_raw_recheck_rejects_stored_application_reference_tampering(slot, bad, field):
    import copy
    runner = suite.Suite.__new__(suite.Suite)
    obs = {'tuple_terminal_refs': [{'byte_start': 1}, {'byte_start': 2}], 'generation_manifest': [], 'policy_context_refs': [{'byte_start': 3}, {'byte_start': 4}]}
    verdict = {'passed': True, 'connection_observation': copy.deepcopy(obs),
               'cases': [{'connection_observation': copy.deepcopy(obs)}],
               'curl': {'connection_observation': copy.deepcopy(obs)}}
    saved = copy.deepcopy(verdict)
    target = (saved['connection_observation'] if slot == 'primary' else
              saved['cases'][0]['connection_observation'] if slot == 'case' else saved['curl']['connection_observation'])
    runner._traffic_oracle = lambda *args: verdict
    result = {'traffic_evidence': {'nonce': 'n', 'runtime_profile': {}},
              'run_chain': [{'start_response': {'state': 'healthy'},
                             'capture': {'observation_contract': 'con008'}, 'traffic_oracle': saved}]}
    assert runner._traffic_recheck_issues(result, {}) == []
    if bad == 'omit': target[field].pop(0)
    if bad == 'duplicate': target[field].append(target[field][0])
    if bad == 'reorder': target[field].reverse()
    if bad == 'generation': target['generation_manifest'].append(target[field][0])
    assert runner._traffic_recheck_issues(result, {}) == ['stored application observations differ from full raw reconstruction']


def test_restart_baseline_requires_verified_restoration_and_keeps_real_differences():
    runner = suite.Suite.__new__(suite.Suite)
    baseline = {'dns_servers': '192.168.204.2', 'routes': '', 'listen_ports': '',
                'windivert_processes': '', 'services': ''}
    first = {'run_id': 'previous-run', 'five_sections_before': baseline,
             'five_sections_after': dict(baseline), 'recovery_audit': {'files': [{'path': 'audit.jsonl'}]}}
    restored = runner._restart_baseline(first)
    assert runner._section_difference(restored, baseline) == {}
    active = dict(baseline, dns_servers='192.168.204.233')
    assert 'dns_servers' in runner._section_difference(restored, active)
    first['five_sections_after'] = active
    with pytest.raises(suite.SuiteError, match='recovery difference'):
        runner._restart_baseline(first)


def test_ipc_evidence_mode_arms_only_environment_and_restores_exactly():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    commands = []

    def fake_vm_json(command, timeout):
        commands.append(command)
        armed = 'FAKENETNG_MCP_FAULT_INJECTION=1' in command and 'enabled=$true' in command
        if armed:
            value = {'enabled': True, 'backup': 'b', 'state': 'Running'}
        else:
            value = {'enabled': False, 'backup': 'b',
                     'environment_restored': True, 'state': 'Running'}
        return value, 'raw-' + str(len(commands))

    runner._vm_json = fake_vm_json
    runner._status = lambda timeout=30: {'state': 'stopped', 'run_id': None, 'controller': None}

    enabled = runner._ipc_evidence_mode(True)
    assert enabled['enabled'] is True
    assert 'New-ItemProperty $key -Name Environment -PropertyType MultiString' in commands[-1]
    assert 'FAKENETNG_MCP_FAULT_INJECTION=1' in commands[-1]
    # Unlike fault mode, IPC evidence arming must not touch service.json or
    # the stop grace: benign acceptance conditions stay byte-identical.
    assert 'stop_grace_seconds' not in commands[-1]
    assert 'fault-mode-original' not in commands[-1]
    assert runner._ipc_evidence_mode(False)['enabled'] is False
    restore = commands[-1]
    assert 'Compare-Object @($saved.values) $current' in restore
    assert 'stop_grace_seconds' not in restore


def test_ipc_evidence_mode_rejects_drifted_service_or_failed_restoration():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    idle = {'state': 'stopped', 'run_id': None, 'controller': None}

    def fake_vm_json(command, timeout):
        armed = 'FAKENETNG_MCP_FAULT_INJECTION=1' in command and 'enabled=$true' in command
        return ({'enabled': True, 'backup': 'b', 'state': 'Running'} if armed else
                {'enabled': False, 'backup': 'b', 'environment_restored': False,
                 'state': 'Running'}), 'raw'
    runner._vm_json = fake_vm_json
    runner._status = lambda timeout=30: idle
    with pytest.raises(suite.SuiteError, match='exact restoration failed'):
        runner._ipc_evidence_mode(False)

    def service_stuck(timeout=30):
        return {'state': 'failed', 'run_id': None, 'controller': None}
    runner._status = service_stuck
    with pytest.raises(suite.SuiteError, match='endpoint unexpected state'):
        runner._ipc_evidence_mode(True)


def test_run_and_resume_arm_ipc_evidence_around_every_scenario(tmp_path, monkeypatch):
    for command in ('run', 'resume'):
        runner = suite.Suite.__new__(suite.Suite)
        runner.root = tmp_path / (command + '-root')
        runner.root.mkdir()
        runner.args = type('Args', (), {'stop_on_first_failure': False})()
        runner.manifest = lambda: {'scenarios': [
            {'scenario_id': 'sst-a', 'fault_class': None},
            {'scenario_id': 'sst-b', 'fault_class': None}]}
        runner.require_clients = lambda: None
        runner._require_preflight = lambda: None
        runner._require_fault_spike = lambda: None
        runner._continuation_gate = lambda: {'vm': {}}
        runner._result_path = lambda sid: runner.root / ('result-' + sid + '.json')

        def state_path(sid):
            path = runner.root / ('state-' + sid + '.json')
            if not path.exists():
                suite.replace_json(path, {'phase': 'pending', 'attempt': 0})
            return path
        runner._state_path = state_path
        order = []

        def fake_run_one(scenario, attempt):
            order.append(('scenario', scenario['scenario_id']))
            if scenario['scenario_id'] == 'sst-a' and command == 'run':
                raise suite.Blocked('continuation gate rejected the scene')
            path = runner._result_path(scenario['scenario_id'])
            suite.write_new_json(path, {'scenario_id': scenario['scenario_id'], 'state': 'pass'})
            return {'scenario_id': scenario['scenario_id'], 'state': 'pass'}
        runner._run_one = fake_run_one

        def fake_mode(enabled):
            order.append(('arm' if enabled else 'restore',))
            return {'enabled': enabled, 'recorded': True}
        monkeypatch.setattr(runner, '_ipc_evidence_mode', fake_mode)

        if command == 'run':
            with pytest.raises(suite.Blocked):
                runner.run('benign')
            enabled_name, disabled_name = ('ipc-evidence-benign-enabled.json',
                                           'ipc-evidence-benign-disabled.json')
        else:
            runner.resume()
            enabled_name, disabled_name = ('ipc-evidence-resume-enabled.json',
                                           'ipc-evidence-resume-disabled.json')
        assert order[0] == ('arm',)
        assert order[-1] == ('restore',)
        assert order.count(('restore',)) == 1
        assert ('scenario', 'sst-a') in order
        assert (runner.root / enabled_name).is_file()
        assert (runner.root / disabled_name).is_file()


@pytest.mark.parametrize('status,passes', [('COMPLETE_DIAGNOSTIC_ONLY', True),
                                          ('INCOMPLETE', False)])
def test_qpc_online_export_seals_bundle_and_keeps_failed_guest_originals(
        tmp_path, monkeypatch, status, passes):
    import io
    import zipfile
    runner = suite.Suite.__new__(suite.Suite)
    runner.root = tmp_path
    run_root = tmp_path / 'evidence' / 'sst-002' / 'attempt-01'
    run_root.mkdir(parents=True)
    original = tmp_path / 'original.json'
    original.write_text('{"original":true}\n')
    base = {'files': [dict(path='original.json', bytes=original.stat().st_size,
                           sha256=hashlib.sha256(original.read_bytes()).hexdigest())]}
    base_path = run_root / 'base.json'
    suite.write_new_json(base_path, base)
    evidence = suite.Evidence(run_root)
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('export/manifest.json', json.dumps({'status': status,
            'error': None if passes else {'message': 'native export failed'}}))
        archive.writestr('terminal.json', json.dumps({'exit_code': 0 if passes else 1}))
        archive.writestr('stdout.txt', 'guest stdout')
        archive.writestr('stderr.txt', 'guest stderr')
    output_bytes = output.getvalue()
    seen = []

    class Transfer:
        def __init__(self, source, public_name):
            self.source = source
            self.public_name = public_name
            self.stopped = False
        def __enter__(self):
            return self
        def __exit__(self, *_):
            self.stopped = True
        @property
        def url(self):
            return 'http://192.168.204.1:12345/qpc-input.zip'
        def record(self):
            return {'stopped': self.stopped,
                    'requests': [{'status': 200, 'bytes': self.source.stat().st_size}]}

    monkeypatch.setattr(suite, 'HostOnlyFileTransfer', Transfer)
    def guest(command, timeout):
        seen.append((command, timeout))
        assert timeout == 1200 and 'C:\\Python313\\python.exe' in command
        return ({'computer': 'DESKTOP-3FI41GR', 'exit_code': 0 if passes else 1,
                 'path': r'C:\guest\output.zip', 'bytes': len(output_bytes),
                 'sha256': hashlib.sha256(output_bytes).hexdigest(),
                 'input_sha256': hashlib.sha256((run_root / 'qpc-input.zip').read_bytes()).hexdigest()},
                {'output': 'guest transfer result'})
    runner._vm_json = guest
    def download(path, size, sha, destination):
        assert path == r'C:\guest\output.zip'
        assert size == len(output_bytes) and sha == hashlib.sha256(output_bytes).hexdigest()
        destination.write_bytes(output_bytes)
        return suite.file_record(destination, tmp_path)
    runner._transfer_guest_file = download
    if passes:
        runner._collect_qpc_export(base_path, base, run_root, evidence, 'run')
    else:
        with pytest.raises(suite.SuiteError, match='Windows export incomplete'):
            runner._collect_qpc_export(base_path, base, run_root, evidence, 'run')
    assert seen
    with zipfile.ZipFile(run_root / 'qpc-input.zip') as archive:
        assert 'evidence/original.json' in archive.namelist()
        assert 'evidence/evidence/sst-002/attempt-01/base.json' in archive.namelist()
        assert 'tools/scenario_qpc_diagnostic.py' in archive.namelist()
    assert (run_root / 'qpc-output.zip').read_bytes() == output_bytes
    assert (run_root / 'qpc-native/export/manifest.json').is_file()
    assert json.loads((run_root / 'qpc-transfer.json').read_text())['host_only_transfer']['stopped']


def test_qpc_guest_transfer_closes_when_guest_command_fails(tmp_path, monkeypatch):
    import zipfile
    runner = suite.Suite.__new__(suite.Suite)
    runner.root = tmp_path
    root = tmp_path / 'attempt'; root.mkdir()
    original = tmp_path / 'source.json'; original.write_text('{}\n')
    base = {'files': [suite.file_record(original, tmp_path)]}
    base_path = root / 'base.json'; suite.write_new_json(base_path, base)
    transfers = []
    class Transfer:
        def __init__(self, source, public_name):
            self.stopped = False; transfers.append(self)
        def __enter__(self): return self
        def __exit__(self, *_): self.stopped = True
        @property
        def url(self): return 'http://192.168.204.1:12345/qpc-input.zip'
        def record(self): return {'stopped': self.stopped, 'requests': []}
    monkeypatch.setattr(suite, 'HostOnlyFileTransfer', Transfer)
    def fail(*_): raise suite.SuiteError('guest parser failed')
    runner._vm_json = fail
    with pytest.raises(suite.SuiteError, match='guest parser failed'):
        runner._collect_qpc_export(base_path, base, root, suite.Evidence(root), 'run')
    assert transfers[0].stopped
    transfer_record = json.loads((root / 'qpc-transfer.json').read_text())
    assert 'guest parser failed' in transfer_record['error']
    with zipfile.ZipFile(root / 'qpc-input.zip') as archive:
        assert 'evidence/source.json' in archive.namelist()


def test_fnpr_sentinel_falls_back_to_container_on_privileged_port_denial(tmp_path, monkeypatch):
    spawned = []

    class FakePopen:
        def __init__(self, command, **kwargs):
            self.command = command
            self.pid = 4242 + len(spawned)
            self._alive = True
            spawned.append(self)
            log = Path(command[command.index('--log') + 1])
            if command[0] != 'docker':
                log.write_text(json.dumps({'event': 'start_failed', 'reason': 'PermissionError',
                                           'bind': '192.168.204.1', 'port': 443}) + '\n')
            else:
                with log.open('a') as stream:
                    stream.write(json.dumps({'event': 'ready', 'bind': '192.168.204.1',
                                             'port': 443}) + '\n')

        def poll(self):
            return None if self._alive else 0

        def terminate(self):
            self._alive = False

        def wait(self, timeout=None):
            return 0

    docker_calls = []

    def fake_run(command, capture_output=True, text=True, **kwargs):
        docker_calls.append(list(command))
        if command[:2] == ['docker', 'inspect'] and len(command) > 2 and command[2] == '-f':
            return subprocess.CompletedProcess(command, 0, stdout='running\n', stderr='')
        if command[:2] == ['docker', 'inspect']:
            return subprocess.CompletedProcess(command, 1, stdout='',
                                               stderr='Error: No such object: ' + command[2])
        return subprocess.CompletedProcess(command, 0, stdout='', stderr='')
    monkeypatch.setattr(suite.subprocess, 'Popen', FakePopen)
    monkeypatch.setattr(suite.subprocess, 'run', fake_run)

    sentinel = suite.FnprSentinel(tmp_path)
    assert sentinel.mode == 'container'
    assert [p.command[0] for p in spawned] == [sys.executable, 'docker']
    docker_command = spawned[1].command
    assert '--network' in docker_command and 'host' in docker_command
    assert '--rm' in docker_command and '-d' in docker_command
    assert suite.FNPR_SENTINEL_IMAGE in docker_command
    assert any('readonly' in part for part in docker_command if 'type=bind' in part)
    stopped = sentinel.stop()
    assert stopped['mode'] == 'container' and stopped['returncode'] == 0
    assert stopped['container'] == sentinel.container
    assert stopped['removal'] == 'confirmed'
    assert any(cmd[:2] == ['docker', 'stop'] for cmd in docker_calls)


def test_fnpr_sentinel_container_respawns_after_transient_death(tmp_path, monkeypatch):
    spawned = []

    class FakePopen:
        def __init__(self, command, **kwargs):
            self.command = command
            self.pid = 5000 + len(spawned)
            spawned.append(self)
            log = Path(command[command.index('--log') + 1])
            if command[0] != 'docker':
                log.write_text(json.dumps({'event': 'start_failed', 'reason': 'PermissionError',
                                           'bind': '192.168.204.1', 'port': 443}) + '\n')

        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    inspect_results = ['exited\n', 'running\n']

    def fake_run(command, capture_output=True, text=True, **kwargs):
        if command[:2] == ['docker', 'inspect'] and len(command) > 2 and command[2] == '-f':
            return subprocess.CompletedProcess(command, 0, stdout=inspect_results.pop(0), stderr='')
        if command[:2] == ['docker', 'inspect']:
            return subprocess.CompletedProcess(command, 1, stdout='',
                                               stderr='Error: No such object: ' + command[2])
        return subprocess.CompletedProcess(command, 0, stdout='', stderr='')
    monkeypatch.setattr(suite.subprocess, 'Popen', FakePopen)
    monkeypatch.setattr(suite.subprocess, 'run', fake_run)
    monkeypatch.setattr(suite.time, 'sleep', lambda seconds: None)

    # The second (respawned) container writes the ready row on construction;
    # the first container is observed as exited once, then replaced.
    original_init = FakePopen.__init__

    def staged_init(self, command, **kwargs):
        original_init(self, command, **kwargs)
        if command[0] == 'docker' and len(spawned) == 3:
            log = Path(command[command.index('--log') + 1])
            with log.open('a') as stream:
                stream.write(json.dumps({'event': 'ready', 'bind': '192.168.204.1',
                                         'port': 443}) + '\n')
    monkeypatch.setattr(FakePopen, '__init__', staged_init)

    sentinel = suite.FnprSentinel(tmp_path)
    assert sentinel.mode == 'container'
    assert sum(1 for p in spawned if p.command[0] == 'docker') == 2


def test_fnpr_sentinel_daemon_blip_is_not_container_death(tmp_path, monkeypatch):
    class FakePopen:
        def __init__(self, command, **kwargs):
            self.pid = 99
            self.command = command
            log = Path(command[command.index('--log') + 1])
            if command[0] != 'docker':
                log.write_text(json.dumps({'event': 'start_failed', 'reason': 'PermissionError',
                                           'bind': '192.168.204.1', 'port': 443}) + '\n')
            else:
                with log.open('a') as stream:
                    stream.write(json.dumps({'event': 'ready', 'bind': '192.168.204.1',
                                             'port': 443}) + '\n')

        def poll(self):
            return None

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    def fake_run(command, capture_output=True, text=True, **kwargs):
        if command[:2] == ['docker', 'inspect'] and len(command) > 2 and command[2] == '-f':
            # First liveness probe hits daemon contention, the second confirms.
            if not hasattr(fake_run, 'blips'):
                fake_run.blips = 0
            fake_run.blips += 1
            if fake_run.blips == 1:
                return subprocess.CompletedProcess(command, 1, stdout='',
                                                   stderr='Cannot connect to the Docker daemon')
            return subprocess.CompletedProcess(command, 0, stdout='running\n', stderr='')
        if command[:2] == ['docker', 'inspect']:
            return subprocess.CompletedProcess(command, 1, stdout='',
                                               stderr='Error: No such object: ' + command[2])
        return subprocess.CompletedProcess(command, 0, stdout='', stderr='')
    monkeypatch.setattr(suite.subprocess, 'Popen', FakePopen)
    monkeypatch.setattr(suite.subprocess, 'run', fake_run)
    sentinel = suite.FnprSentinel(tmp_path)
    assert sentinel.mode == 'container'


def test_fnpr_sentinel_keeps_local_mode_and_fails_closed_on_other_errors(tmp_path, monkeypatch):
    class FakePopen:
        returncode = 0

        def __init__(self, command, **kwargs):
            self.pid = 777
            self.command = command
            log = Path(command[command.index('--log') + 1])
            log.write_text(json.dumps({'event': 'start_failed', 'reason': 'AddressInUse',
                                       'bind': '192.168.204.1', 'port': 443}) + '\n')

        def poll(self):
            return 0

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0
    monkeypatch.setattr(suite.subprocess, 'Popen', FakePopen)
    with pytest.raises(suite.SuiteError, match='did not become ready'):
        suite.FnprSentinel(tmp_path)


def test_listen_endpoint_set_parses_netstat_lines_including_ipv6():
    sections = {'listen_ports':
                'TCP 0.0.0.0:135 0.0.0.0:0 LISTENING\n'
                'TCP [::]:135 [::]:0 LISTENING\n'
                'UDP 192.168.204.233:55346 *:*\n'
                'garbage line\n'}
    parsed = suite.Suite._listen_endpoint_set(sections)
    assert ('TCP', '0.0.0.0:135') in parsed
    assert ('TCP', ':::135') in parsed
    assert ('UDP', '192.168.204.233:55346') in parsed
    assert len(parsed) == 3


def test_section_difference_attribution_separates_residue_from_external():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    before = {'listen_ports': 'TCP 0.0.0.0:135 0.0.0.0:0 LISTENING\n'}
    after = {'listen_ports': ('TCP 0.0.0.0:135 0.0.0.0:0 LISTENING\n'
                              'UDP 192.168.204.233:55346 *:*\n'
                              'UDP 192.168.204.233:53601 *:*\n'
                              'TCP 192.168.204.233:55999 0.0.0.0:0 LISTENING\n')}
    table = [
        {'proto': 'UDP', 'local': '192.168.204.233:55346', 'pid': 11,
         'name': 'fakenetng-mcp-managed.exe', 'command': r'C:\x\fakenetng-mcp-managed.exe'},
        {'proto': 'UDP', 'local': '192.168.204.233:53601', 'pid': 12,
         'name': 'powershell.exe',
         'command': r'powershell.exe -File C:\ProgramData\FakeNet-NG-MCP\logs\scenario-suite-20260912\scenario_probes.ps1'},
        {'proto': 'TCP', 'local': '192.168.204.233:55998', 'pid': 13,
         'name': 'svchost.exe', 'command': 'C:\\Windows\\svchost.exe -k netsvcs'},
    ]
    runner._listening_endpoint_owners = lambda: table

    result = runner._attribute_section_difference(before, after)
    # 55999 vanished (table lists 55998), 55346 is product residue, 53601 is
    # probe residue; only vanished/external may be non-blocking.
    assert [row['local'] for row in result['residue']] == ['192.168.204.233:53601',
                                                           '192.168.204.233:55346']
    assert [row['local'] for row in result['vanished']] == ['192.168.204.233:55999']
    assert result['external'] == []

    table_external = [{'proto': 'UDP', 'local': '192.168.204.233:53601', 'pid': 77,
                       'name': 'msedge.exe', 'command': r'C:\Program Files\msedge.exe'}]
    runner._listening_endpoint_owners = lambda: table_external
    result = runner._attribute_section_difference(before, after)
    assert result['residue'] == []
    assert {row['local'] for row in result['external']} == {'192.168.204.233:53601'}
    assert {row['local'] for row in result['vanished']} == {
        '192.168.204.233:55346', '192.168.204.233:55999'}


def test_section_difference_attribution_fails_closed_on_query_error():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    before = {'listen_ports': ''}
    after = {'listen_ports': 'UDP 192.168.204.233:55346 *:*\n'}

    def failing_query():
        raise suite.SuiteError('listening endpoint ownership query failed')
    runner._listening_endpoint_owners = failing_query
    result = runner._attribute_section_difference(before, after)
    assert result['residue'] == [['UDP', '192.168.204.233:55346']]
    assert 'attribution_error' in result


def test_kernel_capture_stop_tolerates_absent_session():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    captured = {}

    def fake_vm_json(command, timeout):
        captured['command'] = command
        files = [{'path': r'C:\x\kernel-network.etl', 'bytes': 1, 'sha256': 'a' * 64}]
        return {'files': files}, 'raw'
    runner._vm_json = fake_vm_json
    result = runner._stop_kernel_capture({
        'metadata': r'C:\x\m.json', 'session_name': 'sst-kernel-session'})
    assert result['files']
    command = captured['command']
    # An already-ended session (WMI GUID error from logman stop) must be
    # detected by query instead of failing the whole capture cleanup.
    assert 'logman query $m.session_name -ets' in command
    assert command.index('logman query $m.session_name') < command.index('logman stop $m.session_name')
    assert 'session_present_at_stop' in command


def test_restart_baseline_uses_attribution_for_vanished_endpoints():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    before = {'dns_servers': '192.168.204.2', 'routes': '', 'listen_ports': 'TCP 0.0.0.0:135 0.0.0.0:0 LISTENING\n',
              'windivert_processes': '', 'services': ''}
    after = dict(before, listen_ports=before['listen_ports'] +
                 'TCP 192.168.204.233:17858 0.0.0.0:0 LISTENING\n')
    first = {'run_id': 'r', 'five_sections_before': before, 'five_sections_after': after,
             'recovery_audit': {'files': [{'path': 'a.jsonl'}]}}
    runner._listening_endpoint_owners = lambda: []
    vanished = runner._restart_baseline(first)
    assert vanished == after
    product_owned = [{'proto': 'TCP', 'local': '192.168.204.233:17858', 'pid': 9,
                      'name': 'fakenetng-mcp-managed.exe', 'command': 'C:\\x\\managed.exe'}]
    runner._listening_endpoint_owners = lambda: product_owned
    with pytest.raises(suite.SuiteError, match='restart run-01 five-section recovery difference'):
        runner._restart_baseline(first)


def test_runtime_pcap_candidates_require_complete_hash(tmp_path):
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    fake = {'calls': []}

    class FakeReceive:
        def __call__(self, vm, chosen, destination):
            fake['calls'].append(chosen)
            return {'sha256': chosen['sha256'], 'path': str(destination)}

    import types
    transfer_mod = types.ModuleType('artifact_transfer')
    transfer_mod.receive_artifact = FakeReceive()
    import sys as _sys
    _sys.modules['artifact_transfer'] = transfer_mod
    artifacts = {'artifacts': [
        {'path': r'C:\a\r1\x.pcapng', 'type': 'pcap', 'sha256': None, 'size': 10},
        {'path': r'C:\a\r1\x.pcapng', 'type': 'pcap', 'sha256': 'b' * 64, 'size': 10},
    ]}
    result = runner._transfer_runtime_pcap(artifacts, 'r1', tmp_path / 'x.pcap')
    assert result['sha256'] == 'b' * 64
    assert fake['calls'][0]['sha256'] == 'b' * 64


def test_vm_footprint_prune_removes_exported_benign_runs_only(tmp_path):
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    commands = []

    def fake_vm_json(command, timeout):
        commands.append(command)
        return {'pruned_runs': [], 'guest_removed': False}, 'raw'
    runner._vm_json = fake_vm_json
    runner._status = lambda timeout=30: {'state': 'stopped', 'run_id': None, 'controller': None}
    runs = [{'run_id': 'r-1', 'originals': {'files': []}},
            {'run_id': 'r-2', 'originals': None}]
    result = runner._prune_scenario_vm_footprint(runs, r'C:\g\sst-x', None,
                                                 scenario_passed=True)
    assert result['raw'] == 'raw'
    command = commands[0]
    assert 'r-1' in command and 'r-2' not in command
    assert r'C:\g\sst-x'.replace('\\', '\\\\') in command or 'sst-x' in command
    # fault 场景保留 VM 侧 incident 证据，仅清探针目录
    commands.clear()
    runner._prune_scenario_vm_footprint(runs, r'C:\g\sst-x', 'listener_stop',
                                        scenario_passed=True)
    assert 'r-1' not in commands[0] and 'sst-x' in commands[0]
    # 服务未释放 run（failed/恢复责任未清）时不动 artifacts，防止破坏恢复证据
    commands.clear()
    runner._status = lambda timeout=30: {'state': 'failed', 'run_id': 'r-1', 'controller': 'c'}
    skipped = runner._prune_scenario_vm_footprint(runs, r'C:\g\sst-x', None,
                                                   scenario_passed=True)
    assert skipped['service_released_runs'] is False
    assert 'r-1' not in commands[0]


def test_prune_scenario_configs_deletes_only_own_leftovers_and_rebinds_active():
    runner = object.__new__(suite.Suite)
    status = {'state': 'stopped', 'state_version': 7,
              'config_identity': {'name': 'sst-003-active-a1.ini'}}
    reads = {'sst-003-active-a1.ini': {'sha256': 'aa'},
             'sst-003-import-a1.ini': {'sha256': 'cc'},
             'sst-016-scratch-a2.ini': {'sha256': 'bb'}}

    class FakeService:
        def tool(self, name, args=None, timeout=None):
            calls.append((name, dict(args or {})))
            if name == 'list_configs':
                return {'configs': [
                    {'name': 'default.ini'}, {'name': 'sst-003-active-a1.ini'},
                    {'name': 'sst-003-import-a1.ini'}, {'name': 'sst-016-scratch-a2.ini'}]}
            if name == 'read_config':
                return reads.get(args['name'], {'error': 'missing'})
            if name == 'load_config':
                status['config_identity'] = {'name': args['name']}
                status['state_version'] += 1
                return dict(status)
            if name == 'delete_config':
                removed.append(args['name'])
                status['state_version'] += 1
                return dict(status)
            raise AssertionError('unexpected tool ' + name)

    calls = []
    removed = []
    runner.service = FakeService()
    runner._status = lambda timeout=60: dict(status)
    record = runner._prune_scenario_configs('sst-003')
    assert sorted(record['deleted']) == ['sst-003-active-a1.ini', 'sst-003-import-a1.ini']
    assert record['rebound'] == 'default.ini'
    assert not record['failures']
    # The other scenario's config and the builtin stay untouched.
    assert 'sst-016-scratch-a2.ini' not in removed
    assert 'default.ini' not in removed
    # Active leftover must be rebound before its delete.
    load_index = next(i for i, (n, _) in enumerate(calls) if n == 'load_config')
    delete_active = next(i for i, (n, a) in enumerate(calls)
                         if n == 'delete_config' and a['name'] == 'sst-003-active-a1.ini')
    assert load_index < delete_active


def test_cases_verdict_applies_the_same_demand_inside_fault_windows():
    """A fault label alone waives nothing (2026-09-20 VFY-003 rollback).

    The former ``if fault_window: return True`` branch let any fault run
    skip the auxiliary-case demand without one byte of window proof
    (discovery100-118/121 sst-034 stored passes).  The demand is now
    identical with and without the flag; ``fault_window`` is accepted for
    call compatibility only and must never change the verdict.
    """
    verdict = suite.Suite._cases_verdict
    assert verdict(planned=2, releases=1, case_results=[{'passed': True}], fault_window=True) is True
    assert verdict(planned=0, releases=0, case_results=[], fault_window=True) is True
    assert verdict(planned=2, releases=0, case_results=[], fault_window=True) is False
    assert verdict(planned=2, releases=1, case_results=[{'passed': False}], fault_window=True) is False
    for fault_window in (True, False):
        assert verdict(planned=0, releases=0, case_results=[], fault_window=fault_window) is True
        assert verdict(planned=2, releases=1, case_results=[{'passed': True}],
                       fault_window=fault_window) is True
        assert verdict(planned=2, releases=0, case_results=[], fault_window=fault_window) is False
        assert verdict(planned=2, releases=1, case_results=[{'passed': False}],
                       fault_window=fault_window) is False


def _b3_redirect_allow_fixture(root: Path, nic_originals: list):
    """One complete B3 redirect_allow run; NIC originals for the forbidden
    original tuple are injected via ``nic_originals``."""
    runner = object.__new__(suite.Suite)
    runner.root = root
    runner.identity = suite.Identity(candidate_id='mcp-fixture', source_commit='s',
                                     package_sha256='0' * 64)
    profile = suite.materialize_probe_profile(suite.profile_for_bucket('B3', 0), '192.168.204.1')
    nonce = 'oracle-fault'
    ready = {'event': 'ready', 'nonce': nonce, 'profile': profile['bucket'],
             'variant': profile['variant'], 'tempo': profile['tempo'],
             'interleave': profile['interleave'], 'cadence_ms': profile['cadence_ms'],
             'target_host': profile['probe_target']['host'],
             'target_port': profile['probe_target']['port'],
             'target_protocol': profile['probe_target']['protocol'],
             'process_mode': profile['probe_target']['process_mode'],
             'fnpr_role': profile['probe_target']['fnpr_role'],
             'startup_retry_seconds': profile['startup_retry_seconds'],
             'additional_targets': []}
    rows = [ready, {'event': 'released', 'nonce': nonce, 'interleave': profile['interleave']},
            {'event': 'established', 'nonce': nonce, 'connection_id': 'main', 'pid': 777,
             'worker': 'w', 'seq': 1, 'src': '192.168.204.233:5000',
             'dst': '198.51.100.77:443', 'actual_dst': '198.51.100.77:443'},
            {'event': 'send', 'nonce': nonce, 'connection_id': 'main', 'pid': 777,
             'cadence_ms': profile['cadence_ms'], 'utc_ticks': 1_000_000_000},
            {'event': 'send', 'nonce': nonce, 'connection_id': 'main', 'pid': 777,
             'cadence_ms': profile['cadence_ms'],
             'utc_ticks': 1_000_000_000 + profile['cadence_ms'] * 10_000},
            {'event': 'close', 'nonce': nonce, 'connection_id': 'main', 'pid': 777}]
    (root / 'probe.jsonl').write_text('\n'.join(json.dumps(row) for row in rows) + '\n',
                                      encoding='utf-8')
    (root / 'pktmon.txt').write_text('pktmon fixture\n', encoding='utf-8')
    (root / 'run.log').write_text(
        'EGRESS_CONTROL_READY\n'
        'PROCESS_REDIRECT_MAPPING_CREATED original_ipv4=198.51.100.77 original_port=443 '
        'pid=777 source_ipv4=192.168.204.233 source_port=5000 '
        'target_ipv4=192.168.204.1 target_port=443\n', encoding='utf-8')

    def packets(capture, src, dst, protocol, not_after_local=None, not_before_local=None):
        if dst == '198.51.100.77:443':
            # Primary original tuple: the all-stack record proves the send;
            # the physical-NIC leg is exactly the injected leak counterexample.
            return ([{'src': src, 'dst': dst, 'protocol': protocol}],
                    list(nic_originals), {'component_ids': [9]})
        if dst == '192.168.204.1:443':
            return ([{'src': src, 'dst': dst, 'protocol': protocol}],
                    [{'component': 9}], {'component_ids': [9]})
        raise AssertionError('unexpected tuple observed: %s -> %s' % (src, dst))

    runner._pktmon_observations = packets
    run = {'capture': {'probe_path': 'probe.jsonl', 'pktmon_path': 'pktmon.txt'},
           'originals': {'files': [{'path': 'run.log'}]}}
    sentinel = {'rows': [{'event': 'probe_ok', 'nonce': nonce, 'role': 'target',
                          'transport': 'tcp', 'peer': '192.168.204.233:5000'}]}
    return runner, run, profile, nonce, sentinel


def test_fault_window_does_not_waive_forbidden_nic_original_traffic():
    """redirect_allow + a forbidden original-tuple NIC packet must fail.

    discovery100-121 sst-034 stored a pass with
    ``nic_original_packet_count=1`` and ``fault_window_branch_waiver=true``.
    The branch leg (no original NIC packets, policy mapping, sentinel
    receipt) applies identically inside a fault window; the fault label is
    not proof that the packet belongs to the fault's own effect.
    """
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        runner, run, profile, nonce, sentinel = _b3_redirect_allow_fixture(
            root, nic_originals=[{'component': 9, 'timestamp_local': '2026-09-15 08:36:10.0000000'}])
        fault = runner._traffic_oracle(run, profile, nonce, sentinel, fault_window=True)
        offline = runner._traffic_oracle(run, profile, nonce, sentinel)
        assert not fault['passed'] and not offline['passed']
        assert fault['nic_original_packet_count'] == 1
        # Same original evidence, same conclusion and the same reason — the
        # online fault call and the offline recheck are one verdict path.
        assert fault['reason'] == offline['reason']
        assert 'branch' in fault['reason']
        # The clean counterpart (no NIC originals) passes in both modes.
        clean_root = root / 'clean'
        clean_root.mkdir()
        clean_runner, clean_run, clean_profile, clean_nonce, clean_sentinel = (
            _b3_redirect_allow_fixture(clean_root, nic_originals=[]))
        assert clean_runner._traffic_oracle(
            clean_run, clean_profile, clean_nonce, clean_sentinel, fault_window=True)['passed']
        assert clean_runner._traffic_oracle(
            clean_run, clean_profile, clean_nonce, clean_sentinel)['passed']


def test_fault_window_does_not_waive_missing_auxiliary_case_evidence():
    """A fault label cannot replace the auxiliary-case demand (VFY-003).

    Planned boundary cases with no release and no case events previously
    passed via ``_cases_verdict(fault_window=True)``; the release facts and
    the per-case verdicts are now demanded in every mode.
    """
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        runner, run, profile, nonce, sentinel = _b3_redirect_allow_fixture(root, nic_originals=[])
        # B3 plans no auxiliary cases; graft a planned pair onto the profile
        # and onto the probe contract so the fixture exercises the demand.
        profile = json.loads(json.dumps(profile))
        profile['negative_cases'] = (
            {'host': 'example.com', 'port': 443, 'protocol': 'tls', 'expectation': 'deny'},)
        profile['probe_cases'] = (
            {'host': '192.168.204.1', 'port': 443, 'protocol': 'tcp',
             'expectation': 'takeover_allow', 'fnpr_role': 'target'},)
        rows = [json.loads(line) for line in
                (root / 'probe.jsonl').read_text(encoding='utf-8').splitlines()]
        for row in rows:
            if row.get('event') == 'ready':
                row['additional_targets'] = list(profile['negative_cases']) + list(profile['probe_cases'])
        (root / 'probe.jsonl').write_text(
            '\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
        # No 'cases_released' row and no case_* events exist: the demand is
        # unmet and no fault label may excuse it.
        missing = runner._traffic_oracle(run, profile, nonce, sentinel, fault_window=True)
        offline = runner._traffic_oracle(run, profile, nonce, sentinel)
        assert not missing['passed'] and not offline['passed']
        assert missing['reason'] == offline['reason']
        assert 'cases' in missing['reason']


def test_fault_window_does_not_mask_wrong_run_identity():
    """A same-run identity mismatch fails in fault mode too (VFY-003/004).

    Two shapes: probe rows carrying another run's nonce (the schedule check
    rejects them) and a fault primary case bound to a different run_id
    (the identity check rejects it).  Neither may be excused by the fault
    label.
    """
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        runner, run, profile, nonce, sentinel = _b3_redirect_allow_fixture(root, nic_originals=[])
        rows = [json.loads(line) for line in
                (root / 'probe.jsonl').read_text(encoding='utf-8').splitlines()]
        for row in rows:
            if row.get('event') == 'ready':
                row['nonce'] = 'nonce-of-another-run'
        (root / 'probe.jsonl').write_text(
            '\n'.join(json.dumps(row) for row in rows) + '\n', encoding='utf-8')
        wrong_nonce = runner._traffic_oracle(run, profile, nonce, sentinel, fault_window=True)
        assert not wrong_nonce['passed']
        assert 'schedule' in wrong_nonce['reason']

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        runner, run, profile, nonce, sentinel = _b3_redirect_allow_fixture(root, nic_originals=[])
        case_path = root / 'fault-case.json'
        case_path.write_text(json.dumps({
            'schema': 'sst.fault-evidence.case.v2', 'synthetic': False,
            'run_id': 'a-different-run', 'nonce': nonce, 'candidate_id': 'mcp-fixture',
            'session': {'observation_kind': 'tcpip_etw', 'probe_pid': 777,
                        'connection_id': '777-w-1', 'src': '192.168.204.233:5000',
                        'dst': '198.51.100.77:443'}}), encoding='utf-8')
        run['fault_connection_case'] = suite.file_record(case_path, root)
        wrong_case = runner._traffic_oracle(run, profile, nonce, sentinel, fault_window=True)
        assert not wrong_case['passed']
        assert 'fault primary binding failed' in wrong_case['reason']
        assert 'same-run target connection' in wrong_case['reason']


def test_full_positive_fault_evidence_adjudicates_identically_online_and_offline():
    """Complete positive evidence passes in both modes with one verdict.

    Online (fault healthy primary) and offline recheck share the same
    originals, the same identity inputs and — after the waiver removal —
    byte-identical oracle verdicts including the recorded reason.
    """
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        runner, run, profile, nonce, sentinel = _b3_redirect_allow_fixture(root, nic_originals=[])
        online = runner._traffic_oracle(run, profile, nonce, sentinel, fault_window=True)
        offline = runner._traffic_oracle(run, profile, nonce, sentinel)
        assert online['passed'] and offline['passed']
        assert online == offline
        assert online['reason'] is None


def test_every_bucket_has_real_restart_and_start_stop_coverage():
    for seed in (20260912, 20260913, 0, 99):
        manifest = suite.build_manifest(seed)
        for bucket in suite.BUCKET_COUNTS:
            rows = [r for r in manifest['scenarios']
                    if r['config_profile']['bucket'] == bucket and not r['fault_class']]
            assert {r['lifecycle_chain'] for r in rows} == {'restart', 'start-stop'}
        for row in manifest['scenarios']:
            restart = row['lifecycle_chain'] == 'restart'
            names = [item['tool'] for item in row['interface_call_plan']]
            assert ('restart' in names) == restart
            if row['config_profile']['interleave'] == 'restart-window':
                assert restart


def test_manifest_rejects_restart_label_without_restart_operation():
    manifest = suite.build_manifest(20260912)
    row = next(r for r in manifest['scenarios'] if not r['fault_class'])
    row['config_profile']['interleave'] = 'restart-window'
    row['lifecycle_chain'] = 'start-stop'
    row['interface_call_plan'] = [i for i in row['interface_call_plan'] if i['tool'] != 'restart']
    assert any('restart' in issue for issue in suite.manifest_issues(manifest))


def test_policy_boundaries_are_not_tied_to_one_timing_axis():
    profiles = [suite.profile_for_bucket('B1', i) for i in range(25)]
    for expectation in {(p['probe_target']['host'], p['probe_target']['protocol'],
                         p['probe_target'].get('tls_server_name')) for p in profiles}:
        rows = [p for p in profiles if (p['probe_target']['host'], p['probe_target']['protocol'],
                                       p['probe_target'].get('tls_server_name')) == expectation]
        assert len({p['interleave'] for p in rows}) == 5
    profiles = [suite.profile_for_bucket('B4', i) for i in range(20)]
    for variant in {p['variant'] for p in profiles}:
        rows = [p for p in profiles if p['variant'] == variant]
        assert len({p['tempo'] for p in rows}) == 4
        assert len({p['interleave'] for p in rows}) == 4


def test_runtime_pcaps_collected_per_run_after_final_stop(tmp_path):
    """T005-R02: each healthy run binds its own run id to its own pcap."""
    runner = suite.Suite.__new__(suite.Suite)
    calls = []

    def wait(run_id, destination):
        calls.append((run_id, destination))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b'pcap-' + run_id.encode())
        return {'run_id': run_id, 'destination': str(destination)}

    runner._wait_runtime_pcap = wait
    profile = suite.profile_for_bucket('default', 0, in_bucket=0)
    assert suite.runtime_pcap_required(profile)
    evidence = suite.Evidence(tmp_path)
    runs = [
        {'label': 'run-01', 'run_id': 'r1', 'start_response': {'state': 'healthy'}},
        {'label': 'run-02', 'run_id': 'r2', 'start_response': {'state': 'healthy'}},
        {'label': 'run-03', 'run_id': 'r3', 'start_response': {'state': 'failed'}},
    ]
    runner._collect_runtime_pcaps(runs, tmp_path, evidence, profile)
    assert calls == [(runs[0]['run_id'], tmp_path / 'run-01' / 'runtime.pcap'),
                     (runs[1]['run_id'], tmp_path / 'run-02' / 'runtime.pcap')]
    assert runs[0]['runtime_pcap']['run_id'] == 'r1'
    assert runs[1]['runtime_pcap']['run_id'] == 'r2'
    assert 'runtime_pcap' not in runs[2]
    single = [{'label': 'run-01', 'run_id': 'only', 'start_response': {'state': 'healthy'}}]
    calls.clear()
    runner._collect_runtime_pcaps(single, tmp_path, evidence, profile)
    assert calls == [('only', tmp_path / 'run-01' / 'runtime.pcap')]
    # Non-pcap profiles collect nothing at all.
    calls.clear()
    runner._collect_runtime_pcaps(runs, tmp_path, evidence,
                                  suite.profile_for_bucket('B2', 0))
    assert calls == []


def test_vm_footprint_prune_keeps_failed_scenario_originals(tmp_path):
    """T005-R02: a failed scenario never deletes its VM-side evidence."""
    for scenario_passed, expect_vm_command in ((False, False), (True, True)):
        runner = suite.Suite.__new__(suite.Suite)
        runner.vm = object()
        released = {'state': 'stopped', 'run_id': None, 'controller': None}
        runner._status = lambda: released
        vm_commands = []

        def vm_json(command, timeout):
            vm_commands.append(command)
            return {'pruned_runs': [], 'guest_removed': False}, 'raw'
        runner._vm_json = vm_json
        runs = [{'run_id': 'r1', 'originals': {'files': [{'path': 'run.log'}]}}]
        result = runner._prune_scenario_vm_footprint(
            runs, r'C:\guest\probe', None, scenario_passed=scenario_passed)
        assert bool(vm_commands) is expect_vm_command
        if not scenario_passed:
            assert result['pruned_runs'] == [] and result['guest_removed'] is False
            assert result['kept_guest'] == r'C:\guest\probe'
            assert result['kept_runs'] == ['r1']
            assert 'failure originals kept' in result['prune_skipped_reason']
        else:
            assert 'Remove-Item' in vm_commands[0]


def test_vm_footprint_prune_keeps_runs_while_service_bound():
    runner = suite.Suite.__new__(suite.Suite)
    runner.vm = object()
    runner._status = lambda: {'state': 'recovering', 'run_id': 'x', 'controller': 'y'}
    vm_commands = []

    def vm_json(command, timeout):
        vm_commands.append(command)
        return {'pruned_runs': [], 'guest_removed': False}, 'raw'
    runner._vm_json = vm_json
    runs = [{'run_id': 'r1', 'originals': {'files': [{'path': 'run.log'}]}}]
    result = runner._prune_scenario_vm_footprint(
        runs, r'C:\guest\probe', None, scenario_passed=True)
    assert result['pruned_runs'] == []
    # The guest probe directory is transient even for a bound service, but no
    # run artifacts are removed while the service still holds them.
    assert 'runs' in vm_commands[0] and 'Remove-Item' in vm_commands[0]
    assert "Join-Path $runs 'r1'" not in vm_commands[0]


def test_short_window_deny_passes_through_native_record():
    """An inverted conservative wall interval passes via the native record.

    candidate10-12 sst-004 case-4: the deny session lives ~10ms, shorter
    than twice the frozen 15,625,000ns wall-timer uncertainty, so the wall
    containment is structurally unsatisfiable.  The relay's native terminal
    record (FILETIME with a QPC bracket) judges the same decision inside
    the case's own ETW window in one clock domain.
    """
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        runner, profile, nonce, run, sentinel, deny_line, deny_ns = \
            _b1_sni_oracle_fixture(root, observation_end_lower_delay_ms=-200,
                                   native_deny=True)
        case4 = runner._traffic_oracle(run, profile, nonce, sentinel)['cases'][3]
        assert case4['passed'], case4
        binding = case4['sni_binding']
        assert binding['contract_version'] == 2
        native = binding['native_deny']
        assert native['generation'] == 2
        assert native['etw_connect_upper_ns'] <= native['filetime_ns'] <= \
            native['etw_terminal_lower_ns']


def test_native_deny_rejects_substitutes():
    """Every weaker or misplaced native record keeps the case failing."""
    cases = [
        ('filetime outside the ETW window', dict(
            observation_end_lower_delay_ms=-200, native_deny=True,
            native_shift_ns=100 * 10**6)),
        ('duplicate records stay ambiguous', dict(
            observation_end_lower_delay_ms=-200, native_deny=True,
            native_duplicate=True)),
        ('unsupported clock is not native evidence', dict(
            observation_end_lower_delay_ms=-200, native_deny=True,
            native_unsupported=True)),
    ]
    for name, kwargs in cases:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, profile, nonce, run, sentinel, _, _ = \
                _b1_sni_oracle_fixture(root, **kwargs)
            case4 = runner._traffic_oracle(run, profile, nonce,
                                           sentinel)['cases'][3]
            assert not case4['passed'], name
            assert not case4.get('sni_binding'), name


def test_pktmon_exact_nic_tx_counts_rst_and_other_packets(tmp_path):
    """The real selector retains exact physical Tx, including short RSTs."""
    header = ('[02]1CB4.11C4::2026-09-21 13:38:54.917249300 '
              '[Microsoft-Windows-PktMon] PktGroupId 1，PktNumber 1，出现 1，'
              '方向 %s ，类型 以太网 ，组件 %d，边缘 1，筛选器 0，'
              'OriginalSize %d，LoggedSize %d \n')
    body = ('\t00-0C-29-C1-CA-49 > 00-50-56-E7-FE-AA, ethertype IPv4 (0x0800), '
            'length %d: %s > %s: Flags [%s], seq 1, ack 1, win 0, length 0\n')
    source, target = '192.168.204.233.50161', '198.51.100.77.1337'
    def record(size, src=source, dst=target, flags='R.', component=9, direction='Tx'):
        return header % (direction, component, size, size) + body % (size, src, dst, flags)
    trace = ('MSNT_SystemTrace Header\r\nEventsLost: 0\r\nBuffersLost: 0\r\n' +
             record(54) + record(60) + record(194, flags='P.') +
             record(54, src='192.168.204.233.50162') +
             record(54, component=20) + record(54, direction='Rx'))
    (tmp_path / 'pktmon.txt').write_text(trace, encoding='utf-8')
    metadata = {'schema': suite.NIC_CAPTURE_SCHEMA,
                'pktmon_list': ' 9 00-0C-29-C1-CA-49 Intel(R) 82574L Gigabit Network Connection\n',
                'adapters': [{'ifIndex': 11, 'Name': 'Ethernet0',
                              'InterfaceDescription': 'Intel(R) 82574L Gigabit Network Connection',
                              'MacAddress': '00-0C-29-C1-CA-49', 'Status': 'Up'}],
                'pktmon_status_after': '数据包监视器没有运行。'}
    (tmp_path / 'pktmon-nic.json').write_text(json.dumps(metadata), encoding='utf-8')
    runner = suite.Suite.__new__(suite.Suite)
    runner.root = tmp_path
    all_packets, nic_packets, binding = runner._pktmon_observations(
        {'pktmon_path': 'pktmon.txt', 'pktmon_nic_path': 'pktmon-nic.json'},
        '192.168.204.233:50161', '198.51.100.77:1337', 'TCP')
    assert binding['component_ids'] == [9]
    assert [(p['original_size'], p['flags']) for p in nic_packets] == [
        (54, 'R.'), (60, 'R.'), (194, 'P.')]
    assert len(all_packets) == 4  # includes matching tuple on unbound component 20


@pytest.mark.parametrize(('delta_ns', 'expected'), [
    (-2_000_000, False), (-1_000_000, False), (-100, False),
    (0, True), (5_000_000, True), (10_000_000, True),
    (10_000_100, False), (11_000_000, False), (12_000_000, False),
])
def test_native_deny_uses_closed_etw_interval(tmp_path, delta_ns, expected):
    runner = suite.Suite.__new__(suite.Suite)
    lo = 1_790_000_000_000_000_000
    hi = lo + 10_000_000
    row = {'schema': 'fakenetng.relay-native-terminal.v1', 'outcome': 'deny',
           'reason_code': 'sni_mismatch', 'generation': 2,
           'src': '192.168.204.233', 'sport': 50161,
           'original_ip': '119.188.175.46', 'original_port': 443,
           'sni': 'example.com',
           'clock': {'supported': True,
                     'filetime_100ns': (lo + delta_ns + 11644473600000000000) // 100}}
    (tmp_path / 'relay-native-events.jsonl').write_text(json.dumps(row) + '\n', encoding='utf-8')
    actual = runner._native_deny_contained(
        tmp_path / 'run.log', 2, ('192.168.204.233', '50161'),
        ('119.188.175.46', '443'), 'example.com',
        {'etw_connect_upper_ns': lo, 'etw_terminal_lower_ns': hi})
    assert (actual is not None) is expected
    if expected:
        assert actual['filetime_ns'] == lo + delta_ns


def test_native_deny_rejects_wrong_identity_and_duplicate(tmp_path):
    runner = suite.Suite.__new__(suite.Suite)
    lo = 1_790_000_000_000_000_000
    row = {'schema': 'fakenetng.relay-native-terminal.v1', 'outcome': 'deny',
           'reason_code': 'sni_mismatch', 'generation': 2,
           'src': '192.168.204.233', 'sport': 50161,
           'original_ip': '119.188.175.46', 'original_port': 443,
           'sni': 'example.com',
           'clock': {'supported': True,
                     'filetime_100ns': (lo + 11644473600000000000) // 100}}
    path = tmp_path / 'relay-native-events.jsonl'
    def judge(**changes):
        path.write_text(json.dumps(row | changes) + '\n', encoding='utf-8')
        return runner._native_deny_contained(
            tmp_path / 'run.log', 2, ('192.168.204.233', '50161'),
            ('119.188.175.46', '443'), 'example.com',
            {'etw_connect_upper_ns': lo, 'etw_terminal_lower_ns': lo + 10_000_000})
    assert judge() is not None
    for changes in ({'generation': 3}, {'sport': 50162},
                    {'original_ip': '119.188.175.47'}, {'sni': 'other.example'}):
        assert judge(**changes) is None
    path.write_text((json.dumps(row) + '\n') * 2, encoding='utf-8')
    assert runner._native_deny_contained(
        tmp_path / 'run.log', 2, ('192.168.204.233', '50161'),
        ('119.188.175.46', '443'), 'example.com',
        {'etw_connect_upper_ns': lo, 'etw_terminal_lower_ns': lo + 10_000_000}) is None
