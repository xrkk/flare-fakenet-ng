"""Synthetic refusal contract bytes, never native acceptance evidence.

The nonmatch fixture exercises the real hash/tuple/event/native-A validators.
No predicate or integrity check is mocked and no ignored Logs are required.
"""
import copy
import hashlib
import json
from pathlib import Path
from test_scenario_suite import suite


def nonmatch_refusal(tmp_path):
    nonce, pid = 'sst-039-a1-test', 3832
    creation = 639261396537083524
    profile = {'bucket': 'B3', 'interleave': 'before-start',
               'probe_target': {'process_mode': 'nonmatch', 'protocol': 'tcp',
                                'host': '198.51.100.77', 'port': 443,
                                'expectation': 'ordinary_path'}}
    folder = tmp_path / 'evidence' / 'sst-039' / 'attempt-01'
    probe_dir = folder / 'run-01'
    probe_dir.mkdir(parents=True)
    (folder / 'run-01-capture-start.json').write_text(json.dumps({
        'nonce': nonce, 'pid': pid, 'probe_creation_ticks': creation,
        'capture_run_id': nonce + ':run-01', 'run_label': 'run-01',
        'interleave': 'before-start', 'probe_target': profile['probe_target']}), encoding='utf-8')
    probe = [
        {'event': 'ready', 'nonce': nonce, 'pid': pid, 'creation_ticks': creation,
         'native_identity': {'pid': pid, 'nonce': nonce,
                             'run_id': nonce + ':run-01',
                             'creation_filetime_100ns': creation - 504911232000000000},
         'target_host': '198.51.100.77', 'target_port': 443,
         'target_protocol': 'tcp', 'process_mode': 'nonmatch', 'interleave': 'before-start',
         'utc': '2026-09-27T21:00:54.400Z'},
        {'event': 'released', 'nonce': nonce, 'pid': pid, 'utc': '2026-09-27T21:00:54.950Z'},
        {'event': 'connect_attempt', 'nonce': nonce, 'pid': pid,
         'connection_id': nonce + '-1', 'dst': '198.51.100.77:443',
         'utc': '2026-09-27T21:00:54.969Z'},
        {'event': 'finished', 'nonce': nonce, 'pid': pid,
         'utc': '2026-09-27T21:01:50Z'},
    ]
    (probe_dir / 'probe.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in probe), encoding='utf-8')
    xml = ("<Event><System><Provider Name='Microsoft-Windows-Kernel-Network'/>"
           "<Task>10</Task><TimeCreated SystemTime='2026-09-27T21:00:55Z'/></System>"
           "<EventData><Data Name='PID'>3832</Data><Data Name='daddr'>1298412486</Data>"
           "<Data Name='dport'>47873</Data><Data Name='sport'>18628</Data></EventData></Event>")
    (probe_dir / 'kernel-network.events.jsonl').write_text(json.dumps({'ordinal': 61, 'xml': xml}) + '\n')
    for name in ('kernel-network.etl', 'pktmon.etl', 'pktmon.txt', 'pktmon-nic.json'):
        (probe_dir / name).write_bytes(b'original')
    prefix = '[01]0EF8.0154::2026-09-28 05:00:54.'
    pktmon_text = (
        '[00]0EF8.0154::2026-09-28 05:00:53.000000000 [MSNT_SystemTrace] '
        'EndTime: 134350164700000000, EventsLost: 0, StartTime: 134350164530000000, '
        'BuffersLost: 0, LogFileNameString: X:\\pktmon.etl\n'
        + prefix + '976181000 [Microsoft-Windows-TCPIP] TCP: connection 0x1 '
        'transition from ClosedState  to SynSentState , SndNxt = 0.\n'
        + prefix + '976196400 [Microsoft-Windows-TCPIP] TCP: Tcb 0x1 '
        '(local=192.168.204.233:50248 remote=198.51.100.77:443) '
        'requested to connect. PID = 3832.\n'
        + prefix + '976235100 [Microsoft-Windows-TCPIP] TCP: Tcb 0x1 '
        'is going to output SYN with ISN = 7, RcvWnd = 64240, RcvWndScale = 8.\n'
        + prefix + '976249900 [Microsoft-Windows-PktMon] 方向 Tx ，类型 以太网 ，'
        '组件 9，OriginalSize 66，LoggedSize 66\n'
        '\tethertype IPv4: 192.168.204.233.50248 > 198.51.100.77.443: '
        'Flags [S], seq 7, length 0\n')
    (probe_dir / 'pktmon.txt').write_text(pktmon_text, encoding='utf-8')
    (probe_dir / 'pktmon-nic.json').write_text(json.dumps({
        'schema': suite.NIC_CAPTURE_SCHEMA, 'pktmon_status_after': 'stopped',
        'pktmon_list': '9 00-0C-29-C1-CA-49 Intel(R) 82574L Gigabit Network Connection',
        'adapters': [{'MacAddress': '00-0C-29-C1-CA-49',
                      'InterfaceDescription': 'Intel(R) 82574L Gigabit Network Connection',
                      'Status': 'Up', 'ifIndex': 11, 'Name': 'Ethernet0'}],
        'capture_mode': 'all-components-tcpip',
        'clock_before': {'offset_minutes': 480, 'utc_ticks': 639261396520000000,
                         'mono': 0, 'stopwatch_frequency': 10000000},
        'clock_after': {'offset_minutes': 480, 'utc_ticks': 639261396710000000,
                        'mono': 190000000, 'stopwatch_frequency': 10000000},
        'conversion': {'argv': ['pktmon', 'etl2txt', 'X:\\pktmon.etl', '--out', 'X:\\pktmon.txt'],
                       'exit_code': 0,
                       'etl_sha256': hashlib.sha256((probe_dir / 'pktmon.etl').read_bytes()).hexdigest(),
                       'text_sha256': hashlib.sha256((probe_dir / 'pktmon.txt').read_bytes()).hexdigest()},
    }), encoding='utf-8')
    (probe_dir / 'kernel-network.summary.txt').write_text('Total Events Lost 0\n')
    records = [suite.file_record(path, tmp_path) for path in probe_dir.iterdir()]
    by_name = {Path(item['path']).name: item for item in records}
    (probe_dir / 'kernel-network.metadata.json').write_text(json.dumps({'conversion': {
        'etl_sha256': by_name['kernel-network.etl']['sha256'],
        'events_sha256': by_name['kernel-network.events.jsonl']['sha256'],
        'tracerpt_exit_code': 0, 'event_reader_exit_code': 0}}))
    records.append(suite.file_record(probe_dir / 'kernel-network.metadata.json', tmp_path))
    by_name['kernel-network.metadata.json'] = records[-1]
    sections = {key: '' for key in ('dns_servers', 'routes', 'listen_ports',
                                    'windivert_processes', 'services')}
    after_path = folder / 'five-sections-after.json'
    after_path.write_text(json.dumps({'sections': sections, 'difference': {},
                                      'difference_attribution': None}), encoding='utf-8')
    after_record = suite.file_record(after_path, tmp_path)
    reason = 'managed start failed: RuntimeError(' + suite.Suite._ACTIVE_A_REFUSAL_MARKER + ')'
    failure_at = '2026-09-27T21:01:07+00:00'
    failure_event = {'timestamp': 1790542867, 'kind': 'health', 'state': 'failed',
                     'failure_reason': reason}
    started = {'state': 'stopped', 'run_id': None, 'last_run_outcome': 'failed'}
    status = {'state': 'stopped', 'run_id': None, 'controller': None,
              'last_run_outcome': 'failed', 'failure_reason': reason}
    run = {'label': 'run-01', 'run_id': None, 'start_response': started,
           'started_at': '2026-09-27T21:01:34Z',
           'refusal_failure_utc': failure_at,
           'probe_release': {'phase': 'before-start', 'released_utc': '2026-09-27T21:00:54.941Z'},
           'capture': {'files': records, 'all_components': True,
                       'probe_launcher_pid': pid, 'pktmon_capture_issues': [],
                       'pktmon_binding': suite.pktmon_nic_binding(
                           json.loads((probe_dir / 'pktmon-nic.json').read_text(encoding='utf-8')))},
           'five_sections_before': sections, 'five_sections_after': sections,
           'refusal_status_samples': [status] * 3,
           'stop_response': {'state': 'stopped'},
           'traffic_oracle': {'status': 'NOT_EXECUTED', 'passed': None}}
    proof = suite.Suite._active_a_refusal_proof(tmp_path, profile, nonce, run)
    assert proof['syn_proofs'][0]['source'] == '192.168.204.233:50248'
    run['expected_refusal'] = {'reason': reason, 'marker': suite.Suite._ACTIVE_A_REFUSAL_MARKER,
                               'traffic_status': 'NOT_EXECUTED', 'proof': proof}
    def call(tool, value):
        return {'tool': tool, 'expect': 'success', 'ok': True,
                'response': {'result': {'content': [{'text': json.dumps(value)}]}}}
    tools = ['start', 'get_status', 'get_status', 'get_status', 'get_events',
             'list_artifacts', 'stop']
    calls = [call(tool, (started if tool == 'start' else status if tool == 'get_status'
                         else {'state': 'stopped'} if tool == 'stop'
                         else {'events': [failure_event]} if tool == 'get_events'
                         else {})) for tool in tools]
    result = {'scenario': {'interface_call_plan': [
                           {'tool': tool, 'expect': 'success'} for tool in tools],
                           'config_profile': profile},
              'traffic_evidence': {'runtime_profile': profile, 'nonce': nonce,
                                   'capture_views': [after_record]},
              'interface_calls': calls, 'run_chain': [run],
              'health_trace': {'samples': [], 'window': 'W-start-refusal',
                               'traffic_status': 'NOT_EXECUTED'},
              'verdict': {'traffic_oracle': 'NOT_EXECUTED'},
              'five_section_audit': {'before': sections, 'after': sections},
              'recovery': {'final_status': status, 'cleanup_errors': []}}
    run['capture']['observation_contract'] = 'con008'
    scenario = next(x for x in suite.build_manifest(20260912)['scenarios']
                    if x['scenario_id'] == 'sst-039')
    result['scenario'] = scenario
    result['traffic_evidence']['runtime_profile'] = copy.deepcopy(scenario['config_profile'])
    result['interface_calls'] = [call(p['tool'], started if p['tool'] == 'start'
        else status if p['tool'] == 'get_status' else {'state':'stopped'} if p['tool']=='stop'
        else {'events':[failure_event]} if p['tool']=='get_events' else {})
        | {'expect': p['expect'], 'ok': p['expect']=='success'}
        for p in scenario['interface_call_plan']]
    return result


def match_restart_refusal(tmp_path):
    # Independently constructed match contract; no native-A waiver is shared
    # with nonmatch. Every supplied file is written and byte-bound in tmp_path.
    scenario = next(x for x in suite.build_manifest(20260912)['scenarios']
                    if x['scenario_id'] == 'sst-043')
    reason = suite.Suite._QUIESCENCE_REFUSAL_MARKER
    started = dict(state='stopped', run_id=None, last_run_outcome='failed',state_version=10)
    before = dict(started, controller=None, failure_reason=reason)
    after = dict(before, state_version=11)
    stop = dict(state='stopped')
    restart = dict(state='stopped',run_id=None,changed=False,command_id=None,state_version=11,
        error={'code':'not_allowed_in_state','message':'restart requires an active run bound to its run_id'})
    sections = {k: '' for k in ('dns_servers','routes','listen_ports','windivert_processes','services')}
    path=tmp_path/'five-sections-after.json'
    path.write_text(json.dumps(dict(sections=sections,difference={},difference_attribution=None)),encoding='utf-8')
    def call(plan):
        tool=plan['tool'];value=started if tool=='start' else restart if tool=='restart' else after if tool=='get_status' else stop if tool=='stop' else {}
        return dict(plan,ok=(tool!='restart' and plan['expect']=='success'),response={'result':{'content':[{'text':json.dumps(value)}]}})
    run=dict(label='run-01',run_id=None,start_response=started,stop_response=stop,
        refusal_status_samples=[copy.deepcopy(before) for _ in range(3)],
        expected_refusal={'reason':reason,'marker':reason},capture={'observation_contract':'con008'},
        traffic_oracle={'status':'NOT_EXECUTED','passed':None},five_sections_before=sections,five_sections_after=sections)
    return dict(scenario=scenario,interface_calls=[call(p) for p in scenario['interface_call_plan']],run_chain=[run],
        traffic_evidence={'nonce':'synthetic-contract-only','runtime_profile':copy.deepcopy(scenario['config_profile']),
                          'capture_views':[suite.file_record(path,tmp_path)]},
        health_trace={'samples':[],'window':'W-start-refusal','traffic_status':'NOT_EXECUTED'},
        verdict={'traffic_oracle':True},five_section_audit={'before':sections,'after':sections},
        recovery={'final_status':after,'cleanup_errors':[]})
