"""Offline synthetic control reaching the real _run_one shared seal and recheck."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent / 'acceptance'))
import scenario_suite as suite
import scenario_tcpip
import scenario_capture_view as view


SECTIONS = {key: [] for key in ('dns_servers','routes','listen_ports','windivert_processes','services')}


def synthetic_capture(candidate_id):
    """Small synthetic ETW conversion envelope; never a native capture claim."""
    etl = b'synthetic ETL bytes for shared-owner control only'
    start = 134350164530000000
    end = start + 80_000_000  # Eight seconds in FILETIME units.
    path = r'X:\synthetic\pktmon.etl'
    text = (f'\ufeff[00]0000.0000::2026-09-28 05:00:53.000000000 [MSNT_SystemTrace] '
            f'EndTime: {end}, EventsLost: 0, StartTime: {start}, '
            f'BuffersLost: 0, LogFileNameString: {path}\n').encode('utf-16-le')
    boot = {'boot_identifier': 'synthetic-boot'}
    machine = {'machine_guid': 'synthetic-machine'}
    identity = {'supported': True, 'candidate_id': candidate_id,
                'boot': boot, 'vm_identity': machine}
    metadata = {
        'schema': suite.NIC_CAPTURE_SCHEMA, 'pktmon_status_after': 'stopped',
        'pktmon_list': '9 00-0C-29-C1-CA-49 Synthetic Ethernet',
        'adapters': [{'MacAddress': '00-0C-29-C1-CA-49',
                      'InterfaceDescription': 'Synthetic Ethernet', 'Status': 'Up',
                      'ifIndex': 11, 'Name': 'Ethernet0'}],
        'capture_mode': 'all-components-tcpip',
        'clock_before': {'offset_minutes': 480, 'utc_ticks': start + 504911232000000000,
                         'mono': 0, 'stopwatch_frequency': 10_000_000},
        'clock_after': {'offset_minutes': 480, 'utc_ticks': end + 504911232000000000,
                        'mono': 80_000_000, 'stopwatch_frequency': 10_000_000},
        'conversion': {'argv': ['pktmon', 'etl2txt', path, '--out', path[:-4] + '.txt'],
                       'exit_code': 0, 'etl_sha256': hashlib.sha256(etl).hexdigest(),
                       'text_sha256': hashlib.sha256(text).hexdigest()},
        'native_identity_before': identity, 'native_identity_after': identity,
    }
    return etl, text, metadata


def test_real_executor_seals_shared_owner_to_result_and_rechecks(tmp_path, monkeypatch):
    """Run the real shared-owner seal and recheck with synthetic input bytes."""
    monkeypatch.setattr(suite.time, 'sleep', lambda _: None)
    identity = {'candidate_id': 'synthetic-' + 'a' * 64,
                'source_commit': 'b' * 40, 'package_sha256': 'c' * 64}
    args = suite.parse_args(['generate', '--candidate-id', identity['candidate_id'],
        '--source-commit', identity['source_commit'], '--package-sha256', identity['package_sha256'],
        '--suite-root', str(tmp_path), '--capture-contract', 'scenario-shared-v2',
        '--guest-work-root', suite.E_GUEST_WORK_ROOT])
    runner = suite.Suite(args)
    scenario = next(row for row in suite.build_manifest(20260912)['scenarios']
                    if row['scenario_id'] == 'sst-012')
    raw_etl, raw_txt, metadata = synthetic_capture(identity['candidate_id'])
    lo, hi = scenario_tcpip.validate_capture(raw_txt, raw_etl, metadata, 50_000_000)
    assert hi - lo > 4_000_000_000
    boot = metadata['native_identity_before']['boot']
    machine = metadata['native_identity_before']['vm_identity']
    file_bytes = {}
    trace = []
    def probe_bytes(nonce, label, pid):
        creation = 638000000000000000 + pid
        native = {'supported': True, 'run_id': nonce + ':' + label, 'nonce': nonce,
                  'candidate_id': identity['candidate_id'], 'pid': pid,
                  'creation_filetime_100ns': creation - 504911232000000000,
                  'boot': boot, 'vm_identity': machine}
        when = lo + (1 if label == 'run-01' else 3) * 1_000_000_000
        ticks = 621355968000000000 + when // 100
        return (json.dumps({'event':'ready','nonce':nonce,'pid':pid,
                            'creation_ticks':creation,'utc_ticks':ticks,
                            'native_identity':native}) + '\n' +
                json.dumps({'event':'close','nonce':nonce,'utc_ticks':ticks+10000}) + '\n').encode(), creation

    def capture(guest, profile, nonce, label, owner=None):
        trace.append(('start-shared' if owner else 'start-physical', label))
        base = guest + '\\' + label
        pid = 101 if label == 'run-01' else 102
        raw_probe, creation = probe_bytes(nonce, label, pid)
        file_bytes[base + r'\probe.jsonl'] = raw_probe
        for name in view.KERNEL_NAMES:
            file_bytes[base + '\\' + name] = b'kernel-fixture'
        if owner is not None:
            file_bytes[base + r'\probe-launch.json'] = json.dumps({
                'pid':pid,'creation_ticks':creation,'nonce':nonce,
                'capture_run_id':nonce+':'+label,
                'candidate_id':identity['candidate_id']}).encode()
        if owner is None:
            file_bytes[base + r'\pktmon.etl'] = raw_etl
            file_bytes[base + r'\pktmon.txt'] = raw_txt
            file_bytes[base + r'\pktmon-nic.json'] = (json.dumps(metadata).encode())
        return {'guest':base,'run_label':label,'pid':pid,
                'probe_creation_ticks':creation,'probe':base+r'\probe.jsonl',
                'start':base+r'\probe.start','case':base+r'\probe.cases',
                'stop':base+r'\probe.stop','stdout':base+r'\probe.stdout',
                'stderr':base+r'\probe.stderr',
                'etl':(owner['etl'] if owner else base+r'\pktmon.etl'),
                'pktmon_nic':(owner['pktmon_nic'] if owner else base+r'\pktmon-nic.json'),
                'requested_file_size_mib':128,'started':'2026-09-27T00:00:00Z',
                **({'shared_physical':True,'physical_owner_id':owner['physical_owner_id']}
                   if owner else {})}
    def stop(c):
        trace.append(('stop-shared' if c.get('shared_physical') else 'stop-physical',c['run_label']))
        paths = [c['probe']] + [c['guest']+'\\'+name for name in view.KERNEL_NAMES]
        if c.get('shared_physical'):
            paths.append(c['guest']+r'\probe-launch.json')
        if not c.get('shared_physical'):
            paths += [c['etl'],c['guest']+r'\pktmon.txt',c['pktmon_nic']]
        return {'files':[{'path':p,'bytes':len(file_bytes[p]),
                          'sha256':hashlib.sha256(file_bytes[p]).hexdigest()} for p in paths]}
    def transfer(guest_path, size, digest, local):
        raw = file_bytes[guest_path]
        assert len(raw) == size and hashlib.sha256(raw).hexdigest() == digest
        local.parent.mkdir(parents=True,exist_ok=True)
        local.write_bytes(raw)
        return suite.file_record(local,runner.root)
    runner.require_clients = lambda: None
    runner._require_preflight = lambda: {'api_ipv4':'192.168.204.233',
                                          'external_dns_server':'8.8.8.8'}
    runner._continuation_gate = lambda: {}
    runner._capture_sections = lambda: (SECTIONS,{})
    runner._prune_scenario_configs = lambda _: {}
    runner._start_capture_and_probe = lambda g,p,n,l: capture(g,p,n,l)
    runner._start_probe_on_shared_capture = lambda g,p,n,l,o: capture(g,p,n,l,o)
    runner._stop_capture_and_probe = stop
    runner._transfer_guest_file = transfer
    runner._run_auxiliary_cases = lambda *args: None
    runner._release_probe = lambda c,phase: {'phase':phase,'released_utc':'2026-09-27T00:00:00Z'}
    runner._run_recovery_sections = lambda *args: ({}, SECTIONS)
    runner._section_difference = lambda *args: {}
    runner._restart_baseline = lambda *args: SECTIONS
    runner._collect_runtime_pcaps = lambda *args: None
    runner._prune_scenario_vm_footprint = lambda *args,**kwargs: {}
    runner._benign_log_issues = lambda *args: []
    runner._traffic_oracle = lambda *args,**kwargs: {'passed':True,'cases':[]}
    def export(run_id, destination, evidence):
        p=destination/'run.log';p.parent.mkdir(parents=True,exist_ok=True);p.write_text('synthetic control\n')
        evidence.add(p)
        return {'files':[suite.file_record(p,runner.root)]}
    runner._export_run_originals = export
    state = ['stopped']
    version = [3]
    current_run = [None]
    runner._status = lambda: {'state':state[0],'state_version':version[0],
                              'run_id':current_run[0],'controller':None,
                              'last_run_outcome':'ok' if state[0]=='stopped' else None}
    runner._outcome_code = lambda outcome: 'state_conflict'
    def tool(name,args=None,timeout=120):
        args=args or {}
        stale = name == 'create_config' and str(args.get('name','')).endswith('-stale')
        if name in ('start','restart'):
            state[0]='healthy';current_run[0]='product-1' if name=='start' else 'product-2'
        elif name=='stop':
            state[0]='stopped';current_run[0]=None
        if name in ('create_config','edit_config','rename_config','import_config','delete_config','load_config','start','restart','stop') and not stale:
            version[0]+=1
        value = ({'state':state[0],'run_id':current_run[0]} if name in ('start','restart','stop','get_status') else
                 {'sha256':'a'*64} if name=='read_config' else {})
        return {'ok':not stale,'value':value,'response':value,
                'sent_arguments':args,'response_headers':{},
                'error':{'code':'state_conflict'} if stale else None}
    runner.service=SimpleNamespace(controller_id='control',tool_outcome=tool)
    result=runner._run_one(scenario,1)
    assert result['state']=='pass',result['failure']
    assert trace == [('start-physical','run-01'),('start-shared','run-02'),
                     ('stop-shared','run-02'),('stop-physical','run-01')]
    assert result['run_chain'][0]['capture']['physical_owner'] == result['run_chain'][1]['capture']['physical_owner']
    sealed = suite.read_json(runner._result_path('sst-012'))
    assert suite.result_issues(sealed,runner.root) == []
    assert runner._traffic_recheck_issues(sealed,sealed['scenario']) == []

    def reseal_physical(root, result, name, changed, *, update_conversion=False):
        owner_old = result['run_chain'][0]['capture']['physical_owner']
        owner_path = root / owner_old['path']
        owner = json.loads(owner_path.read_text())
        old = next(x for x in owner['physical_files'] if Path(x['path']).name == name)
        target = root / old['path']
        target.write_bytes(changed(target.read_bytes()))
        changed_records = {old['path']: suite.file_record(target, root)}
        if update_conversion:
            meta_old = next(x for x in owner['physical_files']
                            if Path(x['path']).name == 'pktmon-nic.json')
            meta_path = root / meta_old['path']
            metadata_new = json.loads(meta_path.read_text())
            metadata_new['conversion']['text_sha256'] = hashlib.sha256(target.read_bytes()).hexdigest()
            meta_path.write_text(json.dumps(metadata_new))
            changed_records[meta_old['path']] = suite.file_record(meta_path, root)
        owner['physical_files'] = [changed_records.get(x['path'],x)
                                   for x in owner['physical_files']]
        owner_path.write_text(json.dumps(owner))
        owner_new = suite.file_record(owner_path,root)
        for run in result['run_chain']:
            capture = run['capture']
            capture['files'] = [changed_records.get(x['path'],x) for x in capture['files']]
            capture['physical_owner'] = owner_new
            view_old = capture['run_view']
            view_path = root / view_old['path']
            view_payload = json.loads(view_path.read_text())
            view_payload['physical_files'] = owner['physical_files']
            view_payload['owner'] = owner_new
            view_path.write_text(json.dumps(view_payload))
            view_new = suite.file_record(view_path,root)
            capture['run_view'] = view_new
            result['traffic_evidence']['capture_views'] = [
                view_new if x['path']==view_old['path'] else x
                for x in result['traffic_evidence']['capture_views']]

    mutations = [
        ('loss','pktmon.txt',
         lambda raw: raw.replace('EventsLost: 0'.encode('utf-16-le'),
                                 'EventsLost: 1'.encode('utf-16-le')),True,
         'ETL event/buffer loss'),
        ('etl-hash','pktmon.etl',lambda raw:raw+b'changed',False,
         'conversion hash mismatch'),
        ('header','pktmon.txt',
         lambda raw:raw.replace('[MSNT_SystemTrace]'.encode('utf-16-le'),
                                 '[not_a_header____]'.encode('utf-16-le')),True,
         'missing/ambiguous ETL trace header'),
        ('clock','pktmon-nic.json',
         lambda raw:json.dumps(dict(json.loads(raw.decode('utf-8-sig')),
                 clock_after=dict(json.loads(raw.decode('utf-8-sig'))['clock_after'],
                                  stopwatch_frequency=1))).encode(),False,
         'invalid capture monotonic frequency'),
    ]
    for label,name,change,conversion_hash,reason in mutations:
        subroot = tmp_path.parent / (tmp_path.name + '-' + label)
        shutil.copytree(tmp_path,subroot)
        mutated = suite.read_json(subroot/'results/scenario-sst-012.json')
        reseal_physical(subroot,mutated,name,change,update_conversion=conversion_hash)
        runner.root=subroot
        issue = runner._traffic_recheck_issues(mutated,mutated['scenario'])
        assert len(issue)==1 and reason in issue[0],(label,issue)
        assert any(reason in x for x in suite.result_issues(mutated,subroot)),label
    seal_failure_root=tmp_path.parent / (tmp_path.name + '-seal-failure')
    seal_failure_root.mkdir()
    runner.root=seal_failure_root
    monkeypatch.setattr(view, 'validate_shared_views',
                        lambda *args: (_ for _ in ()).throw(ValueError('synthetic seal failure')))
    before=len(trace)
    failed=runner._run_one(scenario,1)
    assert failed['state']=='fail' and 'synthetic seal failure' in failed['failure']
    assert trace[before:] == [('start-physical','run-01'),('start-shared','run-02'),
                             ('stop-shared','run-02'),('stop-physical','run-01')]
    assert state[0]=='stopped'
    uncertain_root=tmp_path.parent / (tmp_path.name + '-second-start-unknown')
    uncertain_root.mkdir()
    runner.root=uncertain_root
    state[0]='stopped'
    def uncertain_second(*args):
        trace.append(('start-shared-unknown','run-02'))
        raise suite.UnsettledCaptureStart('synthetic response unknown')
    runner._start_probe_on_shared_capture=uncertain_second
    before=len(trace)
    uncertain=runner._run_one(scenario,1)
    assert uncertain['state']=='fail' and 'synthetic response unknown' in uncertain['failure']
    assert trace[before:] == [('start-physical','run-01'),
                             ('start-shared-unknown','run-02')]
    assert state[0]=='healthy'
