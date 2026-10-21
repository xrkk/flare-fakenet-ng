"""Boot-bound recovery must not inherit old PID-only UDP exceptions."""
import copy
import json
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from fakenet.mcp import baseline as module
from fakenet.mcp.endpoint_attribution import foreign_udp_owner_changes


_fixture_spec = importlib.util.spec_from_file_location(
    'reboot_endpoint_fixtures', Path(__file__).with_name('test_endpoint_attribution.py'))
_fixtures = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(_fixtures)
foreign_case = _fixtures.foreign_case
capture_two_samples = _fixtures.capture_two_samples


def test_full_audit_rejects_cross_boot_pid_reuse_even_when_old_helper_accepts(tmp_path, monkeypatch):
    baseline, sample, proof = foreign_case()
    assert foreign_udp_owner_changes(baseline, sample, proof)['accepted']
    sections = module.CapturedSections(baseline['sections'])
    sections.windows = baseline['observation_windows']
    store = module.BaselineStore(tmp_path / 'baselines')
    store.save(baseline['run_id'], sections)
    current = module.CapturedSections(sample['current'])
    current.windows = sample['observation_windows']
    current.reboot_context = {'schema': 'fakenetng.reboot-context.v1',
        'boot': {'computer': 'fixture', 'start_ns': baseline['observation_windows']['listen_ports']['end_ns'] + 1},
        'owners': [], 'rows': []}
    capture_two_samples(monkeypatch, module, current)
    observed = SimpleNamespace(audit_proof=lambda deadline: proof,
                               start_proof=lambda: {'run_id': proof['run_id'], 'start': proof['start']})
    assert store.full_audit_diff(baseline['run_id'], settle_seconds=.02,
                                 observation=observed), 'cross-boot PID reuse was waived'


def reboot_case():
    from fakenet.mcp.reboot_recovery import SCHEMA, FILETIME_EPOCH
    at = 1_700_000_000_000_000_000
    ticks = lambda ns: str(FILETIME_EPOCH + ns // 100)
    old_rows = ('TCP 0.0.0.0:49669 0.0.0.0:0 LISTENING 704\n'
                'TCP [::]:49669 [::]:0 LISTENING 704\n'
                'UDP [fe80::1%11]:50924 *:* 1924')
    new_rows = ('TCP 0.0.0.0:49670 0.0.0.0:0 LISTENING 900\n'
                'TCP [::]:49670 [::]:0 LISTENING 900\n'
                'UDP [fe80::1%11]:61181 *:* 901')
    sections = {k:'same' for k in module.BASELINE_FIELDS}
    sections.update(listen_ports=old_rows, windivert_processes=json.dumps({'managed':[]}))
    baseline = {'run_id':'benign-run','sections':sections,'managed_driver_root':r'C:\Product',
                'observation_windows':{'listen_ports':{'start_ns':at+2*10**9,'end_ns':at+3*10**9}}}
    proof = {'run_id':'benign-run','start':{'run_id':'benign-run','time_ns':at+10**9,
             'processes':[{'ProcessId':p,'CreationTime':ticks(at-10**9)} for p in (704,1924)]}}
    boot = {'computer':'FIXTURE','start_ns':at+10*10**9,'event':{
            'provider':'Microsoft-Windows-Kernel-General','id':12,'record_id':42,
            'computer':'FIXTURE','start_ns':at+10*10**9}}
    image = r'C:\Windows\System32\svchost.exe'
    context = {'schema':SCHEMA,'boot':boot,'boot_after':boot['start_ns'],
               'started_ns':at+13*10**9,'ended_ns':at+15*10**9,'system_root':r'C:\Windows',
               'rows':[{'protocol':'TCP','address':h,'port':49670,'pid':900} for h in ('0.0.0.0','::')]+[
                       {'protocol':'UDP','address':'fe80::1%11','port':61181,'pid':901}],
               'owners':[{'pid':900,'image':image,'birth_ticks':ticks(at+11*10**9),'alive':True,
                          'services':[{'name':'PolicyAgent','pid':900,'state':'Running','command':image+' -k network'}]},
                         {'pid':901,'image':r'C:\Windows\System32\services.exe',
                          'birth_ticks':ticks(at+11*10**9),'alive':True,'services':[],
                          'critical':True,'sid':'S-1-5-18'}]}
    sample = {'run_id':'benign-run','current':dict(sections,listen_ports=new_rows),
              'observation_windows':{'listen_ports':{'start_ns':at+12*10**9,'end_ns':at+16*10**9}},
              'reboot_context':context}
    return baseline,sample,proof


def test_boot_delta_is_read_only_and_has_every_original_owner():
    from fakenet.mcp.reboot_recovery import cross_boot_endpoint_changes
    args = reboot_case(); old = copy.deepcopy(args)
    result = cross_boot_endpoint_changes(*args)
    assert result['accepted'], result
    assert len(result['attributed']) == 6
    assert args == old


@pytest.mark.parametrize('problem', ['no_event','event_computer','event_start','same_boot',
    'missing_start','old_birth_missing','old_birth_future','dead_owner','image_missing',
    'product_path','foreign_product_name','non_service','wrong_sid','not_critical',
    'scm_pid','scm_image','owner_duplicate','endpoint_duplicate','different_scope',
    'route_changed','collection_failed','boot_changed','native_outside_window','unknown_row'])
def test_cross_boot_unknown_or_unrelated_changes_never_pass(problem):
    from fakenet.mcp.reboot_recovery import cross_boot_endpoint_changes
    baseline,sample,proof = reboot_case(); c=sample['reboot_context']
    if problem=='no_event': c['boot'].pop('event')
    elif problem=='event_computer': c['boot']['event']['computer']='OTHER'
    elif problem=='event_start': c['boot']['event']['start_ns']+=100
    elif problem=='same_boot': c['boot']['start_ns']=1
    elif problem=='missing_start': proof.pop('start')
    elif problem=='old_birth_missing': proof['start']['processes'].pop()
    elif problem=='old_birth_future': proof['start']['processes'][0]['CreationTime']=c['owners'][0]['birth_ticks']
    elif problem=='dead_owner': c['owners'][0]['alive']=False
    elif problem=='image_missing': c['owners'][0]['image']=None
    elif problem=='product_path': c['owners'][0]['image']=r'C:\Product\renamed.exe'
    elif problem=='foreign_product_name': c['owners'][0]['image']=r'C:\Other\fakenet.exe'
    elif problem=='non_service': c['owners'][0]['services']=[]
    elif problem=='wrong_sid': c['owners'][1]['sid']='S-1-5-19'
    elif problem=='not_critical': c['owners'][1]['critical']=False
    elif problem=='scm_pid': c['owners'][0]['services'][0]['pid']=999
    elif problem=='scm_image': c['owners'][0]['services'][0]['command']=r'C:\Other\svchost.exe'
    elif problem=='owner_duplicate': c['owners'].append(copy.deepcopy(c['owners'][0]))
    elif problem=='endpoint_duplicate': sample['current']['listen_ports']+='\n'+sample['current']['listen_ports'].splitlines()[0]
    elif problem=='different_scope':
        sample['current']['listen_ports']=sample['current']['listen_ports'].replace('%11','%12')
        c['rows'][-1]['address']='fe80::1%12'
    elif problem=='route_changed': sample['current']['routes']='different'
    elif problem=='collection_failed': sample['current']['services']=module.COLLECTION_FAILED
    elif problem=='boot_changed': c['boot_after']+=100
    elif problem=='native_outside_window': c['ended_ns']+=100*10**9
    elif problem=='unknown_row': sample['current']['listen_ports']+='\nUNPARSED ROW'
    result=cross_boot_endpoint_changes(baseline,sample,proof)
    assert result['accepted'] is False, (problem,result)


def test_two_current_samples_must_agree_on_instance_and_endpoint_set():
    from fakenet.mcp.reboot_recovery import cross_boot_pair
    b,s,p=reboot_case(); other=copy.deepcopy(s)
    assert cross_boot_pair(b,[s,other],p)['accepted']
    other['reboot_context']['owners'][0]['birth_ticks']=str(int(other['reboot_context']['owners'][0]['birth_ticks'])+1)
    assert not cross_boot_pair(b,[s,other],p)['accepted']


def test_full_audit_recovers_legacy_boot_preserving_baseline_bytes(tmp_path,monkeypatch):
    b,s,p=reboot_case(); sections=module.CapturedSections(b['sections']);sections.windows=b['observation_windows']
    store=module.BaselineStore(tmp_path/'baselines');store.save(b['run_id'],sections)
    path=store.root/(b['run_id']+'.json'); original=path.read_bytes()
    current=module.CapturedSections(s['current']);current.windows=s['observation_windows'];current.reboot_context=s['reboot_context']
    capture_two_samples(monkeypatch,module,current)
    obs=SimpleNamespace(start_proof=lambda:p,audit_proof=lambda deadline:(_ for _ in ()).throw(ValueError('old boot trace absent')))
    assert store.full_audit_diff(b['run_id'],settle_seconds=.02,observation=obs)=={}
    assert store.last_cross_boot_attribution['accepted']
    assert path.read_bytes()==original
    assert next((tmp_path/'logs').glob('*.reboot-attribution.json')).is_file()
    # A later missing audit cannot reuse the previously accepted transition.
    assert store.full_audit_diff('missing')
    assert store.last_cross_boot_attribution is None


@pytest.mark.parametrize('missing_event',[False,True])
def test_no_legacy_fallback_after_cross_boot_rejection(tmp_path,monkeypatch,missing_event):
    b,s,p=reboot_case()
    if missing_event:s['reboot_context']['boot'].pop('event')
    else:s['reboot_context']['owners'][0]['services']=[]
    sections=module.CapturedSections(b['sections']);sections.windows=b['observation_windows']
    store=module.BaselineStore(tmp_path/'baselines');store.save(b['run_id'],sections)
    current=module.CapturedSections(s['current']);current.windows=s['observation_windows'];current.reboot_context=s['reboot_context']
    capture_two_samples(monkeypatch,module,current)
    import fakenet.mcp.endpoint_attribution as old
    def must_not_call(*args,**kwargs):raise AssertionError('old UDP path reached')
    for name in ('closed_udp_changes','foreign_udp_owner_changes','restarted_service_udp_changes'):
        monkeypatch.setattr(old,name,must_not_call)
    assert store.full_audit_diff(b['run_id'],settle_seconds=.02,observation=SimpleNamespace(start_proof=lambda:p))


@pytest.mark.parametrize('failure',[None,'observer','other_diff','fenced','release','compensate'])
def test_supervisor_releases_only_normal_recovery_and_keeps_failed_outcome(tmp_path,monkeypatch,failure):
    from fakenet.mcp.supervisor import RealSupervisor
    from fakenet.mcp.snapshot import StateSnapshot
    from fakenet.mcp.coordination import Coordinator
    root=tmp_path/'baselines';root.mkdir()
    marker=StateSnapshot(tmp_path/'state.json')
    run='57886d22-ae94-473f-b9f0-f4242655a884';controller='11111111-2222-4333-8444-555555555555'
    marker.write(run_id=run,controller_id=controller,state_version=1,
                 command_id='old-command',config_sha256='a'*64,
                 baseline_path=str(root/(run+'.json')),needs_recovery=True)
    def fail():raise RuntimeError('injected failure')
    store=SimpleNamespace(root=root,last_cross_boot_attribution={'accepted':True},
        compensate=lambda *a:fail() if failure=='compensate' else None,
        full_audit_diff=lambda *a,**kw:{'services':'changed'} if failure=='other_diff' else {})
    runner=RealSupervisor(snapshot=marker,baseline_store=store)
    monkeypatch.setattr(runner,'_await_exit_evidence',lambda deadline:None)
    monkeypatch.setattr(runner,'_register_run_artifacts',lambda *a:None)
    monkeypatch.setattr(runner,'_collect_incident',lambda *a,**kw:None)
    if failure=='observer':runner._endpoint_observation=SimpleNamespace(finish=lambda deadline:{'absent':False})
    if failure=='release':runner._activity_lock=SimpleNamespace(release=fail)
    coordinator=Coordinator(runner);coordinator.restore_responsibility(marker.read()[0],'failed')
    if failure=='fenced':
        monkeypatch.setattr(Coordinator,'operation_fenced',property(lambda _:True))
    reply=coordinator.submit(command_id='new-stop',expected_version=coordinator.snapshot()['state_version'],
        controller=controller,controller_valid=True,kind='stop',describe={},execute=lambda c:runner.stop(c))
    data,corrupt=marker.read();assert not corrupt
    if failure is None:
        assert reply['state']=='stopped' and reply['last_run_outcome']=='failed'
        assert coordinator.snapshot()['run_id'] is None and coordinator.snapshot()['controller'] is None
        assert data['needs_recovery'] is False
    else:
        assert reply['state']=='failed'
        assert coordinator.snapshot()['run_id']==run and data['needs_recovery'] is True


def test_expired_capture_does_not_issue_a_shell_query(monkeypatch):
    from fakenet.mcp import reboot_recovery as rr
    monkeypatch.setattr(rr,'os',SimpleNamespace(name='nt'))
    monkeypatch.setattr(module,'_run',lambda *a,**kw:pytest.fail('query after deadline'))
    assert rr.capture_context(deadline=0)['error']


def test_startup_recovery_publishes_failed_outcome_after_normal_release(tmp_path, monkeypatch):
    from fakenet.mcp.supervisor import RealSupervisor
    from fakenet.mcp.snapshot import StateSnapshot
    from fakenet.mcp.coordination import Coordinator
    root = tmp_path / 'baselines'
    root.mkdir()
    snapshot = StateSnapshot(tmp_path / 'state.json')
    run = '57886d22-ae94-473f-b9f0-f4242655a884'
    snapshot.write(run_id=run, controller_id='11111111-2222-4333-8444-555555555555',
                   state_version=1, command_id='old-command', config_sha256='a' * 64,
                   baseline_path=str(root / (run + '.json')), needs_recovery=True)
    store = SimpleNamespace(root=root, last_cross_boot_attribution={'accepted': True},
                            compensate=lambda *args: None, full_audit_diff=lambda *args, **kwargs: {})
    runner = RealSupervisor(snapshot=snapshot, baseline_store=store)
    monkeypatch.setattr(runner, '_await_exit_evidence', lambda deadline: None)
    monkeypatch.setattr(runner, '_register_run_artifacts', lambda *args: None)
    coordinator = Coordinator(runner)
    assert runner.recover(coordinator) == 'stopped'
    status = coordinator.snapshot()
    assert status['run_id'] is None and status['controller'] is None
    assert snapshot.read()[0]['needs_recovery'] is False
    assert status['last_run_outcome'] == 'failed'
