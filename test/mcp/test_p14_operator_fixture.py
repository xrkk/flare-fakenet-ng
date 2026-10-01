"""Self-contained operator orchestration predicates, never native case credit."""
import copy
import importlib.util
import json
from pathlib import Path
import socket
import pytest
spec=importlib.util.spec_from_file_location('p14_operator',Path(__file__).parent/'acceptance/p14_operator_fixture.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
def ready():return dict(run_id='own-run',controller='own-controller',nonce='own-nonce',pid=42,creation_time='134335767401378067',address='127.0.0.1',port=49153,in_any_job=False,managed_job_proof=dict(supervisor_pid=7484,supervisor_creation='134335767401378067',target_pid=8848,target_creation='134353424763296015',duplicates_closed=True,probe_job_closed=True,jobs=[dict(worker_member=False,members=['8848'])]))
def cli(code):return dict(native_ended=True,exit_code=code,seconds=151,cli=dict(pid=22,creation_time='134335767401378067',semantic='fakenetng-mcp.exe stop'))
def proof():
 b=dict(run_id='own-run',controller='own-controller',baseline_sha256='rawhash',failure_reason='environment restoration audit failed',audit_tcp_difference=True,needs_recovery=True)
 pre=dict(instance_id='same',pid=7484,creation_time='native',attempt=0)
 return dict(operator=cli(1),retry=cli(0),before=b,held=copy.deepcopy(b),resources=dict(native_ended=True),service_alive_at_CLI1=True,prestop_before=pre,prestop_failed=dict(pre,attempt=1,phase='failed'),prestop_final=dict(pre,attempt=2,phase='succeeded'),start_error='not_allowed_in_state',start_owner_preserved=True,fixture_closed=dict(reason='cooperative_release'),fixture_native_ended=True,three_absent_samples=True,service_stopped=True,final_marker=dict(needs_recovery=False),baseline_sha_before='rawhash',baseline_sha_after='rawhash',two_clean_audit_samples=True,original_failure_preserved=True,fixture_did_not_expire=True,fixture_product_job_independent=True)
def test_audit_only_does_not_require_live_helper_or_job():assert p.verdict(proof())['passed']
@pytest.mark.parametrize('change',['run_id','controller','nonce','pid','creation_time','action'])
def test_release_requires_exact_own_receipt(change):
 r=ready();receipt=p.release_receipt(r);receipt[change]='foreign';assert not p.release_matches(receipt,r)
@pytest.mark.parametrize('change',['run','controller','nonce','expired','other_address','in_job','missing_native','bad_port'])
def test_fixture_identity_and_lease_fail_closed(change):
 r=ready();run=r['run_id'];controller=r['controller'];nonce=r['nonce'];elapsed=12
 if change=='run':run='foreign'
 elif change=='controller':controller='foreign'
 elif change=='nonce':nonce='foreign'
 elif change=='expired':elapsed=1800
 elif change=='other_address':r['address']='0.0.0.0'
 elif change=='in_job':r['managed_job_proof']['jobs'][0]['worker_member']=True
 elif change=='missing_native':r['creation_time']=None
 else:r['port']=0
 assert not p.fixture_valid(r,run,controller,nonce,elapsed)
def test_unknown_launch_or_mutation_called_once():
 calls=[]
 def unknown():calls.append(1);raise TimeoutError('transport')
 with pytest.raises(p.Unknown):p.once(unknown)
 assert calls==[1]
@pytest.mark.parametrize('change',['rpc_not_native_end','cli0_on_first','too_late','overwritten_owner','marker_false','not_live_service','old_failed_attempt','old_succeeded_retry','baseline_changed','no_clean_audit','lease_expiry','foreign_release','no_native_resources','no_start_rejection','missing_failure'])
def test_invalid_operator_chain_does_not_pass(change):
 d=proof()
 if change=='rpc_not_native_end':d['operator']['native_ended']=False
 elif change=='cli0_on_first':d['operator']['exit_code']=0
 elif change=='too_late':d['operator']['seconds']=511
 elif change=='overwritten_owner':d['held']['run_id']='new'
 elif change=='marker_false':d['held']['needs_recovery']=False
 elif change=='not_live_service':d['service_alive_at_CLI1']=False
 elif change=='old_failed_attempt':d['prestop_failed']['attempt']=0
 elif change=='old_succeeded_retry':d['prestop_final']['attempt']=1
 elif change=='baseline_changed':d['baseline_sha_after']='changed'
 elif change=='no_clean_audit':d['two_clean_audit_samples']=False
 elif change=='lease_expiry':d['fixture_did_not_expire']=False;d['fixture_closed']['reason']='lease_expired'
 elif change=='foreign_release':d['fixture_native_ended']=False
 elif change=='no_native_resources':d['resources']['native_ended']=False
 elif change=='no_start_rejection':d['start_error']=None
 else:d['before']['failure_reason']=None
 assert not p.verdict(d)['passed']
def test_resource_pending_needs_independent_native_live_original_deadline():
 d=proof();assert not p.validate_responsibility(d['before'],d['held'],'resource_pending',{'pid':42,'helper':43,'job':1})
 assert p.validate_responsibility(d['before'],d['held'],'resource_pending',dict(independent_native_live=True,original_deadline=60))
def test_cooperative_close_only_own_socket_leaves_foreign_socket():
 own=socket.socket();foreign=socket.socket()
 try:
  own.bind(('127.0.0.1',0));own.listen();foreign.bind(('127.0.0.1',0));foreign.listen();a=own.getsockname();b=foreign.getsockname();own.close()
  with socket.create_connection(b,timeout=1):pass
  with pytest.raises(OSError):socket.create_connection(a,timeout=1)
 finally:own.close();foreign.close()
def test_unknown_cli_end_is_not_success():assert not p.cli_valid({'rpc_completed':True,'exit_code':1,'seconds':2},1)
def test_old_prestop_failure_is_not_new_attempt():assert not p.new_attempt(proof()['prestop_failed'],proof()['prestop_failed'])
def test_worker_source_has_no_external_traffic_or_force_clear():
 s=p.WORKER.read_text();assert 'IPAddress]::Loopback,0' in s and 'IsProcessInJob' in s and 'GetProcessTimes' in s
 assert 'CreateNew' in s and 'Test-Release' in s and '$listener.Stop()' in s
 for forbidden in ['AcceptTcpClient','Kill(','Stop-Process','taskkill','TerminateJobObject','Set-DnsClient','Set-Net','Restart-Service']:assert forbidden not in s

def test_rejudge_rejects_corrupted_indexed_raw_bytes_before_any_success(tmp_path):
 raw=b'{"invalid":"original"}';path=tmp_path/'original.json';path.write_bytes(raw)
 p.write_new(tmp_path/'proof-input.json',{})
 p.write_new(tmp_path/'original-index.json',{'files':[dict(local='original.json',path='C:\\own\\original.json',size=len(raw),sha256=p.sha(raw))]})
 path.write_bytes(b'corrupt')
 with pytest.raises(AssertionError):p.rejudge(tmp_path)
def test_rejudge_rejects_missing_raw_original(tmp_path):
 p.write_new(tmp_path/'proof-input.json',{})
 p.write_new(tmp_path/'original-index.json',{'files':[dict(local='missing.json',path='C:\\own\\missing.json',size=2,sha256='0'*64)]})
 with pytest.raises(FileNotFoundError):p.rejudge(tmp_path)
def test_atomic_journal_never_replaces_baseline_or_existing_evidence(tmp_path):
 baseline=tmp_path/'baseline.json';baseline.write_bytes(b'original-baseline')
 with pytest.raises(FileExistsError):p.write_new(baseline,{'new':'baseline'})
 assert baseline.read_bytes()==b'original-baseline'
def test_release_repeated_call_does_not_relaunch_or_affect_foreign_socket():
 r=object.__new__(p.Runner);r.launched=True;r.released=True
 r.vm=lambda *_:pytest.fail('must not write another release or launch')
 r.release()

def raw_case(tmp_path,change=None):
 d=proof();run='own-run';nonce='own-nonce';controller='own-controller'
 base=json.dumps({'run_id':run,'sections':dict.fromkeys(p.SECTIONS,'baseline')}).encode();digest=p.sha(base)
 pre=d['prestop_before'];failed=d['prestop_failed'];success=d['prestop_final']
 def scene(pre,needs,state,pid=7484):return dict(prestop=pre,service=dict(State=state),pid=pid,creation_time='134335767401378067',product=dict(run_id=run,controller=controller,failure_reason='environment restoration audit failed'),marker=dict(needs_recovery=needs))
 ownready=ready();ownready.update(run_id=run,controller=controller,nonce=nonce)
 side={'baseline-sealed.json':dict(sha256=digest),'fixture-ready.json':ownready,'01-public-stop-failed-scene.json':scene(pre,True,'Running'),'02-prestop-readonly-scene.json':scene(failed,True,'Running'),'03-start-refused-scene.json':scene(failed,True,'Running'),'04-retry-terminal-scene.json':scene(success,False,'Stopped'),'operator-cli-original.json':cli(1),'retry-cli-original.json':cli(0),'start-r07-refusal.json':dict(ok=False,error=dict(code='not_allowed_in_state')),'fixture-native-ended.json':dict(exit_code=0,output='native fixture ended')}
 for n in range(3):side[f'{n+5:02}-absent-sample.json']={'rows':[]}
 if change=='CLI_RPC_only':side['operator-cli-original.json']['native_ended']=False
 elif change=='old_retry_attempt':side['04-retry-terminal-scene.json']['prestop']['attempt']=1
 elif change=='owner_overwrite':side['02-prestop-readonly-scene.json']['product']['run_id']='foreign'
 elif change=='service_alive_on_final':side['04-retry-terminal-scene.json']['service']['State']='Running'
 elif change=='start_not_rejected':side['start-r07-refusal.json']['error']['code']='other'
 records=[]
 def original(local,guest,value):
  path=tmp_path/local;path.parent.mkdir(parents=True,exist_ok=True)
  raw=value if isinstance(value,bytes) else json.dumps(value).encode();path.write_bytes(raw)
  records.append(dict(local=local,path=guest,size=len(raw),sha256=p.sha(raw)))
 original('operator-held-originals/owner-result.json','C:\\logs\\owner-result.json',dict(target=dict(run_id=run,budget_seconds=60),helper_ended=True,retained_target_handle_closed=True,complete=True,deadline_monotonic=70,completed_monotonic=71 if change=='late_native_end' else 65))
 original('operator-held-originals/versions.json','C:\\own\\versions.json',dict(managed_process=dict(exit_code=0,job_members=[123] if change=='Job_not_ended' else [])))
 tcp='TCP 127.0.0.1:49153 0.0.0.0:0 LISTENING 42'
 original('operator-held-originals/recovery-audit-failed.jsonl','C:\\logs\\recovery-audit-failed.jsonl',(json.dumps(dict(run_id=run,current=dict(listen_ports=tcp),differences={} if change=='no_TCP_diff' else dict(listen_ports='delta')))+'\n').encode())
 clean=dict(differences={},current={});original('final-originals/recovery-audit-clean.jsonl','C:\\logs\\recovery-audit-clean.jsonl',((json.dumps(clean)+'\n')*2).encode())
 original('final-originals/baseline.json','C:\\own\\baselines\\'+run+'.json',base)
 original('final-originals/closed.json','E:\\own\\'+nonce+'\\closed.json',dict(seconds=120,reason='cooperative_release'))
 for role in ['operator','retry']:original('final-originals/'+role+'.json','E:\\own\\'+nonce+'\\'+role+'\\result.json',side[role+'-cli-original.json'])
 sidecars=[]
 for name,v in side.items():
  p.write_new(tmp_path/name,v);r=(tmp_path/name).read_bytes();sidecars.append(dict(local=name,size=len(r),sha256=p.sha(r)))
 p.write_new(tmp_path/'proof-input.json',d);p.write_new(tmp_path/'original-index.json',dict(files=records,sidecars=sidecars))
 return tmp_path

def test_full_raw_rejudge_positive_is_selfcontained_logical_only(tmp_path):assert p.rejudge(raw_case(tmp_path))['passed']
@pytest.mark.parametrize('change',['CLI_RPC_only','old_retry_attempt','owner_overwrite','service_alive_on_final','start_not_rejected','late_native_end','Job_not_ended','no_TCP_diff'])
def test_raw_rejudge_negative_uses_actual_bound_sources_not_cached_booleans(tmp_path,change):
 assert not p.rejudge(raw_case(tmp_path,change))['passed']

def test_healthy_export_uses_only_sealed_exact_paths_not_live_capture_or_logs():
 plan=p.export_plan('healthy-originals');assert plan['sealed_only'] and not plan['binary_inventory']
 assert set(plan['names'])=={'creation.jsonl','active-config.ini'}
 for name in ['packets.pcap','endpoint.etl','run.log','stdout_stderr.log','endpoint-events.json']:assert name not in plan['names']
def test_closed_stage_can_inventory_formal_binary_originals():
 assert p.export_plan('closure-originals')['binary_inventory']

def prep():return dict(observer=None,service=dict(State='Running'),prestop=dict(phase='idle',attempt=0),own=[dict(files=[dict(name='worker-err.txt',raw='Get-FileHash CommandNotFoundException')])])
def test_proven_pre_cli_preparation_only_continuation():assert p.preparation_eligible({'status':'FAILED'},prep(),False)
@pytest.mark.parametrize('change',['already_entered','live_observer','prestop_active','prestop_attempt','service_stopped','no_proven_error'])
def test_preparation_continuation_never_replays_entered_or_unknown_business(change):
 o=prep();entered=False
 if change=='already_entered':entered=True
 elif change=='live_observer':o['observer']={'pid':42}
 elif change=='prestop_active':o['prestop']['phase']='failed'
 elif change=='prestop_attempt':o['prestop']['attempt']=1
 elif change=='service_stopped':o['service']['State']='Stopped'
 else:o['own']=[]
 assert not p.preparation_eligible({'status':'FAILED'},o,entered)

def test_inherited_foreign_job_is_allowed_only_with_exact_closed_product_job_witness():
 r=ready();r['in_any_job']=True
 assert p.fixture_valid(r,r['run_id'],r['controller'],r['nonce'],20)
 r.pop('managed_job_proof');assert not p.fixture_valid(r,r['run_id'],r['controller'],r['nonce'],20)
@pytest.mark.parametrize('change',['service_pid_reuse','service_creation_reuse','missing_target','worker_is_member','duplicate_still_open','probe_still_open','wrong_target_list','multiple_candidate_jobs'])
def test_exact_native_product_job_witness_fail_closed(change):
 r=ready()['managed_job_proof']
 if change=='service_pid_reuse':r['supervisor_pid']=99
 elif change=='service_creation_reuse':r['supervisor_creation']='reused'
 elif change=='missing_target':r['target_creation']=None
 elif change=='worker_is_member':r['jobs'][0]['worker_member']=True
 elif change=='duplicate_still_open':r['duplicates_closed']=False
 elif change=='probe_still_open':r['probe_job_closed']=False
 elif change=='wrong_target_list':r['jobs'][0]['members']=[]
 else:r['jobs'].append(copy.deepcopy(r['jobs'][0]))
 assert not p.independent_product_job(r)
def test_job_gate_preparation_failure_before_listener_can_be_reconciled():
 o=prep();o['own'][0]['files'][0]['raw']='external listener must not inherit any Job'
 assert p.preparation_eligible({'status':'FAILED'},o,False)
