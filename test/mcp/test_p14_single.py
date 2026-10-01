"""Self-contained P14 observer regressions: synthetic proof, never VM results."""
import copy
import importlib.util
from pathlib import Path
import pytest
spec=importlib.util.spec_from_file_location('p14_single',Path(__file__).parent/'acceptance'/'p14_single.py')
p14=importlib.util.module_from_spec(spec);spec.loader.exec_module(p14)

def proof():
    owner={'run_id':'r','controller':'c','pid':73,'creation_time':123,'job':{'native_handle':42},'helper':{'pid':74,'creation_time':124},'exit_deadline':450,'failure_reason':'original restore failure','needs_recovery':True}
    return {'before':owner,'held':copy.deepcopy(owner),'operation':{'semantic':'fakenetng-mcp.exe stop','exit_code':1,'seconds':5},'start':{'error_code':'not_allowed_in_state','owner_after':copy.deepcopy(owner)},'fault_arm':{'run_id':'r','nonce':'own-nonce'},'fault_disabled':{'run_id':'r','nonce':'own-nonce','verified_absent':True},'retry':{'run_id':'r','seconds':7,'exit_code':0},'after':{'needs_recovery':False,'owner':None},'five_sections_before':dict.fromkeys(p14.SECTIONS,'raw before'),'five_sections_after':dict.fromkeys(p14.SECTIONS,'raw after'),'audit_diff':{}}

def test_positive_retained_then_same_owner_recovery():
    assert p14.responsibility_verdict(proof())['passed']

@pytest.mark.parametrize('change',['operation_not_recovery','overwritten_start','missing_creation','wrong_helper','changed_deadline','foreign_disable','unbounded_retry','wrong_retry_owner','unresolved','missing_section','client_proxy','wrong_nonce','empty_job'])
def test_wrong_or_missing_responsibility_never_passes(change):
    p=proof()
    if change=='operation_not_recovery':p['held']['needs_recovery']=False
    elif change=='overwritten_start':p['start']['owner_after']['run_id']='new'
    elif change=='missing_creation':p['before'].pop('creation_time')
    elif change=='wrong_helper':p['held']['helper']['creation_time']+=1
    elif change=='changed_deadline':p['held']['exit_deadline']+=1
    elif change=='foreign_disable':p['fault_disabled']['run_id']='other'
    elif change=='unbounded_retry':p['retry']['seconds']=511
    elif change=='wrong_retry_owner':p['retry']['run_id']='other'
    elif change=='unresolved':p['after']['needs_recovery']=True
    elif change=='wrong_nonce':p['fault_disabled']['nonce']='foreign'
    elif change=='empty_job':p['before']['job']={}
    elif change=='missing_section':p['five_sections_after'].pop('routes')
    else:p['operation']['semantic']='unrelated client disconnect'
    assert not p14.responsibility_verdict(p)['passed']


def test_real_config_argument_name_does_not_collide_with_tool_name(tmp_path):
    j=p14.Journal(tmp_path);j.gate=lambda **kw:None
    j.value=lambda *_:{'state_version':9}
    calls=[]
    j.call=lambda *args:calls.append(args) or {'ok':True}
    assert j.mutation('create_config',name='own.ini',content='input')['ok']
    assert calls[0][0]=='create_config' and calls[0][1]['name']=='own.ini'
    assert calls[0][1]['expected_state_version']==9
    assert calls[0][1]['command_id'].startswith('r05-p14-')


def test_operator_requires_actual_failed_native_owner_before_action(tmp_path):
    j=p14.Journal(tmp_path);j.run_id='r';j.snapshot=lambda:{'marker':{'needs_recovery':False}}
    j.value=lambda *_:{'state':'stopped'}
    j.vm=lambda *_:pytest.fail('must not invoke operator on unrelated clean service')
    with pytest.raises(AssertionError):j.operator_stop({})
