"""Pure offline policy/identity/rollback regressions. No nft or VM operations."""
import copy
import importlib.util
import json
from pathlib import Path
import time
from unittest.mock import Mock

import pytest
from fakenet.mcp import host_merge, host_observer, host_policy, host_probe

UUID='B3E04D56-3DB2-9F3D-4D52-3EC22C4CFDC0'
COMMAND='44444444-5555-4666-8777-888888888888'


def facts():
    target={'vm_uuid':UUID,'mac':'00:0c:29:4c:fd:c0',
            'guest_ipv4':'192.168.204.149','guest_ipv6':'2001:db8:204::149',
            'host_ipv4':'192.168.204.1','host_link_local':'fe80::250:56ff:fec0:8',
            'boot_id':'guest-epoch'}
    entries=[{'table':{'family':'inet','name':host_policy.TABLE}},
             {'chain':{'family':'inet','table':host_policy.TABLE,'name':'prerouting',
                       'type':'filter','hook':'prerouting','prio':-150,'policy':'accept'}}]
    for name,typ in [('tcp_drop4','ipv4_addr'),('tcp_drop6','ipv6_addr')]:
        entries.append({'set':{'family':'inet','table':host_policy.TABLE,'name':name,
                              'type':[typ,'inet_service',typ,'inet_service'],
                              'size':4096,'timeout':60000,'flags':['dynamic','timeout'],'elem':[]}})
    for expr in host_policy.expected_rules(target):
        entries.append({'rule':{'family':'inet','table':host_policy.TABLE,'chain':'prerouting','expr':expr}})
    now=time.time()
    return {'target':target,'ruleset':{'nftables':entries},
            'network':{'matching_vm':1,'vmnet8_users':1,'all_nics_mapped':True,'bypasses':[]},
            'natd':{'pid':3730,'birth_ticks':2179,'boot_id':'host-boot',
                    'state':'stopped','all_threads_stopped':True,'pidfd_identity':True},
            'observer_identity':{'pid':9000,'birth_ticks':100,'boot_id':'host-boot',
                                 'script_sha256':'a'*64,'lease_id':'b'*32,
                                 'window_start':now-10,'window_end':now+100}}


def config():
    return {'expected_uuid':UUID,'expected_mac':'00:0c:29:4c:fd:c0','guest_ip':'192.168.204.149'}


def set_elem(value,count=1):
    value['ruleset']['nftables'][2]['set']['elem']=[{'elem':{'val':{'concat':[
        '192.168.204.149',50000,'198.51.100.77',80]},'counter':{'packets':count,'bytes':60}}}]


def test_policy_requires_complete_structural_rules_not_boolean_claims():
    value=facts()
    assert host_policy.evaluate(value,config())['ok']
    value['policy']={'management_only':True,'fallback_all_vmnet8':True}
    del value['ruleset']
    assert not host_policy.evaluate(value,config())['ok']


@pytest.mark.parametrize('mutation',[
    lambda f:f['ruleset']['nftables'].pop(),  # missing final drop
    lambda f:f['ruleset']['nftables'][1]['chain'].update(prio=-100),
    lambda f:f['ruleset']['nftables'][2]['set'].update(size=0),
    lambda f:f['ruleset']['nftables'][2]['set'].update(timeout=0),
    lambda f:f['ruleset']['nftables'][4]['rule']['expr'].pop(1),  # missing target MAC
    lambda f:f['ruleset']['nftables'][6]['rule']['expr'].pop(8),  # missing original host tuple
    lambda f:f['ruleset']['nftables'].insert(4,{'rule':{'family':'inet','table':host_policy.TABLE,'chain':'prerouting','expr':[{'accept':None}]}}),
    lambda f:f['network'].update(vmnet8_users=2),
    lambda f:f['network'].update(all_nics_mapped=False),
    lambda f:f['natd'].update(all_threads_stopped=False),
    lambda f:f['target'].update(mac='11:22:33:44:55:66'),
    lambda f:f['observer_identity'].update(window_end=float('inf')),
])
def test_known_wrong_policies_are_rejected(mutation):
    value=facts();mutation(value)
    assert host_policy.evaluate(value,config())['ok'] is False


def test_counters_do_not_change_identity_but_real_rules_and_lease_do():
    value=facts();first=host_policy.evaluate(value,config())['identity']
    set_elem(value,3)
    value['ruleset']['nftables'][-1]['rule']['expr'][-2]['counter']={'packets':99,'bytes':111}
    assert host_policy.evaluate(value,config())['identity']==first
    value['observer_identity']['lease_id']='c'*32
    assert host_policy.evaluate(value,config())['identity']!=first


def test_drop_delta_only_valid_complete_sets_and_exact_tuple():
    before=facts();after=copy.deepcopy(before);set_elem(after,2)
    fields={'family':'ipv4','source':'192.168.204.149','source_port':50000,
            'destination':'198.51.100.77','destination_port':80}
    assert host_policy.drop_delta(before,after,**fields)==2
    assert host_policy.drop_delta(before,after,**dict(fields,source_port=50001))==0
    before['ruleset']['nftables'].pop(2)
    assert host_policy.drop_delta(before,after,**fields) is None


def test_earlier_rewrite_and_flowtable_are_rejected():
    value=facts();entries=value['ruleset']['nftables']
    entries += [{'chain':{'family':'ip','table':'raw','name':'early','hook':'prerouting','prio':-300}},
                {'rule':{'family':'ip','table':'raw','chain':'early','expr':[{'mangle':{'key':{},'value':1}}]}}]
    assert not host_policy.evaluate(value,config())['ok']
    entries[-1]['rule']['expr']=[{'match':{'left':{},'right':1,'op':'=='}},{'counter':{}},{'drop':None}]
    assert host_policy.evaluate(value,config())['ok']
    entries.append({'flowtable':{'family':'inet','table':'x','name':'flow'}})
    assert not host_policy.evaluate(value,config())['ok']


def test_response_requires_real_kernel_live_producer():
    value={'schema':host_observer.SCHEMA,'command_id':COMMAND,'phase':'pre','challenge':'a'*32,
           'producer':{'uid':0,'pid':99999999,'birth_ticks':1,'boot_id':'fake','script_sha256':'x',
                       'window_start':time.time()-1,'window_end':time.time()+100},'facts':{}}
    with pytest.raises(host_observer.ObserverError,match='not live'):
        host_observer.validate_response(value,command_id=COMMAND,phase='pre',challenge='a'*32)


def test_response_live_identity_and_fresh_collection(monkeypatch):
    value=facts();owner=value['observer_identity'];now=time.time()
    response={'schema':host_observer.SCHEMA,'command_id':COMMAND,'phase':'pre','challenge':'a'*32,
              'producer':dict(owner,uid=0),'script_sha256':owner['script_sha256'],
              'collected_at':now,'facts':value}
    monkeypatch.setattr(host_observer,'_proc_identity',lambda pid:dict(owner,uid=0))
    monkeypatch.setattr(host_observer,'_script_sha',lambda *a:owner['script_sha256'])
    assert host_observer.validate_response(response,command_id=COMMAND,phase='pre',challenge='a'*32,now=now,requested_at=now)['facts']==value
    response['collected_at']=now-10
    with pytest.raises(host_observer.ObserverError,match='not current'):
        host_observer.validate_response(response,command_id=COMMAND,phase='pre',challenge='a'*32,now=now,requested_at=now)


def test_root_channel_rejects_nonroot_and_writable_ancestor(tmp_path):
    with pytest.raises(host_observer.ObserverError):
        host_observer.RootObserverClient({'directory':str(tmp_path),'expected_uid':1000})


def fixture_module():
    spec=importlib.util.spec_from_file_location('fixture_main',Path(__file__).resolve().parents[2]/'tools/fakenet_egress_fixture.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


@pytest.mark.parametrize('change',[
    {'challenge':'../../something-is-wrong'}, {'version':True}, {'extra':'shell'},
    {'phase':'apply'}, {'command_id':'not-registered'},
])
def test_root_protocol_cannot_request_actions_or_paths(change):
    module=fixture_module();request={'schema':module.REQUEST_SCHEMA,'version':1,'command_id':COMMAND,'phase':'pre','challenge':'a'*32};request.update(change)
    with pytest.raises(RuntimeError):module.validate_request(request,{'commands':[COMMAND],'window_start':time.time()-1,'window_end':time.time()+1})


def test_root_recovery_retains_isolation_when_cleanup_unknown(monkeypatch,tmp_path):
    module=fixture_module();config={'natd_pid':3730,'natd_birth_ticks':2179}
    state={'config_sha256':module.sha(config),'host_boot':'boot','nat_before':{'birth_ticks':2179}}
    monkeypatch.setattr(module,'read_root',lambda path:state)
    monkeypatch.setattr(module,'proc',lambda pid:{'boot_id':'boot'})
    monkeypatch.setattr(module,'check_quiescence',Mock(side_effect=RuntimeError('unknown guest')))
    signal=Mock();command=Mock();monkeypatch.setattr(module.signal,'pidfd_send_signal',signal,raising=False);monkeypatch.setattr(module,'command',command)
    with pytest.raises(RuntimeError,match='unknown guest'):module.recover(tmp_path/'state',config,tmp_path)
    signal.assert_not_called();command.assert_not_called()


def test_root_recovery_rejects_pid_reuse_before_signal(monkeypatch,tmp_path):
    module=fixture_module();config={'natd_pid':3730,'natd_birth_ticks':2179}
    state={'config_sha256':module.sha(config),'host_boot':'boot','nat_before':{'birth_ticks':2179}}
    monkeypatch.setattr(module,'read_root',lambda p:state);monkeypatch.setattr(module,'proc',lambda pid:{'boot_id':'boot'})
    monkeypatch.setattr(module,'check_quiescence',lambda *a:None)
    monkeypatch.setattr(module,'current_nat',lambda config:{'birth_ticks':9999})
    signal=Mock();monkeypatch.setattr(module.signal,'pidfd_send_signal',signal,raising=False)
    with pytest.raises(RuntimeError,match='PID reused'):module.recover(tmp_path/'state',config,tmp_path)
    signal.assert_not_called()


def test_attempt_only_is_never_sufficient_for_tcp_drop():
    row={'kind':'tcp','family':'ipv4','destination':'198.51.100.77','port':80,'attempted':True,'sent':0,'received':''}
    assert host_merge._drop_evidence(row,{}, {}) is None
    assert host_probe.classify_step(row,row,'blocked',boundary_verified=True)[0]=='unknown'


def test_real_merge_requires_complete_connect_and_same_window():
    from datetime import datetime, timezone
    now=time.time();before=facts();after=copy.deepcopy(before);set_elem(after,2)
    policy1=host_policy.evaluate(before,config());policy2=host_policy.evaluate(after,config())
    producer=before['observer_identity']
    pre={'policy':policy1,'observer':{'available':True,'phase':'pre','command_id':COMMAND,'producer':producer,'facts':before,'response':{'collected_at':now-1}}}
    final={'policy':policy2,'observer':{'available':True,'phase':'final','command_id':COMMAND,'producer':producer,'facts':after,'response':{'collected_at':now+1}}}
    iso=lambda t:datetime.fromtimestamp(t,timezone.utc).isoformat()
    row={'kind':'tcp','family':'ipv4','destination':'198.51.100.77','port':80,'attempted':True,'connect_called':True,'exclusive':True,'connect_started':iso(now),'connect_ended':iso(now+.1),'probe_pid':100,'probe_birth_ticks':123,'script_hash':'hash','bound_local_endpoint':'192.168.204.149:50000','local_endpoint':'192.168.204.149:50000','received':'','sent':0}
    probe={'instance':{'pid':100,'creation_ticks':123,'script_hash':'hash'},'identity':{'boot_id':'guest-epoch'}}
    assert host_merge._drop_evidence(row,pre,final,probe)==2
    for key,bad in [('probe_pid',999),('connect_called',False),('exclusive',False),('probe_birth_ticks',124),('connect_started',iso(now-10))]:
        assert host_merge._drop_evidence(dict(row,**{key:bad}),pre,final,probe) is None
    final['observer']['phase']='pre'
    assert host_merge._drop_evidence(row,pre,final,probe) is None


def test_root_preflight_refuses_earlier_rewrite_before_any_mutation():
    module=fixture_module()
    sample={'nftables':[{'chain':{'family':'ip','table':'raw','name':'early','hook':'prerouting','prio':-300}}, {'rule':{'family':'ip','table':'raw','chain':'early','expr':[{'mangle':{'key':{},'value':1}}]}}]}
    with pytest.raises(RuntimeError,match='earlier'):module.preflight_rules(sample)
    sample['nftables'][1]['rule']['expr']=[{'match':{}},{'counter':{}},{'drop':None}]
    module.preflight_rules(sample)
