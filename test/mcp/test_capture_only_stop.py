"""Real controller/cache gates; lifecycle execution is a declared local seam."""
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.tools import register_tools
from fakenet.mcp.errors import McpError

OWNER='88888888-1111-4222-8333-555555555555'
OTHER='99999999-1111-4222-8333-555555555555'
CHECKPOINT_SCHEMA='fakenet.capture-checkpoint.v1'
CHECKPOINT_ID='11111111-2222-4333-8444-555555555555'
ROLES=('raw','converted','observations','nbis','seal','html','log')


def checkpoint():
    return {'schema':CHECKPOINT_SCHEMA,'capture_id':CHECKPOINT_ID,
            'capture_interval_complete':True,'recording_continues':False,
            'process':{'pid':4242,'birth':'777'},
            'files':[{'role':role,'path':'/opt/fakenet-ng/Logs/r41-'+role,
                      'bytes':11,'device':2050,'inode':900+index,
                      'sha256':'c'*64}
                     for index,role in enumerate(ROLES)]}


def surface(capture=True):
    stop=Mock(return_value=dict(state='stopped',changed=True,run_id=None,release_controller=True))
    seal_result=dict(state='healthy',changed=True,run_id='a'*32,release_controller=False,
                     capture_checkpoint=checkpoint())
    seal=Mock(return_value=seal_result)
    runner=SimpleNamespace(stop=stop,health_detail=lambda state:{'process_alive':state=='healthy'})
    if capture:runner.seal_capture=seal
    coordinator=Coordinator(runner)
    coordinator.restore_responsibility({'run_id':'a'*32,'controller_id':OWNER,'needs_recovery':True},'healthy')
    active=['default.ini'];caller=[OWNER]
    context=SimpleNamespace(coordinator=coordinator,runner=runner,
        store=SimpleNamespace(set_active=lambda value:active.__setitem__(0,value)),
        controller_identity=lambda:(caller[0],'valid_uuid'),
        error_response=lambda error:{'error':error.to_dict()})
    tools={}
    def register(**metadata):
        def decorate(func):tools[func.__name__]=func;return func
        return decorate
    register_tools(SimpleNamespace(tool=register),context)
    return tools,coordinator,stop,seal,active,caller,seal_result


def test_capture_stop_retains_owner_and_default_stop_releases():
    tools,c,stop,seal,active,caller,seal_result=surface()
    value=tools['stop']('capture-1',1,capture_only=True)
    assert value['state']=='healthy' and c.snapshot()['controller']==OWNER
    assert c.snapshot()['run_id']=='a'*32 and active==['default.ini']
    assert value['capture_checkpoint']==checkpoint()
    assert value['release_controller'] is False
    assert {'state','state_version','run_id','changed','error',
            'command_id','last_run_outcome'} <= set(value)
    seal.assert_called_once();stop.assert_not_called()
    again=tools['stop']('capture-1',1,capture_only=True)
    assert again['replayed'] is True
    assert again['capture_checkpoint']==checkpoint()
    assert again['release_controller'] is False
    seal.assert_called_once()
    status=c.command_status(command_id='capture-1',controller=OWNER,controller_valid=True)
    assert status['status']=='completed'
    assert status['response']['capture_checkpoint']==checkpoint()
    value=tools['stop']('normal-stop',2)
    assert value['state']=='stopped' and c.snapshot()['run_id'] is None
    assert 'capture_checkpoint' not in value and 'release_controller' not in value
    assert active==[None];stop.assert_called_once()
    status=c.command_status(command_id='capture-1',controller=OWNER,controller_valid=True)
    assert status['status']=='completed'
    assert status['response']['capture_checkpoint']==checkpoint()


def test_capture_receipt_isolation_across_views_and_replay():
    tools,c,stop,seal,active,caller,seal_result=surface()
    value=tools['stop']('capture-1',1,capture_only=True)
    value['capture_checkpoint']['capture_id']='fresh-response-poison'
    status=c.command_status(command_id='capture-1',controller=OWNER,controller_valid=True)
    status['response']['capture_checkpoint']['capture_id']='query-view-poison'
    seal_result['capture_checkpoint']['capture_id']='runner-result-poison'
    again=tools['stop']('capture-1',1,capture_only=True)
    assert again['capture_checkpoint']==checkpoint()
    again['capture_checkpoint']['process']['pid']=1
    second=tools['stop']('capture-1',1,capture_only=True)
    assert second['capture_checkpoint']==checkpoint()
    status=c.command_status(command_id='capture-1',controller=OWNER,controller_valid=True)
    assert status['response']['capture_checkpoint']==checkpoint()
    seal.assert_called_once()


def test_capture_error_response_has_no_checkpoint():
    tools,c,stop,seal,active,caller,seal_result=surface()
    seal.side_effect=McpError('internal_error','capture checkpoint failed')
    value=tools['stop']('capture-error',1,capture_only=True)
    assert value['error']['code']=='internal_error'
    assert 'capture_checkpoint' not in value and 'release_controller' not in value
    assert seal.call_count==1


def test_exit_fenced_capture_stop_has_no_checkpoint():
    tools,c,stop,seal,active,caller,seal_result=surface()
    def fenced(coord):
        coord.fail_controlled_exit('controlled exit')
        return dict(seal_result)
    seal.side_effect=fenced
    value=tools['stop']('capture-fenced',1,capture_only=True)
    assert value['state']=='failed'
    assert 'capture_checkpoint' not in value
    again=tools['stop']('capture-fenced',1,capture_only=True)
    assert again['error']['code']=='not_allowed_in_state'
    assert 'capture_checkpoint' not in again
    seal.assert_called_once()


def test_normal_stop_fresh_response_is_isolated():
    tools,c,stop,seal,active,caller,_=surface()
    value=tools['stop']('normal-stop-fresh',1)
    assert value['state']=='stopped' and value['command_id']=='normal-stop-fresh'
    value['state']='caller_poison'
    value['command_id']='caller-renamed'
    status=c.command_status(command_id='normal-stop-fresh',controller=OWNER,controller_valid=True)
    assert status['status']=='completed'
    assert status['response']['state']=='stopped'
    assert status['response']['command_id']=='normal-stop-fresh'
    replay=tools['stop']('normal-stop-fresh',99)
    assert replay['replayed'] is True
    assert replay['state']=='stopped' and replay['command_id']=='normal-stop-fresh'
    replay['state']='replay-poison'
    status=c.command_status(command_id='normal-stop-fresh',controller=OWNER,controller_valid=True)
    assert status['response']['state']=='stopped'
    status['response']['state']='query-poison'
    again=tools['stop']('normal-stop-fresh',99)
    assert again['state']=='stopped'


def test_foreign_controller_cannot_seal():
    tools,c,stop,seal,active,caller,_=surface();caller[0]=OTHER
    value=tools['stop']('foreign',1,capture_only=True)
    assert value['error']['code']=='controller_conflict';seal.assert_not_called()
    assert c.snapshot()['state_version']==1 and active==['default.ini']
    assert 'capture_checkpoint' not in value


def test_stale_version_cannot_seal():
    tools,c,stop,seal,active,caller,_=surface()
    value=tools['stop']('stale',999,capture_only=True)
    assert value['error']['code']=='state_conflict';seal.assert_not_called()
    assert 'capture_checkpoint' not in value


def test_invalid_boolean_has_no_mutation():
    tools,c,stop,seal,active,caller,_=surface()
    value=tools['stop']('bad',1,capture_only='true')
    assert value['error']['code']=='invalid_request'
    assert c.snapshot()['state_version']==1;seal.assert_not_called()
    assert 'capture_checkpoint' not in value


def test_unsupported_runner_does_not_turn_into_normal_stop():
    tools,c,stop,seal,active,caller,_=surface(capture=False)
    value=tools['stop']('unsupported',1,capture_only=True)
    assert value['error']['code']=='not_allowed_in_state';stop.assert_not_called()
    assert c.snapshot()['run_id']=='a'*32 and active==['default.ini']
    assert 'capture_checkpoint' not in value
