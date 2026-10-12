"""Real controller/cache gates; lifecycle execution is a declared local seam."""
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from fakenet.mcp.coordination import Coordinator
from fakenet.mcp.tools import register_tools
from fakenet.mcp.errors import McpError

OWNER='88888888-1111-4222-8333-555555555555'
OTHER='99999999-1111-4222-8333-555555555555'


def surface(capture=True):
    stop=Mock(return_value=dict(state='stopped',changed=True,run_id=None,release_controller=True))
    seal=Mock(return_value=dict(state='healthy',changed=True,run_id='a'*32,release_controller=False,
                              capture_checkpoint={'nature':'local lifecycle double'}))
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
    return tools,coordinator,stop,seal,active,caller


def test_capture_stop_retains_owner_and_default_stop_releases():
    tools,c,stop,seal,active,caller=surface()
    value=tools['stop']('capture-1',1,capture_only=True)
    assert value['state']=='healthy' and c.snapshot()['controller']==OWNER
    assert c.snapshot()['run_id']=='a'*32 and active==['default.ini']
    seal.assert_called_once();stop.assert_not_called()
    again=tools['stop']('capture-1',1,capture_only=True)
    assert again['replayed'] is True;seal.assert_called_once()
    value=tools['stop']('normal-stop',2)
    assert value['state']=='stopped' and c.snapshot()['run_id'] is None
    assert active==[None];stop.assert_called_once()


def test_foreign_controller_cannot_seal():
    tools,c,stop,seal,active,caller=surface();caller[0]=OTHER
    value=tools['stop']('foreign',1,capture_only=True)
    assert value['error']['code']=='controller_conflict';seal.assert_not_called()
    assert c.snapshot()['state_version']==1 and active==['default.ini']


def test_stale_version_cannot_seal():
    tools,c,stop,seal,active,caller=surface()
    value=tools['stop']('stale',999,capture_only=True)
    assert value['error']['code']=='state_conflict';seal.assert_not_called()


def test_invalid_boolean_has_no_mutation():
    tools,c,stop,seal,active,caller=surface()
    value=tools['stop']('bad',1,capture_only='true')
    assert value['error']['code']=='invalid_request'
    assert c.snapshot()['state_version']==1;seal.assert_not_called()


def test_unsupported_runner_does_not_turn_into_normal_stop():
    tools,c,stop,seal,active,caller=surface(capture=False)
    value=tools['stop']('unsupported',1,capture_only=True)
    assert value['error']['code']=='not_allowed_in_state';stop.assert_not_called()
    assert c.snapshot()['run_id']=='a'*32 and active==['default.ini']
