"""Real Linux runner/tool/coordinator wiring with isolated OS backends."""
import os
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from fakenet.mcp import linuxrunner as lr
from fakenet.mcp.config import ServiceConfig
from fakenet.mcp.configstore import ConfigStore
from fakenet.mcp.tools import AppContext, register_tools
from fakenet.mcp.transportguard import controller_header_state
from fakenet.diverters import linuxnetpolicy as policy_module
from test_linuxnetpolicy import OrderedRules

A = '11111111-2222-4333-8444-555555555555'
B = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
INI = '[FakeNet]\nDivertTraffic=No\n'


@pytest.fixture
def wired(tmp_path, monkeypatch):
    monkeypatch.setenv('FAKENETNG_MCP_PROGRAMDATA', str(tmp_path / 'data'))
    monkeypatch.setattr(lr, '__file__', str(tmp_path / 'fakenet/mcp/linuxrunner.py'))
    store = ConfigStore(tmp_path / 'custom', tmp_path / 'builtin', tmp_path / 'audit.jsonl')
    # Parsing/listener imports are outside this owner/lock boundary; the
    # isolated backend supplies a known valid configuration verdict.
    monkeypatch.setattr(store, 'validate_content', lambda content: {'valid': True})
    store.create(controller=A, command_id='fixture', name='case.ini', content=INI)
    runner = lr.LinuxRunner(config_path_resolver=lambda name, builtin: str(store.custom_root / name))
    processes = []
    rules = {'present': True}

    class Process:
        def __init__(self, argv, **kwargs):
            self.flag = argv[argv.index('-f') + 1]
            self.returncode = None
            processes.append(self)
        def poll(self):
            if os.path.exists(self.flag):
                self.returncode = 0
            return self.returncode
        def terminate(self):
            self.returncode = 0
        def kill(self):
            self.returncode = -9
        def wait(self, timeout=None):
            return self.returncode

    monkeypatch.setattr(lr.subprocess, 'Popen', Process)
    monkeypatch.setattr(lr, '_ipt_has', lambda *a: rules['present'])
    ctx = AppContext(ServiceConfig('127.0.0.1', 28788, ['127.0.0.1']), runner=runner, store=store)
    functions = {}
    def register(**kw):
        def decorate(f):
            functions[f.__name__] = f
            return f
        return decorate
    register_tools(SimpleNamespace(tool=register), ctx)
    def call(operation, owner=A, **args):
        token = controller_header_state.set(owner)
        try:
            return functions[operation](**args)
        finally:
            controller_header_state.reset(token)
    def mutate(operation, owner=A, **args):
        return call(operation, owner, command_id=str(uuid.uuid4()),
                    expected_state_version=ctx.coordinator.snapshot()['state_version'], **args)
    mutate('load_config', name='case.ini')
    yield ctx, call, mutate, processes, rules
    rules['present'] = False
    if runner._proc is not None:
        runner.stop(ctx.coordinator)


def test_owner_rejection_and_active_config_lock_through_registered_tools(wired):
    ctx, call, mutate, procs, rules = wired
    started = mutate('start')
    snapshot = ctx.coordinator.snapshot()
    assert snapshot['state'] == 'healthy'
    assert snapshot['controller'] == A
    assert ctx.store.active_name == 'case.ini'
    for name in ('stop', 'restart'):
        rejected = mutate(name, B)
        assert rejected['error']['code'] == 'controller_conflict'
        assert ctx.coordinator.snapshot() == snapshot
        assert procs[0].poll() is None and len(procs) == 1
    rejected = mutate('load_config', B, name='case.ini')
    assert rejected['error']['code'] == 'controller_conflict'
    assert ctx.coordinator.snapshot() == snapshot
    before = ctx.store.read('case.ini')
    rejected = mutate('edit_config', name='case.ini', content=INI+'# changed\n', expected_sha256=before['sha256'])
    assert rejected['error']['code'] == 'config_in_use'
    assert ctx.store.read('case.ini') == before
    assert call('get_status', B)['run_id'] == started['run_id']
    rules['present'] = False
    stopped = mutate('stop')
    assert stopped['state'] == 'stopped'
    final = call('get_status')
    assert final['controller'] is None and final['run_id'] is None
    assert final['failure_reason'] is None and ctx.store.active_name is None


def test_failed_stop_retains_responsibility_and_reason(wired):
    ctx, call, mutate, procs, rules = wired
    mutate('start')
    failed = mutate('stop')
    assert failed['state'] == 'failed'
    assert 'NFQUEUE' in call('get_status')['failure_reason']
    assert call('get_status')['controller'] == A
    assert ctx.store.active_name == 'case.ini'
    repeated = mutate('stop')
    assert repeated['state'] == 'failed'
    assert call('get_status')['controller'] == A
    rules['present'] = False
    assert mutate('stop')['state'] == 'stopped'
    assert call('get_status')['failure_reason'] is None



def test_ordered_rules_repeat_cleanup_and_precise_endpoints(monkeypatch):
    model = OrderedRules()
    monkeypatch.setattr(policy_module, '_run', model)
    policy = policy_module.NetPolicy([('192.168.204.1',2222),('fd00::1',2222)])
    policy.install_control_exclusions_v4()
    policy.block_ipv6()
    v6 = model.chains['ip6tables','filter','OUTPUT']
    drop = next(i for i,r in enumerate(v6) if r[-1]=='DROP')
    assert all(i < drop for i,r in enumerate(v6) if r[-1]=='ACCEPT')
    incoming = model.chains['iptables','mangle','INPUT']
    endpoint = next(r for r in incoming if '192.168.204.1' in r)
    assert '-p' in endpoint and 'tcp' in endpoint and '--dport' in endpoint and '2222' in endpoint
    ipv6_endpoint = next(r for r in v6 if 'fd00::1' in r)
    assert 'tcp' in ipv6_endpoint and '--sport' in ipv6_endpoint and '2222' in ipv6_endpoint
    before = {k:list(v) for k,v in model.chains.items()}
    policy.install_control_exclusions_v4(); policy.block_ipv6()
    assert model.chains == before
    policy.stop()
    assert not any(model.chains.values())


def test_adoption_does_not_delete_foreign_wide_rule(monkeypatch):
    model = OrderedRules()
    wide = ('-s','192.168.204.1','-j','ACCEPT')
    model.chains['iptables','mangle','INPUT'] = [wide]
    monkeypatch.setattr(policy_module, '_run', model)
    policy = policy_module.NetPolicy([('192.168.204.1',2222)])
    policy.adopt_leftovers()
    assert model.chains['iptables','mangle','INPUT'] == [wide]
    with pytest.raises(RuntimeError):
        policy.install_control_exclusions_v4()


def test_registered_start_replay_does_not_spawn_again(wired):
    ctx, call, mutate, procs, rules = wired
    version=ctx.coordinator.snapshot()['state_version']
    command=str(uuid.uuid4())
    started=call('start',command_id=command,expected_state_version=version)
    replay=call('start',command_id=command,expected_state_version=version)
    assert replay['replayed'] is True and replay['run_id']==started['run_id']
    assert len(procs)==1 and ctx.store.active_name=='case.ini'


def test_start_failure_does_not_bind_success(wired, monkeypatch):
    ctx, call, mutate, procs, rules = wired
    monkeypatch.setattr(lr.subprocess,'Popen',lambda *a,**k:SimpleNamespace(poll=lambda:2,returncode=2))
    with pytest.raises(lr.LinuxRunnerError):mutate('start')
    status=call('get_status')
    assert status['controller'] is None and status['run_id'] is None
    assert ctx.store.active_name is None
