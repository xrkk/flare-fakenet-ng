from types import SimpleNamespace

from fakenet.mcp.tools import register_tools


def test_failed_stop_retains_active_config_until_clean_recovery():
    tools = {}
    def register():
        def decorate(function):
            tools[function.__name__] = function
            return function
        return decorate
    active = ['case.ini']
    coordinator = SimpleNamespace(running=True)
    coordinator.submit = lambda **args: args['execute'](coordinator)
    runner = SimpleNamespace(stop=lambda coord: {'state': 'failed', 'run_id': 'run1'})
    ctx = SimpleNamespace(coordinator=coordinator, runner=runner,
                          store=SimpleNamespace(set_active=lambda value: active.__setitem__(0, value)),
                          controller_identity=lambda: ('owner', 'valid_uuid'))
    register_tools(SimpleNamespace(tool=register), ctx)
    assert tools['stop']('stop1', 1)['state'] == 'failed'
    assert active[0] == 'case.ini'
    runner.stop = lambda coord: {'state': 'stopped', 'run_id': None}
    assert tools['stop']('stop2', 2)['state'] == 'stopped'
    assert active[0] is None
