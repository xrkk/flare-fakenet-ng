import json
from fakenet.mcp.baseline import audit_compare


def test_verified_control_client_is_not_a_managed_engine_but_unknown_copies_are():
    image = r'C:\Program Files\FakeNet-NG-MCP\fakenetng-mcp.exe'
    service = '"' + image + '" run'
    supervisor = dict(ProcessName='fakenetng-mcp', Id=10,
                      ExecutablePath=image, CommandLine=service)
    before = dict(modules=[], managed=[supervisor], drivers=[], service_command=service)
    cli = dict(ProcessName='fakenetng-mcp', Id=20, ExecutablePath=image,
               CommandLine='"' + image + '" stop')
    def diff(row):
        after = dict(before, managed=[supervisor, row])
        sections = {k: 'same' for k in ('routes','dns_servers','listen_ports','services')}
        return audit_compare(dict(sections, windivert_processes=json.dumps(before)),
                             dict(sections, windivert_processes=json.dumps(after)))
    assert not diff(cli)
    assert diff(dict(cli, ExecutablePath=r'C:\unrelated\fakenetng-mcp.exe'))
    assert diff(dict(cli, CommandLine='"' + image + '" managed-child run-id dir'))
    assert diff(dict(cli, CommandLine='"' + image + '" run'))
    assert diff(dict(cli, CommandLine=''))
