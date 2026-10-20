"""Read-only host provider mapping without touching real interfaces."""
import json
from pathlib import Path

from fakenet.mcp.host_provider import HostProvider

UUID = '56 4d e0 b3 b2 3d 3d 9f-4d 52 3e c2 2c 4c fd c0'


def make_files(tmp_path, connection='nat', nat='yes', forwarding='1',
               second_nic=None, ipv6_default='0', ipv6_interface='0'):
    vmx = tmp_path / 'fixture.vmx'
    lines = [
        'displayName = "fixture"',
        'guestOS = "windows9-64"',
        'uuid.bios = "%s"' % UUID,
        'ethernet0.present = "TRUE"',
        'ethernet0.connectionType = "%s"' % connection,
        'ethernet0.vnet = "vmnet8"',
        'ethernet0.generatedAddress = "00:0c:29:4c:fd:c0"',
    ]
    if second_nic:
        lines += [
            'ethernet1.present = "TRUE"',
            'ethernet1.connectionType = "%s"' % second_nic,
            'ethernet1.vnet = "vmnet1"',
            'ethernet1.generatedAddress = "00:0c:29:4c:fd:c1"',
        ]
    vmx.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    networking = tmp_path / 'networking'
    networking.write_text(
        'answer VNET_8_DHCP yes\n'
        'answer VNET_8_HOSTONLY_SUBNET 192.168.204.0\n'
        'answer VNET_8_NAT %s\n'
        'answer VNET_8_VIRTUAL_ADAPTER yes\n'
        'answer VNET_1_NAT no\n' % nat, encoding='utf-8')
    nat_conf = tmp_path / 'nat.conf'
    nat_conf.write_text(
        '[host]\n'
        'ip = 192.168.204.2\n'
        'netmask = 255.255.255.0\n'
        'device = /dev/vmnet8\n', encoding='utf-8')
    return vmx, networking, nat_conf, forwarding, ipv6_default, ipv6_interface


def runner_factory(forwarding='1', ipv6_default='0', ipv6_interface='0',
                   vmx_path='fixture.vmx'):
    def runner(argv, timeout):
        if argv[:3] == ['ip', '-j', '-6']:
            kind = argv[3]
            value = {'route': [], 'rule': []}.get(kind, [])
            return {'returncode': 0, 'stdout': json.dumps(value),
                    'stderr': ''}
        if argv[:2] == ['ip', '-j']:
            kind = argv[2]
            value = {
                'address': [
                    {'ifname': 'vmnet8', 'link_type': 'ether',
                     'addr_info': [{'family': 'inet',
                                    'local': '192.168.204.1',
                                    'prefixlen': 24}]},
                    {'ifname': 'vmnet1', 'link_type': 'ether',
                     'addr_info': [{'family': 'inet',
                                    'local': '192.168.180.1',
                                    'prefixlen': 24}]},
                ],
                'link': [
                    {'ifname': 'vmnet8', 'link_type': 'ether',
                     'operstate': 'UNKNOWN',
                     'address': '00:50:56:c0:00:08'},
                    {'ifname': 'vmnet1', 'link_type': 'ether',
                     'operstate': 'UNKNOWN',
                     'address': '00:50:56:c0:00:01'},
                ],
                'route': [{'dst': 'default', 'dev': 'wlp0s20f3',
                           'gateway': '192.168.1.1'}],
                'neigh': [{'dst': '192.168.204.149', 'dev': 'vmnet8',
                           'lladdr': '00:0c:29:4c:fd:c0'}],
                'rule': [{'priority': 0, 'table': 'local'}],
            }[kind]
            return {'returncode': 0, 'stdout': json.dumps(value),
                    'stderr': ''}
        if argv[:3] == ['ip', 'route', 'get']:
            return {'returncode': 0,
                    'stdout': '192.168.204.149 dev vmnet8 src 192.168.204.1\n',
                    'stderr': ''}
        if argv[0] == 'sysctl':
            keys = argv[1:]
            values = {
                'net.ipv4.ip_forward': forwarding,
                'net.ipv4.conf.all.forwarding': forwarding,
                'net.ipv4.conf.default.forwarding': forwarding,
                'net.ipv6.conf.all.forwarding': '0',
                'net.ipv6.conf.default.forwarding': ipv6_default,
            }
            for interface in ('vmnet8', 'vmnet1', 'lo'):
                values['net.ipv4.conf.%s.forwarding' % interface] = forwarding
                values['net.ipv6.conf.%s.forwarding' % interface] = (
                    ipv6_interface if interface == 'vmnet1' else '0')
            return {'returncode': 0,
                    'stdout': '\n'.join('%s = %s' % (key, values.get(key, '0'))
                                        for key in keys) + '\n',
                    'stderr': ''}
        if argv[0] == 'ps':
            return {'returncode': 0,
                    'stdout': ' 1 init\n3730 vmnet-natd\n'
                              '3958 vmware-vmx -s %s\n' % vmx_path,
                    'stderr': ''}
        if argv[0] == 'lsmod':
            return {'returncode': 0, 'stdout': 'vmnet 77824 17\n',
                    'stderr': ''}
        if argv[0] == 'nft':
            return {'returncode': 1, 'stdout': '',
                    'stderr': 'Operation not permitted'}
        if argv[0] == 'iptables-save':
            return {'returncode': 4, 'stdout': '',
                    'stderr': 'Permission denied'}
        if argv[0] == 'vmware-networks':
            return {'returncode': 1, 'stdout': '',
                    'stderr': 'Failed to initialize'}
        return {'returncode': 1, 'stdout': '', 'stderr': 'fixture'}

    return runner


def config_for(tmp_path, vmx, networking, nat_conf):
    return {
        'vmx_path': str(vmx),
        'expected_uuid': UUID,
        'expected_computer': 'DESKTOP-3FI41GR',
        'guest_ip': '192.168.204.149',
        'vmware_networking_path': str(networking),
        'nat_conf_path': str(nat_conf),
        'interface': 'vmnet8',
    }


def test_nat_with_unknown_firewall_is_not_a_pass(tmp_path):
    files = make_files(tmp_path, connection='nat', nat='yes', forwarding='1')
    provider = HostProvider(config_for(tmp_path, *files[:3]),
                            runner=runner_factory('1'))
    snapshot = provider.snapshot()
    assert snapshot['network_type'] == 'nat'
    assert snapshot['nat_active'] is True
    assert snapshot['boundary']['value'] is None
    assert 'nat_active' in snapshot['boundary']['reasons']
    assert snapshot['firewall']['known'] is False
    assert snapshot['vmx']['mac'] == '00:0c:29:xx:xx:xx'
    assert snapshot['route_to_guest']['returncode'] == 0
    assert snapshot['forwarding']['ipv4'] == 1
    assert snapshot['raw_commands']


def test_host_only_complete_facts_can_pass(tmp_path):
    files = make_files(tmp_path, connection='hostonly', nat='no',
                       forwarding='0')
    provider = HostProvider(config_for(tmp_path, *files[:3]),
                            runner=runner_factory('0'))
    snapshot = provider.snapshot()
    assert snapshot['network_type'] == 'hostonly'
    assert snapshot['nat_active'] is False
    assert snapshot['boundary']['value'] is True, snapshot['boundary']
    assert snapshot['boundary']['reason'] == \
        'hostonly_all_nics_no_nat_forwarding'
    assert snapshot['vmx']['nics'][0]['interface'] == 'vmnet8'


def test_second_bridged_nic_and_ipv6_default_interface_are_unknown(tmp_path):
    files = make_files(tmp_path, connection='hostonly', nat='no',
                       forwarding='0', second_nic='bridged',
                       ipv6_default='1', ipv6_interface='1')
    provider = HostProvider(config_for(tmp_path, *files[:3]),
                            runner=runner_factory('0', ipv6_default='1',
                                                  ipv6_interface='1'))
    snapshot = provider.snapshot()
    assert snapshot['network_type'] == 'bridged'
    assert snapshot['bridge_active'] is True
    assert snapshot['boundary']['value'] is None
    assert 'bridge_active' in snapshot['boundary']['reasons']
    assert snapshot['forwarding']['ipv6_default'] == 1
    assert snapshot['forwarding']['per_interface']['vmnet1']['ipv6'] == 1


def test_unknown_vmx_is_unknown_not_pass(tmp_path):
    config = {
        'vmx_path': str(tmp_path / 'missing.vmx'),
        'guest_ip': '192.168.204.149',
        'interface': 'vmnet8',
    }
    provider = HostProvider(config, runner=runner_factory('1'))
    snapshot = provider.snapshot()
    assert snapshot['network_type'] == 'unknown'
    assert snapshot['boundary']['value'] is None
