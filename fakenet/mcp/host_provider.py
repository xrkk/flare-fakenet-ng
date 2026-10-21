"""Fixed, read-only host facts for the Ubuntu/VMware verification provider.

No argv or path comes from the AI.  The provider reads the configured VMX,
VMware network files, every present VM NIC, ip/sysctl/process facts and, when
permitted, firewall rules.  A missing mapping, permission failure or unknown
family/interface fact becomes an explicit unknown; it is never promoted to a
containment pass.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

from fakenet.mcp import host_observer, host_policy
from fakenet.mcp.host_identity import normal_uuid as _normal_uuid


def _sha_text(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _mask_mac(value):
    parts = str(value or '').split(':')
    if len(parts) == 6:
        return ':'.join(parts[:3] + ['xx', 'xx', 'xx'])
    return str(value or '')


def _plain_file(path):
    p = Path(str(path or ''))
    if not p.is_absolute() or p.is_symlink() or not p.is_file():
        return False
    try:
        for parent in [p, *p.parents]:
            if parent == parent.parent:
                break
            if parent.is_symlink():
                return False
    except OSError:
        return False
    return True


class HostProvider:
    def __init__(self, config, runner=None, observer=None):
        self.config = dict(config)
        self.runner = runner
        self.commands = []
        self._deadline = None
        self.observer = observer
        self._observer_context = None
        if self.observer is None and config.get('observer'):
            self.observer = host_observer.RootObserverClient(config['observer'])

    def set_observer_context(self, command_id, phase, challenge):
        self._observer_context = {
            'command_id': str(command_id), 'phase': str(phase),
            'challenge': str(challenge)}

    def _collect_observer(self):
        if self.observer is None or not self._observer_context:
            return None
        context = self._observer_context
        try:
            response = self.observer.request(
                context['command_id'], context['phase'],
                context['challenge'], timeout=self._remaining_observer())
        except Exception as exc:  # noqa: BLE001 - observer is fail-closed
            return {'available': False, 'error': repr(exc),
                    'phase': context['phase']}
        return {'available': True, 'phase': context['phase'],
                'response': response, 'facts': response.get('facts'),
                'producer': response.get('producer'),
                'challenge': response.get('challenge'),
                'command_id': response.get('command_id')}

    def _remaining_observer(self):
        if self._deadline is None:
            return 2.0
        return max(0.0, min(2.0, self._deadline - time.monotonic()))

    def _run(self, argv, timeout=5):
        if self._deadline is not None:
            timeout = max(0.0, min(timeout, self._deadline - time.monotonic()))
            if timeout <= 0:
                result = {'returncode': None, 'stdout': '',
                          'stderr': 'deadline'}
                item = {'argv': list(argv), 'returncode': None, 'stdout': '',
                        'stderr': 'deadline'}
                self.commands.append(item)
                return item
        if self.runner is not None:
            result = self.runner(argv, timeout)
        else:
            try:
                completed = subprocess.run(
                    argv, capture_output=True, text=True, timeout=timeout,
                    encoding='utf-8', errors='replace', shell=False)
                result = {'returncode': completed.returncode,
                          'stdout': completed.stdout or '',
                          'stderr': completed.stderr or ''}
            except Exception as exc:  # noqa: BLE001 - report the real failure
                result = {'returncode': None, 'stdout': '',
                          'stderr': repr(exc)}
        stdout = str(result.get('stdout') or '')
        item = {'argv': list(argv), 'returncode': result.get('returncode'),
                'stdout': stdout[:128 * 1024],
                'stdout_truncated': len(stdout) > 128 * 1024,
                'stderr': str(result.get('stderr') or '')[:32 * 1024]}
        self.commands.append(item)
        return item

    def _read_text(self, path, limit=128 * 1024):
        path = Path(str(path or ''))
        if not _plain_file(path):
            return {'path': str(path), 'available': False,
                    'error': 'not a plain file'}
        try:
            raw = path.read_bytes()[:limit]
        except OSError as exc:
            return {'path': str(path), 'available': False, 'error': repr(exc)}
        return {'path': str(path), 'available': True, 'content': raw.decode(
            'utf-8', 'replace'), 'sha256': hashlib.sha256(raw).hexdigest(),
            'size': len(raw)}

    @staticmethod
    def _vmx_fields(text):
        values = {}
        for line in text.splitlines():
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip().strip('"')
        return values

    @staticmethod
    def _answer_fields(text):
        values = {}
        for line in text.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[0] == 'answer':
                values[parts[1]] = parts[2]
        return values

    @staticmethod
    def _nat_fields(text):
        values = {}
        section = None
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('[') and line.endswith(']'):
                section = line[1:-1]
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                values[(section + '.' if section else '') +
                       key.strip()] = value.strip()
        return values

    @staticmethod
    def _sysctl_fields(text):
        values = {}
        for line in text.splitlines():
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            try:
                values[key.strip()] = int(value.strip())
            except ValueError:
                values[key.strip()] = value.strip()
        return values

    def _ip_json(self, kind):
        return self._ip_json_argv(['ip', '-j', kind])

    def _ip_json_argv(self, argv):
        result = self._run(argv)
        if result['returncode'] != 0:
            return {'available': False, 'error': result['stderr']}
        try:
            value = json.loads(result['stdout'] or '[]')
            return {'available': True, 'value': value}
        except ValueError as exc:
            return {'available': False, 'error': repr(exc)}

    @staticmethod
    def _vmx_nics(fields):
        nics = []
        groups = {}
        for key, value in fields.items():
            match = re.match(r'^ethernet(\d+)\.(.+)$', key)
            if match:
                groups.setdefault(int(match.group(1)), {})[match.group(2)] = value
        for index, item in sorted(groups.items()):
            connection = item.get('connectionType', 'unknown')
            present = str(item.get('present', 'TRUE')).upper() == 'TRUE'
            if not present and connection == 'unknown':
                continue
            nics.append({
                'index': index,
                'present': present,
                'connection_type': connection,
                'vnet': item.get('vnet', ''),
                'mac': item.get('address') or item.get('generatedAddress',
                                                       ''),
                'start_connected': str(item.get(
                    'startConnected', 'TRUE')).upper() == 'TRUE',
            })
        return nics

    @staticmethod
    def _interface_map(ip):
        links = {}
        for row in (ip.get('link', {}).get('value') or []):
            if isinstance(row, dict) and row.get('ifname'):
                links[row['ifname']] = row
        addresses = {}
        for row in (ip.get('address', {}).get('value') or []):
            if isinstance(row, dict) and row.get('ifname'):
                addresses.setdefault(row['ifname'], []).extend(
                    row.get('addr_info') or [])
        return links, addresses

    def snapshot(self, deadline=None):
        self._deadline = deadline
        observer_record = self._collect_observer()
        observer_policy = None
        vmx_path = self.config.get('vmx_path', '')
        vmx = self._read_text(vmx_path)
        vmx_fields = self._vmx_fields(vmx.get('content', '')) if vmx.get(
            'available') else {}
        networking = self._read_text(self.config.get(
            'vmware_networking_path', ''))
        networking_fields = self._answer_fields(
            networking.get('content', '')) if networking.get('available') else {}
        nat = self._read_text(self.config.get('nat_conf_path', ''))
        nat_fields = self._nat_fields(nat.get('content', '')) if nat.get(
            'available') else {}
        nics = self._vmx_nics(vmx_fields)
        if observer_record and observer_record.get('available'):
            observer_config = dict(self.config)
            observer_config.setdefault('expected_mac', (nics[0] if len(nics) == 1 else {}).get('mac'))
            observer_policy = host_policy.evaluate(observer_record.get('facts'), observer_config)
        configured_interface = str(self.config.get('interface') or 'vmnet8')
        ip = {kind: self._ip_json(kind) for kind in
              ('address', 'link', 'route', 'neigh', 'rule')}
        ip['ipv6_route'] = self._ip_json_argv(['ip', '-j', '-6', 'route'])
        ip['ipv6_rule'] = self._ip_json_argv(['ip', '-j', '-6', 'rule'])
        links, addresses = self._interface_map(ip)
        interfaces = sorted(set(links) | set(addresses))
        vnets = {}
        for key, value in networking_fields.items():
            match = re.match(r'^(VNET_\d+)_(.+)$', key)
            if match:
                vnets.setdefault(match.group(1), {})[match.group(2)] = value
        forwarding_keys = [
            'net.ipv4.ip_forward',
            'net.ipv4.conf.all.forwarding',
            'net.ipv4.conf.default.forwarding',
            'net.ipv6.conf.all.forwarding',
            'net.ipv6.conf.default.forwarding',
        ]
        for interface in interfaces:
            forwarding_keys.append('net.ipv4.conf.%s.forwarding' % interface)
            forwarding_keys.append('net.ipv6.conf.%s.forwarding' % interface)
        forwarding = self._run(['sysctl'] + forwarding_keys)
        sysctl = self._sysctl_fields(forwarding['stdout'])
        processes = self._run(['ps', '-C', 'vmware-vmx', '-C', 'vmnet-natd',
                               '-o', 'pid=,comm=,args='])
        lsmod = self._run(['lsmod'])
        firewall_nft = self._run(['nft', 'list', 'ruleset'])
        firewall_ipt = self._run(['iptables-save'])
        vmware_networks = self._run(['vmware-networks', '--status'])
        firewall_known = (firewall_nft['returncode'] == 0 or
                          firewall_ipt['returncode'] == 0)
        guest_ip = str(self.config.get('guest_ip') or '')
        route_to_guest = self._run(['ip', 'route', 'get', guest_ip]) if guest_ip \
            else {'returncode': None, 'stdout': '', 'stderr': 'guest_ip unset',
                  'argv': []}
        vm_processes = []
        for line in (processes.get('stdout') or '').splitlines():
            fields = line.split(None, 2)
            if len(fields) >= 2 and fields[1] == 'vmware-vmx':
                vm_processes.append(line.strip()[:2048])
        matching_vm = [line for line in vm_processes
                       if str(vmx_path) in line or Path(str(vmx_path)).name in line or
                       (_normal_uuid(vmx_fields.get('uuid.bios')) and
                        _normal_uuid(vmx_fields.get('uuid.bios')) in
                        _normal_uuid(line))]
        neigh = []
        for row in (ip['neigh'].get('value') or []):
            if isinstance(row, dict) and str(row.get('dst')) == guest_ip:
                neigh.append(row)
        target_interface = configured_interface
        mapped_nics = []
        reasons = []
        for nic in nics:
            vnet = str(nic.get('vnet') or configured_interface)
            link = links.get(vnet)
            mapped = {
                **nic,
                'interface': vnet,
                'interface_present': bool(link),
                'interface_state': (link or {}).get('operstate'),
                'interface_mac': (link or {}).get('address'),
                'vmnet': vnet.upper().replace('VMNET', 'VNET_'),
            }
            mapped_nics.append(mapped)
            if not link:
                reasons.append('nic_interface_unmapped:%s' % vnet)
        network_types = {nic['connection_type'] for nic in mapped_nics}
        if 'bridged' in network_types:
            network_type = 'bridged'
        elif 'nat' in network_types:
            network_type = 'nat'
        elif network_types and network_types <= {'hostonly'}:
            network_type = 'hostonly'
        else:
            network_type = 'unknown'
        target_nic = mapped_nics[0] if mapped_nics else None
        if target_nic:
            target_interface = target_nic['interface']
        vnet_key = target_interface.upper().replace('VMNET', 'VNET_')
        vnet_facts = dict(vnets.get(vnet_key, {}))
        nat_active = (network_type == 'nat' or
                      str(vnet_facts.get('NAT', 'no')).lower() == 'yes' or
                      any(nic.get('connection_type') == 'nat'
                          for nic in mapped_nics))
        bridge_active = network_type == 'bridged'
        ipv4_forward = sysctl.get('net.ipv4.ip_forward')
        ipv4_all = sysctl.get('net.ipv4.conf.all.forwarding')
        ipv4_default = sysctl.get('net.ipv4.conf.default.forwarding')
        ipv6_all = sysctl.get('net.ipv6.conf.all.forwarding')
        ipv6_default = sysctl.get('net.ipv6.conf.default.forwarding')
        per_interface = {}
        for interface in interfaces:
            per_interface[interface] = {
                'ipv4': sysctl.get('net.ipv4.conf.%s.forwarding' % interface),
                'ipv6': sysctl.get('net.ipv6.conf.%s.forwarding' % interface),
            }
        forwarding_values = [ipv4_forward, ipv4_all, ipv4_default,
                             ipv6_all, ipv6_default]
        forwarding_values += [row['ipv4'] for row in per_interface.values()]
        forwarding_values += [row['ipv6'] for row in per_interface.values()]
        if any(value not in (0, None) for value in forwarding_values):
            reasons.append('forwarding_enabled')
        if any(value is None for value in forwarding_values):
            reasons.append('forwarding_fact_missing')
        if not vmx.get('available'):
            reasons.append('vmx_unavailable')
        if not networking.get('available'):
            reasons.append('networking_unavailable')
        if not nics:
            reasons.append('vmx_nic_missing')
        if processes.get('stdout_truncated'):
            reasons.append('process_facts_truncated')
        elif processes.get('returncode') != 0:
            reasons.append('process_facts_unavailable')
        elif not vm_processes:
            reasons.append('vmware_process_missing')
        elif not matching_vm:
            reasons.append('vmx_running_instance_unmapped')
        if not neighbor_matches(neigh, target_interface,
                                (target_nic or {}).get('mac')):
            reasons.append('guest_neighbor_unmapped')
        if route_to_guest.get('returncode') != 0:
            reasons.append('guest_route_unavailable')
        elif target_interface not in str(route_to_guest.get('stdout') or ''):
            reasons.append('guest_route_interface_mismatch')
        default_routes = [row for row in
                          ((ip['route'].get('value') or []) +
                           (ip['ipv6_route'].get('value') or []))
                          if isinstance(row, dict) and
                          str(row.get('dst')) in ('default', '0.0.0.0/0',
                                                   '::/0')]
        mapped_interfaces = {nic.get('interface') for nic in mapped_nics}
        if any(str(row.get('dev')) in mapped_interfaces
               for row in default_routes):
            reasons.append('target_default_route')
        if (not ip['route'].get('available') or
                not ip['rule'].get('available') or
                not ip['ipv6_route'].get('available') or
                not ip['ipv6_rule'].get('available')):
            reasons.append('route_or_rule_unavailable')
        if nat_active:
            reasons.append('nat_active')
        if bridge_active:
            reasons.append('bridge_active')
        if observer_record is not None:
            if not observer_record.get('available'):
                reasons.append('observer_unavailable')
            elif observer_policy is None or not observer_policy.get('ok'):
                reasons.extend(observer_policy.get('reasons') if observer_policy else ['observer_policy_invalid'])
        if (not _normal_uuid(vmx_fields.get('uuid.bios')) or
                not _normal_uuid(self.config.get('expected_uuid')) or
                _normal_uuid(vmx_fields.get('uuid.bios')) != _normal_uuid(
                    self.config.get('expected_uuid'))):
            reasons.append('vmx_uuid_mismatch')
        target_blockers = [reason for reason in reasons if reason not in (
            'forwarding_enabled', 'nat_active')]
        if (observer_record is not None and observer_record.get('available')
                and observer_policy and observer_policy.get('ok')
                and not target_blockers):
            boundary = {'value': True, 'reason': 'validated_local_isolation_policy',
                        'policy_identity': observer_policy.get('identity'),
                        'observer_bound': True}
        elif (not reasons and target_nic and network_type == 'hostonly' and
                not nat_active and not bridge_active):
            boundary = {'value': True, 'reason': 'hostonly_all_nics_no_nat_forwarding'}
        elif reasons:
            boundary = {'value': None, 'reason': reasons[0],
                        'reasons': reasons}
        else:
            boundary = {'value': None, 'reason': 'insufficient_facts',
                        'reasons': ['insufficient_facts']}
        return {
            'schema': 'fakenetng.host-egress-provider.v2',
            'vmx': {
                'path': vmx_path,
                'sha256': vmx.get('sha256'),
                'available': vmx.get('available'),
                'uuid': vmx_fields.get('uuid.bios', ''),
                'connection_type': (target_nic or {}).get(
                    'connection_type', 'unknown'),
                'mac': _mask_mac((target_nic or {}).get('mac', '')),
                'guest_os': vmx_fields.get('guestOS', ''),
                'nics': mapped_nics,
            },
            'networking': {'available': networking.get('available'),
                           'sha256': networking.get('sha256'),
                           'vnets': vnets,
                           'target_vnet': vnet_key,
                           'target': vnet_facts},
            'nat': dict(nat_fields, available=nat.get('available'),
                        sha256=nat.get('sha256')),
            'ip': ip,
            'interfaces': per_interface,
            'route_to_guest': route_to_guest,
            'guest_neighbor': neigh,
            'default_routes': default_routes,
            'forwarding': {'sysctl': sysctl, 'ipv4': ipv4_forward,
                           'ipv4_all': ipv4_all,
                           'ipv4_default': ipv4_default,
                           'ipv6_all': ipv6_all,
                           'ipv6_default': ipv6_default,
                           'per_interface': per_interface},
            'processes': {'ps': processes, 'lsmod': lsmod,
                          'vmware_vmx': vm_processes,
                          'matching_vm': matching_vm},
            'firewall': {'known': firewall_known,
                         'nft': firewall_nft, 'iptables': firewall_ipt},
            'vmware_networks': vmware_networks,
            'network_type': network_type,
            'nat_active': nat_active,
            'bridge_active': bridge_active,
            'boundary': dict(boundary, role='legacy_diagnostic_not_qualification'),
            'qualification_basis': 'passive_running_observation',
            'observer': observer_record,
            'policy': observer_policy,
            'raw_commands': list(self.commands),
        }


def neighbor_matches(neigh, interface, mac):
    if not neigh or not interface:
        return False
    for row in neigh:
        if str(row.get('dev')) != str(interface):
            continue
        if mac and str(row.get('lladdr') or '').lower() != str(mac).lower():
            continue
        return True
    return False
