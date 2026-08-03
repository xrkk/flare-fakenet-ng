# Copyright 2025 Google LLC

# Diverter for Windows implemented using WinDivert library

import logging

from pydivert.windivert import *

import socket

import os
import dpkt
from . import fnpacket

import time
import threading
import platform

from .winutil import *
from .diverterbase import *

import subprocess
import ipaddress

from .egresspolicy import EgressPolicy, PolicyConfigError, Verdict


class WindowsPacketCtx(fnpacket.PacketCtx):
    def __init__(self, lbl, wdpkt):
        self.wdpkt = wdpkt
        raw = wdpkt.raw.tobytes()

        super(WindowsPacketCtx, self).__init__(lbl, raw)

    # Packet mangling properties are extended here to also write the data to
    # the pydivert.Packet object. This is because there appears to be no way to
    # populate the pydivert.Packet object with plain octets unless you can also
    # provide @interface and @direction arguments which do not appear at a
    # glance to be directly available as attributes of pydivert.Packet,
    # according to https://ffalcinelli.github.io/pydivert/
    #
    # Perhaps we can get these from wd_addr?

    # src_ip overrides

    @property
    def src_ip(self):
        return self._src_ip

    @src_ip.setter
    def src_ip(self, new_srcip):
        super(self.__class__, self.__class__).src_ip.fset(self, new_srcip)
        self.wdpkt.src_addr = new_srcip

    # dst_ip overrides

    @property
    def dst_ip(self):
        return self._dst_ip

    @dst_ip.setter
    def dst_ip(self, new_dstip):
        super(self.__class__, self.__class__).dst_ip.fset(self, new_dstip)
        self.wdpkt.dst_addr = new_dstip

    # sport overrides

    @property
    def sport(self):
        return self._sport

    @sport.setter
    def sport(self, new_sport):
        super(self.__class__, self.__class__).sport.fset(self, new_sport)
        if self.proto:
            self.wdpkt.src_port = new_sport

    # dport overrides

    @property
    def dport(self):
        return self._dport

    @dport.setter
    def dport(self, new_dport):
        super(self.__class__, self.__class__).dport.fset(self, new_dport)
        if self.proto:
            self.wdpkt.dst_port = new_dport


class Diverter(DiverterBase, WinUtilMixin):

    def __init__(self, diverter_config, listeners_config, ip_addrs,
                 logging_level=logging.INFO):

        # Populated by winutil and used to restore modified Interfaces back to
        # DHCP
        self.adapters_dhcp_restore = list()
        self.adapters_dns_restore = list()

        super(Diverter, self).__init__(diverter_config, listeners_config,
                                       ip_addrs, logging_level)

        self.running_on_windows = True

        if not self.single_host_mode:
            self.logger.critical('Windows diverter currently only supports '
                                 'SingleHost mode')
            sys.exit(1)

        # Used (by winutil) for caching of DNS server names prior to changing
        self.adapters_dns_server_backup = dict()

        # Configure external and loopback IP addresses
        self.external_ip = self.get_best_ipaddress()
        if not self.external_ip:
            self.external_ip = self.get_ip_with_gateway()
        if not self.external_ip:
            self.external_ip = socket.gethostbyname(socket.gethostname())

        self.logger.debug('External IP: %s Loopback IP: %s' %
                          (self.external_ip, self.loopback_ip))

        #######################################################################
        # Initialize filter and WinDivert driver

        self.domain_allowlist_mode = (
            self.external_access_policy == 'domainallowlist')
        self.handle = None
        self._stopping = threading.Event()
        self._diverter_exited = threading.Event()
        self._network_restore_lock = threading.Lock()
        self._network_restored = False
        self._dns_modified = False
        self._dns_service_stopped = False
        self._drop_log_state = {}
        self._policy_listeners = []

        # DomainAllowList expands capture to IPv6 and delays opening WinDivert
        # until every listener and callback is ready.  Disabled mode preserves
        # the legacy constructor-time open behavior.
        self.filter = ('outbound and (ip or ipv6)'
                       if self.domain_allowlist_mode else 'outbound and ip')

        if self.domain_allowlist_mode:
            dns_server = self._select_external_dns_server()
            try:
                self.egress_policy = EgressPolicy(
                    self._dict,
                    set(self.ip_addrs.get(4, [])).union([self.external_ip]),
                    self.ip_addrs.get(6, []),
                    dns_server)
            except (PolicyConfigError, ValueError) as exc:
                self.logger.critical('Invalid DomainAllowList configuration: %s', exc)
                raise
            self._validate_policy_listeners()
        else:
            self._open_windivert_handle()

    def _select_external_dns_server(self):
        configured = str(self.getconfigval('ExternalDnsServer', 'Auto')).strip()
        candidates = []
        if configured.lower() == 'auto':
            for value in self.get_dns_servers() or []:
                if isinstance(value, bytes):
                    value = value.split(b'\x00', 1)[0].decode('ascii', 'ignore')
                candidates.append(str(value))
        else:
            candidates.append(configured)

        local = set(self.ip_addrs.get(4, [])).union(
            [self.external_ip, self.loopback_ip, '0.0.0.0'])
        for candidate in candidates:
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if (address.version == 4 and str(address) not in local and
                    not address.is_loopback and not address.is_link_local and
                    not address.is_multicast and not address.is_unspecified and
                    not address.is_reserved):
                return str(address)
        raise PolicyConfigError(
            'ExternalDnsServer=Auto found no usable non-local IPv4 resolver')

    def _validate_policy_listeners(self):
        relay_port = self.egress_policy.relay_port
        relay_sections = [
            cfg for cfg in self.listeners_config.values()
            if cfg.get('listener', '').lower() == 'domainegressrelay'
        ]
        if len(relay_sections) != 1:
            raise PolicyConfigError(
                'DomainAllowList requires exactly one DomainEgressRelay listener')
        relay = relay_sections[0]
        if relay.get('protocol', '').lower() != 'tcp' or int(relay['port']) != relay_port:
            raise PolicyConfigError('DomainEgressRelay protocol/port mismatch')
        dns_protocols = {
            cfg.get('protocol', '').lower()
            for cfg in self.listeners_config.values()
            if (cfg.get('listener', '').lower() == 'dnslistener' and
                int(cfg.get('port', 0)) == 53)
        }
        if dns_protocols != {'udp', 'tcp'}:
            raise PolicyConfigError(
                'DomainAllowList requires both UDP/53 and TCP/53 DNS listeners')
        for cfg in self.listeners_config.values():
            if (int(cfg.get('port', 0)) == relay_port and
                    cfg.get('listener', '').lower() != 'domainegressrelay'):
                raise PolicyConfigError('ExternalRelayPort conflicts with another listener')

    def _open_windivert_handle(self):
        if self.handle is not None:
            return
        try:
            self.handle = WinDivert(filter=self.filter)
            self.handle.open()
        except WindowsError as e:
            if e.winerror == 5:
                self.logger.critical('ERROR: Insufficient privileges to run '
                                     'windows diverter.')
                self.logger.critical('       Please restart with '
                                     'Administrator privileges.')
            elif e.winerror == 3:
                self.logger.critical('ERROR: Could not locate WinDivert DLL '
                                     'or one of its components.')
                self.logger.critical('       Please make sure you have copied '
                                     'FakeNet-NG to the C: drive.')
            else:
                self.logger.critical('ERROR: Failed to open a handle to the '
                                     'WinDivert driver: %s', e)
            self.handle = None
            raise

    def configure_policy_runtime(self, listeners):
        if self.domain_allowlist_mode:
            self._policy_listeners = list(listeners)

    def suspend_policy(self):
        if self.domain_allowlist_mode and self.egress_policy:
            self.egress_policy.suspend()

    ###########################################################################
    # Diverter controller functions

    def startCallback(self):
        if self.domain_allowlist_mode:
            self._open_windivert_handle()

        self.logger.debug('Diverting ports: ')
        self._stopping.clear()
        self._diverter_exited.clear()
        self.diverter_thread = threading.Thread(
            target=self.divert_thread, name='WinDivert')
        self.diverter_thread.daemon = True
        self.diverter_thread.start()

        if self.domain_allowlist_mode:
            # Fail before changing DNS if the receiver did not become live.
            self.diverter_thread.join(0.05)
            if not self.diverter_thread.is_alive():
                if self.handle:
                    self.handle.close()
                raise RuntimeError('WinDivert receiver thread failed to start')

        try:
            # Set local DNS only after policy listeners and WinDivert are
            # ready. Mark it first so a partial registry update is restored.
            if self.is_set('modifylocaldns'):
                self._dns_modified = True
                self.set_dns_server(self.external_ip)
                if self.domain_allowlist_mode:
                    observed = set()
                    for value in self.get_dns_servers() or []:
                        if isinstance(value, bytes):
                            value = value.split(b'\x00', 1)[0].decode(
                                'ascii', 'ignore')
                        observed.add(str(value))
                    if self.external_ip not in observed:
                        raise RuntimeError(
                            'local DNS redirection could not be verified')

            if self.is_set('stopdnsservice'):
                self._dns_service_stopped = True
                self.stop_service_helper('Dnscache')

            self.flush_dns()
        except Exception:
            if self.domain_allowlist_mode:
                self.egress_policy.suspend()
            self._stopping.set()
            try:
                self._restore_network_settings()
            except Exception:
                self.logger.exception(
                    'Network restoration failed during startup rollback')
            finally:
                if self.handle:
                    self.handle.close()
            self.diverter_thread.join(5)
            raise

        if self.domain_allowlist_mode:
            self.watchdog_thread = threading.Thread(
                target=self._watch_diverter_thread,
                name='WinDivertWatchdog', daemon=True)
            self.watchdog_thread.start()
            self.address_refresh_thread = threading.Thread(
                target=self._refresh_local_addresses,
                name='LocalAddressSnapshot', daemon=True)
            self.address_refresh_thread.start()
            self.log_egress_event(
                'DOMAIN_ALLOWLIST_READY',
                dns=self.egress_policy.external_dns_server,
                relay_port=self.egress_policy.relay_port)

        return True

    def divert_thread(self):
        try:
            while not self._stopping.is_set():
                wdpkt = self.handle.recv()

                if wdpkt is None:
                    self.logger.error('ERROR: Can\'t handle packet.')
                    continue

                if self.domain_allowlist_mode:
                    self._handle_policy_packet(wdpkt)
                else:
                    self._handle_legacy_packet(wdpkt)

        except WindowsError as e:
            if e.winerror in [4, 6, 995]:
                return
            else:
                raise
        except Exception:
            self.logger.exception('WinDivert receiver terminated unexpectedly')
        finally:
            self._diverter_exited.set()

    def _callbacks(self):
        return ([self.check_log_icmp, self.redirIcmpIpUnconditionally],
                [self.maybe_redir_port, self.maybe_fixup_sport,
                 self.maybe_redir_ip, self.maybe_fixup_srcip])

    def _handle_legacy_packet(self, wdpkt):
        pkt = WindowsPacketCtx('divert_thread', wdpkt)
        cb3, cb4 = self._callbacks()
        self.handle_pkt(pkt, cb3, cb4)
        self._send_packet(pkt)

    def _handle_policy_packet(self, wdpkt):
        raw = wdpkt.raw.tobytes()
        if not raw:
            self.log_egress_event('DROP_EXTERNAL', reason='empty_packet')
            return
        version = (raw[0] & 0xf0) >> 4
        ipv6_verdict = self.classify_ipv6_preparse(
            raw, bool(getattr(wdpkt, 'is_loopback', False)))
        if ipv6_verdict is not None:
            if ipv6_verdict == Verdict.REINJECT_LOCAL:
                self._send_windivert_packet(
                    wdpkt, 'IPv6 loopback reinjection')
            else:
                self.log_egress_event('DROP_EXTERNAL',
                                      reason='external_ipv6')
            return
        if version != 4:
            self.log_egress_event('DROP_EXTERNAL', reason='unknown_ip_version')
            return

        new_mapping_generation = None
        try:
            pkt = WindowsPacketCtx('domain_allowlist', wdpkt)
            self.write_pcap(pkt)
            original = (pkt.proto, pkt.src_ip0, pkt.sport0,
                        pkt.dst_ip0, pkt.dport0)

            if pkt.proto:
                permit = self.egress_policy.match_control_flow(*original)
                if permit:
                    verdict = self.finalize_egress_verdict(
                        pkt, permit=permit)
                    if verdict == Verdict.ALLOW_INTERNAL_UPSTREAM:
                        self.log_egress_event(
                            'ALLOW_INTERNAL_UPSTREAM', kind=permit.kind,
                            ip=pkt.dst_ip0, port=pkt.dport0,
                            sport=pkt.sport0)
                        self._send_packet(pkt)
                    return

            mapping = self.apply_domain_relay_return_fixup(pkt, original)
            if mapping:
                verdict = self.finalize_egress_verdict(
                    pkt, relay_return_fixed=True)
                if verdict != Verdict.REINJECT_LOCAL:
                    self.log_egress_event(
                        'DROP_EXTERNAL', reason='stale_relay_return',
                        original_ip=pkt.dst_ip0,
                        original_port=pkt.dport0)
                    self.egress_policy.close_relay_mapping(
                        mapping.generation)
                    return
                self.write_pcap(pkt)
                if not self._send_packet(pkt):
                    self.egress_policy.close_relay_mapping(
                        mapping.generation)
                return

            redirected = False
            if pkt.proto:
                mapping = self.apply_domain_relay_forward_redirect(
                    pkt, original)
                if mapping:
                    redirected = True
                elif self._is_new_tcp_syn(pkt):
                    mapping, lease = self.redirect_domain_tls_syn(pkt)
                    if mapping:
                        new_mapping_generation = mapping.generation
                        redirected = True
                        self.log_egress_event(
                            'REDIRECT_TLS_RELAY', domain=lease.domain,
                            original_ip=pkt.dst_ip0,
                            relay_port=self.egress_policy.relay_port)

            handled_by_base = False
            if (not redirected and
                    self.egress_policy.non_allowed_action == 'divert'):
                cb3, cb4 = self._callbacks()
                self.handle_pkt(pkt, cb3, cb4,
                                raw_already_captured=True)
                handled_by_base = True

            verdict = self.finalize_egress_verdict(pkt, redirected)
            if verdict == Verdict.DROP_EXTERNAL:
                self.log_egress_event(
                    'DROP_EXTERNAL', reason='no_authorized_route',
                    original_ip=pkt.dst_ip0, original_port=pkt.dport0)
                if mapping:
                    self.egress_policy.close_relay_mapping(
                        mapping.generation)
                return
            if pkt.mangled and not handled_by_base:
                self.write_pcap(pkt)
            if verdict == Verdict.DIVERT_FAKE:
                self.log_egress_event(
                    'DIVERT_FAKE', original_ip=pkt.dst_ip0,
                    original_port=pkt.dport0)
            if not self._send_packet(pkt) and mapping:
                self.egress_policy.close_relay_mapping(mapping.generation)
        except Exception as exc:
            if new_mapping_generation:
                self.egress_policy.close_relay_mapping(
                    new_mapping_generation)
            self.log_egress_event('DROP_EXTERNAL', reason='policy_exception',
                                  error=type(exc).__name__)
            self.logger.exception('DomainAllowList packet failed closed')

    def _is_new_tcp_syn(self, pkt):
        return bool(pkt.proto == 'TCP' and
                    (pkt.hdr.data.flags & dpkt.tcp.TH_SYN) and
                     not (pkt.hdr.data.flags & dpkt.tcp.TH_ACK))

    @staticmethod
    def classify_ipv6_preparse(raw, is_loopback):
        if raw and ((raw[0] & 0xf0) >> 4) == 6:
            return (Verdict.REINJECT_LOCAL if is_loopback else
                    Verdict.DROP_EXTERNAL)
        return None

    def apply_domain_relay_return_fixup(self, pkt, original):
        if not pkt.proto:
            return None
        mapping = self.egress_policy.match_relay_reverse(*original)
        if mapping:
            pkt.src_ip = mapping.server_ip
            pkt.sport = mapping.server_port
        return mapping

    def apply_domain_relay_forward_redirect(self, pkt, original):
        if not pkt.proto:
            return None
        mapping = self.egress_policy.match_relay_forward(*original)
        if mapping:
            pkt.dst_ip = mapping.relay_ip
            pkt.dport = mapping.relay_port
        return mapping

    def redirect_domain_tls_syn(self, pkt):
        lease = self.egress_policy.lease_for(pkt.dst_ip0, pkt.dport0)
        if not lease:
            return None, None
        relay_ip = self.getNewDestinationIp(pkt.src_ip0)
        mapping = self.egress_policy.create_relay_mapping(
            pkt.src_ip0, pkt.sport0, pkt.dst_ip0, pkt.dport0,
            relay_ip, self.egress_policy.relay_port)
        pkt.dst_ip = relay_ip
        pkt.dport = self.egress_policy.relay_port
        return mapping, lease

    def finalize_egress_verdict(self, pkt, relay_redirected=False,
                                permit=None, relay_return_fixed=False):
        if permit is not None:
            return Verdict.ALLOW_INTERNAL_UPSTREAM
        if relay_return_fixed:
            return (Verdict.REINJECT_LOCAL
                    if self.egress_policy.is_exact_local_ipv4(pkt.dst_ip)
                    else Verdict.DROP_EXTERNAL)
        if relay_redirected:
            if (pkt.proto == 'TCP' and
                    pkt.dport == self.egress_policy.relay_port and
                    self.egress_policy.is_exact_local_ipv4(pkt.dst_ip) and
                    self.listener_ports.isListener(pkt.proto, pkt.dport)):
                return Verdict.REDIRECT_TLS_RELAY
            return Verdict.DROP_EXTERNAL
        if (pkt.proto == 'UDP' and pkt.sport == 68 and pkt.dport == 67 and
                pkt.dst_ip == '255.255.255.255'):
            return Verdict.REINJECT_LOCAL
        if self.egress_policy.is_exact_local_ipv4(pkt.dst_ip):
            if pkt.proto and self.listener_ports.isListener(pkt.proto,
                                                            pkt.dport):
                return Verdict.DIVERT_FAKE
            return Verdict.REINJECT_LOCAL
        return Verdict.DROP_EXTERNAL

    def _send_packet(self, pkt):
        if self._send_windivert_packet(pkt.wdpkt, 'packet reinjection'):
            return True
        protocol = pkt.proto or ('ICMP' if pkt.is_icmp else 'Unknown')
        self.logger.error('ERROR: Failed to send %s %s %s packet',
                          self.pktDirectionStr(pkt),
                          self.pktInterfaceStr(pkt), protocol)
        self.logger.error('  %s', pkt.hdrToStr())
        return False

    def _send_windivert_packet(self, wdpkt, description):
        self.setLastErrorNull()
        try:
            self.handle.send(wdpkt)
            return True
        except Exception as exc:
            self.logger.error('ERROR: %s failed: %s', description, exc)
            return False

    def select_source_ipv4(self, target_ip, target_port):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((str(target_ip), int(target_port)))
            source_ip = probe.getsockname()[0]
        finally:
            probe.close()
        if not self.egress_policy.is_exact_local_ipv4(source_ip):
            raise RuntimeError('route selected a non-local source address')
        return source_ip

    def log_egress_event(self, event, **fields):
        now = time.monotonic()
        signature = (event, tuple(sorted(fields.items())))
        if (event == 'DROP_EXTERNAL' or event.endswith('_DENY') or
                event == 'DNS_SERVFAIL'):
            previous = self._drop_log_state.get(signature, 0)
            if now - previous < 1:
                return
            self._drop_log_state[signature] = now
            if len(self._drop_log_state) > 1024:
                self._drop_log_state = {
                    key: stamp for key, stamp in self._drop_log_state.items()
                    if now - stamp < 60}
        suffix = ' '.join('%s=%s' % item for item in sorted(fields.items()))
        self.logger.info('%s%s', event, (' ' + suffix) if suffix else '')

    def _watch_diverter_thread(self):
        self._diverter_exited.wait()
        if not self._stopping.is_set():
            self.logger.critical(
                'WinDivert receiver exited; closing capture and restoring network')
            try:
                self.egress_policy.suspend()
                for listener in reversed(self._policy_listeners):
                    try:
                        listener.stop()
                        listener._policy_stopped = True
                    except Exception:
                        self.logger.exception(
                            'Failed stopping listener after WinDivert exit')
            finally:
                try:
                    self._restore_network_settings()
                except Exception:
                    self.logger.exception(
                        'Network restoration failed after receiver exit')
                finally:
                    if self.handle:
                        self.handle.close()

    def _refresh_local_addresses(self):
        while not self._stopping.wait(5):
            try:
                addresses = set()
                for adapter in self.get_adapters_info():
                    addresses.update(self.get_ipaddresses(adapter))
                if self.external_ip:
                    addresses.add(self.external_ip)
                if not self.egress_policy.update_local_ipv4(addresses):
                    self.logger.critical(
                        'DomainAllowList suspended after unsafe address change')
                    return
                for domain, ip in self.egress_policy.drain_expired_leases():
                    self.log_egress_event(
                        'DNS_LEASE_EXPIRE', domain=domain, ip=ip)
            except Exception:
                self.logger.exception('Failed refreshing local address snapshot')
                self.egress_policy.suspend()
                self.logger.critical(
                    'DomainAllowList suspended after address refresh failure')
                return

    def stopCallback(self):
        self._stopping.set()
        if self.domain_allowlist_mode:
            # Keep capture fail-closed while restoring DNS. Once the original
            # network settings are back, closing WinDivert is the final step.
            if self.egress_policy:
                self.egress_policy.suspend()
            try:
                self._restore_network_settings()
            except Exception:
                self.logger.exception('Network restoration failed during stop')
            finally:
                if self.handle:
                    try:
                        self.handle.close()
                    except Exception:
                        self.logger.exception('Failed closing WinDivert handle')
        elif self.handle:
            try:
                self.handle.close()
            except Exception:
                self.logger.exception('Failed closing WinDivert handle')
        if (getattr(self, 'diverter_thread', None) and
                self.diverter_thread is not threading.current_thread()):
            self.diverter_thread.join(5)
        if (getattr(self, 'address_refresh_thread', None) and
                self.address_refresh_thread is not threading.current_thread()):
            self.address_refresh_thread.join(5)
        if (getattr(self, 'watchdog_thread', None) and
                self.watchdog_thread is not threading.current_thread()):
            self.watchdog_thread.join(5)
        if self.pcap:
            self.pcap.close()
            self.pcap = None
        if not self.domain_allowlist_mode:
            self._restore_network_settings()
        if self.egress_policy:
            self.egress_policy.close()
        return True

    def _restore_network_settings(self):
        with self._network_restore_lock:
            if self._network_restored:
                return
            self._network_restored = True
        # Restore DHCP adapter settings
        for interface_name in self.adapters_dhcp_restore:

            cmd_set_dhcp = ('netsh interface ip set address name="%s" dhcp' %
                            interface_name)

            # Restore DHCP on interface
            try:
                subprocess.check_call(cmd_set_dhcp, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                self.logger.error('Failed to restore DHCP on interface %s.' %
                                  interface_name)
            else:
                self.logger.info('Restored DHCP on interface %s' %
                                 interface_name)

        # Restore DHCP adapter settings
        for interface_name in self.adapters_dns_restore:

            cmd_del_dns = ('netsh interface ip delete dns name="%s" all' %
                           interface_name)
            cmd_set_dns_dhcp = ('netsh interface ip set dns "%s" dhcp' %
                                interface_name)

            # Restore DNS on interface
            try:
                subprocess.check_call(cmd_del_dns, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
                subprocess.check_call(cmd_set_dns_dhcp, shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError as e:
                self.logger.error("Failed to restore DNS on interface %s." %
                                  interface_name)
            else:
                self.logger.info("Restored DNS on interface %s" %
                                 interface_name)

        # Restore DNS server
        if self._dns_modified:
            self.restore_dns_server()
            self._dns_modified = False

        # Restart DNS service
        if self._dns_service_stopped:
            self.start_service_helper('Dnscache')
            self._dns_service_stopped = False

        self.flush_dns()

    def pktInterfaceStr(self, pkt):
        """WinDivert provides is_loopback which Windows Diverter uses to
        display information about the disposition of packets it is
        processing during error and other cases.
        """
        return 'loopback' if pkt.wdpkt.is_loopback else 'external'

    def pktDirectionStr(self, pkt):
        """WinDivert provides is_inbound which Windows Diverter uses to
        display information about the disposition of packets it is
        processing during error and other cases.
        """
        return 'inbound' if pkt.wdpkt.is_inbound else 'outbound'

    def redirIcmpIpUnconditionally(self, crit, pkt):
        """Redirect ICMP to loopback or external IP if necessary.

        On Windows, we can't conveniently use an iptables REDIRECT rule to get
        ICMP packets sent back home for free, so here is some code.
        """
        if (pkt.is_icmp and
                pkt.icmp_id not in self.blacklist_ids["ICMP"] and
                pkt.dst_ip not in [self.loopback_ip, self.external_ip]):
            self.logger.info('Modifying ICMP packet (type %d, code %d):' %
                             (pkt.icmp_type, pkt.icmp_code))
            self.logger.info('  from: %s' % (pkt.hdrToStr()))
            pkt.dst_ip = self.getNewDestinationIp(pkt.src_ip)
            self.logger.info('  to:   %s' % (pkt.hdrToStr()))

        return pkt


def main():

    diverter_config = {'redirectalltraffic': 'no',
                       'defaultlistener': 'DefaultListener',
                       'dumppackets': 'no'}
    listeners_config = {'DefaultListener': {'port': '1337', 'protocol': 'TCP'}}

    diverter = Diverter(diverter_config, listeners_config)
    diverter.start()

    ###########################################################################
    # Run processing
    import time

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        diverter.stop()

    ###########################################################################
    # Run tests
    # TODO

if __name__ == '__main__':
    main()
