# Copyright 2025 Google LLC

import logging

import threading
import netifaces
import socketserver
from dnslib import *

import socket
import ipaddress
import secrets
import struct

from . import *

INDENT = '  '


class DNSListener(object):

    def taste(self, data, dport):

        confidence = 1 if dport == 53 else 0

        try:
            d = DNSRecord.parse(data)
        except:
            return confidence

        return confidence + 2

    def __init__(
            self,
            config={},
            name='DNSListener',
            logging_level=logging.INFO,
            ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)

        self.config = config
        self.local_ip = config.get('ipaddr')
        self.server = None
        self.name = 'DNS'
        self.port = self.config.get('port', 53)
        self.diverterListenerCallbacks = None

        self.logger.debug('Starting...')

        self.logger.debug('Initialized with config:')
        for key, value in config.items():
            self.logger.debug('  %10s: %s', key, value)
        if self.logger.level == logging.INFO:
            self.logger.info('Hiding logs from blacklisted processes')

    def start(self):

        # Start UDP listener  
        if self.config['protocol'].lower() == 'udp':
            self.logger.debug('Starting UDP ...')
            self.server = ThreadedUDPServer((self.local_ip, int(self.config.get('port', 53))), self.config, self.logger, UDPHandler)

        # Start TCP listener
        elif self.config['protocol'].lower() == 'tcp':
            self.logger.debug('Starting TCP ...')
            self.server = ThreadedTCPServer((self.local_ip, int(self.config.get('port', 53))), self.config, self.logger, TCPHandler)

        self.server.nxdomains = int(self.config.get('nxdomains', 0))
        self.server.diverterListenerCallbacks = self.diverterListenerCallbacks

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.debug('Stopping...')
        
        # Stop listener
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def acceptDiverterListenerCallbacks(self, diverterListenerCallbacks):
        self.diverterListenerCallbacks = diverterListenerCallbacks
        if self.server:
            self.server.diverterListenerCallbacks = diverterListenerCallbacks

    def configure_dependencies(self, listeners, diverter,
                               diverterListenerCallbacks):
        self.acceptDiverterListenerCallbacks(diverterListenerCallbacks)


class DNSHandler():
    def log_message(self, log_level, is_process_blacklisted, message, *args):
        """The primary objective of this method is to control the log messages
        generated for requests from blacklisted processes.

        In a case where the DNS server is same as the local machine, the DNS
        requests from a blacklisted process will reach the DNS listener (which
        listens on port 53 locally) nevertheless. As a user may not wish to see
        logs from a blacklisted process, messages are logged with level DEBUG.
        Executing FakeNet in the verbose mode will print these logs.
        """
        if is_process_blacklisted:
            self.server.logger.log(logging.DEBUG, message, *args)
        else:
            self.server.logger.log(log_level, message, *args)
           
    def parse(self, data):
        response = ""
        proto = 'TCP' if self.server.socket_type == socket.SOCK_STREAM else 'UDP'
        callbacks = self.server.diverterListenerCallbacks
        is_process_blacklisted, process_name, pid = callbacks \
            .isProcessBlackListed(proto, sport=self.client_address[1])

        try:
            # Parse data as DNS        
            d = DNSRecord.parse(data)

        except Exception as e:
            self.log_message(logging.ERROR, is_process_blacklisted, 'Error: Invalid DNS Request')
            for line in hexdump_table(data):
                self.log_message(logging.WARNING, is_process_blacklisted, INDENT + line)

        else:                 
            # Only Process DNS Queries
            if QR[d.header.qr] == "QUERY":
                     
                # Gather query parameters
                # NOTE: Do not lowercase qname here, because we want to see
                #       any case request weirdness in the logs.
                qname = str(d.q.qname)
                
                # Chop off the last period
                if qname[-1] == '.': qname = qname[:-1]

                qtype = QTYPE[d.q.qtype]
                self.qname = qname
                self.qtype = qtype

                if process_name is None or pid is None:
                    self.log_message(logging.INFO, is_process_blacklisted,
                                      'Received %s request for domain \'%s\'.',
                                      qtype, qname)
                else:
                    self.log_message(logging.INFO, is_process_blacklisted,
                                     'Received %s request for domain \'%s\' from %s (%s)',
                                     qtype, qname, process_name, pid)

                if callbacks.egressPolicyEnabled():
                    if not callbacks.isLocalAddress(self.client_address[0]):
                        self.log_message(logging.WARNING,
                                         is_process_blacklisted,
                                         'Rejecting non-local DNS client %s',
                                         self.client_address[0])
                        return self._error_response(d, RCODE.REFUSED)
                    allowed_root = callbacks.resolveDnsRule(qname)
                    if allowed_root and qtype == 'A':
                        return self._resolve_allowed_a(
                            d, qname, allowed_root, proto, callbacks)
                    if allowed_root and qtype == 'AAAA':
                        return self._empty_response(d)

                # Create a custom response to the query
                response = DNSRecord(DNSHeader(id=d.header.id, bitmap=d.header.bitmap, qr=1, aa=1, ra=1), q=d.q)

                if qtype == 'A':
                    # Get fake record from the configuration or use the external address
                    fake_record = self.server.config.get('responsea', None)

                    # msftncsi does request ipv6 but we only support v4 for now
                    #TODO integrate into randomized/custom responses. Keep it simple for now.
                    if 'dns.msftncsi.com' in qname:
                        fake_record = '131.107.255.225'

                    # Using socket.gethostbyname(socket.gethostname()) will return
                    # 127.0.1.1 on Ubuntu systems that automatically add this entry
                    # to /etc/hosts at install time or at other times. To produce a
                    # plug-and-play user experience when using FakeNet for Linux,
                    # we can't ask users to maintain /etc/hosts (which may involve
                    # resolveconf or other work). Instead, we will give users a
                    # choice:
                    #
                    #  * Configure a static IP, e.g. 192.0.2.123
                    #    Returns that IP
                    #
                    #  * Set the DNS Listener DNSResponse to "GetHostByName"
                    #    Returns socket.gethostbyname(socket.gethostname())
                    #
                    #  * Set the DNS Listener DNSResponse to "GetFirstNonLoopback"
                    #    Returns the first non-loopback IP in use by the system
                    #
                    # If the DNSResponse setting is omitted, the listener will
                    # default to getting the first non-loopback IPv4 address (for A
                    # records).
                    #
                    # The DNSResponse setting was previously statically set to
                    # 192.0.2.123, which for local scenarios works fine in Windows
                    # standalone use cases because all connections to IP addresses
                    # are redirected by Diverter. Changing the default setting to 
                    #
                    # IPv6 is not yet implemented, but when it is, it will be
                    # necessary to consider how to get similar behavior to

                    if fake_record == 'GetFirstNonLoopback':
                        for iface in netifaces.interfaces():
                            for link in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
                                if 'addr' in link:
                                    addr = link['addr']
                                    if not addr.startswith('127.'):
                                        fake_record = addr
                                        break
                    elif fake_record == 'GetHostByName' or fake_record is None:
                        fake_record = socket.gethostbyname(socket.gethostname())

                    if self.server.nxdomains > 0:
                        self.log_message(logging.INFO, is_process_blacklisted, 'Ignoring query. NXDomains: %d',
                                self.server.nxdomains)
                        self.server.nxdomains -= 1
                    else:
                        self.log_message(logging.DEBUG, is_process_blacklisted, 'Responding with \'%s\'',
                                                 fake_record)
                        response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](fake_record)))

                elif qtype == 'MX':

                    fake_record = self.server.config.get('responsemx', 'mail.evil.com')

                    # dnslib doesn't like trailing dots
                    if fake_record[-1] == ".": fake_record = fake_record[:-1]

                    self.log_message(logging.DEBUG, is_process_blacklisted, 'Responding with \'%s\'',
                                             fake_record)
                    response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](fake_record)))


                elif qtype == 'TXT':

                    fake_record = self.server.config.get('responsetxt', 'FAKENET')

                    self.log_message(logging.DEBUG, is_process_blacklisted, 'Responding with \'%s\'',
                                             fake_record)
                    response.add_answer(RR(qname, getattr(QTYPE,qtype), rdata=RDMAP[qtype](fake_record)))

                response = response.pack()
                
        return response  

    def _empty_response(self, request):
        return DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=0,
                                   ra=1, rd=request.header.rd,
                                   rcode=RCODE.NOERROR), q=request.q).pack()

    def _error_response(self, request, rcode=RCODE.SERVFAIL):
        return DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=0,
                                   ra=1, rd=request.header.rd,
                                   rcode=rcode), q=request.q).pack()

    def _resolve_allowed_a(self, request, qname, allowed_root, proto,
                           callbacks):
        settings = callbacks.getEgressSettings()
        try:
            upstream = self._query_upstream(request, proto, callbacks,
                                            settings)
            return self._validate_and_synthesize(
                request, upstream, qname, allowed_root, callbacks)
        except Exception as exc:
            self.server.logger.warning(
                'Controlled DNS resolution failed for %s: %s', qname, exc)
            callbacks.logEgressEvent('DNS_SERVFAIL', domain=qname,
                                     reason=type(exc).__name__)
            return self._error_response(request)

    def _query_upstream(self, request, client_proto, callbacks, settings):
        upstream_id = secrets.randbelow(65536)
        query = DNSRecord(DNSHeader(id=upstream_id, rd=1), q=request.q).pack()
        response = self._query_upstream_udp(query, callbacks, settings)
        parsed = DNSRecord.parse(response)
        self._validate_upstream_header(parsed, request, upstream_id)
        if parsed.header.tc:
            response = self._query_upstream_tcp(query, callbacks, settings)
            parsed = DNSRecord.parse(response)
            self._validate_upstream_header(parsed, request, upstream_id)
        return parsed

    def _query_upstream_udp(self, query, callbacks, settings):
        target = settings['dns_server']
        source = callbacks.selectSourceIPv4(target, 53)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        token = None
        try:
            sock.settimeout(settings['dns_timeout'])
            sock.bind((source, 0))
            sport = sock.getsockname()[1]
            token = callbacks.registerControlFlow(
                'dns', 'UDP', source, sport, target, 53,
                ttl=settings['dns_timeout'] + 2)
            sock.connect((target, 53))
            sock.send(query)
            response = sock.recv(65535)
            callbacks.logEgressEvent(
                'ALLOW_INTERNAL_UPSTREAM', kind='dns', resolver=target,
                proto='UDP', sport=sport)
            return response
        finally:
            if token:
                callbacks.revokeControlFlow(token)
            sock.close()

    def _query_upstream_tcp(self, query, callbacks, settings):
        target = settings['dns_server']
        source = callbacks.selectSourceIPv4(target, 53)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        token = None
        try:
            sock.settimeout(settings['dns_timeout'])
            sock.bind((source, 0))
            sport = sock.getsockname()[1]
            token = callbacks.registerControlFlow(
                'dns', 'TCP', source, sport, target, 53,
                ttl=settings['dns_timeout'] + 2)
            sock.connect((target, 53))
            sock.sendall(struct.pack('!H', len(query)) + query)
            length = struct.unpack('!H', self._recv_exact(sock, 2))[0]
            if length > 65535:
                raise ValueError('oversized TCP DNS response')
            response = self._recv_exact(sock, length)
            callbacks.logEgressEvent(
                'ALLOW_INTERNAL_UPSTREAM', kind='dns', resolver=target,
                proto='TCP', sport=sport)
            return response
        finally:
            if token:
                callbacks.revokeControlFlow(token)
            sock.close()

    @staticmethod
    def _recv_exact(sock, count):
        chunks = []
        remaining = count
        while remaining:
            chunk = sock.recv(remaining)
            if not chunk:
                raise OSError('unexpected EOF')
            chunks.append(chunk)
            remaining -= len(chunk)
        return b''.join(chunks)

    @staticmethod
    def _norm_name(value):
        return str(value).rstrip('.').encode('idna').decode('ascii').lower()

    def _validate_upstream_header(self, response, request, upstream_id):
        if response.header.id != upstream_id or response.header.qr != 1:
            raise ValueError('upstream DNS transaction mismatch')
        if response.header.rcode != RCODE.NOERROR:
            raise ValueError('upstream DNS returned an error')
        if len(response.questions) != 1:
            raise ValueError('upstream DNS question count mismatch')
        question = response.questions[0]
        if (self._norm_name(question.qname) != self._norm_name(request.q.qname)
                or question.qtype != QTYPE.A):
            raise ValueError('upstream DNS question mismatch')

    def _validate_and_synthesize(self, request, upstream, qname,
                                 allowed_root, callbacks):
        cnames = {}
        addresses = {}
        for rr in upstream.auth + upstream.ar:
            if rr.rtype in (QTYPE.A, QTYPE.CNAME):
                raise ValueError('address injection outside answer section')
        for rr in upstream.rr:
            owner = self._norm_name(rr.rname)
            if rr.rtype == QTYPE.CNAME:
                if owner in cnames:
                    raise ValueError('multiple CNAME records for one owner')
                cnames[owner] = (self._norm_name(rr.rdata.label), int(rr.ttl))
            elif rr.rtype == QTYPE.A:
                addresses.setdefault(owner, []).append((str(rr.rdata),
                                                        int(rr.ttl)))
            else:
                raise ValueError('unexpected answer type')

        current = self._norm_name(qname)
        visited = set()
        chain = []
        chain_ttls = []
        while current in cnames:
            if current in visited or len(visited) >= 16:
                raise ValueError('CNAME loop or excessive chain')
            visited.add(current)
            target, ttl = cnames[current]
            chain.append((current, target, ttl))
            chain_ttls.append(ttl)
            current = target

        relevant = visited.union([current])
        if any(owner not in relevant for owner in cnames) or any(
                owner != current for owner in addresses):
            raise ValueError('unrelated DNS answer owner')

        response = DNSRecord(DNSHeader(
            id=request.header.id, qr=1, aa=0, ra=1,
            rd=request.header.rd, rcode=RCODE.NOERROR), q=request.q)
        for owner, target, ttl in chain:
            response.add_answer(RR(owner, QTYPE.CNAME, ttl=ttl,
                                   rdata=CNAME(target)))

        records = []
        for address, ttl in addresses.get(current, []):
            ip = ipaddress.ip_address(address)
            if ip.version != 4 or not ip.is_global:
                raise ValueError('upstream returned non-global IPv4')
            effective_ttl = min(chain_ttls + [ttl])
            if effective_ttl <= 0:
                continue
            records.append((address, effective_ttl))
            response.add_answer(RR(current, QTYPE.A, ttl=effective_ttl,
                                   rdata=A(address)))

        if records:
            installed = callbacks.replaceDnsLeases(allowed_root, records)
            for address in installed:
                ttl = next(ttl for ip, ttl in records if ip == address)
                callbacks.logEgressEvent(
                    'DNS_LEASE_ADD', domain=allowed_root, ip=address,
                    ttl=ttl)
        elif addresses.get(current):
            raise ValueError('upstream answer has no positive-TTL A record')
        elif chain:
            ttl = min(chain_ttls)
            if ttl > 0:
                callbacks.registerDnsAlias(allowed_root, current, ttl)
        else:
            raise ValueError('upstream answer has no CNAME or A record')
        return response.pack()

class UDPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):

        try:
            (data,sk) = self.request
            response = self.parse(data)

            # Collect NBI
            nbi = {
                'Query Type': self.qtype,
                'Domain': self.qname
                }
            collect_nbi(self.client_address[1], nbi, 'UDP', 'No',
                        self.server.diverterListenerCallbacks)

            if response:
                sk.sendto(response, self.client_address)

        except socket.error as msg:
            self.server.logger.error('Error: %s', msg.strerror or msg)

        except Exception as e:
            self.server.logger.error('Error: %s', e)

class TCPHandler(DNSHandler, socketserver.BaseRequestHandler):

    def handle(self):

        # Timeout connection to prevent hanging
        self.request.settimeout(int(self.server.config.get('timeout', 5)))

        try:
            length = struct.unpack('!H', self._recv_exact(self.request, 2))[0]
            data = self._recv_exact(self.request, length)
            response = self.parse(data)

            # Collect NBI
            nbi = {
                'Query Type': self.qtype,
                'Domain': self.qname
                }
            collect_nbi(self.client_address[1], nbi, 'TCP',
                        self.server.config.get('usessl'),
                        self.server.diverterListenerCallbacks)
            
            if response:
                # Calculate and add the additional "length" parameter
                # used in TCP DNS protocol 
                length = binascii.unhexlify("%04x" % len(response))            
                self.request.sendall(length+response)      

        except socket.timeout:
            self.server.logger.warning('Connection timeout.')

        except socket.error as msg:
            self.server.logger.error('Error: %s', msg.strerror)

        except Exception as e:
            self.server.logger.error('Error: %s', e)

class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):

    # Override SocketServer.UDPServer to add extra parameters
    def __init__(self, server_address, config, logger, RequestHandlerClass):
        self.config = config
        self.logger = logger
        socketserver.UDPServer.__init__(self, server_address, RequestHandlerClass)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    
    # Override default value
    allow_reuse_address = True

    # Override SocketServer.TCPServer to add extra parameters
    def __init__(self, server_address, config, logger, RequestHandlerClass):
        self.config = config
        self.logger = logger
        socketserver.TCPServer.__init__(self,server_address,RequestHandlerClass)

def hexdump_table(data, length=16):

    hexdump_lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_line   = ' '.join(["%02X" % ord(b) for b in chunk ] )
        ascii_line = ''.join([b if ord(b) > 31 and ord(b) < 127 else '.' for b in chunk ] )
        hexdump_lines.append("%04X: %-*s %s" % (i, length*3, hex_line, ascii_line ))
    return hexdump_lines

def collect_nbi(sport, nbi, proto, is_ssl_encrypted, diverterListenerCallbacks):
    # Report diverter everytime we capture an NBI
    diverterListenerCallbacks.logNbi(sport, nbi, proto, 'DNS', is_ssl_encrypted)


###############################################################################
# Testing code
def test(config):

    print("\t[DNSListener] Testing 'google.com' A record.")
    query = DNSRecord(q=DNSQuestion('google.com',getattr(QTYPE,'A')))
    answer_pkt = query.send('localhost', int(config.get('port', 53)))
    answer = DNSRecord.parse(answer_pkt)

    print('-'*80)
    print(answer)
    print('-'*80)

    print("\t[DNSListener] Testing 'google.com' MX record.")
    query = DNSRecord(q=DNSQuestion('google.com',getattr(QTYPE,'MX')))
    answer_pkt = query.send('localhost', int(config.get('port', 53)))
    answer = DNSRecord.parse(answer_pkt)

    print('-'*80)
    print(answer)

    print("\t[DNSListener] Testing 'google.com' TXT record.")
    query = DNSRecord(q=DNSQuestion('google.com',getattr(QTYPE,'TXT')))
    answer_pkt = query.send('localhost', int(config.get('port', 53)))
    answer = DNSRecord.parse(answer_pkt)

    print('-'*80)
    print(answer)
    print('-'*80)

def main():
    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)
    
    config = {'port': '53', 'protocol': 'UDP', 'responsea': '127.0.0.1', 'responsemx': 'mail.bad.com', 'responsetxt': 'FAKENET', 'nxdomains': 3 }

    listener = DNSListener(config, logging_level = logging.DEBUG)
    listener.start()


    ###########################################################################
    # Run processing
    import time

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    ###########################################################################
    # Run tests
    test(config)

if __name__ == '__main__':
    main()
