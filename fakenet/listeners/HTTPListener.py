# Copyright 2026 Google LLC

import logging
from configparser import ConfigParser

import os
import sys
import importlib.util
import importlib.machinery

import threading
import socketserver
import http.server
import io
import select

import ssl
import socket

import posixpath
import mimetypes

import time

from .ssl_utils import SSLWrapper
from . import *

MIME_FILE_RESPONSE = {
    'text/html':    'FakeNet.html',
    'image/png':    'FakeNet.png',
    'image/ico':    'FakeNet.ico',
    'image/jpeg':   'FakeNet.jpg',
    'application/octet-stream': 'FakeNetMini.exe',
    'application/x-msdownload': 'FakeNetMini.exe',
    'application/x-msdos-program': 'FakeNetMini.exe',
    'application/pdf': 'FakeNet.pdf',
    'application/xml': 'FakeNet.html'
}

INDENT = '  '


def qualify_file_path(filename, fallbackdir):
    path = filename
    if path:
        if not os.path.exists(path):
            path = os.path.join(fallbackdir, filename)
        if not os.path.exists(path):
            raise RuntimeError('Cannot find %s' % (filename))

    return path

def load_source(modname, filename):
    # Reference: https://docs.python.org/3/whatsnew/3.12.html#imp
    loader = importlib.machinery.SourceFileLoader(modname, filename)
    spec = importlib.util.spec_from_file_location(modname, filename, loader=loader)
    module = importlib.util.module_from_spec(spec)
    # The module is always executed and not cached in sys.modules.
    # Uncomment the following line to cache the module.
    # sys.modules[module.__name__] = module
    loader.exec_module(module)
    return module


class CustomResponse(object):
    def __init__(self, name, conf, configroot):
        self.name = name

        match_specs = {'httpuris', 'httphosts'}
        response_specs = {'httprawfile', 'httpstaticstring', 'httpdynamic'}

        if not match_specs.intersection(conf):
            raise ValueError('Custom HTTP config section %s lacks '
                             '%s' % (name, '/'.join(match_specs)))

        nr_responses = len(response_specs.intersection(conf))
        if nr_responses != 1:
            raise ValueError('Custom HTTP config section %s has %d of %s' %
                             (name, nr_responses, '/'.join(response_specs)))

        if ('contenttype' in conf) and ('httpstaticstring' not in conf):
            raise ValueError('Custom HTTP config section %s has ContentType '
                             'which is only usable with '
                             'HttpStaticString' % (name))

        self.uris = conf.get('httpuris', {})
        if self.uris:
            self.uris = {u.strip() for u in self.uris.split(',')}

        self.hosts = conf.get('httphosts', {})
        if self.hosts:
            self.hosts = {h.strip().lower() for h in self.hosts.split(',')}

        self.raw_file = qualify_file_path(conf.get('httprawfile'), configroot)
        if self.raw_file:
            self.raw_file = open(self.raw_file, 'rb').read()

        self.handler = None
        pymod_path = qualify_file_path(conf.get('httpdynamic'), configroot)
        if pymod_path:
            pymod = load_source('cr_' + self.name, pymod_path)
            funcname = 'HandleHttp'
            funcname_legacy = 'HandleRequest'
            if hasattr(pymod, funcname):
                self.handler = getattr(pymod, funcname)
            elif hasattr(pymod, funcname_legacy):
                self.handler = getattr(pymod, funcname_legacy)
            else:
                raise ValueError('Loaded %s module %s has no function %s' %
                                 ('httpdynamic', conf.get('httpdynamic'),
                                  funcname))

        self.static_string = conf.get('httpstaticstring')
        if self.static_string is not None:
            self.static_string = self.static_string.replace('\\r\\n', '\r\n')
        self.content_type = conf.get('ContentType')

    def checkMatch(self, host, uri):
        hostmatch = (host.strip().lower() in self.hosts)
        if (not hostmatch) and (':' in host):
            host = host[:host.find(':')]
            hostmatch = (host.strip().lower() in self.hosts)


        urimatch = False
        for match_uri in self.uris:
            if uri.endswith(match_uri):
                urimatch = True
                break

        # Conjunctive (logical and) evaluation if both are specified
        if self.uris and self.hosts:
            return hostmatch and urimatch
        else:
            return hostmatch or urimatch

    def respond(self, req, meth, postdata=None):
        current_time = req.date_time_string()
        if self.raw_file:
            up_to_date = self.raw_file.replace(b'<RAW-DATE>', current_time.encode("utf-8"))
            req.wfile.write(up_to_date)
        elif self.handler:
            self.handler(req, meth, postdata)
        elif self.static_string is not None:
            up_to_date = self.static_string.replace('<RAW-DATE>', current_time)
            req.send_response(200)
            req.send_header('Content-Length', len(up_to_date))
            if self.content_type:
                req.send_header('Content-Type', self.content_type)
            req.end_headers()
            req.wfile.write(up_to_date.encode("utf-8"))


class HTTPListener(object):

    def taste(self, data, dport):

        request_methods = [b'GET', b'HEAD', b'POST', b'PUT', b'DELETE', b'TRACE',
            b'OPTIONS', b'CONNECT', b'PATCH']

        confidence = 1 if dport in [80, 443] else 0

        for method in request_methods:
            if data.lstrip().startswith(method):
                confidence += 2
                continue

        return confidence

    if not mimetypes.inited:
        mimetypes.init() # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'text/html', # Default
        })

    def __init__(
            self,
            config={},
            name='HTTPListener',
            logging_level=logging.DEBUG,
            ):

        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging_level)

        self.config = config
        self.name = name
        self.local_ip = config.get('ipaddr')
        self.server = None
        self.diverterListenerCallbacks = None
        self.port = self.config.get('port', 80)
        self.sslwrapper = None

        self.logger.debug('Initialized with config:')
        for key, value in config.items():
            self.logger.debug('  %10s: %s', key, value)

        # Initialize webroot directory
        path = self.config.get('webroot','defaultFiles')
        self.webroot_path = ListenerBase.abs_config_path(path)
        if self.webroot_path is None:
            self.logger.error('Could not locate webroot directory: %s', path)
            sys.exit(1)

    def start(self):
        self.logger.debug('Starting...')

        self.server = ThreadedHTTPServer((self.local_ip,
            int(self.config.get('port'))), ThreadedHTTPRequestHandler)
        self.server.logger = self.logger
        self.server.config = self.config
        self.server.webroot_path = self.webroot_path
        self.server.extensions_map = self.extensions_map

        if self.config.get('usessl') == 'Yes':
            self.logger.debug("HTTP Listener starting with SSL")
            config = {
                'cert_dir': self.config.get('cert_dir', os.path.join('configs', 'temp_certs')),
                'networkmode': self.config.get('networkmode', None),
                'static_ca': self.config.get('static_ca', 'No'),
                'ca_cert': self.config.get('ca_cert'),
                'ca_key': self.config.get('ca_key'),
                'webroot': self.webroot_path
            }
            self.sslwrapper = SSLWrapper(config)
            self.server.sslwrapper = self.sslwrapper
            self.server.socket = self.server.sslwrapper.wrap_socket(
                self.server.socket)

        self.server.custom_responses = []
        custom = self.config.get('custom')

        def checkSetting(d, name, value):
            if name not in d:
                return False
            return d[name].lower() == value.lower()

        if custom:
            configdir = self.config.get('configdir')
            custom = qualify_file_path(custom, configdir)
            customconf = ConfigParser()
            customconf.read(custom)

            for section in customconf.sections():
                entries = dict(customconf.items(section))

                if (('instancename' not in entries) and
                        ('listenertype' not in entries)):
                    msg = 'Custom Response lacks ListenerType or InstanceName'
                    raise RuntimeError(msg)

                if (checkSetting(entries, 'instancename', self.name) or
                        checkSetting(entries, 'listenertype', 'HTTP')):
                    cr = CustomResponse(section, entries, configdir)
                    self.server.custom_responses.append(cr)

        self.server.diverterListenerCallbacks = self.diverterListenerCallbacks
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop(self):
        self.logger.debug('Stopping...')
        if self.server:
            server = self.server
            step_started = time.monotonic()
            wake_result = server.begin_shutdown()
            self.logger.info(
                'HTTP_STOP_WAKE active_before=%s result=%s',
                wake_result['active_before'], wake_result['result'])
            self.logger.info(
                'HTTP_STOP_STEP step=begin_shutdown elapsed_ms=%d',
                int((time.monotonic() - step_started) * 1000))

            step_started = time.monotonic()
            transport_result = server.close_active_transport()
            self.logger.info(
                'HTTP_STOP_TRANSPORT active=%s fileno=%s timeout=%s '
                'shutdown=%s close=%s',
                transport_result['active'], transport_result['fileno'],
                transport_result['timeout'], transport_result['shutdown'],
                transport_result['close'])
            self.logger.info(
                'HTTP_STOP_STEP step=transport elapsed_ms=%d',
                int((time.monotonic() - step_started) * 1000))

            step_started = time.monotonic()
            server.shutdown()
            self.logger.info(
                'HTTP_STOP_STEP step=server_shutdown elapsed_ms=%d',
                int((time.monotonic() - step_started) * 1000))

            step_started = time.monotonic()
            server.server_close()
            self.logger.info(
                'HTTP_STOP_STEP step=server_close elapsed_ms=%d',
                int((time.monotonic() - step_started) * 1000))

            step_started = time.monotonic()
            if self.server_thread:
                self.server_thread.join()
            self.logger.info(
                'HTTP_STOP_STEP step=server_thread_join elapsed_ms=%d',
                int((time.monotonic() - step_started) * 1000))
            self.server = None
            self.server_thread = None

    def acceptDiverterListenerCallbacks(self, diverterListenerCallbacks):
        self.diverterListenerCallbacks = diverterListenerCallbacks
        if self.server:
            self.server.diverterListenerCallbacks = diverterListenerCallbacks

    def configure_dependencies(self, listeners, diverter, callbacks):
        self.acceptDiverterListenerCallbacks(callbacks)


class _StopAwareSocketReader(io.RawIOBase):

    def __init__(self, transport, stop_reader, stop_event):
        super(_StopAwareSocketReader, self).__init__()
        self._transport = transport
        self._stop_reader = stop_reader
        self._stop_event = stop_event

    def readable(self):
        return True

    def readinto(self, buffer):
        if self._stop_event.is_set():
            raise OSError('HTTP server is stopping')
        if isinstance(self._transport, ssl.SSLSocket) and \
                self._transport.pending():
            return self._transport.recv_into(buffer)
        timeout = self._transport.gettimeout()
        try:
            readable, _unused_write, _unused_error = select.select(
                [self._transport, self._stop_reader], [], [], timeout)
        except (OSError, ValueError):
            if self._stop_event.is_set():
                raise OSError('HTTP server is stopping')
            raise
        if self._stop_reader in readable:
            raise OSError('HTTP server is stopping')
        if self._transport not in readable:
            raise socket.timeout('timed out')
        return self._transport.recv_into(buffer)


class ThreadedHTTPServer(http.server.HTTPServer):

    def __init__(self, *args, **kwargs):
        self._transport_lock = threading.Lock()
        self._active_transport = None
        self._stopping = False
        self._stop_event = threading.Event()
        super(ThreadedHTTPServer, self).__init__(*args, **kwargs)
        self._stop_reader, self._stop_writer = socket.socketpair()

    def begin_shutdown(self):
        with self._transport_lock:
            already_stopping = self._stopping
            active_before = self._active_transport is not None
            self._stopping = True
            self._stop_event.set()
        if already_stopping:
            return {
                'active_before': active_before,
                'result': 'already-signaled',
            }
        try:
            self._stop_writer.sendall(b'\x00')
        except OSError as exc:
            result = self._format_stop_socket_error(exc)
        else:
            result = 'signaled'
        return {'active_before': active_before, 'result': result}

    def _register_transport(self, transport):
        with self._transport_lock:
            if self._stopping:
                return False
            self._active_transport = transport
            return True

    def _clear_transport(self, transport):
        with self._transport_lock:
            if self._active_transport is transport:
                self._active_transport = None

    def close_active_transport(self):
        with self._transport_lock:
            transport = self._active_transport
            self._active_transport = None
        if transport is None:
            return {
                'active': False,
                'fileno': '-',
                'timeout': '-',
                'shutdown': 'not-run',
                'close': 'not-run',
            }
        try:
            fileno = transport.fileno()
        except (OSError, ValueError):
            fileno = 'unavailable'
        try:
            timeout = transport.gettimeout()
        except (OSError, ValueError):
            timeout = 'unavailable'
        shutdown_result = 'ok'
        try:
            transport.shutdown(socket.SHUT_RDWR)
        except OSError as exc:
            shutdown_result = self._format_stop_socket_error(exc)
        close_result = 'ok'
        try:
            transport.close()
        except OSError as exc:
            close_result = self._format_stop_socket_error(exc)
        return {
            'active': True,
            'fileno': fileno,
            'timeout': timeout,
            'shutdown': shutdown_result,
            'close': close_result,
        }

    @staticmethod
    def _format_stop_socket_error(exc):
        return '%s(errno=%s,winerror=%s)' % (
            type(exc).__name__, getattr(exc, 'errno', None),
            getattr(exc, 'winerror', None))

    def get_request(self):
        request, client_address = super(ThreadedHTTPServer, self).get_request()
        if not self._register_transport(request):
            request.close()
            raise OSError('HTTP server is stopping')
        try:
            if isinstance(request, ssl.SSLSocket):
                request.do_handshake()
        except Exception:
            self._clear_transport(request)
            request.close()
            raise
        return request, client_address

    def shutdown_request(self, request):
        self._clear_transport(request)
        super(ThreadedHTTPServer, self).shutdown_request(request)

    def server_close(self):
        try:
            super(ThreadedHTTPServer, self).server_close()
        finally:
            for control_socket in (self._stop_reader, self._stop_writer):
                try:
                    control_socket.close()
                except OSError:
                    pass

    def handle_error(self, request, client_address):
        exctype, value = sys.exc_info()[:2]
        with self._transport_lock:
            stopping = self._stopping
        expected = (exctype is not None and
                    issubclass(exctype, (OSError, ssl.SSLError)))
        if stopping and expected:
            self.logger.debug('HTTP request interrupted during stop: %s',
                              value)
            return
        self.logger.error('Error: %s', value, exc_info=sys.exc_info())

class ThreadedHTTPRequestHandler(http.server.BaseHTTPRequestHandler):

    def __init__(self, *args):
        http.server.BaseHTTPRequestHandler.__init__(self, *args)
        self.logger = self.server.logger

    def version_string(self):
        return self.server.config.get('version', "FakeNet/1.3")

    def setup(self):
        self.request.settimeout(int(self.server.config.get('timeout', 10)))
        http.server.BaseHTTPRequestHandler.setup(self)
        self.rfile.close()
        self.rfile = io.BufferedReader(_StopAwareSocketReader(
            self.connection, self.server._stop_reader,
            self.server._stop_event))

    def doCustomResponse(self, meth, post_data=None):
        uri = self.path
        host = self.headers.get('host', '')

        for cr in self.server.custom_responses:
            if cr.checkMatch(host, uri):
                self.server.logger.debug('Invoking custom response %s' % (cr.name))
                cr.respond(self, meth, post_data)
                return True

        return False

    def do_HEAD(self):
        # Log request
        self.server.logger.info(INDENT + self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(INDENT + line)

        # collect nbi
        self.collect_nbi(self.requestline, self.headers)

        # Prepare response
        if not self.doCustomResponse('HEAD'):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

    def do_GET(self):
        # Log request
        self.server.logger.info(INDENT + self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(INDENT + line)

        # collect nbi
        self.collect_nbi(self.requestline, self.headers)

        # Prepare response
        if not self.doCustomResponse('GET'):
            # Get response type based on the requested path
            response, response_type = self.get_response(self.path)

            # Prepare response
            self.send_response(200)
            self.send_header("Content-Type", response_type)
            self.send_header("Content-Length", len(response))
            self.end_headers()

            self.wfile.write(response)

    def do_POST(self):
        post_body = b''

        content_len = int(self.headers.get('content-length', 0))
        post_body = self.rfile.read(content_len)

        # Log request
        self.server.logger.info(INDENT + self.requestline)
        for line in str(self.headers).split("\n"):
            self.server.logger.info(INDENT + line)
        for line in post_body.split(b"\n"):
            self.server.logger.info(INDENT.encode('utf-8') + line)

        # collect nbi
        self.collect_nbi(self.requestline, self.headers, post_body)

        # Store HTTP Posts
        if self.server.config.get('dumphttpposts') and self.server.config['dumphttpposts'].lower() == 'yes':
                http_filename = "%s_%s.txt" % (self.server.config.get('dumphttppostsfileprefix', 'http'), time.strftime("%Y%m%d_%H%M%S"))

                self.server.logger.info('Storing HTTP POST headers and data to %s.', http_filename)
                http_f = open(http_filename, 'wb')

                if http_f:
                    http_f.write(self.requestline.encode('utf-8') + b"\r\n")
                    http_f.write(str(self.headers).encode('utf-8') + b"\r\n")
                    http_f.write(post_body)

                    http_f.close()
                else:
                    self.server.logger.error('Failed to write HTTP POST headers and data to %s.', http_filename)

        # Prepare response
        if not self.doCustomResponse('GET', post_body):
            # Get response type based on the requested path
            response, response_type = self.get_response(self.path)

            # Prepare response
            self.send_response(200)
            self.send_header("Content-Type", response_type)
            self.send_header("Content-Length", len(response))
            self.end_headers()

            self.wfile.write(response)
    
    def collect_nbi(self, requestline, headers, post_data=None):
        nbi = {}
        method, uri, version = requestline.split(" ")
        nbi["Method"] = method
        nbi["URI"] = uri
        nbi["Version"] = version

        for line in str(headers).rstrip().split("\n"):
            key, _, value = line.partition(":")
            nbi[key] = value.lstrip()

        if post_data:
            nbi["Request Body"] = post_data

        # report diverter everytime we capture an NBI
        self.server.diverterListenerCallbacks.logNbi(self.client_address[1],
                nbi, 'TCP', 'HTTP', self.server.config.get('usessl'))

    def get_response(self, path):
        response = "<html><head><title>FakeNet</title><body><h1>FakeNet</h1></body></html>"
        response_type = 'text/html'

        if path[-1] == '/':
            response_type = 'text/html'
            path += 'index.html'
        else:
            _, ext = posixpath.splitext(path)
            response_type = self.server.extensions_map.get(ext, 'text/html')

        # Do after checking for trailing '/' since normpath removes it
        response_filename = ListenerBase.safe_join(self.server.webroot_path, path)

        # Check the requested path exists
        if not os.path.exists(response_filename):

            self.server.logger.debug('Could not find path: %s', response_filename)

            # Try default MIME file
            response_filename = os.path.join(self.server.webroot_path, MIME_FILE_RESPONSE.get(response_type, 'FakeNet.html'))

            # Check default MIME file exists
            if not os.path.exists(response_filename):
                self.server.logger.debug('Could not find path: %s', response_filename)
                self.server.logger.error('Could not locate requested file or default handler.')
                return (response, response_type)

        self.server.logger.debug('Responding with mime type: %s file: %s',
                                 response_type, response_filename)

        try:
            f = open(response_filename, 'rb')
        except Exception as e:
            self.server.logger.error('Failed to open response file: %s', response_filename)
            response_type = 'text/html'
        else:
            response = f.read()
            f.close()

        return (response, response_type)

    def log_message(self, format, *args):
        return


###############################################################################
# Testing code
def test(config):

    import requests

    url = "%s://localhost:%s" % ('http' if config.get('usessl') == 'No' else 'https', int(config.get('port', 8080)))

    print("\t[HTTPListener] Testing HEAD request.")
    print('-'*80)
    print(requests.head(url, verify=False, stream=True).text)
    print('-'*80)

    print("\t[HTTPListener] Testing GET request.")
    print('-'*80)
    print(requests.get(url, verify=False, stream=True).text)
    print('-'*80)

    print("\t[HTTPListener] Testing POST request.")
    print('-'*80)
    print(requests.post(url, {'param1':'A'*80, 'param2':'B'*80}, verify=False, stream=True).text)
    print('-'*80)

def main():
    """
    Run from the flare-fakenet-ng root dir with the following command:

       python2 -m fakenet.listeners.HTTPListener

    """
    logging.basicConfig(format='%(asctime)s [%(name)15s] %(message)s', datefmt='%m/%d/%y %I:%M:%S %p', level=logging.DEBUG)

    config = {'port': '8443', 'usessl': 'Yes', 'webroot': 'fakenet/defaultFiles' }

    listener = HTTPListener(config)
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
