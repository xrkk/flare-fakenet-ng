# Copyright 2025 Google LLC

#!/usr/bin/env python
#
# FakeNet-NG is a next generation dynamic network analysis tool for malware
# analysts and penetration testers.
#
# Original developer: Peter Kacherginsky
# Current developer: Mandiant FLARE Team (FakeNet@mandiant.com)

import datetime
import logging
import logging.handlers
import os
import sys
import time
import netifaces
import threading
import traceback

from collections import OrderedDict

from optparse import OptionParser,OptionGroup
from configparser import ConfigParser

import platform

from optparse import OptionParser
from collections import namedtuple

###############################################################################
# Listener services
from fakenet import listeners
from fakenet.listeners import *


def _runtime_directory():
    """Directory beside fakenet.exe, or the equivalent source repo root."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _reserve_default_log_path(now=None, pid=None):
    now = now or datetime.datetime.now()
    pid = pid if pid is not None else os.getpid()
    directory = os.path.join(_runtime_directory(), 'Logs')
    os.makedirs(directory, exist_ok=True)
    stem = 'fakenet-%s-p%d' % (now.strftime('%Y%m%d-%H%M%S-%f'), pid)
    for number in range(1000):
        suffix = '' if number == 0 else '-%d' % number
        path = os.path.join(directory, stem + suffix + '.log')
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            continue
        os.close(descriptor)
        return path
    raise OSError('Could not allocate a unique FakeNet-NG log filename')


def _requested_log_file(argv=None):
    """Read only the existing -l option before OptionParser may exit."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    for index, argument in enumerate(arguments):
        if argument == '--':
            break
        if argument in ('-l', '--log-file'):
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if argument.startswith('--log-file='):
            return argument.split('=', 1)[1]
        if argument.startswith('-l') and len(argument) > 2:
            return argument[2:]
    return None


def _configure_startup_logging(log_file=None, level=logging.INFO,
                               console=False):
    """Install exactly one UTF-8 file handler for this FakeNet process."""
    reserved = not log_file
    path = os.path.abspath(log_file) if log_file else \
        _reserve_default_log_path()
    try:
        file_handler = logging.FileHandler(path, mode='a', encoding='utf-8')
    except BaseException:
        if reserved:
            try:
                os.remove(path)
            except OSError:
                pass
        raise

    date_format = '%m/%d/%y %I:%M:%S %p'
    file_handler.setLevel(level)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)-8s] [%(name)18s] '
        'pid=%(process)d thread=%(threadName)s %(message)s',
        datefmt=date_format))
    root_logger = logging.getLogger('')
    root_logger.handlers = []
    root_logger.setLevel(level)
    root_logger.addHandler(file_handler)
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(name)18s] %(message)s', datefmt=date_format))
        root_logger.addHandler(console_handler)
    root_logger.info(
        'FakeNet-NG startup: log=%s executable=%s frozen=%s cwd=%s argv=%r',
        path, sys.executable, bool(getattr(sys, 'frozen', False)),
        os.getcwd(), sys.argv)
    return root_logger, path

###############################################################################
# FakeNet
###############################################################################

class Fakenet(object):

    def __init__(self, logging_level = logging.INFO):

        self.logger = logging.getLogger('FakeNet')
        self.logger.setLevel(logging_level)

        self.logging_level = logging_level

        # Diverter used to intercept and redirect traffic
        self.diverter = None
        self.policy_mode = False

        # FakeNet options and parameters
        self.fakenet_config_dir = ''
        self.fakenet_config = dict()

        # Diverter options and parameters
        self.diverter_config = dict()

        # Listener options and parameters
        self.listeners_config = OrderedDict()

        # List of running listener providers
        self.running_listener_providers = list()

        self._stop_lock = threading.Lock()
        self._stop_complete = threading.Event()
        self._stop_started = False
        self._stop_result = None
        self._stop_error = None

    def parse_config(self, config_filename):
        # Handling Pyinstaller bundle scenario: https://pyinstaller.org/en/stable/runtime-information.html
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            dir_path = os.path.dirname(sys.executable)
        else:
            dir_path = os.path.dirname(__file__)

        if not config_filename:

            config_filename = os.path.join(dir_path, 'configs', 'default.ini')

        if not os.path.exists(config_filename):

            config_filename = os.path.join(dir_path, 'configs', config_filename)

            if not os.path.exists(config_filename):

                self.logger.critical('Could not open configuration file %s',
                                     config_filename)
                sys.exit(1)

        self.fakenet_config_dir = os.path.dirname(config_filename)
        config = ConfigParser()
        config.read(config_filename)

        self.logger.info('Loaded configuration file: %s', config_filename)

        # Parse configuration
        for section in config.sections():

            if section == 'FakeNet':
                self.fakenet_config = dict(config.items(section))

            elif section == 'Diverter':
                self.diverter_config = dict(config.items(section))

            elif config.getboolean(section, 'enabled'):
                self.listeners_config[section] = dict(config.items(section))


        # Expand listeners
        self.listeners_config = self.expand_listeners(self.listeners_config)

    def expand_ports(self, ports_list):
        ports = []
        for i in ports_list.split(','):
            if '-' not in i:
                ports.append(int(i))
            else:
                l,h = list(map(int, i.split('-')))
                ports+= list(range(l,h+1))
        return ports

    def expand_listeners(self, listeners_config):

        listeners_config_expanded = OrderedDict()

        for listener_name in listeners_config:

            listener_config = self.listeners_config[listener_name]
            ports = self.expand_ports(listener_config['port'])

            if len(ports) > 1:

                for port in ports:

                    listener_config['port'] = port
                    listeners_config_expanded["%s_%d" % (listener_name, port)] = listener_config.copy()

            else:
                listeners_config_expanded[listener_name] = listener_config

        return listeners_config_expanded

    def start(self):

        self.policy_mode = (str(self.diverter_config.get(
            'externalaccesspolicy', 'disabled')).lower() ==
            'domainallowlist')
        if self.policy_mode and platform.system() != 'Windows':
            raise RuntimeError(
                'EgressControl is implemented only for Windows')
        if (self.policy_mode and str(self.fakenet_config.get(
                'diverttraffic', 'no')).lower() != 'yes'):
            raise RuntimeError(
                'EgressControl requires DivertTraffic=Yes')

        fn_addr = '0.0.0.0'
        if self.fakenet_config.get('diverttraffic') and self.fakenet_config['diverttraffic'].lower() == 'yes':

            if (('networkmode' not in self.diverter_config) or
                    (self.diverter_config['networkmode'].lower() not in
                     ['singlehost', 'multihost', 'auto'])):
                self.logger.critical('Error: You must configure a ' +
                                     'NetworkMode for Diverter, either ' +
                                     'SingleHost, MultiHost, or Auto')
                sys.exit(1)

            # Select platform specific diverter
            platform_name = platform.system()

            iface_ip_info = IfaceIpInfo()

            ip_addrs = dict()
            ip_addrs[4] = iface_ip_info.get_ips([4])
            ip_addrs[6] = iface_ip_info.get_ips([6])

            if platform_name == 'Windows':

                # Check Windows version
                if platform.release() in ['2000', 'XP', '2003Server', 'post2003']:
                    self.logger.critical('Error: FakeNet-NG only supports ' +
                                         'Windows Vista+.')
                    self.logger.critical('       Please use the original ' +
                                         'Fakenet for older versions of ' +
                                         'Windows.')
                    sys.exit(1)

                if self.diverter_config['networkmode'].lower() == 'auto':
                    self.diverter_config['networkmode'] = 'singlehost'

                from fakenet.diverters.windows import Diverter
                self.diverter = Diverter(self.diverter_config, self.listeners_config, ip_addrs, self.logging_level)

            elif platform_name.lower().startswith('linux'):
                if self.diverter_config['networkmode'].lower() == 'auto':
                    self.diverter_config['networkmode'] = 'multihost'

                if self.diverter_config['networkmode'].lower() == 'multihost':
                    if (self.diverter_config['linuxrestrictinterface'].lower()
                            != 'off'):
                        fn_iface = self.diverter_config['linuxrestrictinterface']
                        if fn_iface in iface_ip_info.ifaces:
                            try:
                                # default to first link
                                fn_addr = iface_ip_info.get_ips([4], fn_iface)[0]
                            except LookupError as e:
                                self.logger.error('Couldn\'t get IP for %s' %
                                                  (fn_iface))
                                sys.exit(1)
                        else:
                            self.logger.error(
                                'Invalid interface %s specified. Proceeding '
                                'without interface restriction. Exiting.',
                                fn_iface)
                            sys.exit(1)

                from fakenet.diverters.linux import Diverter
                self.diverter = Diverter(self.diverter_config, self.listeners_config, ip_addrs, self.logging_level)

            else:
                self.logger.critical(
                    'Error: Your system %s is currently not supported.' %
                    (platform_name))
                sys.exit(1)

        # Import DiverterListenerCallbacks
        from fakenet.diverters.diverterbase import DiverterListenerCallbacks
        self.diverterListenerCallbacks = DiverterListenerCallbacks(self.diverter)

        # Start all of the listeners
        for listener_name in self.listeners_config:

            listener_config = self.listeners_config[listener_name]
            listener_config['ipaddr'] = fn_addr
            listener_config['configdir'] = self.fakenet_config_dir
            # Anonymous listener
            if not 'listener' in listener_config:
                self.logger.debug('Anonymous %s listener on %s port %s...',
                                 listener_name, listener_config['protocol'],
                                 listener_config['port'])
                continue

            # Get a specific provider for the listener name
            try:
                listener_module   = getattr(listeners, listener_config['listener'])
                listener_provider = getattr(listener_module, listener_config['listener'])

            except AttributeError as e:
                self.logger.error('Listener %s is not implemented.', listener_config['listener'])
                self.logger.error("%s" % e)
                if self.policy_mode:
                    raise RuntimeError(
                        'EgressControl listener provider is unavailable: %s' %
                        listener_config['listener']) from e

            else:
                listener_config['networkmode'] = self.diverter_config['networkmode']
                listener_provider_instance = listener_provider(
                        listener_config, listener_name, self.logging_level)

                # Store listener provider object
                self.running_listener_providers.append(listener_provider_instance)

                if not self.policy_mode:
                    try:
                        listener_provider_instance.start()
                    except Exception as e:
                        self.logger.error('Error starting %s listener on port %s:',
                                          listener_config['listener'],
                                          listener_config['port'])
                        self.logger.error(" %s" % e)
                        sys.exit(1)

        if self.policy_mode:
            # Configure policy listener dependencies before any bind or worker
            # thread. Providers that need dependencies must implement this
            # construction-safe method.
            for listener in self.running_listener_providers:
                configure = getattr(listener, 'configure_dependencies', None)
                if configure:
                    configure(self.running_listener_providers, self.diverter,
                              self.diverterListenerCallbacks)
            self.diverter.configure_policy_runtime(
                self.running_listener_providers)
            started = []
            try:
                for listener in self.running_listener_providers:
                    listener._policy_stopped = False
                    listener.start()
                    started.append(listener)
                    worker = (getattr(listener, 'server_thread', None) or
                              getattr(listener, '_accept_thread', None))
                    if worker:
                        worker.join(0.05)
                        if not worker.is_alive():
                            raise RuntimeError(
                                'policy listener worker failed to start: %s' %
                                listener.name)
            except Exception:
                self.logger.exception('Policy listener startup failed closed')
                for listener in reversed(started):
                    try:
                        self._stop_policy_listener(listener)
                    except Exception:
                        self.logger.exception('Listener rollback failed')
                raise

        # Hand every listener its diverter reference BEFORE diversion
        # starts: packets redirected by the diverter must never reach a
        # proxy listener whose diverter reference is still None
        # (v1.22 §12.25).
        for listener in self.running_listener_providers:

            if self.policy_mode and getattr(
                    listener, 'configure_dependencies', None):
                continue

            # Only listeners that implement acceptListeners(listeners)
            # interface receive running_listener_providers
            try:
                listener.acceptListeners(self.running_listener_providers)
            except AttributeError:
                self.logger.debug("acceptListeners() not implemented by Listener %s" % listener.name)

            # Only listeners that implement acceptDiverter(diverter)
            # interface receive diverter
            try:
                listener.acceptDiverter(self.diverter)
            except AttributeError:
                self.logger.debug("acceptDiverter() not implemented by Listener %s" % listener.name)

            # Only listeners that implement acceptDiverterListenerCallbacks(diverterListenerCallbacks)
            # interface receive diverterListenerCallbacks
            try:
                listener.acceptDiverterListenerCallbacks(self.diverterListenerCallbacks)
            except AttributeError:
                self.logger.debug("acceptDiverterListenerCallbacks() not implemented by Listener %s" % listener.name)

        # Start the diverter
        if self.diverter:
            try:
                self.diverter.start()
            except Exception:
                if self.policy_mode:
                    self.logger.exception(
                        'Policy diverter startup failed; rolling back listeners')
                    for listener in reversed(
                            self.running_listener_providers):
                        try:
                            self._stop_policy_listener(listener)
                        except Exception:
                            self.logger.exception(
                                'Listener rollback after diverter failure failed')
                raise



    def stop(self):
        with self._stop_lock:
            if self._stop_started:
                stop_owner = False
            else:
                self._stop_started = True
                stop_owner = True

        if not stop_owner:
            self._stop_complete.wait()
            if self._stop_error is not None:
                raise self._stop_error
            return self._stop_result

        self.logger.info("Stopping...")
        first_error = None
        healthy = True
        try:
            if self.policy_mode and self.diverter:
                try:
                    self.diverter.suspend_policy()
                except BaseException as exc:
                    first_error = exc
                    healthy = False
                    self.logger.exception('Policy suspension failed')

            providers = (reversed(self.running_listener_providers)
                         if self.policy_mode else
                         iter(self.running_listener_providers))
            for provider in providers:
                try:
                    if self.policy_mode:
                        self._stop_policy_listener(provider)
                    else:
                        provider.stop()
                except BaseException as exc:
                    if first_error is None:
                        first_error = exc
                    healthy = False
                    self.logger.exception(
                        'Listener failed during stop: %s', provider.name)

            if self.diverter:
                try:
                    if self.diverter.stop() is False:
                        healthy = False
                except BaseException as exc:
                    if first_error is None:
                        first_error = exc
                    healthy = False
                    self.logger.exception('Diverter failed during stop')

            if first_error is not None:
                raise first_error
            return healthy
        finally:
            with self._stop_lock:
                self._stop_result = healthy
                self._stop_error = first_error
                self._stop_complete.set()

    def wait_for_capture_failure(self, timeout):
        if self.diverter:
            return self.diverter.wait_for_capture_failure(timeout)
        time.sleep(timeout)
        return False

    @staticmethod
    def _stop_policy_listener(listener):
        if getattr(listener, '_policy_stopped', False):
            return
        listener.stop()
        listener._policy_stopped = True


class IfaceIpInfo():
    """Make netifaces queryable via listcomps of namedtuples"""

    IfaceIp = namedtuple('IfaceIp', 'iface ip ver')

    _ver_to_spec = {4: netifaces.AF_INET, 6: netifaces.AF_INET6}
    _valid_ipvers = [4, 6]

    def __init__(self):
        self.ifaces = netifaces.interfaces()
        self.ips = []

        for iface in self.ifaces:
            addrs = netifaces.ifaddresses(iface)
            for ipver in self._valid_ipvers:
                self._tabulate_iface(iface, addrs, ipver)

    def _tabulate_iface(self, iface, addrs, ipver):
        spec = self._ver_to_spec[ipver]
        if spec in addrs:
            for link in addrs[spec]:
                self._tabulate_link(iface, link, ipver)

    def _tabulate_link(self, iface, link, ipver):
        if 'addr' in link:
            addr = link['addr']
            self.ips.append(self.IfaceIp(iface, addr, ipver))

    def get_ips(self, ipvers, iface=None):
        """Return IP addresses bound to local interfaces including loopbacks.

        Parameters
        ----------
        ipvers : list(int)
            IP versions desired (4, 6, or both)
        iface : str or NoneType
            Optional interface to limit the query
        returns:
            list(str): IP addresses as requested
        """
        if not all(ver in self._valid_ipvers for ver in ipvers):
            raise ValueError('Only IP versions 4 and 6 are supported')

        if iface and (iface not in self.ifaces):
            raise ValueError('Unrecognized iface %s' % (iface))

        downselect = [i for i in self.ips if i.ver in ipvers]
        if iface:
            downselect = [i for i in downselect if i.iface == iface]
        return [i.ip for i in downselect]


def wait_for_shutdown(fakenet, stop_flag=None):
    """Wait for an operator stop flag or a capture-fatal event."""
    while True:
        if fakenet.wait_for_capture_failure(0.1):
            fakenet.logger.critical(
                'Capture failed; initiating controlled shutdown')
            return 1
        if stop_flag and os.path.exists(stop_flag):
            fakenet.logger.info('Stop flag found at %s' % stop_flag)
            return 0


def main():
    rc = 0
    fakenet = None
    options = None
    logger = None
    # Wrap everything in try/except for SystemExit to require confirmation
    # before closing the console window
    try:
        print(r"""
______      _  ________ _   _ ______ _______     _   _  _____
|  ____/\   | |/ /  ____| \ | |  ____|__   __|   | \ | |/ ____|
| |__ /  \  | ' /| |__  |  \| | |__     | |______|  \| | |  __
|  __/ /\ \ |  < |  __| | . ` |  __|    | |______| . ` | | |_ |
| | / ____ \| . \| |____| |\  | |____   | |      | |\  | |__| |
|_|/_/    \_\_|\_\______|_| \_|______|  |_|      |_| \_|\_____|

                        Version 3.5
_____________________________________________________________
                Developed by FLARE Team
    Copyright (C) 2016-2026 Mandiant, Inc. All rights reserved.
_____________________________________________________________
                                                """)

        # Parse command line arguments
        parser = OptionParser(usage = "python -m fakenet.fakenet [options]:")
        parser.add_option("-c", "--config-file", action="store",  dest="config_file",
                        help="configuration filename", metavar="FILE")
        parser.add_option("-v", "--verbose",
                        action="store_true", dest="verbose", default=False,
                        help="print more verbose messages (default: False)")
        parser.add_option("-l", "--log-file", action="store", dest="log_file")
        parser.add_option("-s", "--log-syslog", action="store_true", dest="syslog",
                        default=False, help="Log to syslog via /dev/log  (default: False)")
        parser.add_option("-f", "--stop-flag", action="store", dest="stop_flag",
                        help="terminate if stop flag file is created")
        parser.add_option("-p", "--no-pause", action="store_true", default=False,
                          help="disable pause for confirmation before closing the console (default: pause)")
        # TODO: Rework the way loggers are created and configured by subcomponents
        # to produce the expected result when logging control is asserted at the
        # top level. For now, the setting serves its real purpose which is to ease
        # testing on Linux after modifying logging such that console and file
        # output are not mutually exclusive.
        parser.add_option("-n", "--no-console-output", action="store_true",
                        dest="no_con_out", default=False,
                        help="Suppress console output (for testing on Linux)")

        try:
            (options, args) = parser.parse_args()
        except SystemExit:
            # --help and invalid-option exits are still real process starts.
            requested_log = _requested_log_file()
            try:
                logger, _log_path = _configure_startup_logging(requested_log)
            except IOError:
                print(('Failed to open log file: %s' %
                       (requested_log or os.path.join(
                           _runtime_directory(), 'Logs'))))
                raise SystemExit(1)
            logger.info('FakeNet-NG option parsing requested process exit')
            raise

        logging_level = logging.DEBUG if options.verbose else logging.INFO
        date_format = '%m/%d/%y %I:%M:%S %p'
        try:
            logger, _log_path = _configure_startup_logging(
                options.log_file, logging_level,
                console=not options.no_con_out)
        except IOError:
            print(('Failed to open log file: %s' %
                   (options.log_file or os.path.join(
                       _runtime_directory(), 'Logs'))))
            sys.exit(1)

        if options.syslog:
            platform_name = platform.system()
            sysloghandler = None
            if platform_name == 'Windows':
                sysloghandler = logging.handlers.NTEventLogHandler('FakeNet-NG')
            elif platform_name.lower().startswith('linux'):
                sysloghandler = logging.handlers.SysLogHandler('/dev/log')
            else:
                print(('Error: Your system %s is currently not supported.' %
                    (platform_name)))
                sys.exit(1)

            # Specify datefmt for consistency, but syslog generally logs the time
            # on each log line, so %(asctime) is omitted here.
            sysloghandler.formatter = logging.Formatter(
                '"FakeNet-NG": {"loggerName":"%(name)s", '
                '"moduleName":"%(module)s", '
                '"levelName":"%(levelname)s", '
                '"message":"%(message)s"}', datefmt=date_format)
            logger.addHandler(sysloghandler)

        fakenet = Fakenet(logging_level)
        fakenet.parse_config(options.config_file)

        if options.stop_flag:
            options.stop_flag = os.path.expandvars(options.stop_flag)
            fakenet.logger.info('Will seek stop flag at %s' % (options.stop_flag))

        fakenet.start()
        logger.info('FakeNet-NG started successfully')

        rc = wait_for_shutdown(fakenet, options.stop_flag)

    except KeyboardInterrupt:
        if logger:
            logger.info('KeyboardInterrupt')
        print("KeyboardInterrupt")
    except BaseException as e:
        rc = e.code if isinstance(e, SystemExit) else 1
        if rc != 0:
            if logger:
                # logger.exception already carries the full traceback to the
                # log file and the console; a second raw print_exc() only
                # duplicated the console dump (v1.24 §12.27).
                logger.exception('FakeNet-NG terminated with an error')
    finally:
        if fakenet:
            try:
                if fakenet.stop() is False:
                    rc = 1
            except BaseException:
                rc = 1
                if logger:
                    logger.exception('FakeNet-NG stop failed')
        # Delete flag only after FakeNet-NG has stopped to indicate completion
        if options and options.stop_flag and os.path.exists(options.stop_flag):
            try:
                os.remove(options.stop_flag)
            except:
                print(f"WARNING: could not delete stop flag file: {options.stop_flag}")

        # We have to check if options has been fully parsed because of --help or invalid options
        # "not no_pause" is confusing, but this is unfortunately the best way to set the default  with optparse
        if options and not options.no_pause:
            input("[Press Enter to exit]")

        if logger:
            logger.info('FakeNet-NG exiting: rc=%s', rc)
        sys.exit(rc)

if __name__ == '__main__':
    main()
