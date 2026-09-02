# Copyright 2026 Google LLC
"""fakenetng-mcp command line: install / uninstall / start / stop / run / debug.

``install`` is Windows-only (sc.exe + netsh).  ``debug`` runs the service in
the foreground for development and acceptance probes.
"""

import argparse
import logging
import os
import subprocess
import sys
import threading

from fakenet.mcp import MCP_PACKAGE_NAME, MCP_PACKAGE_VERSION
from fakenet.mcp import config as config_module
from fakenet.mcp import firewall, paths, singleinstance
from fakenet.mcp.winservice import SERVICE_NAME, run_as_service

logger = logging.getLogger(MCP_PACKAGE_NAME)

_SERVICE_READY_TIMEOUT_S = 60.0


def _setup_logging():
    handlers = []
    if sys.stderr is not None:
        handlers.append(logging.StreamHandler(sys.stderr))
    try:
        dirs = paths.ensure_data_directories()
        handlers.append(logging.FileHandler(
            dirs['logs'] / 'service.log', encoding='utf-8'))
    except OSError:
        pass
    if not handlers:
        handlers.append(logging.NullHandler())
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
        handlers=handlers)


def _sc(*args):
    command = ['sc.exe'] + list(args)
    completed = subprocess.run(
        command, capture_output=True, text=True, encoding='utf-8',
        errors='replace')
    return completed


def _terminate_existing_service():
    """Stop the old service and wait until the SCM fully releases it.

    ``sc create`` fails with 1072 (marked for deletion) when the previous
    instance still has open handles; poll until ``sc query`` reports 1060.
    """
    import time

    _sc('stop', SERVICE_NAME)
    queryex = _sc('queryex', SERVICE_NAME)
    for line in (queryex.stdout or '').splitlines():
        line = line.strip()
        if line.startswith('PID'):
            parts = line.split()
            if len(parts) >= 3 and parts[-1].isdigit() and parts[-1] != '0':
                subprocess.run(['taskkill', '/F', '/PID', parts[-1]],
                               capture_output=True, text=True)
            break
    _sc('delete', SERVICE_NAME)
    deadline = time.time() + 20.0
    while time.time() < deadline:
        probe = _sc('query', SERVICE_NAME)
        text = (probe.stdout or '') + (probe.stderr or '')
        # sc.exe returns 0 even on failure; the 1060 text is the signal.
        if '1060' in text:
            return
        time.sleep(0.5)


def _exe_path():
    return os.path.abspath(sys.executable)


def cmd_install(args):
    if os.name != 'nt':
        print('install requires Windows (sc.exe)', file=sys.stderr)
        return 2
    cfg = config_module.ServiceConfig(
        listen_ip=args.listen_ip,
        listen_port=args.port,
        allowed_host_ips=args.allowed_host,
        source='install-cli')
    paths.ensure_data_directories()
    cfg.save()
    bin_path = '"%s" run' % _exe_path()
    _terminate_existing_service()
    created = None
    for attempt in range(3):
        created = _sc('create', SERVICE_NAME, 'binPath=', bin_path,
                      'start=', 'auto', 'DisplayName=',
                      'FakeNet-NG MCP (fakenetng-mcp)')
        if created.returncode == 0:
            break
        import time

        time.sleep(2.0)
    if created.returncode != 0:
        print('sc create failed: %s%s' % (created.stdout, created.stderr),
              file=sys.stderr)
        return 1
    _sc('description', SERVICE_NAME,
        'FakeNet-NG MCP supervisor service (headless, LocalSystem)')
    _sc('failure', SERVICE_NAME, 'reset=', '0',
        'actions=', 'restart/30000')
    try:
        output = firewall.ensure_rule(cfg.listen_port, cfg.allowed_host_ips)
        print('firewall rule ensured')
        _ = output
    except RuntimeError as exc:
        print('firewall rule failed: %s' % exc, file=sys.stderr)
        return 1
    print('installed: %s (listen %s:%d, allowed %s)' % (
        SERVICE_NAME, cfg.listen_ip, cfg.listen_port,
        ','.join(cfg.allowed_host_ips)))
    return 0


def cmd_uninstall(args):
    if os.name != 'nt':
        print('uninstall requires Windows (sc.exe)', file=sys.stderr)
        return 2
    _sc('stop', SERVICE_NAME)
    deleted = _sc('delete', SERVICE_NAME)
    try:
        firewall.remove_rule()
    except RuntimeError as exc:
        print('firewall rule removal failed: %s' % exc, file=sys.stderr)
    if deleted.returncode != 0 and '1060' not in deleted.stdout \
            and '1060' not in deleted.stderr:
        print('sc delete failed: %s%s' % (deleted.stdout, deleted.stderr),
              file=sys.stderr)
        return 1
    print('uninstalled: %s' % SERVICE_NAME)
    return 0


def cmd_start(args):
    if os.name != 'nt':
        return 2
    started = _sc('start', SERVICE_NAME)
    print(started.stdout or started.stderr)
    return 0 if started.returncode == 0 else 1


def cmd_stop(args):
    if os.name != 'nt':
        return 2
    stopped = _sc('stop', SERVICE_NAME)
    print(stopped.stdout or stopped.stderr)
    return 0 if stopped.returncode == 0 else 1


def service_main(controller):
    """Long-running service body (SCM or debug)."""
    stop_event = (controller.stop_event if controller is not None
                  else threading.Event())

    from fakenet.mcp import jobobject

    job_handle = jobobject.setup_kill_on_close_job()
    _ = job_handle  # keep alive for the process lifetime

    try:
        cfg = config_module.ServiceConfig.load()
    except config_module.ConfigError as exc:
        logger.error('config load failed: %s', exc)
        return 1
    logger.info('config loaded from %s (listen %s:%d)', cfg.source,
                cfg.listen_ip, cfg.listen_port)

    try:
        guard = singleinstance.acquire()
    except singleinstance.SingleInstanceError as exc:
        logger.error('single-instance guard rejected: %s', exc)
        return 1
    _ = guard  # keep the handle alive for the process lifetime

    if os.name == 'nt':
        try:
            ok, detail = firewall.verify_rule(cfg.listen_port,
                                              cfg.allowed_host_ips)
            if not ok:
                logger.warning('firewall rule check failed (%s); recreating',
                               detail)
                firewall.ensure_rule(cfg.listen_port, cfg.allowed_host_ips)
        except RuntimeError as exc:
            logger.error('firewall verification error: %s', exc)

    from fakenet.mcp import paths as mcp_paths
    from fakenet.mcp import server as server_module
    from fakenet.mcp import snapshot as mcp_snapshot
    from fakenet.mcp.baseline import BaselineStore
    from fakenet.mcp.supervisor import perform_startup_recovery

    dirs = mcp_paths.ensure_data_directories()
    if os.environ.get('FAKENETNG_MCP_TESTDOUBLE') != '1':
        outcome = perform_startup_recovery(
            mcp_snapshot.StateSnapshot(dirs['state'] / 'state.json'),
            BaselineStore(dirs['baselines']),
            _RecoveryCoordinatorView())
        logger.info('startup recovery outcome: %s', outcome)

    ready = threading.Event()
    failure = {'code': 0}
    server_stop = threading.Event()

    def serve():
        try:
            server_module.run_server(cfg, ready_event=ready)
        except SystemExit:
            failure['code'] = 1
        except Exception:
            logger.exception('server loop failed')
            failure['code'] = 1
        finally:
            ready.set()
            server_stop.set()

    thread = threading.Thread(target=serve, name='mcp-server', daemon=True)
    thread.start()
    if not ready.wait(timeout=_SERVICE_READY_TIMEOUT_S):
        logger.error('server did not become ready within %ss',
                     _SERVICE_READY_TIMEOUT_S)
        return 1
    if failure['code']:
        return failure['code']

    if controller is not None:
        controller.report_running()
    logger.info('fakenetng-mcp serving on %s:%d', cfg.listen_ip,
                cfg.listen_port)

    stop_event.wait()

    logger.info('stop requested; shutting down endpoint')
    if controller is not None:
        controller.report_stop_pending()
    # Ask uvicorn to exit: the serve thread's server instance owns the loop.
    from fakenet.mcp import server as server_module_again
    server_module_again.request_shutdown()
    server_stop.wait(timeout=30.0)
    logger.info('fakenetng-mcp stopped')
    return failure['code']


def cmd_run(args):
    _setup_logging()
    run_as_service(service_main)
    return 0


def cmd_debug(args):
    _setup_logging()
    return service_main(None)


def build_parser():
    parser = argparse.ArgumentParser(prog=MCP_PACKAGE_NAME)
    parser.add_argument('--version', action='version',
                        version='%s %s' % (MCP_PACKAGE_NAME, MCP_PACKAGE_VERSION))
    sub = parser.add_subparsers(dest='command')

    install = sub.add_parser('install', help='install the Windows service')
    install.add_argument('--listen-ip', required=True)
    install.add_argument('--port', type=int,
                         default=config_module.DEFAULT_PORT)
    install.add_argument('--allowed-host', action='append', required=True,
                         help='allowed host source IP (repeatable)')
    install.set_defaults(func=cmd_install)

    uninstall = sub.add_parser('uninstall', help='remove the service')
    uninstall.set_defaults(func=cmd_uninstall)

    start = sub.add_parser('start', help='sc start')
    start.set_defaults(func=cmd_start)

    stop = sub.add_parser('stop', help='sc stop')
    stop.set_defaults(func=cmd_stop)

    run = sub.add_parser('run', help='run as SCM service entry')
    run.set_defaults(func=cmd_run)

    debug = sub.add_parser('debug', help='run in foreground (no SCM)')
    debug.set_defaults(func=cmd_debug)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, 'command', None):
        parser.print_help()
        return 2
    return args.func(args)


class _RecoveryCoordinatorView:
    """Minimal failure-reason carrier for the startup recovery path."""

    def __init__(self):
        self._failure_reason = None

    @property
    def failure_reason(self):
        return self._failure_reason
