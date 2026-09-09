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
import time
from pathlib import Path

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
        errors='replace', timeout=20)
    return completed


def _terminate_existing_service():
    """Delete only after the current instance completes its two-phase stop."""
    if cmd_stop(None):
        raise RuntimeError('existing service did not stop cleanly')
    deleted = _sc('delete', SERVICE_NAME)
    if deleted.returncode not in (0, 1060):
        raise RuntimeError('service deletion failed: ' + deleted.stdout + deleted.stderr)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        query = _sc('query', SERVICE_NAME)
        if query.returncode == 1060:
            return
        time.sleep(0.1)
    raise TimeoutError('service deletion did not complete')


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
        extra_control_ports=getattr(args, 'extra_exclude_port', []) or [],
        source='install-cli')
    paths.ensure_data_directories()
    bin_path = '"%s" run' % _exe_path()
    try:
        _terminate_existing_service()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    cfg.save()
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
    secured = _sc('sdset', SERVICE_NAME,
                  'D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)'
                  '(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)')
    if secured.returncode:
        print('service control ACL setup failed', file=sys.stderr)
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
    if cmd_stop(None):
        return 1
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
    from fakenet.mcp.service_stop import stop_installed_service
    try:
        cfg = config_module.ServiceConfig.load()
    except config_module.ConfigError:
        # Fresh installation has neither a service nor recovery state.
        # The wrapper checks SCM and the marker before allowing deletion.
        from types import SimpleNamespace
        cfg = SimpleNamespace(stop_grace_seconds=60)
    dirs = paths.data_directories()
    try:
        stop_installed_service(cfg, dirs['logs'] / 'service-stop-result.json',
                               dirs['state'] / 'state.json')
        return 0
    except Exception as exc:
        logger.error('controlled service stop failed: %s', exc)
        print(str(exc), file=sys.stderr)
        return 1


def service_main(controller):
    """Long-running service body (SCM or debug)."""
    stop_event = (controller.stop_event if controller is not None
                  else threading.Event())

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
    # Failed exits keep the guard until process death. A clean SCM handoff
    # releases it after HTTP termination, before SvcRun reports STOPPED.

    if os.name == 'nt':
        try:
            ok, detail = firewall.verify_rule(cfg.listen_port,
                                              cfg.allowed_host_ips)
            if not ok:
                logger.warning('firewall rule check failed (%s); recreating',
                               detail)
                firewall.ensure_rule(cfg.listen_port, cfg.allowed_host_ips)
                ok, detail = firewall.verify_rule(cfg.listen_port,
                                                  cfg.allowed_host_ips)
                if not ok:
                    raise RuntimeError(detail)
        except RuntimeError as exc:
            # Keep diagnostics available; every managed start independently
            # revalidates the effective rule and fails closed before work.
            logger.error('firewall protection unavailable; managed start '
                         'will be refused: %s', exc)

    from fakenet.mcp import paths as mcp_paths
    from fakenet.mcp import server as server_module
    from fakenet.mcp import snapshot as mcp_snapshot
    from fakenet.mcp.baseline import BaselineStore
    from fakenet.mcp.supervisor import perform_startup_recovery

    dirs = mcp_paths.ensure_data_directories()
    context = None

    ready = threading.Event()
    failure = {'code': 0}
    server_stop = threading.Event()
    def serve():
        try:
            import fakenet.mcp.server as srv

            # One assembly path for SCM, debug and protocol tests: deployment
            # options (including compatibility) must reach the same guard.
            app = srv.build_app(cfg, context=context)
            import uvicorn

            config_uvicorn = uvicorn.Config(
                app, host=cfg.listen_ip, port=cfg.listen_port,
                log_level=cfg.log_level.lower(), lifespan='on',
                access_log=False, log_config=None)
            instance = uvicorn.Server(config_uvicorn)
            srv._active_server = instance
            ready_watch = threading.Event()

            def _watch():
                while not instance.started and not instance.should_exit:
                    time.sleep(0.05)
                ready_watch.set()

            threading.Thread(target=_watch, daemon=True).start()
            threading.Thread(target=lambda: (ready_watch.wait(30),
                                             ready.set()),
                             daemon=True).start()
            instance.run()
            server_stop.set()
            ready.set()
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

    ctx = getattr(server_module, '_active_context', None)
    if ctx is None:
        logger.error('server ready without an application context')
        server_module.request_shutdown()
        return 1
    if controller is not None:
        controller.configure_prestop(ctx, cfg, dirs['logs'] / 'service-stop-result.json')
    if os.environ.get('FAKENETNG_MCP_TESTDOUBLE') != '1':
        # The real context is observable before recovery. Startup state is
        # recovering, so clients cannot start work during this bounded phase.
        ctx.runner.recover(ctx.coordinator)
    if controller is not None:
        controller.report_running()
    logger.info('fakenetng-mcp serving on %s:%d', cfg.listen_ip,
                cfg.listen_port)

    while not stop_event.wait(0.1):
        if server_stop.is_set():
            logger.error('HTTP endpoint exited unexpectedly')
            return 1

    logger.info('stop requested; shutting down endpoint')
    if controller is not None:
        controller.report_stop_pending()
    # Ask uvicorn to exit: the serve thread's server instance owns the loop.
    from fakenet.mcp import server as server_module_again
    server_module_again.request_shutdown()
    if not server_stop.wait(timeout=30.0):
        logger.error('HTTP endpoint shutdown exceeded its budget')
        return 1
    thread.join(timeout=1.0)
    if thread.is_alive():
        logger.error('HTTP worker still alive after shutdown notification')
        return 1
    guard.close()
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
    install.add_argument('--extra-exclude-port', action='append',
                         default=[], type=int,
                         help='extra host-only port excluded from the main '
                              'capture filter (repeatable)')
    install.set_defaults(func=cmd_install)

    uninstall = sub.add_parser('uninstall', help='remove the service')
    uninstall.set_defaults(func=cmd_uninstall)

    start = sub.add_parser('start', help='sc start')
    start.set_defaults(func=cmd_start)

    stop = sub.add_parser('stop', help='two-phase controlled service stop')
    stop.set_defaults(func=cmd_stop)

    run = sub.add_parser('run', help='run as SCM service entry')
    run.set_defaults(func=cmd_run)

    debug = sub.add_parser('debug', help='run in foreground (no SCM)')
    debug.set_defaults(func=cmd_debug)
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ['managed-fault-hang']:
        from fakenet.mcp.faultinject import enabled
        if not enabled():
            return 2
        from fakenet.mcp.incident import IncidentCollector
        Path('fault-child-stacks.txt').write_text(IncidentCollector._thread_stacks(), encoding='utf-8')
        time.sleep(3600)
        return 0
    if argv and argv[0] == 'incident-dump':
        if len(argv) != 4:
            return 2
        from fakenet.mcp.dumpworker import dump_main
        return dump_main(int(argv[1]), argv[2], argv[3])
    if argv and argv[0] == 'managed-child':
        if len(argv) != 3:
            return 2
        from fakenet.mcp.managed import child_main
        return child_main(argv[1], argv[2])
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, 'command', None):
        parser.print_help()
        return 2
    return args.func(args)
