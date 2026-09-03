# Copyright 2026 Google LLC
"""fakenetng-mcp server assembly (P01 slice).

Builds the SDK (mcp==2.1.1) modern-era MCP server, adds the single no-side-
effect probe tool ``ping``, wraps the Starlette app with the transport guard
and serves it bound to the configured host-only address only.

P02 will extend the tool surface; P01 exposes only ``ping`` plus protocol
built-ins (server/discover, tools/list).
"""

import logging

from fakenet.mcp import (MCP_ENDPOINT_PATH, MCP_PACKAGE_NAME,
                         MCP_PACKAGE_VERSION, MCP_PROTOCOL_VERSION)
from fakenet.mcp.config import ServiceConfig
from fakenet.mcp.transportguard import (TransportGuardMiddleware,
                                        classify_controller_header,
                                        controller_header_state)


def build_mcp_server(config=None, context=None):
    """Create the MCPServer instance with the probe and domain tools."""
    from mcp.server.mcpserver import MCPServer

    from fakenet.mcp.tools import AppContext, register_tools

    server = MCPServer(name=MCP_PACKAGE_NAME, version=MCP_PACKAGE_VERSION)

    @server.tool()
    def ping() -> dict:
        """No-side-effect probe: service identity, protocol and controller
        header judgment for the calling connection."""
        controller = controller_header_state.get()
        return {
            'service': MCP_PACKAGE_NAME,
            'version': MCP_PACKAGE_VERSION,
            'protocol': MCP_PROTOCOL_VERSION,
            'controller_header': classify_controller_header(controller),
        }

    if context is None and config is not None:
        context = AppContext(config)
    if context is not None:
        register_tools(server, context)
    global _active_context
    _active_context = context
    return server


def build_app(config: ServiceConfig, logger=None, context=None):
    """Return the guarded ASGI app bound to the configured endpoint path."""
    server = build_mcp_server(config, context=context)
    starlette_app = server.streamable_http_app(
        streamable_http_path=MCP_ENDPOINT_PATH,
        json_response=True,
        stateless_http=True,
        host=config.listen_ip,
    )
    return TransportGuardMiddleware(
        starlette_app, endpoint_path=MCP_ENDPOINT_PATH, logger=logger)


_active_server = None
_active_context = None


def request_shutdown():
    """Ask the active uvicorn server to exit its serve loop."""
    instance = _active_server
    if instance is not None:
        instance.should_exit = True


def run_server(config: ServiceConfig, ready_event=None, stop_hook=None):
    """Serve the MCP endpoint on config.listen_ip:config.listen_port.

    ``ready_event`` is set once the server is accepting connections;
    ``stop_hook`` (if given) runs after the server loop exits.
    Binding failure raises (the caller must not swallow it: the service
    refuses to start when the host-only address is unavailable).
    """
    import threading

    import uvicorn

    global _active_server

    logger = logging.getLogger(MCP_PACKAGE_NAME)
    app = build_app(config, logger=logger)
    # log_config=None keeps uvicorn from installing its ColourizedFormatter,
    # which calls sys.stdout.isatty() and crashes in SCM service context
    # where the standard streams are absent.
    server_config = uvicorn.Config(
        app, host=config.listen_ip, port=config.listen_port,
        log_level=config.log_level.lower(), lifespan='on', access_log=False,
        log_config=None)
    instance = uvicorn.Server(server_config)
    _active_server = instance

    if ready_event is not None:
        def _watch_ready():
            while not instance.started and not instance.should_exit:
                threading.Event().wait(0.05)
            ready_event.set()
        threading.Thread(target=_watch_ready, daemon=True).start()

    instance.run()
    if stop_hook:
        stop_hook()
    return instance
