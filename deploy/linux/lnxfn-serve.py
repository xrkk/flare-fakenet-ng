#!/usr/bin/env python3
"""LNX-FN guest MCP entry: Bearer-gated, Linux runner, host-only bind."""
import os
from fakenet.mcp.config import ServiceConfig
from fakenet.mcp import server as mcp_server
from fakenet.mcp.bearerauth import load_token

TOKEN_FILE = '/etc/fakenet-ng-linux/token'
LISTEN_IP = os.environ.get('FAKENETNG_LISTEN_IP', '127.0.0.1')
LISTEN_PORT = int(os.environ.get('FAKENETNG_LISTEN_PORT', '28788'))

config = ServiceConfig(LISTEN_IP, LISTEN_PORT, [LISTEN_IP, '127.0.0.1'])
os.environ['FAKENETNG_MCP_LINUX_RUNNER'] = '1'
mcp_server.run_server(config) if False else None
# bearer gate requires build_app path with token; use run_server extension:
import uvicorn, logging
app = mcp_server.build_app(config, logging.getLogger('fakenetng-mcp'),
                            bearer_token=load_token(TOKEN_FILE))
uvicorn.run(app, host=LISTEN_IP, port=LISTEN_PORT, log_level='info',
            access_log=False)
