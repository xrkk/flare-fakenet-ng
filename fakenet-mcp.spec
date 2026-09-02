# -*- mode: python -*-

# fakenetng-mcp onedir spec (P01 IMP-P01-06).
# Entry: fakenet/mcp/__main__.py -> fakenetng-mcp.exe
# hiddenimports pinned from the Wine build probes: the MCP SDK and
# uvicorn resolve several backends dynamically.

block_cipher = None


a = Analysis(['fakenet/mcp/__main__.py'],
             pathex=['.'],
             datas=None,
             hiddenimports=[
                 'mcp',
                 'mcp.types',
                 'mcp.shared',
                 'mcp.shared._httpx_utils',
                 'mcp.server',
                 'mcp.server.mcpserver',
                 'mcp.server.lowlevel',
                 'mcp.server.lowlevel.server',
                 'mcp.server.streamable_http_manager',
                 'mcp.server.session',
                 'mcp.server.connection',
                 'mcp.server.context',
                 'mcp.server.sse',
                 'mcp.server.auth',
                 'uvicorn',
                 'uvicorn.logging',
                 'uvicorn.loops',
                 'uvicorn.loops.auto',
                 'uvicorn.loops.asyncio',
                 'uvicorn.protocols',
                 'uvicorn.protocols.http',
                 'uvicorn.protocols.http.auto',
                 'uvicorn.protocols.http.h11_impl',
                 'uvicorn.protocols.websockets',
                 'uvicorn.protocols.websockets.auto',
                 'uvicorn.lifespan',
                 'uvicorn.lifespan.on',
                 'uvicorn.lifespan.off',
                 'anyio._backends._asyncio',
                 'pydantic',
                 'pydantic.deprecated.decorator',
                 'pywintypes',
                 'win32serviceutil',
                 'win32service',
                 'servicemanager',
                 'win32event',
                 'win32api',
                 'win32timezone',
                 'pythoncom',
             ],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             cipher=block_cipher,
             )

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# WinDivert drivers, mirroring the formal fakenet.spec contract: pydivert
# bundles its own copy, and the repo-root windivert/ files guarantee the
# service can load the driver for the real lifecycle (P03).
driver_files = [
    ('WinDivert64.dll', 'windivert/WinDivert64.dll', 'BINARY'),
    ('WinDivert64.sys', 'windivert/WinDivert64.sys', 'BINARY'),
    ('WinDivert32.dll', 'windivert/WinDivert32.dll', 'BINARY'),
    ('WinDivert32.sys', 'windivert/WinDivert32.sys', 'BINARY'),
]

exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          icon=None,
          name='fakenetng-mcp',
          debug=False,
          strip=False,
          upx=False,
          console=True)

coll = COLLECT(exe,
               a.binaries + driver_files + a.datas,
               strip=False,
               upx=False,
               name='fakenetng-mcp-dist')
