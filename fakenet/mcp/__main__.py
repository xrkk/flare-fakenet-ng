# Copyright 2026 Google LLC
"""Entry point: python -m fakenet.mcp (frozen as fakenetng-mcp.exe)."""

import sys

from fakenet.mcp.cli import main

if __name__ == '__main__':
    sys.exit(main())
