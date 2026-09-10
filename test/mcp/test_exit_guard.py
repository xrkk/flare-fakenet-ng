import os
import subprocess
import sys

import pytest


@pytest.mark.skipif(os.name != 'nt', reason='Windows named mutex')
def test_helper_entry_does_not_queue_another_process():
    from fakenet.mcp.exit_guard import SingleFlight
    source = ('from fakenet.mcp.exit_guard import SingleFlight; '
              'g=SingleFlight(); acquired=g.acquire(); g.close(); '
              'raise SystemExit(0 if acquired else 3)')
    with SingleFlight():
        rejected = subprocess.run([sys.executable, '-c', source], timeout=10,
                                  capture_output=True, text=True)
        assert rejected.returncode == 3, rejected.stderr
    accepted = subprocess.run([sys.executable, '-c', source], timeout=10,
                              capture_output=True, text=True)
    assert accepted.returncode == 0, accepted.stderr
