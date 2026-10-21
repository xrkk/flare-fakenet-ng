"""Real limited-query identity ABI, exercised in the Windows package gate."""
import os
import pytest
from fakenet.mcp.reboot_recovery import native_process_identity, filetime_ns


@pytest.mark.skipif(os.name != 'nt',reason='Windows native process identity ABI')
def test_current_process_handle_proves_image_birth_and_liveness():
    value=native_process_identity(os.getpid())
    assert value['pid']==os.getpid() and value['alive'] is True
    assert value['image'].lower().endswith('.exe')
    assert filetime_ns(value['birth_ticks'])>0
