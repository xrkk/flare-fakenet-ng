"""The receiver thread must exit cleanly when the handle is removed.

candidate12 sst-002 rerun: the diverter_stop injection replaces the handle
with None while the receiver is between recv() calls; `self.handle.recv()`
then raised AttributeError, which logged a run.log traceback, recorded a
spurious capture failure, and cascaded into a failed stop (three exception
blocks where the fault contract allows none).  The same clean exit that a
recv() on a closed handle takes must also be taken when the handle object
is already gone.
"""
import logging
import sys
import threading
import types

try:
    from fakenet.diverters.windows import Diverter
except ImportError:  # Linux runners: stub the Windows registry module.
    _winreg = types.ModuleType('winreg')
    for _name in ('KEY_READ', 'KEY_WRITE', 'KEY_ALL_ACCESS', 'HKEY_LOCAL_MACHINE',
                  'HKEY_CURRENT_USER', 'QUERY_VALUE', 'KEY_QUERY_VALUE',
                  'KEY_SET_VALUE', 'REG_SZ', 'REG_MULTI_SZ', 'REG_DWORD',
                  'REG_BINARY', 'CreateKeyEx', 'OpenKey', 'QueryValueEx',
                  'SetValueEx', 'CloseKey', 'EnumKey', 'EnumValue', 'DeleteKey'):
        setattr(_winreg, _name, None)
    sys.modules.setdefault('winreg', _winreg)
    from fakenet.diverters.windows import Diverter


def _receiver_with_handle(handle_value):
    diverter = Diverter.__new__(Diverter)
    diverter._stopping = threading.Event()
    diverter._diverter_exited = threading.Event()
    diverter.handle = handle_value
    diverter.logger = logging.getLogger('test-divert-thread')
    failures = []
    diverter._record_capture_failure = failures.append
    return diverter, failures


def test_removed_handle_exits_cleanly_without_capture_failure():
    diverter, failures = _receiver_with_handle(None)
    diverter.divert_thread()
    assert diverter._diverter_exited.is_set()
    assert failures == []


def test_live_handle_still_reaches_recv():
    class FakeHandle:
        def __init__(self):
            self.recv_calls = 0

        def recv(self):
            self.recv_calls += 1
            diverter._stopping.set()
            # None is the documented "cannot handle packet" observation; the
            # loop continues and then exits through the stopping flag.
            return None

    diverter, failures = _receiver_with_handle(None)
    handle = FakeHandle()
    diverter.handle = handle
    diverter._handle_policy_packet = lambda packet: None
    diverter._handle_legacy_packet = lambda packet: None
    diverter.egress_control_mode = False
    diverter.divert_thread()
    assert handle.recv_calls == 1
    assert diverter._diverter_exited.is_set()
    assert failures == []
