"""Controlled OS backend for the faithful Windows fixture child (CTRLC-IPC).

Mirrors test/test_acceptance_manual_ctrlc_ipc.py's _Backend/_Iface: a real
start/stop lifecycle backend with no OS network operations.  The REAL core,
watchdog threads, IPC/CtrlC paths, observations and judging are untouched;
this replaces only the WinDivert OS interface under the fixture boundary."""
class IfaceIpInfo:
    """No-arg interface probe mirroring the controlled local fixture: a
    fixed owned interface table with no OS network calls."""
    ifaces = {'eth0': []}

    def get_ips(self, versions, iface=None):
        return ['192.0.2.10'] if 4 in versions else []


class Backend:
    instances = []
    fail_stop = False

    def __init__(self, *args, **kwargs):
        self.running = False
        self.nfqueues = []
        self.flagsblacklist = []
        self.start_calls = 0
        self.stop_calls = 0
        self.wait_calls = 0
        Backend.instances.append(self)

    def start(self):
        import time
        self.start_calls += 1
        self.running = True
        self.started_epoch = time.time()

    def stop(self):
        import time
        self.stop_calls += 1
        if Backend.fail_stop:
            raise OSError('stop failed (fixture)')
        self.running = False
        self.stopped_epoch = time.time()
        return True

    def wait_for_shutdown(self, *args, **kwargs):
        self.wait_calls += 1
        return 0

    def wait_for_capture_failure(self, timeout):
        return False

    def check_active_ethernet_adapters(self):
        return True

    def blacklists_enabled(self):
        return False
