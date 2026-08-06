import logging
import socket
import sys
import threading
import types
import unittest


fake_netfilterqueue = types.ModuleType('netfilterqueue')
fake_netfilterqueue.NetfilterQueue = object
sys.modules.setdefault('netfilterqueue', fake_netfilterqueue)

from fakenet.diverters.linutil import LinuxDiverterNfqueue
from fakenet.diverters.linux import Diverter
from fakenet.diverters.pcapwriter import PcapWriteError


class CallbackQueue(object):
    def run_socket(self, sock):
        raise PcapWriteError('injected queue callback failure')


class AliveThread(object):
    def __init__(self):
        self.join_timeout = None

    def join(self, timeout=None):
        self.join_timeout = timeout

    def is_alive(self):
        return True


class Rule(object):
    def __init__(self, result=0):
        self.remove_calls = 0
        self.result = result

    def remove(self):
        self.remove_calls += 1
        return self.result


class BoundQueue(object):
    def __init__(self):
        self.unbind_calls = 0

    def unbind(self):
        self.unbind_calls += 1


class DeadThread(AliveThread):
    def is_alive(self):
        return False


class VerdictPacket(object):
    def __init__(self):
        self.drop_calls = 0
        self.accept_calls = 0

    def get_payload(self):
        return b'\x45' + (b'\x00' * 19)

    def drop(self):
        self.drop_calls += 1

    def accept(self):
        self.accept_calls += 1


class LinuxPcapLifecycleTests(unittest.TestCase):
    def test_queue_thread_exposes_callback_failure(self):
        observed = []
        queue = LinuxDiverterNfqueue.__new__(LinuxDiverterNfqueue)
        queue.logger = logging.getLogger('linux-queue-test')
        queue._nfqueue = CallbackQueue()
        queue._sk = object()
        queue._stopflag = False
        queue._thread_error = None
        queue._thread_exited = threading.Event()
        queue._on_error = observed.append

        queue._threadproc()

        self.assertIsInstance(queue.thread_error, PcapWriteError)
        self.assertTrue(queue.thread_exited)
        self.assertEqual([queue.thread_error], observed)

    def test_queue_stop_is_bounded_and_does_not_unbind_live_thread(self):
        queue = LinuxDiverterNfqueue.__new__(LinuxDiverterNfqueue)
        queue.logger = logging.getLogger('linux-queue-test')
        queue._stopflag = False
        queue._started = True
        queue._thread = AliveThread()
        queue._bound = True
        queue._nfqueue = BoundQueue()
        queue._rule_added = True
        queue._rule = Rule()

        self.assertFalse(queue.stop(timeout=0.01))
        self.assertEqual(0.01, queue._thread.join_timeout)
        self.assertEqual(0, queue._nfqueue.unbind_calls)
        self.assertEqual(1, queue._rule.remove_calls)

    def test_queue_rule_cleanup_failure_is_observable_without_live_thread(self):
        queue = LinuxDiverterNfqueue.__new__(LinuxDiverterNfqueue)
        queue.logger = logging.getLogger('linux-queue-test')
        queue._stopflag = False
        queue._started = True
        queue._thread = DeadThread()
        queue._bound = True
        queue._nfqueue = BoundQueue()
        queue._rule_added = True
        queue._rule = Rule(result=1)
        queue._stop_error = None

        self.assertFalse(queue.stop(timeout=0.01))
        self.assertFalse(queue.thread_alive)
        self.assertIsInstance(queue.stop_error, RuntimeError)
        self.assertEqual(1, queue._nfqueue.unbind_calls)

    def test_capture_failure_drops_current_nfqueue_packet(self):
        diverter = Diverter.__new__(Diverter)
        diverter.logger = logging.getLogger('linux-handler-test')
        diverter.outgoing_net_cbs = []
        diverter.outgoing_trans_cbs = []
        diverter.handle_pkt = lambda *args, **kwargs: (
            (_ for _ in ()).throw(PcapWriteError('injected')))
        packet = VerdictPacket()

        with self.assertLogs('linux-handler-test', level='CRITICAL') as logs:
            with self.assertRaises(PcapWriteError):
                diverter.handle_outgoing(packet)

        self.assertEqual(1, packet.drop_calls)
        self.assertEqual(0, packet.accept_calls)
        self.assertEqual(1, len([
            line for line in logs.output
            if 'PCAP_DUAL_CURRENT_PACKET_DROP hook=outgoing' in line]))


if __name__ == '__main__':
    unittest.main()
