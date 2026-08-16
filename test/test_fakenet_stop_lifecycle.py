import logging
import sys
import threading
import types
import unittest


fake_netifaces = types.ModuleType('netifaces')
fake_netifaces.AF_INET = 2
fake_netifaces.AF_INET6 = 23
fake_netifaces.interfaces = lambda: []
fake_netifaces.ifaddresses = lambda interface: {}
sys.modules.setdefault('netifaces', fake_netifaces)

from fakenet.fakenet import Fakenet, wait_for_shutdown


class Listener(object):
    def __init__(self, name, events):
        self.name = name
        self.events = events
        self._policy_stopped = False
        self.stop_calls = 0

    def stop(self):
        self.stop_calls += 1
        self.events.append('listener-' + self.name)


class Diverter(object):
    def __init__(self, events):
        self.events = events
        self.stop_calls = 0
        self.failure = threading.Event()

    def suspend_policy(self):
        self.events.append('policy-suspend')

    def stop(self):
        self.stop_calls += 1
        self.events.append('diverter-stop')
        return True

    def wait_for_capture_failure(self, timeout):
        return self.failure.wait(timeout)


class FakenetStopLifecycleTests(unittest.TestCase):
    def _fakenet(self):
        events = []
        fakenet = Fakenet(logging.ERROR)
        fakenet.policy_mode = True
        fakenet.diverter = Diverter(events)
        fakenet.running_listener_providers = [
            Listener('one', events), Listener('two', events)]
        return fakenet, events

    def test_policy_stop_is_ordered_and_idempotent(self):
        fakenet, events = self._fakenet()

        self.assertTrue(fakenet.stop())
        self.assertTrue(fakenet.stop())

        self.assertEqual([
            'policy-suspend', 'listener-two', 'listener-one', 'diverter-stop'
        ], events)
        self.assertEqual(1, fakenet.diverter.stop_calls)

    def test_wait_for_capture_failure_delegates_to_diverter(self):
        fakenet, unused = self._fakenet()
        fakenet.diverter.failure.set()

        self.assertTrue(fakenet.wait_for_capture_failure(0))

    def test_control_loop_returns_nonzero_on_capture_failure_with_100ms_wait(self):
        fake = types.SimpleNamespace()
        fake.logger = logging.getLogger('fakenet-loop-test')
        fake.waits = []

        def wait(timeout):
            fake.waits.append(timeout)
            return True

        fake.wait_for_capture_failure = wait

        self.assertEqual(1, wait_for_shutdown(fake))
        self.assertEqual([0.1], fake.waits)

    def test_start_without_diverter_assigns_listener_bind_address(self):
        fakenet = Fakenet(logging.ERROR)
        fakenet.fakenet_config = {'diverttraffic': 'no'}
        fakenet.diverter_config = {
            'externalaccesspolicy': 'disabled',
            'networkmode': 'singlehost',
        }
        fakenet.listeners_config = {
            'AnonymousTCPListener': {
                'port': 1337,
                'protocol': 'TCP',
            },
        }

        fakenet.start()

        self.assertIsNone(fakenet.diverter)
        self.assertEqual(
            '0.0.0.0',
            fakenet.listeners_config['AnonymousTCPListener']['ipaddr'])


if __name__ == '__main__':
    unittest.main()
