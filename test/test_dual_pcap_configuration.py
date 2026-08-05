import configparser
import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[1]


class DualPcapConfigurationTests(unittest.TestCase):
    def _dump_value(self, relative):
        config = configparser.ConfigParser()
        config.read(ROOT / relative)
        return config.getboolean('Diverter', 'DumpPackets')

    def test_general_profiles_enable_paired_capture(self):
        self.assertTrue(self._dump_value('fakenet/configs/default.ini'))
        self.assertTrue(self._dump_value('fakenet/configs/debug.ini'))
        self.assertTrue(self._dump_value('test/template.ini'))

    def test_reviewed_policy_profiles_remain_capture_disabled(self):
        for relative in (
                'fakenet/configs/burp.ini',
                'fakenet/configs/domain_allowlist_windows.ini',
                'fakenet/configs/domain_reviewed_ipv4_windows.ini',
                'fakenet/configs/domain_takeover_windows.ini'):
            with self.subTest(relative=relative):
                self.assertFalse(self._dump_value(relative))

    def test_platforms_no_longer_close_a_single_legacy_writer(self):
        for relative in ('fakenet/diverters/windows.py',
                         'fakenet/diverters/linux.py'):
            text = (ROOT / relative).read_text(encoding='utf-8')
            self.assertNotIn('self.pcap', text)
            self.assertNotIn('pcap_lock', text)


if __name__ == '__main__':
    unittest.main()
