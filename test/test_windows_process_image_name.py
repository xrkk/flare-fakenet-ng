import logging
import unittest
from unittest import mock

from fakenet.diverters import winutil


class ProcessImageNameTests(unittest.TestCase):
    def test_unicode_process_path_uses_wide_windows_api_without_utf8_decode(self):
        observed = {'closed': []}

        class Kernel32(object):
            @staticmethod
            def OpenProcess(access, inherit, pid):
                return 123

            @staticmethod
            def CloseHandle(handle):
                observed['closed'].append(handle)
                return True

        class Psapi(object):
            @staticmethod
            def GetProcessImageFileNameW(handle, buffer, size):
                buffer.value = (
                    r'\Device\HarddiskVolume3\样本分析\reviewed-client.exe')
                return len(buffer.value)

        fake_windll = mock.Mock(kernel32=Kernel32(), psapi=Psapi())
        helper = winutil.WinUtilMixin.__new__(winutil.WinUtilMixin)
        helper.logger = logging.getLogger(__name__)

        with mock.patch.object(winutil, 'windll', fake_windll):
            self.assertEqual(
                'reviewed-client.exe', helper.get_process_image_filename(321))

        self.assertEqual([123], observed['closed'])


if __name__ == '__main__':
    unittest.main()
