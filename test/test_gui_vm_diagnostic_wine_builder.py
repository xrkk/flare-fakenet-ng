import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class DiagnosticWineBuilderTests(unittest.TestCase):
    def test_image_uses_windows_python_and_pinned_pyinstaller(self):
        dockerfile = (ROOT / 'tools' / 'docker' / 'gui-vm-diagnostic' /
                      'Dockerfile').read_text(encoding='utf-8')
        for marker in (
                'FROM vpb/ubuntu-base:24.04-local',
                'PYTHON_VERSION=3.11.9',
                '5ee42c4eee1e6b4464bb23722f90b45303f79442df63083f05322f1785f5fdde',
                'C:\\\\Python311\\\\python.exe',
                'netifaces-plus==0.12.5',
                'pydivert==2.0.9', 'pyinstaller==6.22.0',
                'pytest==8.3.5',
                'ENTRYPOINT ["/usr/bin/tini", "--"]',
                'chown -R "${HOST_UID}:${HOST_GID}"',
                'sha256sum -c -'):
            self.assertIn(marker, dockerfile)

    def test_wrapper_builds_without_privileged_or_host_network(self):
        wrapper = (ROOT / 'Build-GuiVmDiagnosticPackage.sh').read_text(
            encoding='utf-8')
        self.assertIn('docker build', wrapper)
        self.assertIn('docker run --rm', wrapper)
        self.assertIn('--build-arg "HOST_UID=$(id -u)"', wrapper)
        self.assertIn('sha256sum --check', wrapper)
        self.assertIn('--source-commit HEAD', wrapper)
        self.assertIn('--worktree-overlay', wrapper)
        self.assertIn("MODE=\"${1:-package}\"", wrapper)
        self.assertIn("MODE\" == '--image-only'", wrapper)
        self.assertNotIn('--privileged', wrapper)
        self.assertNotIn('--network host', wrapper)

    def test_builder_refuses_overwrite_and_checks_pe_and_markers(self):
        builder = (ROOT / 'tools' /
                   'build_gui_vm_diagnostic_wine.py').read_text(
                       encoding='utf-8')
        for marker in (
                'Refusing to overwrite', "!= b'MZ'",
                "PACKAGE_VERSION = 'v33-diagnostic-03'",
                'STOP_PHASE_BEGIN phase=complete',
                'STOP_PROVIDER_BEGIN name=%s',
                'probe_takeover_path', 'diagnostic-results-',
                'prepare_diagnostic_core_spec',
                'Core spec onedir markers missing',
                'stop_trace_runtime_hook.py',
                "'core_bundle_mode': 'pyinstaller-onefile-diagnostic-debug'",
                "'core_bootloader_debug': True",
                "'source_overlay_files': overlay_rows",
                'core_work.mkdir()', 'gui_work.mkdir()',
                "'source_commit': resolved",
                "'acceptance_entry': 'test/gui_vm/Run-Diagnostics.cmd'"):
            self.assertIn(marker, builder)


if __name__ == '__main__':
    unittest.main()
