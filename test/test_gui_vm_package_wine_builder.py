import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / 'tools' / 'build_gui_vm_package_wine.py'
SPEC = importlib.util.spec_from_file_location('formal_wine_builder', BUILDER)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def test_internal_stage_directory_is_ascii_for_wine():
    assert builder.STAGE_DIRECTORY == 'stage'
    assert builder.STAGE_DIRECTORY.isascii()
    assert '/' not in builder.STAGE_DIRECTORY
    assert '\\' not in builder.STAGE_DIRECTORY


def test_wine_python_commands_pin_reviewed_xvfb_geometry():
    command = builder.wine_command(['-c', 'print(1)'])
    assert command[:6] == [
        'xvfb-run', '-a', '-s', '-screen 0 1920x1080x24',
        'wine', builder.WINDOWS_PYTHON]
    assert command[6:] == ['-c', 'print(1)']


def test_formal_wine_builder_is_v35_and_uses_immutable_source():
    text = BUILDER.read_text(encoding='utf-8')
    assert builder.PACKAGE_VERSION == 'v35'
    assert builder.PLAN_VERSION == '2026.08.27-01 v0.3'
    assert builder.PLAN_BLOB == '88406db0d83b44f6c0258cadfd08d82efae2a685'
    plan = (ROOT / 'PLAN' / '2026.08.27' /
            '2026.08.27-01-PCAP捕获完整性与双向载荷HTML报告修复方案.md')
    # Wine's Z: drive cannot reliably address this Chinese filename.  The
    # actual builder is Linux Python and verify_source() always hashes it;
    # Windows-Python regression still asserts the frozen reviewed identity.
    if plan.is_file():
        assert builder.git_blob_sha1(plan) == builder.PLAN_BLOB
    else:
        assert os.name == 'nt'
    assert "'source_snapshot_mode': 'commit'" in text
    assert 'Refusing to overwrite' in text
    assert 'fakenet.payload-report.v1' in text
    assert "'capture_queue': 'length=8192;time_ms=2048'" in text
    assert 'size_bytes=33554432' not in text


def test_formal_wine_entry_requires_pinned_image_and_scoped_output():
    shell = (ROOT / 'Build-GuiVmPackage.sh').read_text(encoding='utf-8')
    assert 'docker image inspect' in shell
    assert 'gui-vm-diagnostic-builder:py3119-pyi6220' in shell
    assert 'to_container_path' in shell
    assert 'v35-r' in BUILDER.read_text(encoding='utf-8')


def test_archived_regression_gate_precedes_pyinstaller_and_is_split():
    text = BUILDER.read_text(encoding='utf-8')
    gate = text.index('regression = run_windows_regression_gate(stage, build_root)')
    pyinstaller = text.index("'-m', 'PyInstaller', 'fakenet.spec'")
    assert gate < pyinstaller
    assert "'--ignore=%s' % path for path in HTTP_CONFLICT_TESTS" in text
    assert '--junitxml' in text
    assert 'pydivert-2.1.0-py2.py3-none-any.whl' in text
    assert 'EXPECTED_SKIP_MODULES' in text
    assert 'Windows-Python command failed' in text


def test_onedir_is_flattened_before_root_pe_validation():
    text = BUILDER.read_text(encoding='utf-8')
    collect = text.index("collect_dir = stage / 'fakenet-dat'")
    flatten = text.index("shutil.move(str(item), str(destination_item))")
    pe_check = text.index("fakenet_exe = stage / 'fakenet.exe'")
    assert collect < flatten < pe_check


def test_junit_summary_exposes_exact_skip_set_for_failure_gate():
    xml = '''<?xml version="1.0"?>
<testsuites><testsuite tests="3" failures="0" errors="0" skipped="2">
  <testcase classname="test.test_gui_configmodel.ConfigModelTests" name="test_locale">
    <skipped message="locale" />
  </testcase>
  <testcase classname="test.test_gui_vm_acceptance.AcceptanceTests" name="test_script">
    <skipped message="wine" />
  </testcase>
  <testcase classname="test.test_payload_report.PayloadReportTests" name="test_ok" />
</testsuite></testsuites>'''
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'results.xml'
        path.write_text(xml, encoding='utf-8')
        summary = builder._junit_summary(path)
    assert summary['tests'] == 3
    assert summary['passed'] == 1
    assert summary['skipped'] == 2
    assert any('test_gui_configmodel' in item
               for item in summary['skip_tests'])
    assert any('test_gui_vm_acceptance' in item
               for item in summary['skip_tests'])


def test_regression_gate_failure_blocks_pyinstaller_without_real_build():
    with tempfile.TemporaryDirectory() as directory:
        stage = Path(directory) / 'stage'
        (stage / 'wheelhouse').mkdir(parents=True)
        shutil.copy2(
            ROOT / 'wheelhouse' / 'pydivert-2.1.0-py2.py3-none-any.whl',
            stage / 'wheelhouse' / 'pydivert-2.1.0-py2.py3-none-any.whl')
        with mock.patch.object(builder, 'wine_path',
                               return_value='Z:/pydivert21'), \
                mock.patch.object(
                    builder, 'wine_python_logged',
                    side_effect=RuntimeError('regression gate failed')) as run:
            try:
                builder.run_windows_regression_gate(stage, Path(directory))
            except RuntimeError as exc:
                assert 'regression gate failed' in str(exc)
            else:
                raise AssertionError('regression failure was not propagated')
            assert run.call_count == 1


def test_independent_zip_verifier_checks_manifest_hashes_and_timestamp():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        stage = root / 'stage'
        stage.mkdir()
        payload = b'payload\n'
        (stage / 'payload.txt').write_bytes(payload)
        manifest = {
            'source_commit': 'a' * 40,
            'plan_version': builder.PLAN_VERSION,
            'plan_blob': builder.PLAN_BLOB,
            'files': [{
                'path': 'payload.txt', 'size': len(payload),
                'sha256': hashlib.sha256(payload).hexdigest(),
            }],
        }
        (stage / 'gui-vm-manifest.json').write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + '\n',
            encoding='utf-8')
        archive = root / 'package.zip'
        output = root / 'verification.json'

        builder.write_deterministic_zip(stage, archive)
        result = builder.verify_package_zip(archive, manifest, output)

        assert result['verdict'] == 'PASS'
        assert result['plan_blob'] == builder.PLAN_BLOB
        assert result['verified_files'] == 1
        assert json.loads(output.read_text(encoding='utf-8')) == result
