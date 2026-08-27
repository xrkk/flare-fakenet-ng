from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_core_spec_is_true_onedir():
    source = (ROOT / 'fakenet.spec').read_text(encoding='utf-8')

    assert 'exclude_binaries=True' in source
    assert 'COLLECT(exe,' in source
    assert 'a.binaries + driver_files' in source.split('COLLECT(exe,', 1)[1]
    assert "name='fakenet-dat'" in source


def test_vm_builder_flattens_onedir_to_package_root():
    source = (ROOT / 'Build-GuiVmPackage.ps1').read_text(
        encoding='utf-8-sig')

    for marker in (
            "'v35'", "'2026.08.27-01 v0.2'",
            "'0bd8aea9a56d97f165b05e5fc6a68b08f06b4d20'",
            "Join-Path $stage 'fakenet-dat'",
            'Move-Item -LiteralPath $item.FullName -Destination $stage',
            "Join-Path $stage '_internal'",
            "'pyinstaller-onedir'",
            "'test/gui_vm/Run-Tests.cmd'",
            'Run-SamplePayloadAcceptance.cmd',
            "'fakenet.payload-report.v1'",
            "run_formal_stop_acceptance.py",
            "verify_reassembly.py", "generate_payload_report_fixture.py",
            "tools\\replay_sample_payload.py"):
        assert marker in source
    assert "} else { 'pyinstaller-onefile' })" not in source


def test_release_workflow_copies_complete_onedir_payload():
    source = (ROOT / '.github' / 'workflows' / 'build.yaml').read_text(
        encoding='utf-8')

    assert 'dist\\fakenet-dat\\fakenet.exe' in source
    assert 'dist\\fakenet-dat\\_internal' in source
    assert 'Copy-Item "dist\\fakenet-dat\\*"' in source
    assert 'Copy-Item "dist\\fakenet.exe"' not in source
