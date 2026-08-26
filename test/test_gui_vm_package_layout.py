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
            "'v34'", "'2026.08.26-01 v0.7'",
            "Join-Path $stage 'fakenet-dat'",
            'Move-Item -LiteralPath $item.FullName -Destination $stage',
            "Join-Path $stage '_internal'",
            "'pyinstaller-onedir'",
            "'test/gui_vm/Run-Tests.cmd'",
            "run_formal_stop_acceptance.py"):
        assert marker in source
    assert "} else { 'pyinstaller-onefile' })" not in source


def test_release_workflow_copies_complete_onedir_payload():
    source = (ROOT / '.github' / 'workflows' / 'build.yaml').read_text(
        encoding='utf-8')

    assert 'dist\\fakenet-dat\\fakenet.exe' in source
    assert 'dist\\fakenet-dat\\_internal' in source
    assert 'Copy-Item "dist\\fakenet-dat\\*"' in source
    assert 'Copy-Item "dist\\fakenet.exe"' not in source
