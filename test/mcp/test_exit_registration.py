"""Registration ownership must survive partial install and external drift."""
import copy
import pytest
from fakenet.mcp.exit_registration import install, restore, IFEO, SPE


class Registry:
    def __init__(self):
        self.values = {(IFEO, 'GlobalFlag'): (4, 16), (SPE, 'Unrelated'): (1, 'keep')}
        self.keys = {IFEO, SPE}
        self.writes = 0
        self.fail_at = None

    def read(self, key, name):
        return self.values.get((key, name))

    def write(self, key, name, value):
        self.writes += 1
        if self.writes == self.fail_at:
            raise OSError('injected registry write failure')
        self.keys.add(key)
        self.values[key, name] = tuple(value)

    def delete_value(self, key, name):
        del self.values[key, name]

    def missing_keys(self):
        return [key for key in (IFEO, SPE) if key not in self.keys]

    def delete_empty_key(self, key):
        if not any(k == key for k, _ in self.values):
            self.keys.discard(key)


def test_restore_preserves_unrelated_flags_values_and_original_types(tmp_path):
    reg = Registry(); original = copy.deepcopy(reg.values)
    record = tmp_path / 'registration.json'
    install(reg, record, tmp_path / 'monitor.exe')
    assert reg.read(IFEO, 'GlobalFlag') == (4, 528)
    assert reg.read(SPE, 'ReportingMode') == (4, 1)
    assert reg.read(SPE, 'IgnoreSelfExits') == (4, 0)
    restore(reg, record)
    assert reg.values == original
    assert record.exists()  # Ownership history is retained, not erased.


def test_existing_exit_monitor_is_not_overwritten(tmp_path):
    reg = Registry(); reg.values[SPE, 'MonitorProcess'] = (1, 'external.exe')
    before = copy.deepcopy(reg.values)
    with pytest.raises(RuntimeError, match='external'):
        install(reg, tmp_path / 'registration.json', tmp_path / 'monitor.exe')
    assert reg.values == before and reg.writes == 0


def test_partial_install_rolls_back_only_owned_changes(tmp_path):
    reg = Registry(); original = copy.deepcopy(reg.values); reg.fail_at = 3
    record = tmp_path / 'registration.json'
    with pytest.raises(OSError, match='injected'):
        install(reg, record, tmp_path / 'monitor.exe')
    assert reg.values == original
    assert record.exists()


def test_external_drift_blocks_restore_before_any_other_mutation(tmp_path):
    reg = Registry(); record = tmp_path / 'registration.json'
    install(reg, record, tmp_path / 'monitor.exe')
    reg.values[SPE, 'MonitorProcess'] = (1, 'changed-after-install.exe')
    before = copy.deepcopy(reg.values)
    with pytest.raises(RuntimeError, match='drift'):
        restore(reg, record)
    assert reg.values == before


def test_reinstall_matches_existing_owner_without_new_writes(tmp_path):
    reg = Registry(); record = tmp_path / 'registration.json'; exe = tmp_path / 'monitor.exe'
    install(reg, record, exe); writes = reg.writes
    install(reg, record, exe)
    assert reg.writes == writes


def test_monitor_flag_never_enables_before_target_only_reporting(tmp_path):
    class ObservedRegistry(Registry):
        def write(self, key, name, value):
            if (key, name) == (IFEO, 'GlobalFlag') and value[1] & 0x200:
                assert self.read(SPE, 'ReportingMode') == (4, 1)
                assert self.read(SPE, 'IgnoreSelfExits') == (4, 0)
                assert self.read(SPE, 'MonitorProcess') is not None
            if (key, name) == (SPE, 'ReportingMode'):
                assert not self.read(IFEO, 'GlobalFlag')[1] & 0x200
            super().write(key, name, value)

        def delete_value(self, key, name):
            if key == SPE:
                assert not self.read(IFEO, 'GlobalFlag')[1] & 0x200
            super().delete_value(key, name)
    reg = ObservedRegistry(); record = tmp_path / 'registration.json'
    install(reg, record, tmp_path / 'monitor.exe')
    restore(reg, record)
