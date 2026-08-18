# -*- coding: utf-8 -*-
"""configmodel read/write fidelity tests (plan v0.2 §6, two-layer view)."""

import os
import locale

import pytest

from fakenet.gui import configmodel
from fakenet.fakenet import Fakenet

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIGS = os.path.join(REPO, 'fakenet', 'configs')

MAIN_INIS = (
    'default.ini', 'burp.ini', 'debug.ini',
    'egress_control_windows.ini', 'domain_reviewed_ipv4_windows.ini',
    'domain_takeover_windows.ini', 'process_redirect_windows.ini',
)


def _fakenet_view(path):
    """fakenet's own view of a config file. parse_config() already runs
    expand_listeners() internally (fakenet.py:113)."""
    fn = Fakenet()
    fn.parse_config(path)
    return fn


@pytest.mark.parametrize('name', MAIN_INIS)
def test_round_trip_fakenet_view(name, tmp_path):
    """Layer 1: saved output reparses through fakenet's own loader with
    identical enabled sections, keys and port expansion."""
    source = os.path.join(CONFIGS, name)
    model = configmodel.ConfigModel.load(source)
    saved = str(tmp_path.joinpath(name))
    model.save(saved)

    before = _fakenet_view(source)
    after = _fakenet_view(saved)

    assert list(after.listeners_config.keys()) == \
        list(before.listeners_config.keys()), name
    for section, orig_items in before.listeners_config.items():
        new_items = after.listeners_config[section]
        assert sorted(k.lower() for k in new_items) == \
            sorted(k.lower() for k in orig_items), (name, section)
        for key, value in orig_items.items():
            if key == 'port':
                assert int(new_items[key]) == int(value), (name, section)
            else:
                assert new_items[key] == value, (name, section, key)
    assert sorted(k.lower() for k in after.diverter_config) == \
        sorted(k.lower() for k in before.diverter_config)
    assert sorted(k.lower() for k in after.fakenet_config) == \
        sorted(k.lower() for k in before.fakenet_config)


@pytest.mark.parametrize('name', MAIN_INIS + ('sample_custom_response.ini',))
def test_round_trip_editor_view(name, tmp_path):
    """Layer 2: every section (incl. Enabled False) is preserved losslessly."""
    source = os.path.join(CONFIGS, name)
    model = configmodel.ConfigModel.load(source)
    if name == 'sample_custom_response.ini':
        model.kind = 'custom'  # [Example*] sections must not gain Enabled
    saved = str(tmp_path.joinpath(name))
    model.save(saved)
    reloaded = configmodel.ConfigModel.load(saved)

    assert list(reloaded.sections.keys()) == list(model.sections.keys())
    for sec_name, sec in model.sections.items():
        new_sec = reloaded.section(sec_name)
        assert [k.lower() for k in new_sec.keys()] == \
            [k.lower() for k in sec.keys()], sec_name
        for key, value in sec.items():
            assert new_sec.get(key) == value, (sec_name, key)


def test_percent_escaping_round_trip(tmp_path):
    model = configmodel.ConfigModel.new_config()
    model.diverter().set('DumpPacketsFilePrefix', 'a%b')
    path = str(tmp_path.joinpath('pct.ini'))
    model.save(path)
    with open(path, 'rb') as handle:
        raw = handle.read().decode('ascii')
    assert 'a%%b' in raw, 'logical % must be written as %%'
    reloaded = configmodel.ConfigModel.load(path)
    assert reloaded.diverter().get('DumpPacketsFilePrefix') == 'a%b'
    # fakenet reads with BasicInterpolation -> sees the logical value.
    import configparser
    parser = configparser.ConfigParser()  # default interpolation
    parser.read(path)
    assert parser.get('Diverter', 'dumppacketsfileprefix') == 'a%b'


def test_boolean_literals_normalised(tmp_path):
    model = configmodel.ConfigModel.load(os.path.join(CONFIGS,
                                                      'default.ini'))
    # Push non-canonical spellings through the model.
    model.diverter().set('DumpPackets', 'on')
    for sec in model.listener_sections():
        sec.set('Enabled', 'yes')
    http = model.section('HTTPListener443')
    http.set('UseSSL', 'true')
    path = str(tmp_path.joinpath('bool.ini'))
    model.save(path)
    reloaded = configmodel.ConfigModel.load(path)
    assert reloaded.diverter().get('DumpPackets') == 'Yes'
    assert http is not None and reloaded.section('HTTPListener443') \
        .get('UseSSL') == 'Yes'
    for sec in reloaded.listener_sections():
        assert sec.get('Enabled') in ('True', 'False')


def test_enabled_always_written(tmp_path):
    model = configmodel.ConfigModel.new_config()
    sec = model.ensure_section('MyListener')
    sec.set('Port', '8080')
    sec.set('Protocol', 'TCP')
    path = str(tmp_path.joinpath('enabled.ini'))
    model.save(path)
    fn = _fakenet_view(path)  # must not raise NoOptionError
    assert 'mylistener' in [k.lower() for k in fn.listeners_config]


def test_unknown_keys_preserved(tmp_path):
    model = configmodel.ConfigModel.new_config()
    model.diverter().set('SomeFutureKey', 'value')
    sec = model.ensure_section('Weird')
    sec.set('Port', '9')
    sec.set('Protocol', 'UDP')
    sec.set('MysteryOption', '42')
    path = str(tmp_path.joinpath('unknown.ini'))
    model.save(path)
    reloaded = configmodel.ConfigModel.load(path)
    assert reloaded.diverter().get('SomeFutureKey') == 'value'
    assert reloaded.section('Weird').get('MysteryOption') == '42'


def test_section_name_case_preserved(tmp_path):
    model = configmodel.ConfigModel.new_config()
    path = str(tmp_path.joinpath('case.ini'))
    model.save(path)
    with open(path, 'r', encoding='ascii') as handle:
        text = handle.read()
    assert '[FakeNet]' in text and '[Diverter]' in text


def test_gbk_source_round_trip(tmp_path):
    if locale.getpreferredencoding(False).lower() not in (
            'cp936', 'gbk', 'gb2312'):
        pytest.skip('host locale is not GBK family')
    banner = '中文件横幅'
    raw = ('[FTPListener21]\nEnabled: True\nPort: 21\nProtocol: TCP\n'
           'Listener: FTPListener\nBanner: %s\n' % banner).encode('gbk')
    path = str(tmp_path.joinpath('gbk.ini'))
    with open(path, 'wb') as handle:
        handle.write(raw)
    model = configmodel.ConfigModel.load(path)
    assert model.encoding == 'locale'
    assert model.section('FTPListener21').get('Banner') == banner
    model.save(path)
    with open(path, 'rb') as handle:
        assert handle.read() == raw  # byte-identical when nothing changed


def test_utf8_bom_preserved(tmp_path):
    banner = '横幅'
    raw = ('[FTPListener21]\nEnabled: True\nPort: 21\n'
           'Protocol: TCP\nListener: FTPListener\nBanner: %s\n'
           % banner).encode('utf-8-sig')  # utf-8-sig prepends the BOM
    path = str(tmp_path.joinpath('bom.ini'))
    with open(path, 'wb') as handle:
        handle.write(raw)
    model = configmodel.ConfigModel.load(path)
    assert model.encoding == 'utf-8-sig' and model.bom
    assert model.section('FTPListener21').get('Banner') == banner
    model.save(path)
    with open(path, 'rb') as handle:
        data = handle.read()
    assert data.startswith(b'\xef\xbb\xbf')


def test_new_file_ascii_no_bom_crlf(tmp_path):
    model = configmodel.ConfigModel.new_config()
    path = str(tmp_path.joinpath('new.ini'))
    model.save(path)
    with open(path, 'rb') as handle:
        data = handle.read()
    assert not data.startswith(b'\xef\xbb\xbf')
    assert b'\r\n' in data
    data.decode('ascii')


def test_external_modification_guard(tmp_path):
    model = configmodel.ConfigModel.new_config()
    path = str(tmp_path.joinpath('guard.ini'))
    model.save(path)
    stamp = model.mtime + 50
    os.utime(path, (stamp, stamp))
    with pytest.raises(configmodel.ExternalModifiedError):
        model.save(path)


def test_port_expansion_matches_fakenet():
    assert configmodel.expand_ports('80') == [80]
    assert configmodel.expand_ports('60000-60010') == \
        list(range(60000, 60011))
    assert configmodel.expand_ports('67, 68, 137') == [67, 68, 137]
    model = configmodel.ConfigModel.load(os.path.join(CONFIGS,
                                                      'default.ini'))
    pasv = model.section('FTPListenerPASV')
    names = model.expanded_listener_names(pasv)
    expected = ['FTPListenerPASV_%d' % port for port in range(60000, 60011)]
    assert names == expected
    fn = _fakenet_view(os.path.join(CONFIGS, 'default.ini'))
    assert names == [name for name in fn.listeners_config
                     if name.startswith('FTPListenerPASV')]
