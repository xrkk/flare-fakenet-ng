# Copyright 2026 Google LLC
"""ServiceConfig behavior (P01 IMP-P01-03)."""

import json

import pytest

from fakenet.mcp.config import ConfigError, ServiceConfig


def test_valid_config_roundtrip(tmp_path):
    cfg = ServiceConfig(listen_ip='192.168.204.149', listen_port=28788,
                        allowed_host_ips=['192.168.204.1'])
    path = tmp_path / 'service.json'
    cfg.save(path)
    loaded = ServiceConfig.load(path)
    assert loaded.listen_ip == '192.168.204.149'
    assert loaded.listen_port == 28788
    assert loaded.allowed_host_ips == ['192.168.204.1']


def test_zero_wildcard_listen_rejected():
    with pytest.raises(ConfigError):
        ServiceConfig(listen_ip='0.0.0.0', listen_port=28788,
                      allowed_host_ips=['192.168.204.1'])
    with pytest.raises(ConfigError):
        ServiceConfig(listen_ip='::', listen_port=28788,
                      allowed_host_ips=['192.168.204.1'])


def test_port_bounds_enforced():
    for bad in (0, -1, 65536, 'x'):
        with pytest.raises(ConfigError):
            ServiceConfig(listen_ip='10.0.0.1', listen_port=bad,
                          allowed_host_ips=['10.0.0.2'])


def test_allowed_hosts_must_be_nonempty_list():
    with pytest.raises(ConfigError):
        ServiceConfig(listen_ip='10.0.0.1', listen_port=28788,
                      allowed_host_ips=[])
    with pytest.raises(ConfigError):
        ServiceConfig(listen_ip='10.0.0.1', listen_port=28788,
                      allowed_host_ips=['  '])


def test_load_missing_file_and_fields(tmp_path):
    with pytest.raises(ConfigError):
        ServiceConfig.load(tmp_path / 'absent.json')
    partial = tmp_path / 'partial.json'
    partial.write_text(json.dumps({'listen_ip': '10.0.0.1'}), encoding='utf-8')
    with pytest.raises(ConfigError):
        ServiceConfig.load(partial)


def test_save_is_atomic_and_replaces(tmp_path):
    cfg = ServiceConfig(listen_ip='10.0.0.1', listen_port=1,
                        allowed_host_ips=['10.0.0.2'])
    path = tmp_path / 'service.json'
    cfg.save(path)
    cfg.listen_port = 2
    cfg.save(path)
    assert json.loads(path.read_text(encoding='utf-8'))['listen_port'] == 2
    leftovers = [item.name for item in tmp_path.iterdir()
                 if item.name != 'service.json']
    assert leftovers == []
