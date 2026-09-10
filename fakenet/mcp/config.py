# Copyright 2026 Google LLC
"""Deployment configuration for fakenetng-mcp (configs\\service.json).

Values are deployment inputs (REQ-015): nothing about a specific VM is
hard-coded; install writes this file from explicit CLI arguments.
"""

import json
from pathlib import Path

from fakenet.mcp import paths

REQUIRED_FIELDS = ('listen_ip', 'listen_port', 'allowed_host_ips')
DEFAULT_PORT = 28788


class ConfigError(ValueError):
    pass


class ServiceConfig:

    def __init__(self, listen_ip, listen_port, allowed_host_ips,
                 log_level='INFO', extra_control_ports=None,
                 stop_grace_seconds=60, source=None,
                 allow_legacy_protocol=False):
        if not isinstance(listen_ip, str) or not listen_ip.strip():
            raise ConfigError('listen_ip must be a non-empty string')
        listen_ip = listen_ip.strip()
        if listen_ip in ('0.0.0.0', '::'):
            raise ConfigError(
                'listen_ip must be a specific host-only address, not %r' % listen_ip)
        if not isinstance(listen_port, int) or not (1 <= listen_port <= 65535):
            raise ConfigError('listen_port must be an integer in 1..65535')
        if isinstance(allowed_host_ips, str):
            allowed_host_ips = [allowed_host_ips]
        if (not isinstance(allowed_host_ips, list) or not allowed_host_ips or
                not all(isinstance(item, str) and item.strip()
                        for item in allowed_host_ips)):
            raise ConfigError('allowed_host_ips must be a non-empty list of strings')
        self.listen_ip = listen_ip
        self.listen_port = int(listen_port)
        self.allowed_host_ips = [item.strip() for item in allowed_host_ips]
        self.log_level = str(log_level or 'INFO').upper()
        if extra_control_ports is None:
            extra_control_ports = []
        if isinstance(extra_control_ports, bool):
            raise ConfigError('extra control ports must be integers in 1..65535')
        if isinstance(extra_control_ports, int):
            extra_control_ports = [extra_control_ports]
        if not isinstance(extra_control_ports, (list, tuple)):
            raise ConfigError('extra control ports must be a list of integers')
        clean_ports = []
        for item in extra_control_ports:
            # Rejecting illegal types keeps the protection parameter an input
            # contract: a coercion would silently invent a bound port.
            if isinstance(item, bool) or not isinstance(item, int):
                raise ConfigError('extra control ports must be integers in 1..65535')
            if not (1 <= item <= 65535):
                raise ConfigError('extra control ports must be in 1..65535')
            if item != int(listen_port) and item not in clean_ports:
                clean_ports.append(item)
        self.extra_control_ports = clean_ports
        grace = int(stop_grace_seconds if stop_grace_seconds is not None
                    else 60)
        if not (5 <= grace <= 600):
            raise ConfigError('stop_grace_seconds must be in 5..600')
        self.stop_grace_seconds = grace
        if not isinstance(allow_legacy_protocol, bool):
            raise ConfigError('allow_legacy_protocol must be a boolean')
        self.allow_legacy_protocol = allow_legacy_protocol
        self.source = str(source) if source else None

    def to_dict(self):
        return {
            'listen_ip': self.listen_ip,
            'listen_port': self.listen_port,
            'allowed_host_ips': list(self.allowed_host_ips),
            'log_level': self.log_level,
            'extra_control_ports': list(self.extra_control_ports),
            'stop_grace_seconds': self.stop_grace_seconds,
            'allow_legacy_protocol': self.allow_legacy_protocol,
        }

    @classmethod
    def from_dict(cls, data, source=None):
        missing = [field for field in REQUIRED_FIELDS if field not in data]
        if missing:
            raise ConfigError('service config missing fields: %s' % ', '.join(missing))
        return cls(
            listen_ip=data['listen_ip'],
            listen_port=data['listen_port'],
            allowed_host_ips=data['allowed_host_ips'],
            log_level=data.get('log_level', 'INFO'),
            extra_control_ports=data.get('extra_control_ports', []),
            stop_grace_seconds=data.get('stop_grace_seconds', 60),
            source=source,
            allow_legacy_protocol=data.get('allow_legacy_protocol', False),
        )

    @classmethod
    def load(cls, config_path=None):
        path = Path(config_path) if config_path else paths.service_config_path()
        if not path.is_file():
            raise ConfigError('service config not found: %s' % path)
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise ConfigError('service config unreadable (%s): %s' % (path, exc))
        if not isinstance(data, dict):
            raise ConfigError('service config must be a JSON object: %s' % path)
        return cls.from_dict(data, source=str(path))

    def save(self, config_path=None):
        """Atomically write the deployment config (temp file + replace)."""
        import os
        import tempfile

        target = Path(config_path) if config_path else paths.service_config_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        handle, tmp_name = tempfile.mkstemp(
            dir=str(target.parent), prefix='.service-', suffix='.json')
        try:
            with os.fdopen(handle, 'w', encoding='utf-8') as stream:
                json.dump(self.to_dict(), stream, indent=2)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp_name, target)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
