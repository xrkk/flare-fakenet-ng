"""Host MCP stdio facade for one-call egress isolation verification.

The facade is launched by the MCP client over stdio.  It exposes exactly one
tool and uses fixed configuration plus fixed clients; the AI supplies only a
canonical command_id.  No HTTP listener, daemon or reverse callback is added.
"""
from __future__ import annotations

import argparse
import base64
import configparser
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
import urllib.parse
import urllib.request
import uuid

import anyio
from contextlib import asynccontextmanager
import httpx2 as httpx
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from fakenet.mcp import MCP_PACKAGE_VERSION, egress_contract, host_merge, \
    host_probe, schemas
from fakenet.mcp.host_provider import HostProvider
from fakenet.mcp.host_state import HostStateError, HostStateStore

PROTOCOL_VERSION = '2026-07-28'
DEFAULT_COMPACT_LIMIT = 65536


class HostFacadeError(RuntimeError):
    def __init__(self, code, message, detail=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail or {}



def _auth_headers(specification):
    """Resolve only explicit environment references, never literal credentials.

    Values stay inside the transport and are not included in config, intent,
    result or evidence. Missing/invalid references refuse the request before IO.
    """
    refs = specification.get('auth_headers_env') or {}
    if not isinstance(refs, dict):
        raise HostFacadeError('invalid_request', 'auth header references invalid')
    allowed = {'authorization': 'Authorization', 'x-api-key': 'X-API-Key'}
    result = {}
    import os as _os
    import re as _re
    def resolve(name):
        if not isinstance(name, str) or not _re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', name):
            raise HostFacadeError('invalid_request', 'auth environment reference invalid')
        value = _os.environ.get(name)
        if not value or len(value) > 8192 or not value.isascii() or '\x00' in value or '\r' in value or '\n' in value:
            raise HostFacadeError('invalid_request', 'auth environment reference unavailable')
        return value
    profile = specification.get('mcp_auth_ref')
    if profile is not None:
        import stat as _stat
        import tomllib as _tomllib
        if not isinstance(profile, dict) or set(profile) != {'path', 'server'}:
            raise HostFacadeError('invalid_request', 'MCP auth reference invalid')
        path = Path(str(profile['path']))
        try:
            if not path.is_absolute():
                raise ValueError('absolute reference required')
            fd = _os.open(path, _os.O_RDONLY | _os.O_NOFOLLOW | _os.O_CLOEXEC)
            try:
                before = _os.fstat(fd)
                if (not _stat.S_ISREG(before.st_mode) or
                        before.st_uid != _os.geteuid() or before.st_mode & 0o022 or
                        before.st_size > 1024 * 1024):
                    raise ValueError('unsafe credential reference')
                raw = b''
                while len(raw) <= 1024 * 1024:
                    chunk = _os.read(fd, min(65536, 1024 * 1024 + 1 - len(raw)))
                    if not chunk:
                        break
                    raw += chunk
                after = _os.fstat(fd)
                if len(raw) > 1024 * 1024 or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise ValueError('credential reference changed')
            finally:
                _os.close(fd)
            node = _tomllib.loads(raw.decode('utf8'))['mcp_servers'][profile['server']]
            if node.get('url') != specification.get('url'):
                raise ValueError('credential endpoint mismatch')
            literal_headers = node.get('http_headers') or {}
            env_headers = node.get('env_http_headers') or {}
            if not isinstance(literal_headers, dict) or not isinstance(env_headers, dict):
                raise ValueError('credential headers invalid')
            for name, value in literal_headers.items():
                if not isinstance(name, str) or name.lower() not in allowed:
                    raise ValueError('unsupported credential header')
                key = allowed[name.lower()]
                if key in result or not isinstance(value, str) or not value or len(value) > 8192 or not value.isascii() or any(c in value for c in ('\r','\n','\x00')):
                    raise ValueError('credential header invalid')
                result[key] = value
            for name, reference in env_headers.items():
                if not isinstance(name, str) or name.lower() not in allowed or allowed[name.lower()] in result:
                    raise ValueError('credential references ambiguous')
                result[allowed[name.lower()]] = resolve(reference)
            token_ref = node.get('bearer_token_env_var')
            if token_ref is not None:
                if 'Authorization' in result:
                    raise ValueError('credential references ambiguous')
                result['Authorization'] = 'Bearer ' + resolve(token_ref)
            if not result:
                raise ValueError('credential reference has no authentication')
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            # Never echo the configuration, decoded credential or TOML error.
            raise HostFacadeError('invalid_request', 'MCP auth reference unavailable or mismatched') from None
    for name, reference in refs.items():
        if not isinstance(name, str) or name.lower() not in allowed:
            raise HostFacadeError('invalid_request', 'auth header is not allowed')
        key = allowed[name.lower()]
        if key in result:
            raise HostFacadeError('invalid_request', 'auth header reference duplicated')
        result[key] = resolve(reference)
    bearer = specification.get('bearer_token_env')
    if bearer is not None:
        if 'Authorization' in result:
            raise HostFacadeError('invalid_request', 'conflicting auth references')
        result['Authorization'] = 'Bearer ' + resolve(bearer)
    return result


def _safe_transport_error(error, specification):
    message = repr(error)
    for value in _auth_headers(specification).values():
        message = message.replace(value, '<REDACTED>')
        if value.startswith('Bearer '):
            message = message.replace(value[7:], '<REDACTED>')
    return message


def _sdk_http_client(specification, timeout):
    headers = _auth_headers(specification)
    url = _checked_endpoint_url(specification.get('url'), 'MCP', specification.get('allowed_hosts'))
    if not headers:
        return Client(url, read_timeout_seconds=float(timeout))
    @asynccontextmanager
    async def transport():
        async with httpx.AsyncClient(headers=headers, trust_env=False,
                                     follow_redirects=False,
                                     timeout=float(timeout)) as http_client:
            async with streamable_http_client(url,
                                              http_client=http_client) as streams:
                yield streams
    return Client(transport(), read_timeout_seconds=float(timeout))

def _now():
    return datetime.now(timezone.utc).isoformat()


def _sha(value):
    if not isinstance(value, (str, bytes)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True,
                           separators=(',', ':'))
    if isinstance(value, str):
        value = value.encode('utf-8')
    return hashlib.sha256(value).hexdigest()


def _plain_absolute(path, *, kind='file', must_exist=True):
    value = str(path or '')
    if not value or not Path(value).is_absolute():
        raise HostFacadeError('invalid_request', '%s path must be absolute' % kind)
    p = Path(value)
    for part in [p, *p.parents]:
        if part == part.parent:
            break
        try:
            if part.is_symlink():
                raise HostFacadeError('invalid_request',
                                      '%s path has a symlink component' % kind)
        except OSError as exc:
            raise HostFacadeError('invalid_request',
                                  '%s path unavailable: %r' % (kind, exc)) from None
    if p.exists() and ((kind == 'file' and not p.is_file()) or
                       (kind == 'directory' and not p.is_dir())):
        raise HostFacadeError('invalid_request', '%s path type mismatch' % kind)
    if must_exist and not p.exists():
        raise HostFacadeError('invalid_request', '%s path unavailable' % kind)
    return p


def _parse_time(value):
    text = str(value or '').strip()
    if not text:
        raise HostFacadeError('invalid_request', 'scope time is missing')
    try:
        parsed = datetime.fromisoformat(text.replace('Z', '+00:00'))
    except ValueError:
        raise HostFacadeError('invalid_request', 'scope time is invalid') from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _scope_action(scope, action):
    actions = scope.get('actions')
    if not isinstance(actions, list) or action not in actions:
        raise HostFacadeError('invalid_request',
                              'probe scope does not cover action: %s' % action)


def _validate_scope(scope, config):
    if not isinstance(scope, dict) or scope.get(
            'schema') != 'fakenetng.probe-scope.v1':
        raise HostFacadeError('invalid_request', 'probe scope schema invalid')
    if type(scope.get('version')) is not int or scope['version'] != 1:
        raise HostFacadeError('invalid_request', 'probe scope version invalid')
    if not isinstance(scope.get('scope_id'), str) or not scope['scope_id']:
        raise HostFacadeError('invalid_request', 'probe scope id missing')
    if scope.get('mode') != 'probe' or scope.get(
            'authorization') != 'granted' or scope.get('revoked') is not False:
        raise HostFacadeError('invalid_request',
                              'probe scope is revoked or not a probe grant')
    now = datetime.now(timezone.utc)
    if now < _parse_time(scope.get('not_before')):
        raise HostFacadeError('invalid_request', 'probe scope is not active yet')
    if now >= _parse_time(scope.get('expires_at')):
        raise HostFacadeError('invalid_request', 'probe scope has expired')
    vmx = config.get('vmx') or {}
    vm = scope.get('vm') or {}
    if _normal_uuid(vm.get('uuid')) != _normal_uuid(vmx.get('expected_uuid')):
        raise HostFacadeError('invalid_request', 'probe scope VM UUID mismatch')
    if str(vm.get('computer') or '') != str(vmx.get('expected_computer') or ''):
        raise HostFacadeError('invalid_request',
                              'probe scope computer mismatch')
    objects = scope.get('objects') or {}
    if str(objects.get('vmx_path') or '') != str(vmx.get('path') or ''):
        raise HostFacadeError('invalid_request', 'probe scope VMX path mismatch')
    if str(objects.get('guest_ip') or '') != str(config.get('guest_ip') or ''):
        raise HostFacadeError('invalid_request', 'probe scope guest IP mismatch')
    fakenet = config.get('fakenet_mcp') or {}
    if str(objects.get('config_name') or '') != str(
            fakenet.get('config_name') or ''):
        raise HostFacadeError('invalid_request',
                              'probe scope FakeNet config mismatch')
    paths = scope.get('paths') or {}
    if str(paths.get('output_root') or '') != str(config.get('output_root') or ''):
        raise HostFacadeError('invalid_request',
                              'probe scope output root mismatch')
    if str(paths.get('state_root') or '') != str(config.get('state_root') or ''):
        raise HostFacadeError('invalid_request',
                              'probe scope state root mismatch')
    tools = scope.get('tools') or {}
    if not isinstance(tools.get('windows'), list) or             'PowerShell' not in tools['windows']:
        raise HostFacadeError('invalid_request',
                              'probe scope must allow Windows PowerShell')
    for name in ('get_status', 'read_config', 'verify_egress_isolation'):
        if not isinstance(tools.get('fakenet'), list) or name not in tools[
                'fakenet']:
            raise HostFacadeError('invalid_request',
                                  'probe scope FakeNet tool missing: %s' % name)
    if not isinstance(tools.get('velo'), list):
        raise HostFacadeError('invalid_request', 'probe scope Velo tools missing')
    velo_tool = (config.get('velo_mcp') or {}).get('tool')
    if velo_tool and velo_tool not in tools['velo']:
        raise HostFacadeError('invalid_request',
                              'probe scope Velo tool mismatch')
    policy = config.get('policy') or {}
    probe = scope.get('probe') or {}
    expected_template = host_probe.script_sha256(host_probe.PROBE_TEMPLATE)
    if probe.get('script_sha256') != expected_template:
        raise HostFacadeError('invalid_request',
                              'probe scope script hash mismatch')
    destinations = probe.get('destinations')
    if not isinstance(destinations, list) or             '198.51.100.77' not in destinations or             '2001:db8::77' not in destinations:
        raise HostFacadeError('invalid_request',
                              'probe scope destinations incomplete')
    if probe.get('echo_destination') != '198.51.100.77' or             probe.get('echo_port') != 1337:
        raise HostFacadeError('invalid_request', 'probe scope echo invalid')
    if not isinstance(probe.get('matrix_versions'), list) or             policy.get('matrix_version', 'v1') not in probe['matrix_versions']:
        raise HostFacadeError('invalid_request',
                              'probe scope matrix version mismatch')
    if probe.get('allow_random_ports') is not True:
        raise HostFacadeError('invalid_request',
                              'probe scope random ports not allowed')
    control = scope.get('control_ports')
    required = policy.get('required_control_ports')
    if not isinstance(control, list) or set(control) != set(required or []):
        raise HostFacadeError('invalid_request',
                              'probe scope control ports mismatch')
    budget = scope.get('budget') or {}
    if type(budget.get('total_ms')) is not int or not 1000 <= budget[
            'total_ms'] <= 60000:
        raise HostFacadeError('invalid_request', 'probe scope budget invalid')
    if type(budget.get('finish_ms')) is not int or not 0 < budget[
            'finish_ms'] < budget['total_ms']:
        raise HostFacadeError('invalid_request',
                              'probe scope finish budget invalid')
    declared = scope.get('sample_context')
    sample = config.get('sample_context') or {}
    if declared is not None:
        if not isinstance(declared, dict):
            raise HostFacadeError('invalid_request',
                                  'probe scope sample context invalid')
        for key in ('account', 'sid', 'session'):
            if declared.get(key) is not None and str(declared.get(key)) != str(
                    sample.get(key)):
                raise HostFacadeError('invalid_request',
                                      'probe scope sample context mismatch')
    return scope


def _canonical_uuid(value):
    try:
        parsed = str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        raise HostFacadeError('invalid_request',
                              'command_id must be a canonical UUID') from None
    if parsed != str(value):
        raise HostFacadeError('invalid_request',
                              'command_id must be a canonical UUID')
    return parsed


def _read_config(path):
    path = _plain_absolute(path, kind='file')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise HostFacadeError('invalid_request',
                              'host config unreadable: %r' % exc) from None
    if not isinstance(value, dict) or value.get(
            'schema') != 'fakenetng-host-mcp.config.v1':
        raise HostFacadeError('invalid_request', 'host config schema invalid')
    return value


def _atomic_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      indent=2) + '\n').encode('utf-8')
    if path.exists() or path.is_symlink():
        raise HostFacadeError('invalid_request',
                              'evidence path already exists: %s' % path)
    fd, temporary = __import__('tempfile').mkstemp(
        dir=path.parent, prefix='.host-evidence-')
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return {'path': str(path), 'sha256': _sha(raw), 'size': len(raw)}


def _load_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _sha_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _normal_uuid(value):
    return re.sub(r'[\s-]', '', str(value or '')).lower()


def _endpoint_parts(value):
    text = str(value or '')
    if ':' not in text:
        return None, None
    host, _, port = text.rpartition(':')
    host = host.strip('[]').split('%')[0]
    try:
        number = int(port)
    except ValueError:
        return None, None
    if not host or not 1 <= number <= 65535:
        return None, None
    return host, number


def _int_list(value):
    result = []
    for item in str(value or '').replace(';', ',').split(','):
        item = item.strip()
        if item.isdigit():
            number = int(item)
            if 1 <= number <= 65535 and number not in result:
                result.append(number)
    return result


def parse_fakenet_config(content):
    parser = configparser.ConfigParser(strict=False)
    try:
        parser.read_string(str(content or ''))
    except configparser.Error as exc:
        raise HostFacadeError('invalid_request',
                              'guest config parse failed: %r' % exc) from None
    diverter = parser['Diverter'] if parser.has_section('Diverter') else {}
    bypass_tcp = _int_list(diverter.get('BlackListPortsTCP', ''))
    bypass_udp = _int_list(diverter.get('BlackListPortsUDP', ''))
    redirect_all = str(diverter.get('RedirectAllTraffic', 'No')).lower() == 'yes'
    def _words(section, key):
        value = str(parser.get(section, key, fallback='') or '')
        return sorted({item.strip().lower() for item in value.split(',')
                       if item.strip()})

    global_rules = {
        'white': _words('Diverter', 'ProcessWhiteList'),
        'black': _words('Diverter', 'ProcessBlackList'),
        'host_white': _words('Diverter', 'HostWhiteList'),
        'host_black': _words('Diverter', 'HostBlackList'),
    }
    mapped = set()
    listener_map = {}
    listener_rules = {}
    for section in parser.sections():
        if section == 'Diverter':
            continue
        enabled = str(parser.get(section, 'Enabled', fallback='True')).lower()
        if enabled == 'false':
            continue
        port = str(parser.get(section, 'Port', fallback='')).strip()
        listener = str(parser.get(section, 'Listener', fallback='')).strip()
        if port.isdigit() and listener:
            number = int(port)
            mapped.add(number)
            listener_kind = listener.lower()
            if str(parser.get(section, 'SSL', fallback='')).lower() in (
                    'yes', 'true', '1'):
                listener_kind += ':tls'
            listener_map[number] = listener_kind
            listener_rules[number] = {
                'listener': listener_kind,
                'white': _words(section, 'ProcessWhiteList'),
                'black': _words(section, 'ProcessBlackList'),
                'host_white': _words(section, 'HostWhiteList'),
                'host_black': _words(section, 'HostBlackList'),
            }
    return {'bypass_tcp': bypass_tcp, 'bypass_udp': bypass_udp,
            'mapped_ports': sorted(mapped), 'listener_map': listener_map,
            'process_rules': {'global': global_rules,
                              'listeners': listener_rules},
            'redirect_all': redirect_all}


def _sample_identity(identity, sample):
    return egress_contract.sample_context_matches(identity, sample)



class HostFacade:
    def __init__(self, config, *, provider=None, fakenet_client=None,
                 windows_client=None, velo_client=None, state_store=None):
        self.config = config
        if not str(config.get('output_root')) or not str(
                config.get('state_root')):
            raise HostFacadeError('invalid_request',
                                  'output_root and state_root are required')
        self.output_root = _plain_absolute(
            config.get('output_root'), kind='directory',
            must_exist=False).resolve()
        self.state_root = _plain_absolute(
            config.get('state_root'), kind='directory',
            must_exist=False).resolve()
        self.state = state_store or HostStateStore(self.state_root)
        provider_config = dict(config)
        provider_config.update({
            'vmx_path': (config.get('vmx') or {}).get('path', ''),
            'expected_uuid': (config.get('vmx') or {}).get('expected_uuid', ''),
            'expected_computer': (config.get('vmx') or {}).get(
                'expected_computer', ''),
            'guest_ip': config.get('guest_ip', ''),
            'vmware_networking_path': config.get(
                'vmware_networking_path', ''),
            'nat_conf_path': config.get('nat_conf_path', ''),
            'interface': config.get('interface', 'vmnet8'),
        })
        self.provider = provider or HostProvider(provider_config)
        self.fakenet_client = fakenet_client
        self.windows_client = windows_client
        self.velo_client = velo_client

    # -- fixed authorization/config checks ---------------------------------
    def _authorization(self, action=None):
        auth = self.config.get('probe_authorization')
        if not isinstance(auth, dict) or auth.get('authorized') is not True:
            raise HostFacadeError('invalid_request',
                                  'probe authorization is not enabled')
        source = auth.get('source_ref')
        expected_sha = auth.get('source_sha256')
        source_path = _plain_absolute(source, kind='file')
        if not isinstance(expected_sha, str) or _sha_file(
                source_path) != expected_sha.lower():
            raise HostFacadeError('invalid_request',
                                  'probe authorization source changed')
        try:
            scope = json.loads(source_path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            raise HostFacadeError('invalid_request',
                                  'probe scope unreadable: %r' % exc) from None
        scope = _validate_scope(scope, self.config)
        declared_scope = auth.get('scope')
        if declared_scope and declared_scope != scope.get('scope_id'):
            raise HostFacadeError('invalid_request',
                                  'probe scope id does not match the config')
        if not isinstance(scope.get('actions'), list):
            raise HostFacadeError('invalid_request',
                                  'probe scope actions missing')
        if action is not None:
            _scope_action(scope, action)
        vmx = self.config.get('vmx') or {}
        fakenet = self.config.get('fakenet_mcp') or {}
        return {
            'source_ref': str(source_path),
            'source_sha256': _sha_file(source_path),
            'scope_sha256': _sha(json.dumps(scope, ensure_ascii=False,
                                           sort_keys=True,
                                           separators=(',', ':'))),
            'scope': scope,
            'template_sha256': host_probe.script_sha256(
                host_probe.PROBE_TEMPLATE),
            'target_key': _sha({
                'vm_uuid': _normal_uuid(vmx.get('expected_uuid')),
            }),
        }

    def _config_fingerprint(self, command_id, auth):
        return _sha({'command_id': command_id, 'config': self.config,
                     'scope_sha256': auth['scope_sha256'],
                     'scope': auth['scope'],
                     'probe_template': auth['template_sha256']})

    # -- state helpers ------------------------------------------------------
    def _error_result(self, command_id, code, message, record=None,
                      request=None, plan_preview=None):
        checks = {key: {'value': None, 'evidence_refs': []}
                  for key in egress_contract.EXPECTED_CHECKS}
        plan = None
        observation = None
        if isinstance(request, dict):
            try:
                plan = {
                    'run_id': request['run_id'],
                    'vm_epoch': request['vm_epoch'],
                    'policy_identity': request['policy_identity'],
                    'execution_context_identity':
                        request['execution_context_identity'],
                    'probe_nonce': request['probe_nonce'],
                    'required_control_ports': request['required_control_ports'],
                }
                observation = dict(plan, response_nonce=None,
                                   effective_control_exclusion_ports=None,
                                   checks=checks)
            except KeyError:
                plan = observation = None
        matrix_version = (request or {}).get(
            'matrix_version') or (self.config.get('policy') or {}).get(
                'matrix_version', 'v1')
        steps = []
        source = request if isinstance(request, dict) else (
            plan_preview if isinstance(plan_preview, dict) else None)
        if isinstance(source, dict):
            try:
                matrix = host_probe.matrix_steps(
                    int(source['random_tcp_port']),
                    int(source['random_udp_port']),
                    source.get('probe_nonce'))
                steps = [{
                    'id': row['id'], 'outcome': 'not_run',
                    'expected': None,
                    'observed': {'reason': code},
                    'reason_code': code, 'evidence_refs': [],
                    'started_at': None, 'ended_at': None,
                } for row in matrix]
            except (KeyError, TypeError, ValueError):
                steps = []
        if not steps:
            steps = [{'id': 'host_precondition', 'outcome': 'unknown',
                      'expected': 'host configuration and scope',
                      'observed': {'reason': code},
                      'reason_code': code, 'evidence_refs': [],
                      'started_at': None, 'ended_at': None}]
        not_run = [{'id': step['id'], 'reason': step['reason_code']}
                   for step in steps if step['outcome'] == 'not_run']
        return {
            'schema_version': egress_contract.SCHEMA_VERSION,
            'verification_id': (record or {}).get('verification_id'),
            'command_id': command_id,
            'lifecycle': {'state': (record or {}).get('stage', 'failed'),
                          'started_at': (record or {}).get('created_at'),
                          'ended_at': _now(),
                          'duration_ms': None, 'reason': message},
            'verdict': 'unknown',
            'bindings': {},
            'steps': steps,
            'checks': checks,
            'helper_input': ({'plan': plan, 'observation': observation}
                             if plan else {}),
            'conclusion': {'status': 'underdetermined', 'verdict': 'unknown',
                           'failed_checks': [],
                           'unknown_checks': list(checks) + [
                               'matrix_completeness'],
                           'sample_path_qualified': False,
                           'stop_remaining_probes': False,
                           'matrix_completeness': {
                               'status': 'underdetermined', 'complete': False,
                               'reason': code},
                           'authorized': False, 'reason': code},
            'coverage': {'matrix_version': matrix_version,
                         'planned': len(steps), 'executed': 0,
                         'matrix_planned': 30 if not_run else 0,
                         'matrix_not_run': not_run, 'not_run': not_run},
            'manifest': {'sha256': _sha([]), 'entries': [],
                         'invalidation_conditions': []},
            'invalidation_conditions': [],
            'limitations': ['host verification did not complete'],
            'authorized': False,
            'error': {'code': code, 'message': message},
        }

    def _pending_result(self, record):
        result = self._error_result(
            record['command_id'],
            'ownership_unknown' if record.get('stage') == 'running'
            else record.get('stage', 'unknown'),
            'original verification has no completed result; no rerun performed',
            record=record, request=record.get('request'))
        reconciliation = {'available': False, 'reason': 'not_attempted'}
        guest_id = record.get('guest_command_id')
        if isinstance(guest_id, str) and guest_id and hasattr(
                self._fakenet(), 'get_command_status'):
            try:
                status = self._fakenet().get_command_status(
                    guest_id, timeout=5)
                reconciliation = {'available': True, 'guest_command_id':
                                  guest_id, 'guest_status': status}
            except Exception as exc:  # noqa: BLE001 - retain exact failure
                reconciliation = {'available': False, 'guest_command_id':
                                  guest_id, 'error': repr(exc)}
        result['reconciliation'] = reconciliation
        result['probe_instance'] = record.get('probe_instance')
        return result

    @staticmethod
    def _partial_steps(probe_result, expected_map, guest_result):
        try:
            steps = host_merge._matrix_steps(
                probe_result, expected_map,
                boundary_verified=((probe_result.get('boundary') or {}).get(
                    'value') is True))
            steps.extend((guest_result or {}).get('steps') or [])
            return steps
        except Exception:
            return []

    def _load_verified_result(self, record, auth):
        result_path = _plain_absolute(record.get('result_path'), kind='file')
        actual_sha = _sha_file(result_path)
        if not record.get('result_sha256') or actual_sha != record.get(
                'result_sha256'):
            return self._error_result(
                record['command_id'], 'integrity_error',
                'completed result bytes do not match the durable record',
                record=record, request=record.get('request'))
        try:
            document = json.loads(result_path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as exc:
            return self._error_result(
                record['command_id'], 'integrity_error',
                'completed result is unreadable: %r' % exc,
                record=record, request=record.get('request'))
        if document.get('verification_id') != record.get(
                'verification_id') or document.get('command_id') != record.get(
                    'command_id'):
            return self._error_result(
                record['command_id'], 'integrity_error',
                'completed result identity does not match the durable record',
                record=record, request=record.get('request'))
        entries = (document.get('manifest') or {}).get('entries') or []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get('side') == 'guest':
                # Guest originals stay in the guest run lifecycle; the host
                # verifies the recorded guest hash, not a host path.
                continue
            path = entry.get('path')
            digest = entry.get('sha256')
            if not path or not digest:
                continue
            try:
                evidence = _plain_absolute(path, kind='file')
            except HostFacadeError:
                return self._error_result(
                    record['command_id'], 'stale_result',
                    'a referenced evidence file is unavailable',
                    record=record, request=record.get('request'))
            if _sha_file(evidence) != str(digest).lower():
                return self._error_result(
                    record['command_id'], 'stale_result',
                    'a referenced evidence file changed',
                    record=record, request=record.get('request'))
        final_status = record.get('final_status')
        if not isinstance(final_status, dict):
            return self._error_result(
                record['command_id'], 'stale_result',
                'completed record has no final status snapshot',
                record=record, request=record.get('request'))
        try:
            current_status = self._fakenet().get_status(timeout=5)
            self._set_observer_context(
                record['command_id'], 'pre', secrets.token_hex(16))
            current_host = self._host_snapshot(time.monotonic() + 5)
        except Exception as exc:  # noqa: BLE001 - current state unknown
            return self._error_result(
                record['command_id'], 'stale_result',
                'current state is unavailable: %r' % exc,
                record=record, request=record.get('request'))
        for key in ('run_id', 'controller', 'state_version'):
            if current_status.get(key) != final_status.get(key):
                return self._error_result(
                    record['command_id'], 'stale_result',
                    'current guest %s differs from the completed result' % key,
                    record=record, request=record.get('request'))
        if _normal_uuid((current_host.get('vmx') or {}).get('uuid')) !=                 _normal_uuid((record.get('final_host') or {}).get('vmx_uuid')):
            return self._error_result(
                record['command_id'], 'stale_result',
                'current VM identity differs from the completed result',
                record=record, request=record.get('request'))
        for key in ('network_type', 'boundary', 'nat_active',
                    'bridge_active'):
            if current_host.get(key) != (record.get(
                    'final_host') or {}).get(key):
                return self._error_result(
                    record['command_id'], 'stale_result',
                    'current network %s differs from the completed result' %
                    key, record=record, request=record.get('request'))
        current_policy = (current_host.get('policy') or {}).get('identity')
        if current_policy != (record.get('final_host') or {}).get(
                'observer_policy_identity'):
            return self._error_result(
                record['command_id'], 'stale_result',
                'current observer policy differs from the completed result',
                record=record, request=record.get('request'))
        return document

    def _set_observer_context(self, command_id, phase, challenge):
        setter = getattr(self.provider, 'set_observer_context', None)
        if callable(setter):
            setter(command_id, phase, challenge)

    def _host_snapshot(self, deadline):
        return self.provider.snapshot(deadline=deadline)

    # -- client defaults ----------------------------------------------------
    def _fakenet(self):
        if self.fakenet_client is None:
            specification = dict(self.config['fakenet_mcp'])
            allowed = specification.get('allowed_hosts')
            if not allowed:
                allowed = ['127.0.0.1', '::1', 'localhost']
                if self.config.get('guest_ip'):
                    allowed.append(str(self.config['guest_ip']))
            specification['allowed_hosts'] = allowed
            self.fakenet_client = FakeNetHttpClient(specification)
        return self.fakenet_client

    def _windows(self):
        if self.windows_client is None:
            self.windows_client = WindowsMcpClient(self.config['windows_mcp'])
        return self.windows_client

    def _velo(self):
        if self.velo_client is None:
            specification = self.config.get('velo_mcp') or {}
            self.velo_client = VeloMcpClient(specification)
        return self.velo_client

    # -- verification -------------------------------------------------------
    def verify(self, command_id):
        policy = self.config.get('policy') or {}
        preview = {
            'probe_nonce': secrets.token_hex(16),
            'random_tcp_port': 40000 + secrets.randbelow(20000),
            'random_udp_port': 40000 + secrets.randbelow(20000),
            'matrix_version': policy.get('matrix_version', 'v1'),
        }
        try:
            command_id = _canonical_uuid(command_id)
            auth = self._authorization()
        except HostFacadeError as exc:
            return self._error_result(str(command_id), exc.code, exc.message,
                                      plan_preview=preview)
        try:
            with self.state.lock(command_id):
                record = self.state.load(command_id)
                fingerprint = self._config_fingerprint(command_id, auth)
                if record is not None:
                    if record.get('config_fingerprint') != fingerprint:
                        return self._error_result(
                            command_id, 'invalid_request',
                            'command_id was admitted under different '
                            'configuration/scope',
                            record=record)
                    if record.get('stage') == 'completed':
                        return self._load_verified_result(record, auth)
                    return self._pending_result(record)
                active = self.state.find_active_target(auth['target_key'])
                if active is not None:
                    return self._error_result(
                        command_id, 'ownership_unknown',
                        'another verification intent for the same target '
                        'is still active; no second probe was started')
                try:
                    with self.state.lock_target(auth['target_key']):
                        active_after = self.state.find_active_target(
                            auth['target_key'])
                        if active_after is not None:
                            return self._error_result(
                                command_id, 'ownership_unknown',
                                'target intent became active before the lock')
                        now = _now()
                        record = {
                            'command_id': command_id,
                            'config_fingerprint': fingerprint,
                            'scope_sha256': auth['scope_sha256'],
                            'scope_identity': auth['scope'],
                            'target_key': auth['target_key'],
                            'verification_id': str(uuid.uuid4()),
                            'probe_nonce': secrets.token_hex(16),
                            'guest_command_id': None,
                            'random_tcp_port': 40000 + secrets.randbelow(
                                20000),
                            'random_udp_port': 40000 + secrets.randbelow(
                                20000),
                            'stage': 'prepared',
                            'created_at': now,
                            'updated_at': now,
                        }
                        record['guest_command_id'] = str(uuid.uuid5(
                            uuid.NAMESPACE_URL,
                            record['verification_id'] + ':guest'))
                        self.state.create(command_id, record)
                        return self._run(record, auth)
                except HostStateError as exc:
                    if str(exc) == 'target_busy':
                        return self._error_result(
                            command_id, 'operation_busy',
                            'another verification for the same target is '
                            'running')
                    raise
        except HostStateError as exc:
            return self._error_result(
                command_id, 'operation_busy' if str(exc) == 'command_busy'
                else 'invalid_request', str(exc))

    @staticmethod
    def _remaining(deadline, cap):
        return max(0.0, min(float(cap), deadline - time.monotonic()))

    @classmethod
    def _budget(cls, deadline, cap):
        remaining = cls._remaining(deadline, cap)
        if remaining <= 0:
            raise HostFacadeError('deadline_exceeded',
                                  'no budget left; action not started')
        return remaining

    @staticmethod
    def _utc_deadline(seconds):
        return (datetime.now(timezone.utc) + timedelta(
            seconds=max(0.0, float(seconds)))).isoformat()


    def _recheck_action(self, action):
        auth = self._authorization(action)
        admitted = getattr(self, '_admitted_scope_sha', None)
        if admitted is not None and auth['scope_sha256'] != admitted:
            raise HostFacadeError(
                'invalid_request',
                'probe scope changed after the command was admitted')
        return auth

    def _guest_state(self, fakenet, config_name, deadline):
        if self._remaining(deadline, 20) <= 0:
            raise HostFacadeError('deadline_exceeded',
                                  'no time left for guest state')
        timeout = self._budget(deadline, 20)
        status = fakenet.get_status(timeout=timeout)
        timeout = self._budget(deadline, 20)
        config = fakenet.read_config(config_name, timeout=timeout)
        return status, config

    def _assert_guest_unchanged(self, fakenet, config_name, status,
                                config_record, deadline):
        if self._remaining(deadline, 15) <= 0:
            raise HostFacadeError('deadline_exceeded',
                                  'no time left for guest re-read')
        timeout = self._budget(deadline, 15)
        status2 = fakenet.get_status(timeout=timeout)
        timeout = self._budget(deadline, 15)
        config2 = fakenet.read_config(config_name, timeout=timeout)
        expected = {
            'run_id': status.get('run_id'),
            'controller': status.get('controller'),
            'state_version': status.get('state_version'),
            'config_sha256': config_record.get('sha256'),
        }
        observed = {
            'run_id': status2.get('run_id'),
            'controller': status2.get('controller'),
            'state_version': status2.get('state_version'),
            'config_sha256': config2.get('sha256'),
        }
        if observed != expected:
            raise HostFacadeError(
                'state_conflict',
                'guest run/config/controller changed during verification',
                {'expected': expected, 'observed': observed})
        return status2, config2

    @staticmethod
    def _host_invariants(host):
        host = host or {}
        return {
            'vmx_uuid': (host.get('vmx') or {}).get('uuid'),
            'nics': (host.get('vmx') or {}).get('nics'),
            'network_type': host.get('network_type'),
            'nat_active': host.get('nat_active'),
            'bridge_active': host.get('bridge_active'),
            'boundary': host.get('boundary'),
            'forwarding': host.get('forwarding'),
            'interfaces': host.get('interfaces'),
            'route_to_guest': host.get('route_to_guest'),
            'default_routes': host.get('default_routes'),
            'firewall_known': (host.get('firewall') or {}).get('known'),
            'observer_policy_identity': (host.get('policy') or {}).get(
                'identity'),
        }

    def _final_consistency(self, fakenet, config_name, initial_status,
                           initial_config, initial_host, identity,
                           finish_deadline, scope, command_id=None,
                           challenge=None):
        observed = {'checked_at': _now()}
        try:
            if self._remaining(finish_deadline, 1) <= 0:
                observed['reason'] = 'deadline'
                return None, observed
            self._recheck_action('host_provider')
            status2 = fakenet.get_status(timeout=self._budget(finish_deadline, 20))
            config2 = fakenet.read_config(config_name, timeout=self._budget(finish_deadline, 20))
            if command_id is not None and challenge is not None:
                self._set_observer_context(command_id, 'final', challenge)
            host2 = self._host_snapshot(finish_deadline)
            observed.update({'status': status2,
                             'config_sha256': config2.get('sha256'),
                             'host_sha256': _sha(host2)})
            if status2.get('run_id') != initial_status.get('run_id'):
                observed['reason'] = 'run_changed'
                return False, observed
            if status2.get('controller') != initial_status.get('controller'):
                observed['reason'] = 'controller_changed'
                return False, observed
            if status2.get('state_version') != initial_status.get(
                    'state_version'):
                observed['reason'] = 'state_version_changed'
                return False, observed
            if config2.get('sha256') != initial_config.get('sha256'):
                observed['reason'] = 'config_changed'
                return False, observed
            if self._host_invariants(initial_host) != self._host_invariants(
                    host2):
                observed['reason'] = 'host_network_or_identity_changed'
                observed['host_snapshot'] = host2
                return False, observed
            observed['host_snapshot'] = host2
            if self._remaining(finish_deadline, 1) <= 0:
                observed['reason'] = 'deadline_before_final_probe'
                return None, observed
            self._recheck_action('windows_probe')
            final_remaining = self._remaining(finish_deadline, 5)
            deadline_ms = max(1, int(final_remaining * 1000))
            final_deadline_utc = self._utc_deadline(final_remaining)
            script = host_probe.probe_script(
                self._nonce_for_action, [], deadline_ms=deadline_ms,
                positive_enabled=False,
                deadline_utc=final_deadline_utc)
            result, raw = self._windows().probe(
                script, timeout=final_remaining)
            expected_script = host_probe.script_identity(
                self._nonce_for_action, [], deadline_ms=deadline_ms,
                positive_enabled=False,
                deadline_utc=final_deadline_utc)
            host_probe.validate_probe_result(
                result, [], nonce=self._nonce_for_action,
                expected_script_hash=expected_script,
                positive_required=False)
            identity2 = result.get('identity') or {}
            observed['windows_identity'] = {
                key: identity2.get(key) for key in
                ('pid', 'creation_ticks', 'account', 'sid', 'session',
                 'vm_uuid', 'boot_id')}
            for key in ('account', 'sid', 'session', 'vm_uuid', 'boot_id',
                        'token_integrity_level', 'policy_scope',
                        'protocol_class'):
                if identity.get(key) != identity2.get(key):
                    observed['reason'] = 'windows_identity_changed:%s' % key
                    return False, observed
            observed['reason'] = 'stable'
            return True, observed
        except Exception as exc:  # noqa: BLE001 - final read unknown
            observed['error'] = repr(exc)
            observed['reason'] = 'final_read_failed'
            return None, observed

    def _run(self, record, auth):
        command_id = record['command_id']
        verification_id = record['verification_id']
        record['stage'] = 'running'
        self.state.update(command_id, record)
        started_monotonic = time.monotonic()
        scope = auth['scope']
        budget = scope.get('budget') or {}
        total_ms = int(budget.get('total_ms', 50000))
        finish_ms = int(budget.get('finish_ms', 5000))
        action_deadline = started_monotonic + max(
            1.0, (total_ms - finish_ms) / 1000.0)
        finish_deadline = started_monotonic + max(1.0, total_ms / 1000.0)
        self._nonce_for_action = record['probe_nonce']
        self._admitted_scope_sha = auth['scope_sha256']
        try:
            auth = self._recheck_action('host_provider')
            record['pre_challenge'] = secrets.token_hex(16)
            record['final_challenge'] = secrets.token_hex(16)
            self._command_id_for_observer = command_id
            self._set_observer_context(
                command_id, 'pre', record['pre_challenge'])
            self.state.update(command_id, record)
            host = self._host_snapshot(action_deadline)
            fakenet = self._fakenet()
            if hasattr(fakenet, 'list_tools'):
                fakenet.list_tools(timeout=self._budget(action_deadline, 20))
            policy = self.config.get('policy') or {}
            config_name = (self.config.get('fakenet_mcp') or {}).get(
                'config_name', 'default.ini')
            status, config_record = self._guest_state(fakenet, config_name, action_deadline)
            if status.get('state') != 'healthy':
                raise HostFacadeError(
                    'not_allowed_in_state',
                    'guest FakeNet is not healthy: %r' % status.get('state'))
            controller = (self.config.get('fakenet_mcp') or {}).get(
                'controller_id')
            if status.get('controller') != controller:
                raise HostFacadeError(
                    'controller_conflict',
                    'configured controller does not own the current guest run')
            run_id = status.get('run_id')
            if not isinstance(run_id, str) or not run_id:
                raise HostFacadeError('state_conflict',
                                      'guest run_id is unavailable')
            parsed_config = parse_fakenet_config(config_record.get('content'))
            required_ports = policy.get('required_control_ports')
            if not egress_contract.valid_ports(required_ports):
                raise HostFacadeError(
                    'invalid_request',
                    'required_control_ports must be a valid non-empty list')
            matrix_version = policy.get('matrix_version', 'v1')
            if matrix_version != egress_contract.MATRIX_VERSION:
                raise HostFacadeError('invalid_request',
                                      'unsupported matrix version')
            random_tcp = record['random_tcp_port']
            random_udp = record['random_udp_port']
            nonce = record['probe_nonce']
            matrix = host_probe.matrix_steps(
                random_tcp, random_udp, nonce,
                listener_map=parsed_config['listener_map'],
                redirect_all=parsed_config['redirect_all'])
            policy = self.config.get('policy') or {}
            self._recheck_action('windows_probe')
            windows = self._windows()
            if hasattr(windows, 'list_tools'):
                windows.list_tools(timeout=self._budget(action_deadline, 20))
            identity_timeout = self._remaining(action_deadline, 45)
            if identity_timeout <= 0:
                raise HostFacadeError('deadline_exceeded',
                                      'no time left for Windows identity')
            identity_deadline_utc = self._utc_deadline(identity_timeout)
            identity_script = host_probe.probe_script(
                nonce, [], deadline_ms=max(1, int(identity_timeout * 1000)),
                positive_enabled=False,
                deadline_utc=identity_deadline_utc)
            identity_script_hash = host_probe.script_identity(
                nonce, [], deadline_ms=max(1, int(identity_timeout * 1000)),
                positive_enabled=False,
                deadline_utc=identity_deadline_utc)
            identity_result, identity_raw = windows.probe(
                identity_script, timeout=identity_timeout)
            host_probe.validate_probe_result(
                identity_result, [], nonce=nonce,
                expected_script_hash=identity_script_hash,
                positive_required=False)
            identity = identity_result.get('identity') or {}
            vmx = self.config.get('vmx') or {}
            if _normal_uuid(identity.get('vm_uuid')) != _normal_uuid(
                    vmx.get('expected_uuid')):
                raise HostFacadeError(
                    'state_conflict', 'guest VM UUID differs from configured VMX')
            if str(identity.get('computer') or '') != str(
                    vmx.get('expected_computer') or ''):
                raise HostFacadeError(
                    'state_conflict', 'guest computer differs from configured VM')
            sample_context = self.config.get('sample_context') or {}
            sample_ok = _sample_identity(identity, sample_context)
            if sample_ok is False:
                raise HostFacadeError(
                    'state_conflict',
                    'Windows probe account/session differs from the declared '
                    'sample launcher context')
            status, config_record = self._assert_guest_unchanged(
                fakenet, config_name, status, config_record, action_deadline)
            boundary = (host.get('boundary') or {}).get('value')
            probe_result = identity_result
            probe_raw = identity_raw
            if boundary is True:
                self._recheck_action('matrix_probe')
                matrix_timeout = self._remaining(action_deadline, 30)
                if matrix_timeout <= 0:
                    raise HostFacadeError('deadline_exceeded',
                                          'no time left for matrix')
                matrix_deadline_utc = self._utc_deadline(matrix_timeout)
                probe_script = host_probe.probe_script(
                    nonce, matrix, deadline_ms=max(
                        1, int(matrix_timeout * 1000)),
                    deadline_utc=matrix_deadline_utc)
                probe_script_hash = host_probe.script_identity(
                    nonce, matrix, deadline_ms=max(
                        1, int(matrix_timeout * 1000)),
                    deadline_utc=matrix_deadline_utc)
                probe_result, probe_raw = windows.probe(
                    probe_script, timeout=matrix_timeout)
                host_probe.validate_probe_result(
                    probe_result, [row['id'] for row in matrix], nonce=nonce,
                    expected_script_hash=probe_script_hash)
            else:
                probe_result = dict(identity_result)
                probe_result['matrix_run'] = False
                probe_result['not_run_reason'] = (
                    'host_isolation_unproven' if boundary is None
                    else 'host_egress_leak_observed')
            probe_identity = probe_result.get('identity') or {}
            for key in ('account', 'sid', 'session', 'vm_uuid', 'boot_id',
                        'token_integrity_level', 'policy_scope',
                        'protocol_class'):
                if str(probe_identity.get(key)) != str(identity.get(key)):
                    raise HostFacadeError(
                        'state_conflict',
                        'matrix probe execution context differs from the '
                        'identity probe: %s' % key)
            identity = probe_identity
            sample_ok = _sample_identity(identity, sample_context)
            if sample_ok is False:
                raise HostFacadeError(
                    'state_conflict',
                    'matrix probe context differs from the declared sample')
            process_rules_value = egress_contract.process_rules_match(
                sample_context.get('launcher_path'),
                identity.get('image_path'),
                parsed_config.get('process_rules'))
            if process_rules_value is False:
                raise HostFacadeError(
                    'state_conflict',
                    'sample/probe are not covered by the same FakeNet '
                    'process rules')
            positive = probe_result.get('positive') or {}
            positive_local = _endpoint_parts(positive.get('local_endpoint'))
            positive_remote = _endpoint_parts(positive.get('remote_endpoint'))
            if positive and (positive_local[0] is None or
                             positive_remote[0] is None):
                raise HostFacadeError(
                    'state_conflict',
                    'positive probe local/remote endpoint is unavailable')
            vm_epoch = _sha({
                'vmx_uuid': vmx.get('expected_uuid'),
                'boot_id': identity.get('boot_id'),
                'vmx_sha256': (host.get('vmx') or {}).get('sha256'),
            })
            policy_identity = _sha({
                'config_identity': status.get('config_identity'),
                'config_sha256': config_record.get('sha256'),
                'matrix_version': matrix_version,
                'required_control_ports': required_ports,
                'process_rules': parsed_config.get('process_rules'),
            })
            execution_context_identity = _sha({
                'identity': {key: identity.get(key) for key in
                             ('account', 'sid', 'session', 'image_path',
                              'image_sha256', 'vm_uuid', 'boot_id')},
                'sample_context': sample_context,
            })
            host_sha = _sha(host)
            request = {
                'schema_version': egress_contract.SCHEMA_VERSION,
                'verification_id': verification_id,
                'run_id': run_id,
                'vm_epoch': vm_epoch,
                'policy_identity': policy_identity,
                'execution_context_identity': execution_context_identity,
                'process_rules_equivalent': process_rules_value,
                'probe_nonce': nonce,
                'required_control_ports': required_ports,
                'matrix_version': matrix_version,
                'random_tcp_port': random_tcp,
                'random_udp_port': random_udp,
                'host_evidence_sha256': host_sha,
                'host_probe_pid': identity.get('pid'),
                'host_probe_creation': identity.get('creation_ticks'),
                'host_probe_started': positive.get('started'),
                'host_probe_ended': positive.get('ended'),
                'host_probe_source': positive_local[0],
                'host_probe_source_port': positive_local[1],
                'host_probe_protocol': ('TCP' if positive else None),
                'host_probe_destination': (positive_remote[0] if positive
                                           else '198.51.100.77'),
                'host_probe_port': (positive_remote[1] if positive else 1337),
                'guest_echo_allowed': (
                    (scope.get('probe') or {}).get('guest_echo_allowed')
                    is True),
                'budget': {'total_ms': total_ms,
                           'guest_ms': int(policy.get('guest_budget_ms',
                                                      15000)),
                           'matrix_ms': 30000, 'cleanup_ms': finish_ms},
                'controller': controller,
            }
            record['request'] = request
            record['probe_instance'] = {
                'windows': probe_result.get('instance'),
                'identity': {key: identity.get(key) for key in
                             ('pid', 'creation_ticks', 'account', 'sid',
                              'session', 'vm_uuid', 'boot_id')},
            }
            record['guest_command_id'] = record.get('guest_command_id')
            self.state.update(command_id, record)
            guest_result = None
            guest_error = None
            self._recheck_action('guest_verify')
            status, config_record = self._assert_guest_unchanged(
                fakenet, config_name, status, config_record, action_deadline)
            guest_timeout = self._remaining(action_deadline, 20)
            if guest_timeout <= 0:
                guest_error = {'code': 'deadline_exceeded'}
            else:
                try:
                    guest_response = fakenet.verify_egress(
                        record['guest_command_id'],
                        int(status.get('state_version')),
                        schemas.VerificationRequest(**request).model_dump(
                            mode='json'), timeout=guest_timeout)
                    guest_result = guest_response.get('verification')
                    if guest_response.get('error') or not isinstance(
                            guest_result, dict):
                        guest_error = guest_response.get('error') or {
                            'code': 'guest_verification_missing'}
                except Exception as exc:  # noqa: BLE001 - retain result
                    guest_error = {'code': 'guest_transport_error',
                                   'message': repr(exc)}
            fakenet_ok = isinstance(guest_result, dict) and guest_error is None
            # The guest verification is itself a coordinator mutation.  Accept
            # exactly our own +1 state version, no other concurrent change,
            # then use the post-action status as the final baseline.
            pre_version = status.get('state_version')
            post_status, post_config = self._guest_state(
                fakenet, config_name, action_deadline)
            if (post_status.get('run_id') != status.get('run_id') or
                    post_status.get('controller') != status.get('controller') or
                    post_config.get('sha256') != config_record.get('sha256')):
                raise HostFacadeError(
                    'state_conflict',
                    'guest run/controller/config changed during verification')
            try:
                pre_version_int = int(pre_version)
                post_version_int = int(post_status.get('state_version'))
            except (TypeError, ValueError):
                raise HostFacadeError(
                    'state_conflict',
                    'guest state version is unavailable') from None
            if post_version_int not in (pre_version_int, pre_version_int + 1):
                raise HostFacadeError(
                    'state_conflict',
                    'guest state version changed by more than this operation')
            status, config_record = post_status, post_config
            self._recheck_action('velo_probe')
            velo_timeout = self._remaining(action_deadline, 15)
            if velo_timeout <= 0:
                velo_ok, velo_detail = None, {'error': 'deadline'}
            else:
                velo_ok, velo_detail = self._velo().probe(
                    timeout=velo_timeout)
            channels = {
                'windows_mcp': True,
                'fakenet_mcp': fakenet_ok,
                'velo_mcp': velo_ok,
                'details': {'windows_mcp': {'ok': True,
                                            'pid': identity.get('pid')},
                            'fakenet_mcp': {'ok': fakenet_ok,
                                            'error': guest_error},
                            'velo_mcp': {'ok': velo_ok,
                                         'detail': velo_detail}},
            }
            expected_map = host_probe.expected_steps(
                bypass_tcp=parsed_config['bypass_tcp'],
                bypass_udp=parsed_config['bypass_udp'],
                mapped_ports=parsed_config['mapped_ports'],
                redirect_all=parsed_config['redirect_all'],
                random_tcp_port=random_tcp, random_udp_port=random_udp,
                nonce=nonce, listener_map=parsed_config['listener_map'])
            final_consistency, final_observed = self._final_consistency(
                fakenet, config_name, status, config_record, host, identity,
                finish_deadline, scope, command_id=command_id,
                challenge=record['final_challenge'])
            probe_result['final_consistency'] = final_consistency
            final_host_snapshot = final_observed.pop('host_snapshot', None)
            probe_result['final_consistency_observed'] = final_observed
            evidence_dir = (self.output_root / 'verifications' /
                            verification_id)
            host_evidence = _atomic_json(
                evidence_dir / 'host-provider.json', host)
            final_host_evidence = None
            if final_host_snapshot is not None:
                final_host_evidence = _atomic_json(
                    evidence_dir / 'host-final.json', final_host_snapshot)
            probe_evidence = _atomic_json(
                evidence_dir / 'windows-probe.json',
                {'probe': probe_result, 'raw': probe_raw,
                 'instance': probe_result.get('instance')})
            if guest_result is not None:
                _atomic_json(evidence_dir / 'guest-result.json', guest_result)
            probe_result['matrix_run'] = bool(probe_result.get('matrix_run'))
            if not probe_result.get('matrix_run'):
                probe_result.setdefault('not_run_reason',
                                        'host_isolation_unproven')
            result = host_merge.build_host_result(
                command_id=command_id, request=request,
                guest_result=guest_result, host_snapshot=host,
                probe_result=probe_result, expected_map=expected_map,
                config=self.config, channels=channels,
                host_evidence=host_evidence, probe_evidence=probe_evidence,
                final_host_evidence=final_host_evidence,
                host_final_snapshot=final_host_snapshot)
            result['bindings']['host_evidence_sha256'] = host_sha
            artifact = _atomic_json(evidence_dir / 'result.json', result)
            result['artifact'] = artifact
            result['_result_sha256'] = artifact['sha256']
            limit = int(policy.get('output_compact_limit_bytes',
                                   DEFAULT_COMPACT_LIMIT))
            encoded = json.dumps(result, ensure_ascii=False).encode('utf-8')
            if len(encoded) > limit:
                full = _atomic_json(evidence_dir / 'result.full.json', result)
                record['stage'] = 'completed'
                error = self._error_result(
                    command_id, 'output_limit',
                    'compact result exceeded the configured limit',
                    record=record, request=request)
                error['artifact'] = full
                error['full_result_sha256'] = full['sha256']
                _atomic_json(evidence_dir / 'output-limit.json', error)
                error['artifact'] = full
                record['final_status'] = status
                record['final_host'] = {
                    'vmx_uuid': (host.get('vmx') or {}).get('uuid'),
                    'network_type': host.get('network_type'),
                    'boundary': host.get('boundary'),
                    'nat_active': host.get('nat_active'),
                    'bridge_active': host.get('bridge_active'),
                    'observer_policy_identity': (host.get('policy') or {}).get(
                        'identity'),
                }
                record['stage'] = 'completed'
                record['result_path'] = str(evidence_dir / 'output-limit.json')
                record['result_sha256'] = _sha_file(
                    evidence_dir / 'output-limit.json')
                self.state.update(command_id, record)
                return error
            record['final_status'] = status
            record['final_host'] = {
                'vmx_uuid': (host.get('vmx') or {}).get('uuid'),
                'network_type': host.get('network_type'),
                'boundary': host.get('boundary'),
                'nat_active': host.get('nat_active'),
                'bridge_active': host.get('bridge_active'),
                'observer_policy_identity': (host.get('policy') or {}).get(
                    'identity'),
            }
            record['stage'] = 'completed'
            record['result_path'] = str(evidence_dir / 'result.json')
            record['result_sha256'] = _sha_file(evidence_dir / 'result.json')
            record['updated_at'] = _now()
            self.state.update(command_id, record)
            result.pop('_result_sha256', None)
            return result
        except HostFacadeError as exc:
            code = exc.code
            record['stage'] = ('ownership_unknown' if 'timeout' in code or
                               'transport' in code else 'failed')
            record['failure'] = {'code': code, 'message': exc.message}
            record['updated_at'] = _now()
            self.state.update(command_id, record)
            error = self._error_result(
                command_id, code, exc.message, record=record,
                request=record.get('request'), plan_preview=record)
            partial = self._partial_steps(
                locals().get('probe_result'), locals().get('expected_map'),
                locals().get('guest_result'))
            if partial:
                error['steps'] = partial
                error['coverage']['executed'] = sum(
                    1 for step in partial if step.get('outcome') != 'not_run')
                error['coverage']['matrix_executed'] = sum(
                    1 for step in partial if step.get('outcome') != 'not_run'
                    and str(step.get('id', '')).startswith(('ipv4_', 'ipv6_')))
                error['coverage']['matrix_not_run'] = [
                    {'id': step.get('id'), 'reason': step.get('reason_code')}
                    for step in partial if step.get('outcome') == 'not_run']
            return error
        except Exception as exc:  # noqa: BLE001 - preserve the original
            record['stage'] = 'failed'
            record['failure'] = {'code': 'internal_error',
                                 'message': repr(exc)}
            record['updated_at'] = _now()
            self.state.update(command_id, record)
            return self._error_result(command_id, 'internal_error',
                                      repr(exc), record=record,
                                      request=record.get('request'),
                                      plan_preview=record)

# -- HTTP/MCP clients -------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HostFacadeError('guest_transport_error',
                              'guest MCP redirect is not allowed')


def _checked_loopback_url(value, label):
    parsed = urllib.parse.urlparse(str(value or ''))
    if parsed.scheme != 'http' or not parsed.hostname:
        raise HostFacadeError('invalid_request', '%s must be an HTTP URL' % label)
    if parsed.username or parsed.password:
        raise HostFacadeError('invalid_request', '%s credentials not allowed' % label)
    if parsed.hostname not in ('127.0.0.1', '::1', 'localhost'):
        raise HostFacadeError('invalid_request', '%s must be loopback' % label)
    if parsed.path not in ('', '/mcp') or parsed.query or parsed.fragment:
        raise HostFacadeError('invalid_request', '%s path is not fixed' % label)
    return parsed.geturl()


class FakeNetHttpClient:
    def __init__(self, specification):
        self.specification = dict(specification)
        self.url = _checked_endpoint_url(specification.get('url'), 'FakeNet MCP', specification.get('allowed_hosts'))
        self.controller = str(specification.get('controller_id') or '')
        self.timeout = float(specification.get('timeout_seconds', 20))
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())

    def _post(self, request, timeout=None):
        budget = self.timeout if timeout is None else min(
            self.timeout, float(timeout))
        if budget <= 0:
            raise HostFacadeError('deadline_exceeded',
                                  'guest request not started: budget exhausted')

        async def call():
            # Socket read timeouts alone reset per packet. This cancellation
            # scope bounds connect, headers, and the complete bounded body.
            with anyio.fail_after(budget):
                async with httpx.AsyncClient(
                        trust_env=False, follow_redirects=False,
                        timeout=budget) as client:
                    async with client.stream(
                            'POST', self.url, content=request.data,
                            headers={**dict(request.header_items()), **_auth_headers(self.specification)}) as response:
                        if response.status_code != 200:
                            raise HostFacadeError(
                                'guest_transport_error',
                                'guest MCP HTTP status %s' % response.status_code)
                        chunks, size = [], 0
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > 4 * 1024 * 1024:
                                raise HostFacadeError(
                                    'guest_transport_error',
                                    'guest MCP response exceeds bounded body')
                            chunks.append(chunk)
                        return (b''.join(chunks).decode('utf-8', 'replace'),
                                response.headers.get('content-type', ''))
        try:
            return anyio.run(call)
        except HostFacadeError:
            raise
        except Exception as exc:
            raise HostFacadeError('guest_transport_error', _safe_transport_error(exc, self.specification)) from None

    def _call(self, name, arguments, timeout=None):
        body = {
            'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
            'params': {'name': name, 'arguments': arguments or {},
                       '_meta': {
                           'io.modelcontextprotocol/protocolVersion':
                               PROTOCOL_VERSION,
                           'io.modelcontextprotocol/clientInfo': {
                               'name': 'fakenetng-host-mcp', 'version': '0'},
                           'io.modelcontextprotocol/clientCapabilities': {},
                       }},
        }
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': PROTOCOL_VERSION,
            'Mcp-Method': 'tools/call',
            'Mcp-Name': name,
            'X-FakeNet-Controller-ID': self.controller,
        }
        request = urllib.request.Request(
            self.url, data=json.dumps(body).encode('utf-8'),
            method='POST', headers=headers)
        raw, content_type = self._post(request, timeout)
        if 'text/event-stream' in content_type:
            frames = [line[5:].strip() for line in raw.splitlines()
                      if line.startswith('data:')]
            raw = frames[-1] if frames else ''
        try:
            envelope = json.loads(raw)
        except ValueError as exc:
            raise HostFacadeError('guest_transport_error',
                                  'guest MCP response invalid: %r' % exc) \
                from None
        if envelope.get('error'):
            raise HostFacadeError('guest_transport_error',
                                  str(envelope['error']))
        result = envelope.get('result') or {}
        if result.get('isError'):
            raise HostFacadeError('guest_tool_error',
                                  'guest MCP tool returned isError')
        content = result.get('content') or []
        texts = [item.get('text') for item in content
                 if isinstance(item, dict) and isinstance(item.get('text'), str)]
        if len(texts) != 1:
            raise HostFacadeError('guest_transport_error',
                                  'guest MCP content is ambiguous')
        try:
            return json.loads(texts[0])
        except ValueError as exc:
            raise HostFacadeError('guest_transport_error',
                                  'guest tool JSON invalid: %r' % exc) from None

    def list_tools(self, timeout=None):
        timeout = self.timeout if timeout is None else float(timeout)
        if timeout <= 0:
            raise HostFacadeError('guest_timeout', 'FakeNet tool budget exhausted')
        body = {
            'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {},
        }
        request = urllib.request.Request(
            self.url, data=json.dumps(body).encode('utf-8'), method='POST',
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json, text/event-stream',
                     'MCP-Protocol-Version': PROTOCOL_VERSION,
                     'Mcp-Method': 'tools/list'})
        raw, content_type = self._post(request, timeout)
        if 'text/event-stream' in content_type:
            frames = [line[5:].strip() for line in raw.splitlines()
                      if line.startswith('data:')]
            raw = frames[-1] if frames else ''
        try:
            envelope = json.loads(raw)
        except ValueError as exc:
            raise HostFacadeError('guest_transport_error',
                                  'guest tools/list invalid: %r' % exc) from None
        tools = (envelope.get('result') or {}).get('tools')
        names = {item.get('name') for item in tools or []
                 if isinstance(item, dict)}
        expected = {'get_status', 'read_config', 'verify_egress_isolation'}
        if not expected.issubset(names):
            raise HostFacadeError('guest_transport_error',
                                  'guest MCP tool surface incomplete')
        return tools

    def get_status(self, timeout=None):
        return self._call('get_status', {}, timeout=timeout)

    def get_command_status(self, command_id, timeout=None):
        return self._call('get_command_status', {'command_id': command_id},
                          timeout=timeout)

    def read_config(self, name, timeout=None):
        return self._call('read_config', {'name': name}, timeout=timeout)

    def verify_egress(self, command_id, expected_state_version, request,
                      timeout=None):
        return self._call('verify_egress_isolation', {
            'command_id': command_id,
            'expected_state_version': expected_state_version,
            'verification_request': request,
        }, timeout=timeout)


WINDOWS_COMMAND_LIMIT = 32767
WINDOWS_COMMAND_MARGIN = 4096


def _gzip_base64(script):
    raw = script.encode('utf-8')
    compressed = gzip.compress(raw, mtime=0)
    return base64.b64encode(compressed).decode('ascii'), raw


def _windows_probe_command(script):
    encoded, raw = _gzip_base64(script)
    expected = hashlib.sha256(raw).hexdigest()
    command = (
        "$b=[Convert]::FromBase64String('" + encoded + "');"
        "$ms=[IO.MemoryStream]::new($b);"
        "$gz=[IO.Compression.GZipStream]::new($ms,"
        "[IO.Compression.CompressionMode]::Decompress);"
        "$sr=[IO.StreamReader]::new($gz,[Text.Encoding]::UTF8);"
        "try{$s=$sr.ReadToEnd()}finally{$sr.Dispose();$gz.Dispose();"
        "$ms.Dispose()};"
        "$h=[Security.Cryptography.SHA256]::Create().ComputeHash("
        "[Text.Encoding]::UTF8.GetBytes($s));"
        "$x=(([BitConverter]::ToString($h)).Replace('-',''))."
        "ToLowerInvariant();"
        "if($x -ne '" + expected + "'){throw 'script hash mismatch'};"
        "& ([ScriptBlock]::Create($s))")
    utf16 = command.encode('utf-16-le')
    direct_units = len(utf16) // 2
    encoded_command = base64.b64encode(utf16)
    if (direct_units > WINDOWS_COMMAND_LIMIT - WINDOWS_COMMAND_MARGIN or
            len(encoded_command) > WINDOWS_COMMAND_LIMIT - WINDOWS_COMMAND_MARGIN):
        raise HostFacadeError(
            'windows_command_too_long',
            'compressed Windows probe command exceeds the fixed command limit')
    return command


class WindowsMcpClient:
    def __init__(self, specification):
        self.specification = specification or {}
        self.url = _checked_endpoint_url(
            self.specification.get('url'), 'Windows-MCP',
            self.specification.get('allowed_hosts'))
        self.timeout = float(self.specification.get('timeout_seconds', 45))

    def _client(self, timeout):
        if timeout is None or float(timeout) <= 0:
            raise HostFacadeError('windows_timeout', 'Windows budget exhausted')
        return _sdk_http_client(self.specification, timeout)

    def list_tools(self, timeout=None):
        timeout = self.timeout if timeout is None else float(timeout)
        if timeout <= 0:
            raise HostFacadeError('windows_timeout', 'Windows tool budget exhausted')
        async def call():
            with anyio.fail_after(timeout):
                async with self._client(timeout) as client:
                    return await client.list_tools()
        try:
            outcome = anyio.run(call)
        except Exception as exc:  # noqa: BLE001 - report transport failure
            raise HostFacadeError('windows_transport_error', _safe_transport_error(exc, self.specification)) from None
        tools = {tool.name: tool for tool in getattr(outcome, 'tools', [])}
        tool = tools.get('PowerShell')
        if tool is None:
            raise HostFacadeError('windows_tool_missing',
                                  'Windows-MCP PowerShell tool is unavailable')
        schema = getattr(tool, 'input_schema', None) or getattr(
            tool, 'inputSchema', None) or {}
        properties = schema.get('properties') if isinstance(schema, dict) else {}
        if not isinstance(properties, dict) or 'command' not in properties:
            raise HostFacadeError('windows_tool_schema',
                                  'Windows-MCP PowerShell schema is not fixed')
        return tools

    def probe(self, script, timeout=None):
        timeout = self.timeout if timeout is None else float(timeout)
        timeout = min(timeout, self.timeout)
        if timeout <= 0:
            raise HostFacadeError('windows_timeout', 'no Windows probe budget')
        started = time.monotonic()
        try:
            command = _windows_probe_command(script)
        except HostFacadeError:
            raise
        except Exception as exc:  # noqa: BLE001 - report encoding failure
            raise HostFacadeError('windows_encoding_error', repr(exc)) from None
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise HostFacadeError('windows_timeout',
                                  'Windows probe encoding exhausted budget')
        timeout = remaining

        async def call():
            with anyio.fail_after(timeout):
                async with self._client(timeout) as client:
                    return await client.call_tool(
                        'PowerShell', {'command': command,
                                       'timeout': min(timeout, max(1, int(timeout)))})

        try:
            outcome = anyio.run(call)
        except Exception as exc:  # noqa: BLE001 - report the transport result
            raise HostFacadeError('windows_transport_error', _safe_transport_error(exc, self.specification)) \
                from None
        texts = []
        for item in getattr(outcome, 'content', None) or []:
            text = getattr(item, 'text', None)
            if text is not None:
                texts.append(text)
        raw = '\n'.join(texts)
        status = None
        marker = 'Status Code:'
        index = raw.rfind(marker)
        if index >= 0:
            tail = raw[index + len(marker):].strip().splitlines()
            if tail:
                try:
                    status = int(tail[0].strip())
                except ValueError:
                    status = None
        if getattr(outcome, 'is_error', False) or status != 0:
            raise HostFacadeError(
                'windows_probe_failed',
                'Windows PowerShell probe did not return Status Code 0')
        response = raw
        response_index = raw.find('Response:')
        if response_index >= 0:
            response = raw[response_index + len('Response:'):].lstrip(' \t\r\n')
            status_index = response.rfind('\n\nStatus Code:')
            if status_index >= 0:
                response = response[:status_index]
        try:
            parsed = host_probe.extract_marker(response)
        except Exception as exc:  # noqa: BLE001 - report parse failure
            raise HostFacadeError('windows_probe_failed', repr(exc)) \
                from None
        return parsed, raw


class VeloMcpClient:
    def __init__(self, specification):
        self.specification = specification or {}
        self.url = _checked_endpoint_url(
            self.specification.get('url'), 'Velo-MCP',
            self.specification.get('allowed_hosts'))
        self.tool = self.specification.get('tool')
        self.arguments = self.specification.get('arguments') or {}
        self.allowed_tools = list(self.specification.get('allowed_tools') or [])
        self.allowed_arguments = list(self.specification.get(
            'allowed_arguments') or [])
        self.timeout = float(self.specification.get('timeout_seconds', 15))

    def _validate(self):
        if not self.url or not self.tool:
            return False, {'error': 'velo control tool is not configured'}
        if self.tool not in self.allowed_tools:
            return False, {'error': 'velo tool is not in the fixed scope'}
        if not isinstance(self.arguments, dict) or any(
                key not in self.allowed_arguments for key in self.arguments):
            return False, {'error': 'velo arguments are not fixed by scope'}
        return True, {}

    def list_tools(self, timeout=None):
        budget = self.timeout if timeout is None else float(timeout)
        if budget <= 0:
            raise HostFacadeError('velo_timeout', 'Velo tool budget exhausted')
        async def call():
            with anyio.fail_after(budget):
                async with _sdk_http_client(self.specification, budget) as client:
                    return await client.list_tools()
        return anyio.run(call)

    def probe(self, timeout=None):
        ok, detail = self._validate()
        if not ok:
            return None, detail
        budget = self.timeout if timeout is None else float(timeout)
        if budget <= 0:
            return False, {'error': 'deadline'}
        deadline = time.monotonic() + budget
        try:
            tools = {tool.name for tool in getattr(
                self.list_tools(budget), 'tools', [])}
            if self.tool not in tools:
                return False, {'error': 'configured Velo tool is not deployed'}
            budget = deadline - time.monotonic()
            if budget <= 0:
                return False, {'error': 'deadline'}
            async def call():
                with anyio.fail_after(budget):
                    async with _sdk_http_client(self.specification, budget) as client:
                        return await client.call_tool(self.tool, self.arguments)
            outcome = anyio.run(call)
        except Exception as exc:  # noqa: BLE001 - report the transport result
            return False, {'error': _safe_transport_error(exc, self.specification)}
        return (not bool(getattr(outcome, 'is_error', False)),
                {'tool': self.tool})


def _checked_endpoint_url(value, label, allowed_hosts=None):
    parsed = urllib.parse.urlparse(str(value or ''))
    if parsed.scheme not in ('http', 'https', 'ws', 'wss') or not parsed.hostname:
        raise HostFacadeError('invalid_request', '%s must be a fixed URL' % label)
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise HostFacadeError('invalid_request', '%s URL is not fixed' % label)
    allowed = set(allowed_hosts or ['127.0.0.1', '::1', 'localhost'])
    if parsed.hostname not in allowed:
        raise HostFacadeError('invalid_request',
                              '%s endpoint is not in the fixed allowlist' % label)
    return parsed.geturl()


def build_server(facade):
    server = MCPServer(name='fakenetng-host-mcp',
                       version=MCP_PACKAGE_VERSION)

    @server.tool(
        description='One-call host/guest egress isolation verification; '
                    'returns every planned step and the helper input.',
        annotations=ToolAnnotations(readOnlyHint=False,
                                    destructiveHint=False,
                                    openWorldHint=False),
        structured_output=True)
    def verify_egress_isolation(command_id: str) -> schemas.VerificationResult:
        return facade.verify(command_id)

    return server


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    args = parser.parse_args(argv)
    config = _read_config(args.config)
    facade = HostFacade(config)
    build_server(facade).run(transport='stdio')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
