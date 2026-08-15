# -*- coding: utf-8 -*-
"""Schema integrity anchors (plan v0.2 §6).

Every key present in the shipped INI profiles must be covered by the GUI
schema; the pinned resource tuple must match egresspolicy.py; the listener
class list must match the modules under fakenet/listeners/.
"""

import os
import re
import configparser

import pytest

from fakenet.gui import schema

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIGS = os.path.join(REPO, 'fakenet', 'configs')

MAIN_INIS = (
    'default.ini', 'burp.ini', 'debug.ini',
    'domain_allowlist_windows.ini', 'domain_reviewed_ipv4_windows.ini',
    'domain_takeover_windows.ini', 'process_redirect_windows.ini',
)
CUSTOM_RESPONSE_INI = 'sample_custom_response.ini'


def _parse(path):
    parser = configparser.ConfigParser(interpolation=None)
    with open(path, 'r', encoding='utf-8-sig') as handle:
        parser.read_file(handle)
    return parser


def _all_main_parsers():
    for name in MAIN_INIS:
        yield name, _parse(os.path.join(CONFIGS, name))


def test_fakenet_section_keys_covered():
    for name, parser in _all_main_parsers():
        if not parser.has_section('FakeNet'):
            continue
        for key in parser.options('FakeNet'):
            field = schema.fakenet_field(key)
            assert field is not None, (
                '[FakeNet] key %r in %s not covered by schema' % (key, name))


def test_diverter_section_keys_covered():
    for name, parser in _all_main_parsers():
        if not parser.has_section('Diverter'):
            continue
        for key in parser.options('Diverter'):
            field = schema.diverter_field(key)
            assert field is not None, (
                '[Diverter] key %r in %s not covered by schema' % (key, name))


def test_listener_section_keys_covered():
    for name, parser in _all_main_parsers():
        for section in parser.sections():
            if section in ('FakeNet', 'Diverter'):
                continue
            listener_class = parser.get(section, 'Listener', fallback='')
            known = schema.listener_known_keys(listener_class)
            for key in parser.options(section):
                assert key.lower() in known, (
                    'listener key %r (section %r, Listener %r) in %s '
                    'not covered by schema' % (key, section, listener_class,
                                               name))


def test_custom_response_keys_covered():
    parser = _parse(os.path.join(CONFIGS, CUSTOM_RESPONSE_INI))
    for section in parser.sections():
        for key in parser.options(section):
            field = schema.custom_response_field(key)
            assert field is not None, (
                'custom response key %r (section %r) not covered'
                % (key, section))


def test_resource_tuple_anchored_to_egresspolicy():
    source_path = os.path.join(REPO, 'fakenet', 'diverters', 'egresspolicy.py')
    with open(source_path, 'r', encoding='utf-8') as handle:
        source = handle.read()
    match = re.search(r'expected = \(([^)]*)\)', source)
    assert match, 'egresspolicy.py expected tuple not found'
    expected = tuple(int(part.strip()) for part in match.group(1).split(','))
    assert expected == (5, 65536, 256, 32, 128, 16, 300, 1048576)
    assert schema.EXPECTED_RESOURCE_TUPLE == expected
    for key in schema.EXPECTED_RESOURCE_KEYS:
        pinned = schema.LOCKED_FIELD_VALUES[key]
        assert int(pinned) == expected[schema.EXPECTED_RESOURCE_KEYS.index(key)]


def test_pinned_locks_anchored_to_source():
    source_path = os.path.join(REPO, 'fakenet', 'diverters',
                               'processredirect.py')
    with open(source_path, 'r', encoding='utf-8') as handle:
        source = handle.read()
    assert re.search(r'must (?:be|equal)("?TCP"?)', source) or \
        "'TCP'" in source, 'processredirect TCP pin not found'
    assert schema.LOCKED_FIELD_VALUES['ExternalProcessRedirectProtocol'] == \
        'TCP'
    assert schema.LOCKED_FIELD_VALUES['ExternalAllowedTCPPorts'] == '443'


def test_listener_classes_match_modules():
    modules = set()
    listeners_dir = os.path.join(REPO, 'fakenet', 'listeners')
    for name in os.listdir(listeners_dir):
        if not name.endswith('.py') or name.startswith('__'):
            continue
        stem = name[:-3]
        if stem in ('ListenerBase', 'BannerFactory'):
            continue
        modules.add(stem)
    assert modules == set(schema.LISTENER_CLASSES), (
        'schema listener classes drifted from fakenet/listeners/: '
        'missing=%r extra=%r' % (modules - set(schema.LISTENER_CLASSES),
                                 set(schema.LISTENER_CLASSES) - modules))


def test_debug_labels_anchored():
    from fakenet.diverters import debuglevels
    labels = set(debuglevels.DLABELS.values())
    labels.add('Off')
    assert set(schema.DEBUG_LABELS) == labels


def test_system_injected_keys_not_in_schema():
    # fakenet.py injects these keys into every *listener* dict at runtime;
    # they must never appear as listener fields.  (NetworkMode legitimately
    # exists in [Diverter]; only ipaddr/configdir are listener-only.)
    for injected in schema.SYSTEM_INJECTED_KEYS:
        assert injected not in schema.listener_known_keys('')
    assert schema.diverter_field('ipaddr') is None
    assert schema.diverter_field('configdir') is None


def test_locked_field_flags_consistent():
    for key, value in schema.LOCKED_FIELD_VALUES.items():
        field = schema.diverter_field(key)
        assert field is not None and field.lock, (
            'locked value declared for non-locked field %r' % key)
        if field.wtype in (schema.T_BOOL_YESNO,):
            assert value == 'Yes'
        elif field.wtype == schema.T_INT:
            assert str(int(field.default)) == value


def test_egress_policy_switch_schema_preserves_ini_literals():
    field = schema.diverter_field('ExternalAccessPolicy')
    assert field.wtype == schema.T_BOOL_POLICY
    assert field.label == '出站策略总开关'
    assert field.group == '基础策略'
    assert field.default == schema.EGRESS_POLICY_DISABLED == 'Disabled'
    assert field.enum == (
        schema.EGRESS_POLICY_DISABLED, schema.EGRESS_POLICY_ENABLED)
    assert schema.EGRESS_POLICY_ENABLED == 'DomainAllowList'
    assert schema.egress_group_names()[0] == '基础策略'


def test_every_visible_schema_field_has_help_text():
    groups = [schema.FAKENET_FIELDS, schema.DIVERTER_FIELDS,
              schema.LISTENER_COMMON_FIELDS,
              schema.CUSTOM_RESPONSE_FIELDS]
    groups.extend(schema.LISTENER_TYPE_FIELDS.values())
    fields = [field for group in groups for field in group]
    assert len(fields) == 117
    missing = [field.key for field in fields
               if not (field.hint or '').strip()]
    assert missing == []


# ---------------------------------------------------------------------------
# End-to-end anchor (§6): the four functional profiles, with their build-time
# placeholders substituted by reviewed values, must validate clean through
# the GUI rule engine — this pulls windows.py-level coupling into the
# dual-source anchor net (F8 reinforcement, v0.2).
# ---------------------------------------------------------------------------

FUNCTIONAL_INIS = (
    'domain_allowlist_windows.ini',
    'domain_reviewed_ipv4_windows.ini',
    'domain_takeover_windows.ini',
    'process_redirect_windows.ini',
)


def _substitute_placeholders(model):
    import hashlib
    diverter = model.diverter()
    if (diverter.get('ExternalDnsServer') or '').startswith('__'):
        diverter.set('ExternalDnsServer', '8.8.8.8')
    image = os.path.abspath(__file__)
    if (diverter.get('ExternalProcessRedirectImagePath') or
            '').startswith('__'):
        diverter.set('ExternalProcessRedirectImagePath', image)
        with open(image, 'rb') as handle:
            diverter.set('ExternalProcessRedirectImageSHA256',
                         hashlib.sha256(handle.read()).hexdigest())
    if (diverter.get('ExternalProcessRedirectOriginalIPv4') or
            '').startswith('__'):
        diverter.set('ExternalProcessRedirectOriginalIPv4', '110.242.69.21')
    if (diverter.get('ExternalProcessRedirectTargetIPv4') or
            '').startswith('__'):
        diverter.set('ExternalProcessRedirectTargetIPv4', '192.168.204.1')


@pytest.mark.parametrize('name', FUNCTIONAL_INIS)
def test_functional_profile_placeholders_flagged(name):
    from fakenet.gui import configmodel, validator
    model = configmodel.ConfigModel.load(os.path.join(CONFIGS, name))
    errors = [i for i in validator.validate(model)
              if i.level == validator.ERROR]
    assert any('占位符' in i.message for i in errors), (
        'placeholder values in %s must be flagged' % name)


@pytest.mark.parametrize('name', FUNCTIONAL_INIS)
def test_functional_profile_valid_after_substitution(name):
    from fakenet.gui import configmodel, validator
    model = configmodel.ConfigModel.load(os.path.join(CONFIGS, name))
    _substitute_placeholders(model)
    errors = [i for i in validator.validate(model)
              if i.level == validator.ERROR]
    assert errors == [], '%s: unexpected errors: %r' % (name, errors)
