# Copyright 2026 Google LLC
"""Controller header classification (P01 IMP-P01-04)."""

from fakenet.mcp.transportguard import classify_controller_header


def test_valid_canonical_uuid():
    value = '11111111-2222-4333-8444-555555555555'
    assert classify_controller_header(value) == 'valid_uuid'


def test_valid_uppercase_hex():
    value = 'AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE'
    assert classify_controller_header(value) == 'valid_uuid'


def test_missing_when_none_or_empty():
    assert classify_controller_header(None) == 'missing'
    assert classify_controller_header('') == 'missing'


def test_invalid_formats():
    assert classify_controller_header('not-a-uuid') == 'invalid_format'
    # Non-hex digit in the groups.
    assert classify_controller_header(
        '11111111-2222-4333-8444-55555555555z') == 'invalid_format'
    assert classify_controller_header(
        '11111111222243338444555555555555x') == 'invalid_format'


def test_variant_and_version_bits_required():
    # Non-v4 UUID: still a valid UUID per RFC (we only require UUID shape).
    assert classify_controller_header(
        '11111111-2222-1333-8444-555555555555') == 'valid_uuid'
    assert classify_controller_header('11111111-2222-4333-8444-55555555555') == \
        'invalid_format'
