# -*- coding: utf-8 -*-
"""Contract: no bare legacy-value comparisons against 'domainallowlist'.

The v30 field run (plan 12.32.5) showed that renaming the config value to
EgressControl silently broke every site still comparing against the bare
legacy literal: policy mode fell back to legacy behavior and
DomainEgressRelay refused to start. Every consumer must use the alias
tuple ('egresscontrol', 'domainallowlist') so both values work.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).parents[1]

BARE_COMPARISON = re.compile(
    r"[!=]=\s*['\"]domainallowlist['\"]")


def test_no_bare_domainallowlist_comparisons_in_core():
    offenders = []
    for path in (REPO / 'fakenet').rglob('*.py'):
        text = path.read_text(encoding='utf-8', errors='replace')
        for lineno, line in enumerate(text.splitlines(), 1):
            if BARE_COMPARISON.search(line):
                offenders.append('%s:%d: %s' % (path, lineno, line.strip()))
    assert offenders == [], 'legacy-value comparisons must use the alias ' \
        'tuple: %r' % offenders


def test_alias_tuple_present_where_policy_value_read():
    # the two hard gates that crashed v30 must mention both values
    base = (REPO / 'fakenet' / 'diverters' / 'diverterbase.py')\
        .read_text(encoding='utf-8')
    assert "('egresscontrol', 'domainallowlist')" in base
    relay = (REPO / 'fakenet' / 'listeners' / 'DomainEgressRelay.py')\
        .read_text(encoding='utf-8')
    assert 'egressPolicyEnabled' in relay
