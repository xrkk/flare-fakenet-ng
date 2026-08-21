# -*- coding: utf-8 -*-
"""Contract test for the sink divert fix (plan 2026.08.21-01 I5/I9.5).

The ALLOW_TAKEOVER_SINK pass-through and the takeover_sink verdict argument
were removed: sink-bound traffic must flow through the divert path. Scope is
deliberately limited to the three files I5 modifies — validator.py keeps an
unrelated takeover_sink variable (the takeover sink IPv4 string), so a
whole-tree literal scan would misfire (audit A-03).
"""

import os
import re

TARGETS = (
    os.path.join('fakenet', 'diverters', 'windows.py'),
    os.path.join('fakenet', 'diverters', 'egresspolicy.py'),
    os.path.join('fakenet', 'gui', 'procview.py'),
)

FORBIDDEN_PATTERNS = (
    'ALLOW_TAKEOVER_SINK',
    re.compile(r'\btakeover_sink\b'),
)


def test_removed_sink_verdict_literals_stay_out():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for relative in TARGETS:
        with open(os.path.join(repo, relative), 'r', encoding='utf-8') as fh:
            text = fh.read()
        for pattern in FORBIDDEN_PATTERNS:
            if isinstance(pattern, str):
                assert pattern not in text, (
                    '%s reintroduces the removed sink pass-through token %r'
                    % (relative, pattern))
            else:
                assert pattern.search(text) is None, (
                    '%s reintroduces the removed sink pass-through '
                    'identifier via %r' % (relative, pattern.pattern))


def test_matches_takeover_sink_predicate_itself_is_retained():
    """The read-only predicate stays (tests target it; future external
    collection deployments may reuse it) — verify it still exists while no
    caller passes it into the verdict computation."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo, 'fakenet', 'diverters', 'egresspolicy.py'),
              'r', encoding='utf-8') as fh:
        text = fh.read()
    assert re.search(r'def matches_takeover_sink\(', text) is not None
