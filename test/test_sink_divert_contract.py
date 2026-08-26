# -*- coding: utf-8 -*-
"""Positive contract for the exact Ubuntu takeover sink path (IMP-004)."""

import os

TARGETS = (
    os.path.join('fakenet', 'diverters', 'windows.py'),
    os.path.join('fakenet', 'diverters', 'egresspolicy.py'),
    os.path.join('fakenet', 'gui', 'procview.py'),
)

def test_exact_sink_verdict_is_present_in_all_contract_surfaces():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for relative in TARGETS:
        with open(os.path.join(repo, relative), 'r', encoding='utf-8') as fh:
            text = fh.read()
        assert 'ALLOW_TAKEOVER_SINK' in text, (
            '%s is missing the exact sink verdict contract' % relative)


def test_existing_sink_predicate_is_used_by_windows_route_gate():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    paths = [
        os.path.join('fakenet', 'diverters', 'egresspolicy.py'),
        os.path.join('fakenet', 'diverters', 'windows.py'),
    ]
    texts = []
    for relative in paths:
        with open(os.path.join(repo, relative), 'r', encoding='utf-8') as fh:
            texts.append(fh.read())
    assert 'def matches_takeover_sink(' in texts[0]
    assert 'predicate = getattr(policy, \'matches_takeover_sink\'' in texts[1]
