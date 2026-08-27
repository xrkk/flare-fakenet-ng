#!/usr/bin/env python3
"""Offline verifier for the embedded FakeNet-NG payload report model.

The verifier deliberately parses HTML as data and never evaluates its
JavaScript.  It is safe to run against an untrusted report exported from a VM
and provides a stable JSON result for the GUI/VM evidence bundle.
"""

import argparse
import base64
import hashlib
from html.parser import HTMLParser
import json
import os
import re
import sys


SCHEMA = 'fakenet.html-verification.v1'
MODEL_SCHEMA = 'fakenet.payload-report.v1'


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _read(path):
    with open(path, 'rb') as stream:
        return stream.read()


def _script_data(html_text):
    pattern = re.compile(
        r'<script\b[^>]*\bid=["\']payload-data["\'][^>]*>(.*?)</script\s*>',
        re.I | re.S)
    matches = pattern.findall(html_text)
    if len(matches) != 1:
        raise ValueError('exactly one payload-data JSON script is required')
    return matches[0].strip()


class _OfflineDomPolicy(HTMLParser):
    """Parse executable/resource DOM surface without inspecting inert JSON."""

    _RESOURCE_ATTRIBUTES = {
        'action', 'data', 'href', 'src', 'srcset',
    }
    _INERT_TYPES = {
        'application/json', 'application/ld+json',
    }

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=False)
        self.inert_script_depth = 0
        self.active_script_depth = 0
        self._active_script = []
        self.inert_script_count = 0
        self.active_script_count = 0
        self.external_resources = []
        self.unsafe_sinks = []
        self.event_handlers = []
        self.javascript_urls = []
        self.element_count = 0

    @staticmethod
    def _attributes(attributes):
        return {str(key).lower(): (value or '')
                for key, value in attributes}

    @staticmethod
    def _is_external(value):
        value = str(value or '').strip()
        return (bool(re.match(r'(?i)^(?:https?:)?//', value)) or
                bool(re.match(r'(?i)^https?:', value)))

    def handle_starttag(self, tag, attrs):
        tag = str(tag).lower()
        self.element_count += 1
        attributes = self._attributes(attrs)
        for name, value in attributes.items():
            if name.startswith('on'):
                self.event_handlers.append('%s[%s]' % (tag, name))
            if name in self._RESOURCE_ATTRIBUTES and self._is_external(value):
                self.external_resources.append('%s[%s]=%s' %
                                                (tag, name, value))
            if name in self._RESOURCE_ATTRIBUTES and re.match(
                    r'(?i)^javascript:', str(value).strip()):
                self.javascript_urls.append('%s[%s]' % (tag, name))
        if tag != 'script':
            return
        script_type = attributes.get('type', '').split(';', 1)[0].strip().lower()
        script_id = attributes.get('id', '')
        inert = script_type in self._INERT_TYPES
        if script_id == 'payload-data' and script_type != 'application/json':
            # The report data element must stay an inert JSON script, not an
            # executable script with a convenient identifier.
            self.unsafe_sinks.append('payload-data script is executable')
        if inert:
            self.inert_script_depth += 1
            self.inert_script_count += 1
        else:
            self.active_script_depth += 1
            self.active_script_count += 1
            self._active_script.append([])

    def handle_endtag(self, tag):
        if str(tag).lower() != 'script':
            return
        if self.inert_script_depth:
            self.inert_script_depth -= 1
        elif self.active_script_depth:
            self.active_script_depth -= 1
            source = ''.join(self._active_script.pop())
            for match in re.finditer(
                    r'(?i)\b(?:innerHTML|outerHTML|insertAdjacentHTML|'
                    r'document\.write|eval)\b', source):
                self.unsafe_sinks.append(match.group(0))
            # JavaScript's lowercase ``function`` declaration is ordinary
            # application code in the fixed template.  Only the case-
            # sensitive Function constructor is a code-generation sink.
            if re.search(r'\bFunction\s*\(', source):
                self.unsafe_sinks.append('Function')
            if re.search(r'(?i)https?://', source):
                self.external_resources.append('active-script-url')

    def handle_data(self, data):
        if self.active_script_depth and self._active_script:
            self._active_script[-1].append(data)

    def handle_entityref(self, name):
        if self.active_script_depth and self._active_script:
            self._active_script[-1].append('&%s;' % name)

    def handle_charref(self, name):
        if self.active_script_depth and self._active_script:
            self._active_script[-1].append('&#%s;' % name)


def _offline_dom_result(html_text):
    parser = _OfflineDomPolicy()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception as exc:
        raise ValueError('offline DOM parse failed: %s' % exc) from exc
    result = {
        'elements': parser.element_count,
        'active_scripts': parser.active_script_count,
        'inert_scripts': parser.inert_script_count,
        'external_resources': list(parser.external_resources),
        'unsafe_dom_sinks': list(parser.unsafe_sinks),
        'event_handlers': list(parser.event_handlers),
        'javascript_urls': list(parser.javascript_urls),
    }
    if parser.external_resources:
        raise ValueError('external network reference found in DOM: %s' %
                         ', '.join(parser.external_resources))
    if parser.unsafe_sinks or parser.event_handlers or parser.javascript_urls:
        raise ValueError('unsafe executable DOM surface found: %s' % result)
    return result


def _check_model(model):
    if model.get('schema') != MODEL_SCHEMA:
        raise ValueError('unexpected payload model schema')
    flows = model.get('flows')
    if not isinstance(flows, list):
        raise ValueError('payload model flows must be a list')
    flow_results = []
    for flow in flows:
        if not flow.get('owner'):
            raise ValueError('flow owner is absent')
        for direction in (flow.get('directions') or {}).values():
            try:
                payload = base64.b64decode(
                    direction.get('base64', '').encode('ascii'), validate=True)
            except Exception as exc:
                raise ValueError('invalid direction Base64: %s' % exc) from exc
            actual_hash = _sha256(payload)
            if len(payload) != int(direction.get('bytes', -1)):
                raise ValueError('direction length mismatch')
            if actual_hash != direction.get('sha256'):
                raise ValueError('direction hash mismatch')
            if flow.get('protocol') == 'UDP':
                cursor = 0
                datagram_ids = set()
                for datagram in direction.get('datagrams', []):
                    if int(datagram.get('offset', -1)) != cursor:
                        raise ValueError('UDP datagram boundary mismatch')
                    length = int(datagram.get('length', -1))
                    if int(datagram.get('bytes', -1)) != length:
                        raise ValueError('UDP datagram byte count mismatch')
                    datagram_id = str(datagram.get('id', ''))
                    if not datagram_id or datagram_id in datagram_ids:
                        raise ValueError('UDP datagram ID missing or duplicated')
                    datagram_ids.add(datagram_id)
                    reference = datagram.get('base64') or {}
                    if (reference.get('source') != direction.get('id') or
                            int(reference.get('offset', -1)) != cursor or
                            int(reference.get('length', -1)) != length):
                        raise ValueError('UDP datagram Base64 reference mismatch')
                    if datagram.get('sha256') != _sha256(
                            payload[cursor:cursor + length]):
                        raise ValueError('UDP datagram hash mismatch')
                    cursor += length
                if cursor != len(payload):
                    raise ValueError('UDP datagram total mismatch')
            flow_results.append({
                'flow_id': flow.get('id'), 'direction_id': direction.get('id'),
                'protocol': flow.get('protocol'), 'bytes': len(payload),
                'sha256': actual_hash,
            })
    capture = model.get('capture') or {}
    if capture.get('overall_health') is not True:
        raise ValueError('capture model is marked incomplete')
    return flow_results


def verify(html_path, expected_path=None):
    raw = _read(html_path)
    text = raw.decode('utf-8')
    checks = {}
    checks['utf8'] = True
    dom_result = _offline_dom_result(text)
    checks['offline'] = not bool(dom_result['external_resources'])
    checks['safe_dom_sinks'] = not bool(
        dom_result['unsafe_dom_sinks'] or dom_result['event_handlers'] or
        dom_result['javascript_urls'])
    checks['offline_dom_result'] = dom_result
    try:
        model = json.loads(_script_data(text))
    except (ValueError, TypeError) as exc:
        raise ValueError('embedded model is not valid JSON: %s' % exc) from exc
    flow_results = _check_model(model)
    checks['schema'] = model.get('schema') == MODEL_SCHEMA
    checks['base64_hash_length'] = True
    if expected_path:
        expected = json.loads(_read(expected_path).decode('utf-8'))
        if expected != model:
            raise ValueError('embedded model differs from expected model')
        checks['expected_model'] = True
    return {
        'schema': SCHEMA,
        'input_html_sha256': _sha256(raw),
        'model_schema': model.get('schema'),
        'checks': checks,
        'flows': flow_results,
        'verdict': 'PASS',
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--html', required=True)
    parser.add_argument('--expected-json')
    parser.add_argument('--output')
    args = parser.parse_args(argv)
    result = None
    exit_code = 0
    try:
        result = verify(args.html, args.expected_json)
    except Exception as exc:
        exit_code = 1
        result = {
            'schema': SCHEMA,
            'input_html_sha256': (_sha256(_read(args.html))
                                  if os.path.isfile(args.html) else None),
            'checks': {}, 'verdict': 'FAIL', 'error': str(exc),
        }
    payload = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        with open(args.output, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(payload)
    else:
        sys.stdout.write(payload)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
