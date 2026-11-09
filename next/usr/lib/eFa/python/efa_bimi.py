# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""5w: the BIMI check of incoming mail (draft-brand-indicators-for-message-identification). Only for a sender domain that passed
DMARC with p=quarantine or p=reject; the logo is SVG Tiny PS over HTTPS, at most 32 KB, read by a strict parser without
entities. A certificate (a=) is not checked: the result names policy.authority=none."""
import base64
import re
import subprocess
import time
import urllib.request
import xml.parsers.expat

MAX_SVG = 32 * 1024
CACHE_SECONDS = 3600
FORBIDDEN = {'script', 'foreignobject', 'animate', 'animatemotion', 'animatetransform', 'set', 'image', 'use', 'a', 'iframe', 'embed', 'object'}
_cache = {}


def dmarc_policy(results, domain):
    """'quarantine' or 'reject' when an Authentication-Results line says dmarc=pass with that policy for the domain, else ''."""
    for line in results:
        for part in line.split(';'):
            if not re.search(r'\bdmarc=pass\b', part, re.I):
                continue
            policy, found = re.search(r'\(policy=(\w+)\)', part), re.search(r'header\.from=([^\s;]+)', part)
            if policy and found and found.group(1).lower().rstrip('.') == domain and policy.group(1).lower() in ('quarantine', 'reject'):
                return policy.group(1).lower()
    return ''


def record(text):
    """(location, authority) of a BIMI record, or None if it is none."""
    fields = dict(item.strip().split('=', 1) for item in text.split(';') if '=' in item)
    if fields.get('v', '').strip() != 'BIMI1':
        return None
    location = fields.get('l', '').strip()
    if location and not location.startswith('https://'):
        return None
    return location, fields.get('a', '').strip()


def svg_problem(data):
    """'' when data is SVG Tiny PS without active or outside content, else why not."""
    if len(data) > MAX_SVG:
        return 'larger than 32 KB'
    if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        return 'a DTD or entities are not allowed'
    state = {'root': None, 'problem': ''}
    parser = xml.parsers.expat.ParserCreate()

    def start(name, attrs):
        local = name.split(':')[-1].lower()
        if state['root'] is None:
            state['root'] = (local, attrs)
        if local in FORBIDDEN:
            state['problem'] = state['problem'] or f'element {local} not allowed'
        for key, value in attrs.items():
            key = key.lower()
            if key.startswith('on') or (key.endswith('href') and not str(value).startswith('#')) or 'javascript:' in str(value).lower():
                state['problem'] = state['problem'] or f'attribute {key} not allowed'
    parser.StartElementHandler = start
    parser.SetParamEntityParsing(xml.parsers.expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(data, True)
    except xml.parsers.expat.ExpatError as err:
        return f'not valid XML: {err}'
    root = state['root']
    if not root or root[0] != 'svg':
        return 'not an SVG'
    if root[1].get('baseProfile', '').lower() != 'tiny-ps' or root[1].get('version', '') != '1.2':
        return 'not SVG Tiny PS (version 1.2, baseProfile tiny-ps)'
    return state['problem']


def txt(name):
    """The TXT records of a name through the own resolver, joined; [] when there are none."""
    done = subprocess.run(['dig', '+short', '+time=3', '+tries=1', name, 'TXT', '@127.0.0.1'], capture_output=True, text=True, timeout=10)
    return [''.join(re.findall(r'"([^"]*)"', line)) for line in done.stdout.splitlines() if line.strip()]


def fetch_svg(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'eFa-next BIMI check'}), timeout=5) as reply:
        return reply.read(MAX_SVG + 1)


def check(domain, selector, results, now=None, lookup=txt, fetch=fetch_svg):
    """(result, reason, headers to add): pass with BIMI-Location and BIMI-Indicator, or fail/none/skipped. Cached per domain."""
    now = time.time() if now is None else now
    if not dmarc_policy(results, domain):
        return 'skipped', 'DMARC did not pass with quarantine or reject', []
    selector = selector if re.fullmatch(r'[A-Za-z0-9_-]{1,63}', selector or '') else 'default'
    key = f'{selector}._bimi.{domain}'
    cached = _cache.get(key)
    if cached and cached[0] > now:
        return cached[1]
    answer = ('none', 'no BIMI record', [])
    try:
        found = [record(text) for text in lookup(key)]
        found = [item for item in found if item]
        if found and found[0][0]:
            data = fetch(found[0][0])
            problem = svg_problem(data)
            if problem:
                answer = ('fail', problem, [])
            else:
                answer = ('pass', '', [('BIMI-Location', f'v=BIMI1; l={found[0][0]}'),
                                       ('BIMI-Indicator', base64.b64encode(data).decode())])
        elif found:
            answer = ('declined', 'the domain declines BIMI', [])
    except (OSError, ValueError, subprocess.SubprocessError) as err:
        answer = ('temperror', str(err)[:80], [])
    if len(_cache) > 5000:
        _cache.clear()
    _cache[key] = (now + CACHE_SECONDS, answer)
    return answer


def self_test():
    results = ['mx.own.example; dkim=pass header.d=brand.example; spf=pass smtp.mailfrom=brand.example; dmarc=pass (policy=reject) header.from=brand.example']
    assert dmarc_policy(results, 'brand.example') == 'reject' and dmarc_policy(results, 'other.example') == ''
    assert dmarc_policy(['x; dmarc=pass (policy=none) header.from=brand.example'], 'brand.example') == ''
    assert record('v=BIMI1; l=https://brand.example/logo.svg; a=') == ('https://brand.example/logo.svg', '') and record('v=spf1') is None
    assert record('v=BIMI1; l=http://brand.example/logo.svg') is None
    good = b'<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps"><title>Brand</title><path d="M0 0h10v10z"/></svg>'
    assert svg_problem(good) == ''
    assert svg_problem(good.replace(b'<path', b'<script>alert(1)</script><path')) == 'element script not allowed'
    assert svg_problem(good.replace(b'<path ', b'<path onclick="x()" ')).startswith('attribute onclick')
    assert 'entities' in svg_problem(b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg>&x;</svg>')
    assert 'Tiny PS' in svg_problem(b'<svg xmlns="http://www.w3.org/2000/svg"></svg>') and svg_problem(b'x' * (MAX_SVG + 1)) == 'larger than 32 KB'
    _cache.clear()
    result, _reason, headers = check('brand.example', '', results, now=0, lookup=lambda name: ['v=BIMI1; l=https://brand.example/l.svg'], fetch=lambda url: good)
    assert result == 'pass' and headers[0] == ('BIMI-Location', 'v=BIMI1; l=https://brand.example/l.svg') and base64.b64decode(headers[1][1]) == good
    assert check('brand.example', '', results, now=10, lookup=lambda name: [], fetch=lambda url: b'')[0] == 'pass', 'from the cache'
    assert check('brand.example', '', ['dmarc=fail'], now=10)[0] == 'skipped'
    _cache.clear()
    assert check('brand.example', '', results, now=0, lookup=lambda name: ['v=BIMI1; l=https://b/l.svg'], fetch=lambda url: b'<svg/>')[0] == 'fail'
    print('self-test ok')


if __name__ == '__main__':
    self_test()
