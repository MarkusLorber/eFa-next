# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""12, N1: threat feeds into local lists for rspamd. The parsers of the feed kinds (abuse.ch URLhaus and ThreatFox, STIX 2.1 as
TAXII 2.1 envelope or bundle, MISP attributes, a plain list), each giving indicators of four kinds: url, domain, sha256, ip.
Only data: nothing here talks to the network."""
import ipaddress
import json
import re

KINDS = ('url', 'domain', 'sha256', 'ip')
MAX_INDICATORS = 200000
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
STIX_RE = re.compile(r"\[\s*(url:value|domain-name:value|ipv4-addr:value|ipv6-addr:value|file:hashes\.'?SHA-256'?)\s*=\s*'([^']{1,2048})'\s*\]", re.I)


def clean(kind, value):
    """The value as the lists keep it, or None for one that does not fit its kind."""
    value = str(value or '').strip()
    if kind == 'url':
        value = value.split('#', 1)[0]
        return value if re.match(r'^https?://[^\s"<>]{3,2040}$', value, re.I) else None
    if kind == 'domain':
        value = value.lower().rstrip('.')
        return value if DOMAIN_RE.match(value) else None
    if kind == 'sha256':
        value = value.lower()
        return value if SHA256_RE.match(value) else None
    if kind == 'ip':
        try:
            return str(ipaddress.ip_address(value.split(':')[0] if value.count(':') == 1 else value))
        except ValueError:
            return None
    return None


def _add(found, kind, value):
    value = clean(kind, value)
    if value and sum(len(items) for items in found.values()) < MAX_INDICATORS:
        found[kind].add(value)


def parse(kind, data):
    """{kind: set of values} of one download. ValueError for data that is not of the feed kind."""
    found = {name: set() for name in KINDS}
    text = data.decode('utf-8', 'replace') if isinstance(data, bytes) else data
    if kind in ('urlhaus', 'list'):
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            for name in (('url',) if kind == 'urlhaus' else ('url', 'sha256', 'ip', 'domain')):
                if clean(name, line):
                    _add(found, name, line)
                    break
        return found
    try:
        doc = json.loads(text)
    except ValueError:
        raise ValueError('not JSON')
    if kind == 'threatfox':
        items = doc.values() if isinstance(doc, dict) else doc if isinstance(doc, list) else []
        for entries in items:
            for entry in entries if isinstance(entries, list) else [entries]:
                if not isinstance(entry, dict):
                    continue
                value, ioc = str(entry.get('ioc_value') or entry.get('ioc') or ''), str(entry.get('ioc_type') or '')
                name = {'url': 'url', 'domain': 'domain', 'ip:port': 'ip', 'sha256_hash': 'sha256'}.get(ioc)
                if name:
                    _add(found, name, value)
        return found
    if kind == 'stix':
        objects = doc.get('objects') if isinstance(doc, dict) else None
        objects = objects if isinstance(objects, list) else []
        for obj in objects:
            if isinstance(obj, dict) and obj.get('type') == 'indicator' and obj.get('pattern_type', 'stix') == 'stix' and not obj.get('revoked'):
                for field, value in STIX_RE.findall(str(obj.get('pattern', ''))):
                    field = field.lower()
                    _add(found, 'url' if field == 'url:value' else 'domain' if field == 'domain-name:value' else 'ip' if 'addr' in field else 'sha256', value)
        return found
    if kind == 'misp':
        response = doc.get('response') if isinstance(doc, dict) else None
        attributes = response.get('Attribute') if isinstance(response, dict) else None
        attributes = attributes if isinstance(attributes, list) else []
        for item in attributes:
            if isinstance(item, dict) and item.get('to_ids', True):
                name = {'url': 'url', 'link': 'url', 'domain': 'domain', 'hostname': 'domain', 'sha256': 'sha256', 'ip-dst': 'ip', 'ip-src': 'ip'}.get(item.get('type'))
                if name:
                    _add(found, name, item.get('value'))
        return found
    raise ValueError(f'unknown feed kind {kind}')


def self_test():
    assert all(not any(parse(kind, data).values()) for kind in ('threatfox', 'stix', 'misp') for data in (b'null', b'5', b'{"objects": 3, "response": []}'))
    assert parse('urlhaus', b'# comment\nhttp://evil.example/x.exe\nnot a url\nhttps://bad.example/a#frag\n')['url'] == {'http://evil.example/x.exe', 'https://bad.example/a'}
    threatfox = json.dumps({'1': [{'ioc_value': '192.0.2.7:443', 'ioc_type': 'ip:port'}], '2': [{'ioc_value': 'evil.example', 'ioc_type': 'domain'}],
                            '3': [{'ioc_value': 'A' * 64, 'ioc_type': 'sha256_hash'}], '4': [{'ioc_value': 'x', 'ioc_type': 'md5_hash'}]})
    found = parse('threatfox', threatfox)
    assert found['ip'] == {'192.0.2.7'} and found['domain'] == {'evil.example'} and found['sha256'] == {'a' * 64}
    stix = json.dumps({'objects': [{'type': 'indicator', 'pattern_type': 'stix', 'pattern': "[url:value = 'https://phish.example/login']"},
                                   {'type': 'indicator', 'pattern': "[file:hashes.'SHA-256' = '" + 'b' * 64 + "'] OR [domain-name:value = 'c2.example']"},
                                   {'type': 'indicator', 'revoked': True, 'pattern': "[domain-name:value = 'old.example']"},
                                   {'type': 'malware', 'name': 'x'}]})
    found = parse('stix', stix)
    assert found['url'] == {'https://phish.example/login'} and found['sha256'] == {'b' * 64} and found['domain'] == {'c2.example'}
    misp = json.dumps({'response': {'Attribute': [{'type': 'ip-dst', 'value': '2001:db8::1', 'to_ids': True}, {'type': 'domain', 'value': 'Bad.Example.', 'to_ids': True},
                                                  {'type': 'comment', 'value': 'x'}, {'type': 'url', 'value': 'https://y.example/', 'to_ids': False}]}})
    found = parse('misp', misp)
    assert found['ip'] == {'2001:db8::1'} and found['domain'] == {'bad.example'} and not found['url']
    assert parse('list', 'evil.example\n198.51.100.1\n' + 'c' * 64 + '\n')['domain'] == {'evil.example'}
    for kind, data in (('stix', 'not json'), ('nope', '{}')):
        try:
            parse(kind, data)
            raise AssertionError(kind)
        except ValueError:
            pass
    assert clean('domain', 'x' * 300 + '.example') is None and clean('url', 'javascript:alert(1)') is None
    print('self-test ok')


if __name__ == '__main__':
    self_test()
