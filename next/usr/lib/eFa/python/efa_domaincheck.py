# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""6a: the checks of the mail security of a domain from its DNS answers: SPF, DMARC, TLS-RPT, BIMI, and the light of a domain.
Only parsing here; the queries are made by efactl. Each check: {'check', 'light' (green, yellow, red, grey), 'is', 'should', 'record'}."""
import re

LIGHTS = ('green', 'yellow', 'red', 'grey')
SPF_LOOKUP_LIMIT = 10
SPF_MECHANISMS = ('all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists')
SPF_COUNTED = ('include', 'a', 'mx', 'ptr', 'exists')


def txt_value(line):
    """One TXT answer of dig +short: its quoted strings joined; a line without quotes as it is."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
    return ''.join(part.replace('\\"', '"') for part in parts) if parts else line.strip()


def check(name, light, is_, should='', record=''):
    return {'check': name, 'light': light, 'is': is_[:300], 'should': should[:300], 'record': record[:600]}


def spf_terms(record):
    """The terms of an SPF record without v=spf1, or ValueError for a term that is not SPF (RFC 7208)."""
    terms = record.split()[1:]
    for term in terms:
        name = term.lstrip('+-~?').split(':', 1)[0].split('/', 1)[0].split('=', 1)[0].lower()
        if '=' in term and name in ('redirect', 'exp'):
            continue
        if name not in SPF_MECHANISMS and not re.fullmatch(r'[a-z][a-z0-9_.-]*=.*', term.lower()):
            raise ValueError(f'unknown term {term[:40]}')
        if name in ('ip4', 'ip6') and ':' not in term:
            raise ValueError(f'{term[:40]} without an address')
        if name in ('include', 'exists') and ':' not in term:
            raise ValueError(f'{term[:40]} without a domain')
    return terms


def spf_record(answers):
    """The one SPF record among the TXT answers, or (None, the problem)."""
    found = [value for value in (txt_value(line) for line in answers) if value.lower() == 'v=spf1' or value.lower().startswith('v=spf1 ')]
    if not found:
        return None, 'no SPF record'
    if len(found) > 1:
        return None, f'{len(found)} SPF records: there must be exactly one'
    return found[0], ''


def spf_lookups(record, txt_of, seen=None, depth=0):
    """The DNS lookups an SPF check makes for this record, includes and redirect counted with their own (RFC 7208, 4.6.4).
    txt_of(name) -> the TXT answers of name. A loop or depth over 10 counts as over the limit."""
    seen = seen if seen is not None else set()
    if depth > SPF_LOOKUP_LIMIT:
        return SPF_LOOKUP_LIMIT + 1
    count = 0
    for term in spf_terms(record):
        name, _, value = term.lstrip('+-~?').partition(':')
        name = name.split('/', 1)[0].lower()
        if name.startswith('redirect='):
            name, value = 'redirect', term.split('=', 1)[1]
        if name in SPF_COUNTED or name == 'redirect':
            count += 1
        if name in ('include', 'redirect') and value:
            target = value.lower().rstrip('.')
            if target in seen:
                return SPF_LOOKUP_LIMIT + 1
            seen.add(target)
            inner, _problem = spf_record(txt_of(target) or [])
            if inner:
                count += spf_lookups(inner, txt_of, seen, depth + 1)
        if count > SPF_LOOKUP_LIMIT:
            break
    return count


def spf_check(domain, answers, txt_of):
    record, problem = spf_record(answers)
    should = f'"v=spf1 mx ~all" at the least, with every server that sends for {domain}'
    suggestion = f'{domain}. IN TXT "v=spf1 mx ~all"'
    if record is None:
        return check('SPF', 'red', problem, should, suggestion if problem == 'no SPF record' else '')
    try:
        lookups = spf_lookups(record, txt_of)
    except ValueError as err:
        return check('SPF', 'red', f'{record}: {err}', should)
    ending = [term for term in record.split()[1:] if term.lstrip('+-~?').lower() == 'all']
    if lookups > SPF_LOOKUP_LIMIT:
        return check('SPF', 'red', f'{record}: {lookups} DNS lookups, more than {SPF_LOOKUP_LIMIT}: receivers see a permerror', 'at most 10 lookups')
    if not ending or ending[-1][0] in '+?' or ending[-1] == 'all':
        return check('SPF', 'red', f'{record}: ends without ~all or -all, anyone may send', 'ends with ~all or -all')
    return check('SPF', 'green', f'{record} ({lookups} lookups)')


def dmarc_tags(value):
    return {key.strip().lower(): item.strip() for key, _, item in (part.partition('=') for part in value.split(';')) if key.strip()}


def dmarc_check(domain, answers, suggested=''):
    found = [txt_value(line) for line in answers if txt_value(line).lower().startswith('v=dmarc1')]
    record = suggested or f'_dmarc.{domain}. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@{domain}"'
    if len(found) != 1:
        return check('DMARC', 'red', 'no DMARC record' if not found else f'{len(found)} DMARC records', 'one record with p= and rua=', record)
    tags = dmarc_tags(found[0])
    policy = tags.get('p', '').lower()
    if policy not in ('none', 'quarantine', 'reject'):
        return check('DMARC', 'red', f'{found[0]}: p= is missing or wrong', 'p=none, quarantine or reject', record)
    if not tags.get('rua'):
        return check('DMARC', 'yellow', f'{found[0]}: no rua, nobody gets the reports', 'rua=mailto:...', record)
    if policy == 'none':
        return check('DMARC', 'yellow', f'{found[0]}: p=none only watches', 'p=quarantine or p=reject once the reports are clean')
    strict = [name for name in ('adkim', 'aspf') if tags.get(name, 'r').lower() == 's']
    return check('DMARC', 'green', found[0] + (f' (strict {", ".join(strict)})' if strict else ''))


def tlsrpt_check(domain, answers, address=''):
    found = [txt_value(line) for line in answers if txt_value(line).lower().startswith('v=tlsrptv1')]
    record = f'_smtp._tls.{domain}. IN TXT "v=TLSRPTv1; rua=mailto:{address or "tls-reports@" + domain}"'
    if len(found) != 1:
        return check('TLS-RPT', 'red', 'no TLS-RPT record' if not found else f'{len(found)} TLS-RPT records', 'one record with rua=', record)
    if not re.search(r'rua=(mailto:[^@\s;]+@[^\s;,]+|https://\S+)', found[0], re.I):
        return check('TLS-RPT', 'red', f'{found[0]}: no valid rua', 'rua=mailto:... or https://...', record)
    return check('TLS-RPT', 'green', found[0])


def bimi_check(domain, answers):
    found = [txt_value(line) for line in answers if txt_value(line).lower().startswith('v=bimi1')]
    if not found:
        return check('BIMI', 'grey', 'no BIMI record (optional)')
    return check('BIMI', 'green' if re.search(r'\bl=https://', found[0]) else 'yellow', found[0], 'l=https://... (SVG Tiny PS)')


def light(checks):
    """The light of a domain: red if one check is red, yellow if one is yellow, else green; grey ones (optional) do not count."""
    lights = {item['light'] for item in checks}
    return 'red' if 'red' in lights else 'yellow' if 'yellow' in lights else 'green'


def prompt_needed(checks):
    """6a: the admin is asked to act while SPF, DMARC, MTA-STS or TLS-RPT are missing or wrong."""
    return sorted(item['check'] for item in checks if item['check'] in ('SPF', 'DMARC', 'MTA-STS', 'TLS-RPT') and item['light'] == 'red')


def self_test():
    assert txt_value('"v=spf1 include:a.example" " -all"') == 'v=spf1 include:a.example -all' and txt_value('plain') == 'plain'
    zone = {'a.example': ['"v=spf1 include:b.example include:c.example -all"'], 'b.example': ['"v=spf1 mx a ~all"'],
            'c.example': ['"v=spf1 redirect=d.example"'], 'd.example': ['"v=spf1 ip4:192.0.2.0/24 -all"'],
            'loop.example': ['"v=spf1 include:loop.example -all"']}
    txt_of = zone.get
    assert spf_lookups('v=spf1 include:a.example -all', txt_of) == 6
    assert spf_check('own.example', ['"v=spf1 include:a.example -all"'], txt_of)['light'] == 'green'
    assert spf_check('own.example', [], txt_of)['record'] == 'own.example. IN TXT "v=spf1 mx ~all"'
    assert spf_check('own.example', ['"v=spf1 mx -all"', '"v=spf1 a -all"'], txt_of)['light'] == 'red'
    assert spf_check('own.example', ['"v=spf1 mx +all"'], txt_of)['light'] == 'red' and spf_check('own.example', ['"v=spf1 mx"'], txt_of)['light'] == 'red'
    assert 'more than 10' in spf_check('own.example', ['"v=spf1 include:loop.example -all"'], txt_of)['is']
    many = '"v=spf1 ' + ' '.join(f'a:h{i}.example' for i in range(11)) + ' -all"'
    assert spf_check('own.example', [many], txt_of)['light'] == 'red'
    assert 'unknown term' in spf_check('own.example', ['"v=spf1 bogus -all"'], txt_of)['is']
    assert dmarc_check('own.example', [])['record'].startswith('_dmarc.own.example. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@own.example"')
    assert dmarc_check('own.example', ['"v=DMARC1; p=reject; rua=mailto:d@own.example; adkim=s"'])['light'] == 'green'
    assert dmarc_check('own.example', ['"v=DMARC1; p=none; rua=mailto:d@own.example"'])['light'] == 'yellow'
    assert dmarc_check('own.example', ['"v=DMARC1; p=reject"'])['light'] == 'yellow' and dmarc_check('own.example', ['"v=DMARC1; p=x"'])['light'] == 'red'
    assert tlsrpt_check('own.example', ['"v=TLSRPTv1; rua=mailto:tls@own.example"'])['light'] == 'green'
    assert tlsrpt_check('own.example', [], 'r@own.example')['record'] == '_smtp._tls.own.example. IN TXT "v=TLSRPTv1; rua=mailto:r@own.example"'
    assert tlsrpt_check('own.example', ['"v=TLSRPTv1; rua=ftp://x"'])['light'] == 'red'
    assert bimi_check('own.example', [])['light'] == 'grey' and bimi_check('own.example', ['"v=BIMI1; l=https://own.example/l.svg"'])['light'] == 'green'
    checks = [check('SPF', 'green', ''), check('BIMI', 'grey', ''), check('DMARC', 'yellow', '')]
    assert light(checks) == 'yellow' and light(checks[:2]) == 'green' and light(checks + [check('MTA-STS', 'red', '')]) == 'red'
    assert prompt_needed(checks + [check('MTA-STS', 'red', ''), check('DNSSEC', 'red', '')]) == ['MTA-STS']
    print('self-test ok')


if __name__ == '__main__':
    self_test()
