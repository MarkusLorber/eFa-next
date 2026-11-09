# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""DNS evidence of a mail: the records the checks of rspamd used, asked again from the local resolver right after the scan.

Within their TTL these are answers from the cache of the resolver, the same ones rspamd got. Each distinct record set is stored once.
Standard library only; the DNS client speaks just enough of RFC 1035 and RFC 6891 for this.
"""
import base64
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import struct
import time

RESOLVER = ('127.0.0.1', 53)
TIMEOUT = 2.0
TYPES = {'A': 1, 'NS': 2, 'CNAME': 5, 'PTR': 12, 'MX': 15, 'TXT': 16, 'AAAA': 28}
NAMES = {number: name for name, number in TYPES.items()}
SPF_LOOKUPS = 10
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$', re.I)


def query_packet(name, qtype, qid):
    """A query with recursion and EDNS0 with the DO bit, so the resolver says whether it validated the answer (AD)."""
    labels = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.rstrip('.').split('.')) + b'\0'
    header = struct.pack('>HHHHHH', qid, 0x0120, 1, 0, 0, 1)
    opt = b'\0' + struct.pack('>HHIH', 41, 1232, 0x8000, 0)
    return header + labels + struct.pack('>HH', TYPES[qtype], 1) + opt


def _name(data, offset, depth=0):
    """A name at offset, with compression; returns (name, offset after it)."""
    labels, end = [], None
    while True:
        if offset >= len(data) or depth > 20:
            raise ValueError('bad name')
        length = data[offset]
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if end is None:
                end = offset + 2
            offset, depth = pointer, depth + 1
            continue
        if length == 0:
            return '.'.join(labels), (end if end is not None else offset + 1)
        labels.append(data[offset + 1:offset + 1 + length].decode('ascii', 'replace'))
        offset += 1 + length


def _rdata(data, offset, rtype, length):
    raw = data[offset:offset + length]
    if rtype == 1 and length == 4:
        return str(ipaddress.IPv4Address(raw))
    if rtype == 28 and length == 16:
        return str(ipaddress.IPv6Address(raw))
    if rtype in (2, 5, 12):
        return _name(data, offset)[0]
    if rtype == 15:
        # A null MX (RFC 7505) points at the root.
        return f'{struct.unpack(">H", raw[:2])[0]} {_name(data, offset + 2)[0] or "."}'
    if rtype == 16:
        parts, pos = [], 0
        while pos < len(raw):
            parts.append(raw[pos + 1:pos + 1 + raw[pos]].decode('utf-8', 'replace'))
            pos += 1 + raw[pos]
        return ''.join(parts)
    return base64.b64encode(raw).decode()


def parse_answer(data, qid):
    """{'rcode', 'ad', 'tc', 'answers': [(type, ttl, value)]} of a reply to the query with this ID."""
    if len(data) < 12:
        raise ValueError('short reply')
    rid, flags, qdcount, ancount = struct.unpack('>HHHH', data[:8])
    if rid != qid:
        raise ValueError('wrong ID')
    offset = 12
    for _ in range(qdcount):
        offset = _name(data, offset)[1] + 4
    answers = []
    for _ in range(ancount):
        offset = _name(data, offset)[1]
        rtype, _rclass, ttl, length = struct.unpack('>HHIH', data[offset:offset + 10])
        offset += 10
        # With the DO bit the signatures come along; the AD flag already says what they proved.
        if rtype in NAMES:
            answers.append((NAMES[rtype], ttl, _rdata(data, offset, rtype, length)))
        offset += length
    return {'rcode': flags & 0xF, 'ad': bool(flags & 0x0020), 'tc': bool(flags & 0x0200), 'answers': answers}


def lookup(name, qtype, resolver=RESOLVER, timeout=TIMEOUT):
    """Ask the resolver once, over TCP when the UDP answer is cut. Errors come back as a result, never as an exception."""
    started = time.monotonic()
    qid = secrets.randbelow(65536)
    try:
        packet = query_packet(name, qtype, qid)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, resolver)
            reply = parse_answer(sock.recvfrom(4096)[0], qid)
        if reply['tc']:
            with socket.create_connection(resolver, timeout=timeout) as sock:
                sock.sendall(struct.pack('>H', len(packet)) + packet)
                size = struct.unpack('>H', sock.recv(2))[0]
                data = b''
                while len(data) < size:
                    chunk = sock.recv(size - len(data))
                    if not chunk:
                        break
                    data += chunk
                reply = parse_answer(data, qid)
    except (OSError, ValueError, UnicodeError, struct.error, IndexError) as err:
        reply = {'rcode': None, 'ad': False, 'tc': False, 'answers': [], 'error': str(err)[:120]}
    reply['ms'] = round((time.monotonic() - started) * 1000, 2)
    reply.pop('tc', None)
    return reply


def record_key(name, qtype, answers):
    """The same record set always has the same key, whatever the TTL left in the cache."""
    values = sorted(f'{rtype} {value}' for rtype, _ttl, value in answers)
    return hashlib.sha256(json.dumps([name.lower().rstrip('.'), qtype, values]).encode()).hexdigest()


def tag_values(header):
    """The tags of a DKIM-Signature or ARC-Seal header."""
    return {key.strip().lower(): value.strip() for key, _sep, value in (part.partition('=') for part in header.split(';')) if key.strip()}


def key_info(txt):
    """Type and size of a DKIM key record."""
    tags = tag_values(txt)
    kind = tags.get('k', 'rsa').lower()
    try:
        key = base64.b64decode(re.sub(r'\s', '', tags.get('p', '')))
    except ValueError:
        key = b''
    if not key:
        return {'type': kind, 'bits': None, 'revoked': 'p' in tags}
    # The modulus is the long part of an RSA SubjectPublicKeyInfo; the frame takes about 38 bytes.
    return {'type': kind, 'bits': 256 if kind == 'ed25519' else max(0, (len(key) - 38) * 8 // 256 * 256)}


def parse_headers(text):
    """(name, value) of each header, folded lines joined."""
    found = []
    for line in (text or '').replace('\r\n', '\n').split('\n'):
        if line[:1] in (' ', '\t') and found:
            found[-1] = (found[-1][0], found[-1][1] + ' ' + line.strip())
        elif ':' in line:
            name, _sep, value = line.partition(':')
            found.append((name.strip(), value.strip()))
    return found


def plan(doc, headers):
    """What to ask for one mail: (check, name, type)."""
    wanted = []
    envelope = str(doc.get('from') or '').rsplit('@', 1)[-1].lower()
    if DOMAIN_RE.match(envelope):
        wanted += [('spf', envelope, 'TXT'), ('sender MX', envelope, 'MX'), ('sender A', envelope, 'A'), ('sender AAAA', envelope, 'AAAA')]
    header_from = next((value for name, value in headers if name.lower() == 'from'), '')
    found = re.findall(r'@([A-Za-z0-9.-]+)', header_from)
    if found and DOMAIN_RE.match(found[-1].lower()):
        wanted.append(('dmarc', '_dmarc.' + found[-1].lower(), 'TXT'))
    for name, value in headers:
        if name.lower() in ('dkim-signature', 'arc-seal'):
            tags = tag_values(value)
            domain, selector = tags.get('d', '').lower(), tags.get('s', '')
            if DOMAIN_RE.match(domain) and re.fullmatch(r'[A-Za-z0-9._-]{1,63}', selector):
                wanted.append(('dkim' if name.lower() == 'dkim-signature' else 'arc', f'{selector}._domainkey.{domain}', 'TXT'))
    try:
        ip = ipaddress.ip_address(str(doc.get('ip') or ''))
        wanted.append(('client PTR', ip.reverse_pointer, 'PTR'))
    except ValueError:
        pass
    return wanted


def spf_follow(record, ask, depth=0, seen=None):
    """The include and redirect chain of an SPF record, at most 10 lookups as RFC 7208 allows."""
    seen = seen if seen is not None else set()
    chain = []
    for term in record.split()[1:]:
        target = None
        if term.lower().lstrip('+-~?').startswith('include:'):
            target = term.split(':', 1)[1]
        elif term.lower().startswith('redirect='):
            target = term.split('=', 1)[1]
        if not target or '%' in target or target.lower() in seen or len(seen) >= SPF_LOOKUPS or depth > 9 or not DOMAIN_RE.match(target):
            continue
        seen.add(target.lower())
        reply = ask(target, 'TXT')
        chain.append(('spf include', target, 'TXT', reply))
        spf = next((value for rtype, _ttl, value in reply['answers'] if rtype == 'TXT' and value.lower().startswith('v=spf1')), '')
        if spf:
            chain += spf_follow(spf, ask, depth + 1, seen)
    return chain


RESULT_PREFIX = {'spf': ('R_SPF_',), 'dkim': ('R_DKIM_', 'DKIM_'), 'dmarc': ('DMARC_',), 'arc': ('ARC_',)}


def results(doc):
    """The verdicts of rspamd per check, from its symbols, and the blocklist hits with what they matched."""
    found = {check: [] for check in RESULT_PREFIX}
    lists = []
    for symbol in doc.get('symbols') or []:
        name = str(symbol.get('name', '')) if isinstance(symbol, dict) else str(symbol)
        options = symbol.get('options') if isinstance(symbol, dict) else None
        for check, prefixes in RESULT_PREFIX.items():
            if name.startswith(prefixes):
                found[check].append(name + (f" [{', '.join(map(str, options))}]" if options else ''))
        if name.startswith(('RBL_', 'RECEIVED_', 'URIBL_', 'DBL_', 'SURBL_', 'EFA_RBL_', 'SEM_', 'MSBL_')):
            lists.append({'symbol': name, 'matched': [str(item) for item in (options or [])][:10], 'score': symbol.get('score') if isinstance(symbol, dict) else None})
    return found, lists


def collect(doc, headers, ask=lookup, resolver_name='127.0.0.1 (local Unbound)'):
    """(evidence of the mail, {key: record set}) with each answer once."""
    asked, records, checks = time.time(), {}, []
    plan_items = plan(doc, headers)
    for check, name, qtype in plan_items:
        reply = ask(name, qtype)
        items = [(check, name, qtype, reply)]
        if check == 'spf':
            spf = next((value for rtype, _ttl, value in reply['answers'] if rtype == 'TXT' and value.lower().startswith('v=spf1')), '')
            items += spf_follow(spf, ask) if spf else []
        if check == 'client PTR':
            for _rtype, _ttl, target in reply['answers'][:3]:
                if DOMAIN_RE.match(target):
                    family = 'AAAA' if ':' in str(doc.get('ip')) else 'A'
                    forward = ask(target, family)
                    items.append(('client forward', target, family, forward))
        for item_check, item_name, item_type, item_reply in items:
            key = record_key(item_name, item_type, item_reply['answers'])
            records[key] = {'name': item_name, 'type': item_type, 'answers': item_reply['answers']}
            entry = {'check': item_check, 'query': item_name, 'type': item_type, 'record': key, 'rcode': item_reply['rcode'], 'ad': item_reply['ad'],
                     'ms': item_reply['ms'], 'ttl': min((ttl for _t, ttl, _v in item_reply['answers']), default=None)}
            if item_reply.get('error'):
                entry['error'] = item_reply['error']
            if item_check in ('dkim', 'arc'):
                txt = next((value for rtype, _ttl, value in item_reply['answers'] if rtype == 'TXT'), '')
                entry['key'] = key_info(txt) if txt else None
            checks.append(entry)
    forward = [entry for entry in checks if entry['check'] == 'client forward']
    ptr_ok = any(str(doc.get('ip')) in [value for _t, _ttl, value in records[entry['record']]['answers']] for entry in forward)
    verdicts, lists = results(doc)
    return {'asked': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(asked)), 'resolver': resolver_name,
            'note': 'Asked again right after the scan; within the TTL these are the answers from the cache of the resolver.',
            'checks': checks, 'fcrdns': ptr_ok if forward else None, 'results': verdicts, 'blocklists': lists}, records


def self_test():
    # A real reply: compression, TXT in two strings, the AD flag.
    reply = (struct.pack('>HHHHHH', 7, 0x81A0, 1, 2, 0, 0) + b'\x06_dmarc\x07example\x03org\x00' + struct.pack('>HH', 16, 1)
             + b'\xc0\x0c' + struct.pack('>HHIH', 16, 1, 300, 22) + b'\x0bv=DMARC1; p' + b'\x09=reject; '
             + b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 60, 4) + bytes([192, 0, 2, 1]))
    signed = reply[:6] + struct.pack('>H', 3) + reply[8:] + b'\xc0\x0c' + struct.pack('>HHIH', 46, 1, 60, 3) + b'sig'
    assert [answer[0] for answer in parse_answer(signed, 7)['answers']] == ['TXT', 'A'], 'RRSIG is not an answer of its own'
    null_mx = (struct.pack('>HHHHHH', 9, 0x8180, 1, 1, 0, 0) + b'\x01a\x07example\x00' + struct.pack('>HH', 15, 1)
               + b'\xc0\x0c' + struct.pack('>HHIH', 15, 1, 60, 3) + b'\x00\x00\x00')
    assert parse_answer(null_mx, 9)['answers'] == [('MX', 60, '0 .')]
    parsed = parse_answer(reply, 7)
    assert parsed == {'rcode': 0, 'ad': True, 'tc': False, 'answers': [('TXT', 300, 'v=DMARC1; p=reject; '), ('A', 60, '192.0.2.1')]}, parsed
    for bad in (reply[:10], reply[:30], b'\x00\x07' + reply[2:12] + b'\xc0\x0c\xc0\x0c'):
        try:
            parse_answer(bad, 7)
            raise AssertionError(bad)
        except (ValueError, struct.error, IndexError):
            pass
    try:
        parse_answer(reply, 8)
        raise AssertionError('wrong id accepted')
    except ValueError:
        pass
    assert query_packet('a.example', 'TXT', 1)[12:23] == b'\x01a\x07example\x00'
    assert record_key('A.example.', 'TXT', [('TXT', 300, 'x')]) == record_key('a.example', 'TXT', [('TXT', 5, 'x')])
    assert key_info('v=DKIM1; k=rsa; p=' + base64.b64encode(b'x' * 294).decode())['bits'] == 2048
    assert key_info('v=DKIM1; k=ed25519; p=' + base64.b64encode(b'x' * 32).decode()) == {'type': 'ed25519', 'bits': 256}
    assert key_info('v=DKIM1; p=')['revoked']
    answers = {('example.org', 'TXT'): ['v=spf1 include:_spf.example.net -all'], ('_spf.example.net', 'TXT'): ['v=spf1 include:_spf.example.net ip4:192.0.2.0/24 -all'],
               ('_dmarc.example.org', 'TXT'): ['v=DMARC1; p=none'], ('sel._domainkey.example.org', 'TXT'): ['v=DKIM1; k=ed25519; p=' + base64.b64encode(b'k' * 32).decode()],
               ('1.2.0.192.in-addr.arpa', 'PTR'): ['mx.example.org'], ('mx.example.org', 'A'): ['192.0.2.1']}
    asked = []

    def fake(name, qtype):
        asked.append((name, qtype))
        values = answers.get((name, qtype), [])
        return {'rcode': 0 if values else 3, 'ad': False, 'answers': [(qtype, 300, value) for value in values], 'ms': 0.1}
    doc = {'from': 'bounce@example.org', 'ip': '192.0.2.1', 'symbols': [{'name': 'R_SPF_ALLOW', 'options': ['+ip4:192.0.2.0/24']}, {'name': 'DMARC_POLICY_ALLOW'},
                                                                         {'name': 'RBL_SPAMHAUS_ZEN', 'options': ['192.0.2.1:127.0.0.2'], 'score': 4.0}]}
    headers = [('From', 'A <a@example.org>'), ('DKIM-Signature', 'v=1; a=ed25519-sha256; d=example.org; s=sel; b=x'), ('DKIM-Signature', 'd=evil"; s=x')]
    evidence, records = collect(doc, headers, fake)
    names = [(entry['check'], entry['query']) for entry in evidence['checks']]
    assert ('spf include', '_spf.example.net') in names and names.count(('spf include', '_spf.example.net')) == 1, 'a loop is followed once'
    assert ('dmarc', '_dmarc.example.org') in names and ('dkim', 'sel._domainkey.example.org') in names and ('client forward', 'mx.example.org') in names
    assert not [name for name, _type in asked if 'evil' in name], 'a bad tag is never asked'
    assert evidence['fcrdns'] is True and evidence['results']['spf'] == ['R_SPF_ALLOW [+ip4:192.0.2.0/24]']
    assert evidence['blocklists'] == [{'symbol': 'RBL_SPAMHAUS_ZEN', 'matched': ['192.0.2.1:127.0.0.2'], 'score': 4.0}]
    assert [entry['key'] for entry in evidence['checks'] if entry['check'] == 'dkim'] == [{'type': 'ed25519', 'bits': 256}]
    assert len(records) == len({entry['record'] for entry in evidence['checks']})
    # Nothing listens here: an error result, quickly, no exception.
    reply = lookup('example.org', 'TXT', ('127.0.0.1', 9), 0.2)
    assert reply['answers'] == [] and 'error' in reply and reply['ms'] < 1000
    print('self-test ok')


if __name__ == '__main__':
    self_test()
