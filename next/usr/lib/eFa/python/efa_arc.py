# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M1-1: a new ARC set (RFC 8617) after the content milter changed a mail.

rspamd seals the mail (instance n) before efa-cdr runs; when efa-cdr then changes links, tracking or the banner, the message
signature of instance n no longer fits. efa-cdr adds instance n+1 with the same domain and selector: ARC-Authentication-Results
(the results rspamd wrote), ARC-Message-Signature over the changed mail and ARC-Seal over all sets. A receiver checks only the
newest message signature and every seal, so the chain holds again. Only rsa-sha256 (the one algorithm of RFC 8617), relaxed
canonicalisation, standard library plus python3-cryptography (already a dependency)."""
import base64
import hashlib
import re
import time

# Headers efa-cdr never changes; the MIME headers (Content-Type ...) are left out because the disarm may rewrite them.
SIGNED = ('from', 'to', 'cc', 'subject', 'date', 'message-id', 'reply-to', 'in-reply-to', 'references')
ARC_NAMES = {'arc-authentication-results': 'aar', 'arc-message-signature': 'ams', 'arc-seal': 'as'}
MAX_INSTANCE = 50


def canon_header(name, value):
    """Relaxed header canonicalisation (RFC 6376 3.4.2), with the CRLF."""
    value = re.sub(r'\r?\n', '', value)
    value = re.sub(r'[ \t]+', ' ', value).strip()
    return f'{name.strip().lower()}:{value}\r\n'.encode('utf-8', 'surrogateescape')


def canon_body(body):
    """Relaxed body canonicalisation (RFC 6376 3.4.4): lines end in CRLF, white space folded, empty lines at the end gone."""
    lines = re.split(rb'\r?\n', body)
    out = [re.sub(rb'[ \t]+', b' ', line).rstrip(b' \t') for line in lines]
    while out and out[-1] == b'':
        out.pop()
    return b''.join(line + b'\r\n' for line in out)


def tag(value, name):
    found = re.search(r'(?:^|;)\s*' + name + r'\s*=\s*([^;]*)', value)
    return re.sub(r'\s+', '', found.group(1)) if found else ''


def without_b(value):
    """The value with the b= tag empty (for signing and checking), the bh= tag untouched."""
    return re.sub(r'((?:^|;)\s*b\s*=)[^;]*', r'\1', value)


def arc_sets(headers):
    """{instance: {'aar'|'ams'|'as': value}} of the ARC headers; None for a broken chain (a gap, a double, over 50)."""
    sets = {}
    for name, value in headers:
        kind = ARC_NAMES.get(name.lower())
        if not kind:
            continue
        instance = tag(value, 'i')
        if not instance.isdigit() or not 1 <= int(instance) <= MAX_INSTANCE or kind in sets.get(int(instance), {}):
            return None
        sets.setdefault(int(instance), {})[kind] = value
    if sorted(sets) != list(range(1, len(sets) + 1)) or any(len(item) != 3 for item in sets.values()):
        return None
    return sets


def _sign(key_pem, data):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError('ARC signs with RSA only')
    return base64.b64encode(key.sign(data, padding.PKCS1v15(), hashes.SHA256())).decode()


def _wrap(value):
    """The base64 of a signature folded, so no header line is longer than the mail standard allows (LF and tab: the milter
    protocol folds with a bare newline, Postfix writes CRLF)."""
    return '\n\t'.join(value[index:index + 72] for index in range(0, len(value), 72))


def seal(headers, body, domain, selector, key_pem, authserv_id, results, now=None):
    """The headers of instance n+1 for this mail: [(name, value)] in the order ARC-Seal, ARC-Message-Signature,
    ARC-Authentication-Results. headers: the header list as it leaves (name, value), body: the body as it leaves."""
    sets = arc_sets(headers)
    if sets is None:
        raise ValueError('the ARC chain of the mail is broken')
    instance = len(sets) + 1
    if instance > MAX_INSTANCE:
        raise ValueError('too many ARC sets')
    # cv: none for the first set; fail when an earlier seal says so (then the chain stays failed), else pass. The seal of
    # instance n comes from rspamd on this host a moment before: it checked the chain before it.
    cv = 'none' if instance == 1 else 'fail' if any(tag(item['as'], 'cv') == 'fail' for item in sets.values()) else 'pass'
    stamp = int(time.time() if now is None else now)
    aar = f'i={instance}; {authserv_id}; {results or "none"}'
    last = {}
    for name, value in headers:
        if name.lower() in SIGNED:
            last[name.lower()] = (name, value)
    signed = [name for name in SIGNED if name in last]
    bh = base64.b64encode(hashlib.sha256(canon_body(body)).digest()).decode()
    ams = f'i={instance}; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={selector}; t={stamp}; h={":".join(signed)}; bh={bh}; b='
    data = b''.join(canon_header(*last[name]) for name in signed) + canon_header('ARC-Message-Signature', ams)[:-2]
    ams += _wrap(_sign(key_pem, data))
    arc_seal = f'i={instance}; a=rsa-sha256; t={stamp}; cv={cv}; d={domain}; s={selector}; b='
    chain = {**sets, instance: {'aar': aar, 'ams': ams, 'as': arc_seal}}
    data = b''
    for number in sorted(chain):
        data += canon_header('ARC-Authentication-Results', chain[number]['aar']) + canon_header('ARC-Message-Signature', chain[number]['ams'])
        data += canon_header('ARC-Seal', without_b(chain[number]['as']) if number == instance else chain[number]['as'])
    data = data[:-2]
    arc_seal += _wrap(_sign(key_pem, data))
    return [('ARC-Seal', arc_seal), ('ARC-Message-Signature', ams), ('ARC-Authentication-Results', aar)]


def verify(headers, body, public_pem):
    """True when the newest message signature and every seal of the mail check out with this key (one sealer, for the tests)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    key = serialization.load_pem_public_key(public_pem)
    sets = arc_sets(headers)
    if not sets:
        return False
    last = {}
    for name, value in headers:
        last[name.lower()] = (name, value)

    def check(signature, data):
        try:
            key.verify(base64.b64decode(re.sub(r'\s+', '', signature)), data, padding.PKCS1v15(), hashes.SHA256())
            return True
        except (InvalidSignature, ValueError):
            return False
    top = max(sets)
    ams = sets[top]['ams']
    if tag(ams, 'bh') != base64.b64encode(hashlib.sha256(canon_body(body)).digest()).decode():
        return False
    data = b''.join(canon_header(*last[name]) for name in tag(ams, 'h').lower().split(':') if name in last)
    if not check(tag(ams, 'b'), data + canon_header('ARC-Message-Signature', without_b(ams))[:-2]):
        return False
    for number in sorted(sets):
        data = b''
        for item in range(1, number + 1):
            data += canon_header('ARC-Authentication-Results', sets[item]['aar']) + canon_header('ARC-Message-Signature', sets[item]['ams'])
            data += canon_header('ARC-Seal', without_b(sets[item]['as']) if item == number else sets[item]['as'])
        if not check(tag(sets[number]['as'], 'b'), data[:-2]):
            return False
    return True


def self_test():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert canon_header('Subject', ' Hello \r\n\t World  ') == b'subject:Hello World\r\n'
    assert canon_body(b'a  b \r\nc\r\n\r\n\r\n') == b'a b\r\nc\r\n' and canon_body(b'') == b''
    assert without_b('i=1; bh=abc; b=xyz') == 'i=1; bh=abc; b=' and tag('i=2; cv=pass; b=x', 'cv') == 'pass'
    headers = [('From', 'Anna <a@far.example>'), ('To', 'b@own.example'), ('Subject', 'offer'), ('Date', 'Mon, 9 Nov 2026 10:00:00 +0000')]
    # rspamd's seal (instance 1) over the original, then efa-cdr changes the body and adds instance 2.
    first = seal(headers, b'Hello http://x.example/?utm_source=a\r\n', 'own.example', 'efa-arc', private, 'mx.own.example', 'spf=pass', now=100)
    assert verify(headers + first, b'Hello http://x.example/?utm_source=a\r\n', public)
    changed = b'Hello http://x.example/\r\n'
    assert not verify(headers + first, changed, public), 'the change breaks the old message signature'
    second = seal(first + headers, changed, 'own.example', 'efa-arc', private, 'mx.own.example', 'spf=pass; arc=pass', now=200)
    assert [name for name, _value in second] == ['ARC-Seal', 'ARC-Message-Signature', 'ARC-Authentication-Results']
    assert tag(second[0][1], 'i') == '2' and tag(second[0][1], 'cv') == 'pass' and tag(first[0][1], 'cv') == 'none'
    assert verify(second + first + headers, changed, public), 'the new set holds the chain again'
    assert not verify(second + first + headers, changed + b'more\r\n', public)
    assert arc_sets(first + first) is None and arc_sets([('ARC-Seal', 'i=2; cv=none; b=x')]) is None and arc_sets([]) == {}
    failed = [(name, value.replace('cv=none', 'cv=fail')) for name, value in first]
    assert tag(seal(failed + headers, changed, 'own.example', 'efa-arc', private, 'mx', 'x', now=1)[0][1], 'cv') == 'fail'
    print('self-test ok')


if __name__ == '__main__':
    import sys
    if '--self-test' in sys.argv:
        self_test()
