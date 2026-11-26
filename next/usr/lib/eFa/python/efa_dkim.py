# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""G7-25: DKIM signatures made again after efa-cdr changed an outgoing mail (CDR outbound, opt-in).

rspamd signs outgoing mail before efa-cdr runs. When content disarm changes such a mail, its DKIM signature no longer fits.
efa-cdr then replaces each signature of this host with a new one over the changed mail: same domain, selector, algorithm and
signed header list (RFC 6376, relaxed/relaxed; rsa-sha256 and ed25519-sha256 of RFC 8463). If one signature cannot be made
again (no key here, a signature of another server), the caller leaves the mail unchanged: a broken signature is never sent.
Standard library plus python3-cryptography (already a dependency); the canonicalisation is the one of efa_arc."""
import base64
import hashlib
import re
import time

import efa_arc

SELECTOR_RE = re.compile(r'^[A-Za-z0-9._-]{1,63}$')
DOMAIN_RE = re.compile(r'^[a-z0-9.-]{1,253}$')


def load_key(data):
    """A private key from a PEM file, or from the base64 of 64 bytes rspamd writes for ED25519 (seed, then public key)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    if b'-----BEGIN' in data:
        return serialization.load_pem_private_key(data, password=None)
    raw = base64.b64decode(data.strip(), validate=True)
    if len(raw) != 64:
        raise ValueError('not a key rspamd or OpenSSL wrote')
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw[:32])


def _algorithm(key):
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    if isinstance(key, rsa.RSAPrivateKey):
        return 'rsa-sha256'
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return 'ed25519-sha256'
    raise ValueError('DKIM signs with RSA or ED25519 only')


def _raw_sign(key, data):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    if _algorithm(key) == 'rsa-sha256':
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    # RFC 8463: Ed25519 signs the SHA-256 of the data.
    return key.sign(hashlib.sha256(data).digest())


def _picked(headers, names):
    """The header lines a list of signed names stands for: each name takes the next occurrence from the bottom (RFC 6376 5.4.2);
    a name with no occurrence left signs nothing."""
    used, picked = {}, []
    for name in names:
        lower = name.lower()
        found = [item for item in headers if item[0].lower() == lower]
        count = used.get(lower, 0)
        if count < len(found):
            picked.append(found[len(found) - 1 - count])
        used[lower] = count + 1
    return picked


def sign(headers, body, domain, selector, key_data, names, now=None, signer=None, algorithm=None):
    """('DKIM-Signature', value) over the mail as it leaves. headers: [(name, value)] as they leave, body: bytes. G7-17: with
    signer (a key in a hardware module) key_data is None: signer(data) gives the signature for algorithm."""
    key = None if signer else load_key(key_data)
    algorithm = algorithm if signer else _algorithm(key)
    bh = base64.b64encode(hashlib.sha256(efa_arc.canon_body(body)).digest()).decode()
    stamp = int(time.time() if now is None else now)
    value = f'v=1; a={algorithm}; c=relaxed/relaxed; d={domain}; s={selector}; t={stamp}; h={":".join(names)}; bh={bh}; b='
    data = b''.join(efa_arc.canon_header(*item) for item in _picked(headers, names)) + efa_arc.canon_header('DKIM-Signature', value)[:-2]
    raw = signer(data) if signer else _raw_sign(key, data)
    return 'DKIM-Signature', value + efa_arc._wrap(base64.b64encode(raw).decode())


# G7-17: what a signature in a hardware module needs to be: the headers that DKIM covers for a mail eFa-next signs itself.
HSM_HEADERS = ['from', 'to', 'cc', 'subject', 'date', 'message-id', 'reply-to', 'in-reply-to', 'references', 'mime-version', 'content-type']


def hsm_header(raw, domain, selector, signer, algorithm, now=None):
    """('DKIM-Signature', value) of a whole mail, signed in a hardware module; only the headers of HSM_HEADERS that it has."""
    headers, body = split(raw)
    present = {name.lower() for name, _value in headers}
    return sign(headers, body, domain, selector, None, [name for name in HSM_HEADERS if name in present], now, signer, algorithm)


def verify(headers, body, value, public):
    """True when the DKIM-Signature value fits the mail and the public key (cryptography object): for the tests."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding
    if efa_arc.tag(value, 'bh') != base64.b64encode(hashlib.sha256(efa_arc.canon_body(body)).digest()).decode():
        return False
    names = [name for name in efa_arc.tag(value, 'h').split(':') if name]
    data = b''.join(efa_arc.canon_header(*item) for item in _picked(headers, names)) + efa_arc.canon_header('DKIM-Signature', efa_arc.without_b(value))[:-2]
    signature = base64.b64decode(re.sub(r'\s+', '', efa_arc.tag(value, 'b')))
    try:
        if isinstance(public, ed25519.Ed25519PublicKey):
            public.verify(signature, hashlib.sha256(data).digest())
        else:
            public.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except (InvalidSignature, ValueError):
        return False


def split(raw):
    """([(name, value)], body) of a whole mail; folded values keep their line breaks, as the milter hands them on."""
    head, _sep, body = raw.replace(b'\r\n', b'\n').partition(b'\n\n')
    headers = []
    for line in head.decode('utf-8', 'surrogateescape').split('\n'):
        if line[:1] in (' ', '\t') and headers:
            headers[-1] = (headers[-1][0], headers[-1][1] + '\n' + line)
        elif ':' in line:
            name, _colon, value = line.partition(':')
            headers.append((name, value.lstrip(' ')))
    return headers, body.replace(b'\n', b'\r\n')


def resign(old_headers, changed, key_for, now=None):
    """[(index among the DKIM-Signature headers, 1-based), new value] for each signature of the mail, made again over the changed
    mail; None when one of them cannot be made again (key_for(domain, selector) gives the key bytes or None). [] without one."""
    headers, body = split(changed)
    found, index = [], 0
    for name, value in old_headers:
        if name.lower() != 'dkim-signature':
            continue
        index += 1
        domain, selector = efa_arc.tag(value, 'd').lower(), efa_arc.tag(value, 's')
        names = [item for item in efa_arc.tag(value, 'h').split(':') if item]
        if not DOMAIN_RE.match(domain) or not SELECTOR_RE.match(selector) or not names or efa_arc.tag(value, 'l'):
            return None
        key = key_for(domain, selector)
        if not key:
            return None
        found.append((index, sign(headers, body, domain, selector, key, names, now)[1]))
    return found


def self_test():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pem = rsa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    ed_key = ed25519.Ed25519PrivateKey.generate()
    seed = ed_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = ed_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ed_rspamd = base64.b64encode(seed + pub)
    raw = b'From: A <a@own.example>\r\nTo: b@far.example\r\nSubject: offer\r\n  folded\r\nContent-Type: text/plain\r\n\r\nHello  \r\n\r\n'
    headers, body = split(raw)
    assert headers[2] == ('Subject', 'offer\n  folded') and body == b'Hello  \r\n\r\n'
    for key, public in ((rsa_pem, rsa_key.public_key()), (ed_rspamd, ed_key.public_key())):
        name, value = sign(headers, body, 'own.example', 's1', key, ['from', 'to', 'subject', 'content-type'], now=100)
        assert name == 'DKIM-Signature' and verify(headers, body, value, public), value
        assert not verify(headers, b'Hello\r\nchanged\r\n', value, public), 'another body'
        assert not verify([('From', 'x@evil.example')] + headers[1:], body, value, public), 'another From'
    assert efa_arc.tag(sign(headers, body, 'own.example', 's1', ed_rspamd, ['from'])[1], 'a') == 'ed25519-sha256'
    # dkimpy, where it is there (CI), checks the RSA signature the way a receiver does.
    try:
        import dkim
    except ImportError:
        dkim = None
    if dkim:
        public_der = rsa_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        record = b'v=DKIM1; k=rsa; p=' + base64.b64encode(public_der)
        signed = ('DKIM-Signature: ' + sign(headers, body, 'own.example', 's1', rsa_pem, ['from', 'to', 'subject'])[1].replace('\n', '\r\n')
                  + '\r\n').encode() + raw
        assert dkim.verify(signed, dnsfunc=lambda name, timeout=5: record), 'dkimpy accepts it'
    # resign: every signature with its key is made again over the changed mail; one without a key leaves all as they were.
    old = [('DKIM-Signature', 'v=1; a=rsa-sha256; d=own.example; s=s1; h=from:to:subject; bh=x; b=y'),
           ('DKIM-Signature', 'v=1; a=ed25519-sha256; d=own.example; s=s2; h=from:subject; bh=x; b=y')] + headers
    keys = {('own.example', 's1'): rsa_pem, ('own.example', 's2'): ed_rspamd}
    changed = raw.replace(b'Hello', b'Clean')
    new = resign(old, changed, lambda d, s: keys.get((d, s)), now=200)
    assert [index for index, _value in new] == [1, 2]
    after_headers, after_body = split(changed)
    assert verify(after_headers, after_body, new[0][1], rsa_key.public_key()) and verify(after_headers, after_body, new[1][1], ed_key.public_key())
    assert resign(old, changed, lambda d, s: keys.get((d, s)) if s == 's1' else None) is None, 'no key for s2: unchanged'
    assert resign(headers, changed, lambda d, s: None) == [], 'no signature: nothing to make'
    assert resign([('DKIM-Signature', 'v=1; d=own.example; s=s1; h=from; l=10; bh=x; b=y')], changed, lambda d, s: rsa_pem) is None, 'l= stays'
    # G7-17: a signer outside (the module) gives the same signature as the key itself.
    outside = lambda data: _raw_sign(rsa_key, data)
    name, value = hsm_header(raw, 'own.example', 'hsm', outside, 'rsa-sha256', now=300)
    assert verify(headers, body, value, rsa_key.public_key()) and 'h=from:to:subject:content-type;' in value, value
    print('efa_dkim self-test ok')


if __name__ == '__main__':
    self_test()
