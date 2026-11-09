# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Signed link tokens of the link check: the content milter writes them into mail, the web interface follows only those."""
import base64
import hashlib
import hmac
import re

# Symbols of rspamd that mean a listed or phishing address.
DANGEROUS = re.compile(r'^(URIBL_|SURBL_|DBL_|RSPAMD_URIBL|PH_SURBL|ABUSE_SURBL|CRACKED_SURBL|MSBL_EBL|SEM_URIBL|PHISHED_|PHISHING|EFA_RBL_|EFA_YOUNG_DOMAIN)')


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def link_token(url, key, tenant=''):
    """The address, and a signature over it: the redirect follows only what this server wrote. With a tenant (item 4: the hints
    of its warning page) the tenant is a third part, signed with the address."""
    data = url.encode('utf-8')
    signed = data + (b'\0' + tenant.encode() if tenant else b'')
    sign = hmac.new(key, signed, hashlib.sha256).digest()[:12]
    return _b64(data) + '.' + _b64(sign) + ('.' + tenant if tenant else '')


def _parts(token, key):
    """(address, tenant) of a token whose signature fits, else None."""
    pieces = token.split('.')
    if len(pieces) not in (2, 3) or (len(pieces) == 3 and not re.fullmatch(r'\d{1,9}', pieces[2])):
        return None
    try:
        data, sign = (base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)) for part in pieces[:2])
    except (ValueError, TypeError):
        return None
    tenant = pieces[2] if len(pieces) == 3 else ''
    signed = data + (b'\0' + tenant.encode() if tenant else b'')
    if not hmac.compare_digest(hmac.new(key, signed, hashlib.sha256).digest()[:12], sign):
        return None
    url = data.decode('utf-8', 'replace')
    return (url, tenant) if re.match(r'https?://[^\s]+$', url, re.I) else None


def link_target(token, key):
    """The address of a token, or None if the signature does not fit or it is no http or https address."""
    found = _parts(token, key)
    return found[0] if found else None


def link_tenant(token, key):
    """The tenant a token was written for, '' for none or a token that does not fit."""
    found = _parts(token, key)
    return found[1] if found else ''


def dangerous(symbols):
    """The names of rspamd symbols that make an address dangerous."""
    return sorted(name for name in symbols if DANGEROUS.match(name))


def self_test():
    key = b'k' * 32
    token = link_token('https://shop.example/a?b=1', key)
    assert link_target(token, key) == 'https://shop.example/a?b=1' and link_target(token, b'x' * 32) is None and link_target('bad', key) is None
    assert link_target(link_token('javascript:alert(1)', key), key) is None
    with_tenant = link_token('https://shop.example/a', key, '7')
    assert link_target(with_tenant, key) == 'https://shop.example/a' and link_tenant(with_tenant, key) == '7' and link_tenant(token, key) == ''
    assert link_target(with_tenant[:-1] + '8', key) is None, 'the tenant is signed with the address'
    assert link_target(with_tenant + 'x', key) is None
    assert dangerous(['DBL_SPAM', 'MIME_GOOD', 'URIBL_BLACK', 'PHISHING']) == ['DBL_SPAM', 'PHISHING', 'URIBL_BLACK']
    print('self-test ok')


if __name__ == '__main__':
    self_test()
