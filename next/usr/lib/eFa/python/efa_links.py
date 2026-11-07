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


def link_token(url, key):
    """The address, and a signature over it: the redirect follows only what this server wrote."""
    data = url.encode('utf-8')
    sign = hmac.new(key, data, hashlib.sha256).digest()[:12]
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode() + '.' + base64.urlsafe_b64encode(sign).rstrip(b'=').decode()


def link_target(token, key):
    """The address of a token, or None if the signature does not fit or it is no http or https address."""
    try:
        data, sign = (base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)) for part in token.split('.', 1))
    except (ValueError, TypeError):
        return None
    if not hmac.compare_digest(hmac.new(key, data, hashlib.sha256).digest()[:12], sign):
        return None
    url = data.decode('utf-8', 'replace')
    return url if re.match(r'https?://[^\s]+$', url, re.I) else None


def dangerous(symbols):
    """The names of rspamd symbols that make an address dangerous."""
    return sorted(name for name in symbols if DANGEROUS.match(name))


def self_test():
    key = b'k' * 32
    token = link_token('https://shop.example/a?b=1', key)
    assert link_target(token, key) == 'https://shop.example/a?b=1' and link_target(token, b'x' * 32) is None and link_target('bad', key) is None
    assert link_target(link_token('javascript:alert(1)', key), key) is None
    assert dangerous(['DBL_SPAM', 'MIME_GOOD', 'URIBL_BLACK', 'PHISHING']) == ['DBL_SPAM', 'PHISHING', 'URIBL_BLACK']
    print('self-test ok')


if __name__ == '__main__':
    self_test()
