# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The second factor of 5r without storage: TOTP after RFC 6238 (HMAC-SHA1, 30 seconds, 6 digits), the recovery codes and the
otpauth address for the app. efactl keeps the secrets (encrypted, in the database); the setup wizard (efa-init.py) uses the same
code to set up the main admin before the database is there."""
import base64
import hashlib
import hmac
import re
import secrets
import time
import urllib.parse

ISSUER = 'eFa-next'


def hotp(secret, counter, digits=6):
    """RFC 4226: the code of one counter."""
    digest = hmac.new(secret, counter.to_bytes(8, 'big'), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff) % 10 ** digits).zfill(digits)


def totp_step(secret, code, last_step, now=None):
    """The step of a code that fits now (one step of slack each way) and is newer than the last one used, else None."""
    step = int((time.time() if now is None else now) // 30)
    code = re.sub(r'\s', '', code or '')
    if not re.fullmatch(r'\d{6}', code):
        return None
    for candidate in (step - 1, step, step + 1):
        if candidate > last_step and hmac.compare_digest(hotp(secret, candidate), code):
            return candidate
    return None


def recovery_hash(code):
    return hashlib.sha256(('efa-totp-recovery:' + re.sub(r'[\s-]', '', code).lower()).encode()).hexdigest()


def recovery_codes():
    """Ten new recovery codes, shown once; only their hashes are kept."""
    return ['-'.join(secrets.token_hex(2) for _ in range(3)) for _ in range(10)]


def secret_text(secret):
    return base64.b32encode(secret).decode().rstrip('=')


def secret_from_text(text):
    text = re.sub(r'\s', '', text or '').upper()
    return base64.b32decode(text + '=' * (-len(text) % 8))


def uri(secret, label):
    """The otpauth address the apps read from the QR code."""
    return (f'otpauth://totp/{urllib.parse.quote(f"{ISSUER}:{label}")}?secret={secret_text(secret)}&issuer={urllib.parse.quote(ISSUER)}'
            '&algorithm=SHA1&digits=6&period=30')


def grouped(secret):
    text = secret_text(secret)
    return ' '.join(text[i:i + 4] for i in range(0, len(text), 4))


def self_test():
    rfc = b'12345678901234567890'
    assert [hotp(rfc, i) for i in range(3)] == ['755224', '287082', '359152'] and hotp(rfc, 1, 8) == '94287082'
    assert totp_step(rfc, '287 082', 0, now=59) == 1 and totp_step(rfc, '287082', 1, now=59) is None
    assert recovery_hash('ab12-cd34-ef56') == recovery_hash('AB12 CD34 EF56')
    codes = recovery_codes()
    assert len(set(codes)) == 10 and all(re.fullmatch(r'[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}', code) for code in codes)
    assert secret_from_text(grouped(rfc).lower()) == rfc and len(secret_text(rfc)) == 32
    assert uri(rfc, 'admin@mx.example').startswith('otpauth://totp/eFa-next%3Aadmin%40mx.example?secret=GEZDGNBV')
    print('self-test ok')


if __name__ == '__main__':
    import sys
    if '--self-test' in sys.argv:
        self_test()
