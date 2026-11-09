#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""6b: role addresses (postmaster@, abuse@, security@ ...) of a domain go to the targets set for them. This Postfix pipe gets the
mail after the filter and sends it on with sendmail. The envelope sender becomes an SRS address of the domain (Sender Rewriting
Scheme), so SPF of the targets passes; a bounce to such an address comes back here and goes to the original sender.
Exit 0 when done, 67 for an unknown address or a broken SRS address, 75 so Postfix tries again on any other failure."""
import base64
import hashlib
import hmac
import json
import re
import subprocess
import sys
import syslog
import time

FORWARD_FILE = '/etc/eFa/roles-forward.json'
SRS_KEY = '/etc/eFa/srs.key'
MAX_MAIL = 64 * 1024 * 1024
SRS_DAYS = 21
EX_NOUSER, EX_TEMPFAIL = 67, 75
B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'


def _hash(key, *parts):
    digest = hmac.new(key, ''.join(parts).lower().encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()[:4].replace('+', '-').replace('/', '_')


def _stamp(now):
    day = int(now // 86400) % 1024
    return B32[day >> 5] + B32[day & 31]


def srs_forward(sender, domain, key, now=None):
    """The SRS address of a sender at domain: SRS0=HHHH=TT=senderdomain=local, or SRS1 for an SRS address of another forwarder."""
    local, _, sender_domain = sender.rpartition('@')
    if not local or not sender_domain or sender_domain.lower() == domain.lower() and not re.match(r'srs[01]=', local, re.I):
        return sender
    if re.match(r'srs0=', local, re.I):
        rest = local[5:]
        return f'SRS1={_hash(key, sender_domain, rest)}={sender_domain}=={rest}@{domain}'
    if re.match(r'srs1=', local, re.I):
        _hash_old, first, rest = (local[5:].split('=', 2) + ['', ''])[:3]
        return f'SRS1={_hash(key, first, rest)}={first}={rest}@{domain}'
    stamp = _stamp(time.time() if now is None else now)
    return f'SRS0={_hash(key, stamp, sender_domain, local)}={stamp}={sender_domain}={local}@{domain}'


def srs_reverse(address, key, now=None):
    """The original address of an SRS address made here, or None when its hash does not fit or it is older than 21 days."""
    local = address.rpartition('@')[0]
    if re.match(r'srs0=', local, re.I):
        parts = local[5:].split('=', 3)
        if len(parts) != 4:
            return None
        given, stamp, domain, user = parts
        if not hmac.compare_digest(given.lower(), _hash(key, stamp, domain, user).lower()) or len(stamp) != 2 or \
                any(char not in B32 for char in stamp.upper()):
            return None
        day = (B32.index(stamp.upper()[0]) << 5) + B32.index(stamp.upper()[1])
        if (int((time.time() if now is None else now) // 86400) - day) % 1024 > SRS_DAYS:
            return None
        return f'{user}@{domain}'
    if re.match(r'srs1=', local, re.I):
        parts = local[5:].split('=', 2)
        if len(parts) != 3 or not parts[2].startswith('='):
            return None
        given, first, rest = parts[0], parts[1], parts[2][1:]
        if not hmac.compare_digest(given.lower(), _hash(key, first, rest).lower()):
            return None
        return f'SRS0={rest}@{first}'
    return None


def targets_of(recipient, forward, key):
    """(envelope sender function, targets) for a recipient: a role address, or an SRS address of a bounce."""
    recipient = recipient.lower()
    if recipient in forward['roles']:
        return 'forward', forward['roles'][recipient]
    if recipient.rpartition('@')[2] in forward['domains'] and re.match(r'srs[01]=', recipient, re.I):
        original = srs_reverse(recipient, key)
        return ('bounce', [original]) if original else (None, [])
    return None, []


def main():
    sender, recipient = sys.argv[1], sys.argv[2]
    try:
        with open(FORWARD_FILE) as f:
            forward = json.load(f)
        with open(SRS_KEY, 'rb') as f:
            key = f.read().strip()
    except (OSError, ValueError) as err:
        syslog.syslog(syslog.LOG_ERR, f'efa-roles: settings not readable: {err}')
        return EX_TEMPFAIL
    kind, targets = targets_of(recipient, forward, key)
    if not targets:
        print(f'{recipient}: no such role or bounce address', file=sys.stderr)
        return EX_NOUSER
    raw = sys.stdin.buffer.read(MAX_MAIL + 1)
    if len(raw) > MAX_MAIL:
        return 73  # EX_CANTCREAT: too large, Postfix bounces it
    domain = recipient.rpartition('@')[2]
    # A bounce goes back with an empty sender; forwarded mail carries the SRS address of the role domain.
    envelope = '' if kind == 'bounce' or not sender else srs_forward(sender, domain, key)
    done = subprocess.run(['/usr/sbin/sendmail', '-G', '-i', '-f', envelope, '--'] + targets, input=raw, capture_output=True, timeout=120)
    if done.returncode != 0:
        syslog.syslog(syslog.LOG_WARNING, f'efa-roles: sendmail failed for {recipient}: {done.stderr[-200:]!r}')
        return EX_TEMPFAIL
    syslog.syslog(syslog.LOG_INFO, f'efa-roles: {recipient} {kind} to {len(targets)} targets')
    return 0


def self_test():
    key, now = b'k' * 32, 1_800_000_000
    srs = srs_forward('alice@far.example', 'own.example', key, now)
    assert srs.startswith('SRS0=') and srs.endswith('=far.example=alice@own.example'), srs
    assert srs_reverse(srs, key, now) == 'alice@far.example' and srs_reverse(srs.upper(), key, now) == 'ALICE@FAR.EXAMPLE'
    assert srs_reverse(srs, key, now + 22 * 86400) is None, 'older than 21 days'
    assert srs_reverse(srs.replace('alice', 'mallory'), key, now) is None and srs_reverse(srs, b'other', now) is None
    assert srs_reverse('SRS0=xx@own.example', key, now) is None and srs_reverse('plain@own.example', key, now) is None
    again = srs_forward('SRS0=abcd=AA=far.example=alice@mid.example', 'own.example', key, now)
    assert again.startswith('SRS1=') and srs_reverse(again, key, now) == 'SRS0=abcd=AA=far.example=alice@mid.example', again
    assert srs_forward('bob@own.example', 'own.example', key, now) == 'bob@own.example'
    forward = {'roles': {'abuse@own.example': ['team@corp.example']}, 'domains': ['own.example']}
    assert targets_of('Abuse@own.example', forward, key) == ('forward', ['team@corp.example'])
    assert targets_of(srs_forward('alice@far.example', 'own.example', key), forward, key) == ('bounce', ['alice@far.example']) and targets_of('nobody@own.example', forward, key) == (None, [])
    print('self-test ok')


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        self_test()
    else:
        sys.exit(main())
