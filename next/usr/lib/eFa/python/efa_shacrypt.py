# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SHA512-CRYPT ($6$, the scheme of glibc and Dovecot) in plain Python (PY-1): the crypt module of Python is gone from 3.13 on,
and EL10, FreeBSD and later Python versions still need the submitter logins Dovecot reads. Only hashlib of the standard library."""
import hashlib
import hmac
import secrets

ALPHABET = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
ROUNDS_DEFAULT, ROUNDS_MIN, ROUNDS_MAX = 5000, 1000, 999999999
# The order in which the 64 bytes of the digest go into the 86 characters (the specification of Ulrich Drepper).
ORDER = ((0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26), (6, 27, 48), (28, 49, 7), (50, 8, 29),
         (9, 30, 51), (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13), (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38),
         (18, 39, 60), (40, 61, 19), (62, 20, 41))


def _b64(a, b, c, count):
    value = (a << 16) | (b << 8) | c
    out = ''
    for _ in range(count):
        out += ALPHABET[value & 0x3f]
        value >>= 6
    return out


def _repeat(digest, length):
    return (digest * (length // 64 + 1))[:length]


def _hash(password, salt, rounds):
    alternate = hashlib.sha512(password + salt + password).digest()
    a = hashlib.sha512(password + salt + _repeat(alternate, len(password)))
    length = len(password)
    while length:
        a.update(alternate if length & 1 else password)
        length >>= 1
    a = a.digest()
    p = _repeat(hashlib.sha512(password * len(password)).digest(), len(password))
    s = _repeat(hashlib.sha512(salt * (16 + a[0])).digest(), len(salt))
    c = a
    for number in range(rounds):
        step = hashlib.sha512(p if number & 1 else c)
        if number % 3:
            step.update(s)
        if number % 7:
            step.update(p)
        step.update(c if number & 1 else p)
        c = step.digest()
    return ''.join(_b64(c[i], c[j], c[k], 4) for i, j, k in ORDER) + _b64(0, 0, c[63], 2)


def crypt(password, setting):
    """The crypt(3) result of password for a setting $6$[rounds=N$]salt[$...]; '' for any other setting."""
    if not setting.startswith('$6$'):
        return ''
    rest, rounds, named = setting[3:], ROUNDS_DEFAULT, False
    if rest.startswith('rounds='):
        number, _, rest = rest[7:].partition('$')
        if not number.isdigit():
            return ''
        rounds, named = min(max(int(number), ROUNDS_MIN), ROUNDS_MAX), True
    salt = rest.split('$', 1)[0][:16]
    head = '$6$' + (f'rounds={rounds}$' if named else '') + salt
    return head + '$' + _hash(password.encode(), salt.encode(), rounds)


def make(password, rounds=ROUNDS_DEFAULT):
    """A new SHA512-CRYPT hash with 16 random salt characters."""
    salt = ''.join(secrets.choice(ALPHABET) for _ in range(16))
    return crypt(password, f'$6$rounds={rounds}${salt}' if rounds != ROUNDS_DEFAULT else f'$6${salt}')


def verify(password, stored):
    """Constant-time check of a password against a $6$ hash."""
    return stored.startswith('$6$') and hmac.compare_digest(crypt(password, stored).encode(), stored.encode())


def self_test():
    # The test vectors of the specification, and the output of glibc (openssl passwd -6 gives the same).
    assert crypt('Hello world!', '$6$saltstring') == \
        '$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1'
    assert crypt('Hello world!', '$6$rounds=10000$saltstringsaltstring') == \
        '$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.'
    assert crypt('This is just a test', '$6$rounds=5000$toolongsaltstring') == \
        '$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0'
    assert crypt('we have a short salt string but not a short password', '$6$rounds=77777$short') == \
        '$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0'
    assert crypt('a short string', '$6$rounds=123456$asaltof16chars..') == \
        '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1'
    assert crypt('the minimum number is still observed', '$6$rounds=10$roundstoolow') == \
        '$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.'
    stored = make('old pass')
    assert verify('old pass', stored) and not verify('other', stored) and not verify('x', '{PLAIN}x') and crypt('x', '$1$ab') == ''
    print('self-test ok')


if __name__ == '__main__':
    self_test()
