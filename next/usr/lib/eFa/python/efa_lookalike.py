# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M4: whether a domain looks like an own or partner domain, the same kinds as the BEC check of rspamd: homoglyphs and IDN, one
typo (a letter more, less, swapped or another), the same name under another ending, and the own domain as labels in front of a
foreign one. Standard library only."""

# Letters that look alike, to one form each; the BEC check of rspamd uses the confusable skeleton of ICU for the same purpose.
CONFUSABLE = {'0': 'o', '1': 'l', 'i': 'l', '|': 'l', '5': 's', '$': 's', '3': 'e', '@': 'a', 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
              'у': 'y', 'х': 'x', 'і': 'l', 'ј': 'j', 'ԁ': 'd', 'ӏ': 'l', 'ɡ': 'g', 'ο': 'o', 'ν': 'v', 'α': 'a', 'ε': 'e', 'ρ': 'p'}
PAIRS = (('rn', 'm'), ('vv', 'w'), ('cl', 'd'), ('nn', 'm'))


def unicode_domain(domain):
    """The domain with its IDN labels decoded (xn--...)."""
    labels = []
    for label in domain.lower().rstrip('.').split('.'):
        if label.startswith('xn--'):
            try:
                label = label[4:].encode('ascii').decode('punycode')
            except (UnicodeError, ValueError, OverflowError):  # a broken label stays as it is (found by scripts/fuzz.py)
                pass
        labels.append(label)
    return '.'.join(labels)


def skeleton(text):
    text = ''.join(CONFUSABLE.get(char, char) for char in unicode_domain(text))
    for pair, single in PAIRS:
        text = text.replace(pair, single)
    return text


def one_edit(a, b):
    """True for one letter more, less, another, or two neighbours swapped."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [index for index in range(len(a)) if a[index] != b[index]]
        return len(diff) == 1 or len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:index] + long_[index + 1:] == short for index in range(len(long_)))


def split(domain):
    """(name, ending) with the last label as the ending; enough for the comparison, a public suffix list is not needed here."""
    name, _, ending = domain.rpartition('.')
    return name, ending


def lookalike(candidate, protected):
    """(the protected domain, the kind) that candidate imitates, or None. Own subdomains are not lookalikes."""
    candidate = candidate.lower().rstrip('.').lstrip('*.')
    for own in protected:
        if candidate == own or candidate.endswith('.' + own):
            return None
    text = unicode_domain(candidate)
    for own in protected:
        if text.startswith(own + '.') or ('.' + own + '.') in text:
            return own, 'subdomain'
    for own in protected:
        if skeleton(text) == skeleton(own) or skeleton(text).endswith('.' + skeleton(own)):
            return own, 'homoglyph'
    base = text.split('.')
    for own in protected:
        own_name, own_ending = split(own)
        for start in range(len(base) - 1):
            name, ending = '.'.join(base[start:-1]), base[-1]
            if name == own_name and ending != own_ending:
                return own, 'other ending'
            if ending == own_ending and len(own_name) >= 4 and one_edit(name, own_name):
                return own, 'typo'
    return None


def self_test():
    own = ['example.com', 'partner.de']
    assert lookalike('mail.example.com', own) is None and lookalike('example.com', own) is None
    assert lookalike('examp1e.com', own) == ('example.com', 'homoglyph') and lookalike('exarnple.com', own) == ('example.com', 'homoglyph')
    idn = 'xn--' + 'exаmple'.encode('punycode').decode() + '.com'
    assert lookalike(idn, own) == ('example.com', 'homoglyph'), (idn, lookalike(idn, own))
    assert lookalike('exаmple.com', own)[1] == 'homoglyph', 'Cyrillic a'
    assert lookalike('exmaple.com', own) == ('example.com', 'typo') and lookalike('examplee.com', own) == ('example.com', 'typo')
    assert lookalike('example.net', own) == ('example.com', 'other ending') and lookalike('login.example.net', own) == ('example.com', 'other ending')
    assert lookalike('example.com.evil.net', own) == ('example.com', 'subdomain')
    assert lookalike('partner.com', own) == ('partner.de', 'other ending') and lookalike('unrelated.org', own) is None
    assert lookalike('*.parlner.de', own) == ('partner.de', 'typo')
    assert lookalike('xn--ex999999999999999mtle.com', own) is None
    assert one_edit('abcd', 'abdc') and not one_edit('abcd', 'dcba') and not one_edit('abc', 'abcde')
    print('self-test ok')


if __name__ == '__main__':
    self_test()
