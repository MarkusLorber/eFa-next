#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Fails on a bare "eFa" in text: the product is called eFa-next everywhere, so it is not mixed up with the eFa project.
Fails too on internal names of the site that builds it (test hosts, its domains and networks, the upload account): the tree is
published.

Allowed: the predecessor (eFa 5, MailScanner, the eFa project and its licence notices) and technical names that keep the old
word (the packages eFa and eFa-base, /etc/eFa and the other paths, eFa-Backup and the other file names, markers matched on
existing hosts).
    name_check.py
    name_check.py --hash WORDS    the hash of a new internal name for INTERNAL_HASHES
"""
import hashlib
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_FILES = {'NOTICE', 'LICENSES.md', 'THIRD-PARTY-NOTICES.md', 'AUTHORS.md', 'rspamd_evaluation_framework.md', 'scripts/name_check.py'}
SKIP_DIRS = ('.git/', 'LICENSES/', 'docs/images/', 'assets/')
BARE = re.compile(r'(?<![A-Za-z0-9_/.^-])eFa(?!-next)(?![A-Za-z0-9_/%(-])')
PREDECESSOR = re.compile(r'eFa ?5|eFa5|MailScanner|eFa project|efa-project|eFa-Configure|eFa 4|original eFa|eFa \(the project|eFa authors|'
                         r'eFa, the project|old eFa|eFa Email Filter Appliance|eFa-Expand|the eFa logo|eFa source|parts from eFa|not from eFa|'
                         r'packaged into eFa|eFa is built|code from eFa', re.I)
TECHNICAL = re.compile(r'/etc/eFa|/usr/lib/eFa|/var/lib/eFa|/var/eFa|/var/log/eFa|/usr/share/eFa|/usr/libexec/eFa|eFa-Version|eFa-base|'
                       r'eFa-Backup|eFa-Monitor|eFa-Config|eFa\.spec|eFa-6|eFa-\$|eFa\*|eFa-\{|[\'"]eFa[\'"]|Name:\s+eFa|install-state/eFa|'
                       r'eFa-[0-9]|rpm-state/eFa|eFa/|SOURCES/eFa|`eFa`|eFa eFa-base|eFa and eFa-base|-q eFa|upgrade eFa|reinstall eFa|'
                       r'remove .*eFa|X-eFa|eFa-Mail|BuildRoot.*eFa|%\{name\}|logrotate\.d/eFa|packages/eFa|eFa RPM|eFa package|package eFa|'
                       r'eFa-[A-Z]|eFa quarantine')
# Lines that name the package (rpm -q eFa, dnf ..., Requires) or hold a marker matched on existing hosts.
TECHNICAL_LINE = re.compile(r'rpm -[qV]|dnf |Requires|Provides|Obsoletes|%files|%package|for pkg in|PACKAGES|package_hook|--package-hook|'
                            r"PAM_OFF_MARK|\('eFa'|\"eFa\"|eFa-base|install-state")


# Internal names and test activity that must never be in the published tree: test hosts and what was done on them stay in
# internal notes, the public texts describe the product only.
INTERNAL_WORDS = re.compile(r'\bMX0[0-9]\b|test ?hosts?\b|testhost|test system|fresh VM|test VM|test clone', re.I)
# The names of the site (hosts, domains, networks, accounts) only as salted SHA-256 of 1 to 3 words: the published tree does not
# name them itself. A word is a run of letters and digits, lower case; the words joined by one space. New entry: name_check.py --hash WORDS
SALT = 'eFa-next name_check 1'
INTERNAL_HASHES = {
    '9b308d11c7c619406dc422d94afacabfe121a8c60d7b776256b5fa6585875a33', '1f4f6daa2c0c52a5604a7152aec46a52d86fd36615978dc3f46c58d38bea0671',
    'c5e0710ba689f73008fb13f9b854c093dea5467c12b3bc4f92bff75ba3962c00', 'a3933a2f6ad6cdfc0cc81c3f6acd111d7d636f163d47d5646e3cbf268c777e2d',
    '0e834f7ac5b3d741035f71b7cac8afea8ed335e96150d00cbb061ead1ca1393b', 'fff3fa02390f0b282c8302fe0c24bbbb14b40d33238497200ff76b9047ca29d9',
    '5cc33956688ee27ec50fe3d007c83bd055c514d36d4cddd9d695a82965c9f301', '8bcfa073f024c93fca13071a1864a5029c38a24f50bfecb3009835e255fa48fa',
    '1c5e16ba476ece4c766edbc883cfea77500925362bbdf967c0a87d20aa22fd39', 'cc22846a2a3a102474ac68ea5842721b110731cb4832d7cfde50acbade51cb78',
    '91a28d8c43c471ec0aece38123d949dec19cfb0185b66298dcd57d02171cd52f', '42cf2c0b01757fd7abbe272e6563f896758c998dcb6d188a720bbeddcda38d62',
    'dee5c8fb296d3decc1ed93a5b77d707f29166a4927e0f44353f3d7dde1fd55d8', '73d5acb6d41d2b94a1ddbecd9f0c2b2106486213f5c094d703b8de585152bedd',
    'dfbbe186c6c7eb087271f1c2a451fb635e747bc8703bee656768ef89cc4c691a', '1b401e099fe3ad57a669b5a0372dcbade9cdd599c1e55ac4c0d790bbd643e618',
    '7f699d8141051055efccbd865ae395515a2f8b18d9392dfae73e436a75ef747e', '7db5122f3f9e9f6b717c4e8849671e49c4616cd6cea6e1cfcd74b1d293dd553b',
    # 'name check probe', for the self-test
    '9a1ab65eddd639354ad3cef23940f2835530a8fbe3e368aa92e85bdb4ab22fa4'}
WORD = re.compile(r'[a-z0-9]+')


def phrase_hash(words):
    return hashlib.sha256(f'{SALT} {words}'.encode()).hexdigest()


def internal(line):
    """True for test activity or a name of the site in the line."""
    if INTERNAL_WORDS.search(line):
        return True
    words = WORD.findall(line.lower())
    return any(phrase_hash(' '.join(words[i:i + n])) in INTERNAL_HASHES for n in (1, 2, 3) for i in range(len(words) - n + 1))


def bare(line):
    """The positions of a bare eFa in a line that is neither the predecessor nor a technical name."""
    if TECHNICAL_LINE.search(line):
        return []
    return [m.start() for m in BARE.finditer(line)
            if not (PREDECESSOR.search(line[max(0, m.start() - 25):m.end() + 25]) or TECHNICAL.search(line[max(0, m.start() - 25):m.end() + 25]))]


def self_test():
    assert bare('eFa removed the attachment') == [0]
    assert bare('eFa-next removed it') == [] and bare('Migrate from eFa 5') == [] and bare('sudo dnf upgrade eFa eFa-base') == []
    assert bare('see /etc/eFa/wazuh.json') == [] and bare("version:gsub('^eFa%-', '')") == [] and bare('built by the eFa project') == []
    assert internal('green on MX03') and internal('on the test host') and internal('see Name_Check-probe.txt')
    assert internal('found on a fresh VM') and not internal('a host for testing, 10.0.0.5') and not internal('efa_test_block')
    assert not internal('IT-World ITW GmbH sponsors the project'), 'the sponsor may be named'
    assert all(re.fullmatch(r'[0-9a-f]{64}', h) for h in INTERNAL_HASHES)


def main():
    if sys.argv[1:2] == ['--hash']:
        print(phrase_hash(' '.join(WORD.findall(' '.join(sys.argv[2:]).lower()))))
        return 0
    self_test()
    found, inside = [], []
    for top, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d != '.git']
        for name in files:
            path = os.path.relpath(os.path.join(top, name), ROOT).replace(os.sep, '/')
            if path in SKIP_FILES or path.startswith(SKIP_DIRS):
                continue
            try:
                with open(os.path.join(top, name), encoding='utf-8') as fh:
                    lines = fh.read().splitlines()
            except (UnicodeDecodeError, OSError):
                continue
            found += [f'{path}:{number}: {line.strip()[:120]}' for number, line in enumerate(lines, 1) if bare(line)]
            inside += [f'{path}:{number}: {line.strip()[:120]}' for number, line in enumerate(lines, 1) if internal(line)]
    if inside:
        print('Internal names or test activity in the published tree (describe the product, keep test notes internal):')
        print('\n'.join(inside))
        return 1
    if found:
        print('Name the product eFa-next, not eFa (or add the technical name to scripts/name_check.py):')
        print('\n'.join(found))
        return 1
    print('names: no bare eFa')
    return 0


if __name__ == '__main__':
    sys.exit(main())
