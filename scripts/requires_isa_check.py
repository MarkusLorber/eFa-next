#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""A minimum version of a package of others only by its arch-bound name (docs/dev/min-versions.md).

Packages such as rspamd also provide their plain name without a version, and that provide meets any "name >= x": dnf keeps the
old package. Only the arch-bound provide name(x86-64) carries the version. Every Requires line of rpm/*.spec with a version
on a package that is not eFa-next must therefore be a rich dependency over the arch-bound names:
    Requires:       (rspamd(x86-64) >= 4.3.0 or rspamd(aarch-64) >= 4.3.0)
Prints each line that is not, and exits 1 then.
"""
import glob
import re
import sys

ARCHES = ('x86-64', 'aarch-64')
REQUIRES = re.compile(r'^Requires(?:\([a-z,]+\))?:\s*(.+?)\s*$')
VERSIONED = re.compile(r'([A-Za-z0-9_.+-]+(?:\([A-Za-z0-9_.+-]+\))?)\s*(>=|>|=|<=|<)\s*([^\s()]+)')
ARCH_BOUND = re.compile(r'^([A-Za-z0-9_.+-]+)\(([a-z0-9-]+)\)$')


def problems(line):
    """What is wrong with one Requires value; [] when it is fine."""
    found = []
    terms = VERSIONED.findall(line)
    if not terms:
        return found
    names = {}
    for name, op, version in terms:
        bound = ARCH_BOUND.match(name)
        base = bound.group(1) if bound else name
        if base.startswith('eFa-next') or base.startswith('eFa'):
            continue  # own packages: one version per build, the plain provide is exact
        if not bound:
            found.append(f'{base} {op} {version}: by its plain name, which any version provides; use ({base}(x86-64) {op} {version} or {base}(aarch-64) {op} {version})')
            continue
        names.setdefault((base, op, version), set()).add(bound.group(2))
    for (base, op, version), arches in sorted(names.items()):
        missing = [arch for arch in ARCHES if arch not in arches]
        if missing:
            found.append(f'{base} {op} {version}: no term for {", ".join(missing)}')
        if not (line.startswith('(') and line.endswith(')')):
            found.append(f'{base} {op} {version}: not a rich dependency in parentheses')
    return found


def self_test():
    assert problems('(rspamd(x86-64) >= 4.3.0 or rspamd(aarch-64) >= 4.3.0)') == []
    assert problems('rspamd') == [] and problems('eFa-next-base = 1:%{version}-%{release}') == []
    assert problems('rspamd >= 4.3.0')[0].startswith('rspamd >= 4.3.0: by its plain name')
    assert problems('(rspamd(x86-64) >= 4.3.0)') == ['rspamd >= 4.3.0: no term for aarch-64']
    assert problems('rspamd(x86-64) >= 4.3.0 or rspamd(aarch-64) >= 4.3.0') != []


def main():
    self_test()
    bad = 0
    for path in sorted(glob.glob('rpm/*.spec')):
        for number, line in enumerate(open(path, encoding='utf-8'), 1):
            match = REQUIRES.match(line)
            for problem in problems(match.group(1)) if match else []:
                print(f'{path}:{number}: {problem}')
                bad += 1
    print(f'requires-isa: {"FAILED, " + str(bad) + " problem(s)" if bad else "ok"}')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
