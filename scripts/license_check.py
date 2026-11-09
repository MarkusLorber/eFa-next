#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Every source file of eFa-next names its license in its first lines: SPDX AGPL-3.0-or-later, the copyright line and the author.

    scripts/license_check.py [--fix] [--self-test]     --fix adds the lines where they are missing (after a shebang)
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TREES = ('next', 'src', 'build', 'rpm', 'scripts', 'tests', 'migration', 'tools', '.forgejo')
SUFFIXES = ('.py', '.sh', '.lua', '.service', '.timer', '.path', '.socket', '.spec', '.yml', '.yaml', '.conf', '.inc', '.bash', '.j2')
SPDX = 'SPDX-License-Identifier: AGPL-3.0-or-later'
COPYRIGHT = 'Copyright (C) 2026 Markus Lorber and eFa-next contributors'
AUTHOR = 'Author: Markus Lorber, Lukasz Galusinski'
HEAD_LINES = 6


def is_source(path):
    if path.endswith(SUFFIXES):
        return True
    try:
        with open(path, 'rb') as f:
            return f.read(2) == b'#!'
    except OSError:
        return False


def problems(text):
    head = '\n'.join(text.splitlines()[:HEAD_LINES])
    found = []
    if 'SPDX-License-Identifier:' not in head:
        found.append('no SPDX line')
    elif SPDX not in head:
        found.append('another license: ' + re.search(r'SPDX-License-Identifier: (\S+)', head).group(1))
    if 'Copyright' not in head:
        found.append('no copyright line')
    elif COPYRIGHT not in head:
        found.append('another copyright line')
    if AUTHOR not in head:
        found.append('no author line')
    return found


def fixed(text, comment='#'):
    lines = text.split('\n')
    at = 1 if lines and lines[0].startswith('#!') else 0
    head = '\n'.join(lines[:HEAD_LINES])
    add = [line for line, needed in ((f'{comment} {SPDX}', 'SPDX-License-Identifier:' not in head),
                                     (f'{comment} {COPYRIGHT}', 'Copyright' not in head), (f'{comment} {AUTHOR}', AUTHOR not in head)) if needed]
    return '\n'.join(lines[:at] + add + lines[at:])


def files():
    for tree in TREES:
        for top, dirs, names in os.walk(os.path.join(ROOT, tree)):
            dirs[:] = sorted(item for item in dirs if item not in ('__pycache__', 'locale'))
            for name in sorted(names):
                path = os.path.join(top, name)
                if is_source(path):
                    yield path


def self_test():
    assert problems(f'#!/bin/sh\n# {SPDX}\n# {COPYRIGHT}\n# {AUTHOR}\n') == []
    assert problems('#!/usr/bin/python3\n"""x"""\n') == ['no SPDX line', 'no copyright line', 'no author line']
    assert problems(f'# SPDX-License-Identifier: GPL-3.0-or-later\n# Copyright x\n# {AUTHOR}\n') == ['another license: GPL-3.0-or-later', 'another copyright line']
    assert fixed('#!/usr/bin/python3\n"""x"""\n').split('\n')[:4] == ['#!/usr/bin/python3', f'# {SPDX}', f'# {COPYRIGHT}', f'# {AUTHOR}']
    assert problems(fixed('[Unit]\nDescription=x\n')) == []
    assert problems(f'# {SPDX}\n# Copyright (C) 2026 someone\n# {AUTHOR}\n') == ['another copyright line']
    print('self-test ok')


def main():
    if '--self-test' in sys.argv:
        self_test()
        return 0
    bad = 0
    for path in files():
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
        found = problems(text)
        if found and '--fix' in sys.argv:
            with open(path, 'w', encoding='utf-8', newline='') as f:
                f.write(fixed(text))
            found = []
        for item in found:
            print(f'license: {os.path.relpath(path, ROOT)}: {item}')
            bad += 1
    print('license: ok' if not bad else f'license: FAILED, {bad} problems')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
