# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""No Postfix table type written into the code: hash: and btree: exist only on EL9, so the type comes from the platform
layer (map_type). Allowed: the platform modules, and the code that reads or converts configurations of others (eFa 5,
the release upgrade)."""

import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
TREES = ('next', 'src')
# Reads eFa 5 configurations or switches hash/btree to lmdb on purpose.
ALLOWED = {'efa5_convert.py', 'efa_release_upgrade.py', 'test_release_upgrade.py'}
# A table type followed by a path or a variable; "hash: entry" in prose has a space.
LITERAL = re.compile(r'\b(hash|btree):(?=[/${A-Za-z_])')


def offenders():
    found = []
    for tree in TREES:
        for folder, _dirs, names in os.walk(os.path.join(ROOT, tree)):
            for name in names:
                if name.startswith('efa_platform') or name in ALLOWED or name.endswith(('.md', '.po', '.png', '.svg', '.gz', '.pdf', '.pyc')):
                    continue
                path = os.path.join(folder, name)
                try:
                    with open(path, encoding='utf-8') as f:
                        lines = f.read().splitlines()
                except (UnicodeDecodeError, OSError):
                    continue
                found += [f'{os.path.relpath(path, ROOT)}:{number}: {line.strip()[:120]}'
                          for number, line in enumerate(lines, 1) if LITERAL.search(line)]
    return found


class NoTableTypeLiterals(unittest.TestCase):
    def test_none_left(self):
        self.assertEqual(offenders(), [])

    def test_pattern(self):
        self.assertTrue(LITERAL.search("f'check_sender_access hash:{path}'"))
        self.assertTrue(LITERAL.search("'postscreen_cache_map': 'btree:$data_directory/postscreen_cache'"))
        self.assertFalse(LITERAL.search('"""The feed entries: {kind: {hash: entry}}."""'))
        self.assertFalse(LITERAL.search("'efa-own-hash: no settings'"))


if __name__ == '__main__':
    unittest.main()
