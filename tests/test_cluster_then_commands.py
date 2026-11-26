# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The commands a cluster entry runs after its files (then) apply settings and restart services: the web interface must never
run one just because a page opens (CI 2026-11-25: fuzzy-cluster-apply ran on every view of Maintenance & update, 500 ms and a
restart of rspamd each time). Reads the sources, runs nothing."""
import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as f:
        return f.read()


class ThenCommands(unittest.TestCase):
    def test_never_read_by_a_page(self):
        efactl = read('next', 'usr', 'sbin', 'efactl')
        web = read('next', 'usr', 'local', 'sbin', 'efa-web.py')
        then = set(re.findall(r"'then': '([a-z0-9-]+)'", efactl))
        self.assertIn('fuzzy-cluster-apply', then)
        on_button = set(re.findall(r"'([a-z0-9-]+)'", re.search(r'^ON_BUTTON = \{(.*?)\}', web, re.M | re.S).group(1)))
        for name in sorted(then):
            spec = re.search(rf"^    '{name}': \{{.*?'writes': (True|False)", efactl, re.M | re.S)
            self.assertTrue(spec and (spec.group(1) == 'True' or name in on_button), f'{name}: a page would run it')


if __name__ == '__main__':
    unittest.main()
