# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""S1: secrets never on a command line (docs/SECURITY-DESIGN.md). Reads the sources, runs nothing."""

import os
import re
import unittest

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = [os.path.join(TOP, 'next', 'usr', 'sbin', 'efactl'), os.path.join(TOP, 'migration', 'efa-migrate')]
for folder in (os.path.join(TOP, 'next', 'usr', 'local', 'sbin'), os.path.join(TOP, 'next', 'usr', 'lib', 'eFa', 'python'),
               os.path.join(TOP, 'src', 'eFa', 'root', 'usr', 'lib', 'eFa', 'python'), os.path.join(TOP, 'src', 'eFa-base', 'root', 'usr', 'lib', 'eFa', 'python')):
    SOURCES += [os.path.join(folder, name) for name in sorted(os.listdir(folder)) if name.endswith('.py')]
# Arguments named like these are switches, not secrets.
NOT_SECRET = {'new_token'}


class SecretsTest(unittest.TestCase):
    def read(self, path):
        with open(path, encoding='utf-8') as f:
            return f.read()

    def test_secret_arguments_go_over_stdin(self):
        text = self.read(SOURCES[0])
        for match in re.finditer(r"\{'name': '([a-z_0-9]*(?:password|passwd|token|secret)[a-z_0-9]*)'[^}]*\}", text):
            if match.group(1) not in NOT_SECRET:
                self.assertIn("'secret': True", match.group(0), f'efactl argument {match.group(1)} must be secret (stdin)')

    def test_no_password_on_a_command_line(self):
        patterns = (r"['\"]-p['\"]\s*\+", r"f['\"]-p\{", r"['\"]--password=", r"['\"]-w['\"],\s*\w*pass", r"pass:\{", r"['\"]sshpass['\"]",
                    r"['\"]-passin['\"]")
        for path in SOURCES:
            # The self-tests work with made-up passwords; the code before them is what runs.
            text = self.read(path).split('\ndef self_test(')[0]
            for pattern in patterns:
                self.assertIsNone(re.search(pattern, text), f'{os.path.relpath(path, TOP)}: a password on a command line ({pattern})')


if __name__ == '__main__':
    unittest.main()
