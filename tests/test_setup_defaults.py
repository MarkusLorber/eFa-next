# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Secure defaults: a new install turns the attachment checks and content disarm on, an upgrade leaves them as they are."""

import os
import re
import unittest

SETUP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "next", "usr", "lib", "eFa", "setup", "efa-next-setup")


def branch(text, name):
    return re.search(r"^%s\)\n(.*?)^    ;;" % name, text, re.M | re.S).group(1)


class SetupDefaults(unittest.TestCase):
    def test_fresh_on_upgrade_unchanged(self):
        text = open(SETUP).read()
        fresh, upgrade = branch(text, "first-install"), branch(text, "upgrade")
        self.assertIn("efactl attachment-set --mode on --action reject --names reject --executables reject", fresh)
        self.assertNotIn("attachment-set", upgrade)
        self.assertNotIn("cdr-set", upgrade)


if __name__ == "__main__":
    unittest.main()
