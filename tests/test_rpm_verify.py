# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The settings check of the release upgrade takes a package file as the package's own when rpm -V finds its content as
shipped: mode, owner or time alone (an eFa 5 host) change no setting, a changed content does (acceptance 2026-11-12)."""

import unittest
from unittest import mock

import efa_testlib  # noqa: F401  (puts the libraries on the path)
import efa_platform_el9


class RpmVerifyTests(unittest.TestCase):
    def test_content_flags(self):
        changed = efa_platform_el9.rpm_verify_content_changed
        self.assertFalse(changed('.M....G.T.  c /etc/postfix/canonical'))
        self.assertFalse(changed('.......T.  c /etc/unbound/conf.d/example.com.conf'))
        self.assertTrue(changed('S.5....T.  c /etc/postfix/header_checks'))
        self.assertTrue(changed('..5......  c /etc/postfix/virtual'))
        self.assertTrue(changed('....L....    /etc/x'))
        self.assertTrue(changed('missing   c /etc/postfix/generic'))

    def test_unchanged_paths(self):
        outputs = {('rpm', '-qf'): 'postfix\npostfix\npostfix\nfile /etc/own.conf is not owned by any package\n',
                   ('rpm', '-V'): '.M....G.T.  c /etc/postfix/canonical\nS.5....T.  c /etc/postfix/header_checks\n'}

        def run(cmd, check=False):
            return mock.Mock(stdout=outputs[tuple(cmd[:2])])

        with mock.patch.object(efa_platform_el9.c, 'run', run):
            found = efa_platform_el9.EL9().release_package_unchanged(
                ['/etc/postfix/canonical', '/etc/postfix/header_checks', '/etc/postfix/relocated', '/etc/own.conf'])
        # The operator's header_checks and a file of no package count as settings; canonical (only mode and time) does not.
        self.assertEqual(found, {'/etc/postfix/canonical', '/etc/postfix/relocated'})


if __name__ == '__main__':
    unittest.main()
