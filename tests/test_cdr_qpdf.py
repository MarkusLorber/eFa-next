# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Content disarm after the first boot at any time (2026-11-17): qpdf comes with the package, so switching it on installs
nothing and never waits for the package window; a host without qpdf still gets it only in the window."""
import types
import unittest
from unittest import mock

from test_threat import load_efactl


class Qpdf(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def platform(self, installed):
        self.installs = []
        return types.SimpleNamespace(package_installed=lambda name: installed, package_fetch=lambda names, folder: [],
                                     package_scripts=lambda path: '', package_install=self.installs.append)

    def test_present_outside_the_window(self):
        # 05:59, outside minute 20 to 50: the window says wait.
        with mock.patch.object(self.efactl, 'update_window_wait', lambda now: 1260):
            self.assertEqual(self.efactl._qpdf_install(self.platform(True)), 'present')
            self.assertEqual(self.installs, [], 'nothing installed')
            with self.assertRaises(self.efactl.EfaError):
                self.efactl._qpdf_install(self.platform(False))


if __name__ == '__main__':
    unittest.main()
