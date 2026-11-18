# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""2026-11-18 (cluster wizard, gates first): making, joining, changing and ending a cluster is for super admins only, decided
in efactl; settings.edit of a group is not enough. efa-web asks for the password and 2FA again for each of them."""
import unittest

from test_threat import load_efactl
from test_bec_page import load_web

GATED = ('cluster-init', 'cluster-token', 'cluster-join', 'cluster-mode-set', 'cluster-leave', 'cluster-promote', 'cluster-node-remove')


class ClusterGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()
        cls.web = load_web()

    def test_super_admin_only_in_efactl(self):
        editor = {'username': 'anna', 'role': 'custom', 'grants': {'settings.edit', 'settings.view'}}
        for name in GATED:
            self.assertIn(name, self.efactl.SUPER_COMMANDS, name)
            self.assertFalse(self.efactl.command_allowed(editor, name, True), f'{name}: settings.edit without super is refused')
            for role in ('tenant', 'domain', 'helpdesk', 'readonly', 'auditor', 'manager'):
                self.assertFalse(self.efactl.command_allowed({'username': 'x', 'role': role, 'grants': {'settings.edit'}}, name, True), (name, role))
            self.assertTrue(self.efactl.command_allowed({'username': 'boss', 'role': 'super', 'grants': set()}, name, True), name)
            self.assertTrue(self.efactl.command_allowed(None, name, True), f'{name}: root on the console')
        # Reading the cluster stays a permission of its own.
        self.assertTrue(self.efactl.command_allowed(editor, 'cluster-status', False))

    def test_web_mirrors_and_asks_again(self):
        for name in GATED:
            self.assertIn(name, self.web.SUPER_COMMANDS, name)
            self.assertIn(name, self.web.REAUTH_COMMANDS, f'{name}: password and 2FA again')


if __name__ == '__main__':
    unittest.main()
