# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.6.7 (UI review, page by page): on Tenants, the limits are a button inside the card Tenant usage."""
import unittest

from test_bec_page import SCHEMA, load_web

import efa_nav  # noqa: E402  (path set by test_bec_page)


class TenantGroups(unittest.TestCase):
    def test_limits_inside_usage(self):
        web = load_web()
        commands = SCHEMA.get('commands', SCHEMA)
        section = dict((s[0], s[1]) for s in efa_nav.PAGES['tenants']['sections'])['Usage & limits']
        groups = dict(web.card_groups(section, commands))
        self.assertEqual(list(groups), ['tenant-usage'], 'one card')
        self.assertIn('tenant-limits-set', groups['tenant-usage'])


if __name__ == '__main__':
    unittest.main()
