# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.6.7 (UI review, page by page): My account keeps its overview and the guided 2FA open; the forms used seldom (password,
e-mail address, name and phone, my settings, passkeys) are folded below their titles, each opened with one click."""
import re
import time
import unittest

from test_bec_page import SCHEMA, load_web

import efa_nav  # noqa: E402  (path set by test_bec_page)


class AccountFolds(unittest.TestCase):
    def test_seldom_forms_folded(self):
        web = load_web()
        names = {name for section in efa_nav.PAGES['account']['sections'] for name in section[1]} | {'settings'}
        schema = {name: SCHEMA[name] for name in names if name in SCHEMA}

        def fake(*args, secrets_in=None, who=None):
            if args[0] == 'schema':
                return True, schema
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, {}
        web.efactl = fake
        web.efactl_read = fake
        https = {'base_url': 'https://localhost'}
        client = web.app.test_client()
        with client.session_transaction(**https) as sess:
            sess.update(admin=True, csrf='t', sid='af', lang='en', view='standard')
        web.active_sessions['af'] = time.time() + 600
        web.session_checked['af'] = time.time()
        html = client.get('/p/account', **https).get_data(as_text=True)
        for name in ('account-set', 'my-settings-set', 'account-email-set', 'password-change'):
            if name not in schema:
                continue
            fold = re.search(r'<details[^>]*id="' + re.escape(name) + r'-fold"[^>]*>', html)
            self.assertTrue(fold, name)
            self.assertNotIn(' open', fold.group(0), f'{name}: folded')
            self.assertIn(f'id="{name}"', html, f'{name}: its form is there, behind one click')


if __name__ == '__main__':
    unittest.main()
