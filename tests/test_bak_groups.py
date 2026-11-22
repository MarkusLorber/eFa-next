# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.6.7 (UI review, page by page; on top of the sections of 6.0.0.6.6): on Backup & restore the password of the automatic
backups is a button inside the card Automatic backup, the fingerprint of the signing key one inside the backup list."""
import time
import unittest

from test_bec_page import SCHEMA, load_web

import efa_nav  # noqa: E402  (path set by test_bec_page)


class BakGroups(unittest.TestCase):
    def test_password_and_fingerprint_inside_their_cards(self):
        web = load_web()
        commands = SCHEMA.get('commands', SCHEMA)
        groups = dict(web.card_groups(efa_nav.PAGES['bak']['sections'][0][1], commands))
        self.assertIn('backup-password-set', groups['backup-set'], 'a button in Automatic backup')
        self.assertIn('backup-key-show', groups['backup-list'], 'a button in the backup list')
        names = {name for section in efa_nav.PAGES['bak']['sections'] for name in section[1]} | {'settings'}
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
            sess.update(admin=True, csrf='t', sid='bk', lang='en', view='standard')
        web.active_sessions['bk'] = time.time() + 600
        web.session_checked['bk'] = time.time()
        html = client.get('/p/bak', **https).get_data(as_text=True)
        self.assertIn('<details class="cfold"><summary>Password</summary>', html)
        self.assertIn('id="backup-password-set"', html, 'the form is there, behind one click')


if __name__ == '__main__':
    unittest.main()
