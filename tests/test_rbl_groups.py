# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.6.7 (UI review, page by page): on Blocklists, changing one list and your own list are buttons inside the table card."""
import time
import unittest

from test_bec_page import SCHEMA, load_web

import efa_nav  # noqa: E402  (path set by test_bec_page)


class RblGroups(unittest.TestCase):
    def test_change_and_own_list_inside_the_table(self):
        web = load_web()
        commands = SCHEMA.get('commands', SCHEMA)
        names = [name for section in efa_nav.PAGES['rbl']['sections'] for name in section[1]]
        groups = dict(web.card_groups(names, commands))
        self.assertIn('rbl-set', groups['rbl-show'])
        self.assertIn('rbl-custom-set', groups['rbl-show'])
        schema = {name: SCHEMA[name] for name in set(names) | {'settings'} if name in SCHEMA}

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
            sess.update(admin=True, csrf='t', sid='rb', lang='en', view='standard')
        web.active_sessions['rb'] = time.time() + 600
        web.session_checked['rb'] = time.time()
        html = client.get('/p/rbl', **https).get_data(as_text=True)
        self.assertIn('<details class="cfold"><summary>Change one</summary>', html)
        self.assertIn('id="rbl-custom-set"', html, 'the form is there, behind one click')


if __name__ == '__main__':
    unittest.main()
