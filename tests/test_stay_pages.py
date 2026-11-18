# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""2026-11-17 (UI review): on every page a setting keeps the page where it is (stay.js), not only on the Security pages. Each
page is rendered in the Expert view with every command; every form that posts a -set command carries data-stay, unless it is
one of the documented exceptions (STAY_EXCEPT, a step-up of the password)."""
import time
import re
import unittest

from test_bec_page import SCHEMA, load_web

import efa_nav  # noqa: E402  (path set by test_bec_page)


class StayPages(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

        def fake(*args, secrets_in=None, who=None):
            if args[0] == 'schema':
                return True, dict(SCHEMA)
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, {'note': 'Kept for an hour.'} if args[0] == 'login-lockout-set' else {}
        cls.web.efactl = fake
        cls.web.efactl_read = fake

    def client(self, view='expert'):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid='stay', lang='en', view=view)
        self.web.active_sessions['stay'] = time.time() + 600
        self.web.session_checked['stay'] = time.time()
        return client

    def test_every_page(self):
        client = self.client()
        excused = self.web.STAY_EXCEPT | self.web.REAUTH_COMMANDS
        for _group, pages in efa_nav.NAV:
            for page in pages:
                if page['slug'] == 'dash':
                    continue  # the dashboard needs its reads (its forms: notices and layout, both stay.js)
                with self.subTest(page=page['slug']):
                    reply = client.get(f"/p/{page['slug']}", **self.https)
                    self.assertEqual(reply.status_code, 200)
                    forms = re.findall(r'<form method="post" action="/run/([a-z0-9-]+)"([^>]*)>', reply.get_data(as_text=True))
                    missing = sorted({name for name, attrs in forms if name.endswith('-set') and name not in excused and 'data-stay=' not in attrs})
                    self.assertEqual(missing, [], page['slug'])

    def test_json_answer_with_the_note_of_the_command(self):
        answer = self.client().post('/run/login-lockout-set', data={'csrf': 'token', 'json': '1', 'mode': 'on'}, **self.https)
        self.assertEqual(answer.status_code, 200)
        self.assertEqual(answer.get_json(), {'ok': True, 'error': None, 'note': 'Kept for an hour.'})
        self.assertTrue(self.web.stayable('spam-scores-set') and not self.web.stayable('network-set'))
        self.assertFalse(self.web.stayable('my-settings-set'), 'the language changes the whole page')
        self.assertIn("data.note || form.getAttribute('data-saved')", self.web.STAY_JS)


if __name__ == '__main__':
    unittest.main()
