# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-17: the Security page by task. Standard shows four tasks (state, admin access, logins, TLS), everything else in
Expert; address harvesting moved to the spam filter with its old link kept; every setting on the Security pages keeps the page
where it is (stay.js), except the ones whose answer is a page of its own."""
import re
import time
import unittest

from test_bec_page import SCHEMA, load_web

import efa_i18n  # noqa: E402  (path set by test_bec_page)
import efa_nav  # noqa: E402


class SecurityPage(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        names = {name for section in efa_nav.PAGES['sec']['sections'] for name in section[1]} | {'settings'}
        self.schema = {name: SCHEMA[name] for name in names if name in SCHEMA}
        self.status = {}

        def fake(*args, secrets_in=None, who=None):
            if args[0] == 'schema':
                return True, self.schema
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, self.status.get(args[0], {})
        self.web.efactl = fake
        self.web.efactl_read = fake

    def page(self, view='standard', lang='en', slug='sec'):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid='sec', lang=lang, view=view)
        self.web.active_sessions['sec'] = time.time() + 600
        self.web.session_checked['sec'] = time.time()
        reply = client.get(f'/p/{slug}', **self.https)
        self.assertEqual(reply.status_code, 200)
        return reply.get_data(as_text=True)

    def test_standard_shows_the_four_tasks(self):
        """Four compact cards (one line of state, one action), the full cards only in Expert."""
        sections = efa_nav.PAGES['sec']['sections']
        self.assertEqual([section[0] for section in sections if len(section) < 3], [], 'every full card in Expert')
        self.assertEqual([section[0] for section in sections][:4], ['State of this server', 'Admin access', 'Logins', 'TLS'])
        self.status = {'security-status': {'checked': '2026-11-17 06:00', 'level': 'ok', 'findings': []},
                       'floor-status': {'failed': []}, 'cve-watch-status': {'mode': 'on', 'alerts': [], 'last': '2026-11-17 06:27'},
                       'threat-status': {'level': 'ok', 'alerts': []}, 'ssh-root-status': {'mode': 'key-only'},
                       'web-allowlist-show': {'mode': 'all', 'networks': ''}, 'tls-profile-status': {'profile': 'bsi', 'web_protocols': 'TLSv1.2 TLSv1.3'},
                       'login-lockout-status': {'mode': 'on', 'tries': 5, 'minutes': 10, 'hours': 1, 'banned_now': {'efa-web': ['192.0.2.9']}}}
        for view in ('standard', 'expert'):
            html = self.page(view=view)
            cards = re.findall(r'<div class="card[^"]*" id="([a-z0-9-]+)"', html)
            self.assertEqual(cards[:4], ['sec-state', 'sec-access', 'sec-logins', 'sec-tls'], view)
            if view == 'standard':
                self.assertEqual(cards[4:], [c for c in cards[4:] if c in self.web.WARNING_CARDS], 'Standard: only the four tasks')
            self.assertIn('after 5 failed logins in 10 minutes, for 1 hours', html)
            self.assertIn('With an SSH key only', html)
            self.assertIn('class="badge on" aria-pressed="true"', html, 'the lockout switch in the head of Logins')
        self.assertIn('threat-set', [name for section in sections if len(section) >= 3 for name in section[1]])
        self.assertNotIn('harvest-set', [name for section in sections for name in section[1]])

    def test_page_time(self):
        """Within the 100 ms page budget for the rendering itself (the reads are cached and parallel)."""
        for view in ('standard', 'expert'):
            self.page(view=view)
            start = time.perf_counter()
            self.page(view=view)
            self.assertLess(time.perf_counter() - start, 0.1, view)

    def test_harvesting_moved_to_the_spam_filter(self):
        spam = [name for section in efa_nav.PAGES['spam']['sections'] for name in section[1]]
        self.assertIn('harvest-set', spam)
        self.assertEqual(efa_nav.MOVED_CARDS[('sec', 'harvest-set')], 'spam')

    def test_every_setting_keeps_the_page(self):
        html = self.page(view='expert')
        forms = re.findall(r'<form method="post" action="/run/([a-z0-9-]+)"([^>]*)>', html)
        self.assertTrue(forms)
        for name, attrs in forms:
            if name.endswith('-set') and name not in self.web.STAY_EXCEPT and name not in self.web.REAUTH_COMMANDS:
                self.assertIn('data-stay=', attrs, name)
        self.assertTrue(self.web.stayable('login-lockout-set') and not self.web.stayable('firewall-set'))
        self.assertIn("target === '@card'", self.web.STAY_JS)

    def test_german_section_titles(self):
        with open(efa_i18n.__file__.replace('python/efa_i18n.py', '../../share/eFa/locale/de.po'), encoding='utf-8') as f:
            de = efa_i18n.po_entries(f.read())
        titles = [section[0] for section in efa_nav.PAGES['sec']['sections']] + [efa_nav.PAGES['sec']['sub']]
        self.assertEqual([title for title in titles if not de.get(title)], [])


if __name__ == '__main__':
    unittest.main()
