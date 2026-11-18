# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-17 (UI review, page by page like Security): Spam filter by task. Standard shows four task cards (when mail
counts as spam, greylisting, how the filter learns, the extra checks), each with its state; the full cards in Expert."""
import re
import time
import unittest

from test_bec_page import SCHEMA, load_web

import efa_nav  # noqa: E402  (path set by test_bec_page)

TASKS = ['spam-limits', 'spam-grey', 'spam-learn', 'spam-extra']


class SpamPage(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        names = {name for section in efa_nav.PAGES['spam']['sections'] for name in section[1]} | {'settings'}
        self.schema = {name: SCHEMA[name] for name in names if name in SCHEMA}
        self.status = {'settings': {'spam_scores': {'greylist': '4', 'rewrite_subject': '6', 'reject': '15'}, 'greylisting': True,
                                    'greylist_minutes': 5, 'greylist_days': 36},
                       'subject-get': {'subject_tag': '[SPAM]'},
                       'greylisting-status': {'greylisting': True, 'minutes': 5, 'days': 36, 'exceptions_ip': ['192.0.2.1'],
                                              'exceptions_domain': ['mx.example.org', 'mail.example.net'], 'note': ''},
                       'bayes-status': {'spam_learned': 120, 'ham_learned': 80, 'min_learns': 200, 'active': False, 'autolearn': 'off',
                                        'per_user': False, 'backend': 'redis'},
                       'ml-status': {'enabled': True}, 'neural-status': {'enabled': 'rspamd default'},
                       'outbreak-status': {'enabled': True}, 'pyzor-status': {'enabled': False}}

        def fake(*args, secrets_in=None, who=None):
            if args[0] == 'schema':
                return True, self.schema
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, self.status.get(args[0], {})
        self.web.efactl = fake
        self.web.efactl_read = fake

    def page(self, view='standard', lang='en'):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid='sp', lang=lang, view=view)
        self.web.active_sessions['sp'] = time.time() + 600
        self.web.session_checked['sp'] = time.time()
        reply = client.get('/p/spam', **self.https)
        self.assertEqual(reply.status_code, 200)
        return reply.get_data(as_text=True)

    def test_standard_shows_the_tasks(self):
        html = self.page()
        cards = re.findall(r'<div class="card[^"]*" id="([a-z0-9-]+)"', html)
        self.assertEqual([card for card in cards if card in TASKS], TASKS)
        self.assertEqual([card for card in cards if card not in TASKS and card not in self.web.WARNING_CARDS], [], 'nothing else')
        for text in ('[SPAM]', '120 spam, 80 ham', 'rspamd default', '>3<'):
            self.assertIn(text, html)
        self.assertEqual(re.findall(r'class="badge[^"]*" aria-pressed="(true|false)"', html), ['true'], 'greylisting on, its switch')
        self.assertIn('data-stay="@card"', html)
        self.assertIn('.sec-grid{display:grid', html)

    def test_expert_has_the_full_cards(self):
        html = self.page(view='expert')
        self.assertNotIn('id="spam-limits"', html)
        for name in ('spam-scores-set', 'greylisting-set', 'ml-set', 'pyzor-set', 'outbreak-set'):
            self.assertIn(f'id="{name}"', html, name)

    def test_page_time(self):
        for view in ('standard', 'expert'):
            self.page(view=view)
            start = time.perf_counter()
            self.page(view=view)
            self.assertLess(time.perf_counter() - start, 0.1, view)


if __name__ == '__main__':
    unittest.main()
