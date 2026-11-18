# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-18 (UI review: Domain settings showed 13 cards in Standard): Domain settings by task. Standard shows every own
domain in one table (domain check, role addresses, job applications), the EU relation and the domain check; the cards per
domain in Expert."""
import re
import time
import unittest

from test_bec_page import SCHEMA, load_web

import efa_nav  # noqa: E402  (path set by test_bec_page)

TASKS = ['domset-domains', 'domset-eu', 'domset-check']


class DomsetPage(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        names = {name for section in efa_nav.PAGES['domset']['sections'] for name in section[1]}
        self.schema = {name: SCHEMA[name] for name in names if name in SCHEMA}
        self.status = {'domain-check-status': {'mode': 'on', 'prompt': 'off', 'last': '2026-11-18 06:00',
                                               'domains': [{'domain': 'example.org', 'light': 'red', 'problems': ['SPF: missing', 'DMARC: none'], 'checked': ''},
                                                           {'domain': 'example.net', 'light': 'green', 'problems': [], 'checked': ''}]},
                       'role-status': {'domains': [{'domain': 'example.org', 'on': True, 'from': 'all', 'roles': {}},
                                                   {'domain': 'example.net', 'on': False, 'from': 'domain', 'roles': {}}], 'roles': {}, 'default_new_domains': True},
                       'application-status': {'domains': [{'domain': '*', 'mode': 'open'}, {'domain': 'example.net', 'mode': 'list'}], 'exceptions': [], 'open_unconfirmed': []},
                       'eu-relation-status': {'global': 'yes', 'choice': 'yes', 'domains': {'example.net': 'no'}}}

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
            sess.update(admin=True, csrf='token', sid='dp', lang=lang, view=view)
        self.web.active_sessions['dp'] = time.time() + 600
        self.web.session_checked['dp'] = time.time()
        reply = client.get('/p/domset', **self.https)
        self.assertEqual(reply.status_code, 200)
        return reply.get_data(as_text=True)

    def test_standard_shows_the_tasks(self):
        html = self.page()
        cards = re.findall(r'<div class="card[^"]*" id="([a-z0-9-]+)"', html)
        self.assertEqual([c for c in cards if c not in self.web.WARNING_CARDS], TASKS)
        table = html[html.index('id="domset-domains"'):html.index('id="domset-eu"')]
        net, org = table.index('>example.net<'), table.index('>example.org<')
        self.assertLess(net, org, 'by name')
        self.assertIn('<span class="b">2 problems</span>', table[org:])
        self.assertIn('only listed addresses', table[net:org], 'the rule of the domain')
        self.assertIn('to everybody', table[org:], 'the rule for all domains')
        self.assertIn('action="/run/domain-check-run"', table)
        self.assertIn('2026-11-18 06:00', table)

    def test_no_domain(self):
        self.status = {}
        html = self.page()
        self.assertIn('No own domain yet.', html)
        self.assertIn('not answered', html)

    def test_expert_has_the_full_cards(self):
        html = self.page(view='expert')
        self.assertNotIn('id="domset-domains"', html)
        for name in ('domain-settings-show', 'role-set', 'application-set', 'eu-relation-set', 'domain-check-set'):
            self.assertIn(f'id="{name}"', html, name)

    def test_page_time(self):
        for view in ('standard', 'expert'):
            self.page(view=view)
            start = time.perf_counter()
            self.page(view=view)
            self.assertLess(time.perf_counter() - start, 0.1, view)


if __name__ == '__main__':
    unittest.main()
