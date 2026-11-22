# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-18 (UI review, page by page like Security): Network, DNS & certificate by task. Standard shows four task cards
(this server, DNS, certificate, resolver for other networks), each with its state; the full cards, which ask before a
change, in Expert."""
import re
import time
import unittest

from test_bec_page import SCHEMA, load_web

import efa_nav  # noqa: E402  (path set by test_bec_page)

TASKS = ['net-addr', 'net-dns', 'net-cert', 'net-hosts', 'net-share']


class NetPage(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        names = {name for section in efa_nav.PAGES['net']['sections'] for name in section[1]} | {'settings'}
        self.schema = {name: SCHEMA[name] for name in names if name in SCHEMA}
        self.status = {'network-show': {'ipv4.method': 'manual', 'ipv4.addresses': '192.0.2.10/24', 'ipv4.gateway': '192.0.2.1',
                                        'ipv6.method': 'disabled', 'ipv6.addresses': '', 'hostname': 'mx1.example.org', 'connection': 'eth0'},
                       'dns-forward-status': {'forward_all': True, 'public': True, 'system_uses_unbound': True, 'files': {}},
                       'dns-zone-list': {'servers': [], 'tls': False, 'max': 50, 'zones': {'corp.example': {}}},
                       'dns-share-list': {'entries': [{'net': '10.0.0.0/8'}], 'secondary': '', 'max': 20, 'listens_on': ['10.0.0.5']},
                       'hosts-list': {'entries': {'git.corp.example': {'addresses': ['10.0.0.7'], 'note': '', 'scope': 'cluster'}}, 'max': 256,
                                      'cluster': False, 'also_by_hand': ['git.corp.example']}}

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
            sess.update(admin=True, csrf='token', sid='np', lang=lang, view=view)
        self.web.active_sessions['np'] = time.time() + 600
        self.web.session_checked['np'] = time.time()
        reply = client.get('/p/net', **self.https)
        self.assertEqual(reply.status_code, 200)
        return reply.get_data(as_text=True)

    def test_standard_shows_the_tasks(self):
        html = self.page()
        cards = re.findall(r'<div class="card[^"]*" id="([a-z0-9-]+)"', html)
        self.assertEqual([card for card in cards if card in TASKS], TASKS)
        self.assertEqual([card for card in cards if card not in TASKS and card not in self.web.WARNING_CARDS], [], 'nothing else')
        for text in ('mx1.example.org', '192.0.2.10/24', '192.0.2.1', 'public resolvers', '10.0.0.0/8', '10.0.0.5'):
            self.assertIn(text, html)
        self.assertIn('#dns-forward-fix', html, 'names to public resolvers: the fix is offered')
        hosts = html[html.index('id="net-hosts"'):html.index('id="net-share"')]
        self.assertIn('Also in /etc/hosts by hand', hosts)
        self.assertIn('#hosts-set', hosts, 'own host names: the card leads to the full card in Expert')
        grid = html[html.index('id="net-addr"'):html.index('</div></div>', html.index('id="net-share"'))]
        self.assertNotIn('<form', grid, 'the task cards change nothing by themselves: the network cards ask first in Expert')

    def test_dhcp(self):
        self.status['network-show'].update({'ipv4.method': 'auto', 'ipv4.addresses': '', 'ipv4.gateway': ''})
        self.assertIn('automatic (DHCP)', self.page())

    def test_expert_has_the_full_cards(self):
        html = self.page(view='expert')
        self.assertNotIn('id="net-addr"', html)
        for name in ('network-set', 'dns-servers-set', 'letsencrypt-set', 'dns-share-add', 'interface-set'):
            self.assertIn(f'id="{name}"', html, name)

    def test_page_time(self):
        for view in ('standard', 'expert'):
            self.page(view=view)
            start = time.perf_counter()
            self.page(view=view)
            self.assertLess(time.perf_counter() - start, 0.1, view)


if __name__ == '__main__':
    unittest.main()
