# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-17/18 (UI review: "generell ist monitoring nicht intuitiv und übersichtlich gestaltet"): Monitoring by task.
Standard shows one card per way to send data (OpenTelemetry, SIEM, Wazuh) with its state (and switch, without a secret), and where metrics and
reports are; the full cards in Expert."""
import re
import time
import unittest

from test_bec_page import SCHEMA, load_web

import efa_nav  # noqa: E402  (path set by test_bec_page)

TASKS = ['mon-otel', 'mon-siem', 'mon-wazuh']


class MonitoringPage(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        names = {name for section in efa_nav.PAGES['export']['sections'] for name in section[1]} | {'settings', 'token-list', 'report-status'}
        self.schema = {name: SCHEMA[name] for name in names if name in SCHEMA}
        self.status = {'otlp-status': {'enabled': True, 'endpoint': 'https://otel.example.org:4318', 'last_sent': '2026-11-18 10:00',
                                       'last_status': '503', 'dropped': 12, 'signals': ['events']},
                       'siem-status': {'siem': True, 'target': 'siem.example.org', 'port': 6514, 'protocol': 'tls', 'format': 'json'},
                       'wazuh-status': {'installed': '4.9.2', 'connection': 'disconnected', 'manager': 'wazuh.example.org'}}

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
            sess.update(admin=True, csrf='token', sid='mp', lang=lang, view=view)
        self.web.active_sessions['mp'] = time.time() + 600
        self.web.session_checked['mp'] = time.time()
        reply = client.get('/p/export', **self.https)
        self.assertEqual(reply.status_code, 200)
        return reply.get_data(as_text=True)

    def test_standard_shows_the_tasks(self):
        html = self.page()
        cards = re.findall(r'<div class="card[^"]*" id="([a-z0-9-]+)"', html)
        self.assertEqual([card for card in cards if card in TASKS], TASKS)
        self.assertIn('<div class="card task mon-more">', html, 'metrics and reports: buttons to other pages, no card id')
        self.assertEqual([card for card in cards if card not in TASKS and card not in self.web.WARNING_CARDS], [], 'nothing else')
        for text in ('https://otel.example.org:4318', 'siem.example.org:6514', 'TLS, json', '4.9.2', 'wazuh.example.org'):
            self.assertIn(text, html)
        self.assertIn('<span class="b">12</span>', html, 'dropped data in red')
        self.assertIn('<span class="b">disconnected</span>', html, 'a Wazuh agent without its manager in red')
        # SIEM switches in its head; OpenTelemetry has a secret (token) and keeps its form: its head shows the state only.
        self.assertEqual(re.findall(r'class="badge[^"]*" aria-pressed="(true|false)"', html), ['true'], 'SIEM on, its switch')
        self.assertIn('<h2>OpenTelemetry<span class="badge on">On</span></h2>', html)
        self.assertEqual(html.count('data-stay="@card"'), 1)

    def test_off_and_not_installed(self):
        self.status = {}
        html = self.page()
        self.assertEqual(re.findall(r'class="badge[^"]*" aria-pressed="(true|false)"', html), ['false'])
        self.assertIn('<h2>OpenTelemetry<span class="badge">Off</span></h2>', html)
        self.assertIn('#wazuh-install', html, 'no agent: the way to install it')

    def test_expert_has_the_full_cards(self):
        html = self.page(view='expert')
        self.assertNotIn('id="mon-otel"', html)
        for name in ('otlp-set', 'siem-set', 'wazuh-config'):
            self.assertIn(f'id="{name}"', html, name)

    def test_page_time(self):
        for view in ('standard', 'expert'):
            self.page(view=view)
            start = time.perf_counter()
            self.page(view=view)
            self.assertLess(time.perf_counter() - start, 0.1, view)


if __name__ == '__main__':
    unittest.main()
