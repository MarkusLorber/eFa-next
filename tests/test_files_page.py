# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-17 (UI review, page by page like Security): Viruses, attachments & links by task. Standard shows four task
cards (virus signatures, attachments, link check with the banner, content disarm), each with its state and its switch in the
head; the full cards in Expert."""
import re
import time
import unittest

from test_bec_page import SCHEMA, load_web

import efa_nav  # noqa: E402  (path set by test_bec_page)

TASKS = ['files-virus', 'files-attach', 'files-links', 'files-cdr']


class FilesPage(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        names = {name for section in efa_nav.PAGES['files']['sections'] for name in section[1]}
        self.schema = {name: SCHEMA[name] for name in names if name in SCHEMA}
        self.status = {'sanesecurity-status': {'active': True, 'signatures': 4711, 'last_check': '2026-11-17 03:00', 'errors': []},
                       'clam-source-status': {'sources': [self.source('urlhaus', 'URLhaus', True), self.source('securiteinfo', 'SecuriteInfo', False)]},
                       'attachment-status': {'enabled': True, 'action': 'reject', 'encrypted': 'mark', 'macros': 'off', 'extensions': ['exe']},
                       'links-status': {'enabled': False, 'base': '', 'exceptions': []},
                       'banner-status': {'enabled': True},
                       'cdr-status': {'enabled': True, 'service': False, 'originals': 3}}

        def fake(*args, secrets_in=None, who=None):
            if args[0] == 'schema':
                return True, self.schema
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, self.status.get(args[0], {})
        self.web.efactl = fake
        self.web.efactl_read = fake

    @staticmethod
    def source(key, name, active):
        return {'source': key, 'name': name, 'terms': 'free', 'active': active, 'accepted': active, 'files': [key + '.ndb'],
                'terms_accepted': active, 'terms_url': 'https://example.org/terms', 'needs_id': False, 'id_set': False}

    def page(self, view='standard', lang='en'):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid='fp', lang=lang, view=view)
        self.web.active_sessions['fp'] = time.time() + 600
        self.web.session_checked['fp'] = time.time()
        reply = client.get('/p/files', **self.https)
        self.assertEqual(reply.status_code, 200)
        return reply.get_data(as_text=True)

    def test_standard_shows_the_tasks(self):
        html = self.page()
        cards = re.findall(r'<div class="card[^"]*" id="([a-z0-9-]+)"', html)
        self.assertEqual([card for card in cards if card in TASKS], TASKS)
        self.assertEqual([card for card in cards if card not in TASKS and card not in self.web.WARNING_CARDS], [], 'nothing else')
        self.assertIn('4711 signatures', html)
        self.assertIn('URLhaus', html)
        self.assertNotIn('SecuriteInfo', html, 'only the sources in use')
        self.assertIn('not running', html, 'the disarm service down shows')
        # The four switches in the heads show the state in effect: signatures on, attachments on, links off, disarm on.
        self.assertEqual(re.findall(r'class="badge[^"]*" aria-pressed="(true|false)"', html), ['true', 'true', 'false', 'true'])
        self.assertEqual(html.count('data-stay="@card"'), 4, 'every switch keeps the page')
        self.assertIn('.sec-grid{display:grid', html, 'the task cards in two columns, not only on the Security page')

    def test_expert_has_the_full_cards(self):
        html = self.page(view='expert')
        self.assertNotIn('id="files-virus"', html)
        for name in ('attachment-set', 'links-set', 'cdr-set', 'clam-source-status', 'scan-limits-set'):
            self.assertIn(f'id="{name}"', html, name)

    def test_german(self):
        html = self.page(lang='de')
        for text in ('Virensignaturen', 'Anhänge', 'Linkprüfung', 'Entschärfung von Inhalten', 'Einstellungen'):
            self.assertIn(text, html)

    def test_page_time(self):
        for view in ('standard', 'expert'):
            self.page(view=view)
            start = time.perf_counter()
            self.page(view=view)
            self.assertLess(time.perf_counter() - start, 0.1, view)


if __name__ == '__main__':
    unittest.main()
