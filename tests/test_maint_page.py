# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-17 (UI review, page by page like Security): Maintenance & update by task. Standard shows the Update card, then
the maintenance mode (its switch in the head) and power; the full cards in Expert."""
import gc
import re
import time
import unittest

from test_bec_page import SCHEMA, load_web

import efa_nav  # noqa: E402  (path set by test_bec_page)


class MaintPage(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        names = {name for section in efa_nav.PAGES['maint']['sections'] for name in section[1]} | {'settings'}
        self.schema = {name: SCHEMA[name] for name in names if name in SCHEMA and not name.startswith('release-upgrade')}
        self.status = {'autoupdate-status': {'installed': '6.0.0.6.4', 'latest': '6.0.0.6.5', 'update_available': True, 'security_update': False,
                                             'mode': 'auto', 'days': 'mon tue', 'time': '03:00', 'last_check': '2026-11-17 03:00'},
                       'settings': {'maintenance_mode': False}}

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
            sess.update(admin=True, csrf='token', sid='mt', lang=lang, view=view)
        self.web.active_sessions['mt'] = time.time() + 600
        self.web.session_checked['mt'] = time.time()
        reply = client.get('/p/maint', **self.https)
        self.assertEqual(reply.status_code, 200)
        return reply.get_data(as_text=True)

    def test_standard_shows_the_tasks(self):
        html = self.page()
        cards = re.findall(r'<div class="card[^"]*" id="([a-z0-9-]+)"', html)
        tasks = ['maint-mode', 'maint-power']
        self.assertEqual([card for card in cards if card in tasks], tasks)
        self.assertEqual([card for card in cards if card not in tasks + ['update-system'] and card not in self.web.WARNING_CARDS], [], 'nothing else')
        self.assertIn('class="badge" aria-pressed="false"', html, 'the maintenance switch in the head, off')
        self.assertIn('.sec-grid{display:grid', html, 'the task cards in two columns, not only on the Security page')
        expert = self.page(view='expert')
        self.assertIn('id="autoupdate-set"', expert)

    def test_page_time(self):
        for view in ('standard', 'expert'):
            self.page(view=view)
            # The garbage of the tests before (the whole suite) is collected first, so the budget counts the page alone.
            gc.collect()
            start = time.perf_counter()
            self.page(view=view)
            self.assertLess(time.perf_counter() - start, 0.1, view)

    def test_release_upgrade_phases(self):
        view, now = self.web.ru_view, time.time()
        self.assertEqual(view({})['phase'], 'check')
        self.assertEqual(view({'state': 'queued', 'request': 'preupgrade'})['phase'], 'checking')
        self.assertEqual(view({'state': 'ready', 'preflight': {'ready': True}})['phase'], 'check', 'a preflight alone is no check of leapp')
        self.assertEqual(view({'state': 'ready', 'preupgrade': {'ok': True, 'time': now}})['phase'], 'ready')
        self.assertTrue(view({'state': 'ready', 'preupgrade': {'ok': True, 'time': now - 25 * 3600}})['stale'])
        self.assertEqual(view({'state': 'inhibited', 'preupgrade': {'ok': False, 'time': now}, 'warnings': ['x']})['reasons'], ['x'])
        running = view({'state': 'rebooting'})
        self.assertEqual((running['phase'], running['steps'][2]), ('running', ('reboot', 'now')))
        self.assertTrue(view({'state': 'queued', 'request': 'start'})['abortable'])
        self.assertFalse(view({'state': 'upgrading'})['abortable'])
        self.assertEqual(view({'state': 'checks_failed', 'result': {'failed': ['a']}})['failed'], ['a'])
        inhibited = view({'state': 'ready', 'preupgrade': {'ok': True, 'time': now, 'inhibitors': [{'title': 'vendor map discarded'}]}})
        self.assertEqual((inhibited['phase'], inhibited['reasons']), ('blocked', ['leapp inhibitor: vendor map discarded']), 'ready only without any inhibitor')
        self.assertEqual(view({'state': 'ready', 'preupgrade': {'ok': True, 'time': now, 'removal': ['eFa-next']}})['phase'], 'blocked')


if __name__ == '__main__':
    unittest.main()
