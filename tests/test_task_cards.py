# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The task cards of the pages by task (Security, Maintenance, Viruses, Spam, Network ...) are summaries of the standard view
(class "card task"): each has a control or a button into the expert view, and every such button leads to a card that is there.
2026-11-18: scripts/page_times.py check_standard found them as cards without a control."""
import re
import time
import unittest

from test_bec_page import SCHEMA, load_web

TASK = re.compile(r'<div class="card task" id="([a-z0-9-]+)">(.*?)(?=<div class="card[ "]|</main>)', re.S)


class TaskCards(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

        def fake(*args, secrets_in=None, who=None):
            if args[0] == 'schema':
                return True, dict(SCHEMA)
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, {}
        cls.web.efactl = fake
        cls.web.efactl_read = fake

    def page(self, slug, view):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid='tc', lang='en', view=view)
        self.web.active_sessions['tc'] = time.time() + 600
        self.web.session_checked['tc'] = time.time()
        reply = client.get(f'/p/{slug}', **self.https)
        self.assertEqual(reply.status_code, 200, (slug, view))
        return reply.get_data(as_text=True)

    def test_every_task_card_leads_somewhere(self):
        seen = 0
        for slug in self.web.PAGES:
            if slug == 'dash':
                continue
            standard = self.page(slug, 'standard')
            cards = TASK.findall(standard)
            if not cards:
                continue
            expert = self.page(slug, 'expert')
            for name, body in cards:
                seen += 1
                anchors = re.findall(r'href="/p/' + slug + r'\?view=expert#([a-z0-9-]+)"', body)
                self.assertTrue('<form' in body or anchors, f'{slug}/{name}: no control and no way into the expert view')
                for anchor in anchors:
                    self.assertIn(f'id="{anchor}"', expert, f'{slug}/{name}: #{anchor} is not in the expert view')
        self.assertGreaterEqual(seen, 15, 'the task cards of Security, Maintenance, Viruses, Spam and Network')


if __name__ == '__main__':
    unittest.main()
