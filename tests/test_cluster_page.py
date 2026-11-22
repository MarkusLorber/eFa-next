# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-18 (UI review: "Cluster has 0 cards in Standard, the page looks empty"): Cluster & offline by task. Standard shows
the state of the cluster, the staged updates, operation without internet and, on a master, the views over all nodes; the full
cards in Expert."""
import re
import time
import unittest

from test_bec_page import SCHEMA, load_web

import efa_nav  # noqa: E402  (path set by test_bec_page)


class ClusterPage(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        names = {name for section in efa_nav.PAGES['cluster']['sections'] for name in section[1]}
        self.schema = {name: SCHEMA[name] for name in names if name in SCHEMA}
        self.status = {'cluster-status': {'role': 'master', 'name': 'mx-1', 'mode': 'master-client', 'certificate_until': '2029-11-18', 'journal': 9,
                                          'nodes': [{'node': 'mx-2', 'reachable': True, 'behind': 2}, {'node': 'mx-3', 'reachable': False}]},
                       'cluster-update-status': {'enabled': True, 'window': 2, 'first': 'mx-2', 'rollout': {}},
                       'offline-status': {'mirror': '', 'trusted_key': '', 'virus_signatures_days': 3.5}}

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
            sess.update(admin=True, csrf='token', sid='cp', lang=lang, view=view)
        self.web.active_sessions['cp'] = time.time() + 600
        self.web.session_checked['cp'] = time.time()
        reply = client.get('/p/cluster', **self.https)
        self.assertEqual(reply.status_code, 200)
        return reply.get_data(as_text=True)

    def cards(self, html):
        return re.findall(r'<div class="card[^"]*" id="([a-z0-9-]+)"', html)

    def test_master(self):
        html = self.page()
        self.assertEqual([c for c in self.cards(html) if c not in self.web.WARNING_CARDS], ['cluster-state', 'cluster-wizard', 'cluster-hardening', 'cluster-upd', 'cluster-offline', 'cluster-all'])
        for text in ('master (mx-1)', '2, 1 not reachable', 'mx-2', '2 h', '3.5 days old', 'no key trusted', '#cluster-token', '#cluster-maillog'):
            self.assertIn(text, html)
        self.assertIn('<span class="b">2, 1 not reachable</span>', html)

    def test_not_in_a_cluster(self):
        self.status = {'cluster-status': {'role': 'none', 'mode': 'master-client'}}
        html = self.page()
        self.assertEqual([c for c in self.cards(html) if c not in self.web.WARNING_CARDS], ['cluster-state', 'cluster-wizard', 'cluster-upd', 'cluster-offline'])
        self.assertIn('not in a cluster', html)
        self.assertIn('#cluster-init', html)
        self.assertIn('Off: every node installs an update by itself.', html)

    def test_client(self):
        self.status['cluster-status'] = {'role': 'client', 'name': 'mx-2', 'mode': 'master-client', 'master': {'name': 'mx-1', 'host': '192.0.2.1'}}
        html = self.page()
        self.assertIn('client (mx-2)', html)
        self.assertNotIn('id="cluster-all"', html)

    def test_expert_has_the_full_cards(self):
        html = self.page(view='expert')
        self.assertNotIn('id="cluster-state"', html)
        for name in ('cluster-init', 'cluster-update-set', 'update-mirror-set'):
            self.assertIn(f'id="{name}"', html, name)

    def test_page_time(self):
        for view in ('standard', 'expert'):
            self.page(view=view)
            start = time.perf_counter()
            self.page(view=view)
            self.assertLess(time.perf_counter() - start, 0.1, view)


if __name__ == '__main__':
    unittest.main()
