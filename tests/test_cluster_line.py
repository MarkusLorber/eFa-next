# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-18 (his cluster is live): every admin page, both views, says whether this host is the master or a client of
which master, from the local state only (no call per page). On a client a button opens the master (https to its address
only); old or unreadable state says so; outside a cluster nothing; the name of the master is escaped."""
import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from test_bec_page import SCHEMA, load_web
from test_cluster_rates import efa_cluster, load


class Base(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, True)
        os.makedirs(self.folder + '/eFa/cluster')
        for patch in (mock.patch.object(self.web, 'CLUSTER_DIR', self.folder + '/eFa/cluster'),
                      mock.patch.object(self.web, 'CLUSTER_VIEW', efa_cluster.view_file(self.folder))):
            patch.start()
            self.addCleanup(patch.stop)
        self.web.cluster_view_cache.clear()

        def fake(*args, secrets_in=None, who=None):
            if args[0] == 'schema':
                return True, dict(SCHEMA)
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, {}
        self.web.efactl = fake
        self.web.efactl_read = fake

    def page(self, slug='spam', view='standard', lang='en'):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid='cl', lang=lang, view=view)
        self.web.active_sessions['cl'] = time.time() + 600
        self.web.session_checked['cl'] = time.time()
        reply = client.get(f'/p/{slug}', **self.https)
        self.assertEqual(reply.status_code, 200)
        html = reply.get_data(as_text=True)
        return html[html.index('id="cluster-line"'):html.index('</div>', html.index('id="cluster-line"'))] if 'id="cluster-line"' in html else ''

    def write(self, state, contact=None):
        efa_cluster.write_view(state, self.folder, contact=contact)


class ClusterLine(Base):

    def test_master_both_views(self):
        self.write({'role': 'master', 'name': 'node-b', 'mode': 'ha'})
        for view in ('standard', 'expert'):
            line = self.page(view=view)
            self.assertIn('Cluster: master', line, view)
            self.assertIn('(mode ha)', line)
            self.assertNotIn('Open the master', line)
        self.assertIn('Cluster: Master', self.page(lang='de'))

    def test_client_with_the_button_to_its_master(self):
        self.write({'role': 'client', 'name': 'node-a', 'mode': 'ha', 'master': {'name': 'node-b', 'host': 'node-b.example.org'}}, contact=time.time())
        line = self.page()
        self.assertIn('Cluster: client of node-b', line)
        self.assertIn('href="https://node-b.example.org/" target="_blank" rel="noopener noreferrer">Open the master</a>', line)
        self.assertNotIn('may be old', line)
        self.assertIn('Cluster: Client von node-b', self.page(lang='de'))
        self.write({'role': 'client', 'mode': 'master-client', 'master': {'name': 'node-b', 'host': '2001:db8::2'}}, contact=time.time())
        self.assertIn('href="https://[2001:db8::2]/"', self.page())
        self.assertIn('Shared settings are changed on the master.', self.page())
        self.assertIn('id="cluster-line"', self.page('net', view='expert'), 'every page')

    def test_stale_and_unknown(self):
        self.write({'role': 'client', 'mode': 'ha', 'master': {'name': 'node-b', 'host': 'node-b'}}, contact=time.time() - 3600)
        self.assertIn('may be old', self.page())
        self.write({'role': 'client', 'mode': 'ha', 'master_down_since': 1, 'master': {'name': 'node-b', 'host': 'node-b'}}, contact=time.time())
        self.assertIn('may be old', self.page())
        with open(efa_cluster.view_file(self.folder), 'w') as f:
            f.write('{broken')
        self.web.cluster_view_cache.clear()
        self.assertIn('Cluster: state unknown', self.page())
        os.remove(efa_cluster.view_file(self.folder))
        self.assertIn('Cluster: state unknown', self.page())

    def test_not_in_a_cluster(self):
        shutil.rmtree(self.folder + '/eFa/cluster')
        self.write({'role': 'master', 'name': 'left-over'})
        self.assertEqual(self.page(), '', 'no folder of the cluster: no line, whatever file is left')

    def test_escaping_and_only_https_to_the_master(self):
        self.write({'role': 'client', 'mode': 'ha', 'master': {'name': '<script>alert(1)</script>', 'host': 'javascript:alert(1)'}}, contact=time.time())
        line = self.page()
        self.assertNotIn('<script>', line)
        self.assertIn('&lt;script&gt;', line)
        self.assertNotIn('href=', line, 'no button to an address that is not a host name or an IP address')
        for host, url in (('node-b.example.org', 'https://node-b.example.org/'), ('192.0.2.2', 'https://192.0.2.2/'), ('a b', None),
                          ('evil.org/@x', None), ('', None), ('-x.org', None)):
            self.assertEqual(self.web.master_url(host), url, host)

    def test_view_file_has_no_secret(self):
        state = {'role': 'master', 'name': 'node-b', 'tokens': {'abc': 1}, 'nodes': {'node-a': {'fingerprint': 'AA'}}}
        self.write(state)
        with open(efa_cluster.view_file(self.folder)) as f:
            view = json.load(f)
        self.assertEqual(sorted(view), ['mode', 'name', 'role', 'written'])
        self.assertEqual(os.stat(efa_cluster.view_file(self.folder)).st_mode & 0o777, 0o644)


class DashboardCard(Base):
    """The master's dashboard: a Cluster block with its nodes from the last poll of efa-cluster, never a call per page."""

    def setUp(self):
        super().setUp()
        patch = mock.patch.object(self.web, 'CLUSTER_HEALTH', efa_cluster.health_file(self.folder))
        patch.start()
        self.addCleanup(patch.stop)
        self.web.cluster_health_cache.clear()
        # The dashboard draws its blocks only with readable answers: a mail system that runs, no DKIM rotation yet.
        answers = {'status': {'down': []}, 'rotation-status': {'last_run': '', 'next_check': '', 'domains': []}}

        # Only the status in the schema: the dashboard reads nothing else, so no other answer has to be complete here.
        schema = {name: SCHEMA[name] for name in ('status', 'settings') if name in SCHEMA}

        def fake(*args, secrets_in=None, who=None):
            if args[0] == 'schema':
                return True, schema
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, answers.get(args[0], {})
        self.web.efactl = fake
        self.web.efactl_read = fake

    def dash(self, lang='en'):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid='cd', lang=lang, view='standard')
        self.web.active_sessions['cd'] = time.time() + 600
        self.web.session_checked['cd'] = time.time()
        reply = client.get('/', **self.https)
        self.assertEqual(reply.status_code, 200)
        html = reply.get_data(as_text=True)
        return html[html.index('id="dash-cluster"'):html.index('</div>', html.index('id="dash-cluster"'))] if 'id="dash-cluster"' in html else ''

    def health(self, nodes, written=None, mx=None):
        efa_cluster.write_public(efa_cluster.health_file(self.folder), {'written': written or int(time.time()), 'mode': 'ha', 'nodes': nodes,
                                                                     'mx': mx or {'ok': True, 'problems': []}})

    def test_master_card(self):
        self.write({'role': 'master', 'name': 'node-b', 'mode': 'ha'})
        now = int(time.time())
        self.health([{'name': 'node-a', 'role': 'node', 'version': '6.0.0.6.6', 'platform': 'el9', 'contact': now - 20, 'behind': 0, 'sync': 'ok'}])
        card = self.dash()
        self.assertIn('This host is the master (mode ha).', card)
        self.assertIn('>node-a<', card)
        self.assertIn('6.0.0.6.6 (el9)', card)
        self.assertNotIn('Cluster page', card, 'all fine: no button')
        self.assertIn('Dieser Host ist der Master (Modus ha).', self.dash('de'))

    def test_problems_lead_to_the_cluster_page(self):
        self.write({'role': 'master', 'name': 'node-b', 'mode': 'ha'})
        self.health([{'name': 'node-a', 'sync': 'error', 'error': 'timed out', 'behind': 3}, {'name': 'node-c', 'sync': 'pending'}],
                    mx={'ok': False, 'problems': ['Only one node takes the mail']})
        card = self.dash()
        self.assertIn('<span class="b">error</span>', card)
        self.assertIn('<span class="w">pending</span>', card)
        self.assertIn('<span class="w">3</span>', card)
        self.assertIn('Only one node takes the mail', card)
        self.assertIn('href="/p/cluster"', card)

    def test_stale_poll(self):
        self.write({'role': 'master', 'name': 'node-b', 'mode': 'ha'})
        self.health([], written=int(time.time()) - 3600)
        card = self.dash()
        self.assertIn('class="h w"', card, 'an old poll in amber')
        self.assertIn('href="/p/cluster"', card)
        os.remove(efa_cluster.health_file(self.folder))
        self.web.cluster_health_cache.clear()
        self.assertIn('No poll of the nodes yet.', self.dash())

    def test_escaping(self):
        self.write({'role': 'master', 'name': 'node-b', 'mode': 'ha'})
        self.health([{'name': '<b>x</b>', 'version': '<script>1</script>', 'platform': 'el9', 'sync': 'error', 'error': '<img src=x>'}])
        card = self.dash()
        self.assertNotIn('<script>', card)
        self.assertNotIn('<img', card)
        self.assertNotIn('<b>x</b>', card)

    def test_client_and_no_cluster_have_no_card(self):
        self.write({'role': 'client', 'mode': 'ha', 'master': {'name': 'node-b', 'host': 'node-b'}}, contact=time.time())
        self.health([{'name': 'node-a', 'sync': 'ok'}])
        self.assertEqual(self.dash(), '', 'a client shows only the line')
        shutil.rmtree(self.folder + '/eFa/cluster')
        self.assertEqual(self.dash(), '')

    def test_block_can_be_hidden(self):
        self.write({'role': 'master', 'name': 'node-b', 'mode': 'ha'})
        self.health([])
        self.assertIn('cluster', self.web.DASH_LABELS)


class Poll(unittest.TestCase):
    """efa-cluster on the master asks every node once a minute and writes the card; a node that does not answer keeps its
    last contact."""

    @classmethod
    def setUpClass(cls):
        cls.etc = tempfile.mkdtemp()
        os.makedirs(cls.etc + '/eFa/cluster')
        cls.service = load('next/usr/local/sbin/efa-cluster.py', 'efa_cluster_service_poll', cls.etc)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.etc, ignore_errors=True)

    def test_rows(self):
        state = {'role': 'master', 'nodes': {'a': {'host': 'a'}, 'b': {'host': 'b'}, 'c': {'host': 'c', 'pending': True}}}

        def call(node):
            if node['host'] == 'b':
                raise OSError('timed out')
            return {'version': '6.0.0.6.6', 'platform': 'el9', 'applied': 7, 'failed': [], 'status': 'ok'}
        before = {'nodes': [{'name': 'b', 'contact': 1000, 'version': '6.0.0.6.5'}]}
        efa_cluster.write_public(efa_cluster.health_file(self.etc), before)
        with mock.patch.object(efa_cluster, 'journal_read', lambda base: [{'seq': 9}]):
            health = self.service.poll_health(state, call=call, mx=lambda: {'ok': True, 'findings': []}, now=2000)
        rows = {row['name']: row for row in health['nodes']}
        self.assertEqual((rows['a']['sync'], rows['a']['behind'], rows['a']['contact']), ('ok', 2, 2000))
        self.assertEqual((rows['b']['sync'], rows['b']['contact'], rows['b']['version']), ('error', 1000, '6.0.0.6.5'), 'the last contact stays')
        self.assertEqual(rows['c']['sync'], 'pending')
        self.assertNotIn('host', json.dumps(health), 'no addresses in the card file')
        self.assertTrue(health['mx']['ok'])


class Files(unittest.TestCase):
    """2026-11-18: the two files are state, not configuration: in /var/lib/efa-cluster (0755, /var/lib/eFa is root only), not in
    /etc; not in config backups or the snapshot of the cluster; files of before under /etc/eFa go."""

    def test_where_and_not_in_backups(self):
        self.assertEqual(efa_cluster.view_file(), '/var/lib/efa-cluster/view.json')
        self.assertEqual(efa_cluster.health_file(), '/var/lib/efa-cluster/health.json')
        web = load_web()
        self.assertEqual((web.CLUSTER_VIEW, web.CLUSTER_HEALTH), (efa_cluster.view_file(), efa_cluster.health_file()))
        from test_threat import load_efactl
        efactl = load_efactl()
        for path in efactl.BACKUP_PATHS:
            self.assertFalse(efa_cluster.view_file().startswith(path) or path.startswith('/var/lib/efa-cluster'), path)

    def test_written_whole_and_old_files_go(self):
        etc = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, etc, True)
        os.makedirs(etc + '/eFa')
        for name in ('cluster-view.json', 'cluster-health.json'):
            open(f'{etc}/eFa/{name}', 'w').close()
        efa_cluster.drop_old_files(etc)
        self.assertEqual(os.listdir(etc + '/eFa'), [])
        efa_cluster.write_public(efa_cluster.health_file(etc), {'written': 1})
        folder = os.path.dirname(efa_cluster.health_file(etc))
        self.assertEqual(os.listdir(folder), ['health.json'], 'no temp file left')
        self.assertEqual(os.stat(folder).st_mode & 0o777, 0o755)

    def test_status_of_a_node_only_with_a_certificate(self):
        source = open(os.path.join(os.path.dirname(efa_cluster.__file__), '..', '..', '..', 'local', 'sbin', 'efa-cluster.py'), encoding='utf-8').read()
        handler = source.split('    def do_GET(self):')[1].split('    def sync_answer')[0]
        self.assertLess(handler.index("if who is None:"), handler.index("if self.path == '/v1/status':"), 'the platform only to members')


if __name__ == '__main__':
    unittest.main()
