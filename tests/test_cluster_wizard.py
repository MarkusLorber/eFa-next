# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Cluster wizard (2026-11-18): the checks before a join answer only to a valid token and do not use it up; a node that joined
is pending (no traffic, no settings) until its admin saw the preview and confirmed; the confirmation makes a backup first and
stops without it; one run at a time; a pending node that leaves is forgotten by its master. Every gate is in efactl and in
efa-cluster.py, not in the web interface."""
import json
import re
import os
import shutil
import tempfile
import time
import types
import unittest
import urllib.error
from unittest import mock

from test_cluster_rates import efa_cluster, load
from test_threat import load_efactl


class Service(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.etc = tempfile.mkdtemp()
        cls.service = load('next/usr/local/sbin/efa-cluster.py', 'efa_cluster_service_wizard', cls.etc)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.etc, ignore_errors=True)

    def state(self, until):
        return {'role': 'master', 'name': 'node-b', 'tokens': {efa_cluster.token_hash('t' * 32): until}, 'nodes': {}}

    def test_precheck_needs_a_valid_token_and_keeps_it(self):
        now = time.time()
        state = self.state(now + 600)
        with mock.patch.object(efa_cluster, 'efa_version', lambda: '6.0.0.6.7'), mock.patch.object(efa_cluster, 'own_platform', lambda: 'el9'):
            answer = self.service.precheck(state, {'token': 't' * 32}, now=now)
        self.assertEqual(answer, {'version': '6.0.0.6.7', 'platform': 'el9', 'time': int(now)}, 'only version, platform and time')
        self.assertIn(efa_cluster.token_hash('t' * 32), state['tokens'], 'the token stays valid for the join')
        for token, until in (('wrong', now + 600), ('t' * 32, now - 1)):
            with self.assertRaises(PermissionError):
                self.service.precheck(self.state(until), {'token': token}, now=now)

    def test_join_is_pending_and_does_not_hold_the_scrub(self):
        self.assertIn("'pending': True", open(self.service.__file__, encoding='utf-8').read().split('def join(')[1].split('def journal_after')[0])
        state = {'role': 'master', 'nodes': {'a': {'applied': 7}, 'new': {'applied': 0, 'pending': True}}}
        _changed, everyone = self.service.confirm(state, 'a', 9)
        self.assertEqual(everyone, 9, 'the pending node does not hold the scrub of the journal back')
        self.assertEqual(sorted(efa_cluster.active_nodes(state)), ['a'])

    def test_throttle_per_source_and_in_total(self):
        throttle = self.service.Throttle()
        self.assertTrue(all(throttle.allow('precheck 192.0.2.1', now=100) for _ in range(self.service.JOIN_TRIES)))
        self.assertFalse(throttle.allow('precheck 192.0.2.1', now=100), 'per source')
        self.assertTrue(throttle.allow('precheck 192.0.2.1', now=161), 'a minute later again')
        total = [throttle.allow('precheck', now=200, most=self.service.PRECHECK_TOTAL) for _ in range(self.service.PRECHECK_TOTAL + 1)]
        self.assertEqual(total.count(False), 1, 'in total')

    def test_refusals_are_audited_with_the_source(self):
        seen = []
        self.service.audit_refusal('192.0.2.9', 'unknown or expired token', run=lambda line, **_kw: seen.append(line))
        for _ in range(50):
            if seen:
                break
            time.sleep(0.02)
        self.assertEqual(seen[0][1:4], ['audit-note', '--action', 'cluster_precheck_refused'])
        self.assertIn('192.0.2.9: unknown or expired token', seen[0])


class FakeCluster:
    PORT = 8460
    valid_name = staticmethod(lambda name: True)

    def __init__(self, facts=None, error=None):
        self.facts, self.error, self.calls = facts, error, []

    def fetch_ca(self, host, port):
        return 'CA'

    def join_request(self, host, port, ca, body, path='/v1/join'):
        self.calls.append((path, body))
        if self.error:
            raise self.error
        return self.facts

    def fingerprint_pem(self, _pem):
        return 'AA:BB'


class Node(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, True)
        open(self.folder + '/monitor.cron', 'w').close()
        self.audited = []
        for patch in (mock.patch.object(self.efactl, 'MONITOR_CRON', self.folder + '/monitor.cron'),
                      mock.patch.object(self.efactl, 'CLUSTER_JOIN_JOB', self.folder + '/cluster-join.json'),
                      mock.patch.object(self.efactl, '_ru_state', lambda: {}),
                      mock.patch.object(self.efactl, '_efa_version', lambda: '6.0.0.6.7'),
                      mock.patch.object(self.efactl, 'EL_RELEASE', 'el9'),
                      mock.patch.object(self.efactl, '_audit', self.audited.append),
                      mock.patch.object(self.efactl, '_cluster_parts', lambda: (None, None, {}))):
            patch.start()
            self.addCleanup(patch.stop)

    def facts(self, **change):
        return {'version': '6.0.0.6.7', 'platform': 'el9', 'time': int(time.time()), **change}

    def checks(self, fake):
        checks, _ca, _facts = self.efactl.cluster_join_checks(fake, 'node-b.example.org', 8460, 'tok')
        return {item['check']: item for item in checks}

    def test_all_checks_pass(self):
        fake = FakeCluster(self.facts())
        found = self.checks(fake)
        self.assertTrue(all(item['ok'] for item in found.values()), found)
        self.assertEqual(fake.calls, [('/v1/precheck', {'token': 'tok'})], 'the token goes with the check')

    def test_each_check_refuses(self):
        self.assertFalse(self.checks(FakeCluster(self.facts(version='6.0.0.6.6')))['same eFa-next version']['ok'])
        platform = self.checks(FakeCluster(self.facts(platform='el10')))['platform']
        self.assertTrue(platform['ok'], 'EL9 and EL10 nodes in one cluster (6.0.0.6.6)')
        self.assertIn('EL9 and EL10', platform['detail'])
        self.assertFalse(self.checks(FakeCluster(self.facts(time=int(time.time()) - 600)))['time in sync']['ok'])
        token = self.checks(FakeCluster(error=urllib.error.HTTPError('u', 403, 'no', {}, None)))['token']
        self.assertEqual((token['ok'], token['detail']), (False, 'unknown or expired'))
        os.remove(self.folder + '/monitor.cron')
        self.assertFalse(self.checks(FakeCluster(self.facts()))['maintenance mode off']['ok'])
        open(self.folder + '/monitor.cron', 'w').close()
        with mock.patch.object(self.efactl, '_ru_state', lambda: {'state': 'upgrading'}):
            self.assertFalse(self.checks(FakeCluster(self.facts()))['no release upgrade running']['ok'])
        with mock.patch.object(self.efactl, '_cluster_parts', lambda: (None, None, {'role': 'master', 'name': 'node-a'})):
            self.assertFalse(self.checks(FakeCluster(self.facts()))['not in a cluster yet']['ok'])

    def test_text_of_the_master_is_cleaned(self):
        _checks, _ca, facts = self.efactl.cluster_join_checks(FakeCluster(self.facts(version='<script>6.0</script>', platform='el9"x')), 'm', 8460, 't')
        self.assertEqual((facts['version'], facts['platform']), ('script6.0script', 'el9x'))

    def test_join_refused_when_a_check_fails(self):
        fake = FakeCluster(self.facts(platform='el10'))
        args = types.SimpleNamespace(name='node-a', address='192.0.2.11', master='node-b.example.org', ca_fingerprint='AA:BB', port='')
        with mock.patch.object(self.efactl, '_cluster_parts', lambda: (fake, self.folder + '/cluster', {})), \
                mock.patch.object(self.efactl, '_secrets', lambda count, prompt: ['tok']), \
                mock.patch.object(self.efactl, 'cluster_join_checks', lambda *a: ([{'check': 'same platform', 'ok': False, 'detail': 'x'}], 'CA', {})):
            with self.assertRaises(self.efactl.EfaError) as caught:
                self.efactl.cluster_join(args)
        self.assertIn('same platform', str(caught.exception))
        self.assertNotIn(('/v1/join', mock.ANY), fake.calls)
        self.assertFalse(os.path.exists(self.folder + '/cluster'), 'nothing written')

    def pending(self, calls):
        state = {'role': 'client', 'name': 'node-a', 'pending': True, 'master': {'name': 'node-b', 'host': 'node-b', 'port': 8460}}
        fake = types.SimpleNamespace(call=lambda base, host, port, path, body=None, timeout=10: calls.append(path) or {},
                                     read_state=lambda etc: dict(state), write_state=lambda new, etc: calls.append(('state', new)),
                                     job_envelope=efa_cluster.job_envelope)
        return mock.patch.object(self.efactl, '_cluster_pending', lambda: (fake, '/base', state))

    def test_no_settings_without_a_backup(self):
        calls = []

        def broken(_args):
            raise self.efactl.EfaError('disk full')
        with self.pending(calls):
            job = self.efactl.cluster_activate_run(None, backup=broken, resync=lambda _a: calls.append('resync'))
        self.assertEqual((job['state'], job['step']), ('failed', 'backup'))
        self.assertEqual(calls, [], 'neither the master nor the settings')
        self.assertEqual(json.load(open(self.folder + '/cluster-join.json'))['state'], 'failed')

    def test_confirmation_in_order(self):
        calls = []
        with self.pending(calls):
            job = self.efactl.cluster_activate_run(None, backup=lambda _a: calls.append('backup') or {'backup': 'efa-backup-1'},
                                                   resync=lambda _a: calls.append('resync') or {'files': 3})
        self.assertEqual(job['state'], 'done')
        self.assertEqual(calls[:3], ['backup', '/v1/activate', 'resync'])
        self.assertNotIn('pending', calls[3][1], 'the node takes part now')

    def test_master_must_reach_the_node(self):
        calls = []
        with self.pending(calls) as _p:
            state = {'role': 'client', 'name': 'node-a', 'pending': True, 'master': {'name': 'node-b', 'host': 'node-b', 'port': 8460}}

            def refused(*_a, **_kw):
                raise ValueError('HTTP 409: the master does not reach this node')
            fake = types.SimpleNamespace(call=refused, read_state=lambda etc: state, write_state=lambda *a: calls.append('state'),
                                         job_envelope=efa_cluster.job_envelope)
            with mock.patch.object(self.efactl, '_cluster_pending', lambda: (fake, '/base', state)):
                job = self.efactl.cluster_activate_run(None, backup=lambda _a: {}, resync=lambda _a: calls.append('resync'))
        self.assertEqual((job['state'], job['step']), ('failed', 'activate'))
        self.assertEqual(calls, [], 'no settings, the node stays pending')

    def test_one_run_at_a_time(self):
        with open(self.folder + '/cluster-join.json', 'w') as f:
            json.dump({'state': 'running', 'step': 'backup'}, f)
        with self.pending([]):
            with self.assertRaises(self.efactl.EfaError):
                self.efactl.cluster_activate(types.SimpleNamespace(confirm='yes', understood='yes'))

    def test_gates(self):
        for name in ('cluster-join-check', 'cluster-join-preview', 'cluster-activate', 'cluster-activate-run', 'cluster-join-status'):
            self.assertIn(name, self.efactl.SUPER_COMMANDS)
            self.assertFalse(self.efactl.command_allowed({'username': 'a', 'role': 'custom', 'grants': {'settings.edit'}}, name, True), name)
        self.assertEqual(self.efactl.CLUSTER_TOKEN_SECONDS, 1800)
        self.assertTrue(self.efactl.COMMANDS['cluster-join-check']['args'][1]['secret'], 'the token never as an argument')


if __name__ == '__main__':
    unittest.main()


class Web(unittest.TestCase):
    """The wizard on the Cluster page: the steps outside a cluster, the token on the master, the confirmation of a pending
    node with its progress, and the checks before the join with the fingerprint; everything from the master escaped."""
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        from test_bec_page import SCHEMA, load_web
        import efa_nav
        cls.web = load_web()
        names = {name for section in efa_nav.PAGES['cluster']['sections'] for name in section[1]}
        cls.schema = {name: SCHEMA[name] for name in names if name in SCHEMA}

    def setUp(self):
        self.status = {}

        def fake(*args, secrets_in=None, who=None):
            if args[0] == 'schema':
                return True, self.schema
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, self.status.get(args[0], {})
        self.web.efactl = fake
        self.web.efactl_read = fake

    def client(self):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid='cw', lang='en', view='standard')
        self.web.active_sessions['cw'] = time.time() + 600
        self.web.session_checked['cw'] = time.time()
        return client

    def card(self):
        html = self.client().get('/p/cluster', **self.https).get_data(as_text=True)
        start = html.index('id="cluster-wizard"')
        return html[start:html.index('id="cluster-upd"', start)]

    def test_steps_outside_a_cluster(self):
        self.status = {'cluster-status': {'role': 'none'}}
        card = self.card()
        self.assertIn('Set up a cluster', card)
        self.assertIn('Which host is the first master?', card)
        self.assertIn('efactl admin-password', card, 'the way back in')
        self.assertIn('#cluster-init', card)
        self.assertIn('#cluster-join-check', card)

    def test_master_makes_tokens(self):
        self.status = {'cluster-status': {'role': 'master', 'name': 'node-b', 'nodes': []}}
        self.assertIn('#cluster-token', self.card())

    def test_pending_node_confirms(self):
        self.status = {'cluster-status': {'role': 'client', 'name': 'node-a', 'pending': True, 'master': {'name': 'node-b'}},
                       'cluster-join-status': {'state': 'failed', 'step': 'backup', 'error': '<b>disk full</b>', 'steps': ['backup', 'activate', 'settings']}}
        card = self.card()
        self.assertIn('action="/run/cluster-join-preview"', card)
        self.assertIn('action="/run/cluster-activate"', card)
        self.assertIn('name="confirm" value=""', card)
        self.assertIn('Stopped at Backup: &lt;b&gt;disk full&lt;/b&gt;', card)
        self.assertIn('#cluster-leave', card)
        self.assertIn('name="understood" value="yes" required', card, 'the tick box (efactl checks it too)')
        self.assertIn('loses that access', card, 'the logins of the master replace the ones here')
        self.status['cluster-join-status'] = {'state': 'running', 'step': 'activate', 'steps': ['backup', 'activate', 'settings']}
        card = self.card()
        self.assertIn('role="progressbar"', card)
        self.assertIn('aria-valuenow="33"', card)
        self.assertIn('id="cluster-live" data-url="/cluster-join-live"', card, 'live while it runs')
        live = self.client().get('/cluster-join-live', **self.https).get_data(as_text=True)
        self.assertIn('class="cl-live" data-state="running"', live)
        self.assertIn('aria-valuenow="33"', live, 'the same bar as on the page')
        self.assertNotIn('action="/run/cluster-activate"', card, 'one run at a time')
        self.assertIn('cluster-activate', self.web.REAUTH_COMMANDS)
        self.assertIn('cluster-activate-run', self.web.NOT_CALLABLE)

    def test_check_result_with_the_fingerprint(self):
        self.status['cluster-join-check'] = {'ok': False, 'ca_fingerprint': 'AA:BB<i>', 'checks': [
            {'check': 'same platform', 'ok': False, 'detail': 'master el10<script>, this node el9'}, {'check': 'token', 'ok': True, 'detail': 'valid'}]}
        client = self.client()
        reply = client.post('/run/cluster-join-check', data={'csrf': 'token', 'master': 'node-b.example.org', 'token': 't'}, follow_redirects=True, **self.https)
        html = reply.get_data(as_text=True)
        result = html[html.index('id="join-check-result"'):]
        self.assertIn('AA:BB&lt;i&gt;', result)
        self.assertNotIn('<script>', result)
        self.assertIn('Not every check passed', result)
        self.assertIn('<span class="b">failed</span>', result)


class FollowUp(unittest.TestCase):
    """2026-11-18 review: a pending node gets only the preview manifest, no secret; jobs between the nodes carry an id, a time
    and an expiry, replays refused; the logins of the master replace the node's, the tick box checked by efactl; the one
    login of the admin is asked at the master, yes or no, under the rules of the check before the join."""

    @classmethod
    def setUpClass(cls):
        cls.etc = tempfile.mkdtemp()
        os.makedirs(cls.etc + '/eFa/cluster')
        cls.service = load('next/usr/local/sbin/efa-cluster.py', 'efa_cluster_service_follow', cls.etc)
        cls.efactl = load_efactl()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.etc, ignore_errors=True)

    def test_preview_manifest_has_no_secret(self):
        import base64
        secrets_in = ['-----BEGIN PRIVATE KEY-----MIIEsecret', '$6$rounds=5000$hash', 'otpauth://totp/x?secret=JBSWY3DP', 'sasl-pass-1234']
        snapshot = {'seq': 4, 'files': [{'path': 'rspamd/dkim/example.org.key', 'data': base64.b64encode(secrets_in[0].encode()).decode(), 'mode': 0o600}],
                    'postconf': {'smtp_sasl_password_maps': secrets_in[3]}, 'units': {'efa-cdr': True},
                    'sql': "INSERT INTO users VALUES ('anna','%s','%s');" % (secrets_in[1], secrets_in[2])}
        manifest = efa_cluster.preview_manifest(snapshot)
        text = json.dumps(manifest)
        for secret in secrets_in:
            self.assertNotIn(secret, text, secret)
        self.assertEqual(sorted(manifest), sorted(efa_cluster.PREVIEW_KEYS))
        self.assertIsNone(re.search(r'[0-9a-f]{40,}', text), 'no hash of any value or file: a short secret in a plain hash can be guessed')
        self.assertEqual(manifest['files'], ['rspamd/dkim/example.org.key'])
        import hashlib
        mine = {'files': {'rspamd/dkim/example.org.key': hashlib.sha256(secrets_in[0].encode()).hexdigest()},
                'postconf': {'smtp_sasl_password_maps': hashlib.sha256(b'other').hexdigest()}}
        compared = efa_cluster.preview_compare(snapshot, mine)
        self.assertEqual(sorted(compared), sorted(efa_cluster.COMPARE_KEYS))
        self.assertEqual((compared['files'], compared['unchanged_files']), ([], 1), 'the same key file: unchanged, no hash back')
        self.assertEqual(compared['postconf'], [{'name': 'smtp_sasl_password_maps'}], 'changed, only its name')
        back = json.dumps(compared)
        self.assertIsNone(re.search(r'[0-9a-f]{40,}', back))
        for secret in secrets_in:
            self.assertNotIn(secret, back)
        self.assertTrue(efa_cluster.PREVIEW_NEVER, 'the one list of what a pending node never gets')
        handler = open(self.service.__file__, encoding='utf-8').read().split('    def do_GET(self):')[1].split('    def sync_answer')[0]
        self.assertIn("if self.path == '/v1/snapshot' and pending:", handler)
        self.assertIn("preview_manifest(snapshot) if self.path == '/v1/preview'", handler)
        self.assertIn('efa_cluster.preview_compare(snapshot_of_master(), body)', open(self.service.__file__, encoding='utf-8').read())

    def test_jobs_expire_and_are_not_replayed(self):
        seen = {}
        job = efa_cluster.job_envelope('activate', now=1000)
        self.assertIsNone(efa_cluster.job_problem(job, 'activate', seen, now=1001))
        self.assertIn('replay', efa_cluster.job_problem(job, 'activate', seen, now=1002))
        self.assertIn('expired', efa_cluster.job_problem(efa_cluster.job_envelope('activate', now=0), 'activate', {}, now=5000))
        self.assertEqual(efa_cluster.job_problem(efa_cluster.job_envelope('leave', now=1000), 'activate', {}, now=1001), 'not a job of this kind')
        self.assertIn('times', efa_cluster.job_problem(efa_cluster.job_envelope('activate', now=9000), 'activate', {}, now=1000), 'from the future')
        self.assertIn('times', efa_cluster.job_problem({**job, 'id': 'ab' * 16, 'expires': job['issued'] + 3 * 3600}, 'activate', {}, now=1001), 'too long')
        stored = efa_cluster.job_envelope('activate')
        self.assertIsNone(self.service.take_job(stored, 'activate'))
        self.assertIn('replay', self.service.take_job(stored, 'activate'), 'the store of seen ids is on disk')
        self.assertEqual(os.stat(efa_cluster.seen_jobs_file(self.etc)).st_mode & 0o777, 0o600)

    def test_one_login_asked_only_with_a_valid_token(self):
        now = time.time()
        state = {'role': 'master', 'tokens': {efa_cluster.token_hash('t' * 32): now + 600}}
        asked = []

        def run(line, **_kw):
            asked.append(line)
            return types.SimpleNamespace(stdout='{"exists": true}')
        answer = self.service.precheck(state, {'token': 't' * 32, 'user': 'anna'}, now=now, run=run)
        self.assertIs(answer['user_exists'], True)
        self.assertEqual(asked[0][-2:], ['--name', 'anna'], 'one name')
        self.assertNotIn('user_exists', self.service.precheck(state, {'token': 't' * 32, 'user': ['anna', 'bob']}, now=now, run=run), 'never a list')
        self.assertNotIn('user_exists', self.service.precheck(state, {'token': 't' * 32, 'user': 'x; rm'}, now=now, run=run))
        with self.assertRaises(PermissionError):
            self.service.precheck(state, {'token': 'wrong', 'user': 'anna'}, now=now, run=run)
        self.assertEqual(len(asked), 1, 'no answer and no lookup without a valid token')
        handler = open(self.service.__file__, encoding='utf-8').read()
        self.assertIn("if not self.throttle.allow('precheck ' + source) or not self.throttle.allow('precheck', most=PRECHECK_TOTAL):", handler,
                      'the same limits as the check before the join')
        rows = lambda sql, params=(): [{'username': 'anna'}] if params == ('anna',) else []
        with mock.patch.object(self.efactl, 'PASSWORD_FILE', self.etc + '/none'), mock.patch.object(self.efactl, '_admin_query', rows):
            self.assertEqual(self.efactl.cluster_user_exists(types.SimpleNamespace(name='anna')), {'exists': True})
            self.assertEqual(self.efactl.cluster_user_exists(types.SimpleNamespace(name='%')), {'exists': False})

    def test_logins_of_the_node_in_the_preview_without_secrets(self):
        rows = lambda sql, params=(): [{'username': 'local-admin', 'password': '$6$x', 'totp': 'JBSW'}]
        identity = lambda name, allow_disabled=False: {'role': 'super', 'password': '$6$x'}
        with mock.patch.object(self.efactl, 'PASSWORD_FILE', self.etc + '/none'), mock.patch.object(self.efactl, '_admin_query', rows), \
                mock.patch.object(self.efactl, '_load_identity', identity):
            preview = self.efactl.join_preview_of({'files': [], 'unchanged_files': 0, 'postconf': [], 'units': {}, 'tables': ['t']}, 'node-b',
                                                  postconf_now={}, active=lambda unit: False)
        self.assertEqual(preview['accounts_replaced'], [{'name': 'local-admin', 'role': 'super'}])
        self.assertNotIn('$6$', json.dumps(preview))
        self.assertNotIn('JBSW', json.dumps(preview))
        self.assertIn('efactl admin-password', preview['logins'], 'the way back in')

    def test_tick_box_checked_by_efactl(self):
        with self.assertRaises(self.efactl.EfaError) as caught:
            self.efactl.cluster_activate(types.SimpleNamespace(confirm='yes', understood=''))
        self.assertIn('logins are taken over', str(caught.exception))
        with self.assertRaises(self.efactl.EfaError):
            self.efactl.cluster_init(types.SimpleNamespace(name='node-b', mode='ha', confirm=''))


class Hashes(unittest.TestCase):
    def test_node_sends_its_own_hashes_inside_etc_only(self):
        efactl = load_efactl()
        etc = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, etc, True)
        os.makedirs(etc + '/eFa')
        with open(etc + '/eFa/a.json', 'w') as f:
            f.write('{}')
        sent = efactl.join_hashes({'files': ['eFa/a.json', '../../etc/shadow', 'eFa/missing'], 'postconf': ['relayhost']}, etc=etc,
                                  postconf_now={'relayhost': '[smtp.example.org]'})
        self.assertEqual(sorted(sent['files']), ['eFa/a.json'], 'never a path outside, missing ones are new')
        self.assertEqual(sorted(sent['postconf']), ['relayhost'])
