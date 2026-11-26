# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""An admin of single sign-on confirms a critical change with a new login at its provider (Hans 2026-11-22, 6.0.0.7): the
login asks for prompt=login and max_age=0, the answer counts only with a new auth_time of the same account, and the session
gets the five minutes of a password confirmation only through a signed proof bound to it."""
import re
import time
import unittest
import urllib.parse
from unittest import mock

from test_bec_page import load_web
from test_cluster_sync_2fa import load_efactl


class StepUpCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def test_auth_time_and_account(self):
        e = self.efactl
        now = int(time.time())
        e.oidc_stepup_check({'auth_time': now}, now - 5, 'anna', 'anna')
        for claims, expected, bound in (({}, 'anna', 'anna'), ({'auth_time': now - 3600}, 'anna', 'anna'), ({'auth_time': True}, 'anna', 'anna'),
                                        ({'auth_time': now}, 'anna', 'bert'), ({'auth_time': now}, '', '')):
            with self.assertRaises(e.EfaError, msg=(claims, expected, bound)):
                e.oidc_stepup_check(claims, now - 5, expected, bound)

    def test_start_asks_for_a_new_login(self):
        e = self.efactl
        state = {'oidc': True, 'client_id': 'efa', 'issuer': 'https://idp.example'}
        provider = {'authorization_endpoint': 'https://idp.example/auth'}
        with mock.patch.object(e, '_json_read', lambda path, default: state), mock.patch.object(e, '_oidc_provider', lambda st: provider), \
                mock.patch.object(e, 'oidc_redirect', lambda st, portal: 'https://mx.example/login/oidc/callback'):
            plain = e.oidc_start(e.argparse.Namespace(domain='', portal='', tenant='', stepup=''))
            stepup = e.oidc_start(e.argparse.Namespace(domain='', portal='', tenant='', stepup='yes'))
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(stepup['url']).query)
        self.assertEqual((query['prompt'], query['max_age']), (['login'], ['0']))
        self.assertNotIn('max_age', plain['url'])
        self.assertLessEqual(abs(stepup['started'] - time.time()), 2)


class StepUpWeb(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        self.calls, self.answers = [], {}

        def fake(*args, secrets_in=None, who=None):
            self.calls.append(list(args))
            if args[0] == 'session-check':
                return True, {'active': True}
            return self.answers.get(args[0], (True, {}))
        self.web.efactl = fake
        self.web.efactl_read = fake

    def client(self, user='anna'):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid='sso-sid', user=user, role='super', sso=True, sso_tenant='')
        self.web.active_sessions['sso-sid'] = time.time() + 600
        self.web.session_checked['sso-sid'] = time.time()
        return client

    def round_trip(self, client, username):
        self.answers['oidc-start'] = (True, {'url': 'https://idp.example/auth?x=1', 'state': 'st', 'nonce': 'no', 'verifier': 've', 'tenant': '', 'started': 100})
        start = client.get('/login/oidc?stepup=1&back=/p/sec', **self.https)
        self.assertEqual(start.status_code, 302)
        self.assertIn(['oidc-start', '--tenant=', '--stepup=yes'], self.calls)
        self.answers['oidc-finish'] = (True, {'stepup': True, 'username': username})
        back = client.get('/login/oidc/callback?code=c&state=st', **self.https)
        finish = next(call for call in self.calls if call[0] == 'oidc-finish')
        self.assertIn('--stepup=yes', finish)
        self.assertIn('--expect=anna', finish, 'the account of the session, never one the browser names')
        self.assertIn('--started=100', finish)
        url = re.search(r'url=([^"]+)"', back.get_data(as_text=True)).group(1).replace('&amp;', '&')
        return client.get(url, **self.https)

    def test_the_same_account_gets_five_minutes(self):
        client = self.client()
        done = self.round_trip(client, 'anna')
        self.assertEqual((done.status_code, done.headers['Location'].endswith('/p/sec')), (302, True))
        with client.session_transaction(**self.https) as sess:
            self.assertLess(time.time() - sess['reauth'], 5)

    def test_another_account_gets_nothing(self):
        client = self.client()
        self.round_trip(client, 'bert')
        with client.session_transaction(**self.https) as sess:
            self.assertNotIn('reauth', sess)

    def test_a_proof_counts_for_its_session_only(self):
        client = self.client()
        proof = self.web.oidc_signer().dumps(['confirmed', 'anna', 'not-this-session', '/p/sec', time.time()])
        client.get('/login/oidc/confirmed?proof=' + urllib.parse.quote(proof), **self.https)
        with client.session_transaction(**self.https) as sess:
            self.assertNotIn('reauth', sess)

    def test_reauth_of_sso_asks_the_provider(self):
        with self.web.app.test_request_context('/run/user-set'):
            self.web.session.update(sso=True, user='anna', sid='x')
            self.assertFalse(self.web.reauth_ok({'reauth': 'a password'}))
            self.assertEqual(self.web.g.reauth_error, self.web.SSO_STEPUP_TEXT)
            self.assertNotIn(['user-verify'], [call[:1] for call in self.calls], 'no password check for a login of single sign-on')


if __name__ == '__main__':
    unittest.main()
