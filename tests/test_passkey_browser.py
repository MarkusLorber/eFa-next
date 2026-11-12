# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""5s: passkeys in a real browser. Chromium (Playwright) with its virtual authenticator (the WebAuthn domain of the DevTools
protocol, the one the WebAuthn test suite of the W3C uses) makes a real credential and signs real assertions; the page runs the
passkey script of efa-web unchanged, and efactl's passkey-register-options, passkey-register, passkey-login-options and
passkey-login check them with efa_webauthn. Between browser and efactl there is a small HTTPS server in this test in place of
efa-web (the same form fields and addresses); the database table user_passkeys is a list in memory.

A host with a real certificate is not needed: the origin is https://localhost:PORT. The CI host has no certificate a
browser trusts, so passkey-set cannot be switched on there; this test is the way the browser part is checked.

Skipped without playwright; the CI runs it with the Python of the live-test venv and EFA_CI_PASSKEY_BROWSER=yes, then it fails
when playwright or the browser is missing."""

import argparse
import http.server
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import unittest
import urllib.parse
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# The venv of Playwright has only Playwright: efactl takes cryptography and the other packages of the system (python3-*
# from the repositories). Their folders come last, so the packages of the venv keep the lead; nothing is installed.
if sys.prefix != sys.base_prefix:
    import sysconfig
    for scheme_key in ('purelib', 'platlib'):
        system_dir = sysconfig.get_path(scheme_key, vars={'base': sys.base_prefix, 'platbase': sys.base_prefix})
        if system_dir and os.path.isdir(system_dir) and system_dir not in sys.path:
            sys.path.append(system_dir)
import test_write_commands as writes  # noqa: E402

efactl, EfaError = writes.efactl, writes.EfaError
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None
REQUIRED = os.environ.get('EFA_CI_PASSKEY_BROWSER') == 'yes'
BROWSER = os.environ.get('EFA_LIVE_BROWSER') or None
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')


def passkey_js():
    """The script exactly as efa-web.py serves it (the Python string, read without starting the web application)."""
    with open(os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-web.py')) as f:
        source = f.read()
    found = re.search(r'^PASSKEY_JS = (""".*?""")$', source, re.S | re.M)
    return eval(found.group(1), {})  # a string literal of our own source, nothing else


PAGE = '''<!doctype html><html><head><meta charset="utf-8"><title>{title}</title></head><body>
<form method="post" action="{action}"><input type="hidden" name="csrf" value="token-1">{fields}
<div class="btns"><button class="p">Log in</button>{button}</div>
<p class="err" id="passkey-error" hidden>The passkey did not work.</p></form><p id="result">{result}</p>
<script src="/passkey.js"></script></body></html>'''
LOGIN_FIELDS = '<input name="username" value="{username}"><input name="password" type="password"><input type="hidden" name="assertion">'
REGISTER_FIELDS = '<input name="name" value="laptop"><input type="hidden" name="attestation"><input type="hidden" name="client_data">'


class PasskeyDb:
    """The table user_passkeys and the column users.disabled, for the statements of the passkey commands."""

    def __init__(self):
        self.rows, self.disabled = [], {}

    def __call__(self, sql, params=(), *args, **kwargs):
        sql = ' '.join(sql.split())
        if sql.startswith('INSERT INTO user_passkeys'):
            username, cred_id, alg, pem, count, name, aaguid = params
            self.rows.append({'id': len(self.rows) + 1, 'username': username, 'cred_id': cred_id, 'alg': alg, 'pem': pem,
                              'sign_count': count, 'name': name, 'aaguid': aaguid, 'created': 'now', 'last_used': None})
            return []
        if sql.startswith('SELECT cred_id FROM user_passkeys WHERE username'):
            return [{'cred_id': row['cred_id']} for row in self.rows if row['username'] == params[0]]
        if sql.startswith('SELECT id, username, alg, pem, sign_count FROM user_passkeys WHERE cred_id'):
            return [dict(row) for row in self.rows if row['cred_id'] == params[0]]
        if sql.startswith('UPDATE user_passkeys SET sign_count'):
            for row in self.rows:
                if row['id'] == params[1]:
                    row['sign_count'], row['last_used'] = params[0], 'now'
            return []
        if sql.startswith('SELECT id, name, alg, aaguid'):
            return [{key: row[key] for key in ('id', 'name', 'alg', 'aaguid', 'created', 'last_used')} for row in self.rows if row['username'] == params[0]]
        if sql.startswith('SELECT disabled FROM users'):
            return [{'disabled': self.disabled.get(params[0], 0)}]
        if sql.startswith('UPDATE users SET last_login'):
            return []
        raise AssertionError('unexpected statement: ' + sql)


def make_certificate(folder):
    """A certificate for localhost (EC P-256, one day) by the openssl of the system: the venv of Playwright has no cryptography,
    and nothing is installed into it."""
    cert, key = folder + '/cert.pem', folder + '/key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', key, '-out', cert],
                   check=True, capture_output=True)
    for path in (cert, key):
        os.chmod(path, 0o600)
    return cert, key


class Web(http.server.BaseHTTPRequestHandler):
    """efa-web in small: the login page, the page of a new passkey, the two option addresses; each calls the efactl command."""
    test = None

    def log_message(self, *args):
        pass

    def send(self, status, body, kind='text/html'):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def form(self):
        data = self.rfile.read(int(self.headers.get('Content-Length') or 0)).decode()
        return dict(urllib.parse.parse_qsl(data, keep_blank_values=True))

    def page(self, action, result=''):
        if action == '/register':
            fields, button = REGISTER_FIELDS, '<button type="button" id="passkey-add" hidden>Make the passkey now</button>'
        else:
            fields = LOGIN_FIELDS.format(username=self.test.login_name)
            button = '<button type="button" id="passkey-login" hidden>Use a passkey</button>'
        return PAGE.format(title=action, action=action, fields=fields, button=button, result=result)

    def do_GET(self):
        if self.path == '/passkey.js':
            return self.send(200, passkey_js(), 'text/javascript')
        if self.path in ('/login', '/register'):
            return self.send(200, self.page(self.path))
        self.send(404, 'not found')

    def call(self, function, args):
        try:
            return True, function(args)
        except EfaError as err:
            return False, {'error': str(err)}

    def do_POST(self):
        form = self.form()
        if form.get('csrf') != 'token-1':
            return self.send(400, 'csrf')
        if self.path == '/passkey/options':
            ok, out = self.call(efactl.passkey_login_options, argparse.Namespace(username=form.get('username', '')))
            return self.send(200 if ok else 400, json.dumps(out), 'application/json')
        if self.path == '/passkey/register-options':
            ok, out = self.call(efactl.passkey_register_options, argparse.Namespace())
            return self.send(200 if ok else 400, json.dumps(out), 'application/json')
        if self.path == '/register':
            ok, out = self.call(efactl.passkey_register, argparse.Namespace(name=form.get('name'), attestation=form.get('attestation'),
                                                                            client_data=form.get('client_data')))
            self.test.answers.append(('register', ok, out))
            return self.send(200, self.page('/register', 'registered' if ok else 'refused: ' + out['error']))
        if self.path == '/login':
            self.test.sent.append(form.get('assertion', ''))
            if self.test.hold:
                return self.send(200, self.page('/login', 'held'))
            with mock.patch.object(efactl, '_secrets', lambda count, prompt: [form.get('assertion', '')]):
                ok, out = self.call(efactl.passkey_login, None)
            self.test.answers.append(('login', ok, out))
            return self.send(200, self.page('/login', f"logged in as {out['username']}" if ok else 'refused: ' + out['error']))
        self.send(404, 'not found')


@unittest.skipIf(sync_playwright is None and not REQUIRED, 'playwright is missing')
class PasskeyBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            raise AssertionError('EFA_CI_PASSKEY_BROWSER=yes but playwright is missing (see live_test.sh for the venv)')
        cls.harness = writes.WriteCommandTests('test_every_listed_command_is_covered')
        cls.harness.setUp()
        cert, key = make_certificate(cls.harness.tmp)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        Web.test = cls
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Web)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_address[1]
        cls.base = f'https://localhost:{cls.port}'
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(executable_path=BROWSER, args=['--ignore-certificate-errors', '--host-resolver-rules=MAP localhost 127.0.0.1'])

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.harness.tearDown()

    def setUp(self):
        type(self).answers, type(self).sent, type(self).login_name, type(self).hold = [], [], 'anna', False
        self.db = PasskeyDb()
        self.user = {'username': 'anna', 'role': 'super'}
        self.patches = [mock.patch.object(efactl, '_admin_query', self.db), mock.patch.object(efactl, '_totp_self', lambda: self.user['username']),
                        mock.patch.object(efactl, '_load_identity', lambda name, **k: dict(self.user, username=name)),
                        mock.patch.object(efactl, '_audit', lambda text: None),
                        # The origin of this test has a port; on a host it is https://<the host name of the passkeys>.
                        mock.patch.object(efactl, '_passkey_rp', lambda: ('localhost', self.base))]
        for patch in self.patches:
            patch.start()
        efactl._json_write(efactl.PASSKEY_FILE, {'rp_id': 'localhost', 'policy': {'super': 'passwordless'}})
        self.context = self.browser.new_context(ignore_https_errors=True)
        self.page = self.context.new_page()
        self.cdp = self.context.new_cdp_session(self.page)
        self.cdp.send('WebAuthn.enable')
        self.authenticator = self.add_authenticator()

    def tearDown(self):
        self.context.close()
        for patch in reversed(self.patches):
            patch.stop()

    def add_authenticator(self, verified=True):
        return self.cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {
            'protocol': 'ctap2', 'transport': 'internal', 'hasResidentKey': True, 'hasUserVerification': True,
            'isUserVerified': verified, 'automaticPresenceSimulation': True}})['authenticatorId']

    def press(self, path, button):
        self.page.goto(self.base + path)
        self.page.wait_for_selector(f'#{button}:not([hidden])', timeout=10000)
        with self.page.expect_navigation(timeout=15000):
            self.page.click(f'#{button}')
        return self.page.inner_text('#result')

    def register(self):
        result = self.press('/register', 'passkey-add')
        self.assertEqual(result, 'registered', self.answers)
        return self.db.rows[-1]

    def test_register_and_log_in_without_password(self):
        row = self.register()
        self.assertEqual((row['username'], row['name'], row['alg']), ('anna', 'laptop', 'ES256'))
        stored = self.cdp.send('WebAuthn.getCredentials', {'authenticatorId': self.authenticator})['credentials']
        self.assertEqual(len(stored), 1)
        self.assertTrue(stored[0]['isResidentCredential'])
        self.assertEqual(self.press('/login', 'passkey-login'), 'logged in as anna')
        first = self.db.rows[0]['sign_count']
        self.assertGreater(first, 0)
        # Without a user name: the browser chooses the discoverable credential, user verification is required.
        type(self).login_name = ''
        self.assertEqual(self.press('/login', 'passkey-login'), 'logged in as anna')
        self.assertGreater(self.db.rows[0]['sign_count'], first)

    def test_second_key_is_not_taken_twice(self):
        self.register()
        # The same authenticator again: excludeCredentials makes the browser refuse, the page shows the error.
        self.page.goto(self.base + '/register')
        self.page.wait_for_selector('#passkey-add:not([hidden])')
        self.page.click('#passkey-add')
        self.page.wait_for_selector('#passkey-error:not([hidden])', timeout=15000)
        self.assertEqual(len(self.db.rows), 1)

    def test_refusals(self):
        self.register()
        # A role without passwordless login: the signature is right, the role is not.
        efactl._json_write(efactl.PASSKEY_FILE, {'rp_id': 'localhost', 'policy': {'super': 'second'}})
        self.assertIn('refused: Your role logs in with password', self.press('/login', 'passkey-login'))
        efactl._json_write(efactl.PASSKEY_FILE, {'rp_id': 'localhost', 'policy': {'super': 'passwordless'}})
        # A disabled user.
        self.db.disabled['anna'] = 1
        self.assertIn('refused: This user is disabled', self.press('/login', 'passkey-login'))
        self.db.disabled['anna'] = 0
        # A copied key: the stored counter is ahead of the authenticator.
        self.db.rows[0]['sign_count'] = 10 ** 6
        self.assertIn('refused: Passkey not accepted', self.press('/login', 'passkey-login'))

    def fresh_answer(self):
        """A real answer of the browser to a new challenge, held back by the page instead of being sent to efactl."""
        type(self).hold = True
        self.assertEqual(self.press('/login', 'passkey-login'), 'held')
        type(self).hold = False
        return json.loads(self.sent[-1])

    def login_with(self, data):
        with mock.patch.object(efactl, '_secrets', lambda count, prompt: [json.dumps(data)]):
            return efactl.passkey_login(None)

    def test_replay_and_foreign_answers(self):
        """Each check on its own, on a fresh real answer with one thing changed. (Chromium keeps waiting instead of failing when
        no key of the allowed list is there, so these cases change a real answer.)"""
        self.register()
        data = self.fresh_answer()
        self.assertEqual(self.login_with(data)['username'], 'anna')
        self.assertRaisesRegex(EfaError, 'Passkey not accepted', self.login_with, data)
        # The handle of a fresh challenge, the answer to the old one.
        data = self.fresh_answer()
        data['handle'] = efactl.passkey_login_options(argparse.Namespace(username='anna'))['handle']
        self.assertRaisesRegex(EfaError, 'Passkey not accepted', self.login_with, data)
        for change in ({'id': 'AAAA'}, {'handle': 'unknown'}):
            with self.subTest(change=change):
                self.assertRaisesRegex(EfaError, 'Passkey not accepted', self.login_with, {**self.fresh_answer(), **change})
        # Another signature: one byte of the signature value of the DER sequence changed.
        data = self.fresh_answer()
        raw = bytearray(efactl._lib('efa_webauthn').unb64url(data['signature']))
        raw[-1] ^= 1
        self.assertRaisesRegex(EfaError, 'Passkey not accepted', self.login_with, {**data, 'signature': efactl._lib('efa_webauthn').b64url(bytes(raw))})
        # The second factor at user-verify (passkey_check with a user name): a key of anna never counts for bert.
        self.assertRaisesRegex(EfaError, 'Passkey not accepted', efactl.passkey_check, json.dumps(self.fresh_answer()), 'bert')
        self.assertEqual(efactl.passkey_check(json.dumps(self.fresh_answer()), 'anna'), 'anna')

    def test_passkeys_off(self):
        efactl._json_write(efactl.PASSKEY_FILE, {'rp_id': '', 'policy': {}})
        with mock.patch.object(efactl, '_passkey_rp', self.real_rp):
            self.page.goto(self.base + '/register')
            self.page.wait_for_selector('#passkey-add:not([hidden])')
            self.page.click('#passkey-add')
            self.page.wait_for_selector('#passkey-error:not([hidden])', timeout=15000)
        self.assertEqual(self.db.rows, [])

    def real_rp(self):
        rp_id = efactl.passkey_settings()['rp_id']
        if not rp_id:
            raise EfaError('Passkeys are off: a super admin chooses the host name first (passkey-set).')
        return rp_id, self.base


if __name__ == '__main__':
    unittest.main()
