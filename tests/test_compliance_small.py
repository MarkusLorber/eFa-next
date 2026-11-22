# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-19, compliance work packages 2 to 6: admin idle 15 minutes on new installs (upgrades keep theirs), the mail log
of PCI DSS and HIPAA (efa_setup self-test), the CIS 1.9 check with the update policy of eFa-next, BSI TR-03116-4 complete
(session lifetime, no 0-RTT, TLS 1.3, certificate keys), and the login banner of NIST SP 800-53 AC-8 (off by default)."""
import argparse
import json
import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

from test_cluster_sync_2fa import load_efactl

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Small(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def test_idle_15_on_new_installs_only(self):
        with open(os.path.join(TOP, 'next', 'usr', 'lib', 'eFa', 'setup', 'efa-next-setup'), encoding='utf-8') as f:
            text = f.read()
        fresh, upgrade = text.split('\nupgrade)', 1)
        self.assertIn('efactl admin-idle-set --minutes 15', fresh.split('\nfirst-install)', 1)[1])
        self.assertNotIn('admin-idle-set', upgrade, 'an upgrade keeps its value')

    def test_cis_19_takes_the_update_policy(self):
        e = self.efactl
        self.assertTrue(e.os_updates_automatic('enabled', 'off'))
        self.assertTrue(e.os_updates_automatic('not enabled', 'security') and e.os_updates_automatic('unknown', 'all'))
        self.assertFalse(e.os_updates_automatic('not enabled', 'off') or e.os_updates_automatic('not enabled', ''))

    def test_tr_03116_4(self):
        e = self.efactl
        self.assertEqual([e.tls_seconds(t) for t in ('300', '5m', '3600s', '1h', '2d', 'x')], [300, 300, 3600, 3600, 172800, None])
        data = json.load(open(os.path.join(TOP, 'next', 'usr', 'share', 'eFa', 'standards.json'), encoding='utf-8'))
        kinds = {rule['kind'] for rule in data['standards']['bsi-03116-4']['rules']}
        self.assertTrue({'tls_min', 'ciphers12', 'groups_required', 'tls13', 'session_max', 'no_early_data', 'cert_key'} <= kinds)
        rule = {'kind': 'session_max', 'services': ['web', 'mail'], 'hours': 48, 'why': ''}
        good = {'versions': {}, 'session_seconds': {'web': 300, 'mail': 3600}}
        self.assertEqual({row[1] for row in e._std_rule(rule, good, {})}, {'fulfilled'})
        self.assertEqual([row[1] for row in e._std_rule(rule, {'versions': {}, 'session_seconds': {'web': 3 * 86400, 'mail': 3600}}, {})][0], 'not')
        self.assertEqual(e._std_rule({'kind': 'no_early_data', 'why': ''}, {'versions': {}, 'early_data': True}, {})[0][1], 'not')
        self.assertEqual(e._std_rule({'kind': 'no_early_data', 'why': ''}, {'versions': {}, 'early_data': False}, {})[0][1], 'fulfilled')


class LoginBanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.reloads, self.audited = [], []
        with open(os.path.join(self.folder, 'issue.net'), 'w') as f:
            f.write('\\S\nKernel \\r on an \\m\n')
        patches = {'LOGIN_BANNER_FILE': os.path.join(self.folder, 'login-banner.json'), 'ISSUE_NET': os.path.join(self.folder, 'issue.net'),
                   'BANNER_SSHD': os.path.join(self.folder, 'sshd', '45-efa-banner.conf'), 'STATE_LOCK': os.path.join(self.folder, 'lock'),
                   '_sshd_apply': lambda: self.reloads.append(1), '_audit': self.audited.append, 'identity_now': None}
        for name, value in patches.items():
            patcher = mock.patch.object(self.efactl, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_set(self, text, ssh=''):
        return self.efactl.login_banner_set(argparse.Namespace(text=text, ssh=ssh))

    def test_off_by_default_web_and_ssh_and_back(self):
        e = self.efactl
        self.assertEqual(e.login_banner_status(None), {'text': '', 'web': False, 'ssh': False})
        self.assertEqual(self.run_set('Authorised use only.\nAll access is logged.'), {'text': 'Authorised use only.\nAll access is logged.', 'web': True, 'ssh': False})
        self.assertFalse(os.path.exists(e.BANNER_SSHD) or self.reloads, 'SSH only when asked')
        self.run_set('Authorised use only.', ssh='on')
        self.assertEqual(open(e.ISSUE_NET).read(), 'Authorised use only.\n')
        self.assertIn('Banner /etc/issue.net', open(e.BANNER_SSHD).read())
        self.assertEqual(len(self.reloads), 1)
        self.run_set('Authorised use only.', ssh='on')
        self.assertEqual(len(self.reloads), 1, 'sshd only reloads on a change')
        self.run_set('')
        self.assertFalse(os.path.exists(e.BANNER_SSHD), 'empty text: no banner anywhere')
        self.assertIn('Kernel', open(e.ISSUE_NET).read(), 'the original issue.net is back')

    def test_refusals(self):
        e = self.efactl
        for text in ('x' * 1001, 'bell\x07', 'esc\x1b[31m'):
            with self.assertRaises(e.EfaError):
                self.run_set(text)
        with mock.patch.object(e, 'identity_now', {'role': 'admin'}):
            with self.assertRaises(e.EfaError):
                self.run_set('text')
        self.assertFalse(os.path.exists(e.LOGIN_BANNER_FILE))

    def test_web_shows_it_escaped_admin_only(self):
        from test_bec_page import load_web
        web = load_web()
        web.LOGIN_BANNER_FILE = os.path.join(self.folder, 'login-banner.json')
        with open(web.LOGIN_BANNER_FILE, 'w') as f:
            json.dump({'text': 'Only <b>authorised</b>\nuse'}, f)
        web.efactl = lambda *args, **kwargs: (True, {})
        page = web.app.test_client().get('/login', base_url='https://localhost').get_data(as_text=True)
        self.assertIn('Only &lt;b&gt;authorised&lt;/b&gt;<br>use<br>', page)
        self.assertFalse(re.search(r'<b>authorised', page))
        with mock.patch.object(web, 'PORTAL', True):
            self.assertEqual(web.login_banner(), '', 'the user portal has none')


if __name__ == '__main__':
    unittest.main()
