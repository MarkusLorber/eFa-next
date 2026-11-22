# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""PCI DSS 8.2.8, NIST SP 800-53 AC-11: the idle timeout of the admin interface (efactl admin-idle-set). Only fixed values,
only a super admin; longer is weaker and asks the password again (and four eyes while on), shorter asks nothing. efa-web
reads the file again when it changed, and a shorter timeout also ends sessions already open; the portal stays at 60."""
import argparse
import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from test_bec_page import load_web
from test_cluster_sync_2fa import load_efactl


class AdminIdleCommand(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.file = os.path.join(self.folder, 'admin-idle.json')
        self.audited, self.reauth = [], []
        patches = {'ADMIN_IDLE_FILE': self.file, '_audit': self.audited.append, '_reauth': self.reauth.append,
                   'identity_now': {'username': 'boss', 'role': 'super'}, 'STATE_LOCK': os.path.join(self.folder, 'lock')}
        for name, value in patches.items():
            patcher = mock.patch.object(self.efactl, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_set(self, minutes):
        return self.efactl.admin_idle_set(argparse.Namespace(minutes=minutes))

    def test_default_and_clamp(self):
        self.assertEqual(self.efactl.admin_idle_minutes(), 60, 'no file: nothing changes on upgrade')
        for stored, seen in ((3, 5), (900, 60), ('15', 60), (True, 60), (30, 30)):
            with open(self.file, 'w') as f:
                json.dump({'minutes': stored}, f)
            self.assertEqual(self.efactl.admin_idle_minutes(), seen, stored)

    def test_shorter_needs_no_reauth_longer_does(self):
        result = self.run_set('15')
        self.assertEqual((result['minutes'], result['old_minutes'], result['at_most_15']), (15, 60, True))
        self.assertEqual(self.reauth, [], 'shorter is stronger: no re-auth')
        self.assertIn('admin interface idle timeout 60 -> 15 minutes by', self.audited[-1])
        self.run_set('30')
        self.assertEqual(self.reauth, ['boss'], 'longer is weaker: the password again')
        self.assertEqual(self.efactl.admin_idle_status(None)['minutes'], 30)
        with mock.patch.dict(os.environ, {'EFA_FOUR_EYES': 'abc'}):
            self.run_set('60')
        self.assertEqual(self.reauth, ['boss'], 'the run a second admin confirmed asks nobody again')

    def test_refusals(self):
        for value in ('0', '20', '61', '-5', 'x', '', '15; rm'):
            with self.assertRaises(self.efactl.EfaError, msg=value):
                self.run_set(value)
        with mock.patch.object(self.efactl, 'identity_now', {'username': 'ta', 'role': 'tenant'}):
            with self.assertRaises(self.efactl.EfaError):
                self.run_set('15')
        self.assertFalse(os.path.exists(self.file), 'nothing written')

    def test_four_eyes_only_when_longer(self):
        efactl = self.efactl
        self.assertIn('admin-idle-set', efactl.FOUR_EYES_COMMANDS)
        only_if = efactl.FOUR_EYES_ONLY_IF['admin-idle-set']
        self.run_set('15')
        self.assertTrue(only_if(argparse.Namespace(minutes='30')) and not only_if(argparse.Namespace(minutes='10')))
        state = {'all': True, 'tenants': [], 'super': {'on': False, 'consent': []}}
        boss = {'username': 'boss', 'role': 'super', 'tenant_id': None}
        with mock.patch.object(efactl, '_main_admin_id', lambda identity: None):
            self.assertFalse(efactl.four_eyes_needed('admin-idle-set', {**boss, 'role': 'tenant'}, state, argparse.Namespace(minutes='10')))
            self.assertTrue(efactl.four_eyes_needed('admin-idle-set', {**boss, 'role': 'tenant'}, state, argparse.Namespace(minutes='60')),
                            'the re-auth fields do not keep it out of four eyes')
            self.assertFalse(efactl.four_eyes_needed('password-change', {**boss, 'role': 'tenant'}, {**state}, None),
                             'a command with a real secret stays out')

    def test_cluster_wide_and_readable_by_the_web(self):
        efactl = self.efactl
        self.assertTrue(efactl.cluster_replicated('admin-idle-set'), 'one value for the whole cluster')
        self.assertFalse(efactl.cluster_replicated('admin-idle-status'))
        self.assertNotIn('admin-idle.json', efactl.SNAP_SKIP_EFA)
        self.assertEqual(efactl.CONF_READERS['admin-idle.json'], 'efa-conf')
        self.assertEqual(efactl.COMMAND_PERMISSIONS['admin-idle-set'], 'settings.edit')

    def test_hardening_check(self):
        rows = {row['title']: row for row in self.efactl.hardening_checks({**self.facts(), 'admin_idle': 30})}
        row = rows['Admin sessions end after at most 15 minutes idle']
        self.assertEqual((row['result'], row['detail']), ('fail', '30 minutes'))
        self.assertIn('PCI DSS 8.2.8', row['reference'])

    def facts(self):
        # The facts of the self-test of efactl, all passing.
        return {'admin_idle': 15, 'admin_2fa': (True, 'x'), 'login_banner': True, 'fs_encrypted': (True, 'x'), 'tls25': (0, 0), 'restore_test': (True, 'x'), 'fim': (True, 'x'), 'selinux': 'Enforcing', 'firewall': True, 'auditd': True, 'time': True, 'os_updates': True, 'os_updates_detail': '',
                'sshd': {'permitrootlogin': 'no', 'permitemptypasswords': 'no', 'x11forwarding': 'no', 'maxauthtries': '4'}, 'encrypt_method': 'SHA512',
                'shadow_mode': 0, 'sysctl': {}, 'audit_anchor': (None, ''),
                'postconf': {name: '' for name in ('smtpd_tls_protocols', 'smtpd_tls_mandatory_protocols', 'smtp_tls_protocols', 'smtpd_tls_auth_only')},
                'cipher_problems': [], 'pam_587': False, 'dnssec': True, 'dane': True, 'domains': 0, 'mta_sts': False, 'mta_sts_count': 0, 'tls_rpt': True,
                'certificate_ok': True, 'certificate_detail': '', 'cert_keys': {'web': ('ec', 256)}, 'dkim_rsa_bits': [], 'ssh_rsa_bits': None,
                'pqc': True, 'openssl': '', 'auto_profiles': [], 'nginx_tls12': True}


class AdminIdleWeb(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.web.ADMIN_IDLE_FILE = os.path.join(self.folder, 'admin-idle.json')
        self.web.admin_idle_cache.update(mtime=None, seconds=3600)
        self.web.efactl = lambda *args, **kwargs: (True, {'active': True}) if args[0] == 'session-check' else (True, {})

    def write(self, minutes, stamp):
        with open(self.web.ADMIN_IDLE_FILE, 'w') as f:
            json.dump({'minutes': minutes}, f)
        os.utime(self.web.ADMIN_IDLE_FILE, (stamp, stamp))

    def test_reads_again_when_changed(self):
        self.assertEqual(self.web.session_idle(), 3600, 'no file: 60 minutes')
        self.write(15, 1000)
        self.assertEqual(self.web.session_idle(), 900)
        self.write(2, 2000)
        self.assertEqual(self.web.session_idle(), 300, 'never below 5 minutes')
        with open(self.web.ADMIN_IDLE_FILE, 'w') as f:
            f.write('{broken')
        os.utime(self.web.ADMIN_IDLE_FILE, (3000, 3000))
        self.assertEqual(self.web.session_idle(), 300, 'unreadable for a moment: the last value stays')

    def test_shorter_ends_open_sessions(self):
        client = self.web.app.test_client()
        with client.session_transaction(**self.https) as sess:
            sess.update(admin=True, csrf='token', sid='idle', lang='en')
        now = time.time()
        self.web.active_sessions['idle'] = now + 3000  # opened under the old 60 minutes
        self.web.session_checked['idle'] = now
        self.web.session_seen['idle'] = now - 20 * 60  # idle for 20 minutes
        with self.web.app.test_request_context('/', **self.https):
            from flask import session
            session.update(admin=True, sid='idle')
            self.assertTrue(self.web.session_active(), '60 minutes: still on')
            self.web.session_seen['idle'] = now - 20 * 60
            self.write(15, now)
            self.assertFalse(self.web.session_active(), '15 minutes now: out')

    def test_portal_keeps_60(self):
        self.write(5, 4000)
        with mock.patch.object(self.web, 'PORTAL', True):
            self.assertEqual(self.web.session_idle(), 3600)


if __name__ == '__main__':
    unittest.main()
