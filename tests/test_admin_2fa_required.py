# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-19: every admin sets up 2FA (TOTP or a passkey) at the first login. A new install from the start, an upgrade
after a notice of 7 days; nobody is locked out (the setup comes right after the password, on every node of a cluster, and for
the console admin at the first SSH login); OIDC logins keep the factor of their provider; the user portal is unchanged; only
the dev flag of efa-init lifts it; a missing table or a broken file never means "no 2FA needed"."""
import argparse
import datetime
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from test_cluster_sync_2fa import load_efactl

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')


class AdminTwoFactor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.totp, self.keys, self.sources, self.audited = {}, {}, {}, []
        e = self.efactl
        patches = {'ADMIN_2FA_FILE': os.path.join(self.folder, 'admin-2fa.json'), 'STATE_LOCK': os.path.join(self.folder, 'lock'),
                   'admin_2fa_exempt': lambda: False, '_audit': self.audited.append,
                   '_totp_row': lambda user: self.totp.get(user), '_safe_keys': lambda user: self.keys.get(user, []),
                   '_admin_query': self.query, 'totp_policy': lambda: {}, 'setup_guided': lambda: False,
                   '_passkey_mode': lambda role: 'second', '_totp_reenroll': lambda user: False}
        for name, value in patches.items():
            patcher = mock.patch.object(e, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def query(self, sql, params=()):
        if sql.startswith('SELECT source FROM users'):
            source = self.sources.get(params[0])
            return [{'source': source}] if source is not None else []
        raise AssertionError(sql)

    def start(self, mode):
        return self.efactl.admin_2fa_heal(argparse.Namespace(mode=mode))

    def login(self, username, role, code=''):
        with mock.patch.object(self.efactl, 'totp_check', lambda user, given: True):
            return self.efactl._totp_gate({'username': username, 'role': role}, (code, ''))

    def test_fresh_install_requires_it_at_once(self):
        with mock.patch.object(self.efactl, '_cli_user', lambda: ''):
            found = self.start('first-install')
        self.assertEqual(found['from'], datetime.date.today().isoformat())
        for role in ('super', 'admin'):
            self.assertTrue(self.login('anna', role).get('totp_setup_needed'), role)
        self.assertNotIn('totp_setup_needed', self.login('mia@example.com', 'user'), 'the user portal is unchanged')
        self.assertTrue(self.efactl._totp_required('@admin', 'super'), 'the main admin too')

    def test_upgrade_requires_it_at_the_next_login(self):
        # Hans 2026-11-22: no days of notice; after an update every admin sets up 2FA at the next login.
        with mock.patch.object(self.efactl, '_cli_user', lambda: ''):
            found = self.start('upgrade')
        today = datetime.date.today()
        self.assertEqual(found['from'], today.isoformat())
        self.assertTrue(self.login('anna', 'admin').get('totp_setup_needed'), 'at the next login after the update')
        self.assertTrue(self.efactl.admin_2fa_due(today))
        with open(self.efactl.ADMIN_2FA_FILE, 'w') as f:
            f.write('{"from": "%s"}' % (today + datetime.timedelta(days=7)).isoformat())
        with mock.patch.object(self.efactl, '_cli_user', lambda: ''):
            self.start('upgrade')
        self.assertEqual(self.efactl.admin_2fa_from(), today, 'a day in the future of an earlier build comes back to today')
        earlier = today - datetime.timedelta(days=3)
        with open(self.efactl.ADMIN_2FA_FILE, 'w') as f:
            f.write('{"from": "%s"}' % earlier.isoformat())
        with mock.patch.object(self.efactl, '_cli_user', lambda: ''):
            self.start('upgrade')
        self.assertEqual(self.efactl.admin_2fa_from(), earlier, 'an earlier day stays')

    def test_break_glass_and_the_local_console_stay_outside(self):
        # The rule without notice (2026-11-22) must not reach the ways in of an emergency.
        import importlib.machinery
        import importlib.util
        import inspect
        self.assertNotIn('_totp', inspect.getsource(self.efactl.breakglass_login), 'break-glass keeps its one-time codes only')
        path = os.path.join(ROOT, 'next', 'usr', 'sbin', 'efa-console-2fa')
        loader = importlib.machinery.SourceFileLoader('efa_console_2fa_rule', path)
        gate = importlib.util.module_from_spec(importlib.util.spec_from_loader('efa_console_2fa_rule', loader))
        loader.exec_module(gate)
        started, asked = [], []
        with mock.patch.object(gate.os, 'execv', lambda shell, args: started.append(args)):
            gate.main(['-efa-console-2fa'], ask=lambda prompt: asked.append(prompt) or '', run=lambda *a, **k: self.fail('no check on tty'),
                      local=lambda: True, interactive=True)
        self.assertTrue(started and not asked, 'the local console asks for no code and starts the shell')

    def test_a_second_factor_of_either_kind_counts(self):
        with mock.patch.object(self.efactl, '_cli_user', lambda: ''):
            self.start('first-install')
        self.keys['anna'] = [{'id': 1}]
        with mock.patch.object(self.efactl, 'totp_check', lambda user, given: True),                 mock.patch.object(self.efactl, 'passkey_check', lambda assertion, user: True):
            found = self.efactl._totp_gate({'username': 'anna', 'role': 'admin'}, ('', '{"passkey": "answer"}'))
        self.assertNotIn('totp_setup_needed', found, 'a passkey counts')
        self.totp['ben'] = {'active': 1, 'secret': '', 'last_step': 0, 'recovery': '[]'}
        self.assertNotIn('totp_setup_needed', self.login('ben', 'admin', '123456'), 'an active TOTP counts')

    def test_every_confirmation_asks_the_code(self):
        """Hans 2026-11-22: the code of the 2FA app is no longer optional for an admin confirmation (strict), the portal unchanged."""
        e = self.efactl
        with self.assertRaises(e.EfaError) as caught:
            e.confirm_code_required('anna', 'admin')
        self.assertEqual(str(caught.exception), e.CONFIRM_SETUP, 'an admin without 2FA app sets one up first')
        self.keys['anna'] = [{'id': 1}]
        with self.assertRaises(e.EfaError):
            e.confirm_code_required('anna', 'admin')  # a passkey alone gives no code
        self.totp['ben'] = {'active': 1, 'secret': '', 'last_step': 0, 'recovery': '[]'}
        self.assertTrue(e.confirm_code_required('ben', 'super'))
        self.assertFalse(e.confirm_code_required('mia@example.com', 'user'), 'the user portal as before')
        self.sources['carla@example.com'] = 'oidc'
        self.assertFalse(e.confirm_code_required('carla@example.com', 'admin'), 'OIDC: the factor of the provider')
        with mock.patch.object(e, 'totp_check', lambda user, given: True):
            with self.assertRaises(e.EfaError) as caught:
                e._totp_gate({'username': 'ben', 'role': 'admin'}, ('', ''), strict=True)
            self.assertEqual(str(caught.exception), e.CONFIRM_CODE, 'no "if set up": the code is asked')
            self.assertEqual(e._totp_gate({'username': 'ben', 'role': 'admin'}, ('123456', ''), strict=True)['username'], 'ben')
            self.assertEqual(e._totp_gate({'username': 'mia@example.com', 'role': 'user'}, ('', ''), strict=True)['username'], 'mia@example.com')
        self.keys['ben'] = [{'id': 2}]
        with mock.patch.object(e, 'passkey_check', lambda assertion, user: True):
            with self.assertRaises(e.EfaError):
                e._totp_gate({'username': 'ben', 'role': 'admin'}, ('', '{"passkey": "answer"}'), strict=True)
        # The own login (My account): the code before the password is checked; the first 2FA app with the password only.
        with mock.patch.object(e, '_web_call', lambda: True), mock.patch.object(e, '_secrets', lambda n, prompt: ['secret', '']),                 mock.patch.object(e, 'identity_now', {'role': 'admin', 'username': 'ben'}):
            with self.assertRaises(e.EfaError) as caught:
                e._reauth('ben')
            self.assertEqual(str(caught.exception), e.CONFIRM_CODE)
            with self.assertRaises(e.EfaError) as caught:
                e._reauth('anna')
            self.assertEqual(str(caught.exception), e.CONFIRM_SETUP)
        with mock.patch.object(e, 'admin_2fa_exempt', lambda: True):
            self.assertFalse(e.confirm_code_required('anna', 'admin'), 'only the dev flag lifts it, as the rule of the login')

    def test_oidc_keeps_the_factor_of_its_provider(self):
        with mock.patch.object(self.efactl, '_cli_user', lambda: ''):
            self.start('first-install')
        self.sources['carla@example.com'] = 'oidc'
        self.sources['dirk'] = 'local'
        self.assertFalse(self.efactl._totp_required('carla@example.com', 'admin'))
        self.assertTrue(self.efactl._totp_required('dirk', 'admin'))

    def test_fail_closed(self):
        with open(self.efactl.ADMIN_2FA_FILE, 'w') as f:
            f.write('{broken')
        self.assertTrue(self.efactl.admin_2fa_due(), 'a broken file: the rule counts')
        os.remove(self.efactl.ADMIN_2FA_FILE)
        self.assertTrue(self.efactl.admin_2fa_due(), 'no file: the rule counts')

        def no_table(user):
            raise self.efactl.EfaError('2FA cannot be checked (table user_totp missing): login refused.')
        with mock.patch.object(self.efactl, '_totp_row', no_table):
            with self.assertRaises(self.efactl.EfaError):
                self.login('anna', 'admin')

    def test_only_the_dev_flag_lifts_it(self):
        with mock.patch.object(self.efactl, '_cli_user', lambda: ''):
            self.start('first-install')
        with mock.patch.object(self.efactl, 'admin_2fa_exempt', lambda: True):
            self.assertFalse(self.efactl._totp_required('anna', 'admin'))
            self.assertNotIn('totp_setup_needed', self.login('anna', 'admin'))
            rows = {row['title']: row for row in self.efactl.hardening_checks(self.facts())}
        self.assertEqual(rows['2FA required for every admin role']['result'], 'fail', 'a development host shows it as failed')
        flag = self.efactl._lib('efa_setup')
        self.assertTrue(flag.dev_flag_problem(os.path.join(self.folder, 'none')) == '', 'no flag: nothing lifted')

    def test_console_admin_sets_it_up_at_the_first_ssh_login(self):
        e = self.efactl
        with mock.patch.object(e, '_cli_user', lambda: ''):
            self.start('first-install')
        rows = {}
        with mock.patch.object(e, '_console_row', lambda user: rows.get(user)), \
                mock.patch.object(e, '_console_store', lambda user, row: rows.__setitem__(user, row)), \
                mock.patch.dict(os.environ, {'SUDO_USER': 'efaadmin'}), mock.patch.object(e, 'identity_now', None):
            self.assertEqual(e.console_2fa_verify(argparse.Namespace(check='yes')), {'needed': False, 'enroll': True})
            with self.assertRaises(e.EfaError, msg='no shell before the setup'):
                e.console_2fa_verify(argparse.Namespace(check=''))
            started = e.console_2fa_enroll(argparse.Namespace(code='', first='yes'))
            self.assertIn('uri', started)
            rows['efaadmin']['active'] = True
            with self.assertRaises(e.EfaError, msg='the login shell never replaces an active 2FA'):
                e.console_2fa_enroll(argparse.Namespace(code='', first='yes'))
            self.assertEqual(e.console_2fa_verify(argparse.Namespace(check='yes')), {'needed': True, 'enroll': False})
        with mock.patch.object(e, 'identity_now', None):
            with self.assertRaises(e.EfaError):
                e.console_2fa_set(argparse.Namespace(mode='off'))

    def test_cluster_nobody_locked_out(self):
        """Master and node: the setup is reached after the password on both; on a client in master/client mode the setup of the
        web login is refused with the name of the master (where it is set up, the row reaches the node); the console admin is of
        its host and set up there."""
        e = self.efactl
        with mock.patch.object(e, '_cli_user', lambda: ''):
            self.start('upgrade')
        with mock.patch.object(e, 'admin_2fa_due', lambda when=None: True):
            for host in ('master', 'node'):
                for user, role in (('@admin', 'super'), ('anna', 'admin')):
                    if user == '@admin':
                        self.assertTrue(e._totp_required(user, role), host)
                    else:
                        self.assertTrue(self.login(user, role).get('totp_setup_needed'), f'{host}: {user} reaches the setup')
        self.assertTrue(e.cluster_replicated('totp-setup') or 'totp-setup' in e.CLUSTER_2FA, 'the web 2FA comes from the master')
        for command in ('console-2fa-enroll', 'console-2fa-set', 'admin-2fa-heal'):
            self.assertIn(command, e.CLUSTER_LOCAL, f'{command}: of this host, never refused on a node')

    def test_cluster_token_makes_the_2fa_key_first(self):
        """Cluster lock test 2026-11-22: the master has its 2FA key before a node joins, so the key goes with the snapshot."""
        e = self.efactl

        class Cluster:
            PORT = 8460

            @staticmethod
            def token_hash(token):
                return 'h'

            @staticmethod
            def write_state(state, etc):
                pass

            @staticmethod
            def fingerprint_pem(pem):
                return 'AA:BB'
        with open(os.path.join(self.folder, 'ca.crt'), 'w') as f:
            f.write('pem')
        key = os.path.join(self.folder, 'totp.key')
        with mock.patch.object(e, '_cluster_parts', lambda: (Cluster, self.folder, {'role': 'master', 'tokens': {}})),                 mock.patch.object(e, 'TOTP_KEY', key):
            self.assertEqual(e.cluster_token(None)['ca_fingerprint'], 'AA:BB')
        self.assertTrue(os.path.exists(key), 'the key exists before the first node can join')

    def facts(self):
        return {'admin_idle': 15, 'admin_2fa': (self.efactl.admin_2fa_due(), 'x'), 'login_banner': True, 'fs_encrypted': (True, 'x'), 'tls25': (0, 0), 'restore_test': (True, 'x'), 'fim': (True, 'x'), 'selinux': 'Enforcing', 'firewall': True, 'auditd': True,
                'time': True, 'os_updates': True, 'os_updates_detail': '',
                'sshd': {'permitrootlogin': 'no', 'permitemptypasswords': 'no', 'x11forwarding': 'no', 'maxauthtries': '4'}, 'encrypt_method': 'SHA512',
                'shadow_mode': 0, 'sysctl': {}, 'audit_anchor': (None, ''),
                'postconf': {name: '' for name in ('smtpd_tls_protocols', 'smtpd_tls_mandatory_protocols', 'smtp_tls_protocols', 'smtpd_tls_auth_only')},
                'cipher_problems': [], 'pam_587': False, 'dnssec': True, 'dane': True, 'domains': 0, 'mta_sts': False, 'mta_sts_count': 0, 'tls_rpt': True,
                'certificate_ok': True, 'certificate_detail': '', 'cert_keys': {'web': ('ec', 256)}, 'dkim_rsa_bits': [], 'ssh_rsa_bits': None,
                'pqc': True, 'openssl': '', 'auto_profiles': [], 'nginx_tls12': True}


class SaslPerName(unittest.TestCase):
    """The compensating control of PCI DSS 8.3.4 / NIST AC-7 (docs/compliance/compensating-controls.md): the logins of port 587
    are slowed down per login name as well as per address, so guessing from many addresses at one name stops too."""

    def test_per_name(self):
        import importlib.machinery
        import importlib.util
        top = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        loader = importlib.machinery.SourceFileLoader('efa_sasl_test', os.path.join(top, 'next', 'usr', 'local', 'sbin', 'efa-sasl.py'))
        sasl = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
        loader.exec_module(sasl)
        limiter = sasl.Limiter()
        with mock.patch.object(sasl.syslog, 'syslog', lambda *a: None):
            for i in range(sasl.FAIL_LIMIT):  # wrong passwords for one name, each from another address
                self.assertEqual(sasl.check('boss@example.com', 'wrong', f'192.0.2.{i}', {}, limiter, delay=0)[0], False)
            ok, reason = sasl.check('boss@example.com', 'wrong', '198.51.100.9', {}, limiter, delay=0)
        self.assertEqual((ok, reason), (False, 'Too many failed logins, try again later.'), 'a new address, the same name: stopped')
        self.assertFalse(limiter.blocked(('user:other@example.com', 'ip:198.51.100.9')), 'another name is not')
        later = __import__('time').time() + sasl.FAIL_WINDOW + 1
        self.assertFalse(limiter.blocked(('user:boss@example.com', 'ip:198.51.100.9'), later), 'it ends after the window')


if __name__ == '__main__':
    unittest.main()
