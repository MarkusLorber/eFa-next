# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The environment of a host (efactl environment-set): prod, test or dev, only a super admin sets it, audited, only this host
in a cluster, and the dev flag of efa-init forces dev."""
import os
import shutil
import tempfile
import types
import unittest
from unittest import mock

from test_threat import load_efactl


class Environment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.audited = []
        setup = self.efactl._lib('efa_setup')
        for patch in (mock.patch.object(self.efactl, 'ENVIRONMENT_FILE', self.folder + '/environment.json'),
                      mock.patch.object(self.efactl, 'DEV_2FA_FILE', self.folder + '/dev-2fa-hint.json'),
                      mock.patch.object(self.efactl, 'DEV_NO_SETUP_CODE', self.folder + '/dev-no-setup-code'),
                      mock.patch.object(self.efactl, '_audit', self.audited.append),
                      mock.patch.object(setup, 'DEV_FLAG', self.folder + '/dev-no-setup-code')):
            patch.start()
            self.addCleanup(patch.stop)

    def test_default_set_and_audit(self):
        self.assertEqual(self.efactl.environment_status()['environment'], 'prod')
        with mock.patch.object(self.efactl, 'identity_now', None):
            self.assertEqual(self.efactl.environment_set(types.SimpleNamespace(env='test'))['environment'], 'test')
        self.assertTrue(self.audited and self.audited[0].startswith('environment prod -> test by'), self.audited)
        with self.assertRaises(self.efactl.EfaError):
            self.efactl.environment_set(types.SimpleNamespace(env='staging'))
        self.assertIn('environment-set', self.efactl.SUPER_COMMANDS)
        self.assertIn('environment-set', self.efactl.CLUSTER_LOCAL)

    def test_only_a_super_admin(self):
        for role in ('tenant', 'domain', 'helpdesk', 'readonly', 'auditor', 'manager'):
            with mock.patch.object(self.efactl, 'identity_now', {'username': 'anna', 'role': role}):
                with self.assertRaises(self.efactl.EfaError):
                    self.efactl.environment_set(types.SimpleNamespace(env='prod'))
        self.assertFalse(os.path.exists(self.folder + '/environment.json'), 'nothing written by a refused call')
        with mock.patch.object(self.efactl, 'identity_now', {'username': 'boss', 'role': 'super'}):
            self.assertEqual(self.efactl.environment_set(types.SimpleNamespace(env='dev'))['set'], 'dev')

    def test_dev_flag_forces_dev(self):
        flag = self.folder + '/dev-no-setup-code'
        open(flag, 'w').close()
        os.chmod(flag, 0o600)
        found = self.efactl.environment_status()
        if os.getuid() == 0:
            self.assertEqual((found['environment'], found['set'], found['forced_by']), ('dev', 'prod', flag))
        else:
            self.assertEqual(found['environment'], 'prod', 'a flag not owned by root never counts')

    def test_dev_2fa_hint_only_in_dev_and_only_for_oneself(self):
        """Hans 2026-11-17: the 2FA hint can be confirmed on a development host, per user; elsewhere refused, nothing written."""
        for env in ('prod', 'test'):
            with mock.patch.object(self.efactl, 'identity_now', None):
                if env != 'prod':
                    self.efactl.environment_set(types.SimpleNamespace(env=env))
                with self.assertRaises(self.efactl.EfaError):
                    self.efactl.dev_2fa_hint_confirm(None)
        self.assertFalse(os.path.exists(self.folder + '/dev-2fa-hint.json'), 'nothing written outside development')
        with mock.patch.object(self.efactl, 'identity_now', None):
            self.efactl.environment_set(types.SimpleNamespace(env='dev'))
            self.assertEqual(self.efactl.dev_2fa_hint_confirm(None), {'confirmed': '@admin'})
        with mock.patch.object(self.efactl, 'identity_now', {'username': 'anna', 'role': 'helpdesk'}):
            self.assertEqual(self.efactl.dev_2fa_hint_confirm(types.SimpleNamespace(username='boss')), {'confirmed': 'anna'},
                             'only the own login, whatever is passed')
        self.assertIn('2FA hint confirmed for anna in dev mode', self.audited)
        self.assertEqual(self.efactl.COMMANDS['dev-2fa-hint-confirm']['args'], [], 'no user to name')

    def test_dev_flag_line_red_only_when_not_development(self):
        flag = self.folder + '/dev-no-setup-code'
        self.assertEqual(self.efactl.dev_flag_banner(), [])
        open(flag, 'w').close()
        os.chmod(flag, 0o600)
        self.assertEqual(len(self.efactl.dev_flag_banner()), 1, 'a flag on a host set to production: red')
        if os.getuid() != 0:
            return
        with mock.patch.object(self.efactl, 'identity_now', None):
            self.efactl.environment_set(types.SimpleNamespace(env='dev'))
            self.assertEqual(self.efactl.dev_flag_banner(), [], 'development with the flag: the header mark is enough')
            with self.assertRaises(self.efactl.EfaError):
                self.efactl.environment_set(types.SimpleNamespace(env='prod'))
        self.assertEqual(self.efactl.environment_status()['set'], 'dev', 'the refused change wrote nothing')


if __name__ == '__main__':
    unittest.main()
