# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Compliance package 12: the restore test of a backup. The tables a dump creates, the result with event and audit line, the
monthly job (off by default, once a month, not under load) and the hardening fact."""
import argparse
import datetime
import json
import os
import tempfile
import unittest
from unittest import mock

from test_cluster_sync_2fa import load_efactl


class RestoreTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        e = self.efactl
        self.patches = [mock.patch.object(e, name, value) for name, value in (
            ('RESTORE_TEST_STATE', self.tmp + '/state.json'), ('RESTORE_TEST_FILE', self.tmp + '/settings.json'),
            ('RESTORE_TEST_PARENT', self.tmp), ('_audit', mock.Mock()), ('_event', mock.Mock()),
            ('_restore_test_pick', lambda name: '/var/eFa/backup/' + (name or 'efa-backup-20261120-030000.tar.gz.gpg')))]
        # The proxy of subprocess keeps its classes (SubprocessError in an except clause); only run is replaced.
        self.patches += [mock.patch.object(e.os, 'nice'), mock.patch.object(e.subprocess, 'run', mock.Mock())]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()

    def test_dump_tables(self):
        dump = [b'-- MariaDB dump\n', b'CREATE TABLE `orphan` (\n', b'USE `mysql`;\n', b'CREATE TABLE IF NOT EXISTS `global_priv` (\n',
                b'/*!50001 CREATE TABLE `a_view` (\n', b'USE `efa`;\n', b'CREATE TABLE `maillog` (\n', b'INSERT INTO `maillog` VALUES (1);\n',
                b'USE `odd``name`;\n', b'CREATE TABLE `t``1` (\n']
        seen = []
        found = self.efactl.dump_tables(iter(dump), seen.append)
        self.assertEqual(found, {('mysql', 'global_priv'), ('efa', 'maillog'), ('odd`name', 't`1')},
                         'no table before the first USE, no placeholder of a view, quoted backticks')
        self.assertEqual(seen, dump, 'every line goes on to the import')

    def test_run_records(self):
        e = self.efactl
        with mock.patch.object(e, '_restore_test', return_value={'backup': 'efa-backup-20261120-030000.tar.gz.gpg', 'files': 40, 'tables': 88}):
            result = e.backup_restore_test_run(argparse.Namespace(name=''))
        self.assertTrue(result['ok'])
        self.assertEqual(json.load(open(self.tmp + '/state.json'))['tables'], 88)
        self.assertEqual(e._event.call_args[0][:2], ('restore_test_ok', 'info'))
        self.assertEqual(e.restore_test_fact()[0], True)
        with mock.patch.object(e, '_restore_test', side_effect=e.EfaError('This backup holds no database.')):
            result = e.backup_restore_test_run(argparse.Namespace(name=''))
        self.assertFalse(result['ok'])
        self.assertEqual(result['problem'], 'This backup holds no database.')
        self.assertEqual(result['backup'], 'efa-backup-20261120-030000.tar.gz.gpg', 'a failed test names its backup')
        self.assertEqual(e._event.call_args[0][:2], ('restore_test_failed', 'warning'))
        self.assertEqual(e.restore_test_fact(), (False, f"{result['when']}: failed"))
        os.makedirs(self.tmp + '/efa-restore-test-left')
        with mock.patch.object(e, '_restore_test', return_value={'backup': 'b', 'files': 1, 'tables': 1}):
            e.backup_restore_test_run(argparse.Namespace(name=''))
        self.assertFalse(os.path.exists(self.tmp + '/efa-restore-test-left'), 'what a stopped test left is removed')

    def test_monthly_job(self):
        e = self.efactl
        state, start = {}, mock.Mock()
        night = datetime.datetime(2026, 12, 1, 3, 10)
        morning = datetime.datetime(2026, 12, 1, 4, 10)
        with mock.patch.object(e, 'backup_restore_test', start), mock.patch.object(e.os, 'getloadavg', return_value=(0.2, 0, 0)):
            e._restore_test_job(state, morning)
            self.assertFalse(start.called, 'off by default')
            self.assertEqual(e.restore_test_fact(), (None, 'never'), 'never ran and off: for information only')
            with open(self.tmp + '/settings.json', 'w') as f:
                json.dump({'monthly': True}, f)
            e._restore_test_job(state, night)
            self.assertFalse(start.called, 'from 04:00')
            e._restore_test_job(state, morning)
            e._restore_test_job(state, morning + datetime.timedelta(days=3))
            self.assertEqual(start.call_count, 1, 'once a month')
            self.assertEqual(state['restore_test_month'], '2026-12')
            self.assertEqual(e.restore_test_fact(), (False, 'never'), 'on and never passed')
        with mock.patch.object(e, 'backup_restore_test', start), mock.patch.object(e.os, 'getloadavg', return_value=(99.0, 0, 0)):
            e._restore_test_job(state, datetime.datetime(2027, 1, 1, 5, 0))
        self.assertEqual(start.call_count, 1, 'not under load: the next hour tries again')
        self.assertEqual(state['restore_test_month'], '2026-12')


if __name__ == '__main__':
    unittest.main()
