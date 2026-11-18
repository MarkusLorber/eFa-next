# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""6.0.0.6.6.1: the second factors (TOTP, passkeys) go from the master to the nodes as rows, and a node never lets a login
in with the password alone when it cannot read its 2FA. The crypto, the efa libraries and the statements are the real ones;
only the database is a table in memory."""

import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))


def load_efactl():
    loader = importlib.machinery.SourceFileLoader('efactl_sync_2fa', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_sync_2fa', loader))
    loader.exec_module(module)
    return module


class Tables:
    """The two tables of a host, run through the statements efactl makes."""

    def __init__(self):
        self.rows = {'user_totp': [], 'user_passkeys': []}

    def run(self, statements):
        for sql, params in statements:
            table = sql.split()[2]
            if sql.startswith('DELETE FROM'):
                self.rows[table] = []
            else:
                names = sql.split('(', 1)[1].split(')', 1)[0].split(', ')
                self.rows[table].append(dict(zip(names, params)))

    def totp(self, username):
        found = [row for row in self.rows['user_totp'] if row['username'] == username]
        return found[0] if found else None


class Sync2fa(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.audited = []
        self.addCleanup(lambda: __import__('shutil').rmtree(self.folder, ignore_errors=True))

    def host(self, key_name, tables):
        """The patches of one host: its totp.key and its tables."""
        efactl = self.efactl
        return [mock.patch.object(efactl, 'TOTP_KEY', os.path.join(self.folder, key_name)),
                mock.patch.object(efactl, '_totp_row', tables.totp),
                mock.patch.object(efactl, '_admin_query', lambda sql, params=(): []),
                mock.patch.object(efactl, '_audit', self.audited.append)]

    def run_on(self, patches, work):
        for patch in patches:
            patch.start()
        try:
            return work()
        finally:
            for patch in reversed(patches):
                patch.stop()

    def enrolled_master(self):
        """A master with anna enrolled (TOTP) and one passkey, its rows as cluster_2fa_rows gives them."""
        efactl, tables = self.efactl, Tables()
        secret = os.urandom(20)

        def enrol():
            sealed = efactl.totp_seal(secret, 'anna')
            tables.rows['user_totp'] = [{'username': 'anna', 'secret': sealed, 'active': 1, 'last_step': 0, 'recovery': '[]',
                                         'pending': None, 'reenroll': 0}]
            tables.rows['user_passkeys'] = [{'id': 7, 'username': 'anna', 'cred_id': 'cred-1', 'alg': '-7', 'pem': 'PEM', 'sign_count': 3,
                                             'name': 'key', 'aaguid': '0' * 32, 'created': '2026-11-18 10:00:00', 'last_used': None}]
        self.run_on(self.host('master.key', tables), enrol)
        return secret, tables

    def rows_of(self, tables):
        efactl = self.efactl
        with mock.patch.object(efactl, '_admin_query', lambda sql, params=(): tables.rows[sql.split()[3]]):
            return efactl.cluster_2fa_rows()

    def test_join_and_journal_carry_totp_and_passkeys(self):
        efactl = self.efactl
        _secret, master = self.enrolled_master()
        rows = self.rows_of(master)
        self.assertEqual([row['username'] for row in rows['user_totp']], ['anna'])
        self.assertEqual(rows['user_passkeys'][0]['cred_id'], 'cred-1')
        node = Tables()
        node.rows['user_totp'] = [{'username': 'anna', 'secret': 'old', 'active': 1, 'last_step': 0}]
        node.run(efactl.cluster_2fa_statements(rows))
        self.assertEqual(node.rows, master.rows, 'the master replaces the rows of the node')
        # The journal: a 2FA command goes on as the rows, never replayed (a node would make a secret of its own).
        with mock.patch.object(efactl, 'cluster_2fa_rows', lambda: rows):
            entries = efactl.cluster_entries('totp-confirm', mock.Mock(), [])
        self.assertEqual([(entry['command'], entry['args']) for entry in entries], [('cluster-2fa-apply', {})])
        self.assertEqual(json.loads(entries[0]['secrets'][0]), json.loads(json.dumps(rows)))
        for command in efactl.CLUSTER_2FA:
            self.assertTrue(efactl.cluster_replicated(command), f'{command} must reach the journal of the master')
        self.assertFalse(efactl.cluster_replicated('cluster-2fa-apply'), 'the rows are applied, not handed on again')

    def test_broken_rows_change_nothing(self):
        efactl = self.efactl
        for rows in (None, {}, {'user_totp': []}, {'user_totp': 'x', 'user_passkeys': []}, {'user_totp': [{'secret': 'x'}], 'user_passkeys': []}):
            with self.assertRaises(efactl.EfaError):
                efactl.cluster_2fa_statements(rows)
        statements = efactl.cluster_2fa_statements({'user_totp': [{'username': 'anna', 'secret': 's', 'evil); DROP TABLE users; --': 1}],
                                                    'user_passkeys': []})
        self.assertNotIn('DROP', ' '.join(sql for sql, _p in statements), 'only the known columns')

    def test_replicated_user_needs_totp_on_the_node(self):
        efactl = self.efactl
        secret, master = self.enrolled_master()
        node = Tables()
        node.run(efactl.cluster_2fa_statements(self.rows_of(master)))
        node_host = self.host('master.key', node)  # totp.key came from the master with the snapshot

        def login(code):
            return efactl.totp_check('anna', code)
        with self.assertRaisesRegex(efactl.EfaError, '2FA code needed'):
            self.run_on(node_host, lambda: login(None))
        code = efactl.hotp(secret, int(time.time() // 30))
        self.assertTrue(self.run_on(node_host, lambda: login(code)))

    def test_undecryptable_row_denies_the_login(self):
        efactl = self.efactl
        secret, master = self.enrolled_master()
        # A node with its own old key kept the row sealed with the master's key: never password only.
        node_host = self.host('own-old.key', master)
        code = efactl.hotp(secret, int(time.time() // 30))
        with self.assertRaisesRegex(efactl.EfaError, 'cannot be read on this host'):
            self.run_on(node_host, lambda: efactl.totp_check('anna', code))
        self.assertTrue(any('cannot be read on this host' in text for text in self.audited))


if __name__ == '__main__':
    unittest.main()
