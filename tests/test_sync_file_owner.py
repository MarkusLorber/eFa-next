# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""6.0.0.6.6.1: a settings file the master sends (snapshot or journal) is readable by the service that reads it on the node.
In 6.0.0.6.6 a web-allowlist.json new on a node came root:root: efa-web could not read it and refused every admin address."""

import base64
import grp
import importlib.machinery
import importlib.util
import json
import os
import pwd
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))
import efa_cluster  # noqa: E402

ALLOW = base64.b64encode(json.dumps({'mode': 'allowed', 'entries': [{'network': '198.51.100.0/24'}]}).encode()).decode()


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, os.path.join(ROOT, *path.split('/')))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


def readable_by(path, user):
    """Whether user can read path by its owner, group (also supplementary) and mode."""
    info, account = os.stat(path), pwd.getpwnam(user)
    groups = {account.pw_gid} | {item.gr_gid for item in grp.getgrall() if user in item.gr_mem}
    return bool(info.st_mode & 0o004 or (info.st_gid in groups and info.st_mode & 0o040) or (info.st_uid == account.pw_uid and info.st_mode & 0o400))


class SnapshotOwner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load('efactl_sync_owner', 'next/usr/sbin/efactl')

    def apply(self, etc, owned):
        efactl = self.efactl
        snapshot = {'version': efa_cluster.own_version(), 'files': [{'path': 'eFa/web-allowlist.json', 'data': ALLOW, 'mode': 0o600},
                                                                   {'path': 'other/plain.conf', 'data': ALLOW, 'mode': 0o644}],
                    'postconf': {}, 'services': {}, 'sql': '', 'units': {}, 'hostname': 'node-a.example.org'}
        with mock.patch.object(efactl, 'ETC', etc), mock.patch.object(efactl, '_conf_own', owned), \
                mock.patch.object(efactl, 'own_names', lambda *a: None), mock.patch.object(efactl, '_ru_postconf', lambda *a: ''), \
                mock.patch.object(efactl, '_map_type', lambda: 'hash'), mock.patch.object(efactl, '_postfix_map_types', lambda: {'hash'}), \
                mock.patch.object(efactl, '_audit', lambda text: None), mock.patch.object(efactl, '_postconf', lambda name: 'node-b.example.org'):
            return efactl.snapshot_apply(snapshot, files_only=True)

    def test_new_settings_file_gets_the_owner_of_the_table(self):
        calls = []
        with tempfile.TemporaryDirectory() as folder:
            etc = os.path.realpath(folder)
            self.apply(etc, lambda path, mode, group: calls.append((os.path.basename(path), mode, group)))
        self.assertIn(('web-allowlist.json.new', 0o640, 'efa-conf'), calls, 'not root:root, the group efa-web reads it with')
        self.assertFalse([call for call in calls if call[0].startswith('plain.conf')], 'a file outside /etc/eFa/*.json keeps its way')

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'needs root to change owners')
    def test_efa_web_can_read_it(self):
        try:
            grp.getgrnam('efa-conf')
            pwd.getpwnam('efa-web')
        except KeyError:
            self.skipTest('no efa-web or efa-conf on this host')
        with tempfile.TemporaryDirectory() as folder:
            etc = os.path.realpath(folder)
            self.apply(etc, self.efactl._conf_own)
            path = os.path.join(etc, 'eFa', 'web-allowlist.json')
            self.assertTrue(readable_by(path, 'efa-web'), oct(os.stat(path).st_mode))
            self.assertEqual(os.stat(path).st_mode & 0o007, 0, 'not for everyone')


class JournalOwner(unittest.TestCase):
    def test_journal_files_heal_and_keep_owners(self):
        service = load('efa_cluster_sync_owner', 'next/usr/local/sbin/efa-cluster.py')
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            return types.SimpleNamespace(returncode=0, stdout='', stderr='')
        with tempfile.TemporaryDirectory() as folder:
            etc = os.path.realpath(folder)
            os.makedirs(os.path.join(etc, 'eFa'))
            with mock.patch.object(service, 'ETC', etc):
                entry = {'type': 'files', 'files': [{'path': 'eFa/web-allowlist.json', 'data': ALLOW, 'mode': 0o640}]}
                self.assertIsNone(service.apply(entry, run=run))
                self.assertEqual(calls, [[service.EFACTL, 'conf-modes-heal']], 'the table of efactl after a settings file')
                failed = service.apply(entry, run=lambda command, **k: types.SimpleNamespace(returncode=1, stdout='', stderr='no group'))
                self.assertIn('conf-modes-heal', failed, 'a failed heal is a failed entry')
                calls.clear()
                self.assertIsNone(service.apply({'type': 'files', 'files': [{'path': 'other.conf', 'data': ALLOW, 'mode': 0o644}]}, run=run))
                self.assertEqual(calls, [], 'no heal for files outside /etc/eFa/*.json')
                if hasattr(os, 'geteuid') and os.geteuid() == 0:
                    path = os.path.join(etc, 'other.conf')
                    os.chown(path, 0, 1)
                    service.apply({'type': 'files', 'files': [{'path': 'other.conf', 'data': ALLOW, 'mode': 0o640}]}, run=run)
                    self.assertEqual(os.stat(path).st_gid, 1, 'the owner of an existing file stays')


if __name__ == '__main__':
    unittest.main()
