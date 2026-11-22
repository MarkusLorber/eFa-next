# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Compliance package 13: the file check without Wazuh. A signed baseline, renewed after each change through efactl; a change
outside efactl is noted once, with an event, until an admin accepts it; a forged baseline and a change that keeps size and time
are found too."""
import argparse
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from test_cluster_sync_2fa import load_efactl


class Fim(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()
        from cryptography.hazmat.primitives.asymmetric import ed25519
        cls.key = ed25519.Ed25519PrivateKey.generate()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.conf = self.tmp + '/etc'
        os.makedirs(self.conf + '/postfix')
        self.write('postfix/main.cf', 'smtpd_tls_security_level = may\n')
        os.symlink('main.cf', self.conf + '/postfix/link.cf')
        e = self.efactl
        self.patches = [mock.patch.object(e, name, value) for name, value in (
            ('FIM_FILE', self.conf + '/fim.json'), ('FIM_BASELINE', self.tmp + '/baseline.json'), ('FIM_ALERTS', self.tmp + '/alerts.json'),
            ('FIM_PATHS', (self.conf,)), ('FIM_SKIP', (self.conf + '/cluster/',)), ('_backup_sign_key', lambda: self.key),
            ('own_hostname', lambda: 'mx.example'), ('_event', mock.Mock()), ('_audit', mock.Mock()))]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        shutil.rmtree(self.tmp)

    def write(self, name, text):
        with open(f'{self.conf}/{name}', 'w') as f:
            f.write(text)

    def test_outside_change_noted_once(self):
        e = self.efactl
        self.assertEqual(e.fim_check(), [], 'off: no baseline, nothing to compare')
        e.fim_set(argparse.Namespace(mode='on'))
        self.assertEqual(e.fim_status(None)['files'], 3)
        self.assertEqual(e.fim_check(), [], 'the setting of the check, under the folders, is in the baseline')
        self.write('postfix/main.cf', 'smtpd_tls_security_level = none\n')
        os.makedirs(self.conf + '/cluster')
        self.write('cluster/journal.json', '{}')
        found = e.fim_check()
        self.assertEqual(found, [{'file': self.conf + '/postfix/main.cf', 'change': 'changed'}], 'the cluster folder is skipped')
        self.assertEqual(e._event.call_args[0][:2], ('config_file_changed', 'warning'))
        self.assertEqual(e.fim_check(), [], 'noted once while it stays the same')
        self.assertEqual(e.fim_fact(), (False, '1 files changed outside efactl'))
        e.fim_accept(argparse.Namespace(file='all'))
        self.assertEqual(e.fim_status(None)['changed'], [])
        self.assertEqual(e.fim_fact(), (True, 'no change outside efactl'))
        # A baseline someone else wrote: its signature is not the one of this host.
        with open(self.tmp + '/baseline.json') as f:
            data = json.load(f)
        data['files'][self.conf + '/postfix/main.cf'][0] = '0' * 64
        with open(self.tmp + '/baseline.json', 'w') as f:
            json.dump(data, f)
        self.assertEqual(e.fim_check()[0]['change'], 'the signature of the baseline is not valid')
        e.fim_set(argparse.Namespace(mode='off'))
        self.assertFalse(os.path.exists(self.tmp + '/baseline.json'))
        self.assertEqual(e.fim_fact(), (None, 'off'))

    def test_efactl_changes_renew(self):
        e = self.efactl
        e.fim_set(argparse.Namespace(mode='on'))
        # A change through efactl: the dispatcher renews the baseline after it.
        self.write('postfix/main.cf', 'smtpd_tls_security_level = encrypt\n')
        self.write('postfix/efa-new', 'x\n')
        e._fim_renew()
        self.assertEqual(e.fim_check(), [])
        # Outside: same size, time set back. The quick check trusts size and time, the daily one hashes every file.
        path = self.conf + '/postfix/main.cf'
        info = os.stat(path)
        self.write('postfix/main.cf', 'smtpd_tls_security_level = encryp7\n')
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
        self.assertEqual(e.fim_check(), [])
        self.assertEqual(e.fim_check(full=True), [{'file': path, 'change': 'changed'}])
        os.remove(self.conf + '/postfix/efa-new')
        self.assertEqual(e.fim_check(), [{'file': self.conf + '/postfix/efa-new', 'change': 'removed'}])


if __name__ == '__main__':
    unittest.main()
