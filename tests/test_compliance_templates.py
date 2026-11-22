# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Compliance packages 8, 16 (stage 1) and 14: the templates are marked as not checked by a lawyer, the check of the disk
encryption only reports (dm-crypt under /var and /), and the dashboard leads to the SSH profile until it is set."""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from test_cluster_sync_2fa import load_efactl

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Done:
    def __init__(self, code, out):
        self.returncode, self.stdout = code, out


class Templates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def test_templates_say_they_are_templates(self):
        for name, mark in (('DSFA.md', 'nicht anwaltlich geprüft'), ('BAA.md', 'not checked by a lawyer')):
            with open(os.path.join(TOP, 'docs', 'datenschutz', name), encoding='utf-8') as f:
                text = f.read()
            self.assertIn(mark, text[:600], name)
            self.assertIn('DISCLAIMER.md', text, name)
            self.assertIn('privacy-evidence', text, name)

    def test_fs_encrypted(self):
        def run(types):
            def fake(cmd, **kw):
                if cmd[0] == 'findmnt':
                    return Done(0, '/dev/mapper/root\n' if cmd[-1] == '/' else '/dev/mapper/var[/x]\n')
                return Done(0, types[cmd[-1]])
            return fake
        crypt = 'lvm\ncrypt\npart\ndisk\n'
        self.assertEqual(self.efactl.fs_encrypted(run=run({'/dev/mapper/var': crypt, '/dev/mapper/root': crypt}))[0], True)
        plain = self.efactl.fs_encrypted(run=run({'/dev/mapper/var': 'lvm\npart\ndisk\n', '/dev/mapper/root': crypt}))
        self.assertEqual(plain, (False, '/var not encrypted, / encrypted'))
        self.assertIsNone(self.efactl.fs_encrypted(run=lambda cmd, **kw: Done(1, ''))[0], 'cannot tell: not applicable')

    def test_ssh_profile_notice(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder, True)
        e = self.efactl
        flag = os.path.join(folder, '40-efa-bsi.conf')
        with mock.patch.object(e, 'SSH_BSI_FILE', flag), mock.patch.object(e, 'setup_variant_state', lambda: {'set': '2026-11-19'}), \
                mock.patch.object(e, '_system_notices_rest', lambda: []), mock.patch.object(e, 'BREAKGLASS_ALARMS', os.path.join(folder, 'none.json')):
            found = e._system_notices()
            self.assertTrue(any(item[1:3] == ['standards', 'standards-set'] and 'SSH profile' in str(item[0]) for item in found), found)
            open(flag, 'w').close()
            self.assertFalse([item for item in e._system_notices() if 'SSH profile' in str(item[0])], 'gone once it is set')
        with mock.patch.object(e, 'SSH_BSI_FILE', flag + '.no'), mock.patch.object(e, 'setup_variant_state', lambda: {}), \
                mock.patch.object(e, '_system_notices_rest', lambda: []), mock.patch.object(e, 'BREAKGLASS_ALARMS', os.path.join(folder, 'none.json')):
            self.assertFalse([item for item in e._system_notices() if 'SSH profile' in str(item[0])], 'not before the setup')


if __name__ == '__main__':
    unittest.main()
