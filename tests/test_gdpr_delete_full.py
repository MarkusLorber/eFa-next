# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Compliance package 15: GDPR erasure in full. The entries of the sender lists, the erasure list with pseudonyms only, and the
erasure again after a restore of an older backup (also of rows already under a pseudonym)."""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from test_cluster_sync_2fa import load_efactl

KEY = bytes(32)


class Erasure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        e = self.efactl
        maps = {'allow': self.tmp + '/allow.map', 'block': self.tmp + '/block.map'}
        self.files = {'allow': 'anna@example.com\nbob@example.com\n', 'block': 'ANNA@example.com\nspam.example\n',
                      'rules': 'allow|anna@example.com|default\nblock|*@bad.example|anna@example.com\nallow|bob@example.com|carl@example.com\n'}
        for name, text in self.files.items():
            with open(self.tmp + f'/{name}.map', 'w') as f:
                f.write(text)
        with open(self.tmp + '/meta.json', 'w') as f:
            json.dump({'anna@example.com': {'comment': 'x'}, 'bob@example.com': {'comment': 'y'}}, f)
        self.patches = [mock.patch.object(e, name, value) for name, value in (
            ('SENDER_MAPS', maps), ('SENDER_RULES', self.tmp + '/rules.map'), ('SENDER_META', self.tmp + '/meta.json'),
            ('GDPR_ERASED', self.tmp + '/erased.json'), ('_reload_rspamd', mock.Mock()), ('_allow_postfix_apply', mock.Mock()),
            ('_pseudo_key', lambda: KEY), ('_audit', mock.Mock()))]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        shutil.rmtree(self.tmp)

    def read(self, name):
        with open(self.tmp + f'/{name}.map') as f:
            return f.read()

    def test_lists(self):
        e = self.efactl
        self.assertEqual(e.gdpr_lists_erase('anna@example.com'), 4, 'allow, block (any case), a rule as sender and one as recipient')
        self.assertEqual(self.read('allow'), 'bob@example.com\n')
        self.assertEqual(self.read('block'), 'spam.example\n')
        self.assertEqual(self.read('rules'), 'allow|bob@example.com|carl@example.com\n')
        self.assertEqual(list(json.load(open(self.tmp + '/meta.json'))), ['bob@example.com'])
        self.assertTrue(e._reload_rspamd.called)
        e._reload_rspamd.reset_mock()
        self.assertEqual(e.gdpr_lists_erase('nobody@example.com'), 0)
        self.assertFalse(e._reload_rspamd.called, 'nothing to change, no reload')

    def test_erased_again(self):
        e = self.efactl
        alias = e.pseudonym(KEY, 'anna@example.com')
        e.gdpr_erased_add(alias, accounts=False, lists=True)
        e.gdpr_erased_add(alias, accounts=True, lists=False)
        stored = json.load(open(self.tmp + '/erased.json'))
        self.assertEqual(list(stored), [alias], 'the pseudonym only')
        self.assertNotIn('anna', open(self.tmp + '/erased.json').read())
        self.assertEqual((stored[alias]['accounts'], stored[alias]['lists']), (True, True), 'what was asked once stays asked')
        self.assertEqual(oct(os.stat(self.tmp + '/erased.json').st_mode & 0o777), '0o600')
        values = ['Anna@Example.com', 'bob@example.com, <anna@example.com>', alias, None, 'no address']
        self.assertEqual(e.gdpr_candidates(values, KEY, stored), sorted({'anna@example.com', alias}), 'plain and already pseudonymised rows')
        erase = mock.Mock(return_value={'mail_log': 3})
        with mock.patch.object(e, '_admin_query', return_value=[{'a': 'anna@example.com'}, {'a': 'bob@example.com'}]), \
                mock.patch.object(e, '_gdpr_erase', erase):
            self.assertEqual(e.gdpr_reapply(), 1)
        erase.assert_called_once_with('anna@example.com', True, True)
        os.remove(self.tmp + '/erased.json')
        with mock.patch.object(e, '_admin_query', side_effect=AssertionError('no list, no query')):
            self.assertEqual(e.gdpr_reapply(), 0)


if __name__ == '__main__':
    unittest.main()
