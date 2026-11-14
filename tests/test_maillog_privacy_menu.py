# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.6 (Hans): the menu Privacy & Compliance holds the three privacy sections that were under Mail log, and live filtering
of the advanced search asks efactl message-search only for the rows after its cursor, scoped like every message search."""
import argparse
import importlib.machinery
import importlib.util
import os
import sys
import types
import unittest
from unittest import mock

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(TOP, 'src', 'eFa-base', 'root', 'usr', 'lib', 'eFa', 'python'))
sys.path.insert(0, os.path.join(TOP, 'next', 'usr', 'lib', 'eFa', 'python'))
sys.dont_write_bytecode = True

import efa_nav  # noqa: E402

PRIVACY_SECTIONS = ('Data of one person (GDPR)', 'Export headers', 'Storage & privacy')


def load_efactl():
    for name in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
        sys.modules.setdefault(name, __import__(name) if importlib.util.find_spec(name) else types.ModuleType(name))
    loader = importlib.machinery.SourceFileLoader('efactl_privacy_menu', os.path.join(TOP, 'next', 'usr', 'sbin', 'efactl'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_privacy_menu', loader))
    loader.exec_module(module)
    return module


class Menu(unittest.TestCase):
    def test_privacy_page_holds_the_three_sections(self):
        page = efa_nav.PAGES['privacy']
        self.assertEqual(page['title'], 'Privacy & Compliance')
        self.assertEqual(tuple(section[0] for section in page['sections']), PRIVACY_SECTIONS)
        # In the standard view: on their own page the sections are no longer folded into the expert view.
        self.assertTrue(all(len(section) == 2 for section in page['sections']))
        for name in ('gdpr-export', 'gdpr-delete', 'headers-export', 'retention-status', 'retention-set', 'maillog-purge'):
            self.assertIn(name, page['commands'])

    def test_mail_log_keeps_only_the_search(self):
        log = efa_nav.PAGES['log']
        self.assertFalse({section[0] for section in log['sections']} & set(PRIVACY_SECTIONS))
        self.assertFalse(set(log['commands']) & set(efa_nav.PAGES['privacy']['commands']))
        self.assertEqual(log['commands'][:2], ['maillog-search', 'message-search'])

    def test_privacy_next_to_mail_log_and_old_bookmarks(self):
        group = dict(efa_nav.NAV)['Mail & quarantine']
        slugs = [page['slug'] for page in group]
        self.assertEqual(slugs.index('privacy'), slugs.index('log') + 1)
        self.assertEqual({card for (old, card), new in efa_nav.MOVED_CARDS.items() if old == 'log' and new == 'privacy'},
                         set(efa_nav.PAGES['privacy']['commands']))
        # The moved commands are on this one page only.
        seen = [name for _group, pages in efa_nav.NAV for page in pages for name in page['commands'] if name in efa_nav.PAGES['privacy']['commands']]
        self.assertEqual(len(seen), len(set(seen)))

    def test_german_texts(self):
        with open(os.path.join(TOP, 'next', 'usr', 'share', 'eFa', 'locale', 'de.po'), encoding='utf-8') as f:
            po = f.read()
        for text in ('Privacy & Compliance', 'Advanced search', 'Live filtering: on', 'Live filtering: off', 'Mails found'):
            self.assertIn(f'msgid "{text}"', po)
        self.assertIn('msgstr "Datenschutz & Compliance"', po)


class FakeCursor:
    def __init__(self, rows, seen):
        self.rows, self.seen = rows, seen

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params):
        self.seen.append((sql, params))

    def fetchall(self):
        return [dict(row) for row in self.rows]


class FakeDb:
    def __init__(self, rows):
        self.rows, self.seen = rows, []

    def cursor(self):
        return FakeCursor(self.rows, self.seen)

    def close(self):
        pass


def search_args(**values):
    keys = ('sender', 'rcpt', 'subject', 'ip', 'qid', 'action', 'date_from', 'date_to', 'message_id', 'header_from', 'reply_to', 'return_path',
            'x_mailer', 'limit', 'format', 'after_id')
    return argparse.Namespace(**{key: values.get(key, '') for key in keys})


class LiveFilter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def search(self, rows, identity, **values):
        db = FakeDb(rows)
        e = self.efactl
        with mock.patch.object(e, '_maillog_db', return_value=db), mock.patch.object(e, 'pseudo_days', return_value=0), \
                mock.patch.object(e, 'subjects_shown', return_value=True), mock.patch.object(e, '_reader_timezone', return_value=None), \
                mock.patch.object(e, 'local_times', side_effect=lambda rows, _tz: rows), mock.patch.object(e, 'identity_now', identity):
            return e.message_search(search_args(**values)), db.seen

    def test_only_rows_after_the_cursor(self):
        _found, seen = self.search([], None, sender='a@example.org', after_id='41')
        sql, params = seen[0]
        self.assertIn('WHERE sender LIKE %s AND id > %s ORDER BY', sql)
        self.assertEqual(params, ('a@example.org', 41, 100))

    def test_without_filters_the_cursor_alone(self):
        _found, seen = self.search([], None, after_id='7')
        self.assertIn('FROM maillog WHERE id > %s ORDER BY', seen[0][0])
        _found, seen = self.search([], None)
        self.assertNotIn('id >', seen[0][0])

    def test_cursor_must_be_a_number(self):
        with self.assertRaises(self.efactl.EfaError):
            self.search([], None, after_id='1 OR 1=1')

    def test_tenant_scope(self):
        identity = {'domains': ['tenant.example'], 'grants': {'search'}, 'role': 'tenant'}
        rows = [{'id': 50, 'sender': 'x@other.example', 'rcpt': 'y@tenant.example', 'subject': 's'},
                {'id': 51, 'sender': 'x@other.example', 'rcpt': 'z@foreign.example', 'subject': 's'}]
        found, seen = self.search(rows, identity, after_id='41')
        sql, params = seen[0]
        self.assertIn('id > %s', sql)
        self.assertIn('(rcpt LIKE %s OR sender LIKE %s)', sql)
        self.assertEqual(params, ('%@tenant.example%', '%@tenant.example%', 41, 100))
        self.assertEqual([mail['id'] for mail in found['mails']], [50])

    def test_not_shown_in_the_web_form(self):
        args = {arg['name']: arg for arg in self.efactl.COMMANDS['message-search']['args']}
        self.assertIs(args['after_id'].get('web'), False)


if __name__ == '__main__':
    unittest.main()
