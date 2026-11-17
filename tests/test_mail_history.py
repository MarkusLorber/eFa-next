# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""R7-6: the mail history of a scope with several own domains counts each mail once (maillog_daily_rows, history_daily_sum)."""

import unittest

from test_el10_platform import load_efactl


def mail(day, sender, rcpt, action='no action', threat=''):
    return {'day': day, 'sender': sender, 'rcpt': rcpt, 'action': action, 'threat': threat}


class MailHistoryOnce(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def table(self, rows, own):
        return [{'day': day, 'domain': domain, **counts} for (day, domain), counts in self.efactl.maillog_daily_rows(rows, own).items() if domain]

    def test_a_mail_between_two_own_domains_counts_once(self):
        own = {'a.example', 'b.example', 'c.example'}
        rows = [mail('2026-11-14', 'x@a.example', 'y@b.example', 'add header'),
                mail('2026-11-14', 'x@a.example', 'y@b.example, z@c.example', 'reject', 'virus:Eicar'),
                mail('2026-11-14', 'x@out.example', 'y@a.example'),
                mail('2026-11-14', 'x@out.example', 'y@c.example')]
        table = self.table(rows, own)
        sums = self.efactl.history_daily_sum
        both = sums(table, ['a.example', 'b.example'])[0]['2026-11-14']
        self.assertEqual(both, {'total': 3, 'clean': 1, 'spam': 1, 'rejected': 1, 'viruses': 1})
        self.assertEqual(sums(table, ['a.example', 'b.example', 'c.example'])[0]['2026-11-14']['total'], 4)
        self.assertEqual(sums(table, ['a.example'])[0]['2026-11-14']['total'], 3)
        self.assertEqual(sums(table, ['b.example', 'c.example'])[0]['2026-11-14']['total'], 3)
        self.assertEqual(sums(table, ['a.example', 'b.example'])[1], set())

    def test_names_too_long_for_the_column_take_the_mail_log(self):
        own = {f'{"d" * 60}{n}.example' for n in range(6)}
        rcpt = ', '.join('u@' + name for name in sorted(own))
        table = self.table([mail('2026-11-14', 'x@out.example', rcpt)], own)
        self.assertIn('+*', {row['domain'] for row in table})
        self.assertEqual(self.efactl.history_daily_sum(table, sorted(own))[1], {'2026-11-14'})


class MailHistoryPage(unittest.TestCase):
    """R7-8: the page in the language of the reader, every text translated, with a way back to the mail report."""

    @classmethod
    def setUpClass(cls):
        import datetime
        import os
        cls.efactl = load_efactl()
        i18n = cls.efactl._lib('efa_i18n')
        cls.saved = i18n.LOCALE_DIR
        i18n.LOCALE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'next', 'usr', 'share', 'eFa', 'locale')
        i18n._catalogs.clear()
        counts = {'2026-11-03': {'total': 12, 'clean': 8, 'spam': 3, 'rejected': 1, 'viruses': 1}}
        cls.view = cls.efactl.history_view('2026-11', 30, counts, datetime.date(2026, 11, 15))

    @classmethod
    def tearDownClass(cls):
        cls.efactl._lib('efa_i18n').LOCALE_DIR = cls.saved
        cls.efactl._lib('efa_i18n')._catalogs.clear()

    def test_german(self):
        page = self.efactl.history_html(self.view, 'own.example', 'de')
        self.assertIn('<html lang="de">', page)
        for text in ('Mail-Verlauf von own.example', '<th>Mo</th>', '12 Mails', '3 Spam · 1 Viren', '1 abgewiesen', 'Letzte 30 Tage',
                     'Zurück zum Mail-Bericht', '12 Mails im Monat', 'alle Mails'):
            self.assertIn(text, page)
        for text in (' mails<', 'Last 30 days', '<th>Mon</th>', 'all mail'):
            self.assertNotIn(text, page)

    def test_english_and_unknown_language(self):
        for lang in ('en', '', 'xx"'):
            page = self.efactl.history_html(self.view, '', lang)
            self.assertIn('<html lang="en">', page)
            self.assertIn('Back to the mail report', page)
            self.assertIn('href="/p/report#mail-history"', page)


if __name__ == '__main__':
    unittest.main()
