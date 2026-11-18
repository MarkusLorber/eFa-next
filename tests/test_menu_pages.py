# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.6.6 (Hans 2026-11-18: "die menüs im dashboard weiter optimieren und benutzerfreundlicher gestalten"): a long page reads
as its own menu. Only the first section is open, the others name their cards; a warning or the card just used opens its section;
card titles drop what the section already says; small cards stand side by side. Nothing is hidden for good."""
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_menu_reorg as base  # noqa: E402
from test_menu_reorg import SCHEMA, load_web  # noqa: E402

SECTION = re.compile(r'<details class="section" id="sec-(\d+)"( open)?><summary>([^<]*)(?:<span class="secteaser">([^<]*)</span>)?</summary>')


class LongPages(unittest.TestCase):
    https, setUp, page = base.Pages.https, base.Pages.setUp, base.Pages.page

    @classmethod
    def setUpClass(cls):
        cls.web = load_web()

    def sections(self, slug, lang='en', view='standard'):
        _client, reply = self.page(slug, lang, view)
        html = reply.get_data(as_text=True)
        self.assertEqual(reply.status_code, 200, slug)
        return html, [(int(n), bool(o), t.strip(), teaser or '') for n, o, t, teaser in SECTION.findall(html)]

    def test_long_page_opens_only_the_first_section(self):
        # Security shows its task cards in Standard (feature/security-page-ux); its long page of sections is the Expert view.
        html, found = self.sections('sec', view='expert')
        self.assertGreaterEqual(len(found), 4)
        self.assertEqual([open_ for _n, open_, _t, _x in found], [True] + [False] * (len(found) - 1))
        self.assertEqual(found[0][2], 'State of this server', 'the findings first')
        self.assertIn('class="secall" hidden', html, 'the open-all button, shown by the script')
        for _n, open_, title, teaser in found[1:]:
            self.assertTrue(teaser, f'{title}: a closed section names its cards')

    def test_every_card_still_on_the_page(self):
        commands = SCHEMA.get('commands', SCHEMA)
        for slug in ('sec', 'files', 'spam', 'net', 'privacy', 'maint', 'domset', 'users', 'tenants'):
            html, found = self.sections(slug, view='expert')
            self.assertTrue(found, slug)
            names = [name for section in self.web.PAGES[slug]['sections'] for name in section[1]]
            merged = {self.web.STATUS_OF[name] for name in names if self.web.STATUS_OF.get(name) in names}
            missing = [name for name in names if name in commands and name not in self.web.HIDDEN_CARDS and name not in merged
                       and f'id="{name}"' not in html]
            self.assertEqual(missing, [], slug)

    def test_short_page_keeps_its_sections_open(self):
        _html, found = self.sections('rbl')
        self.assertTrue(len(found) >= 2 and all(open_ for _n, open_, _t, _x in found))
        html, found = self.sections('account')
        self.assertNotIn('class="secteaser"', html, 'My account keeps its own groups, all open')

    def test_card_titles_drop_what_the_section_says(self):
        for lang, heading, short in (('en', 'Users', 'Lock (off) or unlock (on)'), ('de', 'Benutzer', 'Sperren (off) oder entsperren (on)')):
            html, _found = self.sections('users', lang)
            card = html[html.index('id="user-state"'):]
            self.assertTrue(card.split('<h2>', 1)[1].startswith(short), (lang, card[:200]))
        html, _found = self.sections('domset', 'de', 'expert')
        self.assertIn('>Jetzt prüfen<', html.replace('<h2>', '>'), 'Domainprüfung: jetzt prüfen under Domainprüfung')

    def test_teaser_names_each_card_once(self):
        _html, found = self.sections('files', 'de', 'expert')
        for _n, _open, title, teaser in found:
            parts = [p.casefold() for p in teaser.split(' · ') if p]
            self.assertEqual(len(parts), len(set(parts)), title)
            self.assertNotIn(title.casefold(), parts, title)

    def test_warning_opens_its_section(self):
        self.outputs['ssh-root-status'] = {'mode': 'password', 'warnings': ['Root may log in with a password.']}
        _html, found = self.sections('sec', view='expert')
        self.assertIn((True, 'Admin access'), [(open_, title) for _n, open_, title, _x in found])

    def test_actions_are_buttons_in_their_card(self):
        html, _found = self.sections('users', 'de')
        group = html[html.index('<div class="cardgroup'):]
        group = group[:group.index('</details></div></div>') + 1]
        for name in ('user-list', 'user-set', 'user-state'):
            self.assertIn(f'id="{name}"', group, name)
        self.assertIn('<details class="cfold"><summary>Sperren (off) oder entsperren (on)</summary>', group)
        groups = self.web.card_groups(['user-list', 'user-show', 'user-set', 'user-state', 'user-2fa-reset'], SCHEMA.get('commands', SCHEMA))
        self.assertEqual(groups[0][0], 'user-list')
        self.assertEqual(groups[0][1], ['user-show', 'user-set', 'user-state'])
        self.assertEqual([head for head, _rest in groups[1:]], ['user-2fa-reset'], 'another title stays a card of its own')

    def test_no_fixed_line_under_the_card_titles(self):
        for slug in ('sec', 'users', 'bak'):
            html, _found = self.sections(slug, 'en', 'expert')
            for title in re.findall(r'</h2>\s*<p class="h">([^<]{20,})', html):
                self.fail(f'{slug}: fixed text under a title: {title[:60]}')

    def test_backup_page_in_sections_and_german(self):
        html, found = self.sections('bak', 'de')
        self.assertEqual([t for _n, _o, t, _x in found][:4], ['Sicherungen', 'Wiederherstellen', 'Externe Sicherungsziele', 'Einstellungen auf einen anderen Host'])
        self.assertIn('Sicherung hochladen', html)
        self.assertNotIn('Upload a backup', html)

    def test_texts_in_german(self):
        html, _found = self.sections('sec', 'de', 'expert')
        self.assertIn('data-open="Alle aufklappen" data-close="Alle zuklappen"', html)


    def test_single_section_does_not_repeat_the_page_title(self):
        for slug in ('firewall', 'queue', 'quar'):
            html, found = self.sections(slug, 'de')
            self.assertEqual(found, [], f'{slug}: one section named like the page: no heading of its own')
            self.assertIn('<div class="card', html, slug)

    def test_cards_of_one_status_show_it_once(self):
        html, _found = self.sections('dlp', 'en', 'expert')
        self.assertEqual(html.count('<h2>Data loss prevention'), 1, 'the own rule is no second card with the same title')
        self.assertIn('<details class="cfold"><summary>Own rule</summary>', html)
        html, _found = self.sections('pdfmail', 'de')
        self.assertEqual(html.count('<h2>Verschlüsselte PDF-Mail'), 1)

    def test_mail_log_tools(self):
        html, _found = self.sections('log', 'de')
        card = html[html.index('id="maillog-search"'):html.index('id="mail-check"')]
        self.assertIn('id="live-open"', card)
        self.assertIn('id="message-search"', card)
        self.assertRegex(card, r'<select id="maillog-search-limit" name="limit">.*<option selected>100</option>.*<option>1000</option>')
        self.assertEqual(html.count('id="message-search"'), 1)

    def test_gdpr_prefix_named_by_the_section(self):
        html, _found = self.sections('privacy', 'en', 'expert')
        self.assertNotIn('<h2>GDPR:', html)


if __name__ == '__main__':
    unittest.main()
