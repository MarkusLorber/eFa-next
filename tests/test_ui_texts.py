# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Every card of the menu and every field it shows has a help text (efa_help, the (i) popup), and every text a form shows
has a German translation: a new command or field fails here until it is explained and translated."""
import json
import os
import re
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))
import efa_help  # noqa: E402
import efa_i18n  # noqa: E402
import efa_nav  # noqa: E402

EFACTL = os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl')
WEB = os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-web.py')
DE = os.path.join(ROOT, 'next', 'usr', 'share', 'eFa', 'locale', 'de.po')


def shown_cards():
    """The commands the menu shows as cards, with their fields as the web interface shows them."""
    schema = json.loads(subprocess.run([sys.executable, '-B', EFACTL, 'schema'], capture_output=True, text=True, check=True).stdout)
    with open(WEB, encoding='utf-8') as f:
        hidden = set(re.findall(r"'([a-z0-9-]+)'", re.search(r'^HIDDEN_CARDS = (\{.*?\})\n', f.read(), re.S | re.M).group(1)))
    cards = {}
    for _group, pages in efa_nav.NAV:
        for page in pages:
            for section in page.get('sections', []):
                for name in section[1]:
                    if name in schema and name not in hidden:
                        cards[name] = [arg for arg in schema[name].get('args') or []
                                       if arg.get('web') is not False and not arg.get('secret') and not arg.get('ack') and arg.get('kind') != 'confirm']
    return schema, cards


class UiTextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema, cls.cards = shown_cards()
        with open(DE, encoding='utf-8') as f:
            cls.de = efa_i18n.po_entries(f.read())

    def test_every_card_has_help(self):
        missing = sorted(name for name in self.cards if not efa_help.CARD.get(name))
        self.assertEqual(missing, [], 'cards without a help text in efa_help.CARD')

    def test_every_field_has_help(self):
        missing = sorted(f'{name}.{arg["name"]}' for name, args in self.cards.items() for arg in args
                         if not efa_help.FIELD.get(name, {}).get(arg['name']))
        self.assertEqual(missing, [], 'fields without a help text in efa_help.FIELD')

    def test_no_help_for_unknown_commands(self):
        unknown = sorted(name for name in set(efa_help.CARD) | set(efa_help.FIELD) if name not in self.schema)
        self.assertEqual(unknown, [], 'help texts of commands that do not exist')
        unknown = sorted(f'{name}.{arg}' for name, fields in efa_help.FIELD.items() if name in self.schema for arg in fields
                         if arg not in [item['name'] for item in self.schema[name].get('args') or []])
        self.assertEqual(unknown, [], 'help texts of fields that do not exist')

    def test_shown_texts_are_translated(self):
        wanted = list(efa_help.CARD.values()) + [text for fields in efa_help.FIELD.values() for text in fields.values()]
        for name, args in self.cards.items():
            wanted.append(efa_help.short_title(self.schema[name]['title']))
            for arg in args:
                label = arg.get('label', '')
                wanted.append(label[:-len(': on or off')] if label.endswith(': on or off') else label)
                shown = efa_help.web_label(label, arg.get('kind'))
                wanted += [shown['label'], shown['placeholder']]
                wanted += [item['text'] for item in arg.get('choices') or [] if re.search('[A-Za-z]{2}', item.get('text', ''))]
        missing = sorted({text for text in wanted if text and text not in ('on or off', 'On or off') and not self.de.get(text)})
        self.assertEqual(missing, [], 'texts without German translation: fill them in de.po (scripts/i18n_extract.py)')

    def test_web_label(self):
        self.assertEqual(efa_help.web_label('Score, empty keeps it'), {'label': 'Score', 'placeholder': 'Empty keeps it', 'clear': False, 'yes': False})
        found = efa_help.web_label('Senders or domains that always pass; - for none')
        self.assertEqual((found['label'], found['clear']), ('Senders or domains that always pass', True))
        self.assertEqual(efa_help.web_label('Type yes to confirm', 'confirm')['label'], 'Yes, do it')
        found = efa_help.web_label('Outside the private ranges: type yes')
        self.assertEqual((found['label'], found['yes']), ('Outside the private ranges', True))
        self.assertEqual(efa_help.web_label('Text, \\n for a new line (with HTML: the text version, empty makes one)')['placeholder'], '')

    def test_first_sentence(self):
        self.assertEqual(efa_help.first_sentence('One. Two.'), 'One.')
        self.assertEqual(efa_help.first_sentence('Only one.'), 'Only one.')
        self.assertEqual(efa_help.short_title('Fail2Ban: switch'), 'Fail2Ban')
        self.assertEqual(efa_help.short_title('Failed logins: lockout'), 'Failed logins: lockout')


if __name__ == '__main__':
    unittest.main()
