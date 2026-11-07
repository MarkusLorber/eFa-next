# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Translations of the interfaces through the gettext interface of Python. The catalogs are plain .po files: read once,
no compiled .mo files, no tools to build them. English is the source language and needs no catalog."""
import gettext
import os
import re

LOCALE_DIR = os.environ.get('EFA_LOCALE', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'share', 'eFa', 'locale'))
LANGUAGES = ('en', 'de')
_catalogs = {}


def po_entries(text):
    """msgid and msgstr pairs of a .po file; continued lines are joined, escapes undone. Untranslated entries are left out."""
    entries, key, current, field = {}, None, None, None

    def unquote(part):
        return re.sub(r'\\(.)', lambda m: {'n': '\n', 't': '\t'}.get(m.group(1), m.group(1)), part[1:-1])

    def store():
        if key and current:
            entries[key] = current
    for line in text.splitlines() + ['']:
        line = line.strip()
        if line.startswith('msgid '):
            store()
            key, current, field = unquote(line[6:]), None, 'id'
        elif line.startswith('msgstr '):
            current, field = unquote(line[7:]), 'str'
        elif line.startswith('"') and field == 'id':
            key += unquote(line)
        elif line.startswith('"') and field == 'str':
            current += unquote(line)
        elif not line:
            store()
            key = current = field = None
    return entries


class Catalog(gettext.NullTranslations):
    def __init__(self, entries):
        super().__init__()
        self.entries = entries

    def gettext(self, message):
        return self.entries.get(message, message)

    def ngettext(self, singular, plural, n):
        return self.gettext(singular if n == 1 else plural)


def catalog(language):
    """The translations of a language; English and unknown languages give the text back unchanged."""
    if language not in _catalogs:
        path = os.path.join(LOCALE_DIR, f'{language}.po')
        try:
            with open(path, encoding='utf-8') as f:
                _catalogs[language] = Catalog(po_entries(f.read()))
        except OSError:
            _catalogs[language] = Catalog({})
    return _catalogs[language]


def pick(wanted, accept):
    """The language of My settings, else the first of the browser eFa knows, else English."""
    if wanted in LANGUAGES:
        return wanted
    for item in (accept or '').split(','):
        code = item.split(';')[0].strip().lower()[:2]
        if code in LANGUAGES:
            return code
    return 'en'


def self_test():
    entries = po_entries('msgid ""\nmsgstr "Content-Type: text/plain"\n\nmsgid "Dashboard"\nmsgstr "Übersicht"\n\n'
                         'msgid "Long "\n"text"\nmsgstr "Langer "\n"Text"\n\nmsgid "Not yet"\nmsgstr ""\n\nmsgid "Line\\nbreak"\nmsgstr "Zeile\\nUmbruch"\n')
    assert entries == {'Dashboard': 'Übersicht', 'Long text': 'Langer Text', 'Line\nbreak': 'Zeile\nUmbruch'}, entries
    german = Catalog(entries)
    assert german.gettext('Dashboard') == 'Übersicht' and german.gettext('Not yet') == 'Not yet' and german.ngettext('Dashboard', 'x', 1) == 'Übersicht'
    assert pick('de', '') == 'de' and pick('auto', 'fr-FR,de-AT;q=0.8') == 'de' and pick('auto', 'fr') == 'en' and pick('', None) == 'en'
    assert catalog('xx').gettext('a') == 'a'
    print('self-test ok')


if __name__ == '__main__':
    self_test()
