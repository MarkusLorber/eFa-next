#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Collects the texts of the interfaces into next/usr/share/eFa/locale/<lang>.po. Existing translations are kept.

    i18n_extract.py            write the catalogs
    i18n_extract.py --check    only count the translated and the missing texts
"""
import ast
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))
import efa_i18n  # noqa: E402
import efa_nav  # noqa: E402

LOCALE = os.path.join(ROOT, 'next', 'usr', 'share', 'eFa', 'locale')
WEB = os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-web.py')
EFACTL = os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl')


def strings(pattern, path):
    with open(path, encoding='utf-8') as f:
        text = f.read()
    return [ast.literal_eval(found) for found in re.findall(pattern, text)]


def texts():
    """The texts in the order they appear: menu, pages, commands, then the fixed texts of the templates."""
    found = []
    for group, pages in efa_nav.NAV:
        found.append(group)
        for page in pages:
            found += [page['title'], page.get('sub', '')]
            found += [section[0] for section in page.get('sections', [])]
            found += list(page.get('notes', {}).values())
    quoted = r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")"""
    found += strings(r"'(?:title|label)': " + quoted, EFACTL)
    found += strings(r"\b_\(" + quoted + r"\)", WEB)
    found += strings(r"\btile\(" + quoted, WEB)
    seen, ordered = set(), []
    for item in found:
        if item and item not in seen and not item.startswith(('http', '/')):
            seen.add(item)
            ordered.append(item)
    return ordered


def quote(text):
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'


def write(language, wanted):
    path = os.path.join(LOCALE, f'{language}.po')
    old = efa_i18n.po_entries(open(path, encoding='utf-8').read()) if os.path.exists(path) else {}
    lines = ['# SPDX-License-Identifier: AGPL-3.0-or-later', f'# {language} texts of the eFa-next interfaces. Written by scripts/i18n_extract.py:',
             '# fill in msgstr, then run it again; texts that are gone are dropped.', 'msgid ""', 'msgstr "Content-Type: text/plain; charset=UTF-8\\n"', '']
    for text in wanted:
        lines += [f'msgid {quote(text)}', f'msgstr {quote(old.get(text, ""))}', '']
    os.makedirs(LOCALE, exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines))
    return sum(1 for text in wanted if old.get(text)), len(wanted)


def main():
    wanted = texts()
    for language in efa_i18n.LANGUAGES:
        if language == 'en':
            continue
        if '--check' in sys.argv:
            path = os.path.join(LOCALE, f'{language}.po')
            text = open(path, encoding='utf-8').read() if os.path.exists(path) else ''
            old = efa_i18n.po_entries(text)
            done = sum(1 for item in wanted if old.get(item))
            listed = set(re.findall(r'^msgid (".*")$', text, re.M))
            # A new text must be in the catalog, even untranslated: run this script after changing texts.
            if any(quote(item) not in listed for item in wanted):
                print(f'i18n: {language}.po misses new texts, run scripts/i18n_extract.py')
                return 1
        else:
            done, _total = write(language, wanted)
        print(f'i18n: {language} {done} of {len(wanted)} texts translated')
    return 0


if __name__ == '__main__':
    sys.exit(main())
