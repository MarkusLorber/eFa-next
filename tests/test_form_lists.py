# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""The form lists of efa_nav name only commands efactl has. A missing comma between two names joins them into one string
(implicit concatenation), which silently drops both from the list."""

import importlib.machinery
import importlib.util
import os
import sys
import tokenize
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
NAV = os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python', 'efa_nav.py')
sys.path.insert(0, os.path.dirname(NAV))


def load_efactl():
    loader = importlib.machinery.SourceFileLoader('efactl_form_lists', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_form_lists', loader))
    loader.exec_module(module)
    return module


class FormLists(unittest.TestCase):
    def test_every_name_is_an_efactl_command(self):
        import efa_nav
        commands = set(load_efactl().COMMANDS)
        unknown = {name: sorted(set(getattr(efa_nav, name)) - commands) for name in ('FORM_NEW', 'FORM_KEYED', 'FORM_SOURCE')}
        self.assertEqual({name: items for name, items in unknown.items() if items}, {})
        self.assertEqual(sorted({source for source, _keys in efa_nav.FORM_SOURCE.values()} - commands), [], 'status commands of FORM_SOURCE')

    def test_no_two_command_names_side_by_side(self):
        # Two string tokens in a row (newlines and comments between them do not count) are one string to Python.
        # Only short command-like names count: long texts are split over lines on purpose.
        name = lambda text: text[1:-1].replace('-', '').isalnum() and len(text) < 40 and text[0] in '\'"'  # noqa: E731
        found, previous = [], None
        with open(NAV, encoding='utf-8') as f:
            for token in tokenize.generate_tokens(f.readline):
                if token.type in (tokenize.NL, tokenize.NEWLINE, tokenize.COMMENT):
                    if token.type == tokenize.NEWLINE:
                        previous = None
                    continue
                if token.type == tokenize.STRING and previous is not None and name(previous.string) and name(token.string):
                    found.append((token.start[0], previous.string, token.string))
                previous = token if token.type == tokenize.STRING else None
        self.assertEqual(found, [], 'a missing comma joins two names into one string')


if __name__ == '__main__':
    unittest.main()
