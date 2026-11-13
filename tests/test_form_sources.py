# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""A form field with a default or a pulldown takes the value in effect, never its default: its source key is not optional."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'next', 'usr', 'lib', 'eFa', 'python'))
import efa_nav  # noqa: E402


class FormSourceTests(unittest.TestCase):
    def test_optional_source_of_a_pulldown_is_found(self):
        forms = {'network-set': ('network-show', {'ipv6_method': '?ipv6.method', 'ipv6_address': '?ipv6.addresses'})}
        args = {'network-set': [{'name': 'ipv6_method', 'default': 'ignore'}, {'name': 'ipv6_address'}]}
        found = efa_nav.optional_source_problems(forms, args.get, {})
        self.assertEqual(len(found), 1)
        self.assertIn('ipv6_method', found[0])
        found = efa_nav.optional_source_problems(forms, lambda name: [{'name': 'ipv6_method'}], {('network-set', 'ipv6_method'): ('IPv6', [])})
        self.assertEqual(len(found), 1, 'a pulldown of ARG_CHOICES counts too')

    def test_network_form_takes_the_value_in_effect(self):
        self.assertEqual(efa_nav.FORM_SOURCE['network-set'][1]['ipv6_method'], 'ipv6.method')


if __name__ == '__main__':
    unittest.main()
