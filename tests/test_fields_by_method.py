# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""2026-11-17 (UI review): a form shows only the fields of the chosen method (schema 'when', copy.js hides and disables the
others): network and interface (static), backup target (S3 or SFTP, own server), OpenTelemetry (auth)."""
import unittest

from test_threat import load_efactl


class FieldsByMethod(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def when(self, command):
        return {arg['name']: arg['when'] for arg in self.efactl.COMMANDS[command]['args'] if arg.get('when')}

    def test_rules(self):
        self.assertEqual(self.when('interface-set'), {'address': 'method=manual', 'gateway': 'method=manual', 'dns': 'method=manual'})
        self.assertEqual(self.when('backup-target-set'), {
            'endpoint': 'kind=s3', 'bucket': 'kind=s3', 'region': 'kind=s3', 'access_key': 'kind=s3', 'secret_key': 'kind=s3',
            'secret_key2': 'kind=s3', 'host': 'kind=sftp', 'port': 'kind=sftp', 'user': 'kind=sftp', 'key_file': 'kind=sftp',
            'eu_confirm': 'provider=own'})
        self.assertEqual(self.when('network-set'), {'address': 'method=manual', 'gateway': 'method=manual',
                                                     'ipv6_address': 'ipv6_method=manual', 'ipv6_gateway': 'ipv6_method=manual'})

    def test_every_rule_names_a_field_with_that_value(self):
        for name, command in self.efactl.COMMANDS.items():
            args = {arg['name']: arg for arg in command['args']}
            for arg in command['args']:
                if not arg.get('when'):
                    continue
                field, _sep, value = arg['when'].replace('!=', '=').partition('=')
                with self.subTest(command=name, arg=arg['name']):
                    self.assertIn(field, args)
                    choices = [item['value'] for item in args[field].get('choices') or []] or \
                              [value for (cmd, arg_name), (_label, options) in self.efactl.ARG_CHOICES.items()
                               if (cmd, arg_name) == (name, field) for value, _text in options]
                    if field != 'provider':
                        self.assertIn(value, choices, 'the value is one of the choices of that field')


if __name__ == '__main__':
    unittest.main()
