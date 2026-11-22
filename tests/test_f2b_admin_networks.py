# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""6.0.0.6.7, the fail2ban lockout after a cluster join: settings files get the owner of the table, the admin networks of the
web allowlist are never banned by the jails of the admin ways in (only explicit networks, never the mail jails)."""

import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))
import efa_cluster  # noqa: E402


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, os.path.join(ROOT, *path.split('/')))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


class AdminExemptNetworks(unittest.TestCase):
    def test_only_explicit_networks_while_the_list_is_on(self):
        entries = [{'network': '198.51.100.0/24'}, {'network': '2001:db8:1::/48'}]
        self.assertEqual(efa_cluster.admin_exempt_networks({'mode': 'allowed', 'entries': entries}), ['198.51.100.0/24', '2001:db8:1::/48'])
        self.assertEqual(efa_cluster.admin_exempt_networks({'mode': 'all', 'entries': entries}), [], 'list off: "all" exempts nothing')
        self.assertEqual(efa_cluster.admin_exempt_networks({'mode': 'allowed', 'entries': []}), [], 'an empty list exempts nothing')
        self.assertEqual(efa_cluster.admin_exempt_networks({}), [])
        self.assertEqual(efa_cluster.admin_exempt_networks(None), [])

    def test_no_entry_as_wide_as_the_internet(self):
        wide = [{'network': '0.0.0.0/0'}, {'network': '::/0'}, {'network': '0.0.0.0/1'}, {'network': '128.0.0.0/1'},
                {'network': '10.0.0.0/7'}, {'network': '2001::/16'}]
        self.assertEqual(efa_cluster.admin_exempt_networks({'mode': 'allowed', 'entries': wide}), [])
        self.assertEqual(efa_cluster.admin_exempt_networks({'mode': 'allowed', 'entries': wide + [{'network': '10.0.0.0/8'}]}), ['10.0.0.0/8'])

    def test_broken_entries_are_skipped(self):
        broken = [{'network': 'nonsense'}, {'network': None}, 'text', {}, {'network': '198.51.100.7'}]
        self.assertEqual(efa_cluster.admin_exempt_networks({'mode': 'allowed', 'entries': broken}), ['198.51.100.7/32'])

    def test_never_the_mail_jails(self):
        self.assertNotIn('postfix-sasl', efa_cluster.ADMIN_EXEMPT_JAILS)
        self.assertNotIn('efa-harvest', efa_cluster.ADMIN_EXEMPT_JAILS)

    def test_unban_in_one_jail_only(self):
        calls = []
        efa_cluster.f2b_unban('198.51.100.7', run=lambda command, **k: calls.append(command), jail='efa-web')
        efa_cluster.f2b_unban('198.51.100.7', run=lambda command, **k: calls.append(command))
        self.assertEqual(calls, [['fail2ban-client', 'set', 'efa-web', 'unbanip', '198.51.100.7'], ['fail2ban-client', 'unban', '198.51.100.7']])


class Jails(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load('efactl_f2b', 'next/usr/sbin/efactl')

    def test_mail_jails_without_the_admin_networks(self):
        efactl = self.efactl
        settings = {**efactl.LOCKOUT_DEFAULTS, 'repeat': True}
        text = efactl.lockout_jail(settings, ['127.0.0.1/8'], ['127.0.0.1/8', '198.51.100.0/24'])
        web, rest = text.split('[postfix-sasl]')
        mail, recidive = rest.split('[recidive]')
        self.assertIn('198.51.100.0/24', web)
        self.assertNotIn('198.51.100.0/24', mail)
        self.assertIn('198.51.100.0/24', recidive)
        never = efactl.never_jail(['127.0.0.1/8', '198.51.100.0/24'])
        self.assertNotIn('[DEFAULT]', never, 'DEFAULT would reach postfix-sasl of efa.local')
        self.assertNotIn('postfix', never)
        self.assertEqual(never.count('ignoreip = 127.0.0.1/8 198.51.100.0/24\n'), 3)
        self.assertGreater(os.path.basename(efactl.FAIL2BAN_NEVER_JAIL), os.path.basename(efactl.LOCKOUT_JAIL), 'read after the lockout jail')

    def test_harvest_jail_keeps_its_own_list(self):
        efactl = self.efactl
        settings = {'tries': 5, 'minutes': 10, 'hours': 1, 'allow': []}
        with mock.patch.object(efactl, 'harvest_ignore', lambda s: ['127.0.0.1/8']), \
                mock.patch.object(efactl, 'admin_networks', lambda: ['198.51.100.0/24']):
            self.assertNotIn('198.51.100.0/24', efactl.harvest_jail(settings))
            self.assertEqual(efactl.fail2ban_never(settings), ['127.0.0.1/8', '198.51.100.0/24'])

    def test_refresh_lifts_only_bans_of_admin_ways_in(self):
        efactl = self.efactl
        lifted = []
        fake = types.SimpleNamespace(ADMIN_EXEMPT_JAILS=efa_cluster.ADMIN_EXEMPT_JAILS,
                                     f2b_banned=lambda: {('efa-web', '198.51.100.7'), ('postfix-sasl', '198.51.100.8'), ('efa-web', '192.0.2.9')},
                                     f2b_unban=lambda address, jail=None: lifted.append((jail, address)))
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(efactl, 'FAIL2BAN_NEVER_JAIL', os.path.join(folder, 'jail.d', 'efa.never.local')), \
                mock.patch.object(efactl, 'ETC', folder), mock.patch.object(efactl.shutil, 'which', lambda name: '/usr/bin/' + name), \
                mock.patch.object(efactl, '_harvest_settings', lambda: {'mode': 'off', 'allow': []}), \
                mock.patch.object(efactl, '_lockout_settings', lambda: {'mode': 'off'}), \
                mock.patch.object(efactl, 'harvest_ignore', lambda s: ['127.0.0.1/8']), \
                mock.patch.object(efactl, 'admin_networks', lambda: ['198.51.100.0/24']), \
                mock.patch.object(efactl, '_lib', lambda name: fake), \
                mock.patch.object(efactl, '_write', lambda path, text, *a: None):
            os.makedirs(os.path.join(folder, 'fail2ban', 'jail.d'))
            efactl.fail2ban_never_refresh(restart=False)
        self.assertEqual(lifted, [('efa-web', '198.51.100.7')], 'not the mail jail, not an address outside')


class SettingsOwner(unittest.TestCase):
    def test_cluster_sync_heals_settings_files(self):
        cluster = load('efa_cluster_service_f2b', 'next/usr/local/sbin/efa-cluster.py')
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            return types.SimpleNamespace(returncode=0, stdout='', stderr='')
        with tempfile.TemporaryDirectory() as etc:
            os.makedirs(os.path.join(etc, 'eFa'))
            data = __import__('base64').b64encode(json.dumps({'mode': 'allowed'}).encode()).decode()
            with mock.patch.object(cluster, 'ETC', etc):
                problem = cluster.apply({'type': 'files', 'files': [{'path': 'eFa/web-allowlist.json', 'data': data, 'mode': 0o640}]}, run=run)
                self.assertIsNone(problem)
                self.assertEqual(calls, [[cluster.EFACTL, 'conf-modes-heal']])
                failing = cluster.apply({'type': 'files', 'files': [{'path': 'eFa/web-allowlist.json', 'data': data, 'mode': 0o640}]},
                                        run=lambda command, **k: types.SimpleNamespace(returncode=1, stdout='', stderr='no group'))
                self.assertIn('conf-modes-heal', failing, 'a failed heal is a failed entry, not silence')
                calls.clear()
                cluster.apply({'type': 'files', 'files': [{'path': 'other.conf', 'data': data, 'mode': 0o644}]}, run=run)
                self.assertEqual(calls, [], 'no heal for files outside /etc/eFa/*.json')

    def test_protected_networks_take_only_explicit_admin_networks(self):
        cluster = load('efa_cluster_service_f2b2', 'next/usr/local/sbin/efa-cluster.py')
        with tempfile.TemporaryDirectory() as etc:
            os.makedirs(os.path.join(etc, 'eFa'))
            path = os.path.join(etc, 'eFa', 'web-allowlist.json')
            with mock.patch.object(cluster, 'ETC', etc):
                with open(path, 'w') as f:
                    json.dump({'mode': 'allowed', 'entries': [{'network': '198.51.100.0/24'}, {'network': '0.0.0.0/0'}]}, f)
                self.assertEqual(cluster.protected_networks({}), ['198.51.100.0/24'])
                with open(path, 'w') as f:
                    json.dump({'mode': 'all', 'entries': [{'network': '198.51.100.0/24'}]}, f)
                self.assertEqual(cluster.protected_networks({}), [])


if __name__ == '__main__':
    unittest.main()
