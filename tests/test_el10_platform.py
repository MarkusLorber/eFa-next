# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The platform per release of Enterprise Linux: detect() by /etc/os-release (fixtures for EL9 and EL10), the EL10
differences (Valkey, lmdb tables), and the Postfix table type in the setup steps."""

import importlib.machinery
import importlib.util
import os
import sys
import types
import unittest
from unittest import mock

from efa_testlib import RootTestCase, c

import efa_platform
import efa_platform_el10
import efa_platform_el9
import efa_services as s

OS_RELEASE = {
    'el9': 'NAME="AlmaLinux"\nVERSION_ID="9.8"\nID="almalinux"\nID_LIKE="rhel centos fedora"\n',
    'el10': 'NAME="AlmaLinux"\nVERSION_ID="10.1"\nID="almalinux"\nID_LIKE="rhel centos fedora"\n',
    'rocky10': 'NAME="Rocky Linux"\nVERSION_ID="10.0"\nID="rocky"\nID_LIKE="rhel centos fedora"\n',
    'el8': 'NAME="AlmaLinux"\nVERSION_ID="8.10"\nID="almalinux"\nID_LIKE="rhel centos fedora"\n',
    'debian': 'NAME="Debian GNU/Linux"\nVERSION_ID="12"\nID=debian\n',
}


def load_efactl():
    """efactl as a module, as tests/test_efactl_calls.py loads it."""
    for name in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
        sys.modules.setdefault(name, __import__(name) if importlib.util.find_spec(name) else types.ModuleType(name))
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'next', 'usr', 'sbin', 'efactl')
    loader = importlib.machinery.SourceFileLoader('efactl_el10', path)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_el10', loader))
    loader.exec_module(module)
    return module


class Detect(RootTestCase):
    def detect(self, name):
        self.write('etc/os-release', OS_RELEASE[name])
        return efa_platform.detect()

    def test_releases(self):
        self.assertIs(type(self.detect('el9')), efa_platform_el9.EL9)
        self.assertIs(type(self.detect('el10')), efa_platform_el10.EL10)
        self.assertIs(type(self.detect('rocky10')), efa_platform_el10.EL10)
        for name in ('el8', 'debian'):
            with self.assertRaises(c.StepError):
                self.detect(name)


class Differences(unittest.TestCase):
    def test_valkey_on_el10(self):
        el9, el10 = efa_platform_el9.EL9(), efa_platform_el10.EL10()
        self.assertEqual(el9.service('redis'), 'redis')
        self.assertEqual(el10.service('redis'), 'valkey')
        self.assertEqual(el9.path('redis_conf'), '/etc/redis/redis.conf')
        self.assertEqual(el10.path('redis_conf'), '/etc/valkey/valkey.conf')
        self.assertEqual(el10.path('redis_dir'), '/var/lib/valkey')
        # Everything else stays as on EL9.
        self.assertEqual(el10.service('mta'), 'postfix')
        self.assertEqual(el10.path('cert_file'), el9.path('cert_file'))

    def test_release_data(self):
        el10 = efa_platform_el10.EL10()
        self.assertIn('centos-10', el10.REPOSITORIES['rspamd'])
        self.assertIn('EPEL 10', el10.REPOSITORIES['clamav'])
        self.assertEqual(el10.VERSIONS['python'], '3.12')
        self.assertFalse(el10.SHA1_SIGNATURES)
        self.assertTrue(efa_platform_el9.EL9.SHA1_SIGNATURES)


class Valkey(RootTestCase):
    def test_redis_calls_reach_valkey_on_el10(self):
        efa_platform_el10.EL10().service_restart('redis')
        efa_platform_el9.EL9().service_restart('redis')
        restarts = [call for call in self.runner.calls if call[:2] == ['systemctl', 'restart']]
        self.assertEqual(restarts, [['systemctl', 'restart', 'valkey'], ['systemctl', 'restart', 'redis']])

    def test_sandbox_of_valkey(self):
        """efactl service-harden on EL10: the drop-in for valkey.service with its folders, none for redis (an alias there)."""
        efactl = load_efactl()
        text = efactl.sandbox_text('valkey')
        self.assertIn('ReadWritePaths=/run /var/lib/valkey -/var/log/valkey', text)
        # Valkey runs as its own user: no option that implies NoNewPrivileges (its SELinux domain change).
        for option in ('NoNewPrivileges', 'ProtectKernelTunables', 'ProtectControlGroups', 'RestrictSUIDSGID'):
            self.assertNotIn(option, text)
        written = []
        el10 = efa_platform_el10.EL10()
        fake = mock.Mock(UNIT_ALIASES=el10.UNIT_ALIASES, service_exists=lambda name: True, service_is_active=lambda name: True,
                         service_hardening=lambda name, on: False, _dropin=lambda name, file, text: written.append(name) or True)
        with mock.patch.object(efactl, '_platform', return_value=fake), mock.patch.object(efactl, '_json_write'), \
                mock.patch.object(efactl, '_audit'), mock.patch.object(efactl, '_stays_active', return_value=True):
            efactl.service_harden(types.SimpleNamespace(mode='on'))
        self.assertIn('valkey', written)
        self.assertNotIn('redis', written)

    def test_cli_and_account(self):
        self.assertEqual(efa_platform_el10.EL10().path('redis_cli'), '/usr/bin/valkey-cli')
        self.assertEqual(efa_platform_el9.EL9().path('redis_cli'), '/usr/bin/redis-cli')
        self.assertEqual(efa_platform_el10.EL10().account('redis_user'), 'valkey')
        self.assertEqual(efa_platform_el9.EL9().account('redis_user'), 'redis')


class ActiveZones(unittest.TestCase):
    def test_firewalld_2_default_suffix(self):
        efactl = load_efactl()
        el9 ='public\n  interfaces: ens192\ntrusted\n  sources: 10.0.0.0/8\n'
        # firewalld 2 (EL10) marks the default zone on its line.
        el10 = 'public (default)\n  interfaces: enp0s3\ntrusted\n  sources: 10.0.0.0/8\n'
        self.assertEqual(efactl.active_zone_names(el9), ['public', 'trusted'])
        self.assertEqual(efactl.active_zone_names(el10), ['public', 'trusted'])
        self.assertEqual(efactl.active_zone_names(''), [])


class MapType(RootTestCase):
    def test_default_per_release(self):
        # The fake postconf answers hash for default_database_type, as EL9 does.
        self.assertEqual(efa_platform_el9.EL9().map_type(), 'hash')
        self.runner.explicit['default_database_type'] = 'lmdb'
        self.assertEqual(efa_platform_el9.EL9().map_type(), 'lmdb')
        self.runner.explicit['default_database_type'] = ''
        self.assertEqual(efa_platform_el10.EL10().map_type(), 'lmdb')
        self.runner.explicit['default_database_type'] = 'nonsense'
        self.assertEqual(efa_platform_el9.EL9().map_type(), 'hash')

    def test_setup_tables_follow_the_type(self):
        el9 = s.postfix_fixed('hash')
        self.assertEqual(el9['transport_maps'], 'hash:/etc/postfix/transport')
        self.assertTrue(el9['smtpd_tls_session_cache_database'].startswith('btree:'))
        el10 = s.postfix_fixed('lmdb')
        self.assertEqual(el10['transport_maps'], 'lmdb:/etc/postfix/transport')
        self.assertTrue(el10['smtpd_tls_session_cache_database'].startswith('lmdb:'))
        self.assertTrue(el10['smtp_tls_session_cache_database'].startswith('lmdb:'))
        self.assertNotIn('hash:', ' '.join(el10.values()))
        self.assertNotIn('btree:', ' '.join(el10.values()))


if __name__ == '__main__':
    unittest.main()
