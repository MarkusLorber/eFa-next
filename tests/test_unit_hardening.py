# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""5v (h): every long-running eFa-next service that runs as its own user has a sandbox drop-in, the full one unless it still
needs sudo; and systemd-analyze verify takes the units where systemd is there."""
import configparser
import glob
import os
import shutil
import subprocess
import unittest

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UNITS = os.path.join(TOP, 'next', 'usr', 'lib', 'systemd', 'system')
FULL = {'NoNewPrivileges', 'CapabilityBoundingSet', 'SystemCallFilter', 'RestrictAddressFamilies', 'ProtectKernelModules'}
# These still start a program through sudo, which needs setuid and its capabilities: only the limits that leave sudo working.
SUDO = {'efa-dkim-api.service', 'efa-init.service'}
SUDO_MIN = {'ProtectControlGroups'}
# With a user of its own, every one of these makes systemd set NoNewPrivileges, and sudo stops working.
SUDO_NEVER = {'NoNewPrivileges', 'CapabilityBoundingSet', 'ProtectSystem', 'RestrictSUIDSGID', 'SystemCallFilter', 'ProtectKernelModules',
              'ProtectKernelLogs', 'ProtectClock', 'ProtectHostname', 'RestrictNamespaces', 'RestrictRealtime', 'LockPersonality',
              'SystemCallArchitectures', 'RestrictAddressFamilies', 'MemoryDenyWriteExecute', 'PrivateDevices'}


def settings(path):
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read(path, encoding='utf-8')
    return parser


class UnitHardeningTests(unittest.TestCase):
    def service_units(self):
        """Long-running services with a user of their own (not root)."""
        for path in sorted(glob.glob(os.path.join(UNITS, '*.service'))):
            service = settings(path)['Service'] if settings(path).has_section('Service') else {}
            user = service.get('User', 'root')
            if service.get('Type', 'simple') == 'simple' and user != 'root':
                yield os.path.basename(path)

    def dropin_keys(self, name):
        keys = set()
        for path in glob.glob(os.path.join(UNITS, name + '.d', '*.conf')):
            parsed = settings(path)
            if parsed.has_section('Service'):
                keys |= set(parsed['Service'])
        unit = settings(os.path.join(UNITS, name))
        if unit.has_section('Service'):
            keys |= set(unit['Service'])
        return keys

    def test_every_own_user_service_is_sandboxed(self):
        names = list(self.service_units())
        self.assertIn('efa-dkim-api.service', names)
        for name in names:
            keys = self.dropin_keys(name)
            if name in SUDO:
                self.assertTrue(SUDO_MIN <= keys, (name, sorted(SUDO_MIN - keys)))
                self.assertFalse(SUDO_NEVER & keys, (name, 'would break sudo', sorted(SUDO_NEVER & keys)))
            else:
                self.assertTrue(FULL <= keys, (name, sorted(FULL - keys)))

    @unittest.skipUnless(shutil.which('systemd-analyze'), 'systemd-analyze is not there')
    def test_systemd_analyze_verify(self):
        for name in ('efa-dkim-api.service', 'efa-init.service'):
            done = subprocess.run(['systemd-analyze', 'verify', '--man=no', os.path.join(UNITS, name)], capture_output=True, text=True)
            self.assertNotIn('Unknown key', done.stderr, done.stderr)
            self.assertNotIn('Unknown lvalue', done.stderr, done.stderr)


if __name__ == '__main__':
    unittest.main()
