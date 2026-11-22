# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""2026-11-18 nginx flaws: the check after a package change names an nginx below the release the vendor fixed, and restarts
(never reloads) nginx that was updated after it started, only when nginx -t takes its settings."""

import importlib.machinery
import importlib.util
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))

try:
    import rpm
    OLDER = lambda a, b: rpm.labelCompare(tuple(a), tuple(b)) < 0  # noqa: E731
except ImportError:
    rpm = None


def load_efactl():
    loader = importlib.machinery.SourceFileLoader('efactl_nginx_evr', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_nginx_evr', loader))
    loader.exec_module(module)
    return module


class FakePlatform:
    def __init__(self, active=True, installed=0, started=0):
        self.active, self.installed, self.started, self.restarted = active, installed, started, []

    def service_is_active(self, name):
        return self.active

    def package_install_time(self, package):
        return self.installed

    def service_started_at(self, name):
        return self.started

    def service_restart(self, name, check=True):
        self.restarted.append(name)


class NginxMinEvr(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    @unittest.skipIf(rpm is None, 'python3-rpm: the comparison of rpm itself')
    def test_fixed_release_per_vendor_and_branch(self):
        finding = self.efactl.nginx_fixed_finding
        alma10, alma9 = ('almalinux', '10'), ('almalinux', '9')
        self.assertIn('lacks the fixes', finding(alma10, ('2', '1.26.3', '16.el10_3.1.alma.1'), OLDER))
        self.assertIn('lacks the fixes', finding(alma10, ('2', '1.26.3', '16.el10_3.1.alma.2'), OLDER), 'alma.2 has only the HTTP/2 fixes')
        self.assertEqual(finding(alma10, ('2', '1.26.3', '16.el10_3.1.alma.3'), OLDER), '')
        self.assertIn('lacks the fixes', finding(alma9, ('2', '1.26.3', '10.module_el9.9.0+349+968a5dd9.1'), OLDER))
        self.assertEqual(finding(alma9, ('2', '1.26.3', '10.module_el9.9.0+357+ccfac862.1.alma.2'), OLDER), '')
        self.assertIn('lacks the fixes', finding(alma9, ('2', '1.20.1', '28.el9_8.6.alma.1'), OLDER), 'the default stream 1.20')
        self.assertEqual(finding(alma9, ('2', '1.20.1', '32.el9_9.1.alma.4'), OLDER), '')
        # RHEL and Rocky name their fixed releases otherwise: no claim, the CVE watch of their errata counts.
        self.assertEqual(finding(('rhel', '10'), ('2', '1.26.3', '16.el10_3.1'), OLDER), '')
        self.assertEqual(finding(('rocky', '9'), ('2', '1.26.3', '10.module+el9.9.0+1.1'), OLDER), '')
        self.assertEqual(finding(alma10, None, OLDER), '')

    def test_no_hard_requires_on_an_alma_release(self):
        for spec in ('eFa.spec', 'eFa-base.spec'):
            text = open(os.path.join(ROOT, 'rpm', spec), encoding='utf-8').read()
            self.assertNotRegex(text, r'Requires:.*nginx.*alma', 'it would refuse RHEL and Rocky')

    def test_updated_nginx_restarts_after_nginx_t(self):
        efactl, audited = self.efactl, []
        ok = types.SimpleNamespace(returncode=0, stdout='', stderr='')
        refused = types.SimpleNamespace(returncode=1, stdout='', stderr='emerg')
        with mock.patch.object(efactl, '_audit', audited.append):
            platform_now = FakePlatform(installed=2000, started=1000)
            with mock.patch.object(efactl.subprocess, 'run', lambda command, **k: ok):
                self.assertEqual(efactl.nginx_after_update(platform_now), '')
            self.assertEqual(platform_now.restarted, ['nginx'], 'a restart, not a reload')
            self.assertTrue(any('restarted after its package update' in text for text in audited))
            stays = FakePlatform(installed=2000, started=1000)
            with mock.patch.object(efactl.subprocess, 'run', lambda command, **k: refused):
                self.assertIn('nginx -t refuses', efactl.nginx_after_update(stays))
            self.assertEqual(stays.restarted, [], 'a config nginx refuses: it keeps running')
            for quiet in (FakePlatform(installed=1000, started=2000), FakePlatform(active=False, installed=2000, started=1000),
                          FakePlatform(installed=0, started=1000)):
                with mock.patch.object(efactl.subprocess, 'run', lambda command, **k: self.fail('no nginx -t')):
                    self.assertEqual(efactl.nginx_after_update(quiet), '')
                self.assertEqual(quiet.restarted, [])

    def test_os_release_id(self):
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='-os-release') as f:
            f.write('NAME="AlmaLinux"\nID="almalinux"\nVERSION_ID="10.3"\n')
        self.addCleanup(os.remove, f.name)
        self.assertEqual(self.efactl._os_release_id(f.name), ('almalinux', '10'))

    def test_every_package_change_runs_it(self):
        source = open(os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'), encoding='utf-8').read()
        body = source[source.index('def os_check_run('):]
        body = body[:body.index('\ndef ')]
        self.assertIn('nginx_after_update(platform_now)', body)
        self.assertIn('nginx_fixed_finding(', body)
        path = open(os.path.join(ROOT, 'next', 'usr', 'lib', 'systemd', 'system', 'efa-os-check.path'), encoding='utf-8').read()
        self.assertIn('PathChanged=/var/lib/rpm/rpmdb.sqlite', path)


if __name__ == '__main__':
    unittest.main()
