# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""Hans 2026-11-20 (criterion 3 of 6.0.0.6): the base system updates with a plain dnf in its branch. After a package change
the services of eFa-next that still run a replaced file restart, the base first; never firewalld, nginx (its own way after
nginx -t) or a unit that runs the check or an update. The packages require third-party software only with a minimum version."""

import importlib.machinery
import importlib.util
import os
import re
import types
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')


def load_efactl():
    loader = importlib.machinery.SourceFileLoader('efactl_third_party', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_third_party', loader))
    loader.exec_module(module)
    return module


class ThirdPartyUpdates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = load_efactl()

    def test_order_and_never(self):
        stale = ['polkit.service', 'efa-web.service', 'redis.service', 'firewalld.service', 'nginx.service', 'clamd@scan.service',
                 'efa-os-check.service', 'efa-update-system.service', 'efactl-runner.service', 'efa-milter-health.service',
                 'postfix.service', 'mariadb.service', 'efa-autoupdate-now.service']
        self.assertEqual(self.e.services_to_restart(stale),
                         ['mariadb', 'redis', 'clamd@scan', 'postfix', 'efa-milter-health', 'efa-web'])
        self.assertEqual(self.e.services_to_restart(iter(['crond.service'])), [], 'a service not of eFa-next stays')

    def test_restart_and_audit(self):
        restarted, audit = [], []
        platform = types.SimpleNamespace(service_restart=lambda name, check=True: restarted.append(name))
        answer = types.SimpleNamespace(returncode=0, stdout='rspamd.service\nfirewalld.service\nefa-web.service\n', stderr='')
        with mock.patch.object(self.e.shutil, 'which', lambda name: '/usr/bin/' + name), \
                mock.patch.object(self.e.subprocess, 'run', lambda *a, **k: answer), mock.patch.object(self.e, '_audit', audit.append):
            self.assertEqual(self.e.restart_stale_services(platform), ['rspamd', 'efa-web'])
        self.assertEqual(restarted, ['rspamd', 'efa-web'])
        self.assertIn('rspamd, efa-web', audit[0])
        with mock.patch.object(self.e.shutil, 'which', lambda name: None):
            self.assertEqual(self.e.restart_stale_services(platform), [], 'without needs-restarting nothing restarts')

    def test_python_module_update_restarts_the_python_services(self):
        # needs-restarting does not see a replaced .py module: a service started before the package update restarts.
        platform = types.SimpleNamespace(package_install_time=lambda name: 2000 if name == 'python3-flask' else 100,
                                         service_is_active=lambda name: name != 'efa-sandbox',
                                         service_started_at=lambda name: {'efa-web': 1500, 'efa-cdr': 2500}.get(name, 0))
        units = ['/usr/lib/systemd/system/' + n for n in ('efa-web.service', 'efa-cdr.service', 'efa-sandbox.service', 'efa-scan@.service')]
        with mock.patch.object(self.e.glob, 'glob', lambda pattern: units):
            self.assertEqual(self.e._python_stale_services(platform), ['efa-web.service'], 'started before the update, active')

    def test_third_party_only_with_a_minimum(self):
        # Never an upper pin on the base system in the packages: >= only; = only on the own eFa-next-base.
        for spec in ('rpm/eFa.spec', 'rpm/eFa-base.spec'):
            with open(os.path.join(ROOT, spec), encoding='utf-8') as f:
                for line in f:
                    if not re.match(r'(Requires|Conflicts):', line):
                        continue
                    self.assertNotRegex(line, r'<|^Conflicts', f'{spec}: {line.strip()}')
                    if re.search(r'(?<![<>])=(?!=)', line.replace('>=', '')):
                        self.assertIn('eFa-next-base', line, f'{spec}: {line.strip()}')


if __name__ == '__main__':
    unittest.main()
