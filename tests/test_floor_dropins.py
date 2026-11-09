# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The drop-ins of the security minimum on units of the distribution (postfix, nginx, dovecot) hold only the ExecStartPre of
efactl floor-check: no sandbox (0737fb9, SELinux). The package brings them and the path unit on install and update and takes
them away on removal."""

import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
UNITS = os.path.join(ROOT, 'next', 'usr', 'lib', 'systemd', 'system')


def lines(path):
    with open(path, encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip() and not line.lstrip().startswith('#')]


class FloorDropinTests(unittest.TestCase):
    def test_only_exec_start_pre(self):
        for service in ('postfix', 'nginx', 'dovecot'):
            folder = os.path.join(UNITS, service + '.service.d')
            self.assertEqual(os.listdir(folder), ['efa-floor.conf'], service)
            self.assertEqual(lines(os.path.join(folder, 'efa-floor.conf')),
                             ['[Service]', f'ExecStartPre=/usr/sbin/efactl floor-check --mode prestart --service {service}'])

    def test_path_unit_runs_the_check(self):
        service = lines(os.path.join(UNITS, 'efa-floor-guard.service'))
        self.assertIn('ExecStart=/usr/sbin/efactl floor-check --mode check', service)
        # Light on the host: lowest priority, and one check after a burst of changes.
        for setting in ('Nice=19', 'CPUSchedulingPolicy=idle', 'IOSchedulingClass=idle', 'ExecStartPre=/bin/sleep 5'):
            self.assertIn(setting, service)
        with open(os.path.join(ROOT, 'scripts', 'ci.sh'), encoding='utf-8') as f:
            ci = f.read()
        self.assertLess(ci.index('ActiveState --value efa-floor-guard.service'), ci.index('--budget-ms 100 < scripts/page_times.py'))
        self.assertIn('Unit=efa-floor-guard.service', lines(os.path.join(UNITS, 'efa-floor-guard.path')))

    def test_package_installs_and_removes(self):
        with open(os.path.join(ROOT, 'rpm', 'eFa.spec'), encoding='utf-8') as f:
            spec = f.read()
        sections = dict(re.findall(r'^(%posttrans|%preun|%postun)\n(.*?)(?=^%\w)', spec, re.M | re.S))
        self.assertLess(sections['%posttrans'].index('systemctl daemon-reload'), sections['%posttrans'].index('/usr/lib/eFa/setup/efa-next-setup'))
        self.assertIn('disable --now efa-floor-guard.path', sections['%preun'])
        self.assertIn('systemctl daemon-reload', sections['%postun'])
        # The files of next/ go into the package by its file list: the drop-ins come and go with it.
        self.assertIn('cp -a next/. %{buildroot}/', spec)
        with open(os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'setup', 'efa-next-setup'), encoding='utf-8') as f:
            setup = f.read()
        self.assertEqual(setup.count('efactl floor-check --mode apply'), 2)
        self.assertIn('p.service_enable("efa-floor-guard.path", start=True)', setup)


if __name__ == '__main__':
    unittest.main()
