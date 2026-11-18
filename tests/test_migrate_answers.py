# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""efa-migrate: a clone renamed to *.localdomain keeps the domain of eFa-Config, and settings that efa-apply would refuse stop
the migration before the old system is removed (before, "configuring" failed after the removal)."""
import importlib.machinery
import importlib.util
import os
import sys
import types
from unittest import mock

for name in ('grp', 'pwd'):
    sys.modules.setdefault(name, __import__(name) if importlib.util.find_spec(name) else types.ModuleType(name))
from efa_testlib import RootTestCase, TOP  # noqa: E402

sys.path.insert(0, os.path.join(TOP, 'next', 'usr', 'lib', 'eFa', 'python'))
import efa5_convert  # noqa: E402

_loader = importlib.machinery.SourceFileLoader('efa_migrate', os.path.join(TOP, 'migration', 'efa-migrate'))
migrate = importlib.util.module_from_spec(importlib.util.spec_from_loader('efa_migrate', _loader))
_loader.exec_module(migrate)

EFA_CONFIG = {'HOSTNAME': 'MX1', 'DOMAINNAME': 'example.org', 'ADMINEMAIL': 'postmaster@example.org', 'TZONE': 'Europe/Berlin',
              'ISUTC': 'YES', 'IPV6ADDRESS': '--', 'IPV6GATEWAY': '--', 'MAILSERVER': '10.0.0.5', 'INTERFACE': 'eth0'}


def plan_of(hostname):
    config = efa5_convert.live_config(EFA_CONFIG, hostname, '10.0.0.4/24', 'Europe/Berlin')
    return {'config': config, 'ipv6dns': False}


class LiveNameTests(RootTestCase):
    def test_clone_with_localdomain_keeps_domain_of_efa_config(self):
        plan = plan_of('mx1-clone.localdomain')
        self.assertEqual((plan['config']['HOSTNAME'], plan['config']['DOMAINNAME']), ('mx1-clone', 'example.org'))
        self.assertEqual(migrate.answers_problem(plan), '')

    def test_real_rename_wins(self):
        plan = plan_of('mx2.mail.example.net')
        self.assertEqual((plan['config']['HOSTNAME'], plan['config']['DOMAINNAME']), ('mx2', 'mail.example.net'))
        self.assertEqual(migrate.answers_problem(plan), '')

    def test_invalid_value_is_named(self):
        plan = plan_of('mx1.example.org')
        plan['config']['DOMAINNAME'] = 'localdomain'
        self.assertEqual(migrate.answers_problem(plan), "invalid value for DOMAINNAME (DOMAINNAME: 'localdomain')")


class AbortBeforeRemovalTests(RootTestCase):
    def run_main(self, plan):
        removed = []
        stubs = {'db_root_problem': lambda: '', 'collect': lambda: plan, 'foreign_blockers': lambda: {},
                 'legal_confirm': lambda accept: 'a0366efbcb284dc9', 'fetch_rpms': lambda: self.root,
                 'preflight': lambda folder: removed.append('preflight') or [], 'backup': lambda *a: removed.append('backup'),
                 'remove_old': lambda *a: removed.append('remove_old'), 'pause_monitor': lambda: removed.append('pause_monitor')}
        with mock.patch.multiple(migrate, **stubs), mock.patch.object(sys, 'argv', ['efa-migrate', '--execute-i-have-a-snapshot']), \
                mock.patch('sys.stderr', new_callable=lambda: __import__('io').StringIO()) as err:
            code = migrate.main()
        return code, removed, err.getvalue()

    def test_invalid_domain_stops_before_anything_changes(self):
        plan = plan_of('mx1.example.org')
        plan['config']['DOMAINNAME'] = 'localdomain'
        code, touched, err = self.run_main(plan)
        self.assertEqual(code, 2)
        self.assertEqual(touched, [], 'no download, backup, monitor pause or removal')
        self.assertIn("invalid value for DOMAINNAME (DOMAINNAME: 'localdomain')", err)
        self.assertIn('Nothing was changed.', err)


if __name__ == '__main__':
    import unittest
    unittest.main()
