# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""6.0.0.6.7: the cron file of the service monitor follows maintenance mode, which has a marker of its own. A cron file that
went missing without the marker (leapp removed eFa-next-base, which owns it as %ghost; the cleanup of an eFa 5 migration)
comes back; a host that lost it before the update keeps maintenance mode on, marked, and the admin decides."""

import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))


def load_efactl():
    loader = importlib.machinery.SourceFileLoader('efactl_moncron', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_moncron', loader))
    loader.exec_module(module)
    return module


class MonitorCron(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__('shutil').rmtree(folder, ignore_errors=True))
        os.makedirs(os.path.join(folder, 'cron.d'))
        os.makedirs(os.path.join(folder, 'eFa'))
        self.cron, self.marker = os.path.join(folder, 'cron.d', 'eFa-Monitor.cron'), os.path.join(folder, 'eFa', 'maintenance.json')
        self.audited, self.events = [], []
        efactl = self.efactl
        patches = [mock.patch.object(efactl, 'MONITOR_CRON', self.cron), mock.patch.object(efactl, 'MAINTENANCE_FILE', self.marker),
                   mock.patch.object(efactl, 'FIRSTBOOT_PENDING', os.path.join(folder, 'firstboot-pending')),
                   mock.patch.object(efactl, 'MONITOR_SKIP', os.path.join(folder, 'skipmonitor')),
                   mock.patch.object(efactl, '_audit', self.audited.append),
                   mock.patch.object(efactl, '_event', lambda name, severity='info', **f: self.events.append(name)),
                   mock.patch.object(efactl, '_dmarc_who', lambda: 'admin anna'),
                   mock.patch.object(efactl, '_write', lambda path, text, *a: open(path, 'w').write(text)),
                   mock.patch.object(efactl, '_json_write', lambda path, data, mode=0o640: json.dump(data, open(path, 'w')))]
        for patch in patches:
            patch.start()
        self.addCleanup(lambda: [patch.stop() for patch in reversed(patches)])
        self.folder = folder

    def maintenance(self, mode):
        return self.efactl.maintenance_set(type('Args', (), {'mode': mode})())

    def test_on_and_off_carry_the_marker(self):
        on = self.maintenance('on')
        self.assertFalse(os.path.exists(self.cron))
        self.assertEqual((on['maintenance_mode'], on['maintenance_by']), (True, 'admin anna'))
        self.assertEqual(self.efactl.monitor_cron_heal()['monitor_cron'], 'maintenance mode', 'maintenance is not healed away')
        self.assertFalse(os.path.exists(self.cron))
        off = self.maintenance('off')
        self.assertTrue(os.path.exists(self.cron) and not os.path.exists(self.marker))
        self.assertEqual(off, {'maintenance_mode': False})

    def test_a_lost_cron_file_comes_back(self):
        self.maintenance('off')
        os.remove(self.cron)  # leapp erased eFa-next-base (%ghost), or the eFa 5 cleanup took the same path
        self.assertEqual(self.efactl.monitor_cron_heal()['monitor_cron'], 'written again')
        self.assertIn('efa-monitor', open(self.cron).read())
        self.assertEqual(self.events, ['monitor_cron_restored'])
        self.assertTrue(any('written again' in text for text in self.audited))
        self.assertEqual(self.efactl.monitor_cron_heal()['monitor_cron'], 'ok')

    def test_the_update_keeps_maintenance_of_before(self):
        # 6.0.0.6.6 and older: no marker; a missing cron file was maintenance mode or lost, nobody knows: it stays on, marked.
        result = self.efactl.monitor_cron_heal(type('Args', (), {'first': 'yes'})())
        self.assertEqual(result['monitor_cron'], 'maintenance mode kept on (marked)')
        self.assertFalse(os.path.exists(self.cron))
        self.assertIn('was missing before the update', json.load(open(self.marker))['note'])
        self.assertEqual(self.efactl.monitor_cron_heal()['monitor_cron'], 'maintenance mode', 'the timer leaves it to the admin')

    def test_a_stale_marker_goes_when_the_cron_file_is_there(self):
        json.dump({'by': 'update', 'at': 1}, open(self.marker, 'w'))
        open(self.cron, 'w').write('x')
        self.assertEqual(self.efactl.monitor_cron_heal()['monitor_cron'], 'ok')
        self.assertFalse(os.path.exists(self.marker))

    def test_not_during_setup_first_boot_or_migration(self):
        for name in ('firstboot-pending', 'skipmonitor'):
            path = os.path.join(self.folder, name)
            open(path, 'w').close()
            self.assertIn('not now', self.efactl.monitor_cron_heal()['monitor_cron'])
            self.assertFalse(os.path.exists(self.cron))
            os.remove(path)

    def test_wired_into_the_timer_and_the_update(self):
        source = open(os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'), encoding='utf-8').read()
        guard = source[source.index('def firewall_guard_run('):]
        self.assertIn('monitor_cron_heal', guard[:guard.index('\ndef ')])
        setup = open(os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'setup', 'efa-next-setup'), encoding='utf-8').read()
        self.assertIn('efactl monitor-cron-heal --first yes', setup.split('upgrade)', 1)[1].split(';;', 1)[0])
        self.assertFalse(self.efactl.cluster_replicated('monitor-cron-heal'), 'every host on its own, also a client')


if __name__ == '__main__':
    unittest.main()
