# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Timer jobs of eFa-next: the ones a planned stop may end take SIGTERM as success (the next timer run follows), the ones whose
interruption needs a look stay a failure. A new timer has to be put into one of the two lists."""
import configparser
import glob
import os
import unittest

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Checks and jobs that start again on their own: an update that restarts the units may end one of them halfway.
INTERRUPTIBLE = {'efa-blocklist', 'efa-cve-watch', 'efa-events', 'efa-firewall-guard', 'efa-mailreport', 'efa-outbound-hold',
                 'efa-sanesecurity', 'efa-reboot-check'}
# Installs packages or changes keys: a run ended halfway has to show as failed.
MUST_FAIL = {'efa-autoupdate', 'efa-dkim-rotation'}


def unit(path):
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read(path, encoding='utf-8')
    return parser


def find(name):
    found = glob.glob(os.path.join(TOP, 'next', '**', name), recursive=True) + glob.glob(os.path.join(TOP, 'src', '**', name), recursive=True)
    return found[0] if found else None


class TimerSigtermTests(unittest.TestCase):
    def timers(self):
        paths = glob.glob(os.path.join(TOP, 'next', '**', '*.timer'), recursive=True) + glob.glob(os.path.join(TOP, 'src', '**', '*.timer'), recursive=True)
        for path in sorted(paths):
            timer = unit(path)
            service = timer.get('Timer', 'Unit', fallback=os.path.basename(path)[:-len('.timer')] + '.service')
            yield service[:-len('.service')], find(service)

    def test_every_timer_classified(self):
        names = {name for name, _path in self.timers()}
        self.assertTrue(names, 'no timers found')
        self.assertEqual(names - INTERRUPTIBLE - MUST_FAIL, set(), 'a new timer: put it into INTERRUPTIBLE or MUST_FAIL')
        self.assertEqual(INTERRUPTIBLE & MUST_FAIL, set())

    def test_sigterm_as_success(self):
        for name, path in self.timers():
            self.assertIsNotNone(path, name)
            service = unit(path)['Service']
            self.assertEqual(service.get('Type'), 'oneshot', name)
            success = service.get('SuccessExitStatus', '')
            if name in INTERRUPTIBLE:
                self.assertIn('SIGTERM', success.split(), name)
            else:
                self.assertNotIn('SIGTERM', success.split(), name)


if __name__ == '__main__':
    unittest.main()
