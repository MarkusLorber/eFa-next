# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The attack alert of 6.0.0.6 (threat-run): what the journal lines count, when a value becomes a warning or an alert, that
a quiet or a normally busy server stays green, that an alert does not flicker off at once, and that a tenant admin gets
no addresses."""
import importlib.machinery
import importlib.util
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(TOP, 'src', 'eFa-base', 'root', 'usr', 'lib', 'eFa', 'python'))
sys.path.insert(0, os.path.join(TOP, 'next', 'usr', 'lib', 'eFa', 'python'))


def load_efactl():
    for name in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
        sys.modules.setdefault(name, __import__(name) if importlib.util.find_spec(name) else types.ModuleType(name))
    loader = importlib.machinery.SourceFileLoader('efactl_threat', os.path.join(TOP, 'next', 'usr', 'sbin', 'efactl'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_threat', loader))
    loader.exec_module(module)
    return module


LINES = ['CONNECT from [203.0.113.9]:4711 to [192.0.2.1]:25', 'CONNECT from [203.0.113.9]:4712 to [192.0.2.1]:25',
         'CONNECT from [198.51.100.4]:1 to [192.0.2.1]:25', 'connect from mail.example.net[198.51.100.4]',
         'warning: unknown[203.0.113.77]: SASL LOGIN authentication failed: UGFzc3dvcmQ6',
         'NOQUEUE: reject: RCPT from unknown[203.0.113.9]: 554 5.7.1 Service unavailable', 'PREGREET 11 after 0.1 from [203.0.113.9]:4713: EHLO x',
         'NOTICE  [postfix-sasl] Ban 203.0.113.77', 'NOTICE  [postfix-sasl] Unban 203.0.113.70',
         'efa-web login failed user admin from 198.51.100.200', 'efa-web login ok user admin from 198.51.100.201']


class Threat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def test_journal_counts(self):
        counts, top = self.efactl.threat_journal_counts(LINES)
        # postscreen sees every client first: its CONNECT lines count, the connect of smtpd after it does not.
        self.assertEqual(counts, {'connections': 3, 'auth_failed': 2, 'rejects': 2, 'bans': 1})
        self.assertEqual(list(top)[0], '203.0.113.9')
        counts, _top = self.efactl.threat_journal_counts(['connect from a.example[192.0.2.9]'])
        self.assertEqual(counts['connections'], 1, 'without postscreen the connect of smtpd counts')

    def test_kernel_counters(self):
        import efa_platform_el9
        netstat = 'TcpExt: SyncookiesSent ListenDrops ListenOverflows\nTcpExt: 5 7 2\nIpExt: InNoRoutes\nIpExt: 0\n'
        snmp = 'Ip: Forwarding\nIp: 2\nTcp: RtoAlgorithm PassiveOpens\nTcp: 1 42\n'
        keys = efa_platform_el9.EL9.TCP_KEYS
        found = efa_platform_el9.EL9.parse_proc_net(netstat, keys)
        found.update(efa_platform_el9.EL9.parse_proc_net(snmp, keys))
        self.assertEqual(found, {'SyncookiesSent': 5, 'ListenDrops': 7, 'ListenOverflows': 2, 'PassiveOpens': 42})
        self.assertEqual(efa_platform_el9.EL9.parse_proc_net('', keys), {})

    def judge(self, ring, mail=None, base=None, queue=0, down=(), resources=None, factor=1.0):
        return self.efactl.threat_judge(ring, mail, base, queue, list(down), resources or {}, factor)

    def test_quiet_and_busy_servers_stay_green(self):
        quiet = [{'connections': 3, 'auth_failed': 0, 'rejects': 1, 'bans': 0, 'syn': 0}] * 30
        self.assertEqual(self.judge(quiet, {'mails': 20, 'spam': 4, 'virus': 0}, {'mails': 25, 'spam': 5, 'virus': 0}), {})
        # A large server: 400 connections a minute is its normal, so it is no flood there.
        busy = [{'connections': 400, 'rejects': 200}] * 59 + [{'connections': 520, 'rejects': 260}]
        self.assertNotIn('smtp_flood', self.judge(busy))
        self.assertNotIn('reject_wave', self.judge(busy))

    def test_floods_and_waves(self):
        ring = [{'connections': 20}] * 59 + [{'connections': 900, 'top': {'203.0.113.9': 700}, 'auth_failed': 12}]
        found = self.judge(ring)
        self.assertEqual(found['smtp_flood']['level'], 'alert')
        self.assertEqual(found['smtp_flood']['top'], [['203.0.113.9', 700]])
        self.assertEqual(self.judge([{'connections': 20}] * 59 + [{'connections': 150}])['smtp_flood']['level'], 'warn')
        self.assertEqual(self.judge([{'syn': 500}])['syn_flood']['level'], 'alert')
        self.assertEqual(self.judge([{'auth_failed': 12}] * 10)['password_attack']['level'], 'alert')
        found = self.judge([{}], {'mails': 400, 'spam': 320, 'virus': 25}, {'mails': 30, 'spam': 10, 'virus': 0})
        self.assertEqual((found['spam_wave']['level'], found['spam_wave']['share']), ('alert', 80))
        self.assertEqual(found['virus_wave']['level'], 'alert')
        self.assertNotIn('spam_wave', self.judge([{}], {'mails': 400, 'spam': 150, 'virus': 0}, {'mails': 300, 'spam': 100, 'virus': 0}),
                         'under half spam is no wave')
        self.assertEqual(self.judge([{}], queue=1500)['queue_flood']['level'], 'alert')
        self.assertEqual(self.judge([{}], down=['service:rspamd'])['service_down']['names'], ['service:rspamd'])
        self.assertEqual(self.judge([{}], resources={'disk_full': (93, 90, 95)})['disk_full']['level'], 'warn')

    def test_sensitivity(self):
        ring = [{'connections': 0}] * 59 + [{'connections': 200}]
        self.assertEqual(self.judge(ring, factor=0.5)['smtp_flood']['level'], 'alert')
        self.assertNotIn('smtp_flood', self.judge(ring, factor=2.0))

    def test_alert_holds_and_eases(self):
        state = {}
        alert = {'smtp_flood': {'level': 'alert', 'value': 900, 'normal': 20}}
        self.efactl.threat_track(state, alert, 1000)
        self.efactl.threat_track(state, {'smtp_flood': {'level': 'warn', 'value': 150, 'normal': 20}}, 1060)
        self.assertEqual(state['active']['smtp_flood']['level'], 'alert', 'no step down within the hold time')
        self.assertEqual(state['active']['smtp_flood']['since'], 1000)
        self.efactl.threat_track(state, {}, 1120)
        self.assertTrue(state['active']['smtp_flood']['easing'])
        self.efactl.threat_track(state, {}, 1060 + self.efactl.THREAT_HOLD + 1)
        self.assertNotIn('smtp_flood', state['active'])

    def test_status_hides_addresses_from_tenant_admins(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder, True)
        kept = {'last': {'level': 'alert', 'checked': 1, 'gauges': {}, 'alerts': [{'kind': 'smtp_flood', 'top': [['203.0.113.9', 700]]}]}}
        with mock.patch.object(self.efactl, 'THREAT_STATE', folder + '/state.json'), mock.patch.object(self.efactl, 'THREAT_FILE', folder + '/threat.json'):
            self.efactl._json_write(folder + '/state.json', kept)
            self.assertIn('top', self.efactl.threat_status(None)['alerts'][0])
            with mock.patch.object(self.efactl, 'identity_now', {'domains': ['example.org']}):
                self.assertNotIn('top', self.efactl.threat_status(None)['alerts'][0])
                with self.assertRaises(self.efactl.EfaError):
                    self.efactl.threat_run(None)
            self.assertEqual(self.efactl.threat_status(None)['sensitivity'], 'normal')
            audited = []
            with mock.patch.object(self.efactl, '_audit', audited.append):
                self.efactl.threat_set(types.SimpleNamespace(sensitivity='high'))
            self.assertEqual(self.efactl.threat_settings()['sensitivity'], 'high')
            self.assertTrue(audited and audited[0].startswith('attack alert sensitivity normal -> high by'), audited)
            self.assertIn('threat-set', self.efactl.SUPER_COMMANDS)
            with self.assertRaises(self.efactl.EfaError):
                self.efactl.threat_set(types.SimpleNamespace(sensitivity='max'))


if __name__ == '__main__':
    unittest.main()
