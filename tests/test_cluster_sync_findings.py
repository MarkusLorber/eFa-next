# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.6.6, findings of a live cluster: the parameters of port 587 only where the node uses them, the MX check behind NAT,
the mode of the master right after the join, and the jobs of the timers never refused by the client guard."""

import argparse
import glob
import importlib.machinery
import importlib.util
import os
import re
import sys
import time
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))


def load_efactl():
    loader = importlib.machinery.SourceFileLoader('efactl_findings', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_findings', loader))
    loader.exec_module(module)
    return module


def timer_commands():
    """Every efactl command a systemd unit, a cron line of the tree or the upgrade of efa-next-setup runs on each host."""
    found = set()
    for path in glob.glob(os.path.join(ROOT, '**', '*.service'), recursive=True) + glob.glob(os.path.join(ROOT, '**', '*.timer'), recursive=True):
        with open(path, encoding='utf-8', errors='replace') as f:
            found |= set(re.findall(r'^ExecStart=.*?efactl\s+([a-z0-9-]+)', f.read(), flags=re.M))
    for path in (os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'), *glob.glob(os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python', '*.py'))):
        with open(path, encoding='utf-8', errors='replace') as f:
            found |= set(re.findall(r'root (?:/usr/bin/flock -n \S+ )?/usr/sbin/efactl ([a-z0-9-]+)', f.read()))
    with open(os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'setup', 'efa-next-setup'), encoding='utf-8') as f:
        upgrade = f.read().split('upgrade)', 1)[1].split(';;', 1)[0]
    found |= set(re.findall(r'step /usr/sbin/efactl ([a-z0-9-]+)', upgrade))
    return found


class SyncFindings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.efactl = load_efactl()
        except ImportError as err:  # efa_cluster needs fcntl
            raise unittest.SkipTest(f'needs a Unix host: {err}')

    def test_submission_parameters_only_where_the_node_uses_them(self):
        snapshot = {'postconf': {'efa_submission_milters': 'inet:127.0.0.1:8907', 'smtpd_milters': 'inet:127.0.0.1:11332'}, 'services': {}}
        without, _services, _skipped = self.efactl.snapshot_local(snapshot, 'lmdb', {'lmdb'}, node_refs={'efa_submission_restrictions'})
        self.assertEqual(sorted(without), ['smtpd_milters'], 'port 587 is the choice of the node: nothing of it by sync')
        used, _services, _skipped = self.efactl.snapshot_local(snapshot, 'lmdb', {'lmdb'}, node_refs={'efa_submission_milters'})
        self.assertEqual(sorted(used), ['efa_submission_milters', 'smtpd_milters'])

    def test_mx_of_a_node_behind_nat(self):
        # The nodes know each other by internal addresses; the MX names a public name of each that resolves to another address.
        nodes = {'10.0.0.11': 'node-a', '10.0.0.12': 'node-b'}
        public = {'mx1.example.org': ['198.51.100.11'], 'mx2.example.org': ['198.51.100.12'], 'mx.other.example': ['203.0.113.9']}
        records = [(10, 'mx1.example.org'), (10, 'mx2.example.org')]
        before = self.efactl.mx_findings('example.org', records, lambda host: public.get(host, []), nodes)
        self.assertTrue(any('is no node of this cluster' in item['text'] for item in before), 'the case of the live cluster')
        found = self.efactl.mx_findings('example.org', records, lambda host: public.get(host, []), nodes,
                                        {'MX1.Example.org': 'node-a', 'mx2.example.org.': 'node-b'})
        self.assertEqual([item['level'] for item in found if item['level'] != 'note'], [], found)
        foreign = self.efactl.mx_findings('example.org', records + [(20, 'mx.other.example')], lambda host: public.get(host, []), nodes,
                                          {'mx1.example.org': 'node-a', 'mx2.example.org': 'node-b'})
        self.assertTrue(any('mx.other.example is no node' in item['text'] for item in foreign), 'a real other MX still counts')

    def test_join_keeps_the_mode_of_the_master_at_once(self):
        written = []

        class Cluster:
            PORT = 8460

            def valid_name(self, name):
                return True

            def fetch_ca(self, host, port):
                return 'CA'

            def fingerprint_pem(self, pem):
                return 'FP'

            def make_request(self, base, name):
                return 'CSR'

            def join_request(self, host, port, ca, body, path='/v1/join'):
                if path == '/v1/precheck':
                    return {'version': '6.0.0.6.6', 'platform': 'el10', 'time': int(time.time())}
                self.body = body
                return {'ca': 'CA', 'cert': 'CERT', 'master': 'node-a', 'master_fingerprint': 'MF', 'mode': 'ha', 'version': '6.0.0.6.6',
                        'platform': 'el10'}

            def write_state(self, state, etc):
                written.append(state)

            def own_version(self):
                return '6.0.0.6.6'

            def own_platform(self):
                return 'el9'

            def version_problem(self, own, other, who='the master'):
                return '' if own.rsplit('.', 1)[0] == other.rsplit('.', 1)[0] else 'other series'
        fake = Cluster()
        base = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'build', 'tmp-cluster-join-test')
        args = argparse.Namespace(name='node-b', address='10.0.0.12', master='10.0.0.11', ca_fingerprint='FP', port='')
        with mock.patch.object(self.efactl, '_cluster_parts', lambda: (fake, base, {})), \
                mock.patch.object(self.efactl, '_secrets', lambda count, prompt: ['token']), \
                mock.patch.object(self.efactl, '_write', lambda path, text, *a: None), mock.patch.object(self.efactl, '_cluster_service', lambda on: None), \
                mock.patch.object(self.efactl, 'cluster_resync', lambda args: {}), mock.patch.object(self.efactl, 'cluster_status', lambda args: {}), \
                mock.patch.object(self.efactl, '_own_names', lambda: ['mx2.example.org']), mock.patch.object(self.efactl.os, 'makedirs', lambda *a, **k: None), \
                mock.patch.object(self.efactl, '_efa_version', lambda: '6.0.0.6.6'),                 mock.patch.object(self.efactl, '_cluster_port_open', lambda state, rules: None):  # never the firewall of this host
            self.efactl.cluster_join(args)
        self.assertEqual(written[-1]['mode'], 'ha', 'the mode of the answer, not master-client until the first poll')
        self.assertEqual(written[-1]['master']['platform'], 'el10')
        self.assertEqual(fake.body['names'], ['mx2.example.org'])
        self.assertEqual((fake.body['version'], fake.body['platform']), ('6.0.0.6.6', 'el9'))

    def test_no_timer_job_is_refused_by_the_client_guard(self):
        commands = timer_commands()
        self.assertIn('floor-check', commands, 'efa-floor-guard')
        blocked = sorted(command for command in commands if command in self.efactl.COMMANDS and self.efactl.cluster_replicated(command)
                         and command not in self.efactl.CLUSTER_MASTER_JOBS)
        self.assertEqual(blocked, [], 'jobs of a timer or of the package setup that a client would refuse')
        # Narrow: what writes shared settings is still refused on a client.
        for shared in ('greylisting-set', 'rbl-set', 'sender-add', 'domain-spam-set'):
            self.assertTrue(self.efactl.cluster_replicated(shared), shared)


if __name__ == '__main__':
    unittest.main()
