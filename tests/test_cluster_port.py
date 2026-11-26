# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The cluster port 8460 opens only for the partner (Hans 2026-11-22): a rich rule per address through the platform layer,
never a firewalld reload; removing a node and leaving close what was opened."""
import argparse
import socket
import tempfile
import unittest
from unittest import mock

from test_cluster_sync_2fa import load_efactl


class ClusterPort(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.platform = mock.MagicMock()
        self.tmp = tempfile.mkdtemp()
        self.cluster = mock.MagicMock()
        self.cluster.PORT = 8460
        self.cluster.token_hash.side_effect = lambda token: 'h-' + token
        self.cluster.fingerprint_pem.return_value = 'AB:CD'
        with open(self.tmp + '/ca.crt', 'w') as f:
            f.write('pem')
        self.patches = [mock.patch.object(self.efactl, '_platform', lambda: self.platform),
                        mock.patch.object(self.efactl, '_totp_box', lambda: None)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()

    def calls(self):
        return [(call.args[0], call.args[1]) for call in self.platform.firewall_rich_rule.call_args_list]

    def test_rules_per_address(self):
        e = self.efactl
        self.assertEqual(e.cluster_port_rules('192.0.2.12', 8460),
                         ['rule family="ipv4" source address="192.0.2.12" port port="8460" protocol="tcp" accept'])
        self.assertEqual(e.cluster_port_rules('2001:db8::12', 8461),
                         ['rule family="ipv6" source address="2001:db8::12" port port="8461" protocol="tcp" accept'])
        answers = [(socket.AF_INET, 1, 6, '', ('192.0.2.13', 0)), (socket.AF_INET6, 1, 6, '', ('2001:db8::13', 0, 0, 0))]
        with mock.patch.object(e.socket, 'getaddrinfo', lambda *a, **k: answers):
            self.assertEqual(len(e.cluster_port_rules('mx-2.example.org', 8460)), 2, 'a name: each of its addresses')
        for bad in ('0.0.0.0/0', 'a b', '"; drop', ''):
            with self.assertRaises(e.EfaError):
                e.cluster_port_rules(bad, 8460)

    def test_token_opens_for_the_node_and_remove_closes(self):
        e = self.efactl
        state = {'role': 'master', 'port': 8460, 'nodes': {'mx-2': {'host': '192.0.2.12', 'port': 8460}}}
        with mock.patch.object(e, '_cluster_parts', lambda: (self.cluster, self.tmp, state)), \
                mock.patch.object(e, 'cluster_status', lambda _a: {}):
            e.cluster_token(argparse.Namespace(node=''))
            self.assertEqual(self.calls(), [], 'no node: nothing opened')
            e.cluster_token(argparse.Namespace(node='192.0.2.12'))
            rule = 'rule family="ipv4" source address="192.0.2.12" port port="8460" protocol="tcp" accept'
            self.assertEqual(self.calls(), [(rule, True)])
            self.assertEqual(state['firewall'], [rule])
            e.cluster_node_remove(argparse.Namespace(name='mx-2'))
            self.assertEqual(self.calls()[-1], (rule, False))
            self.assertEqual(state['firewall'], [])

    def test_leave_closes_everything_opened(self):
        e = self.efactl
        rule = 'rule family="ipv4" source address="192.0.2.1" port port="8460" protocol="tcp" accept'
        state = {'role': 'client', 'name': 'mx-2', 'firewall': [rule], 'master': {'host': '192.0.2.1', 'port': 8460}}
        with mock.patch.object(e, '_cluster_parts', lambda: (self.cluster, self.tmp + '/gone', state)), \
                mock.patch.object(e, '_cluster_service', lambda on: None), mock.patch.object(e, 'freshclam_follow', lambda mode: ''):
            e.cluster_leave(argparse.Namespace(confirm='yes'))
        self.assertEqual(self.calls(), [(rule, False)])

    def test_a_failed_firewall_stops_the_token(self):
        e = self.efactl
        self.platform.firewall_rich_rule.side_effect = RuntimeError('firewalld not running')
        state = {'role': 'master', 'port': 8460, 'tokens': {}}
        with mock.patch.object(e, '_cluster_parts', lambda: (self.cluster, self.tmp, state)):
            with self.assertRaises(e.EfaError):
                e.cluster_token(argparse.Namespace(node='192.0.2.12'))
        self.assertEqual(state['tokens'], {}, 'no token without the port')


if __name__ == '__main__':
    unittest.main()
