# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""Hans 2026-11-20: DNS for other networks per node. In a cluster each entry is for all nodes (also an entry of before) or
for the nodes chosen, changeable with dns-share-edit; the list goes to every node through the journal of the master and each
node answers only the nets of its own entries. Outside a cluster nothing changes."""

import importlib.machinery
import importlib.util
import json
import os
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')


def load_efactl():
    loader = importlib.machinery.SourceFileLoader('efactl_dns_nodes', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_dns_nodes', loader))
    loader.exec_module(module)
    return module


class Platform:
    def __init__(self):
        self.rules = set()

    def firewall_rich_rule(self, rule, add):
        (self.rules.add if add else self.rules.discard)(rule)

    def service_restart(self, name, check=True):
        pass


class DnsShareNodes(unittest.TestCase):
    def setUp(self):
        self.e = load_efactl()
        self.tmp = tempfile.TemporaryDirectory()
        self.platform = Platform()
        self.role, self.cluster = 'master', ('mx-1', {'mx-1', 'mx-2', 'mx-3'}, {'mx-2': '192.0.2.2', 'mx-3': '192.0.2.3'})
        patches = [mock.patch.object(self.e, 'DNS_SHARE_FILE', os.path.join(self.tmp.name, 'dns-share.json')),
                   mock.patch.object(self.e, 'DNS_SHARE_CONF', os.path.join(self.tmp.name, 'efa-dns-share.conf')),
                   mock.patch.object(self.e, 'cluster_role', lambda: self.role),
                   mock.patch.object(self.e, '_dns_share_cluster', lambda: self.cluster if self.role != 'none' else ('', set(), {})),
                   mock.patch.object(self.e, '_own_addresses', lambda: ['192.0.2.1', '127.0.0.1']),
                   mock.patch.object(self.e, '_platform', lambda: self.platform),
                   mock.patch.object(self.e, '_stays_active', lambda *a: True),
                   mock.patch.object(self.e, '_audit', lambda text: None),
                   mock.patch.object(self.e, '_dmarc_who', lambda: 'admin'),
                   mock.patch.object(self.e.subprocess, 'run', lambda *a, **k: types.SimpleNamespace(returncode=0, stdout='', stderr=''))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(self.tmp.cleanup)

    def add(self, nets, nodes=''):
        return self.e.dns_share_add(types.SimpleNamespace(nets=nets, note='', confirm_public='', nodes=nodes))

    def answered(self):
        return sorted({rule.split('"')[3] for rule in self.platform.rules})

    def test_nodes_are_checked(self):
        nodes = self.e.dns_share_nodes
        self.assertEqual(nodes('', 'master', {'mx-1'}), ['all'])
        self.assertEqual(nodes('mx-2,mx-1 mx-2', 'master', {'mx-1', 'mx-2'}), ['mx-1', 'mx-2'])
        for text, role in (('mx-9', 'master'), ('all mx-1', 'master'), ('mx-1', 'none'), ('bad/name', 'client')):
            with self.assertRaises(self.e.EfaError, msg=text):
                nodes(text, role, {'mx-1'})
        self.assertEqual(nodes('mx-9', 'client', {'mx-1'}), ['mx-9'], 'a client takes a node of its master it does not know yet')

    def test_each_node_answers_only_its_entries(self):
        self.add('10.1.0.0/16')
        self.add('10.2.0.0/16', 'mx-2')
        self.assertEqual(self.answered(), ['10.1.0.0/16'], 'mx-1 answers the entry for all, not the one of mx-2')
        listed = self.e.dns_share_list(None)
        self.assertEqual([entry['nodes'] for entry in listed['entries']], ['all nodes', 'mx-2'])
        self.assertEqual(listed['listens_on'], ['mx-1: 192.0.2.1', 'mx-2: 192.0.2.2', 'mx-3: 192.0.2.3'])
        self.e.dns_share_edit(types.SimpleNamespace(net='10.2.0.0/16', nodes='mx-1', note=''))
        self.e.dns_share_edit(types.SimpleNamespace(net='10.1.0.0/16', nodes='mx-3', note=''))
        self.assertEqual(self.answered(), ['10.2.0.0/16'], 'edit opens the net of this node and closes the one gone')
        with self.assertRaises(self.e.EfaError):
            self.e.dns_share_edit(types.SimpleNamespace(net='10.9.0.0/16', nodes='', note=''))

    def test_an_entry_of_before_is_for_all_and_a_removed_node_is_unknown(self):
        with open(self.e.DNS_SHARE_FILE, 'w') as f:
            json.dump({'entries': [{'net': '10.1.0.0/16', 'note': ''}, {'net': '10.2.0.0/16', 'note': '', 'nodes': ['mx-4']}], 'secondary': ''}, f)
        self.e.dns_share_apply(None)
        self.assertEqual(self.answered(), ['10.1.0.0/16'])
        self.assertEqual([entry['nodes'] for entry in self.e.dns_share_list(None)['entries']], ['all nodes', 'mx-4 (unknown)'])

    def test_a_client_follows_its_master(self):
        self.role, self.cluster = 'client', ('mx-2', {'mx-1', 'mx-2'}, {'mx-1': '192.0.2.1'})
        self.e.dns_share_edit(types.SimpleNamespace(net='10.3.0.0/16', nodes='mx-2', note=''))
        self.assertEqual(self.answered(), ['10.3.0.0/16'], 'an entry of the master this node did not have comes in')
        self.e.dns_share_del(types.SimpleNamespace(nets='10.4.0.0/16 10.3.0.0/16'))
        self.assertEqual(self.answered(), [], 'a removal of the master never fails on a node without the net')

    def test_outside_a_cluster_nothing_changes(self):
        self.role = 'none'
        listed = self.add('10.1.0.0/16')
        self.assertNotIn('nodes', listed['entries'][0])
        self.assertNotIn('cluster_nodes', listed)
        self.assertEqual(listed['listens_on'], ['192.0.2.1'])
        with self.assertRaises(self.e.EfaError):
            self.add('10.2.0.0/16', 'mx-2')

    def test_the_list_goes_to_every_node(self):
        for name in ('dns-share-add', 'dns-share-edit', 'dns-share-del'):
            self.assertTrue(self.e.cluster_replicated(name), name)
        self.assertFalse(self.e.cluster_replicated('dns-share-secondary-set'), 'the second resolver is of each host')


if __name__ == '__main__':
    unittest.main()
