# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.6.6: a cluster of EL9 and EL10 nodes (the release upgrade goes one node at a time). The Postfix values of the master's
snapshot are made fit for the Postfix of the node: tables as its type, a table type it lacks never written; nodes of one
release series only."""

import importlib.machinery
import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))
try:
    import efa_cluster  # noqa: E402
except ImportError:  # fcntl: Unix only
    efa_cluster = None

EL10_TYPES = {'lmdb', 'cdb', 'cidr', 'pcre', 'regexp', 'inline', 'static', 'texthash', 'unix', 'proxy', 'tcp', 'socketmap'}
EL9_TYPES = EL10_TYPES | {'hash', 'btree'}
SNAPSHOT_EL9 = {'postconf': {'smtpd_client_restrictions': 'check_client_access hash:/etc/postfix/efa-client-access, permit_mynetworks',
                             'smtp_tls_session_cache_database': 'btree:${data_directory}/smtp_scache',
                             'transport_maps': 'hash:/etc/postfix/transport'},
                'services': {'submission/inet': 'submission inet n - n - - smtpd -o smtpd_sender_restrictions=hash:/etc/postfix/sub_senders'}}
SNAPSHOT_EL10 = {'postconf': {'transport_maps': 'lmdb:/etc/postfix/transport', 'postscreen_cache_map': 'lmdb:$data_directory/postscreen_cache'},
                 'services': {}}


@unittest.skipIf(efa_cluster is None, 'efa_cluster needs a Unix host')
class CrossPlatform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        loader = importlib.machinery.SourceFileLoader('efactl_cluster', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
        cls.efactl = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_cluster', loader))
        loader.exec_module(cls.efactl)

    def test_el9_master_to_el10_node(self):
        postconf, services, skipped = self.efactl.snapshot_local(SNAPSHOT_EL9, 'lmdb', EL10_TYPES)
        self.assertEqual(skipped, [])
        self.assertEqual(postconf['smtpd_client_restrictions'], 'check_client_access lmdb:/etc/postfix/efa-client-access, permit_mynetworks')
        self.assertEqual(postconf['smtp_tls_session_cache_database'], 'lmdb:${data_directory}/smtp_scache')
        self.assertEqual(postconf['transport_maps'], 'lmdb:/etc/postfix/transport')
        self.assertIn('smtpd_sender_restrictions=lmdb:/etc/postfix/sub_senders', services['submission/inet'])
        self.assertNotIn('hash:', ' '.join(list(postconf.values()) + list(services.values())))

    def test_el10_master_to_el9_node(self):
        postconf, _services, skipped = self.efactl.snapshot_local(SNAPSHOT_EL10, 'hash', EL9_TYPES)
        self.assertEqual(skipped, [])
        self.assertEqual(postconf['transport_maps'], 'hash:/etc/postfix/transport', 'the node compiles its tables as hash')
        self.assertEqual(postconf['postscreen_cache_map'], 'btree:$data_directory/postscreen_cache', 'a cache as btree beside hash')

    def test_a_table_type_the_node_lacks_is_never_written(self):
        snapshot = {'postconf': {'virtual_alias_maps': 'ldap:/etc/postfix/ldap-aliases.cf', 'relayhost': '[smtp.example.org]:587'},
                    'services': {}}
        postconf, _services, skipped = self.efactl.snapshot_local(snapshot, 'lmdb', EL10_TYPES)
        self.assertEqual(postconf, {'relayhost': '[smtp.example.org]:587'})
        self.assertEqual(skipped, ['main.cf virtual_alias_maps: table type ldap is not in this Postfix (postconf -m)'])

    def test_a_master_of_another_release_series_is_refused(self):
        with tempfile.NamedTemporaryFile('w', suffix='-Version', delete=False) as f:
            f.write('6.0.0.6.6\n')
        self.addCleanup(os.remove, f.name)
        with mock.patch.object(efa_cluster, 'VERSION_FILES', (f.name,)):
            self.assertEqual(efa_cluster.own_version(), '6.0.0.6.6')
            self.assertEqual(efa_cluster.version_problem('6.0.0.6.6', '6.0.0.6.5'), '', 'patch releases of one series')
            with self.assertRaisesRegex(self.efactl.EfaError, 'one release series'):
                self.efactl.snapshot_apply({**SNAPSHOT_EL9, 'version': '6.0.0.7.0', 'files': [], 'sql': '', 'units': {}})
            # A master of 6.0.0.6.5 names no version in its snapshot: taken (a rolling update goes one node at a time).
            with mock.patch.object(self.efactl, 'own_names', lambda *a: None, create=True):
                done = self.efactl.snapshot_apply({**SNAPSHOT_EL9, 'files': [], 'sql': '', 'units': {}}, files_only=True)
            self.assertIn('not_applied_in_this_test', done)

    def test_rolling_update_with_mixed_patch_releases(self):
        """MX nodes update one at a time: a 6.0.0.6.5 master with a 6.0.0.6.6 node and the reverse follow each other, journal
        and snapshot both ways; another release series does not, and a new node must name its version to join."""
        for own, other in (('6.0.0.6.6', '6.0.0.6.5'), ('6.0.0.6.5', '6.0.0.6.6'), ('6.0.0.6.6', '6.0.0.6.6')):
            self.assertEqual(efa_cluster.version_problem(own, other), '', (own, other))
        self.assertEqual(efa_cluster.version_problem('6.0.0.6.6', ''), '', 'a peer of before this check (no version field): taken')
        self.assertEqual(efa_cluster.version_problem('6.0.0.6.6', None), '')
        self.assertIn('one release series', efa_cluster.version_problem('6.0.0.6.6', '6.0.0.7.0'))
        self.assertIn('names no eFa-next version', efa_cluster.version_problem('6.0.0.6.6', '', 'the node', strict=True))
        # The journal answer of a 6.0.0.6.5 master has no version: the node of 6.0.0.6.6 follows it (efa-cluster follow loop).
        loader = importlib.machinery.SourceFileLoader('efa_cluster_daemon', os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-cluster.py'))
        daemon = importlib.util.module_from_spec(importlib.util.spec_from_loader('efa_cluster_daemon', loader))
        loader.exec_module(daemon)
        state = {'role': 'master', 'name': 'node-a', 'nodes': {}, 'tokens': {efa_cluster.token_hash('t1'): 1000}}
        with self.assertRaisesRegex(ValueError, 'names no eFa-next version'):
            daemon.join(state, {'token': 't1', 'name': 'node-c'}, now=10)

    def test_platform_and_series(self):
        with tempfile.NamedTemporaryFile('w', delete=False) as f:
            f.write('NAME="AlmaLinux"\nVERSION_ID="10.3"\n')
        self.addCleanup(os.remove, f.name)
        self.assertEqual(efa_cluster.own_platform(f.name), 'el10')
        self.assertEqual(efa_cluster.version_series('6.0.0.6.6'), '6.0.0.6')
        self.assertEqual(efa_cluster.version_series('6.0'), '')


if __name__ == '__main__':
    unittest.main()
