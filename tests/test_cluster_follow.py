# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""2026-11-19, on a cluster node: Fail2Ban did not answer within 30 s, the TimeoutExpired ended the follow loop of efa-cluster, and the node
took no change of the master for a day (journal 86 of 132, GeoIP stayed off) while the service still ran. A fault of one
round never ends the loop now; a busy Fail2Ban means no bans for that round; an entry that raises is noted and skipped. A
change a node hands on in HA mode says that the node follows within a minute, and the audit of the master names the node."""

import importlib.machinery
import importlib.util
import os
import subprocess
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
import efa_i18n  # noqa: E402


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, os.path.join(ROOT, path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


class Stop(BaseException):
    """Ends the endless loop of the test (BaseException: the loop catches Exception only)."""


@unittest.skipIf(efa_cluster is None, 'efa_cluster needs a Unix host')
class FollowLoop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.daemon = load('next/usr/local/sbin/efa-cluster.py', 'efa_cluster_follow_test')

    def setUp(self):
        self.etc = tempfile.mkdtemp(prefix='efa-follow-')
        os.makedirs(efa_cluster.folder(self.etc))
        efa_cluster.write_state({'role': 'client', 'name': 'node-a', 'mode': 'ha', 'applied': 86,
                                 'master': {'name': 'node-m', 'host': '192.0.2.2', 'port': 8460}}, self.etc)
        self.patches = [mock.patch.object(self.daemon, 'ETC', self.etc), mock.patch.object(self.daemon, 'sync_pull', lambda: None),
                        mock.patch.object(self.daemon, 'share_rates', lambda state: None)]
        for patch in self.patches:
            patch.start()
        self.logged = []
        self.addCleanup(lambda: [patch.stop() for patch in self.patches])

    def journal(self, entries):
        def call(_base, _host, _port, path, body=None, timeout=30):
            if path.startswith('/v1/journal'):
                after = int(path.split('after=')[1])
                return {'entries': [entry for entry in entries if entry['seq'] > after], 'mode': 'ha', 'version': ''}
            if path == '/v1/bans':
                return {'bans': [], 'unbans': []}
            return {}
        return call

    def rounds(self, count):
        """follow() for count rounds, then stopped."""
        sleeps = iter(range(count + 1))

        def sleep(_seconds):
            if next(sleeps) == count:
                raise Stop()
        with mock.patch.object(self.daemon.time, 'sleep', sleep), mock.patch.object(self.daemon.syslog, 'syslog', lambda _p, text: self.logged.append(text)):
            with self.assertRaises(Stop):
                self.daemon.follow()

    def test_fail2ban_timeout_ends_neither_the_round_nor_the_loop(self):
        def busy(*_args, **_kwargs):
            raise subprocess.TimeoutExpired(['fail2ban-client', 'banned'], 30)
        self.assertEqual(efa_cluster.f2b_banned(run=busy), set(), 'a busy Fail2Ban: no bans this round')
        applied = []
        entries = [{'seq': 87, 'type': 'command', 'command': 'geoip-set', 'args': {'mode': 'on', 'accept_terms': 'yes'}}]
        with mock.patch.object(efa_cluster, 'f2b_banned', lambda run=None: busy()), \
                mock.patch.object(efa_cluster, 'call', self.journal(entries)), \
                mock.patch.object(self.daemon, 'apply', lambda entry: applied.append(entry['seq'])):
            self.rounds(3)
        self.assertEqual(applied, [87], 'the journal is followed although the bans failed')
        self.assertEqual(efa_cluster.read_state(self.etc)['applied'], 87)
        self.assertTrue(any('bans not shared' in text for text in self.logged), self.logged)

    def test_any_fault_of_a_round_is_logged_and_the_next_round_runs(self):
        rounds = []

        def broken(memo):
            rounds.append(1)
            raise RuntimeError('something new')
        with mock.patch.object(self.daemon, 'follow_step', broken):
            self.rounds(3)
        self.assertEqual(len(rounds), 3, 'three rounds, not one')
        self.assertEqual(sum('follow round failed' in text and 'RuntimeError' in text for text in self.logged), 3)

    def test_an_entry_that_raises_is_noted_and_the_next_one_applied(self):
        entries = [{'seq': 87, 'type': 'files', 'files': [{'path': '../outside', 'data': '', 'mode': 0o644}]},
                   {'seq': 88, 'type': 'command', 'command': 'geoip-set', 'args': {'mode': 'on'}}]
        applied = []
        real_apply = self.daemon.apply

        def apply(entry):
            if entry['seq'] == 87:
                return real_apply(entry)  # raises ValueError: a path outside /etc
            applied.append(entry['seq'])
            return None
        with mock.patch.object(efa_cluster, 'f2b_banned', lambda run=None: set()), \
                mock.patch.object(efa_cluster, 'call', self.journal(entries)), mock.patch.object(self.daemon, 'apply', apply):
            self.rounds(1)
        state = efa_cluster.read_state(self.etc)
        self.assertEqual((state['applied'], applied), (88, [88]))
        self.assertEqual(state['failed'][0]['seq'], 87)
        self.assertIn('ValueError', state['failed'][0]['error'])


class ForwardedChange(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load('next/usr/sbin/efactl', 'efactl_forward_test')

    def test_the_node_says_it_follows_and_the_master_names_the_node(self):
        efactl = self.efactl
        args = type('A', (), {'command': 'geoip-set', 'mode': 'on', 'accept_terms': 'yes'})()
        cluster = mock.Mock()
        cluster.call.return_value = {'active': True, 'warnings': ['GeoIP is on but a file is missing: ...']}
        with mock.patch.object(efactl, '_cluster_parts', lambda: (cluster, '/base', {'master': {'name': 'node-m', 'host': '192.0.2.2', 'port': 8460}})), \
                mock.patch.object(efactl, '_dmarc_who', lambda: 'web interface'):
            answer = efactl._cluster_forward(args)
        self.assertTrue(answer['active'])
        self.assertEqual(answer['note'], 'Changed on the master node-m: this node takes it over within a minute.')
        self.assertEqual(efa_i18n.runtime(answer['note'], 'de'), 'Auf dem Master node-m geändert: dieser Knoten übernimmt es innerhalb einer Minute.')
        # The master: run by efa-cluster as root with --client 'cluster-node node-a (web interface)'.
        with mock.patch.dict(os.environ, {'EFA_CLUSTER_FORWARDED': 'node-a'}), mock.patch.object(efactl, 'acting_client', 'cluster-node node-a (web interface)'):
            self.assertEqual(efactl._dmarc_who(), 'cluster-node node-a (web interface)')
        with mock.patch.dict(os.environ, {'EFA_CLUSTER_FORWARDED': ''}, clear=False), mock.patch.object(efactl, 'acting_client', ''):
            os.environ.pop('SUDO_USER', None)
            self.assertEqual(efactl._dmarc_who(), 'console (root)')


if __name__ == '__main__':
    unittest.main()
