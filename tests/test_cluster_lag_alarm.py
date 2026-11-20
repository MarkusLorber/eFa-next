# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""6.0.0.6.6.2: a node that stops following the master never goes unnoticed. The master's health names a node behind the
journal for more than 5 minutes, or one whose follow loop finished no round for more than 2 minutes (the heartbeat of
/v1/status), raises it once (event, admin mail, audit) and drops it when the node is back in step."""

import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))
import efa_cluster  # noqa: E402


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, os.path.join(ROOT, path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


STATE = {'role': 'master', 'name': 'node-a', 'nodes': {'node-b': {'host': '192.0.2.2', 'port': 8460, 'joined': 'x'}}}


class LagAlarm(unittest.TestCase):
    def rows(self, answer, before, now, seq=10):
        return efa_cluster.health_rows(STATE, {'node-b': answer}, {'nodes': before}, seq, now)

    def test_lag_over_five_minutes(self):
        first = self.rows({'applied': 4, 'round': 1000}, [], 1000)[0]
        self.assertEqual((first['behind'], first['lag_since'], first['alarm']), (6, 1000, ''), 'behind, not long yet')
        later = self.rows({'applied': 4, 'round': 1290}, [first], 1301)[0]
        self.assertIn('6 journal entries behind for 5 min', later['alarm'])
        back = self.rows({'applied': 10, 'round': 1350}, [later], 1360)[0]
        self.assertEqual((back['behind'], back['lag_since'], back['alarm']), (0, None, ''), 'in step again: no alarm')

    def test_follow_loop_without_rounds(self):
        row = self.rows({'applied': 10, 'round': 1000}, [], 1121)[0]
        self.assertIn('finished no round for 121 s', row['alarm'])
        self.assertEqual(self.rows({'applied': 10, 'round': 1100}, [], 1121)[0]['alarm'], '')
        self.assertEqual(self.rows({'applied': 10}, [], 5000)[0]['alarm'], '', 'a node of before 6.0.0.6.6.2 sends no heartbeat')

    def test_raised_once_and_shown_in_the_status(self):
        service = load('next/usr/local/sbin/efa-cluster.py', 'efa_cluster_lag')
        calls = []
        with tempfile.TemporaryDirectory() as etc:
            os.makedirs(os.path.join(etc, 'eFa', 'cluster'))
            with mock.patch.object(service, 'ETC', etc), mock.patch.object(service, 'BASE', os.path.join(etc, 'eFa', 'cluster')), \
                    mock.patch.object(service.efa_cluster, 'journal_read', lambda base: [{'seq': 10}]), \
                    mock.patch.object(service.subprocess, 'run', lambda command, **k: calls.append(command) or types.SimpleNamespace(returncode=0, stdout='', stderr='')), \
                    mock.patch.object(service.syslog, 'syslog', lambda *a: None):
                answer = {'applied': 4, 'round': 100}
                service.poll_health(STATE, call=lambda node: answer, mx=lambda: None, now=100)
                service.poll_health(STATE, call=lambda node: answer, mx=lambda: None, now=500)
                service.poll_health(STATE, call=lambda node: answer, mx=lambda: None, now=560)
                alarms = [command for command in calls if 'cluster-alarm' in command]
                self.assertEqual(len(alarms), 1, 'once per alarm, not every minute')
                self.assertEqual(alarms[0][alarms[0].index('--node') + 1], 'node-b')
                with open(efa_cluster.health_file(etc)) as f:
                    self.assertIn('journal entries behind', json.load(f)['nodes'][0]['alarm'])

    def test_status_answers_while_efactl_status_hangs(self):
        import subprocess
        service = load('next/usr/local/sbin/efa-cluster.py', 'efa_cluster_lag3')

        def hang(command, **kwargs):
            raise subprocess.TimeoutExpired(command, 30)
        with tempfile.TemporaryDirectory() as etc:
            os.makedirs(os.path.join(etc, 'eFa', 'cluster'))
            with mock.patch.object(service, 'ETC', etc), mock.patch.object(service.subprocess, 'run', hang):
                answer = service.node_status()
        self.assertEqual(answer['status'], 'unknown')
        self.assertIn('round', answer, 'the heartbeat still goes to the master')
        self.assertLess(service.STATUS_SECONDS, 5, 'the node answers before the master (5 s) gives up')

    def test_sync_self_test_ignores_the_cluster_of_the_host(self):
        # 2026-11-19: a CI host still in a two-node test (a real /etc/eFa/cluster with node-b) failed the self-test.
        service = load('next/usr/local/sbin/efa-cluster.py', 'efa_cluster_lag4')
        real = {'role': 'master', 'name': 'node-a', 'nodes': {'node-b': {'host': '192.0.2.2', 'port': 8460}}}
        original = service.efa_cluster.read_state
        with mock.patch.object(service.efa_cluster, 'read_state', lambda etc='/etc': real if etc == '/etc' else original(etc)):
            service.sync_self_test()
        self.assertEqual(service.ETC, '/etc', 'the folder of the host is back afterwards')

    def test_heartbeat_in_the_status_of_a_node(self):
        service = load('next/usr/local/sbin/efa-cluster.py', 'efa_cluster_lag2')
        self.assertIn("'round': FOLLOW_ROUND['at']", open(os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-cluster.py'), encoding='utf-8').read())
        self.assertEqual(service.FOLLOW_ROUND, {'at': 0})


if __name__ == '__main__':
    unittest.main()
