# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""6.0.0.6.6.1: the status answer of a node (GET /v1/status) with the real efa_cluster library, no fake of it.
In 6.0.0.6.6 node_status() called a function the library does not have, and every status request of the master crashed."""

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


def load_service():
    loader = importlib.machinery.SourceFileLoader('efa_cluster_status_test', os.path.join(ROOT, 'next', 'usr', 'local', 'sbin', 'efa-cluster.py'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efa_cluster_status_test', loader))
    loader.exec_module(module)
    return module


class NodeStatus(unittest.TestCase):
    def test_answer_with_the_real_library(self):
        service = load_service()
        self.assertTrue(service.efa_cluster.__file__.endswith('efa_cluster.py'), 'the real library, not a fake')
        with tempfile.TemporaryDirectory() as etc:
            os.makedirs(os.path.join(etc, 'eFa', 'cluster'))
            service.efa_cluster.write_state({'role': 'client', 'name': 'node-b', 'mode': 'ha', 'applied': 3}, etc)
            # Only the efactl call and the folder: everything of the library runs as on a node.
            with mock.patch.object(service, 'ETC', etc), mock.patch.object(service, 'EFACTL', sys.executable), \
                    mock.patch.dict(os.environ, {'EFA_ETC': etc}):
                answer = service.node_status()
        text = json.dumps(answer)
        self.assertEqual(json.loads(text), answer)
        for key in ('status', 'down', 'version', 'platform', 'time', 'applied', 'failed'):
            self.assertIn(key, answer)
        self.assertEqual(answer['platform'], service.efa_cluster.own_platform())
        self.assertEqual(answer['applied'], 3)
        self.assertIsInstance(answer['time'], int)

    def test_handler_answers_status(self):
        service = load_service()
        answered = []

        class Fake(service.Handler):
            def __init__(self):  # no socket: only do_GET with a member certificate
                self.path = '/v1/status'

            def peer(self):
                return 'node-a'

            def answer(self, code, body):
                answered.append((code, json.loads(json.dumps(body))))
        with tempfile.TemporaryDirectory() as etc:
            os.makedirs(os.path.join(etc, 'eFa', 'cluster'))
            service.efa_cluster.write_state({'role': 'client', 'name': 'node-b', 'mode': 'master-client'}, etc)
            with mock.patch.object(service, 'ETC', etc), mock.patch.object(service, 'EFACTL', sys.executable):
                Fake().do_GET()
        self.assertEqual(answered[0][0], 200)
        self.assertEqual(answered[0][1]['name'], 'node-b')
        self.assertIn('platform', answered[0][1])


if __name__ == '__main__':
    unittest.main()
