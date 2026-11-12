# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""8g: the send limits of efa-outbound hold for the whole cluster. Three nodes in one process: a master (efa-cluster.py with its
real HTTPS server, mutual TLS with certificates of its own CA, made by efa_cluster as on a host) and two clients; each node has
its own Redis (efa_redis.Memory) and its own RateWatch of efa-outbound. A sender spread over the nodes is counted as one."""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error

sys.dont_write_bytecode = True
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
LIB = os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python')
if LIB not in sys.path:
    sys.path.insert(0, LIB)
import efa_cluster  # noqa: E402
import efa_redis  # noqa: E402


def load(path, name, etc=None):
    if etc:
        os.environ['EFA_ETC'] = etc
    try:
        loader = importlib.machinery.SourceFileLoader(name, os.path.join(ROOT, path))
        module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
        loader.exec_module(module)
        return module
    finally:
        os.environ.pop('EFA_ETC', None)


outbound = load('next/usr/local/sbin/efa-outbound.py', 'efa_outbound_rates')
LIMITS = {'recipients_hour': 10, 'domains_hour': 3}


class Node:
    def __init__(self, root, name):
        self.etc, self.name = os.path.join(root, name), name
        self.base = efa_cluster.folder(self.etc)
        os.makedirs(self.base)
        self.redis = efa_redis.Memory()
        self.watch = outbound.RateWatch(outbound.RedisCounts(self.redis))

    def certificate(self, ca_base):
        csr = efa_cluster.make_request(self.base, self.name)
        pem = efa_cluster.sign(ca_base, csr, self.name)
        with open(os.path.join(self.base, 'node.crt'), 'w') as f:
            f.write(pem)
        if ca_base != self.base:
            shutil.copy(os.path.join(ca_base, 'ca.crt'), os.path.join(self.base, 'ca.crt'))
        self.fingerprint = efa_cluster.fingerprint_pem(pem)

    def send(self, who, recipients):
        return self.watch.add(who, recipients, LIMITS)

    def share(self):
        return self.module.share_rates(efa_cluster.read_state(self.etc), self.redis)


class ClusterRatesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix='efa-cluster-rates-')
        cls.master, cls.mx2, cls.mx3 = Node(cls.root, 'mx-1'), Node(cls.root, 'mx-2'), Node(cls.root, 'mx-3')
        efa_cluster.make_ca(cls.master.base, 'mx-1')
        for node in (cls.master, cls.mx2, cls.mx3):
            node.certificate(cls.master.base)
        # A stranger: a certificate of another CA with the same node name.
        cls.stranger = Node(cls.root, 'stranger')
        efa_cluster.make_ca(cls.stranger.base, 'mx-2')
        cls.stranger.name = 'mx-2'
        cls.stranger.certificate(cls.stranger.base)
        # It trusts the real master, so only its own certificate can be refused.
        shutil.copy(os.path.join(cls.master.base, 'ca.crt'), os.path.join(cls.stranger.base, 'ca.crt'))
        cls.master.module = load('next/usr/local/sbin/efa-cluster.py', 'efa_cluster_master', cls.master.etc)
        server = cls.master.module.TLSServer(('127.0.0.1', 0), cls.master.module.Handler)
        server.ssl_context = efa_cluster.context(cls.master.base, server=True)
        cls.server, cls.port = server, server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        efa_cluster.write_state({'role': 'master', 'name': 'mx-1', 'port': cls.port,
                                 'nodes': {node.name: {'host': '127.0.0.1', 'port': 9, 'fingerprint': node.fingerprint} for node in (cls.mx2, cls.mx3)}},
                                cls.master.etc)
        for node in (cls.mx2, cls.mx3, cls.stranger):
            efa_cluster.write_state({'role': 'client', 'name': node.name,
                                     'master': {'host': '127.0.0.1', 'port': cls.port, 'fingerprint': cls.master.fingerprint}}, node.etc)
            node.module = load('next/usr/local/sbin/efa-cluster.py', f'efa_cluster_{node.etc[-5:]}', node.etc)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.root, ignore_errors=True)

    def setUp(self):
        self.master.module.Handler.rates = {}
        for node in (self.master, self.mx2, self.mx3):
            node.redis.data.clear()
            node.watch.windows.clear()

    def round(self):
        """Half a minute of the cluster: every node reports; the order does not matter after two rounds."""
        for _ in range(2):
            for node in (self.mx2, self.mx3, self.master):
                node.share()

    def test_recipients_of_one_sender_over_all_nodes(self):
        self.assertIsNone(self.mx2.send('anna', [f'a{n}@x.example' for n in range(4)]))
        self.assertIsNone(self.mx3.send('anna', [f'b{n}@x.example' for n in range(4)]))
        self.assertIsNone(self.master.send('anna', ['c@x.example']))
        self.round()
        # 4 + 4 + 1 elsewhere and here, plus 2: 11 of 10. Each node alone would have let it through.
        self.assertEqual(self.mx2.send('anna', ['d@x.example', 'e@x.example']), 'recipients')
        self.assertEqual(self.mx2.redis.data['efa:rate:who:anna:%d:pr' % (time.time() // 3600)], '5')
        # The own count stays the own one: reported again, it is not counted twice.
        self.round()
        self.assertEqual(self.mx3.redis.data['efa:rate:who:anna:%d:pr' % (time.time() // 3600)], '7')

    def test_target_domains_count_once(self):
        self.assertIsNone(self.mx2.send('bert', ['a@d1.example', 'b@d2.example']))
        self.assertIsNone(self.mx3.send('bert', ['c@d2.example', 'd@d3.example']))
        self.round()
        self.assertIsNone(self.mx2.send('bert', ['e@d1.example']), 'd1, d2, d3: three domains of three')
        self.assertEqual(self.mx3.send('bert', ['f@d4.example']), 'domains')

    def test_sender_domain_limit_over_the_cluster(self):
        limits = {'domain_recipients_hour': 5}
        self.assertIsNone(self.mx2.watch.add('anna', ['a@x.example'] * 3, limits, domain='own.example'))
        self.assertIsNone(self.mx3.watch.add('bert', ['b@x.example'] * 2, limits, domain='own.example'))
        self.round()
        self.assertEqual(self.mx2.watch.add('carl', ['c@x.example'], limits, domain='own.example'), 'sender-domain')

    def test_master_down_each_node_counts_its_own(self):
        self.mx2.send('anna', ['a@x.example'] * 6)
        state = efa_cluster.read_state(self.mx3.etc)
        state['master'] = {**state['master'], 'port': 9}
        with self.assertRaises(OSError):
            self.mx3.module.share_rates(state, self.mx3.redis)
        self.assertIsNone(self.mx3.send('anna', ['b@x.example'] * 6), 'no counts of the others: the own limit only')
        self.assertEqual(self.mx3.send('anna', ['b@x.example'] * 5), 'recipients')

    def test_stranger_cannot_report(self):
        state = efa_cluster.read_state(self.stranger.etc)
        with self.assertRaises((OSError, urllib.error.HTTPError)):
            self.stranger.module.share_rates(state, efa_redis.Memory())
        self.assertNotIn('mx-2', self.master.module.Handler.rates)

    def test_reports_are_cleaned_and_age(self):
        now, hour = 100000.0, 27
        table = efa_cluster.merge_rates({}, 'mx-2', hour, {'who:anna': [3, ['X.example', 'y.example']], 'bad:key': [1, []], 'who:bert': ['3', []],
                                                           'who:carl': [-1, []], 'who:dora': [2, ['ok.example', 5, 'a' * 300]]}, now)
        self.assertEqual(table['mx-2']['keys'], {'who:anna': [3, ['x.example', 'y.example']], 'who:dora': [2, ['ok.example']]})
        table = efa_cluster.merge_rates(table, 'mx-3', hour, {'who:anna': [2, ['y.example', 'z.example']]}, now + 10)
        self.assertEqual(efa_cluster.peer_rates(table, 'mx-1', hour, now + 10)['who:anna'], [5, ['x.example', 'y.example', 'z.example']])
        self.assertEqual(efa_cluster.peer_rates(table, 'mx-2', hour, now + 10)['who:anna'], [2, ['y.example', 'z.example']])
        self.assertEqual(efa_cluster.peer_rates(table, 'mx-1', hour + 1, now + 10), {}, 'another hour')
        later = now + efa_cluster.RATE_SECONDS + 5
        self.assertEqual(efa_cluster.peer_rates(table, 'mx-1', hour, later)['who:anna'], [2, ['y.example', 'z.example']], 'mx-2 is silent')
        self.assertNotIn('mx-2', efa_cluster.merge_rates(table, 'mx-3', hour, {}, later))

    def test_report_size_is_bounded(self):
        hour = int(time.time() // 3600)
        redis = efa_redis.Memory()
        watch = outbound.RateWatch(outbound.RedisCounts(redis))
        for n in range(250):
            watch.add(f'spray{n}', [f'a@d{m}.example' for m in range(200)], {})
        report = efa_cluster.rate_report(redis, hour)
        self.assertEqual(len(report), 250)
        self.assertTrue(all(len(domains) <= efa_cluster.RATE_DOMAINS for _count, domains in report.values()))
        self.assertLessEqual(sum(len(domains) for _count, domains in report.values()), efa_cluster.RATE_DOMAINS_TOTAL)
        self.assertLess(len(json.dumps({'hour': hour, 'rates': report})), self.master.module.RATES_BODY)


if __name__ == '__main__':
    unittest.main()
