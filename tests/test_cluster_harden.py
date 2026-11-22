# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hardening of the cluster (Hans 2026-11-18): the master sends a job with fixed values only (never a command line), only from
its current certificate, with an id and an expiry; each node checks the values against its own lists, applies them itself,
never lowers anything, keeps a step that fails as it was and goes on; the SSH profile only on ticked hosts, waiting for a
confirmation on the host; one run at a time; audited on both sides; a new node takes the master's choice after a preview."""
import json
import os
import shutil
import tempfile
import time
import types
import unittest
from unittest import mock

from test_cluster_rates import efa_cluster, load
from test_threat import load_efactl


class Node(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, True)
        open(self.folder + '/monitor.cron', 'w').close()
        self.calls, self.audited = [], []
        e = self.efactl
        patches = {'MONITOR_CRON': self.folder + '/monitor.cron', '_ru_state': lambda: {}, '_audit': self.audited.append,
                   'standards_data': lambda: {'standards': {'bsi-02102-2': {}, 'rfc9325': {}}},
                   'standards_state': lambda: {'selected': ['rfc9325']},
                   'standards_set': lambda args: self.calls.append(('standards', args.select, args.keep_ssh, args.apply)) or {'changes': [1, 2]},
                   '_os_item_on': lambda item: item == 'auditd',
                   'os_harden_set': lambda args: self.calls.append(('os', args.item, args.mode)),
                   'kernel_state': lambda: 'off', 'kernel_hardening_set': lambda args: self.calls.append(('kernel', args.mode)),
                   'service_harden_status': lambda _a: {'mode': 'on'}, 'service_harden': lambda args: self.calls.append(('sandbox', args.mode)),
                   'ssh_profile_now': lambda sshd=None: 'system', 'ssh_profile_set': lambda args: self.calls.append(('ssh', args.mode))}
        for name, value in patches.items():
            patch = mock.patch.object(e, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        e._harden().OS_HARDEN  # noqa: B018 - present

    def values(self, **change):
        return {'standards': ['bsi-02102-2'], 'os': ['auditd', 'chronyd'], 'port25_tls': '', 'ssh': 'bsi', 'sandbox': 'default', 'kernel': 'on', **change}

    def test_schema_of_the_node(self):
        for bad in ({'standards': ['nope']}, {'os': ['rm -rf /']}, {'ssh': 'system'}, {'sandbox': 'off'}, {'kernel': 'off'}, {'port25_tls': 'off'},
                    {'command': 'id'}, {'standards': 'bsi-02102-2'}):
            with self.assertRaises(self.efactl.EfaError, msg=bad):
                self.efactl.harden_values({**self.values(), **bad} if 'command' not in bad else {**self.values(), **bad})

    def test_applies_only_more_and_ssh_only_when_ticked(self):
        results = {row['step']: row for row in self.efactl.harden_apply(self.values(), ssh_ok=False)}
        self.assertIn(('standards', 'bsi-02102-2 rfc9325', 'yes', 'yes'), self.calls, 'the chosen added to what is chosen; SSH kept')
        self.assertIn(('os', 'chronyd', 'on'), self.calls)
        self.assertNotIn(('os', 'auditd', 'on'), self.calls, 'on already')
        self.assertIn(('kernel', 'on'), self.calls)
        self.assertNotIn('sandbox', [c[0] for c in self.calls], 'on is more than default: never less')
        self.assertEqual(results['sandbox']['state'], 'kept')
        self.assertEqual((results['SSH profile']['state'], results['SSH profile']['detail']), ('kept', 'not ticked for this host'))
        self.assertNotIn('ssh', [c[0] for c in self.calls])
        self.assertTrue(all('cluster hardening by master' in line for line in self.audited), 'audited on the node')
        self.calls.clear()
        results = {row['step']: row for row in self.efactl.harden_apply(self.values(), ssh_ok=True)}
        self.assertIn(('ssh', 'bsi'), self.calls)
        self.assertEqual(results['SSH profile']['state'], 'waiting', 'the host confirms itself, the master waits')

    def test_failed_step_keeps_its_state_and_the_others_go_on(self):
        with mock.patch.object(self.efactl, 'kernel_hardening_set', side_effect=self.efactl.EfaError('sysctl refused')):
            results = {row['step']: row for row in self.efactl.harden_apply(self.values())}
        self.assertEqual((results['kernel']['state'], results['kernel']['detail']), ('failed', 'sysctl refused'))
        self.assertEqual(results['operating system']['state'], 'ok', 'the next steps went on')

    def test_preview_changes_nothing_and_maintenance_blocks_only_the_real_run(self):
        os.remove(self.folder + '/monitor.cron')
        results = self.efactl.harden_apply(self.values(), preview=True, ssh_ok=True)
        self.assertEqual([c for c in self.calls if c[0] != 'standards'], [], 'nothing switched in a preview')
        self.assertTrue(all(c[3] == '' for c in self.calls if c[0] == 'standards'), 'standards only previewed')
        self.assertIn('preview', [row['state'] for row in results])
        with self.assertRaises(self.efactl.EfaError):
            self.efactl.harden_apply(self.values())
        open(self.folder + '/monitor.cron', 'w').close()
        with mock.patch.object(self.efactl, '_ru_state', lambda: {'state': 'upgrading'}):
            with self.assertRaises(self.efactl.EfaError):
                self.efactl.harden_apply(self.values())

    def test_only_from_the_cluster_service(self):
        with mock.patch.dict(os.environ, {'SUDO_USER': 'efa-web'}):
            with self.assertRaises(self.efactl.EfaError):
                self.efactl.cluster_harden_apply(None)


class Master(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder, True)
        self.state = {'role': 'master', 'name': 'node-b', 'mode': 'ha', 'nodes': {'node-a': {'host': 'node-a', 'port': 8460}, 'node-c': {'host': 'node-c', 'port': 8460, 'pending': True}},
                      'harden': {'standards': ['bsi-02102-2'], 'os': [], 'port25_tls': '', 'ssh': 'bsi', 'sandbox': '', 'kernel': 'on', 'ssh_hosts': ['node-a']}}
        self.fake = types.SimpleNamespace(active_nodes=efa_cluster.active_nodes, job_envelope=efa_cluster.job_envelope,
                                          write_state=lambda state, etc: None, call=lambda *a, **kw: {})
        for name, value in {'_cluster_parts': lambda: (self.fake, '/b', self.state), 'CLUSTER_HARDEN_JOB': self.folder + '/job.json',
                            'CLUSTER_JOIN_JOB': self.folder + '/join.json', '_audit': lambda text: None,
                            'harden_apply': lambda values, preview=False, ssh_ok=False, by='master': [{'step': 'standards', 'state': 'ok', 'detail': by}]}.items():
            patch = mock.patch.object(self.efactl, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def test_run_master_first_then_each_taking_node_by_its_own_job(self):
        sent = []
        job = self.efactl.cluster_harden_run(None, call=lambda node, body: sent.append((node['host'], body)) or {'results': [{'step': 'standards', 'state': 'ok'}]})
        self.assertEqual([host['host'] for host in job['hosts']], ['node-b', 'node-a'], 'the master, then the nodes; a pending one not')
        host, body = sent[0]
        self.assertEqual(body['job'], 'harden')
        self.assertTrue(body['id'] and body['expires'] - body['issued'] <= efa_cluster.JOB_SECONDS)
        self.assertEqual(sorted(body), ['expires', 'id', 'issued', 'job', 'preview', 'ssh', 'values'], 'only the values, never a command')
        self.assertIs(body['ssh'], True, 'node-a is ticked for SSH')
        self.assertEqual(job['state'], 'done')

    def test_one_run_at_a_time(self):
        with open(self.folder + '/join.json', 'w') as f:
            json.dump({'state': 'running'}, f)
        args = types.SimpleNamespace(select='bsi-02102-2', os='', port25_tls='', ssh='', sandbox='', kernel='', ssh_hosts='', preview='', confirm='yes')
        with mock.patch.object(self.efactl, 'harden_values', lambda values: values), mock.patch.object(self.efactl, '_dmarc_who', lambda: 'x'):
            with self.assertRaises(self.efactl.EfaError):
                self.efactl.cluster_harden(args)

    def test_status_waits_for_the_ssh_confirmation_of_the_host(self):
        with open(self.folder + '/job.json', 'w') as f:
            json.dump({'state': 'done', 'hosts': [{'host': 'node-a', 'results': [{'step': 'SSH profile', 'state': 'waiting', 'detail': ''}]}]}, f)
        self.fake.call = lambda *a, **kw: {'profile': 'bsi', 'confirmed': False}
        self.assertEqual(self.efactl.cluster_harden_status(None)['hosts'][0]['results'][0]['state'], 'waiting', 'within its 10 minutes')
        self.fake.call = lambda *a, **kw: {'profile': 'bsi', 'confirmed': True}
        self.assertEqual(self.efactl.cluster_harden_status(None)['hosts'][0]['results'][0]['state'], 'confirmed')
        self.fake.call = lambda *a, **kw: {'profile': 'system', 'confirmed': False}
        self.assertEqual(self.efactl.cluster_harden_status(None)['hosts'][0]['results'][0]['state'], 'reverted')


class Service(unittest.TestCase):
    def test_only_the_current_master_and_a_fresh_job(self):
        etc = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, etc, True)
        service = load('next/usr/local/sbin/efa-cluster.py', 'efa_cluster_service_harden', etc)
        handler = open(service.__file__, encoding='utf-8').read()
        part = handler.split("if self.path == '/v1/harden':")[1].split("if self.path == '/v1/alarm':")[0]
        self.assertIn("self.peer() != 'master'", part, 'member() names the master only by the fingerprint in the state of this node')
        self.assertIn("problem = take_job(body, 'harden')", part)
        self.assertIn("[EFACTL, 'cluster-harden-apply'], input=json.dumps", part, 'the values on stdin, never in arguments')
        self.assertIn("state.get('pending')", part)
        self.assertNotIn('cluster-harden-apply', service.MASTER_RUNS, 'not a command the master may run with arguments')
        member = service.member({'role': 'client', 'master': {'fingerprint': 'AA'}}, 'BB')
        self.assertIsNone(member, 'another cert (another node) is not the master')


class Gates(unittest.TestCase):
    def test_gates(self):
        efactl = load_efactl()
        for name in ('cluster-harden', 'cluster-harden-run', 'cluster-harden-status', 'cluster-harden-apply'):
            self.assertIn(name, efactl.SUPER_COMMANDS)
            self.assertFalse(efactl.command_allowed({'username': 'a', 'role': 'custom', 'grants': {'settings.edit'}}, name, True), name)
        from test_bec_page import load_web
        web = load_web()
        self.assertIn('cluster-harden', web.REAUTH_COMMANDS)
        self.assertIn('cluster-harden-apply', web.NOT_CALLABLE)
        self.assertIn('cluster-harden-run', web.NOT_CALLABLE)


class Web(unittest.TestCase):
    def test_card_live_and_escaped(self):
        from test_bec_page import SCHEMA, load_web
        import efa_nav
        web = load_web()
        names = {name for section in efa_nav.PAGES['cluster']['sections'] for name in section[1]}
        schema = {name: SCHEMA[name] for name in names if name in SCHEMA}
        status = {'cluster-status': {'role': 'master', 'name': 'node-b', 'breakglass': True, 'nodes': []},
                  'cluster-harden-status': {'state': 'running', 'hosts': [{'host': 'node-a<b>', 'results': [
                      {'step': 'kernel', 'state': 'failed', 'detail': '<script>x</script>'}, {'step': 'SSH profile', 'state': 'waiting', 'detail': ''}]}]}}

        def fake(*args, secrets_in=None, who=None):
            if args[0] == 'schema':
                return True, schema
            if args[0] == 'session-check':
                return True, {'active': True}
            return True, status.get(args[0], {})
        web.efactl = fake
        web.efactl_read = fake
        https = {'base_url': 'https://localhost'}
        client = web.app.test_client()
        with client.session_transaction(**https) as sess:
            sess.update(admin=True, csrf='t', sid='ch', lang='en', view='standard')
        web.active_sessions['ch'] = time.time() + 600
        web.session_checked['ch'] = time.time()
        html = client.get('/p/cluster', **https).get_data(as_text=True)
        card = html[html.index('id="cluster-hardening"'):html.index('id="cluster-upd"')]
        self.assertIn('id="cluster-live" data-url="/cluster-harden-live"', card)
        self.assertIn('<span class="b">failed</span>', card)
        self.assertIn('<span class="w">waiting for SSH confirmation</span>', card)
        self.assertNotIn('<script>', card)
        self.assertIn('node-a&lt;b&gt;', card)
        self.assertIn('#cluster-harden', card)
        live = client.get('/cluster-harden-live', **https).get_data(as_text=True)
        self.assertIn('class="cl-live" data-state="running"', live)


if __name__ == '__main__':
    unittest.main()
