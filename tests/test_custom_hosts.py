# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""Own host names (2026-11-19): names and addresses like /etc/hosts, for unbound (Postfix, rspamd) and /etc/hosts; handed on in
a cluster (hosts-set) or kept on one node (hosts-local-set); a change unbound refuses leaves everything as it was."""

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, os.path.join(ROOT, *path.split('/')))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


class Platform:
    def __init__(self):
        self.restarts, self.active = [], True

    def service_restart(self, name, check=True):
        self.restarts.append(name)

    def service_is_active(self, name):
        return self.active


class CustomHosts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load('efactl_custom_hosts', 'next/usr/sbin/efactl')

    def setUp(self):
        e = self.efactl
        self.tmp = tempfile.TemporaryDirectory()
        etc = self.tmp.name
        os.makedirs(etc + '/eFa/local.d')
        os.makedirs(etc + '/unbound/conf.d')
        with open(etc + '/hosts', 'w') as f:
            # The block of the own name, as efa_common.replace_block writes it (its marker name is the technical 'eFa').
            own = 'eFa'
            f.write(f'127.0.0.1 localhost\n10.0.0.9 nas.corp.example nas\n# BEGIN {own} managed block\n10.0.0.2 mx1.example.org mx1\n# END {own} managed block\n')
        self.platform, self.checkconf, self.audit = Platform(), {'code': 0}, []
        run = lambda cmd, **kw: subprocess.CompletedProcess(cmd, self.checkconf['code'], '', 'syntax error' if self.checkconf['code'] else '')
        self.patches = [mock.patch.object(e, 'HOSTS_SHARED', etc + '/eFa/hosts.json'), mock.patch.object(e, 'HOSTS_LOCAL', etc + '/eFa/local.d/hosts.json'),
                        mock.patch.object(e, 'HOSTS_CONF', etc + '/unbound/conf.d/efa-hosts.conf'), mock.patch.object(e, 'HOSTS', etc + '/hosts'),
                        mock.patch.object(e, 'ETC', etc), mock.patch.object(e, '_platform', lambda: self.platform),
                        mock.patch.object(e, '_audit', self.audit.append), mock.patch.object(e, '_dmarc_who', lambda: 'admin'),
                        mock.patch.object(e, 'own_hostname', lambda: 'mx1.example.org'), mock.patch.object(e, 'cluster_role', lambda: 'none'),
                        mock.patch.object(e.subprocess, 'run', run), mock.patch.object(e.time, 'sleep', lambda s: None),
                        mock.patch.object(e, '_conf_own', lambda path, mode, group: os.chmod(path, mode))]
        for patch in self.patches:
            patch.start()
        self.etc = etc

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        self.tmp.cleanup()

    def change(self, func, **args):
        return func(types.SimpleNamespace(**{'action': 'add', 'addresses': '', 'note': '', **args}))

    def read(self, path):
        with open(self.etc + path) as f:
            return f.read()

    def test_names_and_addresses_are_checked(self):
        e = self.efactl
        for bad in ('', 'a b', '-x.example', 'x..example', 'bad_name.example', '$(id)', '10.0.0.1', 'a' * 64 + '.example', 'x.example;reboot'):
            with self.assertRaises(e.EfaError, msg=bad):
                e.hosts_name(bad, protected=set())
        self.assertEqual(e.hosts_name('Git.Corp.Example.', protected=set()), 'git.corp.example')
        self.assertEqual(e.hosts_name('backup', protected=set()), 'backup')
        for name in ('localhost', 'repo.efa-next.eu', 'acme-v02.api.letsencrypt.org', '2.0.0.127.zen.spamhaus.org', 'bl.spamcop.net',
                     '1.0.0.10.in-addr.arpa', 'psbl.surriel.com', 'dnsbl-1.uceprotect.net'):
            with self.assertRaises(e.EfaError, msg=name):
                e.hosts_name(name)
        with self.assertRaises(e.EfaError):
            e.hosts_name('mx1', protected=set(), own='mx1.example.org')
        self.assertEqual(e.hosts_addresses('10.0.0.5, 2001:DB8::5 10.0.0.5'), ['10.0.0.5', '2001:db8::5'])
        for bad in ('', '127.0.0.1', '::1', '169.254.1.1', 'fe80::1', '224.0.0.1', '0.0.0.0', '240.0.0.1', '10.0.0.300', 'host',
                    '10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5'):
            with self.assertRaises(e.EfaError, msg=bad):
                e.hosts_addresses(bad)

    def test_unbound_answers_only_a_and_aaaa_and_ptr_only_for_private(self):
        text = self.efactl.hosts_unbound_text({'git.corp.example': {'addresses': ['10.0.0.5', '2001:db8::5']},
                                               'relay.partner.example': {'addresses': ['192.0.2.20', '10.0.0.5']}})
        self.assertIn('local-zone: "git.corp.example." typetransparent', text)
        self.assertIn('local-data: "git.corp.example. 300 IN A 10.0.0.5"', text)
        self.assertIn('local-data: "git.corp.example. 300 IN AAAA 2001:db8::5"', text)
        self.assertIn('local-data-ptr: "10.0.0.5 300 git.corp.example."', text)
        self.assertEqual(text.count('local-data-ptr: "10.0.0.5'), 1, 'one PTR per address, from the first name')
        self.assertIn('local-data-ptr: "2001:db8::5 300 git.corp.example."', text, '2001:db8::/32 counts as private (documentation)')
        self.assertIn('local-data: "relay.partner.example. 300 IN A 192.0.2.20"', text)

    def test_ptr_never_for_a_public_address(self):
        text = self.efactl.hosts_unbound_text({'out.example': {'addresses': ['198.18.0.1', '8.8.4.4']}})
        self.assertNotIn('8.8.4.4 300', text)
        self.assertIn('local-data: "out.example. 300 IN A 8.8.4.4"', text)

    def test_add_list_remove_standalone(self):
        e = self.efactl
        result = self.change(e.hosts_set, name='Git.Corp.Example', addresses='10.0.0.5 2001:db8::5', note='git  server')
        self.assertEqual(result['entries']['git.corp.example'], {'addresses': ['10.0.0.5', '2001:db8::5'], 'note': 'git server', 'scope': 'cluster'})
        self.assertFalse(result['cluster'])
        self.assertIn('IN A 10.0.0.5', self.read('/unbound/conf.d/efa-hosts.conf'))
        hosts = self.read('/hosts')
        self.assertIn('# BEGIN eFa-next host names managed block\n10.0.0.5 git.corp.example\n2001:db8::5 git.corp.example\n# END eFa-next host names managed block\n', hosts)
        self.assertIn('10.0.0.2 mx1.example.org mx1', hosts, 'the block of the own name stays')
        self.assertTrue(hosts.startswith('127.0.0.1 localhost\n10.0.0.9 nas.corp.example nas\n'), 'lines of the admin stay first')
        self.assertEqual(json.loads(self.read('/eFa/hosts.json'))['entries']['git.corp.example']['addresses'], ['10.0.0.5', '2001:db8::5'])
        self.assertEqual(os.stat(self.etc + '/eFa/hosts.json').st_mode & 0o777, 0o640)
        self.assertEqual(self.platform.restarts, ['unbound'])
        self.assertTrue(any('git.corp.example = 10.0.0.5 2001:db8::5 by admin' in line for line in self.audit))
        self.change(e.hosts_set, name='nas.corp.example', addresses='10.0.0.10')
        self.assertEqual(e.hosts_list(None)['also_by_hand'], ['nas.corp.example'], 'a line of the admin wins in /etc/hosts: shown')
        self.assertEqual(e.hosts_show(e.HOSTS_SHARED), {'git.corp.example': '10.0.0.5, 2001:db8::5 (git server)', 'nas.corp.example': '10.0.0.10'})
        self.change(e.hosts_set, name='git.corp.example', action='remove')
        self.change(e.hosts_set, name='nas.corp.example', action='remove')
        self.assertFalse(os.path.exists(self.etc + '/unbound/conf.d/efa-hosts.conf'), 'no names, no file of unbound')
        self.assertNotIn('host names managed block', self.read('/hosts'), 'no names, no block')
        with self.assertRaises(e.EfaError):
            self.change(e.hosts_set, name='gone.example', action='remove')
        with self.assertRaises(e.EfaError):
            self.change(e.hosts_set, name='x.example', action='drop', addresses='10.0.0.1')

    def test_a_change_unbound_refuses_leaves_everything(self):
        e = self.efactl
        self.change(e.hosts_set, name='a.corp.example', addresses='10.0.0.1')
        before = (self.read('/unbound/conf.d/efa-hosts.conf'), self.read('/eFa/hosts.json'), self.read('/hosts'))
        self.checkconf['code'] = 1
        with self.assertRaises(e.EfaError):
            self.change(e.hosts_set, name='b.corp.example', addresses='10.0.0.2')
        self.assertEqual((self.read('/unbound/conf.d/efa-hosts.conf'), self.read('/eFa/hosts.json'), self.read('/hosts')), before)
        self.checkconf['code'], self.platform.active = 0, False
        with self.assertRaises(e.EfaError):
            self.change(e.hosts_set, name='b.corp.example', addresses='10.0.0.2')
        self.assertEqual((self.read('/unbound/conf.d/efa-hosts.conf'), self.read('/eFa/hosts.json'), self.read('/hosts')), before)

    def test_the_name_of_this_host_wins_and_stays_local(self):
        e = self.efactl
        self.change(e.hosts_set, name='db.corp.example', addresses='10.0.0.20')
        result = self.change(e.hosts_local_set, name='db.corp.example', addresses='10.1.0.20')
        self.assertEqual(result['entries']['db.corp.example']['addresses'], ['10.1.0.20'])
        self.assertEqual(result['entries']['db.corp.example']['scope'], 'host')
        self.assertIn('IN A 10.1.0.20', self.read('/unbound/conf.d/efa-hosts.conf'))
        self.assertNotIn('10.0.0.20', self.read('/unbound/conf.d/efa-hosts.conf'))
        self.assertEqual(json.loads(self.read('/eFa/hosts.json'))['entries']['db.corp.example']['addresses'], ['10.0.0.20'],
                         'the shared file keeps its own entry')
        self.assertEqual(json.loads(self.read('/eFa/local.d/hosts.json'))['entries']['db.corp.example']['addresses'], ['10.1.0.20'])
        self.change(e.hosts_local_set, name='db.corp.example', action='remove')
        self.assertIn('IN A 10.0.0.20', self.read('/unbound/conf.d/efa-hosts.conf'), 'the name of the cluster again')

    def test_apply_writes_only_what_changed(self):
        e = self.efactl
        self.change(e.hosts_set, name='a.corp.example', addresses='10.0.0.1')
        self.platform.restarts.clear()
        e.hosts_apply(None)
        self.assertEqual(self.platform.restarts, [], 'unchanged: unbound keeps running')
        os.remove(self.etc + '/unbound/conf.d/efa-hosts.conf')
        with open(self.etc + '/hosts', 'w') as f:
            f.write('127.0.0.1 localhost\n')
        e.hosts_apply(None)
        self.assertEqual(self.platform.restarts, ['unbound'])
        self.assertIn('10.0.0.1 a.corp.example', self.read('/hosts'))

    def test_limit(self):
        e = self.efactl
        with mock.patch.object(e, 'HOSTS_MAX', 2):
            self.change(e.hosts_set, name='a.example', addresses='10.0.0.1')
            self.change(e.hosts_local_set, name='b.example', addresses='10.0.0.2')
            with self.assertRaises(e.EfaError):
                self.change(e.hosts_set, name='c.example', addresses='10.0.0.3')
            self.change(e.hosts_set, name='a.example', addresses='10.0.0.9')


class Cluster(unittest.TestCase):
    """Each command declares how a cluster treats it (release thread, 2026-11-19): no implicit default."""

    @classmethod
    def setUpClass(cls):
        cls.efactl = load('efactl_custom_hosts_cluster', 'next/usr/sbin/efactl')

    def test_declared(self):
        e = self.efactl
        self.assertTrue(e.cluster_replicated('hosts-set'))
        self.assertEqual(e.CLUSTER_HOSTS_SHARED, {'hosts-set'})
        for name in ('hosts-local-set', 'hosts-apply'):
            self.assertIn(name, e.CLUSTER_LOCAL)
            self.assertFalse(e.cluster_replicated(name))
        self.assertFalse(e.cluster_replicated('hosts-list'))

    def test_snapshot_takes_the_shared_file_never_the_local_one(self):
        e = self.efactl
        with tempfile.TemporaryDirectory() as etc:
            os.makedirs(etc + '/eFa/local.d')
            for path in ('/eFa/hosts.json', '/eFa/local.d/hosts.json'):
                with open(etc + path, 'w') as f:
                    f.write('{"entries": {}}')
            with mock.patch.object(e, 'ETC', etc), mock.patch.object(e, 'RSPAMD_DIR', etc + '/rspamd'), \
                    mock.patch.object(e, 'SUB_DOVECOT', etc + '/none1'), mock.patch.object(e, 'SUB_PASSWD', etc + '/none2'):
                files = [os.path.relpath(path, etc) for path in e.snapshot_files()]
        self.assertIn('eFa/hosts.json', files)
        self.assertNotIn('eFa/local.d/hosts.json', files)


if __name__ == '__main__':
    unittest.main()
