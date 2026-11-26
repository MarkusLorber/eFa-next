# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""6.0.0.7: one quarantine for users in a cluster. The list of the held mail of all nodes, the actions on the node that holds a
mail, links that work on every node, one digest per recipient from the master, and the requests efa-cluster takes for it.
The cluster calls and the database are stand-ins; no test needs root, a host or the network."""

import argparse
import importlib.machinery
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
for name in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
    try:
        __import__(name)
    except ImportError:
        sys.modules[name] = types.ModuleType(name)
for folder in ('next/usr/lib/eFa/python', 'src/eFa/root/usr/lib/eFa/python', 'src/eFa-base/root/usr/lib/eFa/python'):
    if os.path.join(ROOT, folder) not in sys.path:
        sys.path.insert(0, os.path.join(ROOT, folder))


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, os.path.join(ROOT, path))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


efactl = load('next/usr/sbin/efactl', 'efactl_cq')
daemon = load('next/usr/local/sbin/efa-cluster.py', 'efa_cluster_cq')
EfaError = efactl.EfaError


class FakeCluster:
    """cluster.call of efa_cluster: answers by host, records every request."""

    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def call(self, base, host, port, path, body=None, timeout=10, expected=None):
        self.calls.append((host, path, body, timeout))
        answer = self.answers[host]
        if isinstance(answer, Exception):
            raise answer
        return answer(body) if callable(answer) else answer


MASTER_STATE = {'role': 'master', 'name': 'mx1', 'nodes': {'mx2': {'host': 'h2', 'port': 1}, 'mx3': {'host': 'h3', 'port': 1}}}
CLIENT_STATE = {'role': 'client', 'name': 'mx2', 'master': {'name': 'mx1', 'host': 'h1', 'port': 1}}


class Base(unittest.TestCase):
    def node(self, state, answers, local=False):
        cluster = FakeCluster(answers)
        patches = [mock.patch.object(efactl, '_uq_node_name', lambda: state['name']),
                   mock.patch.object(efactl, '_cluster_parts', lambda: (cluster, '/base', state)),
                   mock.patch.object(efactl, 'acting_user', 'a@x.example'), mock.patch.object(efactl, 'acting_limit', '')]
        if local:
            patches.append(mock.patch.dict(os.environ, {'EFA_UQ_LOCAL': '1'}))
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        return cluster


class Ids(unittest.TestCase):
    def test_split_and_names(self):
        self.assertEqual(efactl.uq_split('mx2:17'), ('mx2', '17'))
        self.assertEqual(efactl.uq_split('17'), (None, '17'))
        self.assertEqual(efactl.uq_split('mx2.tok-_x', '.'), ('mx2', 'tok-_x'))
        self.assertEqual(efactl.uq_named([{'id': 5, 'rcpt': 'a@x.example'}], 'mx3'), [{'id': 'mx3:5', 'rcpt': 'a@x.example', 'node': 'mx3'}])

    def test_no_login_made_from_a_request_of_the_cluster(self):
        # F4 (security review 2026-11-24): a login another node names is never made here; only the own link login makes one.
        with open(os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'), encoding='utf-8') as f:
            text = f.read()
        self.assertNotIn('_uq_link_user(args.as_user', text)
        self.assertFalse(hasattr(efactl, 'uq_link_user_wanted'))
        self.assertEqual(text.count('_uq_link_user('), 3, 'the definition, the own link login and the login link of another node')

    def test_ticket_kept_per_login_until_it_expires(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, 'tickets.json')
            efactl.uq_ticket_store('A@x.example', 't1', 3600, path, now=1000)
            self.assertEqual(efactl.uq_ticket_for('a@x.example', path, now=1500), 't1')
            self.assertEqual(efactl.uq_ticket_for('a@x.example', path, now=1000 + 3600), '', 'a minute before the master would refuse it')
            self.assertEqual(efactl.uq_ticket_for('b@x.example', path, now=1500), '')
            efactl.uq_ticket_store('b@x.example', 't2', 3600, path, now=5000)
            with open(path) as f:
                self.assertNotIn('a@x.example', json.load(f), 'expired tickets go')


class List(Base):
    def args(self, **values):
        return argparse.Namespace(command='uq-list', text=values.get('text', ''), limit=values.get('limit', ''))

    def test_alone_unchanged(self):
        with mock.patch.object(efactl, '_uq_node_name', lambda: ''), \
                mock.patch.object(efactl, '_uq_list_here', lambda args: {'mails': [{'id': 1, 'ts': '1'}], 'self_release': False}):
            self.assertEqual(efactl.uq_list(self.args()), {'mails': [{'id': 1, 'ts': '1'}], 'self_release': False})

    def test_master_merges_all_nodes_and_names_the_missing(self):
        cluster = self.node(MASTER_STATE, {'h2': {'mails': [{'id': 7, 'ts': '2026-11-12 10:00:00'}]}, 'h3': OSError('timed out')})
        with mock.patch.object(efactl, '_uq_list_here', lambda args: {'mails': [{'id': 7, 'ts': '2026-11-12 09:00:00'}], 'self_release': True}):
            result = efactl.uq_list(self.args(text='invoice'))
        self.assertEqual([row['id'] for row in result['mails']], ['mx2:7', 'mx1:7'], 'newest first, the same number on two nodes kept apart')
        self.assertEqual(result['unreachable'], ['mx3'])
        self.assertTrue(result['self_release'])
        sent = [body for _host, path, body, _t in cluster.calls if path == '/v1/uq']
        self.assertEqual(len(sent), 2)
        for body in sent:
            self.assertEqual((body['command'], body['mode'], body['as']), ('uq-list', 'local', 'a@x.example'))
            self.assertEqual(body['args']['text'], 'invoice', 'the search, never a filter of rights: the node checks those itself')
        self.assertTrue(all(timeout <= efactl.UQ_CLUSTER_TIMEOUT for *_rest, timeout in cluster.calls))

    def test_master_cuts_to_the_limit(self):
        self.node(MASTER_STATE, {'h2': {'mails': [{'id': n, 'ts': f'2026-11-12 10:0{n}'} for n in range(5)]}, 'h3': {'mails': []}})
        with mock.patch.object(efactl, '_uq_list_here', lambda args: {'mails': [], 'self_release': False}):
            self.assertEqual(len(efactl.uq_list(self.args(limit='3'))['mails']), 3)

    def test_node_that_answers_with_an_error_is_named(self):
        self.node(MASTER_STATE, {'h2': {'error': 'Unknown user.'}, 'h3': {'mails': []}})
        with mock.patch.object(efactl, '_uq_list_here', lambda args: {'mails': [], 'self_release': False}):
            self.assertEqual(efactl.uq_list(self.args())['unreachable'], ['mx2'])

    def test_client_asks_its_master(self):
        merged = {'mails': [{'id': 'mx3:1', 'ts': '1', 'node': 'mx3'}], 'self_release': False, 'unreachable': []}
        cluster = self.node(CLIENT_STATE, {'h1': merged})
        with mock.patch.object(efactl, '_uq_list_here', lambda args: {'mails': [], 'self_release': False}):
            self.assertEqual(efactl.uq_list(self.args()), merged)
        (_host, _path, body, timeout), = cluster.calls
        self.assertEqual(body['mode'], 'cluster')
        self.assertGreater(timeout, efactl.UQ_CLUSTER_TIMEOUT, 'the master waits for its nodes first')

    def test_client_without_master_shows_its_own(self):
        self.node(CLIENT_STATE, {'h1': OSError('refused')})
        with mock.patch.object(efactl, '_uq_list_here', lambda args: {'mails': [{'id': 4, 'ts': '1'}], 'self_release': False}):
            result = efactl.uq_list(self.args())
        self.assertEqual([row['id'] for row in result['mails']], ['mx2:4'])
        self.assertEqual(result['unreachable'], ['mx1'])

    def test_asked_by_another_node_only_this_one(self):
        cluster = self.node(MASTER_STATE, {}, local=True)
        with mock.patch.object(efactl, '_uq_list_here', lambda args: {'mails': [{'id': 4}], 'self_release': False}):
            self.assertEqual(efactl.uq_list(self.args()), {'mails': [{'id': 4}], 'self_release': False})
        self.assertEqual(cluster.calls, [], 'no request goes on from a node that was asked')


class Actions(Base):
    def test_own_mail_stays_here(self):
        self.node(MASTER_STATE, {})
        args = argparse.Namespace(command='uq-release', id='mx1:12')
        self.assertIsNone(efactl._uq_elsewhere('uq-release', args))
        self.assertEqual(args.id, '12')
        args = argparse.Namespace(command='uq-release', id='12')
        self.assertIsNone(efactl._uq_elsewhere('uq-release', args), 'an ID from before the cluster')

    def test_master_asks_the_node_that_holds_it(self):
        cluster = self.node(MASTER_STATE, {'h3': {'released': 12}})
        result = efactl._uq_elsewhere('uq-release', argparse.Namespace(command='uq-release', id='mx3:12'))
        self.assertEqual(result, {'released': 12})
        (host, path, body, _t), = cluster.calls
        self.assertEqual((host, path, body['args'], body['mode'], body['as']), ('h3', '/v1/uq', {'id': '12'}, 'local', 'a@x.example'))

    def test_client_asks_through_the_master_and_gets_cluster_ids(self):
        cluster = self.node(CLIENT_STATE, {'h1': {'id': 12, 'headers': 'From: x'}})
        result = efactl._uq_elsewhere('uq-show', argparse.Namespace(command='uq-show', id='mx3:12'))
        self.assertEqual(result['id'], 'mx3:12')
        (_host, _path, body, _t), = cluster.calls
        self.assertEqual((body['args'], body['mode']), ({'id': 'mx3:12'}, 'cluster'))

    def test_unknown_node_and_unreachable_node(self):
        self.node(MASTER_STATE, {'h2': OSError('timed out')})
        with self.assertRaisesRegex(EfaError, 'not in quarantine'):
            efactl._uq_elsewhere('uq-release', argparse.Namespace(command='uq-release', id='mx9:1'))
        with self.assertRaisesRegex(EfaError, 'mx2 that holds this mail is not reachable'):
            efactl._uq_elsewhere('uq-release', argparse.Namespace(command='uq-release', id='mx2:1'))

    def test_number_of_another_node_never_means_a_mail_here(self):
        cluster = self.node(CLIENT_STATE, {}, local=True)
        with self.assertRaisesRegex(EfaError, 'not in quarantine'):
            efactl._uq_elsewhere('uq-delete', argparse.Namespace(command='uq-delete', id='mx3:1', confirm='yes'))
        self.assertEqual(cluster.calls, [])

    def test_refusal_of_the_holding_node_comes_back(self):
        self.node(MASTER_STATE, {'h2': {'error': 'This mail can only be released by an admin. You can ask for it.'}})
        with self.assertRaisesRegex(EfaError, 'only be released by an admin'):
            efactl._uq_elsewhere('uq-release', argparse.Namespace(command='uq-release', id='mx2:3'))


class Links(Base):
    def test_token_carries_the_node(self):
        stored = []
        with mock.patch.object(efactl, '_uq_node_name', lambda: 'mx2'), mock.patch.object(efactl, '_admin_query', lambda sql, params: stored.append(params)):
            token = efactl.uq_link_make('release', 'a@x.example', 5)
        node, bare = efactl.uq_split(token, '.')
        self.assertEqual(node, 'mx2')
        self.assertEqual(stored[0][0], efactl.hashlib.sha256(bare.encode()).hexdigest(), 'the hash of the token without the name')
        self.assertTrue(daemon.UQ_TOKEN.fullmatch(token))

    def test_link_of_another_node_goes_there(self):
        cluster = self.node(MASTER_STATE, {'h2': {'purpose': 'release', 'done': 'Release this mail'}})
        with mock.patch.object(efactl, '_secrets', lambda n, label: ['mx2.' + 'A' * 43]):
            self.assertEqual(efactl._uq_token('uq-link-use'), (None, {'purpose': 'release', 'done': 'Release this mail'}))
        (_host, _path, body, _t), = cluster.calls
        self.assertEqual((body['token'], body['as'], body['mode']), ('mx2.' + 'A' * 43, '', 'local'))

    def test_own_and_old_links_stay_here(self):
        self.node(MASTER_STATE, {})
        with mock.patch.object(efactl, '_secrets', lambda n, label: ['mx1.abc']):
            self.assertEqual(efactl._uq_token('uq-link-view'), ('abc', None))
        with mock.patch.object(efactl, '_secrets', lambda n, label: ['abc']):
            self.assertEqual(efactl._uq_token('uq-link-view'), ('abc', None))

    def test_login_link_of_another_node_makes_the_login_here(self):
        self.node(CLIENT_STATE, {'h1': {'purpose': 'login', 'done': 'x', 'username': 'a@x.example', 'role': 'user'}})
        made = []
        with mock.patch.object(efactl, '_secrets', lambda n, label: ['mx3.' + 'B' * 43]), \
                mock.patch.object(efactl, '_uq_link_user', lambda address: made.append(address)):
            self.assertEqual(efactl.uq_link_use(argparse.Namespace())['username'], 'a@x.example')
        self.assertEqual(made, ['a@x.example'], 'the portal session starts on this node')


class Digest(Base):
    def claim(self, node, rcpts):
        return {rcpt: {'count': len(ids), 'items': [{'id': f'{node}:{n}', 'ts': f'2026-11-12 0{n}', 'sender': 's', 'subject': 'x',
                                                     'links': {'release': f'{node}.t{n}'}} for n in ids]} for rcpt, ids in rcpts.items()}

    def run_digest(self, state, answers, own):
        cluster = self.node(state, answers)
        sent = []
        with mock.patch.object(efactl, 'uq_state', lambda: {'public_url': 'https://mx.example', 'self_release': True}), \
                mock.patch.object(efactl, '_uq_claim', lambda hour, layers: own), \
                mock.patch.object(efactl, '_uq_send_digest', lambda rcpt, count, items, state, values: sent.append((rcpt, count, [i['id'] for i in items]))):
            efactl._uq_digests(7, {})
        return cluster, sent

    def test_master_sends_one_digest_for_all_nodes(self):
        cluster, sent = self.run_digest(MASTER_STATE, {'h2': {'claimed': self.claim('mx2', {'a@x.example': [1], 'b@x.example': [2]})}, 'h3': OSError('down')},
                                        self.claim('mx1', {'a@x.example': [3]}))
        self.assertEqual(sorted(sent), [('a@x.example', 2, ['mx2:1', 'mx1:3']), ('b@x.example', 1, ['mx2:2'])])
        bodies = [body for _host, _path, body, _t in cluster.calls]
        self.assertEqual({(body['command'], body['mode'], body['args']['hour']) for body in bodies}, {('uq-digest-claim', 'local', '7')})

    def test_client_sends_none(self):
        cluster, sent = self.run_digest(CLIENT_STATE, {}, self.claim('mx2', {'a@x.example': [1]}))
        self.assertEqual((sent, cluster.calls), ([], []), 'its lines wait for the master; claimed only by it, so never twice')

    def test_merge(self):
        merged = efactl.uq_claims_merge(self.claim('mx1', {'a@x.example': [1]}), {**self.claim('mx2', {'a@x.example': [2]}), 'bad': 'x'})
        self.assertEqual(merged['a@x.example']['count'], 2)
        self.assertNotIn('bad', merged)

    def test_claim_marks_at_once(self):
        queries = []

        def query(sql, params=()):
            queries.append((sql, params))
            if sql.startswith('SELECT'):
                return [{'id': 9, 'rcpt': 'a@x.example', 'ts': '2026-11-12 01:00', 'sender': 's@y.example', 'subject': 'x', 'malware': 0}]
            return []
        with mock.patch.object(efactl, '_uq_node_name', lambda: 'mx2'), mock.patch.object(efactl, '_admin_query', query), \
                mock.patch.object(efactl, 'uq_state', lambda: {'self_release': False}):
            claimed = efactl._uq_claim(None, {})
        self.assertEqual(claimed['a@x.example']['items'][0]['id'], 'mx2:9')
        self.assertEqual(set(claimed['a@x.example']['items'][0]['links']), {'request', 'allow', 'block'})
        self.assertTrue(any(sql.startswith('UPDATE quarantine_rcpt SET digested = 1') and params == [9] for sql, params in queries))


class RemoteTrust(unittest.TestCase):
    """R7-2: a node only names a login; never root, never a super admin, never the release of a virus."""

    def test_refused(self):
        user = {'role': 'user', 'grants': {'quarantine.release_malware': {}, 'quarantine.release': {}}}
        self.assertTrue(efactl.cluster_uq_refusal('uq-list', None, None))
        self.assertTrue(efactl.cluster_uq_refusal('uq-release', user, 'super'))
        self.assertEqual(efactl.cluster_uq_refusal('uq-release', user, 'user'), '')
        self.assertEqual(efactl.cluster_uq_refusal('uq-link-use', None, None), '')
        self.assertEqual(efactl.cluster_uq_refusal('uq-digest-claim', None, None), '')

    def test_no_virus_release(self):
        user = {'role': 'domain admin', 'grants': {'quarantine.release_malware': {}, 'quarantine.release': {}}}
        cut = efactl.cluster_uq_identity(user)
        self.assertFalse(efactl.uq_can_release(cut, True, False))
        self.assertTrue(efactl.uq_can_release(cut, False, False))
        self.assertIn('quarantine.release_malware', user['grants'])
        self.assertIsNone(efactl.cluster_uq_identity(None))

    def test_audit_names_the_node(self):
        with mock.patch.dict(os.environ, {'EFA_CLUSTER_UQ': 'mx2'}), mock.patch.object(efactl, 'acting_user', 'a@x.example'):
            self.assertEqual(efactl._dmarc_who(), 'cluster node mx2 (a@x.example)')


class Daemon(unittest.TestCase):
    MASTER = {'role': 'master'}
    CLIENT = {'role': 'client'}

    def test_line(self):
        line, env = daemon.uq_line({'command': 'uq-release', 'as': 'a@x.example', 'args': {'id': '12'}, 'mode': 'local'}, 'master', self.CLIENT)
        self.assertEqual(line[1:], ['--as=a@x.example', '--client=cluster-master', 'uq-release', '--id=12'])
        self.assertEqual(env, {'EFA_CLUSTER_UQ': 'master', 'EFA_UQ_LOCAL': '1'})
        key = b'k' * 32
        ticket = daemon.efa_cluster.ticket_make(key, 'a@x.example', 'mx2')
        line, env = daemon.uq_line({'command': 'uq-list', 'as': 'a@x.example', 'args': {'text': '-x'}, 'mode': 'cluster', 'ticket': ticket}, 'mx2',
                                   self.MASTER, key=key)
        self.assertIn('--text=-x', line, 'a value that starts with a dash stays a value')
        self.assertNotIn('EFA_UQ_LOCAL', env)

    def test_login_of_a_node_needs_a_ticket_of_the_master(self):
        # F4 (security review 2026-11-24): the master does not take the login a node names on its word.
        key = b'k' * 32
        body = {'command': 'uq-list', 'as': 'boss@x.example', 'args': {}, 'mode': 'cluster'}
        for ticket in (None, '', 'x.y', daemon.efa_cluster.ticket_make(key, 'a@x.example', 'mx2'), daemon.efa_cluster.ticket_make(key, 'boss@x.example', 'mx3'),
                       daemon.efa_cluster.ticket_make(b'z' * 32, 'boss@x.example', 'mx2'), daemon.efa_cluster.ticket_make(key, 'boss@x.example', 'mx2', now=0)):
            with self.assertRaises(PermissionError, msg=str(ticket)):
                daemon.uq_line({**body, **({'ticket': ticket} if ticket is not None else {})}, 'mx2', self.MASTER, key=key)
        # A link without a login needs no ticket: its token is checked by the node that made it.
        token = 'mx3.' + 'C' * 43
        daemon.uq_line({'command': 'uq-link-view', 'token': token, 'mode': 'cluster', 'args': {}}, 'mx2', self.MASTER, key=key)
        # The master itself is trusted by its nodes (it checked the ticket before it asks them).
        daemon.uq_line({'command': 'uq-list', 'as': 'boss@x.example', 'args': {}, 'mode': 'local'}, 'master', self.CLIENT, key=b'')

    def test_ticket_only_after_the_masters_own_password_check(self):
        key = b'k' * 32
        good = lambda line, **kw: types.SimpleNamespace(returncode=0, stdout='{"username": "a@x.example", "role": "user"}', stderr='')
        bad = lambda line, **kw: types.SimpleNamespace(returncode=1, stdout='{"error": "Wrong user name or password."}', stderr='')
        other = lambda line, **kw: types.SimpleNamespace(returncode=0, stdout='{"username": "b@x.example"}', stderr='')
        answer = daemon.uq_ticket({'login': 'a@x.example', 'password': 'pw', 'code': '123456'}, 'mx2', good, key=key)
        self.assertTrue(daemon.efa_cluster.ticket_ok(key, answer['ticket'], 'a@x.example', 'mx2'))
        for run in (bad, other):
            with self.assertRaises(PermissionError):
                daemon.uq_ticket({'login': 'a@x.example', 'password': 'pw', 'code': ''}, 'mx2', run, key=key)
        for body in ({'login': '--as=x', 'password': 'pw'}, {'login': 'a@x.example', 'password': ''}, {'login': 'a@x.example', 'password': 'p\nw'}):
            with self.assertRaises(ValueError):
                daemon.uq_ticket(body, 'mx2', good, key=key)
        seen = {}
        daemon.uq_ticket({'login': 'a@x.example', 'password': 'secret-pw', 'code': ''}, 'mx2',
                         lambda line, **kw: seen.update(line=line, **kw) or good(line), key=key)
        self.assertFalse(any('secret-pw' in item for item in seen['line']), 'the password goes by stdin only')
        self.assertTrue(seen['input'].startswith('secret-pw\n'))

    def test_refusals(self):
        refused = [({'command': 'user-set', 'mode': 'local'}, 'master', self.CLIENT),
                   ({'command': 'uq-digest-claim', 'mode': 'local'}, 'mx2', self.MASTER),
                   ({'command': 'uq-list', 'mode': 'cluster'}, 'master', self.CLIENT),
                   ({'command': 'uq-list', 'mode': 'cluster'}, 'mx2', self.CLIENT),
                   ({'command': 'uq-list'}, 'mx2', self.MASTER),
                   ({'command': 'uq-release', 'mode': 'local', 'args': {'id': '1'}}, 'master', self.CLIENT),
                   ({'command': 'uq-link-use', 'mode': 'local'}, 'master', self.CLIENT)]
        for body, who, state in refused:
            with self.assertRaises(PermissionError, msg=str(body)):
                daemon.uq_line(body, who, state)
        bad = [{'command': 'uq-list', 'mode': 'local', 'as': '--client=x'},
               {'command': 'uq-list', 'mode': 'local', 'limit_tenant': '1 OR 1'},
               {'command': 'uq-list', 'mode': 'local', 'args': {'text': 'a\nb'}},
               {'command': 'uq-list', 'mode': 'local', 'args': {'no-name': 'x'}},
               {'command': 'uq-link-use', 'mode': 'local', 'token': 'mx2.short'},
               {'command': 'uq-list', 'mode': 'local', 'args': []}]
        for body in bad:
            with self.assertRaises(ValueError, msg=str(body)):
                daemon.uq_line(body, 'master', self.CLIENT)

    def test_token_goes_by_stdin(self):
        seen = {}

        def run(line, **kw):
            seen.update(line=line, **kw)
            return types.SimpleNamespace(stdout='{"purpose": "release"}', stderr='')
        token = 'mx2.' + 'C' * 43
        with mock.patch.object(daemon.efa_cluster, 'read_state', lambda etc=None: self.CLIENT):
            self.assertEqual(daemon.run_uq({'command': 'uq-link-use', 'token': token, 'mode': 'local'}, 'master', run), {'purpose': 'release'})
        self.assertEqual(seen['input'], token + '\n')
        self.assertFalse(any(token in item for item in seen['line']), 'never on the command line')


if __name__ == '__main__':
    unittest.main()
