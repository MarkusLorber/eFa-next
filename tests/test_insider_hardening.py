# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hardening against attacks from the inside (6.0.0.6 review): lines in arguments only where the table allows them, no forged
lines in the audit file, the keys of the master stay on the master, four eyes cannot be passed by the commands that switch the
protected ones, a failed change is in the audit log whatever its error, and an API token never does what needs a password."""
import argparse
import importlib.machinery
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(TOP, 'src', 'eFa-base', 'root', 'usr', 'lib', 'eFa', 'python'))
sys.path.insert(0, os.path.join(TOP, 'next', 'usr', 'lib', 'eFa', 'python'))


def load(name, path):
    for module in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
        sys.modules.setdefault(module, __import__(module) if importlib.util.find_spec(module) else types.ModuleType(module))
    loader = importlib.machinery.SourceFileLoader(name, path)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


class Efactl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = load('efactl_insider', os.path.join(TOP, 'next', 'usr', 'sbin', 'efactl'))

    def test_lines_only_where_the_table_allows_them(self):
        e = self.e
        disclaimer = e.COMMANDS['disclaimer-template-set']
        self.assertIsNone(e.arg_lines_problem(disclaimer, argparse.Namespace(text='Line one\nLine two', html='<p>a</p>\n<p>b</p>')))
        self.assertIsNone(e.arg_lines_problem(e.COMMANDS['crypto-import'], argparse.Namespace(data='-----BEGIN X-----\nAA\n-----END X-----')))
        for value in ('a\nb', 'a\rb', 'a b', 'a\x0bb'):
            self.assertIn('one line only', e.arg_lines_problem(disclaimer, argparse.Namespace(id=value)) or '', repr(value))
        # Every command that writes a map, a drop-in or a list: a line break in any of its values is refused.
        multi = {(name, arg['name']) for name, cmd in e.COMMANDS.items() for arg in cmd['args'] if arg.get('multiline') or arg.get('lines')}
        self.assertEqual(multi, {('crypto-import', 'data'), ('crypto-hsm-set', 'cert'), ('clam-securiteinfo-set', 'urls'),
                                 ('disclaimer-template-set', 'text'), ('disclaimer-template-set', 'html')})

    def test_audit_file_lines_cannot_be_forged(self):
        e = self.e
        folder = tempfile.mkdtemp()
        try:
            with mock.patch.object(e, 'AUDIT_LOG', folder + '/audit.log'):
                e._audit('note by anna: x\n2026-11-12 03:00:00 audit-mode off by root\rfake more\x85end')
                with open(folder + '/audit.log') as f:
                    text = f.read()
            self.assertEqual(len(text.splitlines()), 1, text)
            self.assertTrue(text.endswith('end\n'))
        finally:
            shutil.rmtree(folder)

    def test_keys_of_the_master_never_go_to_a_node(self):
        e = self.e
        folder = tempfile.mkdtemp()
        try:
            os.makedirs(folder + '/eFa')
            names = ('backup-sign.key', 'offline-bundle.key', 'audit-anchor.key', 'audit-anchor.pub', 'backup-password', 'backup-hsm.json',
                     'audit-strict.key', 'restore-running', 'post-boot-check', 'eFa-Backup.disabled', 'testing-unsigned-el10-repo', 'MySQL-Config',
                     'rules.json', 'srs.key')
            for name in names:
                with open(f'{folder}/eFa/{name}', 'w') as f:
                    f.write('x\n')
            with mock.patch.multiple(e, ETC=folder, RSPAMD_DIR=folder + '/rspamd', SUB_DOVECOT=folder + '/none', SUB_PASSWD=folder + '/none'):
                shared = {os.path.basename(path) for path in e.snapshot_files()}
            # What a node needs to filter the same way (rules, the SRS key for bounces) goes; the signing keys and markers stay.
            self.assertEqual(shared, {'rules.json', 'srs.key'})
        finally:
            shutil.rmtree(folder)

    def test_four_eyes_cannot_be_passed_by_the_switching_commands(self):
        e = self.e
        state, admin = {'all': True, 'tenants': []}, {'role': 'tenant', 'tenant_id': 3}
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('EFA_FOUR_EYES', None)
            for command in ('standards-rollback', 'os-harden-set', 'history-undo', 'audit-rules-set', 'retention-set'):
                self.assertTrue(e.four_eyes_needed(command, admin, state, argparse.Namespace()), command)
            self.assertTrue(e.four_eyes_needed('standards-set', admin, state, argparse.Namespace(apply='yes')))
            self.assertFalse(e.four_eyes_needed('standards-set', admin, state, argparse.Namespace(apply='')), 'a preview never waits')
            self.assertTrue(e.four_eyes_needed('four-eyes-set', admin, state, argparse.Namespace(mode='off')))
            self.assertFalse(e.four_eyes_needed('four-eyes-set', admin, state, argparse.Namespace(mode='on')), 'switching it on never waits')
        self.assertFalse(e.four_eyes_needed('standards-rollback', None, state, argparse.Namespace()), 'root on the console is not affected')

    def test_all_keeps_covering_super_admins_after_the_update(self):
        """A host with four eyes 'all' from before 6.0.0.6: its super admins wait as before, without the level of the main admins;
        the main admin itself stays free (it decides), so a host with one super admin is not locked out."""
        e = self.e
        anna = {'role': 'super', 'username': 'anna', 'tenant_id': None}
        before = {'all': True, 'tenants': [], 'super': {'on': False, 'consent': []}}
        with mock.patch.dict(os.environ, {'SUDO_USER': 'efa-web'}):
            os.environ.pop('EFA_FOUR_EYES', None)
            self.assertTrue(e.four_eyes_needed('rule-set', anna, before, argparse.Namespace(), ['anna', 'main admin']))
            self.assertTrue(e.four_eyes_needed('rule-set', anna, before, argparse.Namespace(), ['anna']), 'also with one main admin')
            self.assertFalse(e.four_eyes_needed('rule-set', None, before, argparse.Namespace(), ['anna']), 'the main admin is not under all')
            self.assertFalse(e.four_eyes_needed('rule-set', anna, {**before, 'all': False}, argparse.Namespace(), ['anna', 'main admin']))

    def test_four_eyes_for_the_main_admins(self):
        """Hans 2026-11-12: only with at least two main admins, and on once every one of them agreed."""
        e, folder = self.e, tempfile.mkdtemp()
        ids = ['anna', 'main admin']
        try:
            with mock.patch.multiple(e, FOUR_EYES_FILE=folder + '/four-eyes.json', _main_admin_ids=lambda: list(ids), _audit=lambda text: None,
                                     four_eyes_list=lambda _args: e.four_eyes_state()), \
                    mock.patch.dict(os.environ, {'SUDO_USER': 'efa-web'}):
                os.environ.pop('EFA_FOUR_EYES', None)
                anna = {'role': 'super', 'username': 'anna', 'tenant_id': None}
                with mock.patch.object(e, 'identity_now', anna):
                    first = e.four_eyes_set(argparse.Namespace(mode='on', tenant='', level='super'))
                self.assertEqual(first['super_missing'], ['main admin'])
                self.assertFalse(e.four_eyes_super_active(e.four_eyes_state(), ids), 'not on before every main admin agreed')
                self.assertFalse(e.four_eyes_needed('rule-set', None, e.four_eyes_state(), argparse.Namespace(), ids))
                with mock.patch.object(e, 'identity_now', None):
                    second = e.four_eyes_set(argparse.Namespace(mode='on', tenant='', level='super'))
                self.assertEqual(second['super_missing'], [])
                state = e.four_eyes_state()
                self.assertTrue(state['super']['on'])
                # The main admin of the web interface and a super admin wait now; the admins below follow 'all' as before.
                self.assertTrue(e.four_eyes_needed('rule-set', None, state, argparse.Namespace(), ids))
                self.assertTrue(e.four_eyes_needed('rule-set', anna, state, argparse.Namespace(), ids))
                self.assertFalse(e.four_eyes_needed('rule-set', {'role': 'tenant', 'tenant_id': 3}, state, argparse.Namespace(), ids))
                self.assertTrue(e.four_eyes_needed('four-eyes-set', anna, state, argparse.Namespace(mode='off'), ids), 'off waits too')
                # With one main admin left it stands still by itself: nobody is locked out.
                self.assertFalse(e.four_eyes_needed('rule-set', anna, state, argparse.Namespace(), ['anna']))
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop('SUDO_USER', None)
                os.environ.pop('EFA_FOUR_EYES', None)
                with mock.patch('sys.stdin') as stdin:
                    stdin.isatty.return_value = False
                    self.assertFalse(e.four_eyes_needed('rule-set', None, state, argparse.Namespace(), ids), 'a script or timer as root never waits')
                    stdin.isatty.return_value = True
                    self.assertTrue(e.four_eyes_needed('rule-set', None, state, argparse.Namespace(), ids), 'root typing at the console waits')
            ids[:] = ['main admin']
            with mock.patch.multiple(e, FOUR_EYES_FILE=folder + '/other.json', _main_admin_ids=lambda: list(ids), _audit=lambda text: None,
                                     identity_now=None, four_eyes_list=lambda _args: {}):
                with self.assertRaises(e.EfaError):
                    e.four_eyes_set(argparse.Namespace(mode='on', tenant='', level='super'))
        finally:
            shutil.rmtree(folder)

    def test_a_failed_change_is_in_the_audit_log_whatever_its_error(self):
        e = self.e
        written, events = [], []

        def broken(_args):
            raise KeyError('now')
        table = {'demo-set': {'func': broken, 'title': 'demo', 'writes': True, 'args': []}}
        with mock.patch.dict(e.COMMANDS, table), \
                mock.patch.multiple(e, strict_settings=lambda: {'on': False, 'require_reason': False, 'content_reason': False, 'days': 365},
                                    _audit=lambda text: None, _audit_state=lambda: {}, history_read=lambda files: None, history_files=lambda: [],
                                    cluster_replicated=lambda command: False, four_eyes_state=lambda: {'all': False, 'tenants': []},
                                    _audit_write=lambda command, args, before, ok: written.append((command, ok)),
                                    _event=lambda *a, **k: events.append(a[0])), \
                mock.patch.object(sys, 'argv', ['efactl', 'demo-set']), mock.patch('sys.stdout') as out, mock.patch('sys.stderr'):
            self.assertEqual(e.main(), 1)
        self.assertEqual(written, [('demo-set', False)])
        self.assertEqual(events, ['config_change_failed'])
        printed = ''.join(call.args[0] for call in out.write.call_args_list)
        self.assertIn('internal error (KeyError)', json.loads(printed)['error'])


class Web(unittest.TestCase):
    https = {'base_url': 'https://localhost'}

    @classmethod
    def setUpClass(cls):
        folder = tempfile.mkdtemp(prefix='efa-insider-test-')
        before = os.environ.get('EFA_ETC')
        os.environ['EFA_ETC'] = folder
        try:
            cls.web = load('efa_web_insider', os.path.join(TOP, 'next', 'usr', 'local', 'sbin', 'efa-web.py'))
        finally:
            if before is None:
                os.environ.pop('EFA_ETC', None)
            else:
                os.environ['EFA_ETC'] = before

    def test_more_changes_need_the_password(self):
        self.assertTrue({'four-eyes-set', 'audit-rules-set', 'retention-set', 'tenant-delete', 'history-undo'} <= self.web.REAUTH_COMMANDS)

    def test_a_token_never_does_what_needs_the_password(self):
        web, calls = self.web, []
        schema = {'audit-mode': {'title': 'Strict audit', 'writes': True, 'args': [{'name': 'mode', 'label': 'Mode'}]},
                  'qr-set': {'title': 'QR', 'writes': True, 'args': [{'name': 'mode', 'label': 'Mode'}]}}
        with mock.patch.object(web, 'api_schema_for_user', lambda: schema), \
                mock.patch.object(web, 'efactl', lambda *args, secrets_in=None, who=None: calls.append(args) or (True, {'done': True})):
            client = web.app.test_client()
            refused = client.post('/api/v1/audit-mode', json={'mode': 'off'}, **self.https)
            done = client.post('/api/v1/qr-set', json={'mode': 'on'}, **self.https)
        self.assertEqual(refused.status_code, 403)
        self.assertEqual(done.status_code, 200)
        self.assertEqual(calls, [('qr-set', '--mode=on')])

    def test_text_areas_send_lines_without_carriage_returns(self):
        web, calls = self.web, []
        command = {'name': 'disclaimer-template-set', 'args': [{'name': 'id', 'label': 'Id'}, {'name': 'text', 'label': 'Text'}]}
        with mock.patch.object(web, 'efactl', lambda *args, secrets_in=None: calls.append(args) or (True, {})):
            web.call_command(command, {'id': 'd1', 'text': 'one\r\ntwo'})
        self.assertEqual(calls, [('disclaimer-template-set', '--id=d1', '--text=one\ntwo')])


if __name__ == '__main__':
    unittest.main()
