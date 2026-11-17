# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Hans 2026-11-15: the notices of the dashboard can be confirmed (away for 30 days or until their text changes), hidden (away until
shown again, also when a number in them changes) and shown again, per host and in the audit log; a stopped service or a problem of
the security check has no such button. The same branch: the hardening wizard takes an nginx file with several HTTPS server blocks
(a migrated host), checks before it changes anything and takes back what it changed when it stops halfway; the 2FA code fields are only as
wide as a code; switches of the blocklists post in place (stay.js)."""
import argparse
import importlib.machinery
import importlib.util
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
WEB = os.path.join(TOP, 'next', 'usr', 'local', 'sbin', 'efa-web.py')


def load(name, path):
    for module in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
        sys.modules.setdefault(module, __import__(module) if importlib.util.find_spec(module) else types.ModuleType(module))
    loader = importlib.machinery.SourceFileLoader(name, path)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader))
    loader.exec_module(module)
    return module


# The efa.conf of a host migrated from eFa 5: the default server of eFa-next and a block of the certbot installer of eFa 5.
MIGRATED_CONF = '''server {
    listen 80 default_server;
    server_name "";
}

server {
    listen 443 ssl default_server;
    server_name "";
    ssl_certificate /etc/pki/tls/certs/efa.crt;
    ssl_certificate_key /etc/pki/tls/private/efa.key;
    include /etc/nginx/efa-hardening.inc;
    location / {
        include /etc/nginx/efa-proxy.inc;
    }
}

server {
    listen 443 ssl ;
    server_name mx.example.org; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/mx.example.org/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/mx.example.org/privkey.pem; # managed by Certbot
    include /etc/nginx/efa-hardening.inc;
}
'''


def ns(**values):
    base = {'action': '', 'text': '', 'slug': '', 'anchor': '', 'key': ''}
    return argparse.Namespace(**{**base, **values})


class NoticeAck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = load('efactl_notice_ack', os.path.join(TOP, 'next', 'usr', 'sbin', 'efactl'))

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='efa-notice-ack-')
        self.audit = []
        self.patches = [mock.patch.object(self.e, 'NOTICE_ACK_FILE', os.path.join(self.tmp, 'notice-ack.json')),
                        mock.patch.object(self.e, 'STATE_LOCK', os.path.join(self.tmp, 'lock')),
                        mock.patch.object(self.e, '_audit', self.audit.append),
                        mock.patch.object(self.e, '_dmarc_who', lambda: 'admin')]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        shutil.rmtree(self.tmp)

    def test_confirm_hide_show(self):
        e = self.e
        done = e.notice_ack(ns(action='confirm', text='a.example lacks DMARC', slug='domset', anchor='domain-check-status'))
        self.assertEqual([item[4] for item in done['notice_acks']], ['confirmed'])
        self.assertEqual(done['key'], e.notice_keys('a.example lacks DMARC', 'domset', 'domain-check-status')[0])
        self.assertIn('dashboard notice confirmed by admin: a.example lacks DMARC', self.audit)
        hidden = e.notice_ack(ns(action='hide', text='3 senders on the allow list', slug='flow', anchor='transport-set'))
        self.assertEqual(hidden['key'], e.notice_keys('9 senders on the allow list', 'flow', 'transport-set')[1], 'hidden: any number')
        self.assertEqual(oct(os.stat(e.NOTICE_ACK_FILE).st_mode & 0o777), '0o600')
        shown = e.notice_ack(ns(action='show', key=done['key']))
        self.assertEqual([item[4] for item in shown['notice_acks']], ['hidden'])
        self.assertTrue(any(line.startswith('dashboard notice shown again by admin') for line in self.audit))
        with self.assertRaises(e.EfaError):
            e.notice_ack(ns(action='show', key=done['key']))

    def test_confirmed_ones_come_back_after_30_days(self):
        e = self.e
        e.notice_ack(ns(action='confirm', text='No backup yet', slug='bak', anchor='backup-now'))
        self.assertEqual(len(e.notice_acks()), 1)
        self.assertEqual(e.notice_acks(now=e.time.time() + 31 * 86400), [])

    def test_el9_support_notice_on_el9_hosts_only(self):
        # Hans 2026-11-15: eFa-next on EL9 has full support and security updates until 2027-05-31, then only the migration to
        # eFa-next 6.x on version 10. Yellow (a notice, confirm and hide work) from 2026-12-01, red (a banner, no button) after.
        e = self.e
        day = e.datetime.date
        self.assertEqual(e.el9_support_state('el9', day(2026, 11, 30)), '')
        self.assertEqual(e.el9_support_state('el9', day(2026, 12, 1)), 'warn')
        self.assertEqual(e.el9_support_state('el9', day(2027, 5, 31)), 'warn')
        self.assertEqual(e.el9_support_state('el9', day(2027, 6, 1)), 'ended')
        self.assertEqual(e.el9_support_state('el10', day(2027, 6, 1)), '')
        self.assertEqual(e.el9_banner('el9', day(2027, 5, 31)), [])
        red = e.el9_banner('el9', day(2027, 6, 1))[0]
        self.assertIn('2027-05-31', red)
        self.assertIn('6.x on version 10', red)
        self.assertNotIn('2028', red)
        import efa_i18n
        self.assertTrue(efa_i18n.runtime(red, 'de').startswith('eFa-next auf EL9'), efa_i18n.runtime(red, 'de'))
        with mock.patch.object(e, 'el9_support_state', return_value='warn'):
            yellow = [item for item in e._safe(e._system_notices, []) if item[1:3] == ['maint', 'release-upgrade']]
        if yellow:  # _system_notices needs more of a host than this test has; where it runs, the yellow notice is ackable
            self.assertIn('2032-05-31', yellow[0][0])
            done = e.notice_ack(ns(action='hide', text=yellow[0][0], slug='maint', anchor='release-upgrade'))
            self.assertEqual(done['notice_acks'][0][4], 'hidden')

    def test_refused(self):
        e = self.e
        for bad in (ns(action='mute', text='x', slug='dash', anchor='status'), ns(action='hide', text='rspamd is down', slug='dash', anchor='status'),
                    ns(action='confirm', text='Security self check: 2 problems', slug='sec', anchor='security-status'),
                    ns(action='hide', text='x', slug='../etc', anchor='a'), ns(action='hide', text='', slug='dash', anchor='a'),
                    ns(action='show', key='../../x')):
            with self.assertRaises(e.EfaError, msg=str(bad)):
                e.notice_ack(bad)
        self.assertFalse(os.path.exists(e.NOTICE_ACK_FILE))

    def test_registered_per_host(self):
        e = self.e
        self.assertTrue(e.COMMANDS['notice-ack']['writes'])
        self.assertEqual(e.COMMAND_PERMISSIONS['notice-ack'], 'settings.edit')
        self.assertIn('notice-ack', e.CLUSTER_LOCAL)

    def test_acks_of_a_foreign_domain_stay_hidden_for_a_domain_admin(self):
        e = self.e
        acks = [['b.example lacks DMARC', 'domset', 'domain-check-status', 'a' * 16, 'hidden', ''],
                ['a.example lacks DMARC', 'domset', 'domain-check-status', 'b' * 16, 'hidden', '']]
        self.assertEqual(e.domain_filter({'notice_acks': acks}, {'a.example'})['notice_acks'], acks[1:])


class HardeningWizard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = load('efactl_notice_ack_harden', os.path.join(TOP, 'next', 'usr', 'sbin', 'efactl'))

    def test_every_https_block_gets_the_web_certificate(self):
        e = self.e
        new = e.nginx_cert_rewrite(MIGRATED_CONF, '/etc/letsencrypt/live/efa-web-ecdsa/fullchain.pem', '/etc/letsencrypt/live/efa-web-ecdsa/privkey.pem')
        self.assertEqual(new.count('ssl_certificate /etc/letsencrypt/live/efa-web-ecdsa/fullchain.pem;'), 2)
        self.assertEqual(new.count('ssl_certificate_key /etc/letsencrypt/live/efa-web-ecdsa/privkey.pem;'), 2)
        self.assertNotIn('efa.crt', new)
        self.assertEqual(new.count('# managed by Certbot'), 1, 'only the server_name line keeps the note of certbot')
        self.assertEqual(new.replace('efa-web-ecdsa/fullchain.pem', '').count('include'), MIGRATED_CONF.count('include'))
        back = e.nginx_cert_restore_text(MIGRATED_CONF, new)
        self.assertEqual(back, MIGRATED_CONF, 'back: each block its own certificate again')
        self.assertIsNone(e.nginx_cert_restore_text(MIGRATED_CONF, new.replace('    ssl_certificate_key /etc/letsencrypt/live/efa-web-ecdsa/privkey.pem;\n', '', 1)))

    def test_unknown_forms_are_refused(self):
        e = self.e
        for conf in ('server { listen 443 ssl; }', 'server {\n ssl_certificate /a;\n ssl_certificate /b;\n ssl_certificate_key /k;\n}'):
            with self.assertRaises(e.EfaError):
                e.nginx_cert_rewrite(conf, '/c', '/k')
        commented = 'server {\n # ssl_certificate /old;\n ssl_certificate /a;\n ssl_certificate_key /k;\n}'
        self.assertIn('# ssl_certificate /old;', e.nginx_cert_rewrite(commented, '/c', '/d'))

    def test_preflight_names_the_nginx_file_before_anything_changes(self):
        e = self.e
        tmp = tempfile.mkdtemp(prefix='efa-preflight-')
        try:
            conf = os.path.join(tmp, 'efa.conf')
            with open(conf, 'w') as f:
                f.write('server { listen 443 ssl; }\n')
            with mock.patch.object(e, 'NGINX_CONF', conf), mock.patch.object(e, '_efa_item_on', lambda key: False):
                self.assertTrue(e.standards_preflight({'os': [], 'efa': {'web-ecdsa': 'off'}}))
                self.assertEqual(e.standards_preflight({'os': [], 'efa': {'dane': 'off'}}), [])
                with open(conf, 'w') as f:
                    f.write(MIGRATED_CONF)
                self.assertEqual(e.standards_preflight({'os': [], 'efa': {'web-ecdsa': 'off'}}), [])
        finally:
            shutil.rmtree(tmp)

    def test_a_stop_halfway_takes_back_what_this_run_changed(self):
        e = self.e
        now = {'tls': {'profile': 'bsi', 'custom': '', 'web13': False}, 'ssh': 'system', 'kernel': False, 'dane': False, 'port25': False}
        wanted = {**now, 'ssh': 'bsi', 'kernel': True}
        # The stop comes from the sandbox step: web-ecdsa (Let's Encrypt) never stops the run since 2026-11-16.
        changes = [('SSH profile', 'outdated', 'bsi', ''), ('Kernel settings', 'outdated', 'on', ''), ('Sandbox of the services', 'off', 'on', '')]
        before = {'os': [], 'efa': {'service-harden': 'off'}}
        undone, audit, written = [], [], {}

        def stop(key, on, mode=None):
            raise e.EfaError('sandbox drop-in not written.')
        with mock.patch.object(e, '_standards_preview', lambda args: (['cis-el'], ([], ['service-harden']), now, wanted, changes, [], before)), \
                mock.patch.object(e, 'standards_preflight', lambda b: []), mock.patch.object(e, 'standards_state', lambda: {'selected': []}), \
                mock.patch.object(e, '_json_write', lambda path, data, mode=0o640: written.__setitem__(path, data)), \
                mock.patch.object(e, '_standards_put', lambda n, w: None), mock.patch.object(e, '_efa_item_on', lambda key: False), \
                mock.patch.object(e, '_efa_item_put', stop), mock.patch.object(e, '_standards_undo', lambda saved: undone.append(saved) or []), \
                mock.patch.object(e, '_audit', audit.append), mock.patch.object(e, '_dmarc_who', lambda: 'admin'):
            with self.assertRaises(e.EfaError) as raised:
                e.standards_set(argparse.Namespace(apply='yes', confirm='yes'))
        self.assertIn('Taken back: SSH profile, Kernel settings.', str(raised.exception))
        self.assertIn('The server is as before.', str(raised.exception))
        self.assertEqual(len(undone), 1)
        self.assertEqual(undone[0]['now'], now)
        self.assertTrue(any('taken back after the stop' in line for line in audit))

    def test_going_back_puts_outdated_files_back_as_they_were(self):
        # Before the wizard: SSH profile and kernel settings of an older version ("outdated", counted as off by the plan).
        # Going back by on/off alone removed the SSH file and kept the new kernel file (2026-11-15).
        e = self.e
        tmp = tempfile.mkdtemp(prefix='efa-undo-')
        try:
            ssh, kernel = os.path.join(tmp, '40-efa-bsi.conf'), os.path.join(tmp, '90-efa.conf')
            for path, text in ((ssh, 'Ciphers old\n'), (kernel, 'net.ipv4.conf.all.rp_filter = 2\n')):
                with open(path, 'w') as f:
                    f.write(text)
            runs = []
            with mock.patch.object(e, 'SSH_BSI_FILE', ssh), mock.patch.object(e, 'KERNEL_FILE', kernel), mock.patch.object(e, 'STATE_LOCK', os.path.join(tmp, 'lock')):
                files = e._standards_files()
                os.remove(ssh)
                with open(kernel, 'w') as f:
                    f.write('net.ipv4.conf.all.rp_filter = 1\n')
                with mock.patch.object(e, '_sshd_apply', lambda: runs.append('sshd')), mock.patch.object(e.subprocess, 'run', lambda cmd, **k: runs.append(cmd[0])), \
                        mock.patch.object(e, '_platform', lambda: types.SimpleNamespace(service_stop=lambda name: None)):
                    kept = []
                    e._standards_files_restore(files, kept)
                self.assertEqual(open(ssh).read(), 'Ciphers old\n')
                self.assertEqual(open(kernel).read(), 'net.ipv4.conf.all.rp_filter = 2\n')
                self.assertEqual(runs, ['sshd', 'sysctl'])
                self.assertEqual(kept, [])
        finally:
            shutil.rmtree(tmp)

    def test_a_blocked_preflight_changes_nothing(self):
        e = self.e
        now = {'tls': {}, 'ssh': 'system', 'kernel': False, 'dane': False, 'port25': False}
        put = []
        with mock.patch.object(e, '_standards_preview', lambda args: (['cis-el'], ([], ['web-ecdsa']), now, {**now, 'kernel': True}, [], [], {'os': [], 'efa': {'web-ecdsa': 'off'}})), \
                mock.patch.object(e, 'standards_preflight', lambda b: ['efa.conf has an unknown form.']), \
                mock.patch.object(e, '_json_write', lambda *a, **k: put.append(a)), mock.patch.object(e, '_standards_put', lambda n, w: put.append(w)):
            with self.assertRaises(e.EfaError) as raised:
                e.standards_set(argparse.Namespace(apply='yes', confirm='yes'))
        self.assertTrue(str(raised.exception).startswith('Stopped before any change:'))
        self.assertEqual(put, [])


class WebPage(unittest.TestCase):
    """Without Flask (a build host) only the texts of the page are read."""

    @classmethod
    def setUpClass(cls):
        with open(WEB, encoding='utf-8') as f:
            cls.source = f.read()

    def test_2fa_code_fields_are_as_wide_as_a_code(self):
        fields = [part for part in self.source.split('<input')[1:] if 'one-time-code' in part.split('>')[0]]
        self.assertGreaterEqual(len(fields), 5)
        self.assertTrue(all('class="otp"' in field.split('>')[0] for field in fields), 'every 2FA code field is narrow')
        self.assertIn('input[type=text].otp,.row input[type=text].otp{width:calc(9ch + 22px);max-width:calc(9ch + 22px)', self.source)

    def test_blocklist_switches_and_terms_stay_in_place(self):
        self.assertEqual(self.source.count('class="toggle" data-stay="rbl-show"') + self.source.count('class="dqs" data-stay="rbl-show"'), 2)
        self.assertIn('data-stay="rbl-show" data-done="{{ row.list }}: {{ _(\'Terms confirmed, the list is on.\') }}"', self.source)
        self.assertEqual(self.source.count('data-stay="clam-source-status"'), 2)
        self.assertRegex(self.source, r"STAY_RUN = \{'notice-ack', 'rbl-set', 'clam-source-set'[,}]", 'these three, maybe more')
        # It posted already: never a second post, at worst the page anew.
        self.assertIn("location.assign(here.toString())", self.source)

    def test_keys_are_those_of_efactl(self):
        try:
            import flask  # noqa: F401
        except ImportError:
            self.skipTest('Flask is not installed')
        e = load('efactl_notice_ack_keys', os.path.join(TOP, 'next', 'usr', 'sbin', 'efactl'))
        web = load('efa_web_notice_ack', WEB)
        for text in ('No backup yet', 'a.example lacks DMARC', '12 senders of eFa 5 on the allow list'):
            self.assertEqual(web.notice_keys(text, 'flow', 'transport-set'), e.notice_keys(text, 'flow', 'transport-set'))
        self.assertEqual(web.NOTICE_FIXED_ONLY, e.NOTICE_FIXED_ONLY)
        notice = web.Notice(('Kein Backup', 'bak', 'backup-now', {}), 'No backup yet')
        acks = [['No backup yet', 'bak', 'backup-now', e.notice_keys('No backup yet', 'bak', 'backup-now')[0], 'confirmed', '2026-12-15']]
        with web.app.test_request_context('/'):
            shown, done = web.notice_split([notice, web.Notice(('rspamd is down', 'dash', 'status', {}), 'rspamd is down')], acks)
        self.assertEqual([item[0] for item in shown], ['rspamd is down'], 'the key is that of the English text, whatever the reader reads')
        self.assertFalse(shown[0][5], 'a stopped service has no buttons')
        self.assertEqual(done[0]['state'], 'confirmed')


if __name__ == '__main__':
    unittest.main()
