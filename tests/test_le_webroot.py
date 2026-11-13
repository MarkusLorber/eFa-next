# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""letsencrypt-set: certbot only gets the certificate through the webroot (no installer that edits nginx), eFa-next writes the
paths itself. With the own ECDSA certificate of the web (web-cert-set ecdsa) nginx keeps it, only Postfix gets the new one;
with web-cert-set mail nginx follows Postfix. Also on Windows: the Unix-only modules are stubbed as in test_efactl_calls."""
import argparse
import importlib.machinery
import importlib.util
import os
import sys
import tempfile
import types
import unittest

sys.dont_write_bytecode = True
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
for name in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
    sys.modules.setdefault(name, __import__(name) if importlib.util.find_spec(name) else types.ModuleType(name))
for folder in ('next/usr/lib/eFa/python', 'src/eFa/root/usr/lib/eFa/python', 'src/eFa-base/root/usr/lib/eFa/python'):
    if os.path.join(ROOT, folder) not in sys.path:
        sys.path.insert(0, os.path.join(ROOT, folder))
_loader = importlib.machinery.SourceFileLoader('efactl_le', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
efactl = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_le', _loader))
_loader.exec_module(efactl)

NGINX = """server {
    listen 443 ssl;
    ssl_certificate %s;
    ssl_certificate_key %s;
}
"""


class LetsencryptSetTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix='efa-le-')
        self.saved = {name: getattr(efactl, name) for name in ('ETC', 'NGINX_CONF', 'ACME_FILE', 'subprocess', '_write', '_json_write', '_postconf_set',
                                                                '_platform', '_audit', '_dmarc_who', '_json_read', '_lineage_spki', '_tlsa_published', 'tlsa_records')}
        efactl.ETC, efactl.NGINX_CONF, efactl.ACME_FILE = self.folder, self.folder + '/efa.conf', self.folder + '/acme.json'
        self.runs, self.postconf, self.reloads, self.failing = [], {}, [], False

        def run(cmd, **_kwargs):
            self.runs.append(list(cmd))
            return types.SimpleNamespace(returncode=1 if self.failing and cmd[0] == 'certbot' else 0, stdout='', stderr='rate limited')

        def write(path, text, mode=0o644):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                f.write(text)

        efactl.subprocess = types.SimpleNamespace(run=run, TimeoutExpired=Exception, CalledProcessError=Exception)
        efactl._write, efactl._json_write = write, lambda path, data, mode=0o640: write(path, repr(data))
        efactl._postconf_set = lambda name, value: self.postconf.__setitem__(name, value)
        efactl._platform = lambda: types.SimpleNamespace(file_labels=lambda path: None, service_reload_if_active=lambda unit: self.reloads.append(unit))
        efactl._audit, efactl._dmarc_who = (lambda text: None), (lambda: 'test')
        # The rollover: a prepared next lineage whose TLSA record DNS shows already.
        efactl._json_read = lambda path, default: {'domain': 'mx.example.org', 'lineage': 'mx.example.org', 'next': 'mx.example.org-next'} \
            if path == efactl.ACME_FILE else default
        efactl._lineage_spki = lambda lineage: lineage.encode()
        efactl.tlsa_records = lambda spki, domain: [f'_25._tcp.{domain}. IN TLSA 3 1 1 {spki.hex()}']
        efactl._tlsa_published = lambda host: {'311' + b'mx.example.org-next'.hex()}
        os.makedirs(f'{self.folder}/letsencrypt/live/mx.example.org-next', exist_ok=True)
        os.makedirs(f'{self.folder}/letsencrypt/live/mx.example.org', exist_ok=True)

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(efactl, name, value)

    def nginx(self, lineage):
        live = f'{self.folder}/letsencrypt/live/{lineage}'
        with open(efactl.NGINX_CONF, 'w') as f:
            f.write(NGINX % (f'{live}/fullchain.pem', f'{live}/privkey.pem'))
        with open(efactl.NGINX_CONF) as f:
            return f.read()

    def apply(self):
        return efactl.letsencrypt_set(argparse.Namespace(domain='mx.example.org', email='admin@example.org', accept_tos='yes'))

    def test_webroot_and_no_installer(self):
        self.nginx('old.example.org')
        self.apply()
        certbot = next(cmd for cmd in self.runs if cmd[0] == 'certbot')
        self.assertEqual(certbot[:4], ['certbot', 'certonly', '--webroot', '-w'])
        self.assertNotIn('--nginx', certbot)
        self.assertIn('--reuse-key', certbot, 'the key stays for a TLSA record (DANE)')

    def test_mail_mode_nginx_follows_postfix(self):
        self.nginx('old.example.org')
        found = self.apply()
        live = f'{self.folder}/letsencrypt/live/mx.example.org'
        with open(efactl.NGINX_CONF) as f:
            self.assertIn(f'ssl_certificate {live}/fullchain.pem;', f.read())
        self.assertEqual(self.postconf['smtpd_tls_cert_file'], f'{live}/fullchain.pem')
        self.assertEqual(found['web'], 'this certificate')
        self.assertEqual(sorted(self.reloads), ['nginx', 'postfix'])

    def test_ecdsa_mode_keeps_the_web_certificate(self):
        before = self.nginx(efactl.WEB_LINEAGE)
        found = self.apply()
        with open(efactl.NGINX_CONF) as f:
            self.assertEqual(f.read(), before, 'the own ECDSA lineage of the web stays in nginx')
        self.assertEqual(self.postconf['smtpd_tls_cert_file'], f'{self.folder}/letsencrypt/live/mx.example.org/fullchain.pem')
        self.assertEqual(found['web'], 'own ECDSA certificate kept')
        self.assertEqual(self.reloads, ['postfix'])
        self.assertNotIn(['nginx', '-t'], self.runs)

    def switch(self):
        return efactl.letsencrypt_rollover(argparse.Namespace(step='switch'))

    def test_rollover_prepare_through_the_webroot(self):
        self.nginx('old.example.org')
        efactl.letsencrypt_rollover(argparse.Namespace(step='prepare'))
        certbot = next(cmd for cmd in self.runs if cmd[0] == 'certbot')
        self.assertEqual(certbot[:4], ['certbot', 'certonly', '--webroot', '-w'])
        self.assertNotIn('--nginx', certbot)

    def test_rollover_switch_mail_mode_nginx_follows(self):
        self.nginx('mx.example.org')
        self.switch()
        live = f'{self.folder}/letsencrypt/live/mx.example.org-next'
        with open(efactl.NGINX_CONF) as f:
            self.assertIn(f'ssl_certificate {live}/fullchain.pem;', f.read())
        self.assertEqual(self.postconf['smtpd_tls_cert_file'], f'{live}/fullchain.pem')
        self.assertFalse([cmd for cmd in self.runs if cmd[:2] == ['certbot', 'install']], 'no installer of certbot')
        self.assertEqual(sorted(self.reloads), ['nginx', 'postfix'])

    def test_rollover_switch_ecdsa_mode_keeps_the_web_certificate(self):
        before = self.nginx(efactl.WEB_LINEAGE)
        self.switch()
        with open(efactl.NGINX_CONF) as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(self.postconf['smtpd_tls_cert_file'], f'{self.folder}/letsencrypt/live/mx.example.org-next/fullchain.pem')
        self.assertEqual(self.reloads, ['postfix'])

    def test_failed_request_changes_nothing(self):
        before = self.nginx('old.example.org')
        self.failing = True
        with self.assertRaises(efactl.EfaError):
            self.apply()
        with open(efactl.NGINX_CONF) as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(self.postconf, {})
        self.assertFalse(os.path.exists(efactl.ACME_FILE))


if __name__ == '__main__':
    unittest.main()
