# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski

"""6.0.0.6.6.1: HTTP/2 of the web interface is off by default and stays as set through every writer of efa.conf: the setup,
web-harden, the certificates (web-cert-set mail puts back the copy of before) and a restore. nginx -t itself runs in CI."""

import importlib.machinery
import importlib.util
import os
import re
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'python'))
SETUP = os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'setup', 'nginx-config.sh')


def load_efactl():
    loader = importlib.machinery.SourceFileLoader('efactl_http2', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_http2', loader))
    loader.exec_module(module)
    return module


def fresh_conf():
    """The efa.conf the setup writes (the heredoc of nginx-config.sh)."""
    text = open(SETUP, encoding='utf-8').read()
    return text.split("<<'EOF'\n", 1)[1].split('\nEOF\n', 1)[0] + '\n'


OLD_ON = fresh_conf().replace('    listen 443 ssl default_server;\n', '    listen 443 ssl default_server;\n    http2 on;\n')


class Http2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efactl = load_efactl()

    def test_fresh_config_has_no_http2(self):
        self.assertNotIn('http2', fresh_conf())
        self.assertNotIn('http2 on', open(SETUP, encoding='utf-8').read().replace('"efactl web-http2"', ''))

    def test_on_then_off_round_trips(self):
        text = self.efactl.nginx_http2_text
        conf = fresh_conf()
        on = text(conf, True, (1, 26, 3))
        self.assertEqual(on.count('    http2 on;\n'), 1)
        self.assertIn('listen 443 ssl default_server;\n    http2 on;\n', on)
        self.assertEqual(text(on, True, (1, 26, 3)), on, 'once')
        self.assertEqual(text(on, False, (1, 26, 3)), conf)
        old = text(conf, True, (1, 20, 1))
        self.assertIn('listen 443 ssl http2 default_server;', old, 'nginx before 1.25.1: the flag of listen')
        self.assertEqual(text(old, False, (1, 20, 1)), conf)
        self.assertEqual(text(OLD_ON, False, (1, 26, 3)), conf, 'the line of 6.0.0.6.6 and older goes')

    def test_no_http3_and_no_mail_proxy_in_the_tree(self):
        # CVE-2026-121810 (HTTP/3) and CVE-2026-113425 (mail proxy): eFa-next switches neither on, anywhere it writes nginx.
        pattern = re.compile(r'^\s*(mail|stream)\s*\{|listen[^;\n]*\s(quic|http3)\b|^\s*http3\s+on|nginx-mod-(mail|stream)|load_module', re.M)
        found = []
        for top in ('next', 'src', 'rpm', 'migration'):
            for root, _dirs, names in os.walk(os.path.join(ROOT, top)):
                for name in names:
                    if name.endswith(('.po', '.pyc', '.png', '.svg', '.woff2')):
                        continue
                    path = os.path.join(root, name)
                    try:
                        text = open(path, encoding='utf-8').read()
                    except (UnicodeDecodeError, OSError):
                        continue
                    found += [f'{os.path.relpath(path, ROOT)}: {match.group(0)}' for match in pattern.finditer(text)]
        self.assertEqual(found, [])

    def test_no_claim_of_fixed_versions(self):
        # The upstream versions (1.30.7 / 1.31.9) say nothing about EL packages, which get the fixes backported under their own
        # version: never a check by them. The fixed releases of the vendor are in NGINX_FIXED (test_nginx_min_evr).
        self.assertFalse(hasattr(self.efactl, 'nginx_http2_fixed'))
        source = open(os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'), encoding='utf-8').read()
        self.assertNotRegex(source, r'1\.30\.7|1\.31\.9')

    def host(self, folder, mode):
        efactl = self.efactl
        conf, before = os.path.join(folder, 'efa.conf'), os.path.join(folder, 'efa.conf.before-web-cert')
        setting = os.path.join(folder, 'web-http2.json')
        if mode:
            with open(setting, 'w') as f:
                f.write('{"mode": "%s"}' % mode)
        nginx_t = []

        def run(command, *args, **kwargs):
            nginx_t.append(command)
            return types.SimpleNamespace(returncode=0, stdout='', stderr='nginx version: nginx/1.26.3\n')
        patches = [mock.patch.object(efactl, 'NGINX_CONF', conf), mock.patch.object(efactl, 'NGINX_CERT_BEFORE', before),
                   mock.patch.object(efactl, 'WEB_HTTP2_FILE', setting), mock.patch.object(efactl.subprocess, 'run', run),
                   mock.patch.object(efactl, '_write', lambda path, text, *a: open(path, 'w').write(text))]
        for patch in patches:
            patch.start()
        self.addCleanup(lambda: [patch.stop() for patch in reversed(patches)])
        return conf, before, nginx_t

    def test_web_cert_set_mail_keeps_http2_off(self):
        with tempfile.TemporaryDirectory() as folder:
            conf, before, nginx_t = self.host(folder, None)
            cert = os.path.join(folder, 'own.pem')
            open(cert, 'w').close()
            # The copy of before is of 6.0.0.6.6 (with "http2 on;"), the config now has the own certificate and no HTTP/2.
            open(before, 'w').write(OLD_ON.replace('/etc/pki/tls/certs/efa.crt', cert).replace('/etc/pki/tls/private/efa.key', cert))
            open(conf, 'w').write(self.efactl.nginx_http2_text(OLD_ON, False, (1, 26, 3)).replace('/etc/pki/tls/certs/efa.crt', '/x.pem'))
            self.assertTrue(self.efactl._nginx_cert_restore())
            self.assertNotIn('http2', open(conf).read())
            self.assertIn(['nginx', '-t'], nginx_t)

    def test_restore_and_certificate_keep_the_setting(self):
        efactl = self.efactl
        with tempfile.TemporaryDirectory() as folder:
            conf, _before, nginx_t = self.host(folder, 'off')
            open(conf, 'w').write(OLD_ON)  # a backup of before brought it back
            self.assertTrue(efactl.web_http2_enforce(reload=False))
            self.assertNotIn('http2', open(conf).read())
            self.assertIn(['nginx', '-t'], nginx_t)
            self.assertFalse(efactl.web_http2_enforce(reload=False), 'no change: no nginx -t, no reload')
            nginx_t.clear()
            with mock.patch.object(efactl, '_platform', lambda: types.SimpleNamespace(service_reload_if_active=lambda unit: nginx_t.append(['reload', unit]))):
                self.assertFalse(efactl.web_http2_enforce())
            self.assertNotIn(['reload', 'nginx'], nginx_t)
            efactl._nginx_certificate('/new.pem', '/new.key')
            self.assertNotIn('http2', open(conf).read())
            self.assertIn('/new.pem', open(conf).read())

    def test_nginx_refusal_takes_it_back(self):
        efactl = self.efactl
        with tempfile.TemporaryDirectory() as folder:
            conf, _before, _t = self.host(folder, 'off')
            open(conf, 'w').write(OLD_ON)
            refused = lambda command, *a, **k: types.SimpleNamespace(returncode=1, stdout='', stderr='nginx: [emerg] x')  # noqa: E731
            with mock.patch.object(efactl.subprocess, 'run', refused):
                with self.assertRaisesRegex(efactl.EfaError, 'taken back'):
                    efactl.web_http2_enforce(reload=False)
            self.assertEqual(open(conf).read(), OLD_ON)

    def test_every_writer_of_efa_conf_takes_the_setting(self):
        source = open(os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'), encoding='utf-8').read()
        for name in ('_nginx_apply', '_nginx_certificate', '_nginx_cert_restore', 'restore'):
            body = re.search(rf'^def {name}\(.*?(?=^def )', source, flags=re.S | re.M).group(0)
            self.assertRegex(body, r'nginx_http2_text|web_http2_enforce', name)
        writers = set(re.findall(r'^def (\w+)\(', source, flags=re.M)) & {
            match.group(1) for match in re.finditer(r'^def (\w+)\((?:(?!^def ).)*?(?:_write\(NGINX_CONF|open\(NGINX_CONF, .w.\))',
                                                    source, flags=re.S | re.M)}
        self.assertLessEqual(writers, {'_nginx_apply', '_nginx_certificate', '_nginx_cert_restore', 'web_http2_enforce'},
                             'a new writer of efa.conf must take the HTTP/2 setting')


if __name__ == '__main__':
    unittest.main()
