# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The calls of efactl that other programs build (efa-apply, efa-next-setup, efa-console-2fa) are parsed by the real argparse of
efactl: a wrong option name fails here, not in the middle of a setup (--console-user). Also on Windows: the
Unix-only modules are stubbed as in scripts/consistency_check.py."""

import importlib.machinery
import importlib.util
import os
import re
import shlex
import sys
import types
import unittest
from unittest import mock

# Programs loaded as modules here must leave no bytecode next to them (/usr/sbin/__pycache__, 9938e79).
sys.dont_write_bytecode = True
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
for name in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
    sys.modules.setdefault(name, types.ModuleType(name))
for folder in ('next/usr/lib/eFa/python', 'src/eFa/root/usr/lib/eFa/python', 'src/eFa-base/root/usr/lib/eFa/python'):
    if os.path.join(ROOT, folder) not in sys.path:
        sys.path.insert(0, os.path.join(ROOT, folder))
_loader = importlib.machinery.SourceFileLoader('efactl_calls', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
efactl = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_calls', _loader))
_loader.exec_module(efactl)

import efa_apply  # noqa: E402
import efa_common as c  # noqa: E402

NOTICE, NOEU = '6ba6c37d96513eaf/1794138779', 'fedcba9876543210/1794138779'
TOTP = {'TOTPSECRET': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'TOTPSTEP': '59000000', 'TOTPRECOVERY': ','.join(['a' * 64] * 10)}


def parse(words):
    """The arguments as efactl itself reads them; argparse ends with SystemExit on an unknown or missing option."""
    try:
        return efactl.build_parser(words).parse_args(words)
    except SystemExit:
        raise AssertionError('efactl does not take: ' + ' '.join(words))


def variant_calls(cfg, secret=None):
    seen = []
    with mock.patch.object(c, 'platform', lambda: None), mock.patch.object(c, 'which', lambda name: '/usr/sbin/' + name), \
            mock.patch.object(c, 'run', lambda cmd, **kw: seen.append(cmd)):
        efa_apply.Steps(cfg, secret or {}).variant()
    return [cmd[1:] for cmd in seen if cmd[0].endswith('/efactl')]


class EfactlCallTests(unittest.TestCase):
    def test_variant_guided_and_manual(self):
        guided = {'SETUPVARIANT': 'guided', 'EULINK': 'no', 'NOTICEACCEPTED': NOTICE, 'EULINKCONFIRM': NOEU, 'FRAMEWORKS': 'nis2,iso27001',
                  'FRAMEWORKNOTE': 'own rules', 'SETUPLANG': 'de', 'CLIUSERNAME': 'efaadmin'}
        manual = {'SETUPVARIANT': 'manual', 'EULINK': 'yes', 'NOTICEACCEPTED': NOTICE, 'SETUPLANG': 'en', 'CLIUSERNAME': 'efa-ci-fresh'}
        for cfg, secret, commands in ((guided, TOTP, ['totp-import', 'setup-variant-apply', 'my-settings-set', 'floor-check']),
                                      (manual, {}, ['setup-variant-apply', 'my-settings-set', 'floor-check']), ({}, {}, ['floor-check'])):
            calls = variant_calls(cfg, secret)
            self.assertEqual([words[0] for words in calls], commands)
            for words in calls:
                parsed = parse(words)
                self.assertEqual(parsed.command, words[0])
            applied = [parse(words) for words in calls if words[0] == 'setup-variant-apply']
            if applied:
                self.assertEqual((applied[0].variant, applied[0].console_user, applied[0].notice), (cfg['SETUPVARIANT'], cfg['CLIUSERNAME'], NOTICE))
        self.assertEqual(parse(variant_calls(guided, TOTP)[1]).noeu, NOEU)

    def test_setup_script_and_login_shell(self):
        with open(os.path.join(ROOT, 'next', 'usr', 'lib', 'eFa', 'setup', 'efa-next-setup'), encoding='utf-8') as f:
            lines = re.findall(r'step /usr/sbin/efactl ([^\n]+)', f.read())
        self.assertIn('floor-check --mode apply', lines)
        for line in lines:
            parse(shlex.split(line))
        loader = importlib.machinery.SourceFileLoader('console_2fa', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efa-console-2fa'))
        gate = importlib.util.module_from_spec(importlib.util.spec_from_loader('console_2fa', loader))
        loader.exec_module(gate)
        self.assertEqual(parse(gate.VERIFY[3:]).command, 'console-2fa-verify')
        # The drop-ins of postfix, nginx and dovecot and the path unit.
        units = os.path.join(ROOT, 'next', 'usr', 'lib', 'systemd', 'system')
        for path in [os.path.join(units, f'{s}.service.d', 'efa-floor.conf') for s in ('postfix', 'nginx', 'dovecot')] + [os.path.join(units, 'efa-floor-guard.service')]:
            with open(path, encoding='utf-8') as f:
                command = re.search(r'^Exec\w+=/usr/sbin/efactl (.+)$', f.read(), re.M).group(1)
            parse(shlex.split(command))

    def test_drives_the_packaged_efa_apply(self):
        # The file the package installs as /usr/lib/eFa/python/efa_apply.py (the bytecode is checked in test_monitor_packaging).
        self.assertTrue(efa_apply.__file__.replace(os.sep, '/').endswith('src/eFa/root/usr/lib/eFa/python/efa_apply.py'))

    def test_wrong_option_fails(self):
        with self.assertRaises(AssertionError):
            parse(['setup-variant-apply', '--variant', 'manual', '--eulink', 'yes', '--notice', NOTICE, '--console-user', 'x'])


if __name__ == '__main__':
    unittest.main()
