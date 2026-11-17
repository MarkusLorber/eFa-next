# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The Update card (Hans 2026-11-15): efactl writes the progress of update-system and of the install of an eFa-next release
into one file, with the package counter of dnf and the seconds of each step; update-progress reads it without dnf or network.
dnf itself is never run: a small Python program prints its transaction lines."""

import contextlib
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
for name in ('grp', 'pwd', 'fcntl', 'syslog', 'termios', 'resource'):
    sys.modules.setdefault(name, __import__(name) if importlib.util.find_spec(name) else types.ModuleType(name))
for folder in ('next/usr/lib/eFa/python', 'src/eFa/root/usr/lib/eFa/python', 'src/eFa-base/root/usr/lib/eFa/python'):
    if os.path.join(ROOT, folder) not in sys.path:
        sys.path.insert(0, os.path.join(ROOT, folder))
_loader = importlib.machinery.SourceFileLoader('efactl_up', os.path.join(ROOT, 'next', 'usr', 'sbin', 'efactl'))
efactl = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_up', _loader))
_loader.exec_module(efactl)

import efa_update_progress as up  # noqa: E402

# What dnf prints for a transaction of three packages, then the check of them.
FAKE_DNF = [sys.executable, '-c', 'import sys\n'
            'for n in (1, 2, 3):\n    print(f"  Upgrading        : pkg{n}-1.0-1.el9.x86_64        {n}/3", flush=True)\n'
            'for n in (1, 2, 3):\n    print(f"  Verifying        : pkg{n}-1.0-1.el9.x86_64        {n}/3", flush=True)\n'
            'print("Complete!")\nsys.stderr.write("a warning\\n")']


class Files(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='efa-up-')
        patches = {'UPDATE_PROGRESS': 'progress.json', 'UPDATE_DURATIONS': 'durations.json', 'UPDATE_PENDING_FILE': 'pending.json',
                   'UPDATE_SYSTEM_FILE': 'update-system.json', 'UPDATE_SYSTEM_LOG': 'update-system.log', 'UPDATE_LOCK': 'update.lock',
                   'UPDATE_FILE': 'autoupdate.json', 'UPDATE_PREVIOUS': 'previous.json'}
        for key, name in patches.items():
            patcher = mock.patch.object(efactl, key, os.path.join(self.dir, name))
            patcher.start()
            self.addCleanup(patcher.stop)
        for key, value in {'_update_installed': lambda: '6.0.0.6.3', '_admin_notify': lambda *a, **k: None}.items():
            patcher = mock.patch.object(efactl, key, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def progress(self):
        with open(efactl.UPDATE_PROGRESS) as f:
            return json.load(f)


class DnfProgress(Files):
    def test_counter_into_the_record(self):
        record = efactl._progress_begin('system', efa_update=False)
        efactl._progress_step(record, 'os')
        code, out, err = efactl._dnf_with_progress(FAKE_DNF, record, 60)
        self.assertEqual(code, 0)
        self.assertIn('Complete!', out)
        self.assertIn('a warning', err)
        written = self.progress()
        self.assertEqual(written['packages'], [3, 3])
        self.assertTrue(written['verifying'])
        self.assertIn('pkg3', written['line'])

    def test_a_silent_hang_is_stopped(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            efactl._dnf_with_progress([sys.executable, '-c', 'import time; time.sleep(30)'], None, 1)


class Records(Files):
    def test_steps_durations_and_the_view(self):
        record = efactl._progress_begin('system', efa_update=True, reboot=False, to='v6.0.0.6.4')
        self.assertEqual(record['steps'], ['backup', 'check', 'efa', 'os', 'health'])
        for step in record['steps']:
            efactl._progress_step(record, step)
            record['step_started'] -= 30
        efactl._progress_end(record, True, 'Updated, health check ok.')
        written = self.progress()
        self.assertEqual(written['state'], 'done')
        self.assertIsNone(written['pid'])
        with open(efactl.UPDATE_DURATIONS) as f:
            self.assertEqual(json.load(f)['system'], {step: 30 for step in record['steps']})
        shown = efactl.update_progress(None)
        self.assertEqual(shown['progress']['state'], 'done')
        self.assertEqual(shown['progress']['percent'], 100)
        self.assertEqual(shown['installed'], '6.0.0.6.3')

    def test_a_dry_run_measures_no_install(self):
        record = efactl._progress_begin('system', efa_update=True, dry_run=True)
        self.assertEqual(record['steps'], ['backup', 'check', 'health'])

    def test_a_step_that_was_not_planned_is_added_in_order(self):
        record = efactl._progress_begin('system', efa_update=False)
        efactl._progress_step(record, 'efa')
        self.assertEqual(record['steps'], ['backup', 'check', 'efa', 'os', 'health'])

    def test_a_dead_run_is_failed(self):
        record = efactl._progress_begin('system', efa_update=False)
        efactl._progress_step(record, 'os')
        record['pid'] = 2 ** 22 + 12345
        efactl._progress_write(record)
        shown = efactl.update_progress(None)['progress']
        self.assertEqual(shown['state'], 'failed')
        self.assertIn('without a result', shown['result'])

    def test_a_planned_start_that_never_came(self):
        efactl._progress_write({'kind': 'system', 'state': 'waiting', 'steps': ['backup', 'os'], 'at': time.time() - 3600})
        self.assertEqual(efactl.update_progress(None)['progress']['state'], 'failed')

    def test_a_run_of_the_version_before_shows_as_running(self):
        started = time.strftime('%Y-%m-%d %H:%M:%S')
        efactl._json_write(efactl.UPDATE_SYSTEM_FILE, {'state': 'running', 'started': started})
        self.assertEqual(efactl.update_progress(None)['progress']['state'], 'running')
        efactl._json_write(efactl.UPDATE_SYSTEM_FILE, {'state': 'running', 'started': '2026-01-01 00:00:00'})
        self.assertEqual(efactl.update_progress(None)['progress']['state'], 'idle', 'an old leftover is no run')

    def test_pending_from_the_last_check(self):
        efactl._pending_note([{'package': 'a'}, {'package': 'b'}], True)
        shown = efactl.update_progress(None)
        self.assertEqual((shown['os_pending'], shown['reboot_required']), (2, True))


class SystemRun(Files):
    """update-system-run from the backup to the health check, with dnf replaced by FAKE_DNF."""

    def test_whole_run(self):
        real = efactl._dnf_with_progress
        steps_seen = []
        real_step = efactl._progress_step

        def step(record, name, **changes):
            steps_seen.append(name)
            return real_step(record, name, **changes)
        replaced = {'backup_now': lambda _a: {'backup': 'backup-1.tar.gz'}, '_backup_make': lambda *a, **k: {'backup': 'config-1.tar.gz'},
                    '_backup_stored_password': lambda: None, '_pending_os_updates': lambda: [{'package': 'pkg1'}] * 3,
                    '_firewall_risky_updates': lambda: {}, '_update_available': lambda *a, **k: False, '_maintenance': lambda mode: None,
                    '_firewall_lock': lambda wait=600: contextlib.nullcontext(), 'firewall_guard_run': lambda _a: None,
                    '_update_health': lambda: [], '_reboot_required': lambda: False, '_progress_step': step,
                    '_dnf_with_progress': lambda command, record, timeout: real(FAKE_DNF, record, timeout)}
        with contextlib.ExitStack() as stack:
            for key, value in replaced.items():
                stack.enter_context(mock.patch.object(efactl, key, value))
            result = efactl.update_system_run(types.SimpleNamespace(dry_run='no', reboot='off'))
        self.assertTrue(result['result'].startswith('Updated, health check ok.'), result)
        self.assertEqual(steps_seen, ['backup', 'check', 'os', 'health'])
        written = self.progress()
        self.assertEqual((written['state'], written['backup'], written['packages']), ('done', 'backup-1.tar.gz', None))
        shown = efactl.update_progress(None)
        self.assertEqual([mark['state'] for mark in shown['progress']['steps']], ['done'] * 4)
        self.assertEqual(shown['os_pending'], 0, 'after the run nothing is pending')


class HeldBack(Files):
    """2026-11-17: one upgrade dnf cannot resolve no longer stops the system update; it is held back and listed."""

    def test_held_back_names_and_marks(self):
        pending = [{'package': 'python3-pyOpenSSL.noarch', 'version': '26.3.0-1.el10_3', 'repository': 'epel'},
                   {'package': 'openssl.x86_64', 'version': '3.5.1-2.el10', 'repository': 'baseos'},
                   {'package': 'tzdata.noarch', 'version': '2026b-1.el10', 'repository': 'baseos'}]
        held = efactl.held_back(pending, ['openssl'], security={'tzdata'}, required=lambda name: ['eFa-next'] if name == 'python3-pyOpenSSL' else [])
        self.assertEqual([item['package'] for item in held], ['tzdata', 'python3-pyOpenSSL'], 'security first, then eFa-next needs it')
        self.assertTrue(held[0]['security'] and held[1]['efa'] and held[1]['repository'] == 'epel')
        self.assertEqual(efactl.held_text(held), 'tzdata (security update), python3-pyOpenSSL (needed by eFa-next)')
        self.assertEqual(efactl.held_back(pending, ['python3-pyOpenSSL', 'openssl', 'tzdata']), [])

    def test_dnf_problem_keeps_whole_lines(self):
        stderr = ('Last metadata expiration check: 0:01:02 ago.\nError: \n Problem: cannot install the best update candidate for package '
                  'python3-pyOpenSSL-25.1.0-1.el10.noarch\n  - nothing provides python3.12dist(cryptography) < 50 with >= 49 needed by '
                  'python3-pyOpenSSL-26.3.0-1.el10_3.noarch from epel\n')
        text = efactl.dnf_problem(stderr)
        self.assertIn('nothing provides python3.12dist(cryptography)', text)
        self.assertIn('python3-pyOpenSSL-26.3.0-1.el10_3.noarch from epel', text, 'the package name whole, not "ython3-..."')
        self.assertNotIn('metadata expiration', text)
        self.assertEqual(efactl.dnf_problem(''), '')

    def test_the_run_installs_the_rest_and_lists_the_held(self):
        def risky():
            efactl.UPDATE_DOWNLOADED = ['openssl']
            return {}
        commands = []
        replaced = {'backup_now': lambda _a: {'backup': 'backup-1.tar.gz'}, '_backup_make': lambda *a, **k: {'backup': 'config-1.tar.gz'},
                    '_backup_stored_password': lambda: None,
                    '_pending_os_updates': lambda: [{'package': 'openssl.x86_64'}, {'package': 'python3-pyOpenSSL.noarch', 'repository': 'epel'}],
                    '_firewall_risky_updates': risky, '_update_available': lambda *a, **k: False, '_maintenance': lambda mode: None,
                    '_firewall_lock': lambda wait=600: contextlib.nullcontext(), 'firewall_guard_run': lambda _a: None,
                    '_update_health': lambda: [], '_reboot_required': lambda: False,
                    '_platform': lambda: types.SimpleNamespace(security_updates=lambda: [], package_required_by=lambda name: []),
                    '_dnf_with_progress': lambda command, record, timeout: commands.append(command) or (0, 'Complete!', '')}
        with contextlib.ExitStack() as stack:
            for key, value in replaced.items():
                stack.enter_context(mock.patch.object(efactl, key, value))
            stack.enter_context(mock.patch.object(efactl, 'UPDATE_DOWNLOADED', None))
            result = efactl.update_system_run(types.SimpleNamespace(dry_run='no', reboot='off'))
        self.assertIn('Held back', result['result'])
        self.assertIn('python3-pyOpenSSL', result['result'])
        self.assertIn('--skip-broken', commands[0])
        self.assertIn('--setopt=best=False', commands[0])
        self.assertNotIn('--allowerasing', commands[0])
        self.assertEqual([item['package'] for item in self.progress()['held']], ['python3-pyOpenSSL'])
        self.assertEqual([item['package'] for item in efactl.update_progress(None)['os_held']], ['python3-pyOpenSSL'])
        with open(efactl.UPDATE_SYSTEM_LOG) as f:
            self.assertIn('held back', f.read())


class EfaInstall(Files):
    """The install of an eFa-next release alone (Install now, or auto in the window): its own steps on the same card."""

    def test_steps(self):
        state = {'latest': 'v6.0.0.6.4', 'verified': 'v6.0.0.6.4'}
        versions = iter(['6.0.0.6.4'])
        replaced = {'_update_available': lambda *a, **k: True, '_installed_tag': lambda: 'v6.0.0.6.3',
                    '_update_download': lambda version, folder: [f'{folder}/eFa-next.rpm'], 'backup_now': lambda _a: {'backup': 'backup-2.tar.gz'},
                    'totp_active_count': lambda: 1, '_firewall_lock': lambda wait=600: contextlib.nullcontext(),
                    '_update_installed': lambda: next(versions, '6.0.0.6.4'), '_update_health': lambda: [], '_json_write': efactl._json_write}
        with contextlib.ExitStack() as stack:
            for key, value in replaced.items():
                stack.enter_context(mock.patch.object(efactl, key, value))
            stack.enter_context(mock.patch.object(efactl._subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, '', '')))
            record = efactl._progress_begin('efa', to='v6.0.0.6.4')
            result = efactl._update_install_steps(state, record)
            efactl._progress_end(record, result.startswith('Installed'), result)
        self.assertTrue(result.startswith('Installed v6.0.0.6.4'), result)
        written = self.progress()
        self.assertEqual(written['state'], 'done')
        self.assertEqual(sorted(written['took']), sorted(['download', 'backup', 'efa', 'health']))
        self.assertEqual(written['backup'], 'backup-2.tar.gz')


class Library(unittest.TestCase):
    def test_self_test(self):
        up.self_test()


if __name__ == '__main__':
    unittest.main()
