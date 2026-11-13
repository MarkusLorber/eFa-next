# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Snapshots of state that writers change while they are read: the backup of efactl (_tar_add_hashed) and the tar of the fresh
test (scripts/ci.sh snap_tar) take 20 snapshots each while writers replace their files atomically, without one failure. The
save of the fresh test is complete or not there at all, and --fresh-restore refuses a half one without unpacking anything."""
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CI = os.path.join(TOP, 'scripts', 'ci.sh')
POSIX = os.name == 'posix' and shutil.which('sh') and shutil.which('tar') and shutil.which('sha256sum')


def ci_function(name):
    text = open(CI, encoding='utf-8').read()
    start = text.index(f'\n{name}() {{') + 1
    return text[start:text.index('\n}\n', start) + 3]


def efactl():
    sys.path.insert(0, os.path.join(TOP, 'src', 'eFa-base', 'root', 'usr', 'lib', 'eFa', 'python'))
    sys.path.insert(0, os.path.join(TOP, 'next', 'usr', 'lib', 'eFa', 'python'))
    loader = importlib.machinery.SourceFileLoader('efactl_snap', os.path.join(TOP, 'next', 'usr', 'sbin', 'efactl'))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('efactl_snap', loader))
    loader.exec_module(module)
    return module


class Hammer:
    """Writers that replace two state files atomically (as _json_write does) as fast as they can."""

    def __init__(self, write, folder):
        self.write, self.folder, self.stop = write, folder, threading.Event()
        self.threads = [threading.Thread(target=self.run, args=(name,), daemon=True) for name in ('threat-state.json', 'floor-guard.json')]

    def run(self, name):
        n = 0
        while not self.stop.is_set():
            n += 1
            self.write(os.path.join(self.folder, name), {'n': n, 'pad': 'x' * (n % 4096)})

    def __enter__(self):
        for thread in self.threads:
            thread.start()
        return self

    def __exit__(self, *_exc):
        self.stop.set()
        for thread in self.threads:
            thread.join()


@unittest.skipUnless(POSIX, 'needs a Unix host with sh, tar and sha256sum')
class Snapshots(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = os.path.join(self.tmp, 'var', 'lib', 'eFa')
        os.makedirs(self.state)

    def test_backup_while_writers_replace_files(self):
        ctl = efactl()
        with Hammer(lambda path, data: ctl._json_write(path, data, mode=0o644), self.state):
            for _ in range(20):
                files, out = {}, io.BytesIO()
                with tarfile.open(fileobj=out, mode='w:gz') as tar:
                    ctl._tar_add_hashed(tar, self.state, files)
                self.assertFalse([name for name in files if name.endswith('.tmp')], 'no .tmp of a writer in the backup')
                out.seek(0)
                with tarfile.open(fileobj=out) as tar:
                    for member in tar.getmembers():
                        if member.isfile():
                            json.loads(tar.extractfile(member).read())  # old or new, never a mix

    def test_snapshot_tar_while_writers_replace_files(self):
        ctl = efactl()
        ctl.STATE_LOCK = os.path.join(self.tmp, 'state.lock')
        body = ci_function('snap_tar')
        rel = os.path.relpath(self.state, '/')
        env = {**os.environ, 'EFA_STATE_LOCK': ctl.STATE_LOCK}
        with Hammer(lambda path, data: ctl._json_write(path, data, mode=0o644), self.state):
            for n in range(20):
                out = os.path.join(self.tmp, f'snap{n}.tar')
                done = subprocess.run(['sh', '-c', body + f'snap_tar "$1" "$2"', 'sh', out, rel], capture_output=True, text=True, timeout=120, env=env)
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
                with tarfile.open(out) as tar:
                    self.assertFalse([m.name for m in tar.getmembers() if m.name.endswith('.tmp')])

    def test_snapshot_tar_never_hides_a_real_error(self):
        out = os.path.join(self.tmp, 'snap.tar')
        done = subprocess.run(['sh', '-c', ci_function('snap_tar') + 'snap_tar "$1" var/lib/no-such-folder-of-efa', 'sh', out],
                              capture_output=True, text=True, timeout=60, env={**os.environ, 'EFA_STATE_LOCK': os.path.join(self.tmp, 'state.lock')})
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(os.path.exists(out), 'no partial snapshot stays')

    def fake_bin(self, fail=''):
        """mysqldump, mysql, rpm, systemctl, nft, uname as on a set-up host; fail names one that fails."""
        bin_dir = os.path.join(self.tmp, 'bin')
        os.makedirs(bin_dir, exist_ok=True)
        scripts = {'mysqldump': 'echo "-- dump"', 'mysql': 'exit 0', 'rpm': 'exit 0', 'systemctl': 'exit 0', 'nft': 'exit 1',
                   'uname': 'echo host.example'}
        for name, text in scripts.items():
            path = os.path.join(bin_dir, name)
            with open(path, 'w') as f:
                f.write('#!/bin/sh\n' + ('exit 3' if name == fail else text) + '\n')
            os.chmod(path, 0o755)
        return bin_dir

    def run_save(self, fail=''):
        config, version = os.path.join(self.tmp, 'eFa-Config'), os.path.join(self.tmp, 'eFa-Version')
        with open(config, 'w') as f:
            f.write('CONFIGURED:YES\n')
        with open(version, 'w') as f:
            f.write('6.0.0.6\n')
        with open(os.path.join(self.state, 'x.json'), 'w') as f:
            f.write('{}')
        saved = os.path.join(self.tmp, 'saved')
        script = (f'FRESH_SAVED={saved}; FRESH_CONFIG={config}; FRESH_VERSION={version}; FRESH_MOVE=/{os.path.relpath(self.state, "/")}; '
                  'FRESH_COPY=; ' + ci_function('snap_tar') + ci_function('fresh_save') + ci_function('fresh_save_into') + 'fresh_save')
        env = {**os.environ, 'PATH': self.fake_bin(fail) + os.pathsep + os.environ['PATH'], 'EFA_STATE_LOCK': os.path.join(self.tmp, 'state.lock')}
        return subprocess.run(['sh', '-c', script], env=env, capture_output=True, text=True, timeout=120), saved

    def test_failed_save_leaves_nothing(self):
        done, saved = self.run_save(fail='mysqldump')
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(os.path.exists(saved) or os.path.exists(saved + '.partial'), 'no marker and no half save after a failure')

    def test_complete_save_and_restore_check(self):
        done, saved = self.run_save()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertTrue(os.path.exists(saved + '/complete') and os.path.exists(saved + '/MANIFEST'))
        check = ci_function('fresh_restore')
        check = check[:check.index('    echo "== back to the state before"')] + '    echo complete-ok\n}\n'
        ok = subprocess.run(['sh', '-c', f'FRESH_SAVED={saved}; ' + check + 'fresh_restore'], capture_output=True, text=True)
        self.assertIn('complete-ok', ok.stdout, ok.stderr)
        # A half save (no mark) or one whose tar changed afterwards: refused, and nothing is unpacked.
        for spoil in (lambda: os.remove(saved + '/complete'), lambda: open(saved + '/settings.tar', 'ab').write(b'x')):
            if not os.path.exists(saved + '/complete'):
                open(saved + '/complete', 'w').close()
            spoil()
            refused = subprocess.run(['sh', '-c', f'FRESH_SAVED={saved}; ' + check + 'fresh_restore'], capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('not a complete save', refused.stdout)
            self.assertNotIn('complete-ok', refused.stdout)


if __name__ == '__main__':
    unittest.main()
